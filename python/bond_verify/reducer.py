"""Pure Bond reducer — §4.1 main transition table, §4.2 money/operation
machines, §4.3 stop/kill machine. Byte-for-byte port of the TypeScript
reducer: consumes validated entries plus already signature-verified
evidence and produces the projected View. Pure: no clock, I/O, randomness.
"""

from __future__ import annotations

from typing import Any

from .canon import BondError, J, ZERO_HASH, deep_equal, is_hash

OPS = ("RESERVE", "ENCUMBER", "CREATE", "UNDO", "RELEASE", "PAY", "STOP")
MONEY_OPS = ("RESERVE", "ENCUMBER", "RELEASE", "PAY")


def op_key(action_id: str, op: str) -> str:
    return action_id + ":" + op.lower()


def pending_ops(st: dict) -> list:
    out = []
    for row in st["ops"].values():
        if row["state"] in ("PREPARED", "SENT", "UNKNOWN"):
            out.append(row["kind"])
    return sorted(set(out))


def to_view(st: dict) -> dict:
    return {
        "receipt_id": st["receiptId"],
        "action_id": st["actionId"],
        "revision": st["revision"],
        "phase": st["phase"],
        "effect": st["effect"],
        "undo": st["undo"],
        "funds": st["funds"],
        "kill": st["kill"],
        "review": st["review"],
        "stop_latched": st["stopLatched"],
        "quarantined": st["quarantined"],
        "pending": pending_ops(st),
        "head": dict(st["head"]),
    }


def initial_state(receipt_id: str, action_id: str) -> dict:
    return {
        "phase": "STAGED",
        "effect": "NOT_DISPATCHED",
        "undo": "PLANNED",
        "funds": "NONE",
        "kill": "ARMED",
        "review": "NONE",
        "stopLatched": False,
        "quarantined": False,
        "ops": {},        # op kind -> {kind, state}
        "markedOps": set(),
        "evidenceRefs": [],
        "appliedFacts": set(),  # J(facts) strings
        "holdFacts": None,
        "holdTerminal": None,
        "terminalBasis": None,
        "sawEncumbrance": False,
        "sawDispatch": False,
        "killCertifiedHash": None,
        "revision": 0,
        "head": {"seq": 0, "hash": ZERO_HASH},
        "receiptId": receipt_id,
        "actionId": action_id,
    }


def residual_effect(st: dict) -> str:
    if st["effect"] == "UNKNOWN" or st["undo"] == "UNKNOWN":
        return "UNKNOWN"
    if st["undo"] == "FAILED":
        return "NOT_REVERSED"
    if st["effect"] == "APPLIED" and st["undo"] != "APPLIED":
        return "DRAFT_PRESENT"
    return "NONE"


def remedy_state(st: dict) -> str:
    if st["review"] != "REJECT":
        return "NOT_TRIGGERED"
    return "PAID" if st["funds"] == "PAID" else "DUE"


def assembly_of(st: dict, bytes_complete: bool) -> str:
    complete = (
        st["phase"] == "CLOSED"
        and st["kill"] == "CERTIFIED"
        and len(pending_ops(st)) == 0
        and not st["quarantined"]
        and remedy_state(st) != "DUE"
        and bytes_complete
    )
    return "COMPLETE" if complete else "INCOMPLETE"


def clone_state(st: dict) -> dict:
    return {
        **st,
        "ops": {k: dict(v) for k, v in st["ops"].items()},
        "markedOps": set(st["markedOps"]),
        "evidenceRefs": [dict(r) for r in st["evidenceRefs"]],
        "appliedFacts": set(st["appliedFacts"]),
        "holdFacts": dict(st["holdFacts"]) if st["holdFacts"] else None,
        "head": dict(st["head"]),
    }


# --- serialization for the journal projection blob ---------------------------

def serialize_state(st: dict) -> dict:
    return {
        "phase": st["phase"], "effect": st["effect"], "undo": st["undo"],
        "funds": st["funds"], "kill": st["kill"], "review": st["review"],
        "stopLatched": st["stopLatched"], "quarantined": st["quarantined"],
        "ops": list(st["ops"].values()),
        "markedOps": sorted(st["markedOps"]),
        "evidenceRefs": st["evidenceRefs"],
        "appliedFacts": sorted(st["appliedFacts"]),
        "holdFacts": st["holdFacts"], "holdTerminal": st["holdTerminal"],
        "terminalBasis": st["terminalBasis"],
        "sawEncumbrance": st["sawEncumbrance"], "sawDispatch": st["sawDispatch"],
        "killCertifiedHash": st["killCertifiedHash"],
        "revision": st["revision"], "head": st["head"],
        "receiptId": st["receiptId"], "actionId": st["actionId"],
    }


def deserialize_state(x: dict) -> dict:
    st = dict(x)
    st["ops"] = {o["kind"]: dict(o) for o in x["ops"]}
    st["markedOps"] = set(x["markedOps"])
    st["appliedFacts"] = set(x["appliedFacts"])
    return st


# ---------------------------------------------------------------------------

class ForkSignal(BondError):
    """A verified observation contradicting a committed terminal fact."""
    def __init__(self, msg: str = "source fork"):
        super().__init__("SOURCE_FORK", msg)


class MissingEvidence(Exception):
    """Event references evidence bytes absent from the package/store."""


def _bad_state(mode: str, msg: str = "bad state"):
    raise BondError("BAD_STATE" if mode == "ingest" else "PROJECTION_INVALID", msg)


def _proj_invalid(msg: str = "projection invalid"):
    raise BondError("PROJECTION_INVALID", msg)


def _put_op(st: dict, kind: str, state: str) -> None:
    cur = st["ops"].get(kind)
    if cur:
        cur["state"] = state
    else:
        st["ops"][kind] = {"kind": kind, "state": state}


def _is_pending(op: dict) -> bool:
    return op["state"] in ("PREPARED", "SENT", "UNKNOWN")


def _bind_operation(st: dict, env: dict, key: str, mode: str) -> dict:
    suffix = key[key.rindex(":") + 1:].upper() if ":" in key else ""
    op = st["ops"].get(suffix)
    if op is None or key != op_key(env["action"]["action_id"], op["kind"]) \
            or op["state"] == "CANCELED":
        _bad_state(mode, f"operation key {key} not bound")
    return op


def _add_evidence_ref(st: dict, ref: dict) -> None:
    if not any(r["hash"] == ref["hash"] for r in st["evidenceRefs"]):
        st["evidenceRefs"].append(dict(ref))
        st["evidenceRefs"].sort(key=lambda r: r["hash"])


def _is_dup_facts(st: dict, facts: dict) -> bool:
    return J(facts) in st["appliedFacts"]


def _mark_applied(st: dict, facts: dict, ref: dict, op: dict | None = None) -> None:
    st["appliedFacts"].add(J(facts))
    _add_evidence_ref(st, ref)
    if op:
        st["markedOps"].add(op["kind"])


def _mark_facts_only(st: dict, facts: dict) -> None:
    st["appliedFacts"].add(J(facts))


def _compute_closing_plan(st: dict) -> None:
    if st["funds"] in ("HELD", "ENCUMBERED"):
        owe_pay = st["review"] == "REJECT" and st["undo"] in ("APPLIED", "FAILED")
        if owe_pay:
            if "PAY" not in st["ops"]:
                _put_op(st, "PAY", "PREPARED")
        elif "RELEASE" not in st["ops"] and st["holdTerminal"] is None:
            _put_op(st, "RELEASE", "PREPARED")


def computed_disposition(st: dict) -> str | None:
    if st["funds"] == "NONE":
        return "NO_HOLD"
    if st["funds"] == "PAID":
        return "PAY"
    if st["funds"] == "RELEASED":
        if st["terminalBasis"] in ("RESERVATION_EXPIRED", "LONG_STOP"):
            return "EXTERNAL_MATURITY"
        return "RELEASE"
    return None


def _economics_resolved(st: dict) -> bool:
    return all(op["kind"] == "STOP" or not _is_pending(op)
               for op in st["ops"].values())


def project_kill(facts: Any, binding: dict, validate) -> dict:
    """§3.3 KILL admissibility + binding against the action's Trellis run.
    Returns {"ok": True, "state": ...} or {"ok": False, "code": ...}."""
    try:
        f = validate(facts)
    except BondError:
        return {"ok": False, "code": "SCHEMA"}
    if (f["run_id"] != binding["trellis_run"]
            or f["host_id"] != binding["trellis_host"]
            or f["task_ref"] != binding["trellis_task_ref"]):
        return {"ok": False, "code": "RUN_BINDING"}
    if f["state"] == "CERTIFIED":
        if (f["stopped_head"] is None or not f["gate_closed"]
                or not f["empty_observed"] or f["audit_gap"]):
            return {"ok": False, "code": "INCOMPLETE"}
        return {"ok": True, "state": "CERTIFIED"}
    return {"ok": True, "state": "UNCONFIRMED"}


def apply_entry(st: dict | None, entry: dict, entry_hash: str,
                env: dict | None, mode: str) -> tuple[dict, bool]:
    """Apply one entry to the projection. Returns (state, noop).
    Raises BondError; ForkSignal => caller commits RecoveryQuarantined;
    MissingEvidence => caller marks the package INCOMPLETE."""
    kind = entry["kind"]
    data = entry["data"]

    if st is None:
        if kind != "ActionStaged":
            _proj_invalid("genesis must be ActionStaged")
        if entry["seq"] != 1 or entry["previous_hash"] != ZERO_HASH:
            _proj_invalid("bad genesis link")
        st0 = initial_state("", entry["action_id"])
        st0["ops"]["RESERVE"] = {"kind": "RESERVE", "state": "PREPARED"}
        st0["revision"] = 1
        st0["head"] = {"seq": 1, "hash": entry_hash}
        return st0, False

    e = env
    prev_pending = {k: _is_pending(o) for k, o in st["ops"].items()}

    def need_evidence(ref):
        if not ref or not is_hash(ref.get("hash")):
            _bad_state(mode, "bad evidence ref")
        r = e["resolve"](ref)
        if r is None:
            raise MissingEvidence()
        return r

    noop = False

    def finish(s):
        s["revision"] = entry["seq"]
        s["head"] = {"seq": entry["seq"], "hash": entry_hash}
        return s, noop

    def dup():
        if mode == "verify":
            _proj_invalid("redundant observation entry")
        return st, True

    if kind == "ActionStaged":
        _proj_invalid("duplicate ActionStaged")

    elif kind == "HoldObserved":
        ref = data["evidence"]
        ev = need_evidence(ref)
        if _is_dup_facts(st, ev["facts"]):
            return dup()
        f = ev["facts"]
        if f["kind"] == "NO_HOLD":
            # Admissible only for the reserve lane; may resolve a locally
            # CANCELED RESERVE (proves the never-sent assumption correct).
            if f["operation_key"] != op_key(e["action"]["action_id"], "RESERVE"):
                _bad_state(mode, "NO_HOLD admissible only for RESERVE")
            op = st["ops"].get("RESERVE")
            if op is None or op["state"] == "KNOWN":
                _bad_state(mode, "NO_HOLD for resolved reserve")
            if (st["holdFacts"] is not None or st["funds"] in ("HELD", "ENCUMBERED")
                    or st["holdTerminal"] in ("RELEASED", "PAID")):
                raise ForkSignal("NO_HOLD contradicts confirmed hold")
            if st["phase"] not in ("STAGED", "CLOSING"):
                _bad_state(mode, "NO_HOLD phase")
            st["phase"] = "CLOSING"
            st["funds"] = "NONE"
            st["holdTerminal"] = "NONE"
            op["state"] = "KNOWN"
            st["markedOps"].add("RESERVE")
            if st["undo"] == "PLANNED":
                st["undo"] = "NOT_NEEDED"
            _mark_applied(st, f, ref)
            return finish(st)
        if f["kind"] != "HOLD":
            _bad_state(mode, "HoldObserved requires HOLD or NO_HOLD")
        if f["state"] not in ("HELD", "ENCUMBERED"):
            _bad_state(mode, "HoldObserved state")
        if f["action_hash"] != entry["action_hash"]:
            _bad_state(mode, "hold action_hash mismatch")
        if not deep_equal(f["terms"], e["action"]["terms"]):
            _bad_state(mode, "hold terms mismatch")
        if f["exclusive"] is not True:
            _bad_state(mode, "hold not exclusive")
        op = _bind_operation(st, e, f["operation_key"], mode)
        if op["kind"] not in ("RESERVE", "ENCUMBER"):
            _bad_state(mode, "HOLD names wrong op")
        if st["holdTerminal"] in ("RELEASED", "PAID"):
            raise ForkSignal("hold mutation after terminal settlement")
        if (st["holdFacts"] and st["holdFacts"]["revision"] >= f["revision"]
                and st["holdFacts"]["state"] != f["state"]):
            raise ForkSignal("hold revision regressed with changed state")
        op_was_pending = prev_pending.get(op["kind"]) is True
        listed = (
            (st["phase"] == "STAGED" and f["state"] == "HELD" and op["kind"] == "RESERVE")
            or (st["phase"] == "COMMITTING" and f["state"] == "ENCUMBERED"
                and op["kind"] == "ENCUMBER")
            or st["phase"] == "CLOSING"
        )
        if not listed and not op_was_pending:
            _bad_state(mode, "HoldObserved in non-admissible phase")
        if st["phase"] == "CLOSED":
            _bad_state(mode, "hold after close")
        _mark_applied(st, f, ref, op)
        st["holdFacts"] = f
        st["funds"] = f["state"]
        if f["state"] == "ENCUMBERED":
            st["sawEncumbrance"] = True
        op["state"] = "KNOWN"
        if st["phase"] == "STAGED" and f["state"] == "HELD" and op["kind"] == "RESERVE":
            st["phase"] = "READY"
        elif st["phase"] == "CLOSING":
            _compute_closing_plan(st)
        return finish(st)

    elif kind == "CommitRequested":
        if st["phase"] != "READY":
            _bad_state(mode, "CommitRequested phase")
        if st["stopLatched"] or st["quarantined"]:
            _bad_state(mode, "commit under stop/quarantine")
        if data["operation_key"] != op_key(entry["action_id"], "ENCUMBER"):
            _bad_state(mode, "bad commit key")
        st["phase"] = "COMMITTING"
        _put_op(st, "ENCUMBER", "PREPARED")
        return finish(st)

    elif kind == "DispatchLatched":
        if st["phase"] != "COMMITTING":
            _bad_state(mode, "DispatchLatched phase")
        if st["funds"] != "ENCUMBERED":
            _proj_invalid("dispatch without encumbered hold")
        if st["sawDispatch"]:
            _proj_invalid("duplicate dispatch marker")
        if data["operation_key"] != op_key(entry["action_id"], "CREATE"):
            _bad_state(mode, "bad create key")
        pol = need_evidence(data["policy"])
        if (pol["facts"]["kind"] != "POLICY" or pol["facts"]["purpose"] != "FORWARD"
                or pol["facts"]["verdict"] != "ALLOW"
                or not deep_equal(pol["facts"]["pin"], e["action"]["policy_pin"])):
            _bad_state(mode, "dispatch policy not verified ALLOW")
        run = need_evidence(data["runtime"])
        if (run["facts"]["kind"] != "RUN" or run["facts"]["state"] != "ACTIVE"
                or run["facts"]["run_id"] != e["binding"]["trellis_run"]
                or run["facts"]["host_id"] != e["binding"]["trellis_host"]
                or run["facts"]["task_ref"] != e["binding"]["trellis_task_ref"]):
            raise BondError("RUN_BINDING", "dispatch run binding")
        hold = need_evidence(data["hold"])
        if (hold["facts"]["kind"] != "HOLD" or hold["facts"]["state"] != "ENCUMBERED"
                or hold["facts"]["action_hash"] != entry["action_hash"]):
            raise BondError("HOLD_BINDING", "dispatch hold binding")
        t = data["timing"]
        if not (t["admitted_ms"] >= t["runtime_observed_ms"]
                and t["admitted_ms"] - t["runtime_observed_ms"] <= 250):
            raise BondError("RUN_STALE", "runtime observation too old at admission")
        _add_evidence_ref(st, data["policy"])
        _add_evidence_ref(st, data["runtime"])
        _add_evidence_ref(st, data["hold"])
        _mark_facts_only(st, pol["facts"])
        _mark_facts_only(st, run["facts"])
        _mark_facts_only(st, hold["facts"])
        st["phase"] = "EXECUTING"
        st["effect"] = "PENDING"
        st["sawDispatch"] = True
        _put_op(st, "CREATE", "SENT")
        st["markedOps"].add("CREATE")
        return finish(st)

    elif kind == "ActionAborted":
        if st["phase"] not in ("STAGED", "READY", "COMMITTING"):
            _bad_state(mode, "abort phase")
        st["phase"] = "CLOSING"
        if st["undo"] == "PLANNED":
            st["undo"] = "NOT_NEEDED"
        reserve = st["ops"].get("RESERVE")
        if reserve and reserve["state"] == "PREPARED":
            reserve["state"] = "CANCELED"
        _compute_closing_plan(st)
        return finish(st)

    elif kind == "EffectObserved":
        ref = data["evidence"]
        ev = need_evidence(ref)
        if _is_dup_facts(st, ev["facts"]):
            return dup()
        f = ev["facts"]
        if f["kind"] != "EFFECT" or f["purpose"] != "FORWARD":
            _bad_state(mode, "EffectObserved facts")
        op = _bind_operation(st, e, f["operation_key"], mode)
        if op["kind"] != "CREATE":
            _bad_state(mode, "EffectObserved names non-CREATE op")
        _check_effect_binding(f, e)
        if st["phase"] == "CLOSED":
            _bad_state(mode, "effect after close")
        if st["phase"] == "AWAITING_REVIEW":
            # New-facts FORWARD observation contradicts the committed
            # terminal effect (identical facts deduplicated above).
            raise ForkSignal("conflicting forward effect")
        _mark_applied(st, f, ref, op)
        if f["outcome"] == "UNKNOWN":
            if st["phase"] not in ("EXECUTING", "UNCERTAIN"):
                _bad_state(mode, "UNKNOWN effect phase")
            op["state"] = "UNKNOWN"
            st["effect"] = "UNKNOWN"
            st["phase"] = "UNCERTAIN"
            st["stopLatched"] = True
            return finish(st)
        op["state"] = "KNOWN"
        if f["outcome"] == "APPLIED":
            st["effect"] = "APPLIED"
            if st["phase"] in ("EXECUTING", "UNCERTAIN"):
                st["phase"] = "AWAITING_REVIEW"
            elif st["phase"] != "CLOSING":
                _bad_state(mode, "EffectObserved phase")
        else:
            st["effect"] = "NOT_APPLIED"
            if st["undo"] == "PLANNED":
                st["undo"] = "NOT_NEEDED"
            if st["phase"] != "CLOSING":
                st["phase"] = "CLOSING"
            _compute_closing_plan(st)
        return finish(st)

    elif kind == "ReviewAccepted":
        if st["phase"] != "AWAITING_REVIEW" or st["funds"] != "ENCUMBERED":
            _bad_state(mode, "ReviewAccepted phase/funds")
        st["review"] = "ACCEPT"
        st["undo"] = "NOT_NEEDED"
        st["phase"] = "CLOSING"
        _compute_closing_plan(st)
        return finish(st)

    elif kind == "ReviewRejected":
        if st["phase"] != "AWAITING_REVIEW" or st["funds"] != "ENCUMBERED":
            _bad_state(mode, "ReviewRejected phase/funds")
        if data["policy"] is not None:
            pol = need_evidence(data["policy"])
            if pol["facts"]["kind"] != "POLICY" or pol["facts"]["purpose"] != "UNDO":
                _bad_state(mode, "rejection policy evidence not UNDO")
            _add_evidence_ref(st, data["policy"])
            _mark_facts_only(st, pol["facts"])
        st["review"] = "REJECT"
        st["undo"] = "PENDING"
        st["phase"] = "COMPENSATING"
        _put_op(st, "UNDO", "PREPARED")
        return finish(st)

    elif kind == "UndoObserved":
        ref = data["evidence"]
        ev = need_evidence(ref)
        if _is_dup_facts(st, ev["facts"]):
            return dup()
        f = ev["facts"]
        if f["kind"] != "EFFECT" or f["purpose"] != "UNDO":
            _bad_state(mode, "UndoObserved facts")
        op = _bind_operation(st, e, f["operation_key"], mode)
        if op["kind"] != "UNDO":
            _bad_state(mode, "UndoObserved names non-UNDO op")
        _check_effect_binding(f, e)
        op_was_pending = prev_pending.get("UNDO") is True
        prepared_local = (
            op["state"] == "PREPARED" and f["outcome"] == "NOT_APPLIED"
            and f["reason"] in ("POLICY_DENIED", "STOPPED_BEFORE_CALL",
                                "DEADLINE_BEFORE_CALL")
        )
        if not op_was_pending and not prepared_local:
            _bad_state(mode, "UNDO op not open")
        if st["phase"] == "CLOSED":
            _bad_state(mode, "undo after close")
        if st["undo"] in ("APPLIED", "FAILED") and f["outcome"] != st["undo"]:
            raise ForkSignal("conflicting terminal undo")
        if st["phase"] not in ("COMPENSATING", "UNCERTAIN", "CLOSING"):
            _bad_state(mode, "UndoObserved phase")
        _mark_applied(st, f, ref, op)
        if f["outcome"] == "UNKNOWN":
            op["state"] = "UNKNOWN"
            st["undo"] = "UNKNOWN"
            st["phase"] = "UNCERTAIN"
            st["stopLatched"] = True
            return finish(st)
        op["state"] = "KNOWN"
        st["undo"] = "APPLIED" if f["outcome"] == "APPLIED" else "FAILED"
        st["phase"] = "CLOSING"
        if st["funds"] == "ENCUMBERED" and st["review"] == "REJECT" \
                and "PAY" not in st["ops"]:
            _put_op(st, "PAY", "PREPARED")
        _compute_closing_plan(st)
        return finish(st)

    elif kind == "FundsObserved":
        ref = data["evidence"]
        ev = need_evidence(ref)
        if _is_dup_facts(st, ev["facts"]):
            return dup()
        f = ev["facts"]
        if f["kind"] != "HOLD" or f["state"] not in ("RELEASED", "PAID"):
            _bad_state(mode, "FundsObserved facts")
        if f["action_hash"] != entry["action_hash"]:
            _bad_state(mode, "funds action_hash mismatch")
        if not deep_equal(f["terms"], e["action"]["terms"]):
            _bad_state(mode, "funds terms mismatch")
        op = _bind_operation(st, e, f["operation_key"], mode)
        if op["kind"] not in ("RELEASE", "PAY", "RESERVE", "ENCUMBER"):
            _bad_state(mode, "FundsObserved names wrong op")
        if st["phase"] == "CLOSED":
            _bad_state(mode, "funds after close")
        if st["holdTerminal"] in ("RELEASED", "PAID"):
            raise ForkSignal("second terminal funds observation")
        is_maturity = f["settlement_basis"] in ("RESERVATION_EXPIRED", "LONG_STOP")
        op_was_pending = prev_pending.get(op["kind"]) is True
        if not is_maturity:
            if f["state"] == "PAID" and not (st["review"] == "REJECT" and op["kind"] == "PAY"):
                raise ForkSignal("PAID without authorized rejection")
            if f["state"] == "RELEASED" and op["kind"] != "RELEASE":
                raise ForkSignal("REQUEST-released evidence names non-release op")
            if st["phase"] != "CLOSING" and not op_was_pending:
                raise ForkSignal("unrequested terminal settlement")
        _mark_applied(st, f, ref, op)
        if op["state"] != "KNOWN":
            op["state"] = "KNOWN"
        if is_maturity:
            _apply_maturity(st, f)
            return finish(st)
        st["funds"] = f["state"]
        st["holdFacts"] = f
        st["holdTerminal"] = f["state"]
        st["terminalBasis"] = "REQUEST"
        return finish(st)

    elif kind == "ActionClosed":
        if st["phase"] != "CLOSING":
            _bad_state(mode, "ActionClosed phase")
        if not _economics_resolved(st):
            _bad_state(mode, "economic work unresolved")
        disp = computed_disposition(st)
        if disp is None or data["disposition"] != disp:
            _proj_invalid("disposition mismatch")
        st["phase"] = "CLOSED"
        return finish(st)

    elif kind == "StopRequested":
        if data["operation_key"] != op_key(entry["action_id"], "STOP"):
            _bad_state(mode, "bad stop key")
        existing = st["ops"].get("STOP")
        if (existing and _is_pending(existing)) or st["kill"] == "CERTIFIED":
            if mode == "verify":
                _proj_invalid("redundant stop entry")
            return st, True
        st["stopLatched"] = True
        if st["kill"] == "ARMED":
            st["kill"] = "REQUESTED"
        _put_op(st, "STOP", "SENT")
        if st["phase"] in ("STAGED", "READY", "COMMITTING"):
            st["phase"] = "CLOSING"
            if st["undo"] == "PLANNED":
                st["undo"] = "NOT_NEEDED"
            reserve = st["ops"].get("RESERVE")
            if reserve and reserve["state"] == "PREPARED":
                reserve["state"] = "CANCELED"
            _compute_closing_plan(st)
        return finish(st)

    elif kind == "KillObserved":
        ref = data["evidence"]
        ev = need_evidence(ref)
        if _is_dup_facts(st, ev["facts"]):
            return dup()
        proj = project_kill(ev["facts"], e["binding"], lambda x: x)
        if not proj["ok"]:
            raise BondError(proj["code"], "kill projection failed")
        if proj["state"] == "CERTIFIED":
            if (st["killCertifiedHash"] is not None
                    and st["killCertifiedHash"] != ev["evidenceHash"]):
                raise ForkSignal("second distinct CERTIFIED observation")
            st["killCertifiedHash"] = ev["evidenceHash"]
            st["kill"] = "CERTIFIED"
            op = st["ops"].get("STOP")
            if op and _is_pending(op):
                op["state"] = "KNOWN"
            st["markedOps"].add("STOP")
        else:
            if st["kill"] == "CERTIFIED":
                raise ForkSignal("UNCONFIRMED after CERTIFIED")
            st["kill"] = "UNCONFIRMED"
        _mark_applied(st, ev["facts"], ref)
        return finish(st)

    elif kind == "EvidenceAttached":
        _add_evidence_ref(st, data["artifact"])
        return finish(st)

    elif kind == "DependencyUncertain":
        op = st["ops"].get(data["operation"])
        if op is None or not _is_pending(op):
            _bad_state(mode, "DependencyUncertain for non-pending op")
        st["markedOps"].add(data["operation"])
        if data["operation"] == "CREATE":
            if st["phase"] not in ("EXECUTING", "UNCERTAIN"):
                _bad_state(mode, "DepUnc CREATE phase")
            op["state"] = "UNKNOWN"
            st["effect"] = "UNKNOWN"
            st["phase"] = "UNCERTAIN"
            st["stopLatched"] = True
        elif data["operation"] == "UNDO":
            if st["phase"] not in ("COMPENSATING", "UNCERTAIN"):
                _bad_state(mode, "DepUnc UNDO phase")
            op["state"] = "UNKNOWN"
            st["undo"] = "UNKNOWN"
            st["phase"] = "UNCERTAIN"
            st["stopLatched"] = True
        else:
            op["state"] = "UNKNOWN"
            if data["operation"] in MONEY_OPS:
                st["funds"] = "UNKNOWN"
        return finish(st)

    elif kind == "RecoveryQuarantined":
        st["quarantined"] = True
        return finish(st)

    else:
        _bad_state(mode, "unknown event kind")


def _apply_maturity(st: dict, facts: dict) -> None:
    """§4.2 maturity override: terminal RELEASED with basis
    RESERVATION_EXPIRED or LONG_STOP."""
    if facts["settlement_basis"] == "RESERVATION_EXPIRED":
        if st["sawEncumbrance"] or st["sawDispatch"]:
            raise ForkSignal("expiry after encumbrance")
    st["funds"] = "RELEASED"
    st["holdFacts"] = facts
    st["holdTerminal"] = "RELEASED"
    st["terminalBasis"] = facts["settlement_basis"]
    for k in MONEY_OPS:
        op = st["ops"].get(k)
        if op and op["state"] == "PREPARED":
            op["state"] = "CANCELED"
    create = st["ops"].get("CREATE")
    undo = st["ops"].get("UNDO")
    effect_open = (st["effect"] in ("PENDING", "UNKNOWN")
                   or (create is not None and _is_pending(create)))
    undo_open = (st["undo"] in ("PENDING", "UNKNOWN")
                 or (undo is not None and _is_pending(undo)))
    if effect_open or undo_open:
        if st["phase"] not in ("CLOSING", "CLOSED"):
            st["phase"] = "UNCERTAIN"
        return
    if st["undo"] == "PLANNED":
        st["undo"] = "NOT_NEEDED"
    st["phase"] = "CLOSING"


def _check_effect_binding(f: dict, e: dict) -> None:
    if f["resource"] != e["plan"]["resource"]:
        _proj_invalid("effect resource mismatch")
    if f["outcome"] == "APPLIED":
        if f["value_hash"] != e["plan"]["value_hash"]:
            _proj_invalid("effect value_hash mismatch")
        if f["version"] is None:
            _proj_invalid("APPLIED without version")
        if f["purpose"] == "FORWARD" and f["reason"] != "CREATED":
            _proj_invalid("bad forward reason")
        if f["purpose"] == "UNDO" and f["reason"] != "DELETED":
            _proj_invalid("bad undo reason")
    else:
        if f["version"] is not None or f["value_hash"] is not None:
            _proj_invalid("non-APPLIED carries version")
        ok_reasons = {
            "UNKNOWN": ["TRANSPORT_UNKNOWN"],
            "NOT_APPLIED": ["ABSENT", "VERSION_CHANGED", "POLICY_DENIED",
                            "STOPPED_BEFORE_CALL", "DEADLINE_BEFORE_CALL"],
        }
        if f["reason"] not in ok_reasons.get(f["outcome"], []):
            _proj_invalid("bad effect reason")
