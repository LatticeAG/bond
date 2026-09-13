"""Closed-schema validators — Bond spec §3.1. Every object is closed, every
property required, absent distinct from null. Validators raise
BondError("SCHEMA") unless a more specific code is named."""

from __future__ import annotations

from typing import Any

from .canon import (
    BondError, b64u_decode, is_amount, is_b64u, is_bond_id, is_external_id,
    is_hash, is_resource_segment, is_time, is_u, time_ms,
)


def _fail(msg: str = "schema violation") -> None:
    raise BondError("SCHEMA", msg)


def _is_obj(x: Any) -> bool:
    return isinstance(x, dict)


def _keys(x: dict, required: list[str]) -> None:
    want = set(required)
    for k in x:
        if k not in want:
            _fail(f"unexpected member {k}")
    for k in required:
        if k not in x:
            _fail(f"missing member {k}")


def _str(x: Any) -> str:
    if not isinstance(x, str):
        _fail("expected string")
    return x


def _bool(x: Any) -> bool:
    if not isinstance(x, bool):
        _fail("expected boolean")
    return x


def _lit(x: Any, v: Any) -> Any:
    if x != v or isinstance(x, bool) != isinstance(v, bool):
        _fail(f"expected {v!r}")
    return x


def _one_of(x: Any, vs: tuple | list) -> Any:
    if not isinstance(x, str) or x not in vs:
        _fail("bad enum value")
    return x


def v_hash(x: Any) -> str:
    if not is_hash(x):
        _fail("bad hash")
    return x


def v_u(x: Any) -> int:
    if not is_u(x):
        _fail("bad integer")
    return x


def v_time(x: Any) -> str:
    if not is_time(x):
        _fail("bad time")
    return x


def v_amount(x: Any) -> str:
    if not is_amount(x):
        _fail("bad amount")
    return x


def v_external_id(x: Any) -> str:
    if not is_external_id(x):
        _fail("bad external id")
    return x


def v_b64(x: Any) -> str:
    if not is_b64u(x):
        _fail("bad base64url")
    return x


def v_id(x: Any, p: str) -> str:
    if not is_bond_id(x, p):
        _fail(f"bad {p} id")
    return x


def v_artifact_ref(x: Any) -> dict:
    if not _is_obj(x):
        _fail("artifact ref not object")
    _keys(x, ["hash", "bytes", "media_type"])
    return {
        "hash": v_hash(x["hash"]),
        "bytes": v_u(x["bytes"]),
        "media_type": _one_of(x["media_type"], ["application/json", "application/pdf"]),
    }


def v_blob(x: Any) -> dict:
    if not _is_obj(x):
        _fail("blob not object")
    _keys(x, ["hash", "bytes", "media_type", "data"])
    data = x["data"]
    if data is not None and not is_b64u(data):
        _fail("bad blob data")
    return {
        "hash": v_hash(x["hash"]),
        "bytes": v_u(x["bytes"]),
        "media_type": _one_of(x["media_type"], ["application/json", "application/pdf"]),
        "data": data,
    }


def v_head(x: Any) -> dict:
    if not _is_obj(x):
        _fail("head not object")
    _keys(x, ["seq", "hash"])
    return {"seq": v_u(x["seq"]), "hash": v_hash(x["hash"])}


def v_policy_pin(x: Any) -> dict:
    if not _is_obj(x):
        _fail()
    _keys(x, ["charter_id", "version", "charter_hash", "manifest_hash", "engine"])
    return {
        "charter_id": v_external_id(x["charter_id"]),
        "version": v_u(x["version"]),
        "charter_hash": v_hash(x["charter_hash"]),
        "manifest_hash": v_hash(x["manifest_hash"]),
        "engine": _lit(x["engine"], "bedrock.eval/1"),
    }


def v_draft(x: Any) -> dict:
    if not _is_obj(x):
        _fail()
    _keys(x, ["status", "supplier_alias", "catalog_item", "quantity", "quoted_minor", "asset"])
    d = {
        "status": _lit(x["status"], "DRAFT"),
        "supplier_alias": v_external_id(x["supplier_alias"]),
        "catalog_item": v_external_id(x["catalog_item"]),
        "quantity": v_u(x["quantity"]),
        "quoted_minor": v_amount(x["quoted_minor"]),
        "asset": _lit(x["asset"], "SIMUSD"),
    }
    if d["quantity"] < 1 or d["quantity"] > 100:
        _fail("quantity out of range")
    q = int(d["quoted_minor"])
    if q < 1 or q > 100000:
        _fail("quoted amount out of range")
    return d


def v_terms(x: Any) -> dict:
    if not _is_obj(x):
        _fail()
    _keys(x, ["asset", "amount_minor", "owner", "beneficiary", "task_id",
              "reserve_until", "long_stop", "trigger"])
    return {
        "asset": _lit(x["asset"], "SIMUSD"),
        "amount_minor": _lit(x["amount_minor"], "1000"),
        "owner": v_external_id(x["owner"]),
        "beneficiary": v_external_id(x["beneficiary"]),
        "task_id": v_external_id(x["task_id"]),
        "reserve_until": v_time(x["reserve_until"]),
        "long_stop": v_time(x["long_stop"]),
        "trigger": _lit(x["trigger"], "OPERATOR_REJECTION_OF_CONFIRMED_DRAFT"),
    }


def v_action(x: Any) -> dict:
    """Full Action validation including the §3.2 structural relations."""
    if not _is_obj(x):
        _fail("action not object")
    _keys(x, ["schema", "profile", "tenant_id", "scope_id", "action_id", "principal_id",
              "action_class", "resource", "expected", "draft", "terms", "policy_pin",
              "adapter_build", "created_at", "execute_before"])
    a = {
        "schema": _lit(x["schema"], "bond.action/1"),
        "profile": _lit(x["profile"], "bond.sim-procurement-draft/1"),
        "tenant_id": v_id(x["tenant_id"], "bnt"),
        "scope_id": v_id(x["scope_id"], "bns"),
        "action_id": v_id(x["action_id"], "bac"),
        "principal_id": v_id(x["principal_id"], "bnp"),
        "action_class": _lit(x["action_class"], "procurement.draft.create/1"),
        "resource": _str(x["resource"]),
        "expected": _lit(x["expected"], "ABSENT"),
        "draft": v_draft(x["draft"]),
        "terms": v_terms(x["terms"]),
        "policy_pin": v_policy_pin(x["policy_pin"]),
        "adapter_build": v_hash(x["adapter_build"]),
        "created_at": v_time(x["created_at"]),
        "execute_before": v_time(x["execute_before"]),
    }
    if a["resource"] != "drafts/" + a["action_id"]:
        _fail("resource must be drafts/<action_id>")
    created = time_ms(a["created_at"])
    deadline = time_ms(a["execute_before"])
    if not (created < deadline <= created + 30000):
        _fail("invalid execution window")
    reserve = time_ms(a["terms"]["reserve_until"])
    if reserve != created + 300000:
        _fail("reserve_until must be created_at+300000ms")
    long_stop = time_ms(a["terms"]["long_stop"])
    if not long_stop > reserve:
        _fail("long_stop must follow reserve expiry")
    if long_stop > created + 45 * 24 * 3600 * 1000:
        _fail("long_stop beyond task posting +45d")
    return a


def v_undo_plan(x: Any) -> dict:
    if not _is_obj(x):
        _fail()
    _keys(x, ["schema", "action_hash", "adapter_build", "operation", "resource",
              "require_status", "require_no_export", "version_source", "value_hash",
              "remedy_minor", "asset", "expires_at"])
    return {
        "schema": _lit(x["schema"], "bond.undo-plan/1"),
        "action_hash": v_hash(x["action_hash"]),
        "adapter_build": v_hash(x["adapter_build"]),
        "operation": _lit(x["operation"], "draft.delete_if_created_version"),
        "resource": _str(x["resource"]),
        "require_status": _lit(x["require_status"], "DRAFT"),
        "require_no_export": _lit(x["require_no_export"], True),
        "version_source": _lit(x["version_source"], "FORWARD_RESULT"),
        "value_hash": v_hash(x["value_hash"]),
        "remedy_minor": _lit(x["remedy_minor"], "1000"),
        "asset": _lit(x["asset"], "SIMUSD"),
        "expires_at": v_time(x["expires_at"]),
    }


def v_paper_review(x: Any) -> dict:
    if not _is_obj(x):
        _fail()
    _keys(x, ["schema", "paper_id", "tenant_id", "holder", "insurer_label",
              "policy_reference", "document", "reviewed_by", "reviewed_at",
              "effective_at", "expires_at", "action_class", "asset",
              "stated_per_action_limit", "exclusions_document", "mode",
              "insurer_confirmed", "aggregate_availability", "coverage_verdict"])
    return {
        "schema": _lit(x["schema"], "bond.paper/1"),
        "paper_id": v_id(x["paper_id"], "bni"),
        "tenant_id": v_id(x["tenant_id"], "bnt"),
        "holder": v_id(x["holder"], "bnp"),
        "insurer_label": _str(x["insurer_label"]),
        "policy_reference": v_external_id(x["policy_reference"]),
        "document": v_artifact_ref(x["document"]),
        "reviewed_by": v_id(x["reviewed_by"], "bnp"),
        "reviewed_at": v_time(x["reviewed_at"]),
        "effective_at": v_time(x["effective_at"]),
        "expires_at": v_time(x["expires_at"]),
        "action_class": _lit(x["action_class"], "procurement.draft.create/1"),
        "asset": _lit(x["asset"], "SIMUSD"),
        "stated_per_action_limit": v_amount(x["stated_per_action_limit"]),
        "exclusions_document": v_artifact_ref(x["exclusions_document"]),
        "mode": _lit(x["mode"], "PAPER_ONLY"),
        "insurer_confirmed": _lit(x["insurer_confirmed"], False),
        "aggregate_availability": _lit(x["aggregate_availability"], "NOT_VERIFIED"),
        "coverage_verdict": _lit(x["coverage_verdict"], "NOT_DETERMINED"),
    }


def check_paper_consistency(paper: dict, action: dict) -> None:
    """Paper/action consistency (§3.2); raises INSURANCE_SCOPE on mismatch."""
    def bad() -> None:
        raise BondError("INSURANCE_SCOPE", "paper inconsistent with action")
    if paper["tenant_id"] != action["tenant_id"]:
        bad()
    if paper["holder"] != action["principal_id"]:
        bad()
    if paper["action_class"] != action["action_class"]:
        bad()
    if paper["asset"] != action["terms"]["asset"]:
        bad()
    if int(paper["stated_per_action_limit"]) < 1000:
        bad()
    created = time_ms(action["created_at"])
    if not (time_ms(paper["effective_at"]) <= created < time_ms(paper["expires_at"])):
        bad()


def v_binding(x: Any) -> dict:
    if not _is_obj(x):
        _fail()
    _keys(x, ["action", "plan", "paper", "trellis_run", "trellis_host", "trellis_task_ref"])
    return {
        "action": v_artifact_ref(x["action"]),
        "plan": v_artifact_ref(x["plan"]),
        "paper": v_artifact_ref(x["paper"]),
        "trellis_run": v_external_id(x["trellis_run"]),
        "trellis_host": v_external_id(x["trellis_host"]),
        "trellis_task_ref": v_id(x["trellis_task_ref"], "bac"),
    }


# --- facts -------------------------------------------------------------------

def v_policy_facts(x: Any) -> dict:
    if not _is_obj(x):
        _fail()
    _keys(x, ["kind", "purpose", "pin", "input_hash", "verdict", "reason", "evaluated_at"])
    return {
        "kind": _lit(x["kind"], "POLICY"),
        "purpose": _one_of(x["purpose"], ["FORWARD", "UNDO"]),
        "pin": v_policy_pin(x["pin"]),
        "input_hash": v_hash(x["input_hash"]),
        "verdict": _one_of(x["verdict"], ["ALLOW", "DENY"]),
        "reason": _str(x["reason"]),
        "evaluated_at": v_time(x["evaluated_at"]),
    }


def v_hold_facts(x: Any) -> dict:
    if not _is_obj(x):
        _fail()
    _keys(x, ["kind", "hold_id", "revision", "action_hash", "terms", "state",
              "exclusive", "operation_key", "journal_head", "settlement_basis"])
    f = {
        "kind": _lit(x["kind"], "HOLD"),
        "hold_id": v_external_id(x["hold_id"]),
        "revision": v_u(x["revision"]),
        "action_hash": v_hash(x["action_hash"]),
        "terms": v_terms(x["terms"]),
        "state": _one_of(x["state"], ["HELD", "ENCUMBERED", "RELEASED", "PAID"]),
        "exclusive": _lit(x["exclusive"], True),
        "operation_key": _str(x["operation_key"]),
        "journal_head": v_head(x["journal_head"]),
        "settlement_basis": None if x["settlement_basis"] is None else
            _one_of(x["settlement_basis"], ["REQUEST", "RESERVATION_EXPIRED", "LONG_STOP"]),
    }
    # §3.3: HELD/ENCUMBERED require null basis; PAID requires REQUEST;
    # RELEASED allows REQUEST, RESERVATION_EXPIRED, or LONG_STOP.
    if f["state"] in ("HELD", "ENCUMBERED") and f["settlement_basis"] is not None:
        _fail()
    if f["state"] == "PAID" and f["settlement_basis"] != "REQUEST":
        _fail()
    return f


def v_no_hold_facts(x: Any) -> dict:
    if not _is_obj(x):
        _fail()
    _keys(x, ["kind", "operation_key", "authoritative", "reason"])
    return {
        "kind": _lit(x["kind"], "NO_HOLD"),
        "operation_key": _str(x["operation_key"]),
        "authoritative": _lit(x["authoritative"], True),
        "reason": _one_of(x["reason"], ["INSUFFICIENT_FUNDS", "EXPIRED", "POLICY_DENIED"]),
    }


def v_effect_facts(x: Any) -> dict:
    if not _is_obj(x):
        _fail()
    _keys(x, ["kind", "purpose", "operation_key", "outcome", "resource",
              "version", "value_hash", "reason"])
    f = {
        "kind": _lit(x["kind"], "EFFECT"),
        "purpose": _one_of(x["purpose"], ["FORWARD", "UNDO"]),
        "operation_key": _str(x["operation_key"]),
        "outcome": _one_of(x["outcome"], ["APPLIED", "NOT_APPLIED", "UNKNOWN"]),
        "resource": _str(x["resource"]),
        "version": None if x["version"] is None else v_external_id(x["version"]),
        "value_hash": None if x["value_hash"] is None else v_hash(x["value_hash"]),
        "reason": _one_of(x["reason"], [
            "CREATED", "DELETED", "ABSENT", "VERSION_CHANGED", "POLICY_DENIED",
            "TRANSPORT_UNKNOWN", "STOPPED_BEFORE_CALL", "DEADLINE_BEFORE_CALL"]),
    }
    if f["outcome"] == "APPLIED" and (f["version"] is None or f["value_hash"] is None):
        _fail()
    if f["outcome"] != "APPLIED" and (f["version"] is not None or f["value_hash"] is not None):
        _fail()
    return f


def v_run_facts(x: Any) -> dict:
    if not _is_obj(x):
        _fail()
    _keys(x, ["kind", "run_id", "host_id", "task_ref", "state", "checkpoint",
              "policy_hash", "complete_prefix"])
    return {
        "kind": _lit(x["kind"], "RUN"),
        "run_id": v_external_id(x["run_id"]),
        "host_id": v_external_id(x["host_id"]),
        "task_ref": v_id(x["task_ref"], "bac"),
        "state": _one_of(x["state"], ["ACTIVE", "STOPPING", "STOPPED", "UNCONFIRMED"]),
        "checkpoint": v_head(x["checkpoint"]),
        "policy_hash": v_hash(x["policy_hash"]),
        "complete_prefix": _bool(x["complete_prefix"]),
    }


def v_kill_facts(x: Any) -> dict:
    if not _is_obj(x):
        _fail()
    _keys(x, ["kind", "run_id", "host_id", "task_ref", "state", "stopped_head",
              "gate_closed", "empty_observed", "audit_gap", "external_effects",
              "remote_replication"])
    return {
        "kind": _lit(x["kind"], "KILL"),
        "run_id": v_external_id(x["run_id"]),
        "host_id": v_external_id(x["host_id"]),
        "task_ref": v_id(x["task_ref"], "bac"),
        "state": _one_of(x["state"], ["CERTIFIED", "UNCONFIRMED"]),
        "stopped_head": None if x["stopped_head"] is None else v_head(x["stopped_head"]),
        "gate_closed": _bool(x["gate_closed"]),
        "empty_observed": _bool(x["empty_observed"]),
        "audit_gap": _bool(x["audit_gap"]),
        "external_effects": _lit(x["external_effects"], "NOT_REVERSED"),
        "remote_replication": _lit(x["remote_replication"], "NOT_ATTESTED"),
    }


def v_facts(x: Any) -> dict:
    if not _is_obj(x) or not isinstance(x.get("kind"), str):
        _fail()
    v = {
        "POLICY": v_policy_facts, "HOLD": v_hold_facts, "NO_HOLD": v_no_hold_facts,
        "EFFECT": v_effect_facts, "RUN": v_run_facts, "KILL": v_kill_facts,
    }.get(x["kind"])
    if v is None:
        _fail("unknown facts kind")
    return v(x)


SOURCE_PROFILES = [
    "fixture/1", "bedrock/1", "mint.bond-hold/1",
    "vekrevert.bond-draft/1", "trellis-bundle/1", "bond.draft-store/1",
]


def v_assertion(x: Any) -> dict:
    if not _is_obj(x):
        _fail()
    _keys(x, ["schema", "action_hash", "observed_at", "source_profile", "source", "facts"])
    return {
        "schema": _lit(x["schema"], "bond.assertion/1"),
        "action_hash": v_hash(x["action_hash"]),
        "observed_at": v_time(x["observed_at"]),
        "source_profile": _one_of(x["source_profile"], SOURCE_PROFILES),
        "source": v_artifact_ref(x["source"]),
        "facts": v_facts(x["facts"]),
    }


def v_draft_store_record(x: Any) -> dict:
    if not _is_obj(x):
        _fail()
    _keys(x, ["schema", "action_hash", "scope_id", "writer_fence", "observed_at", "facts"])
    return {
        "schema": _lit(x["schema"], "bond.draft-store/1"),
        "action_hash": v_hash(x["action_hash"]),
        "scope_id": v_id(x["scope_id"], "bns"),
        "writer_fence": v_u(x["writer_fence"]),
        "observed_at": v_time(x["observed_at"]),
        "facts": v_effect_facts(x["facts"]),
    }


# --- entries -----------------------------------------------------------------

EVENT_KINDS = [
    "ActionStaged", "HoldObserved", "CommitRequested", "DispatchLatched",
    "ActionAborted", "EffectObserved", "ReviewAccepted", "ReviewRejected",
    "UndoObserved", "FundsObserved", "ActionClosed", "StopRequested",
    "KillObserved", "EvidenceAttached", "DependencyUncertain", "RecoveryQuarantined",
]


def _v_event_data(kind: str, x: Any) -> dict:
    if not _is_obj(x):
        _fail()
    if kind == "ActionStaged":
        _keys(x, ["binding"])
        return {"binding": v_binding(x["binding"])}
    if kind in ("HoldObserved", "EffectObserved", "UndoObserved", "FundsObserved", "KillObserved"):
        _keys(x, ["evidence"])
        return {"evidence": v_artifact_ref(x["evidence"])}
    if kind == "CommitRequested":
        _keys(x, ["operation_key"])
        return {"operation_key": _str(x["operation_key"])}
    if kind == "DispatchLatched":
        _keys(x, ["policy", "runtime", "hold", "fence", "operation_key", "timing"])
        t = x["timing"]
        if not _is_obj(t):
            _fail()
        _keys(t, ["boot_id", "runtime_observed_ms", "admitted_ms"])
        return {
            "policy": v_artifact_ref(x["policy"]),
            "runtime": v_artifact_ref(x["runtime"]),
            "hold": v_artifact_ref(x["hold"]),
            "fence": v_u(x["fence"]),
            "operation_key": _str(x["operation_key"]),
            "timing": {
                "boot_id": v_external_id(t["boot_id"]),
                "runtime_observed_ms": v_u(t["runtime_observed_ms"]),
                "admitted_ms": v_u(t["admitted_ms"]),
            },
        }
    if kind == "ActionAborted":
        _keys(x, ["reason"])
        return {"reason": _one_of(x["reason"],
                  ["CANCELED", "DEADLINE", "DEPENDENCY_DENIED", "STOPPED"])}
    if kind == "ReviewAccepted":
        _keys(x, ["principal_id"])
        return {"principal_id": v_id(x["principal_id"], "bnp")}
    if kind == "ReviewRejected":
        _keys(x, ["principal_id", "reason", "policy"])
        return {
            "principal_id": v_id(x["principal_id"], "bnp"),
            "reason": _one_of(x["reason"], ["OPERATOR_REJECTED", "VALIDATION_FAILED"]),
            "policy": None if x["policy"] is None else v_artifact_ref(x["policy"]),
        }
    if kind == "ActionClosed":
        _keys(x, ["disposition"])
        return {"disposition": _one_of(x["disposition"],
                  ["NO_HOLD", "RELEASE", "PAY", "EXTERNAL_MATURITY"])}
    if kind == "StopRequested":
        _keys(x, ["principal_id", "operation_key"])
        return {"principal_id": v_id(x["principal_id"], "bnp"),
                "operation_key": _str(x["operation_key"])}
    if kind == "EvidenceAttached":
        _keys(x, ["artifact", "purpose"])
        return {
            "artifact": v_artifact_ref(x["artifact"]),
            "purpose": _one_of(x["purpose"], ["GROUND_ADVISORY", "WORLD_LINEAGE"]),
        }
    if kind == "DependencyUncertain":
        _keys(x, ["operation"])
        return {"operation": _one_of(x["operation"],
                  ["RESERVE", "ENCUMBER", "CREATE", "UNDO", "RELEASE", "PAY", "STOP"])}
    if kind == "RecoveryQuarantined":
        _keys(x, ["reason"])
        return {"reason": _one_of(x["reason"],
                  ["HASH_CHAIN", "WRITER_FENCE", "CLOCK", "SOURCE_FORK"])}
    _fail("unknown event kind")


def v_entry_body(x: Any) -> dict:
    if not _is_obj(x):
        _fail("entry body not object")
    _keys(x, ["schema", "tenant_id", "action_id", "action_hash", "event_id", "seq",
              "previous_hash", "recorded_at", "actor", "kind", "data"])
    kind = _one_of(x["kind"], EVENT_KINDS)
    return {
        "schema": _lit(x["schema"], "bond.entry/1"),
        "tenant_id": v_id(x["tenant_id"], "bnt"),
        "action_id": v_id(x["action_id"], "bac"),
        "action_hash": v_hash(x["action_hash"]),
        "event_id": v_id(x["event_id"], "bnj"),
        "seq": v_u(x["seq"]),
        "previous_hash": v_hash(x["previous_hash"]),
        "recorded_at": v_time(x["recorded_at"]),
        "actor": v_id(x["actor"], "bnp"),
        "kind": kind,
        "data": _v_event_data(kind, x["data"]),
    }


_OPS = ["RESERVE", "ENCUMBER", "CREATE", "UNDO", "RELEASE", "PAY", "STOP"]


def v_view(x: Any) -> dict:
    if not _is_obj(x):
        _fail()
    _keys(x, ["receipt_id", "action_id", "revision", "phase", "effect", "undo", "funds",
              "kill", "review", "stop_latched", "quarantined", "pending", "head"])
    if not isinstance(x["pending"], list):
        _fail()
    pending = [_one_of(p, _OPS) for p in x["pending"]]
    if len(pending) != len(set(pending)) or pending != sorted(pending):
        _fail("pending not sorted/unique")
    return {
        "receipt_id": v_id(x["receipt_id"], "brc"),
        "action_id": v_id(x["action_id"], "bac"),
        "revision": v_u(x["revision"]),
        "phase": _one_of(x["phase"], [
            "STAGED", "READY", "COMMITTING", "EXECUTING", "AWAITING_REVIEW",
            "COMPENSATING", "UNCERTAIN", "CLOSING", "CLOSED"]),
        "effect": _one_of(x["effect"], ["NOT_DISPATCHED", "PENDING", "APPLIED",
                          "NOT_APPLIED", "UNKNOWN"]),
        "undo": _one_of(x["undo"], ["NOT_NEEDED", "PLANNED", "PENDING", "APPLIED",
                        "FAILED", "UNKNOWN"]),
        "funds": _one_of(x["funds"], ["NONE", "HELD", "ENCUMBERED", "RELEASED",
                         "PAID", "UNKNOWN"]),
        "kill": _one_of(x["kill"], ["ARMED", "REQUESTED", "CERTIFIED", "UNCONFIRMED"]),
        "review": _one_of(x["review"], ["NONE", "ACCEPT", "REJECT"]),
        "stop_latched": _bool(x["stop_latched"]),
        "quarantined": _bool(x["quarantined"]),
        "pending": pending,
        "head": v_head(x["head"]),
    }


def v_receipt_body(x: Any) -> dict:
    if not _is_obj(x):
        _fail("receipt body not object")
    _keys(x, ["schema", "receipt_id", "tenant_id", "action_id", "action_hash",
              "revision", "previous_receipt_hash", "head", "binding", "view",
              "evidence", "issued_at", "simulation", "assembly", "insurance",
              "residual_effect", "remedy", "truth"])
    if not isinstance(x["evidence"], list):
        _fail()
    evidence = [v_artifact_ref(e) for e in x["evidence"]]
    hashes = [e["hash"] for e in evidence]
    if hashes != sorted(hashes) or len(set(hashes)) != len(hashes):
        _fail("evidence not sorted/unique")
    return {
        "schema": _lit(x["schema"], "bond.receipt/1"),
        "receipt_id": v_id(x["receipt_id"], "brc"),
        "tenant_id": v_id(x["tenant_id"], "bnt"),
        "action_id": v_id(x["action_id"], "bac"),
        "action_hash": v_hash(x["action_hash"]),
        "revision": v_u(x["revision"]),
        "previous_receipt_hash": None if x["previous_receipt_hash"] is None
            else v_hash(x["previous_receipt_hash"]),
        "head": v_head(x["head"]),
        "binding": v_binding(x["binding"]),
        "view": v_view(x["view"]),
        "evidence": evidence,
        "issued_at": v_time(x["issued_at"]),
        "simulation": _lit(x["simulation"], True),
        "assembly": _one_of(x["assembly"], ["COMPLETE", "INCOMPLETE"]),
        "insurance": _lit(x["insurance"], "PAPER_ONLY"),
        "residual_effect": _one_of(x["residual_effect"],
            ["NONE", "DRAFT_PRESENT", "NOT_REVERSED", "UNKNOWN"]),
        "remedy": _one_of(x["remedy"], ["NOT_TRIGGERED", "DUE", "PAID"]),
        "truth": _lit(x["truth"], "ISSUER_ASSERTIONS_NOT_REAL_WORLD_PROOF"),
    }


def v_package(x: Any) -> dict:
    if not _is_obj(x):
        _fail("package not object")
    _keys(x, ["schema", "entries", "receipts", "blobs"])
    if not isinstance(x["entries"], list) or not isinstance(x["receipts"], list) \
            or not isinstance(x["blobs"], list):
        _fail()
    return {
        "schema": _lit(x["schema"], "bond.package/1"),
        "entries": x["entries"],
        "receipts": x["receipts"],
        "blobs": x["blobs"],
    }


def v_notice(x: Any) -> dict:
    if not _is_obj(x):
        _fail()
    _keys(x, ["schema", "receipt_id", "revision", "previous_hash", "reason", "recorded_at"])
    return {
        "schema": _lit(x["schema"], "bond.notice/1"),
        "receipt_id": v_id(x["receipt_id"], "brc"),
        "revision": v_u(x["revision"]),
        "previous_hash": None if x["previous_hash"] is None else v_hash(x["previous_hash"]),
        "reason": _one_of(x["reason"], ["HOSTING_WITHDRAWN", "KEY_COMPROMISE_REPORTED"]),
        "recorded_at": v_time(x["recorded_at"]),
    }


def v_http_auth(x: Any) -> dict:
    if not _is_obj(x):
        _fail()
    _keys(x, ["tenant_id", "principal_id", "key_id", "request_id", "method",
              "target", "body_hash", "issued_at", "expires_at"])
    sig = x["sig"]
    if not is_b64u(sig) or len(b64u_decode(sig)) != 64:
        _fail("bad sig")
    return {
        "tenant_id": v_id(x["tenant_id"], "bnt"),
        "principal_id": v_id(x["principal_id"], "bnp"),
        "key_id": v_id(x["key_id"], "bnk"),
        "request_id": v_id(x["request_id"], "bnq"),
        "method": _one_of(x["method"], ["GET", "POST"]),
        "target": _str(x["target"]),
        "body_hash": v_hash(x["body_hash"]),
        "issued_at": v_time(x["issued_at"]),
        "expires_at": v_time(x["expires_at"]),
        "sig": sig,
    }


def v_signed(x: Any, kind: str, v_body) -> dict:
    """Validate a Signed<B>: {body, key_id, hash, sig} closed object."""
    if not _is_obj(x):
        _fail("signed not object")
    _keys(x, ["body", "key_id", "hash", "sig"])
    sig = x["sig"]
    if not is_b64u(sig) or len(b64u_decode(sig)) != 64:
        _fail("bad sig")
    return {
        "body": v_body(x["body"]),
        "key_id": v_id(x["key_id"], "bnk"),
        "hash": v_hash(x["hash"]),
        "sig": sig,
    }


def v_trust_file(x: Any) -> dict:
    if not _is_obj(x):
        _fail("trust not object")
    _keys(x, ["schema", "keys", "allowed_adapter_builds", "expected_heads"])
    _lit(x["schema"], "bond.trust/1")
    if not isinstance(x["keys"], list):
        _fail()
    keys = []
    for k in x["keys"]:
        if not _is_obj(k):
            _fail()
        _keys(k, ["key_id", "public_key_hex", "roles", "assertion_kinds",
                  "source_profiles", "tenant_id", "not_before", "not_after",
                  "compromised_at"])
        if not isinstance(k["roles"], list) or not isinstance(k["assertion_kinds"], list) \
                or not isinstance(k["source_profiles"], list):
            _fail()
        kk = {
            "key_id": v_id(k["key_id"], "bnk"),
            "public_key_hex": v_hash(k["public_key_hex"]),
            "roles": [_one_of(r, ["receipt", "entry", "paper", "assertion",
                          "notice", "http", "draft-store"]) for r in k["roles"]],
            "assertion_kinds": [_one_of(a, ["POLICY", "HOLD", "NO_HOLD", "EFFECT",
                                    "RUN", "KILL"]) for a in k["assertion_kinds"]],
            "source_profiles": [_one_of(p, SOURCE_PROFILES) for p in k["source_profiles"]],
            "tenant_id": v_id(k["tenant_id"], "bnt"),
            "not_before": v_time(k["not_before"]),
            "not_after": v_time(k["not_after"]),
            "compromised_at": None if k["compromised_at"] is None
                else v_time(k["compromised_at"]),
        }
        keys.append(kk)
    key_ids = [k["key_id"] for k in keys]
    if len(set(key_ids)) != len(key_ids) or key_ids != sorted(key_ids):
        _fail("trust keys not sorted/unique")
    pubs = [k["public_key_hex"] for k in keys]
    if len(set(pubs)) != len(pubs):
        _fail("duplicate public keys")
    if not isinstance(x["allowed_adapter_builds"], list):
        _fail()
    for h in x["allowed_adapter_builds"]:
        v_hash(h)
    if not isinstance(x["expected_heads"], list):
        _fail()
    for eh in x["expected_heads"]:
        if not _is_obj(eh):
            _fail()
        _keys(eh, ["receipt_id", "head"])
        v_id(eh["receipt_id"], "brc")
        v_head(eh["head"])
    return {
        "schema": "bond.trust/1",
        "keys": keys,
        "allowed_adapter_builds": x["allowed_adapter_builds"],
        "expected_heads": x["expected_heads"],
    }
