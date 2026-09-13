"""Offline certificate-package verification (§6.3). Verification order:
resource bounds → parse/schema → key-role pins → object digests/signatures
→ hash linkage → binding integrity → evidence validation → receipt
recomputation → anchoring → completeness. Never trusts issuer claims."""

from __future__ import annotations

from .canon import (
    BondError, H, J, PACKAGE_LIMITS, ZERO_HASH, deep_equal, parse_json_bytes,
)
from .evidence import parse_blob, verify_source
from .reducer import (
    MissingEvidence, apply_entry, assembly_of, remedy_state, residual_effect,
    to_view,
)
from .schema import (
    check_paper_consistency, v_action, v_assertion, v_blob, v_entry_body,
    v_paper_review, v_receipt_body, v_signed, v_undo_plan,
)
from .sign import verify_signed

TRUTH = "ISSUER_ASSERTIONS_NOT_REAL_WORLD_PROOF"


def _result(integrity: str, completeness: str, currentness: str,
            head, errors: list) -> dict:
    return {
        "integrity": integrity,
        "completeness": completeness,
        "currentness": currentness,
        "simulation": True,
        "insurance": "PAPER_ONLY",
        "truth": TRUTH,
        "head": head,
        "errors": errors,
    }


def verify_package(pkg_bytes: bytes, trust: dict, expected_head=None,
                   source_verifiers: dict | None = None) -> dict:
    errors: list[str] = []
    try:
        if len(pkg_bytes) > PACKAGE_LIMITS.max_bytes:
            raise BondError("LIMIT", "package bytes")
        o = parse_json_bytes(pkg_bytes, PACKAGE_LIMITS)
        if not isinstance(o, dict):
            raise BondError("SCHEMA")
        if o.get("schema") != "bond.package/1":
            raise BondError("UNSUPPORTED_VERSION")
        if not isinstance(o.get("receipts"), list) \
                or not isinstance(o.get("entries"), list) \
                or not isinstance(o.get("blobs"), list):
            raise BondError("SCHEMA")
        if len(o["entries"]) == 0:
            raise BondError("SCHEMA", "empty package")
        if (len(o["entries"]) > PACKAGE_LIMITS.max_entries
                or len(o["receipts"]) > PACKAGE_LIMITS.max_receipts
                or len(o["blobs"]) > PACKAGE_LIMITS.max_blobs):
            raise BondError("LIMIT", "package member counts")

        entries = [v_signed(e, "entry", v_entry_body) for e in o["entries"]]
        receipts = [v_signed(r, "receipt", v_receipt_body) for r in o["receipts"]]
        blobs: dict[str, dict] = {}
        for b_raw in o["blobs"]:
            b = v_blob(b_raw)
            if b["data"] is not None and b["bytes"] > PACKAGE_LIMITS.max_blob_bytes:
                raise BondError("LIMIT", "blob bytes")
            if b["hash"] in blobs:
                raise BondError("SCHEMA", "duplicate blob")
            blobs[b["hash"]] = b

        b0 = entries[0]["body"]
        tenant_id = b0["tenant_id"]
        action_id = b0["action_id"]
        action_hash = b0["action_hash"]

        prev_entry_hash = ZERO_HASH
        for i, e in enumerate(entries):
            verify_signed("entry", e, trust, tenant_id)
            eb = e["body"]
            if (eb["seq"] != i + 1 or eb["previous_hash"] != prev_entry_hash
                    or eb["tenant_id"] != tenant_id or eb["action_id"] != action_id
                    or eb["action_hash"] != action_hash):
                raise BondError("CHAIN_INVALID", "entry linkage")
            prev_entry_hash = e["hash"]

        if len(receipts) != len(entries):
            raise BondError("PROJECTION_INVALID", "receipts do not cover entries")
        prev_receipt_hash = None
        for i, r in enumerate(receipts):
            verify_signed("receipt", r, trust, tenant_id)
            rb = r["body"]
            if (rb["revision"] != i + 1
                    or rb["previous_receipt_hash"] != prev_receipt_hash
                    or rb["tenant_id"] != tenant_id or rb["action_id"] != action_id
                    or rb["action_hash"] != action_hash
                    or rb["receipt_id"] != receipts[0]["body"]["receipt_id"]
                    or rb["head"]["seq"] != i + 1
                    or rb["head"]["hash"] != entries[i]["hash"]):
                raise BondError("CHAIN_INVALID", "receipt linkage")
            prev_receipt_hash = r["hash"]

        receipt_id = receipts[0]["body"]["receipt_id"]
        binding = receipts[0]["body"]["binding"]
        for r in receipts:
            if not deep_equal(r["body"]["binding"], binding):
                raise BondError("PROJECTION_INVALID", "binding changed mid-chain")

        # Binding integrity: resolve action/plan/paper blobs.
        incomplete = False

        def get_blob(ref):
            b = blobs.get(ref["hash"])
            if (not b or b["data"] is None or b["bytes"] != ref["bytes"]
                    or b["media_type"] != ref["media_type"]):
                return None
            return b

        action_blob = get_blob(binding["action"])
        plan_blob = get_blob(binding["plan"])
        paper_blob = get_blob(binding["paper"])
        if not action_blob or not plan_blob or not paper_blob:
            incomplete = True

        action = plan = None
        if action_blob and plan_blob:
            action = v_action(parse_json_bytes(parse_blob(action_blob), PACKAGE_LIMITS))
            plan = v_undo_plan(parse_json_bytes(parse_blob(plan_blob), PACKAGE_LIMITS))
            if action["action_id"] != action_id or action["tenant_id"] != tenant_id:
                raise BondError("PROJECTION_INVALID", "action binding mismatch")
            if (plan["action_hash"] != action_hash
                    or plan["resource"] != action["resource"]
                    or plan["adapter_build"] != action["adapter_build"]
                    or plan["value_hash"] != H(J(action["draft"]))
                    or plan["expires_at"] != action["terms"]["long_stop"]):
                raise BondError("PROJECTION_INVALID", "plan binding mismatch")
        if paper_blob and action:
            paper = v_signed(parse_json_bytes(parse_blob(paper_blob), PACKAGE_LIMITS),
                             "paper", v_paper_review)
            verify_signed("paper", paper, trust, tenant_id)
            check_paper_consistency(paper["body"], action)

        # Evidence validation + replay.
        ev_cache: dict[str, dict] = {}

        def resolve_evidence(ref):
            cached = ev_cache.get(ref["hash"])
            if cached:
                return cached
            blob = blobs.get(ref["hash"])
            if not blob or blob["data"] is None:
                return None
            try:
                data = parse_blob(blob)
            except BondError:
                raise BondError("HASH_MISMATCH", "evidence blob")
            assertion = v_signed(parse_json_bytes(data, PACKAGE_LIMITS),
                                 "assertion", v_assertion)
            verify_signed("assertion", assertion, trust, tenant_id)
            if assertion["body"]["action_hash"] != action_hash:
                raise BondError("PROJECTION_INVALID", "assertion action binding")
            src_blob = blobs.get(assertion["body"]["source"]["hash"])
            if not src_blob or src_blob["data"] is None:
                return None  # source bytes missing: incomplete
            src_bytes = parse_blob(src_blob)
            verify_source(assertion["body"]["facts"], assertion["body"],
                          src_bytes, trust, tenant_id, source_verifiers)
            out = {"facts": assertion["body"]["facts"], "evidenceHash": ref["hash"]}
            ev_cache[ref["hash"]] = out
            return out

        env = ({"action": action, "plan": plan, "binding": binding,
                "resolve": resolve_evidence}
               if action and plan else None)

        st = None
        replay_ok = env is not None
        for i, entry in enumerate(entries):
            if env is None:
                break
            try:
                st, _ = apply_entry(st, entry["body"], entry["hash"], env, "verify")
            except MissingEvidence:
                incomplete = True
                replay_ok = False
                break
            st["receiptId"] = receipt_id
            rb = receipts[i]["body"]
            if not deep_equal(to_view(st), rb["view"]):
                raise BondError("PROJECTION_INVALID",
                                f"view mismatch at revision {i + 1}")
            if not deep_equal(st["evidenceRefs"], rb["evidence"]):
                raise BondError("PROJECTION_INVALID",
                                f"evidence list mismatch at revision {i + 1}")
            if (residual_effect(st) != rb["residual_effect"]
                    or remedy_state(st) != rb["remedy"]):
                raise BondError("PROJECTION_INVALID",
                                f"residual/remedy mismatch at revision {i + 1}")
            if assembly_of(st, True) != rb["assembly"]:
                raise BondError("PROJECTION_INVALID",
                                f"assembly mismatch at revision {i + 1}")
        if incomplete and "INCOMPLETE" not in errors:
            errors.append("INCOMPLETE")

        # Anchoring: a non-null expected head must equal the verified head.
        head = {"seq": entries[-1]["body"]["seq"], "hash": entries[-1]["hash"]}
        currentness = "UNANCHORED_PREFIX"
        if expected_head is not None:
            if (expected_head["seq"] != head["seq"]
                    or expected_head["hash"] != head["hash"]):
                raise BondError("CHAIN_INVALID",
                                "expected head does not anchor this prefix")
            currentness = "PINNED_PREFIX"

        completeness = (
            "COMPLETE"
            if (not incomplete and st is not None
                and assembly_of(st, True) == "COMPLETE"
                and receipts[-1]["body"]["assembly"] == "COMPLETE")
            else "INCOMPLETE"
        )
        return _result("VALID", completeness, currentness, head, errors)
    except BondError as e:
        return _result("INVALID", "INCOMPLETE", "UNANCHORED_PREFIX", None, [e.code])
