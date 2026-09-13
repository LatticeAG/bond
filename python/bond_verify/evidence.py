"""Evidence verification and construction (§3.3, §3.5). An evidence
artifact is a signed Assertion whose `source` ref pins the native source
bytes. Supported OSS source profiles: `fixture/1` (source bytes = J(facts))
and `bond.draft-store/1` (source bytes = J(Signed<DraftStoreRecord>)).
Native upstream profiles require an installed profile verifier; without
one the result is UNSUPPORTED_COMPOSITION."""

from __future__ import annotations

from typing import Any, Callable

from .canon import (
    BondError, H, J, PACKAGE_LIMITS, b64u_decode, b64u_encode, deep_equal,
    parse_json_bytes,
)
from .schema import v_assertion, v_blob, v_draft_store_record, v_signed
from .sign import Signer, sign_object, verify_signed


def blob_of(data: bytes, media_type: str) -> dict:
    return {
        "hash": H(data),
        "bytes": len(data),
        "media_type": media_type,
        "data": b64u_encode(data),
    }


def ref_of(b: dict) -> dict:
    return {"hash": b["hash"], "bytes": b["bytes"], "media_type": b["media_type"]}


def json_blob(x: Any) -> dict:
    return blob_of(J(x).encode("utf-8"), "application/json")


def parse_blob(b: dict) -> bytes:
    if b["data"] is None:
        raise BondError("INCOMPLETE", "blob bytes absent")
    raw = b64u_decode(b["data"])
    if len(raw) != b["bytes"] or H(raw) != b["hash"]:
        raise BondError("HASH_MISMATCH", "blob content")
    return raw


def verify_source(facts: dict, assertion: dict, source_bytes: bytes,
                  trust: dict, tenant_id: str,
                  source_verifiers: dict | None = None) -> None:
    """Verify native source bytes against asserted facts."""
    profile = assertion["source_profile"]
    if profile == "fixture/1":
        if J(facts).encode("utf-8") != source_bytes:
            raise BondError("PROJECTION_INVALID",
                            "fixture source does not match facts")
        return
    if profile == "bond.draft-store/1":
        parsed = v_signed(parse_json_bytes(source_bytes, PACKAGE_LIMITS),
                          "draft-store", v_draft_store_record)
        verify_signed("draft-store", parsed, trust, tenant_id)
        if (parsed["body"]["action_hash"] != assertion["action_hash"]
                or not deep_equal(parsed["body"]["facts"], facts)):
            raise BondError("PROJECTION_INVALID",
                            "draft-store record does not match assertion")
        return
    v = (source_verifiers or {}).get(profile)
    if v is None:
        raise BondError("UNSUPPORTED_COMPOSITION",
                        f"no verifier installed for source profile {profile}")
    v(facts, source_bytes, assertion, trust, tenant_id)


def verify_evidence(signed_assertion: dict, source_blob: dict, trust: dict,
                    tenant_id: str, expected_action_hash: str,
                    source_verifiers: dict | None = None) -> dict:
    """Full evidence verification against an action hash."""
    verify_signed("assertion", signed_assertion, trust, tenant_id)
    if signed_assertion["body"]["action_hash"] != expected_action_hash:
        raise BondError("PROJECTION_INVALID",
                        "assertion bound to different action")
    if source_blob["data"] is None:
        raise BondError("HASH_MISMATCH", "evidence source bytes")
    source_bytes = b64u_decode(source_blob["data"])
    src = signed_assertion["body"]["source"]
    if H(source_bytes) != src["hash"] or len(source_bytes) != src["bytes"]:
        raise BondError("HASH_MISMATCH", "evidence source bytes")
    verify_source(signed_assertion["body"]["facts"], signed_assertion["body"],
                  source_bytes, trust, tenant_id, source_verifiers)
    evidence_blob = json_blob(signed_assertion)
    return {
        "assertion": signed_assertion,
        "facts": signed_assertion["body"]["facts"],
        "source_bytes": source_bytes,
        "evidence_ref": ref_of(evidence_blob),
        "evidence_blob": evidence_blob,
    }


def make_fixture_evidence(facts: dict, action_hash: str, observed_at: str,
                          key_id: str, signer: Signer) -> dict:
    """Construct simulation evidence (fixture/1)."""
    source = json_blob(facts)
    assertion = sign_object("assertion", {
        "schema": "bond.assertion/1",
        "action_hash": action_hash,
        "observed_at": observed_at,
        "source_profile": "fixture/1",
        "source": ref_of(source),
        "facts": facts,
    }, key_id, signer)
    return {"assertion": assertion, "source": source}


def parse_assertion_blob(data: bytes) -> dict:
    return v_signed(parse_json_bytes(data, PACKAGE_LIMITS), "assertion", v_assertion)
