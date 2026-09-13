"""bond_verify — MIT Bond verification/interchange support (§1, §6.3).

Exposes canonicalization, digests, strict parsing, Ed25519 verification,
signed-object verification, package parsing/verification, and the pure
reduced-state projection. This package deliberately does NOT implement a
coordinator: no execution, no journal writes, no network.
"""

from __future__ import annotations

from .canon import (
    BondError,
    CONTROL_LIMITS,
    PACKAGE_LIMITS,
    ZERO_HASH,
    D,
    H,
    J,
    b64u_decode,
    b64u_encode,
    canonicalize,
    deep_equal,
    is_amount,
    is_b64u,
    is_bond_id,
    is_external_id,
    is_hash,
    is_time,
    is_u,
    parse_json,
    parse_json_bytes,
    time_ms,
)
from .ed25519 import (
    decode_point,
    is_small_order,
    public_key_hex_from_seed,
    verify_strict,
)
from .evidence import (
    blob_of,
    json_blob,
    make_fixture_evidence,
    parse_assertion_blob,
    parse_blob,
    ref_of,
    verify_evidence,
    verify_source,
)
from .reducer import (
    ForkSignal,
    MissingEvidence,
    apply_entry,
    assembly_of,
    clone_state,
    computed_disposition,
    deserialize_state,
    initial_state,
    op_key,
    pending_ops,
    project_kill,
    remedy_state,
    residual_effect,
    serialize_state,
    to_view,
)
from .schema import (
    check_paper_consistency,
    v_action,
    v_assertion,
    v_binding,
    v_blob,
    v_draft,
    v_draft_store_record,
    v_effect_facts,
    v_entry_body,
    v_facts,
    v_hold_facts,
    v_http_auth,
    v_kill_facts,
    v_no_hold_facts,
    v_notice,
    v_package,
    v_paper_review,
    v_policy_facts,
    v_policy_pin,
    v_receipt_body,
    v_run_facts,
    v_signed,
    v_terms,
    v_trust_file,
    v_undo_plan,
    v_view,
)
from .sign import (
    decode_http_auth,
    encode_http_auth,
    seed_signer,
    sign_object,
    trust_keys,
    verify_http_auth,
    verify_signed,
)
from .verify import verify_package


def canonicalize_value(value):
    """canonicalize(value) -> bytes (§8.2 Python API)."""
    return canonicalize(value)


def digest(kind: str, value) -> str:
    """digest(kind, value) -> str — the D() domain digest."""
    if kind not in ("action", "plan", "entry", "receipt", "paper",
                    "assertion", "request", "notice", "draft-store"):
        raise BondError("SCHEMA", "unknown digest domain " + str(kind))
    return D(kind, value)


def parse_package(data: bytes) -> dict:
    """Strict-parse and schema-validate a certificate package."""
    if len(data) > PACKAGE_LIMITS.max_bytes:
        raise BondError("LIMIT", "package bytes")
    pkg = v_package(parse_json_bytes(data, PACKAGE_LIMITS))
    pkg["entries"] = [v_signed(e, "entry", v_entry_body) for e in pkg["entries"]]
    pkg["receipts"] = [v_signed(r, "receipt", v_receipt_body)
                       for r in pkg["receipts"]]
    pkg["blobs"] = [v_blob(b) for b in pkg["blobs"]]
    return pkg


def parse_trust_file(data: bytes) -> dict:
    return v_trust_file(parse_json_bytes(data))


__all__ = [
    "BondError", "CONTROL_LIMITS", "PACKAGE_LIMITS", "ZERO_HASH",
    "D", "H", "J", "canonicalize", "canonicalize_value", "digest",
    "parse_package", "parse_trust_file", "parse_json", "parse_json_bytes",
    "b64u_decode", "b64u_encode", "deep_equal", "time_ms",
    "is_amount", "is_b64u", "is_bond_id", "is_external_id", "is_hash",
    "is_time", "is_u",
    "decode_point", "is_small_order", "public_key_hex_from_seed", "verify_strict",
    "blob_of", "json_blob", "ref_of", "parse_blob", "parse_assertion_blob",
    "make_fixture_evidence", "verify_evidence", "verify_source",
    "apply_entry", "assembly_of", "clone_state", "computed_disposition",
    "deserialize_state", "initial_state", "op_key", "pending_ops",
    "project_kill", "remedy_state", "residual_effect", "serialize_state",
    "to_view", "ForkSignal", "MissingEvidence",
    "check_paper_consistency", "seed_signer", "sign_object", "trust_keys",
    "verify_http_auth", "verify_signed", "verify_package",
    "decode_http_auth", "encode_http_auth",
    "v_action", "v_assertion", "v_binding", "v_blob", "v_draft",
    "v_draft_store_record", "v_effect_facts", "v_entry_body", "v_facts",
    "v_hold_facts", "v_http_auth", "v_kill_facts", "v_no_hold_facts",
    "v_notice", "v_package", "v_paper_review", "v_policy_facts",
    "v_policy_pin", "v_receipt_body", "v_run_facts", "v_signed", "v_terms",
    "v_trust_file", "v_undo_plan", "v_view",
]
