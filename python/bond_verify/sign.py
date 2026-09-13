"""Signed-object helpers — signature domains, trust-key pinning (§3.5),
and HTTP proof-of-possession auth (§6.4)."""

from __future__ import annotations

from typing import Any, Callable

from .canon import BondError, D, b64u_decode, b64u_encode, time_ms
from .ed25519 import verify_strict

Signer = Callable[[bytes], bytes]


def seed_signer(seed_hex: str) -> Signer:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    seed = bytes.fromhex(seed_hex)
    if len(seed) != 32:
        raise BondError("SCHEMA", "seed must be 32 bytes")
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    return lambda m: sk.sign(m)


def sign_object(kind: str, body: Any, key_id: str, signer: Signer) -> dict:
    """Sign `body` under Bond domain `kind`: hash = D(kind,{body,key_id})."""
    h = D(kind, {"body": body, "key_id": key_id})
    sig = b64u_encode(signer(f"LAGI-BOND/sign/{kind}/1\n{h}".encode()))
    return {"body": body, "key_id": key_id, "hash": h, "sig": sig}


_SIGNED_AT = {
    "entry": "recorded_at", "receipt": "issued_at", "paper": "reviewed_at",
    "assertion": "observed_at", "notice": "recorded_at",
    "draft-store": "observed_at", "request": "issued_at",
}

KIND_ROLE = {
    "entry": "entry", "receipt": "receipt", "paper": "paper",
    "assertion": "assertion", "notice": "notice", "http": "http",
    "draft-store": "draft-store", "request": "http",
}


def trust_keys(trust: dict, kind: str, tenant_id: str, at: str) -> list[dict]:
    """Keys authorized for (kind-role, tenant, signed-at). `key_id` on the
    signed object is a label; selection is by trust pins and the signature
    itself is the proof."""
    role = KIND_ROLE.get(kind)
    if role is None:
        raise BondError("UNTRUSTED_KEY", "no role for kind " + kind)
    try:
        t = time_ms(at) if isinstance(at, str) else None
    except BondError:
        t = None  # absent/invalid signed-at: the time pin cannot exclude
    out = []
    for k in trust["keys"]:
        if k["tenant_id"] != tenant_id or role not in k["roles"]:
            continue
        if t is not None:
            if not (time_ms(k["not_before"]) <= t <= time_ms(k["not_after"])):
                continue
            if k["compromised_at"] is not None and t >= time_ms(k["compromised_at"]):
                continue
        out.append(k)
    return out


def verify_signed(kind: str, signed: dict, trust: dict, tenant_id: str) -> None:
    """Key-role pin first, then recomputed hash, then strict Ed25519."""
    keys = trust_keys(trust, kind, tenant_id,
                      signed["body"].get(_SIGNED_AT.get(kind, "")))
    if kind == "assertion":
        a = signed["body"]
        keys = [k for k in keys
                if a["facts"]["kind"] in k["assertion_kinds"]
                and a["source_profile"] in k["source_profiles"]]
    if not keys:
        raise BondError("UNTRUSTED_KEY", f"no trusted key for {kind}")
    expected = D(kind, {"body": signed["body"], "key_id": signed["key_id"]})
    if expected != signed["hash"]:
        raise BondError("HASH_MISMATCH", f"{kind} hash")
    msg = f"LAGI-BOND/sign/{kind}/1\n{signed['hash']}".encode()
    sig = b64u_decode(signed["sig"])
    if not any(verify_strict(msg, sig, bytes.fromhex(k["public_key_hex"]))
               for k in keys):
        raise BondError("SIGNATURE_INVALID", f"{kind} signature")


def verify_http_auth(auth: dict, trust: dict, now: str) -> None:
    """HTTP request-domain auth verification (§6.4)."""
    unsigned = {k: v for k, v in auth.items() if k != "sig"}
    keys = trust_keys(trust, "request", auth["tenant_id"], auth["issued_at"])
    t_i, t_e, t_n = time_ms(auth["issued_at"]), time_ms(auth["expires_at"]), time_ms(now)
    if t_i > t_n + 60000:
        raise BondError("CLOCK_UNSAFE", "issued_at beyond allowed skew")
    if not (t_i < t_e <= t_i + 300000):
        raise BondError("SCHEMA", "invalid auth window")
    if t_n >= t_e:
        raise BondError("DEADLINE", "auth expired")
    if not keys:
        raise BondError("UNTRUSTED_KEY", "no http key")
    h = D("request", unsigned)
    msg = f"LAGI-BOND/sign/request/1\n{h}".encode()
    sig = b64u_decode(auth["sig"])
    if not any(verify_strict(msg, sig, bytes.fromhex(k["public_key_hex"]))
               for k in keys):
        raise BondError("SIGNATURE_INVALID", "request signature")


def decode_http_auth(header: str) -> bytes:
    raw = b64u_decode(header)
    if len(raw) > 8192:
        raise BondError("LIMIT", "auth header too large")
    return raw


def encode_http_auth(auth: dict) -> str:
    from .canon import canonicalize
    return b64u_encode(canonicalize(auth))
