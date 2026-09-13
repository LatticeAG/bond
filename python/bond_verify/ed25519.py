"""Ed25519 strict verification — Bond spec §3.5.

Rejects noncanonical points, small-order public keys/R, S >= L, wrong
lengths, and never attempts Ed25519ph. Point decoding is a direct integer
implementation of RFC 8032 so it is byte-for-byte identical to the TS port;
the signature equation itself is checked by the `cryptography` package.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

P = (1 << 255) - 19
L = (1 << 252) + 27742317777372353535851937790883648493
ED_D = (P - 121665) * pow(121666, P - 2, P) % P
ED_I = pow(2, (P - 1) // 4, P)  # sqrt(-1) mod p

IDENTITY = (0, 1)
BASE = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)


def _ed_add(a: tuple[int, int], b: tuple[int, int]) -> tuple[int, int]:
    ax, ay = a
    bx, by = b
    t = ED_D * ax * bx * ay * by % P
    x = ((ax * by + bx * ay) % P) * pow(1 + t, P - 2, P) % P
    y = ((ay * by + ax * bx) % P) * pow(1 - t, P - 2, P) % P
    return (x, y)


def _ed_mul(p: tuple[int, int], n: int) -> tuple[int, int]:
    r = IDENTITY
    q = p
    while n > 0:
        if n & 1:
            r = _ed_add(r, q)
        q = _ed_add(q, q)
        n >>= 1
    return r


def _le_int(b: bytes) -> int:
    return int.from_bytes(b, "little")


def decode_point(b: bytes) -> tuple[int, int] | None:
    """Strict RFC 8032 point decoding; None when undecodable."""
    if len(b) != 32:
        return None
    sign = (b[31] & 0x80) != 0
    y = _le_int(b[:31] + bytes([b[31] & 0x7F]))
    if y >= P:
        return None
    yy = y * y % P
    u = (yy - 1 + P) % P
    v = (ED_D * yy + 1) % P
    x = u * pow(v, 3, P) % P * pow(u * pow(v, 7, P) % P, (P - 5) // 8, P) % P
    if x * x % P * v % P != u:
        x = x * ED_I % P
        if x * x % P * v % P != u:
            return None
    if x == 0 and sign:
        return None
    if (x & 1) != (1 if sign else 0):
        x = P - x
    return (x, y)


def is_small_order(p: tuple[int, int]) -> bool:
    q = _ed_mul(p, 8)
    return q == IDENTITY


def verify_strict(message: bytes, sig: bytes, public_key: bytes) -> bool:
    """Strict Ed25519 verify: canonical decodings, no small-order, S < L."""
    if len(sig) != 64 or len(public_key) != 32:
        return False
    if _le_int(sig[32:64]) >= L:
        return False
    r = decode_point(sig[0:32])
    a = decode_point(public_key)
    if r is None or a is None:
        return False
    if is_small_order(r) or is_small_order(a):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(sig, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def public_key_hex_from_seed(seed_hex: str) -> str:
    """Derive the public key for a 32-byte Ed25519 seed (hex)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
