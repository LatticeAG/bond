"""Canonicalization, strict JSON parsing, hashing — Bond spec §3.1, §3.5.

J(x) is restricted RFC 8785 canonical JSON over the spec's value subset
(null, boolean, nonnegative safe integers, NFC strings, arrays, objects
with keys sorted in UTF-16 code-unit order). H is lowercase SHA-256 hex.
D(kind, x) = H(UTF8("LAGI-BOND/"+kind+"/1\n") || J(x)).
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from typing import Any

ZERO_HASH = "0" * 64
MAX_SAFE_U = 9007199254740991
MAX_AMOUNT = 9223372036854775807

DOMAIN_KINDS = (
    "action", "plan", "entry", "receipt", "paper",
    "assertion", "request", "notice", "draft-store",
)


class BondError(Exception):
    """Protocol error carrying a Bond code, never a raw library string."""

    def __init__(self, code: str, msg: str = ""):
        super().__init__(msg or code)
        self.code = code
        self.msg = msg or code


def _fail(msg: str = "invalid JSON") -> None:
    raise BondError("SCHEMA", msg)


def _has_lone_surrogate(s: str) -> bool:
    return any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def _dump_str(s: str) -> str:
    # Same minimal escaping as JSON.stringify / JSON.stringify keys.
    if _has_lone_surrogate(s):
        _fail("lone surrogate")
    return json.dumps(s, ensure_ascii=False)


def J(x: Any) -> str:
    """Restricted RFC 8785 canonical JSON. Raises BondError("SCHEMA")."""
    if x is None:
        return "null"
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, str):
        return _dump_str(x)
    if isinstance(x, int):
        if x < 0 or x > MAX_SAFE_U:
            raise BondError("SCHEMA", "integer outside nonnegative safe range")
        return str(x)
    if isinstance(x, list):
        return "[" + ",".join(J(v) for v in x) + "]"
    if isinstance(x, dict):
        # UTF-16 code-unit order: big-endian code units compare byte-wise.
        keys = sorted(x.keys(), key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(_dump_str(k) + ":" + J(x[k]) for k in keys) + "}"
    raise BondError("SCHEMA", "unsupported value in canonical JSON")


def canonicalize(value: Any) -> bytes:
    return J(value).encode("utf-8")


def H(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def D(kind: str, x: Any) -> str:
    return H("LAGI-BOND/" + kind + "/1\n" + J(x))


def deep_equal(a: Any, b: Any) -> bool:
    return J(a) == J(b)


# ---------------------------------------------------------------------------
# Strict JSON parser. Rejects: invalid UTF-8, BOM, trailing data, duplicate
# keys, non-integer numeric tokens, integers above 2^53-1, unpaired
# surrogates, non-NFC text, and resource-limit overflows.
# ---------------------------------------------------------------------------

class ParseLimits:
    def __init__(self, max_bytes: int, max_depth: int, max_members: int):
        self.max_bytes = max_bytes
        self.max_depth = max_depth
        self.max_members = max_members


CONTROL_LIMITS = ParseLimits(65536, 16, 1024)
PACKAGE_LIMITS = ParseLimits(8388608, 16, 1024)
PACKAGE_LIMITS.max_entries = 256
PACKAGE_LIMITS.max_receipts = 256
PACKAGE_LIMITS.max_blobs = 64
PACKAGE_LIMITS.max_blob_bytes = 2097152

_WS = frozenset(" \t\n\r")


class _Parser:
    def __init__(self, text: str, lim: ParseLimits):
        self.text = text
        self.lim = lim
        self.pos = 0
        self.members = 0

    def ws(self) -> None:
        t = self.text
        while self.pos < len(t) and t[self.pos] in _WS:
            self.pos += 1

    def parse(self) -> Any:
        self.ws()
        v = self.value(0)
        self.ws()
        if self.pos != len(self.text):
            _fail("trailing data")
        return v

    def value(self, depth: int) -> Any:
        if depth > self.lim.max_depth:
            raise BondError("LIMIT", "depth exceeded")
        if self.pos >= len(self.text):
            _fail("unexpected end")
        c = self.text[self.pos]
        if c == "{":
            return self.object(depth)
        if c == "[":
            return self.array(depth)
        if c == '"':
            return self.string()
        if self.text.startswith("true", self.pos):
            self.pos += 4
            return True
        if self.text.startswith("false", self.pos):
            self.pos += 5
            return False
        if self.text.startswith("null", self.pos):
            self.pos += 4
            return None
        return self.number()

    def number(self) -> int:
        t = self.text
        start = self.pos
        if self.pos < len(t) and t[self.pos] == "0":
            self.pos += 1
        elif self.pos < len(t) and "1" <= t[self.pos] <= "9":
            while self.pos < len(t) and "0" <= t[self.pos] <= "9":
                self.pos += 1
        else:
            _fail("invalid number token")
        if self.pos < len(t) and t[self.pos] in ".eE+-":
            _fail("non-integer numeric token")
        n = int(t[start:self.pos])
        if n > MAX_SAFE_U:
            _fail("integer out of range")
        return n

    def string(self) -> str:
        t = self.text
        self.pos += 1
        out: list[str] = []
        while True:
            if self.pos >= len(t):
                _fail("unterminated string")
            c = t[self.pos]
            o = ord(c)
            if o == 0x22:
                self.pos += 1
                s = "".join(out)
                if _has_lone_surrogate(s):
                    _fail("unpaired surrogate")
                return s
            if o == 0x5C:
                self.pos += 1
                if self.pos >= len(t):
                    _fail("bad escape")
                e = t[self.pos]
                self.pos += 1
                if e in '"\\/':
                    out.append(e)
                elif e == "b":
                    out.append("\b")
                elif e == "f":
                    out.append("\f")
                elif e == "n":
                    out.append("\n")
                elif e == "r":
                    out.append("\r")
                elif e == "t":
                    out.append("\t")
                elif e == "u":
                    cp = self._hex4()
                    if 0xD800 <= cp <= 0xDBFF:
                        if t[self.pos:self.pos + 2] != "\\u":
                            _fail("unpaired surrogate")
                        self.pos += 2
                        lo = self._hex4()
                        if not 0xDC00 <= lo <= 0xDFFF:
                            _fail("unpaired surrogate")
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                        out.append(chr(cp))
                    elif 0xDC00 <= cp <= 0xDFFF:
                        _fail("unpaired surrogate")
                    else:
                        out.append(chr(cp))
                else:
                    _fail("bad escape")
            else:
                if o < 0x20:
                    _fail("unescaped control character")
                out.append(c)
                self.pos += 1

    def _hex4(self) -> int:
        h = self.text[self.pos:self.pos + 4]
        if not re.fullmatch(r"[0-9a-fA-F]{4}", h):
            _fail("bad \\u escape")
        self.pos += 4
        return int(h, 16)

    def object(self, depth: int) -> dict:
        t = self.text
        self.pos += 1
        self.ws()
        o: dict[str, Any] = {}
        if self.pos < len(t) and t[self.pos] == "}":
            self.pos += 1
            return o
        while True:
            self.ws()
            if self.pos >= len(t) or t[self.pos] != '"':
                _fail("expected object key")
            k = self.string()
            self.members += 1
            if self.members > self.lim.max_members:
                raise BondError("LIMIT", "member count exceeded")
            if k in o:
                _fail("duplicate key")
            self.ws()
            if self.pos >= len(t) or t[self.pos] != ":":
                _fail("expected ':'")
            self.pos += 1
            self.ws()
            o[k] = self.value(depth + 1)
            self.ws()
            if self.pos >= len(t):
                _fail("expected ',' or '}'")
            c = t[self.pos]
            if c == ",":
                self.pos += 1
                continue
            if c == "}":
                self.pos += 1
                return o
            _fail("expected ',' or '}'")

    def array(self, depth: int) -> list:
        t = self.text
        self.pos += 1
        self.ws()
        a: list[Any] = []
        if self.pos < len(t) and t[self.pos] == "]":
            self.pos += 1
            return a
        while True:
            a.append(self.value(depth + 1))
            self.ws()
            if self.pos >= len(t):
                _fail("expected ',' or ']'")
            c = t[self.pos]
            if c == ",":
                self.pos += 1
                continue
            if c == "]":
                self.pos += 1
                return a
            _fail("expected ',' or ']'")


def parse_json_bytes(data: bytes, lim: ParseLimits = CONTROL_LIMITS) -> Any:
    if len(data) > lim.max_bytes:
        raise BondError("LIMIT", "input exceeds byte bound")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise BondError("SCHEMA", "invalid UTF-8")
    if len(text) == 0:
        raise BondError("SCHEMA", "empty input")
    if ord(text[0]) == 0xFEFF:
        raise BondError("SCHEMA", "BOM not allowed")
    if not unicodedata.is_normalized("NFC", text):
        raise BondError("SCHEMA", "input not NFC")
    return _Parser(text, lim).parse()


def parse_json(text: str, lim: ParseLimits = CONTROL_LIMITS) -> Any:
    return parse_json_bytes(text.encode("utf-8"), lim)


# ---------------------------------------------------------------------------
# Canonical base64url (unpadded), verified by decode/re-encode equality.
# ---------------------------------------------------------------------------

import base64

_B64U_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(s: str) -> bytes:
    if not isinstance(s, str) or not _B64U_RE.match(s) or len(s) % 4 == 1:
        raise BondError("SCHEMA", "noncanonical base64url")
    b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if b64u_encode(b) != s:
        raise BondError("SCHEMA", "noncanonical base64url")
    return b


def is_b64u(s: Any) -> bool:
    if not isinstance(s, str) or not _B64U_RE.match(s) or len(s) % 4 == 1:
        return False
    try:
        return b64u_encode(b64u_decode(s)) == s
    except BondError:
        return False


# ---------------------------------------------------------------------------
# Time: valid UTC YYYY-MM-DDTHH:mm:ss.sssZ — no offsets, no leap seconds.
# ---------------------------------------------------------------------------

from datetime import datetime, timezone

_TIME_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z$")


def is_time(x: Any) -> bool:
    if not isinstance(x, str) or not _TIME_RE.match(x):
        return False
    try:
        time_ms(x)
        return True
    except BondError:
        return False


def time_ms(t: str) -> int:
    m = _TIME_RE.match(t)
    if not m:
        raise BondError("SCHEMA", "invalid time")
    y, mo, d, hh, mm, ss, ms = (int(g) for g in m.groups())
    try:
        dt = datetime(y, mo, d, hh, mm, ss, ms * 1000, tzinfo=timezone.utc)
    except ValueError:
        raise BondError("SCHEMA", "invalid time")
    return int(dt.timestamp() * 1000)


def is_amount(x: Any) -> bool:
    return isinstance(x, str) and re.fullmatch(r"(0|[1-9][0-9]*)", x) is not None \
        and int(x) <= MAX_AMOUNT


def is_hash(x: Any) -> bool:
    return isinstance(x, str) and re.fullmatch(r"[0-9a-f]{64}", x) is not None


def is_u(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and 0 <= x <= MAX_SAFE_U


def is_external_id(x: Any) -> bool:
    return isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9:_-]{1,96}", x) is not None


def is_resource_segment(seg: str) -> bool:
    return re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}", seg) is not None \
        and seg not in (".", "..") and "%" not in seg and "\\" not in seg


_ID_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz-"
ID_PREFIXES = ("bnt", "bns", "bnp", "bac", "brc", "bnq", "bnk", "bni", "bnj")
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{21}$")


def is_bond_id(x: Any, prefix: str) -> bool:
    return isinstance(x, str) and x.startswith(prefix + "_") and \
        _ID_RE.match(x[len(prefix) + 1:]) is not None
