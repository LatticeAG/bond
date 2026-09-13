"""Canonicalization + strict-parser vectors (spec §3.1)."""

from __future__ import annotations

import pytest

from bond_verify import (
    BondError, D, H, J, b64u_decode, b64u_encode, canonicalize, digest,
    is_amount, is_b64u, is_bond_id, is_hash, is_time, is_u, parse_json,
    parse_json_bytes, time_ms,
)


class TestCanon:
    def test_scalars(self):
        assert J(None) == "null"
        assert J(True) == "true"
        assert J(False) == "false"
        assert J(0) == "0"
        assert J(9007199254740991) == "9007199254740991"
        assert J("abc") == '"abc"'
        assert canonicalize([1, "a", None]) == b'[1,"a",null]'

    def test_key_order_utf16(self):
        # UTF-16 code-unit order: a supplementary-plane key (D800 DC00) sorts
        # after every BMP key below 0xD800 — "z" (0x7A) first.
        assert J({"b": 1, "a": 2}) == '{"a":2,"b":1}'
        assert J({"\U00010000": 1, "z": 2}) == '{"z":2,"\U00010000":1}'
        assert J({"Z": 1, "a": 2}) == '{"Z":1,"a":2}'

    def test_string_escapes(self):
        assert J('a"b') == '"a\\"b"'
        assert J("a\nb") == '"a\\nb"'
        assert J("café") == '"café"'  # non-ASCII passes through unescaped

    def test_rejections(self):
        with pytest.raises(BondError):
            J(-1)
        with pytest.raises(BondError):
            J(2**53)
        with pytest.raises(BondError):
            J(1.5)
        with pytest.raises(BondError):
            J({"k": float("nan")})
        with pytest.raises(BondError):
            J("\ud800")  # lone surrogate
        with pytest.raises(BondError):
            J({"\udfff": 1})

    def test_digest_domains(self, fixture):
        # Cross-language golden: action hash from the normative fixture.
        assert D("action", fixture["action"]) == fixture["ah"]
        assert digest("action", fixture["action"]) == fixture["ah"]
        with pytest.raises(BondError):
            digest("bogus", {})


class TestStrictParser:
    def test_roundtrip(self):
        assert parse_json('{"a":[1,true,null],"b":"x"}') == \
            {"a": [1, True, None], "b": "x"}

    def test_reject_invalid(self):
        bad = [
            b"",                          # empty
            b"\xef\xbb\xbf{}",            # BOM
            b"{} {}",                     # trailing data
            b'{"a":1,"a":2}',             # duplicate key
            b"01",                        # leading zero
            b"-1",                        # negative
            b"1.0",                       # fraction
            b"1e3",                       # exponent
            b"9007199254740992",          # > 2^53-1
            b'"\\ud800"',                 # lone high surrogate
            b'"\\udc00"',                 # lone low surrogate
            b'"\\ud800x"',                # unpaired surrogate
            b'{"a":01}',                  # bad int
            b'{"a" 1}',                   # missing colon
            b'{"a":1,}',                  # trailing comma
            b"[1,]",                      # trailing comma
            b'"a\nb"',                    # raw control char
            "café".encode("utf-8")[:-1],  # truncated UTF-8
            '{"x":"é"}'.encode(),       # non-NFC text
        ]
        for raw in bad:
            with pytest.raises(BondError):
                parse_json_bytes(raw)

    def test_limits(self):
        deep = "[" * 18 + "]" * 18  # innermost value at depth 17 > limit 16
        with pytest.raises(BondError) as e:
            parse_json(deep)
        assert e.value.code == "LIMIT"
        deep_ok = "[" * 17 + "]" * 17
        assert parse_json(deep_ok) is not None
        wide = "{" + ",".join(f'"k{i}":0' for i in range(1025)) + "}"
        with pytest.raises(BondError) as e:
            parse_json(wide)
        assert e.value.code == "LIMIT"
        with pytest.raises(BondError) as e:
            parse_json_bytes(b" " * 65537)
        assert e.value.code in ("LIMIT", "SCHEMA")

    def test_surrogate_pair_ok(self):
        assert parse_json('"\\ud800\\udc00"') == "\U00010000"


class TestEncodings:
    def test_b64u(self):
        assert b64u_encode(b"hello") == "aGVsbG8"
        assert b64u_decode("aGVsbG8") == b"hello"
        assert is_b64u("aGVsbG8")
        assert not is_b64u("aGVsbG8=")      # padded
        assert not is_b64u("a")             # len%4==1
        assert not is_b64u("aGVsbG8!")

    def test_time(self):
        assert is_time("2026-09-12T12:00:00.000Z")
        assert not is_time("2026-09-12T12:00:00Z")     # no ms
        assert not is_time("2026-09-12T12:00:00.000+00:00")
        assert not is_time("2026-13-01T00:00:00.000Z")  # month 13
        assert time_ms("1970-01-01T00:00:00.000Z") == 0

    def test_ids(self):
        assert is_bond_id("bac_" + "0" * 21, "bac")
        assert not is_bond_id("bac_" + "0" * 20, "bac")
        assert not is_bond_id("bnt_" + "0" * 21, "bac")
        assert is_hash("a" * 64)
        assert not is_hash("A" * 64)
        assert is_amount("1000")
        assert not is_amount("0100")
        assert not is_amount("-5")
        assert is_u(0) and is_u(2**53 - 1) and not is_u(2**53) and not is_u(-1)

    def test_hash_golden(self):
        assert H(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
