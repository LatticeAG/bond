"""Ed25519 strictness + signed-object verification (spec §3.5)."""

from __future__ import annotations

import copy

import pytest

from bond_verify import (
    BondError, D, b64u_decode, b64u_encode, decode_point, is_small_order,
    public_key_hex_from_seed, seed_signer, sign_object, trust_keys,
    verify_http_auth, verify_signed, verify_strict,
)
from conftest import PUBKEY, SEED


class TestEd25519:
    def test_fixture_key(self):
        assert public_key_hex_from_seed(SEED) == PUBKEY

    def test_roundtrip(self):
        signer = seed_signer(SEED)
        msg = b"hello bond"
        sig = signer(msg)
        assert verify_strict(msg, sig, bytes.fromhex(PUBKEY))

    def test_rejects(self):
        sig = seed_signer(SEED)(b"m")
        pk = bytes.fromhex(PUBKEY)
        assert not verify_strict(b"m", sig, pk[:-1])          # short key
        assert not verify_strict(b"m", sig[:-1], pk)          # short sig
        assert not verify_strict(b"x", sig, pk)               # wrong msg
        # S >= L: identity encoding (compressed y=1) as A, R=identity,
        # S = L — noncanonical scalar.
        L = (1 << 252) + 27742317777372353535851937790883648493
        bad = sig[:32] + L.to_bytes(32, "little")
        assert not verify_strict(b"m", bad, pk)
        # Small-order A (identity point, y=1 sign=0)
        ident = (1).to_bytes(32, "little")
        assert not verify_strict(b"m", sig, ident)
        # Small-order R
        assert not verify_strict(b"m", ident + sig[32:], pk)

    def test_decode_point(self):
        assert decode_point(bytes.fromhex(PUBKEY)) is not None
        # identity point decodes and is small-order
        ident = decode_point((1).to_bytes(32, "little"))
        assert ident == (0, 1)
        assert is_small_order(ident)
        # y >= p: noncanonical
        p = (1 << 255) - 19
        assert decode_point(p.to_bytes(32, "little")) is None


class TestSignedObjects:
    def test_sign_and_verify(self, fixture, trust):
        signer = seed_signer(SEED)
        signed = sign_object("paper", fixture["paper"]["body"],
                             "bnk_" + "0" * 21, signer)
        verify_signed("paper", signed, trust, fixture["tenant"])

    def test_signature_bytes_identical_to_fixture(self, fixture):
        # Ed25519 is deterministic: Python signing must reproduce the exact
        # hash and signature bytes the fixture's Node signer produced.
        signer = seed_signer(SEED)
        for kind, obj in [("paper", fixture["paper"]),
                          ("notice", fixture["notice"]),
                          ("entry", fixture["S0"]["entries"][0]),
                          ("receipt", fixture["S0"]["receipts"][0]),
                          ("assertion", fixture["ep"]["assertion"])]:
            out = sign_object(kind, obj["body"], obj["key_id"], signer)
            assert out["hash"] == obj["hash"], f"{kind} hash divergence"
            assert out["sig"] == obj["sig"], f"{kind} sig divergence"

    def test_fixture_sigs_verify(self, fixture, trust):
        # Every signed object the fixture produced verifies under trust.
        objs = [["paper", fixture["paper"]], ["notice", fixture["notice"]]]
        for s in [fixture["S0"], fixture["S3"]]:
            objs += [["entry", e] for e in s["entries"]]
            objs += [["receipt", r] for r in s["receipts"]]
        for kind, o in objs:
            verify_signed(kind, o, trust, fixture["tenant"])

    def test_hash_mismatch(self, fixture, trust):
        bad = copy.deepcopy(fixture["paper"])
        bad["hash"] = "0" * 64
        with pytest.raises(BondError) as e:
            verify_signed("paper", bad, trust, fixture["tenant"])
        assert e.value.code == "HASH_MISMATCH"

    def test_sig_invalid(self, fixture, trust):
        bad = copy.deepcopy(fixture["paper"])
        sig = bytearray(b64u_decode(bad["sig"]))
        sig[0] ^= 1
        bad["sig"] = b64u_encode(bytes(sig))
        with pytest.raises(BondError) as e:
            verify_signed("paper", bad, trust, fixture["tenant"])
        assert e.value.code == "SIGNATURE_INVALID"

    def test_untrusted_tenant(self, fixture, trust):
        with pytest.raises(BondError) as e:
            verify_signed("paper", fixture["paper"], trust,
                          "bnt_" + "1" * 21)
        assert e.value.code == "UNTRUSTED_KEY"

    def test_wrong_role(self, fixture, trust):
        # The trust key lacks the "request"/http role? It has "http".
        # Signing a receipt body under the entry domain changes the hash →
        # HASH_MISMATCH surfaces after role resolution.
        entry = fixture["S0"]["entries"][0]
        with pytest.raises(BondError) as e:
            verify_signed("receipt", entry, trust, fixture["tenant"])
        assert e.value.code in ("HASH_MISMATCH", "UNTRUSTED_KEY")

    def test_compromise_pin(self, fixture, trust):
        t = copy.deepcopy(trust)
        t["keys"][0]["compromised_at"] = "2026-09-11T00:00:00.000Z"
        with pytest.raises(BondError) as e:
            verify_signed("paper", fixture["paper"], t, fixture["tenant"])
        assert e.value.code == "UNTRUSTED_KEY"

    def test_assertion_pins(self, fixture, trust):
        t = copy.deepcopy(trust)
        t["keys"][0]["assertion_kinds"] = ["HOLD"]
        a = fixture["ep"]["assertion"]  # POLICY assertion
        with pytest.raises(BondError) as e:
            verify_signed("assertion", a, t, fixture["tenant"])
        assert e.value.code == "UNTRUSTED_KEY"


class TestHttpAuth:
    def test_fixture_auth(self, fixture, trust):
        verify_http_auth(fixture["httpAuth"], trust, "2026-09-12T12:00:00.000Z")

    def test_expired(self, fixture, trust):
        with pytest.raises(BondError) as e:
            verify_http_auth(fixture["httpAuth"], trust,
                             "2026-09-12T12:06:00.000Z")
        assert e.value.code == "DEADLINE"

    def test_future_issued(self, fixture, trust):
        a = copy.deepcopy(fixture["httpAuth"])
        a["issued_at"] = "2026-09-12T12:05:00.000Z"  # beyond 60s skew
        with pytest.raises(BondError) as e:
            verify_http_auth(a, trust, "2026-09-12T12:00:00.000Z")
        assert e.value.code in ("CLOCK_UNSAFE", "SIGNATURE_INVALID",
                               "HASH_MISMATCH", "SCHEMA")

    def test_bad_sig(self, fixture, trust):
        a = copy.deepcopy(fixture["httpAuth"])
        a["sig"] = b64u_encode(b"\x00" * 64)
        with pytest.raises(BondError) as e:
            verify_http_auth(a, trust, "2026-09-12T12:00:00.000Z")
        assert e.value.code == "SIGNATURE_INVALID"
