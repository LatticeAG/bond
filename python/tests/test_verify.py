"""Offline package verification parity (spec §6.3): golden packages from
the normative fixture plus mutation vectors."""

from __future__ import annotations

import copy

import pytest

from bond_verify import (
    J, BondError, parse_package, verify_package,
)


def pkg_bytes(pkg: dict) -> bytes:
    return J(pkg).encode("utf-8")


class TestGoldenPackages:
    def test_p0_valid(self, fixture, trust):
        v = verify_package(pkg_bytes(fixture["P0"]), trust, fixture["V0"]["head"])
        assert v == fixture["verify0"]
        assert v["integrity"] == "VALID"
        assert v["currentness"] == "PINNED_PREFIX"
        assert v["completeness"] == "INCOMPLETE"  # staged action, kill uncertified

    def test_p0_unanchored(self, fixture, trust):
        v = verify_package(pkg_bytes(fixture["P0"]), trust, None)
        assert v["integrity"] == "VALID"
        assert v["currentness"] == "UNANCHORED_PREFIX"

    def test_pc_complete(self, fixture, trust):
        v = verify_package(pkg_bytes(fixture["PC"]), trust,
                           fixture["complete"]["view"]["head"])
        assert v["integrity"] == "VALID"
        assert v["completeness"] == "COMPLETE"
        assert v["currentness"] == "PINNED_PREFIX"
        assert v["head"] == fixture["complete"]["view"]["head"]

    def test_wrong_pin(self, fixture, trust):
        v = verify_package(pkg_bytes(fixture["P0"]), trust,
                           {"seq": 99, "hash": "0" * 64})
        assert v["integrity"] == "INVALID"
        assert "CHAIN_INVALID" in v["errors"]

    def test_head_matches_last_entry(self, fixture, trust):
        v = verify_package(pkg_bytes(fixture["P0"]), trust, None)
        assert v["head"]["hash"] == fixture["P0"]["entries"][-1]["hash"]


class TestPackageMutations:
    def test_tampered_view(self, fixture, trust):
        p = copy.deepcopy(fixture["PC"])
        p["receipts"][0]["body"]["view"]["phase"] = "CLOSED"
        v = verify_package(pkg_bytes(p), trust, None)
        assert v["integrity"] == "INVALID"
        assert v["errors"][0] in ("HASH_MISMATCH", "PROJECTION_INVALID",
                                  "SIGNATURE_INVALID")

    def test_missing_blob(self, fixture, trust):
        p = copy.deepcopy(fixture["P0"])
        keep = {p["receipts"][0]["body"]["binding"]["action"]["hash"]}
        # Drop every blob but the action — plan/paper refs unresolvable.
        p["blobs"] = [b for b in p["blobs"] if b["hash"] in keep]
        v = verify_package(pkg_bytes(p), trust, None)
        assert v["integrity"] == "VALID"
        assert v["completeness"] == "INCOMPLETE"
        assert "INCOMPLETE" in v["errors"]

    def test_bad_entry_sig(self, fixture, trust):
        p = copy.deepcopy(fixture["P0"])
        e = p["entries"][0]
        sig = bytearray(__import__("base64").urlsafe_b64decode(
            e["sig"] + "=" * (-len(e["sig"]) % 4)))
        sig[0] ^= 1
        e["sig"] = __import__("base64").urlsafe_b64encode(
            bytes(sig)).decode().rstrip("=")
        v = verify_package(pkg_bytes(p), trust, None)
        assert v["integrity"] == "INVALID"
        assert v["errors"] == ["SIGNATURE_INVALID"]

    def test_broken_linkage(self, fixture, trust):
        p = copy.deepcopy(fixture["PC"])
        p["entries"][1]["body"]["previous_hash"] = "f" * 64
        v = verify_package(pkg_bytes(p), trust, None)
        assert v["integrity"] == "INVALID"
        assert v["errors"][0] in ("CHAIN_INVALID", "HASH_MISMATCH",
                                  "SIGNATURE_INVALID")

    def test_unsupported_schema(self, fixture, trust):
        p = copy.deepcopy(fixture["P0"])
        p["schema"] = "bond.package/2"
        v = verify_package(pkg_bytes(p), trust, None)
        assert v["integrity"] == "INVALID"
        assert v["errors"] == ["UNSUPPORTED_VERSION"]

    def test_duplicate_blob(self, fixture, trust):
        p = copy.deepcopy(fixture["P0"])
        p["blobs"].append(copy.deepcopy(p["blobs"][0]))
        v = verify_package(pkg_bytes(p), trust, None)
        assert v["integrity"] == "INVALID"
        assert v["errors"] == ["SCHEMA"]

    def test_not_json(self, trust):
        v = verify_package(b"not json", trust, None)
        assert v["integrity"] == "INVALID"
        assert v["errors"] == ["SCHEMA"]


class TestParsePackage:
    def test_parse_golden(self, fixture):
        pkg = parse_package(pkg_bytes(fixture["P0"]))
        assert pkg["schema"] == "bond.package/1"
        assert pkg["entries"][0]["body"]["kind"] == "ActionStaged"

    def test_parse_rejects(self):
        with pytest.raises(BondError):
            parse_package(b"{}")
        with pytest.raises(BondError):
            parse_package(b'{"schema":"bond.package/1"}')
