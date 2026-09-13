"""Reduced-state parity: replay every normative fixture scene through the
Python reducer and compare each projected view byte-for-byte against the
fixture's golden views (which the TS reducer reproduces)."""

from __future__ import annotations

import pytest

from bond_verify import (
    BondError, ForkSignal, MissingEvidence, apply_entry, computed_disposition,
    deep_equal, initial_state, pending_ops, project_kill, to_view,
    v_kill_facts,
)

SCENES = ["S0", "S1", "S2", "S3", "S4", "SC", "SS", "SA", "complete"]
VIEWS = {"S0": "V0", "S1": "V1", "S2": "V2", "S3": "V3", "S4": "V4",
         "SC": "VC", "SS": "VS", "SA": "VA"}


def make_env(fixture) -> dict:
    """Resolve evidence refs to the fixture's signed-assertion facts."""
    by_hash = {}
    for name in ("ep", "epu", "eh", "ee", "er", "ey", "ef", "eu", "en", "ek"):
        ev = fixture[name]
        # Evidence ref = blob of the assertion (canonical blob, application/json)
        from bond_verify import json_blob, ref_of
        ref = ref_of(json_blob(ev["assertion"]))
        by_hash[ref["hash"]] = {
            "facts": ev["assertion"]["body"]["facts"],
            "evidenceHash": ref["hash"],
        }

    def resolve(ref):
        return by_hash.get(ref["hash"])

    return {
        "action": fixture["action"],
        "plan": fixture["plan"],
        "binding": fixture["binding"],
        "resolve": resolve,
    }


@pytest.mark.parametrize("scene", SCENES)
def test_scene_replay(fixture, scene):
    env = make_env(fixture)
    st = None
    receipt_id = fixture["r"]
    for e in fixture[scene]["entries"]:
        st, _ = apply_entry(st, e["body"], e["hash"], env, "verify")
        st["receiptId"] = receipt_id
    view = to_view(st)
    golden = fixture[scene]["view"]
    assert deep_equal(view, golden), (
        f"{scene}: view divergence\n{view}\nvs\n{golden}")


@pytest.mark.parametrize("scene", ["S0", "S1", "S2", "S3", "S4", "SC", "SS"])
def test_golden_named_views(fixture, scene):
    env = make_env(fixture)
    st = None
    for e in fixture[scene]["entries"]:
        st, _ = apply_entry(st, e["body"], e["hash"], env, "verify")
        st["receiptId"] = fixture["r"]
    assert deep_equal(to_view(st), fixture[VIEWS[scene]])


def test_genesis_rules(fixture):
    env = make_env(fixture)
    # Wrong kind genesis
    bad = dict(fixture["S1"]["entries"][1]["body"], seq=1,
               previous_hash="0" * 64)
    with pytest.raises(BondError) as e:
        apply_entry(None, bad, "a" * 64, env, "verify")
    assert e.value.code == "PROJECTION_INVALID"
    # Wrong seq
    g = dict(fixture["S0"]["entries"][0]["body"], seq=2)
    with pytest.raises(BondError):
        apply_entry(None, g, "a" * 64, env, "verify")


def test_ingest_dup_is_noop(fixture):
    env = make_env(fixture)
    st = None
    for e in fixture["S1"]["entries"]:
        st, _ = apply_entry(st, e["body"], e["hash"], env, "ingest")
        st["receiptId"] = fixture["r"]
    # Re-ingesting the same HoldObserved entry: no-op, state unchanged.
    dup_entry = fixture["S1"]["entries"][1]
    st2, noop = apply_entry(st, dup_entry["body"], dup_entry["hash"], env, "ingest")
    assert noop
    assert st2["revision"] == st["revision"]
    assert st2["head"] == st["head"]


def test_verify_dup_invalid(fixture):
    env = make_env(fixture)
    st = None
    for e in fixture["S1"]["entries"]:
        st, _ = apply_entry(st, e["body"], e["hash"], env, "verify")
        st["receiptId"] = fixture["r"]
    dup_entry = fixture["S1"]["entries"][1]
    with pytest.raises(BondError) as e:
        apply_entry(st, dup_entry["body"], dup_entry["hash"], env, "verify")
    assert e.value.code == "PROJECTION_INVALID"


def test_missing_evidence(fixture):
    env = make_env(fixture)
    env["resolve"] = lambda ref: None
    st, _ = apply_entry(None, fixture["S1"]["entries"][0]["body"],
                        fixture["S1"]["entries"][0]["hash"], env, "verify")
    st["receiptId"] = fixture["r"]
    with pytest.raises(MissingEvidence):
        apply_entry(st, fixture["S1"]["entries"][1]["body"],
                    fixture["S1"]["entries"][1]["hash"], env, "verify")


def test_dispositions(fixture):
    env = make_env(fixture)
    # funds NONE computes NO_HOLD even before close (the disposition is a
    # pure function of committed facts).
    expect = {"S0": "NO_HOLD", "S3": "RELEASE", "S4": "PAY", "SC": "RELEASE"}
    for scene, disp in expect.items():
        st = None
        for e in fixture[scene]["entries"]:
            st, _ = apply_entry(st, e["body"], e["hash"], env, "verify")
        assert computed_disposition(st) == disp


class TestProjectKill:
    def test_certified(self, fixture):
        facts = fixture["ek"]["assertion"]["body"]["facts"]
        r = project_kill(facts, fixture["binding"], v_kill_facts)
        assert r == {"ok": True, "state": "CERTIFIED"}

    def test_incomplete(self, fixture):
        facts = dict(fixture["ek"]["assertion"]["body"]["facts"],
                     gate_closed=False)
        r = project_kill(facts, fixture["binding"], v_kill_facts)
        assert r == {"ok": False, "code": "INCOMPLETE"}

    def test_run_binding(self, fixture):
        facts = dict(fixture["ek"]["assertion"]["body"]["facts"],
                     run_id="run-other")
        r = project_kill(facts, fixture["binding"], v_kill_facts)
        assert r == {"ok": False, "code": "RUN_BINDING"}

    def test_unconfirmed(self, fixture):
        facts = dict(fixture["ek"]["assertion"]["body"]["facts"],
                     state="UNCONFIRMED")
        r = project_kill(facts, fixture["binding"], v_kill_facts)
        assert r == {"ok": True, "state": "UNCONFIRMED"}
