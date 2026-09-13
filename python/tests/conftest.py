"""Shared test fixtures: the normative fixture module rendered to canonical
JSON by Node (the same J/H/D implementation the TS suite uses), then parsed
back through bond_verify's own strict parser — so the corpus exercises both
directions of the interchange."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
PUBKEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


@pytest.fixture(scope="session")
def fixture() -> dict:
    out = subprocess.run(
        ["node", "-e",
         f'const m=require("{REPO}/fixtures/f.js");process.stdout.write(m.J(m.F))'],
        check=True, capture_output=True,
    )
    return json.loads(out.stdout)


@pytest.fixture(scope="session")
def fixture_bytes() -> bytes:
    return subprocess.run(
        ["node", "-e",
         f'const m=require("{REPO}/fixtures/f.js");process.stdout.write(m.J(m.F))'],
        check=True, capture_output=True,
    ).stdout


@pytest.fixture(scope="session")
def trust(fixture) -> dict:
    from bond_verify import v_trust_file
    return v_trust_file(fixture["trust"])
