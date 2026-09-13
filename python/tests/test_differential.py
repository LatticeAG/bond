"""Differential TS/Python corpus: deterministic pseudo-random valid objects
canonicalized by both implementations must produce identical bytes and
digests (spec G5 / parser differential)."""

from __future__ import annotations

import json
import random
import string
import subprocess
from pathlib import Path

import pytest

from bond_verify import D, J, canonicalize

REPO = Path(__file__).resolve().parents[2]

NODE_J = r'''
const m = require(process.argv[1]);
let input = "";
process.stdin.on("data", c => input += c).on("end", () => {
  const objs = JSON.parse(input);
  const out = objs.map(o => ({ j: m.J(o), d: m.D("assertion", o) }));
  process.stdout.write(JSON.stringify(out));
});
'''


def gen(rng: random.Random, depth: int):
    r = rng.random()
    if depth > 4 or r < 0.25:
        c = rng.choice(["str", "int", "bool", "null"])
        if c == "str":
            alpha = string.ascii_letters + string.digits + " _-:/\"\\\n\t" \
                + "éü中\U0001F600"
            return "".join(rng.choice(alpha) for _ in range(rng.randrange(0, 24)))
        if c == "int":
            return rng.choice([0, 1, rng.randrange(0, 2**53 - 1),
                               rng.randrange(0, 100)])
        if c == "bool":
            return rng.random() < 0.5
        return None
    if r < 0.6:
        return [gen(rng, depth + 1) for _ in range(rng.randrange(0, 6))]
    keys = rng.sample(
        ["".join(rng.choice(string.ascii_lowercase + "éü_")
                 for _ in range(rng.randrange(1, 8)))
         for _ in range(12)], rng.randrange(0, 6))
    return {k: gen(rng, depth + 1) for k in keys}


@pytest.fixture(scope="module")
def corpus() -> list:
    rng = random.Random(0xB04D)
    return [gen(rng, 0) for _ in range(1000)]


def test_canonical_bytes_match(corpus):
    proc = subprocess.run(
        ["node", "-e", NODE_J, f"{REPO}/fixtures/f.js"],
        input=json.dumps(corpus), capture_output=True, check=True, text=True)
    golden = json.loads(proc.stdout)
    assert len(golden) == len(corpus)
    for i, (obj, g) in enumerate(zip(corpus, golden)):
        py_j = J(obj)
        assert py_j == g["j"], f"J divergence at corpus[{i}]"
        assert D("assertion", obj) == g["d"], f"D divergence at corpus[{i}]"
        assert canonicalize(obj) == g["j"].encode("utf-8")
