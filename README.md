# Bond

[![CI](https://github.com/LatticeAG/bond/actions/workflows/ci.yml/badge.svg)](https://github.com/LatticeAG/bond/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-22%2B-blue.svg)](package.json)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](python/pyproject.toml)
[![Profile](https://img.shields.io/badge/profile-bond.sim--procurement--draft%2F1-blue.svg)](#simulation-profile)

**Bond** is the LatticeAG gated-execution wrapper SDK for effectful model
actions. It stages an action, reserves escrow against a fixed remedy, pins a
preplanned conditional inverse, latches dispatch behind a verified policy
evaluation and a fresh runtime observation, and issues a signed, hash-chained
action receipt at every revision. Everything is local: the durable journal is
SQLite, the evidence is signed assertions over hash-pinned source bytes, and
verification is pure and offline.

> A Bond receipt means exactly this: **"these assertions were made by these
> keys, under this binding, replaying to this state."** It does not create
> solvency, does not reverse external history, does not establish legal
> insurance coverage, and does not guarantee model behavior.
> `ISSUER_ASSERTIONS_NOT_REAL_WORLD_PROOF` is carried on every receipt.

## Simulation profile

The executable OSS profile is `bond.sim-procurement-draft/1`: simulated
procurement-draft creation only. SIMUSD is a nonredeemable simulated unit.
The remedy paper is `PAPER_ONLY` — a review record, not an insurance product.
Fixture adapters produce `fixture/1` evidence and every receipt carries
`simulation: true`. Adapters configured `installed` resolve to honest
fail-closed stubs that report their missing native capability (for example
`MINT_EXCLUSIVE_HOLD_UNAVAILABLE`) instead of pretending to work.

## Layout

- `packages/core` — strict canonicalization/parsing, Ed25519 verification,
  closed schemas, the pure reducer, offline package verification.
- `packages/sdk` — `BondClient` over a durable SQLite journal: `doctor`,
  `prepare`, `execute`, `cancel`, `accept`, `reject`, `stop`, `reconcile`,
  `inspect`, `attach`, `export`, `verify`.
- `packages/cli` — the `bond` command frontend (`--json`, mapped exit codes).
- `packages/host` — optional certificate-hosting handler (publish, read,
  notices, health) and a loopback dev server.
- `adapters/fixture` — labeled simulation adapters for Bedrock, Mint,
  VekRevert, Trellis, and the draft executor.
- `adapters/native` — fail-closed installed-mode stubs.
- `python/bond_verify` — verification/interchange: `canonicalize`, `digest`,
  `parse_package`, `verify_package`, strict parser, Ed25519, and the reduced
  state projection. It is a verifier, not a coordinator.
- `tests/conformance` — the TV-B--01 … TV-B--75 vectors as executable tests.
- `fixtures/f.js` — the normative fixture module (golden objects, views,
  packages, trust file).

## CLI signing seed

The CLI reads a 32-byte Ed25519 seed encoded as 64 hexadecimal characters
from an environment variable. For `signing_key_ref: "main"` in the config,
set `BOND_SEED_MAIN` before running `bond`:

```sh
export BOND_SEED_MAIN='<64-character hex seed>'
bond --config bond.config.json doctor --json
```

For other references, uppercase the reference and replace every character
outside `A`–`Z` and `0`–`9` with `_`, then prepend `BOND_SEED_`. For example,
`signing_key_ref: "team-key"` uses `BOND_SEED_TEAM_KEY`. The seed's public key
must appear in the configured trust file. Treat the seed as a secret; the
conformance fixture seed is for simulation only.

## Develop

```sh
npm ci && npm test          # TypeScript build + 75 conformance vectors
pip install -e python/ pytest
python3 -m pytest python/tests -q   # Python parity suite
```

The CLI lifecycle (`prepare` → `execute` → `accept`/`reject`/`cancel` →
`export` → `verify`) runs entirely against the fixture world; see
`bond doctor --json` for capability status.

### Fixture dates and the CLI clock

The objects in `fixtures/f.js` are fixed conformance vectors, not rolling demo
inputs. In particular, `F.action.execute_before` is
`2026-09-12T12:00:30.000Z`; the CLI uses the system clock and `prepare`
returns `DEADLINE` at or after that instant. The conformance harness instead
uses a clock pinned to `F.t`. Do not change the system clock to bypass a real
deadline. For a current simulation, create a new action with valid current
`created_at`, `execute_before`, `reserve_until`, and `long_stop` values, plus
paper and trust keys valid for the new times; sign any changed paper again.
Changing the golden fixture objects invalidates their associated signatures and
hashes, so keep them unchanged for conformance and offline verification.
