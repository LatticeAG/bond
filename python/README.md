# bond_verify

Offline verification and interchange support for Bond certificate packages
(profile `bond.sim-procurement-draft/1`).

This package is a verifier, not a coordinator. It exposes:

- `canonicalize(value) -> bytes` / `J(value)` — restricted RFC 8785 canonical
  JSON (UTF-16 key order, NFC text, nonnegative safe integers only).
- `digest(kind, value) -> str` — the `D()` domain digest.
- `parse_package(bytes) -> dict` — strict-parse + closed-schema validation.
- `verify_package(pkg_bytes, trust, expected_head=None) -> dict` — full §6.3
  offline verification returning `{integrity, completeness, currentness,
  simulation, insurance, truth, head, errors}`.
- `verify_signed`, `verify_http_auth` — strict Ed25519 signed-object checks.
- `apply_entry`, `to_view`, … — the pure reduced-state projection.

It does not execute actions, write journals, hold keys beyond caller-provided
signers, or contact any network service. Verification reports
`ISSUER_ASSERTIONS_NOT_REAL_WORLD_PROOF` verbatim: signatures attribute
assertions to keys; they do not create solvency, reverse history, establish
insurance coverage, or guarantee model behavior.
