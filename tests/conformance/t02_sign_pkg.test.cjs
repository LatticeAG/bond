/** TV-B--12..20 — signature verification and offline package verification. */
const test = require("node:test");
const assert = require("node:assert/strict");
const { F, core } = require("./harness.cjs");
const { J, verifySigned, verifyPackage } = core;

const set = (o, path, v) => {
  const c = JSON.parse(JSON.stringify(o));
  const keys = path.split(".");
  let t = c;
  for (let i = 0; i < keys.length - 1; i++) t = t[keys[i]];
  t[keys[keys.length - 1]] = v;
  return c;
};
const errCode = (fn) => { try { fn(); } catch (e) { return e.code; } return null; };

test("TV-B--12 paper signature verifies under trust pins", () => {
  verifySigned("paper", F.paper, F.trust, F.tenant); // does not throw
});

test("TV-B--13 wrong domain kind is HASH_MISMATCH", () => {
  assert.equal(errCode(() => verifySigned("receipt", F.paper, F.trust, F.tenant)), "HASH_MISMATCH");
});

test("TV-B--14 modified body is HASH_MISMATCH", () => {
  const mod = set(F.paper, "body.stated_per_action_limit", "2000");
  assert.equal(errCode(() => verifySigned("paper", mod, F.trust, F.tenant)), "HASH_MISMATCH");
});

test("TV-B--15 empty trust is UNTRUSTED_KEY", () => {
  assert.equal(errCode(() => verifySigned("paper", F.paper, set(F.trust, "keys", []), F.tenant)), "UNTRUSTED_KEY");
});

test("TV-B--16 P0 verifies to golden verify0", () => {
  const v = verifyPackage(Buffer.from(J(F.P0)), F.trust, F.V0.head);
  assert.deepEqual(v, F.verify0);
});

test("TV-B--17 null expected head is UNANCHORED_PREFIX", () => {
  const v = verifyPackage(Buffer.from(J(F.P0)), F.trust, null);
  assert.deepEqual(v, { ...F.verify0, currentness: "UNANCHORED_PREFIX" });
});

test("TV-B--18 missing blob bytes is INCOMPLETE with pinned head", () => {
  const p = set(F.P0, "blobs", F.P0.blobs.map((b) => ({ ...b, data: null })));
  const v = verifyPackage(Buffer.from(J(p)), F.trust, F.V0.head);
  assert.deepEqual(v, { ...F.verify0, errors: ["INCOMPLETE"] });
});

test("TV-B--19 tampered previous_hash is INVALID/HASH_MISMATCH", () => {
  const A = F.action.adapter_build;
  const p = set(F.P0, "entries.0.body.previous_hash", A);
  const v = verifyPackage(Buffer.from(J(p)), F.trust, F.V0.head);
  assert.equal(v.integrity, "INVALID");
  assert.ok(v.errors.includes("HASH_MISMATCH") || v.errors.includes("CHAIN_INVALID"),
    `unexpected errors ${v.errors}`);
  // A forged linkage breaks the signed object hash itself.
  assert.deepEqual(v.errors, ["HASH_MISMATCH"]);
});

test("TV-B--20 wrong expected head is INVALID/CHAIN_INVALID", () => {
  const A = F.action.adapter_build;
  const v = verifyPackage(Buffer.from(J(F.P0)), F.trust, { seq: 2, hash: A });
  assert.equal(v.integrity, "INVALID");
  assert.deepEqual(v.errors, ["CHAIN_INVALID"]);
});
