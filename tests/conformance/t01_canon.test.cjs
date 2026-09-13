/** TV-B--01..11 — canonicalization, hashing, strict parse, action schema. */
const test = require("node:test");
const assert = require("node:assert/strict");
const { F, core } = require("./harness.cjs");
const { J, H, parseJson, parseJsonBytes, vAction } = core;

const set = (o, path, v) => {
  const c = JSON.parse(JSON.stringify(o));
  const keys = path.split(".");
  let t = c;
  for (let i = 0; i < keys.length - 1; i++) t = t[keys[i]];
  t[keys[keys.length - 1]] = v;
  return c;
};
const omit = (o, k) => { const c = { ...o }; delete c[k]; return c; };
const errCode = (fn) => { try { fn(); } catch (e) { return e.code; } return null; };

test("TV-B--01 J sorts object keys", () => {
  assert.equal(J({ b: 2, a: 1 }), '{"a":1,"b":2}');
});

test("TV-B--02 H is sha256 lowercase hex", () => {
  assert.equal(H(Buffer.from("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});

test("TV-B--03 duplicate keys rejected", () => {
  assert.equal(errCode(() => parseJson('{"quantity":1,"quantity":2}')), "SCHEMA");
});

test("TV-B--04 decimal integer token rejected", () => {
  const a = set(F.action, "draft.quantity", 1.0);
  // serialize with a raw 1.0 token, which must be rejected at parse level
  const raw = JSON.stringify(a).replace('"quantity":1', '"quantity":1.0');
  assert.equal(errCode(() => vAction(parseJson(raw))), "SCHEMA");
});

test("TV-B--05 non-canonical amount rejected", () => {
  const a = set(F.action, "draft.quoted_minor", "01");
  assert.equal(errCode(() => vAction(a)), "SCHEMA");
});

test("TV-B--06 quantity over cap rejected", () => {
  assert.equal(errCode(() => vAction(set(F.action, "draft.quantity", 101))), "SCHEMA");
});

test("TV-B--07 resource traversal rejected", () => {
  assert.equal(errCode(() => vAction(set(F.action, "resource", "drafts/../secret"))), "SCHEMA");
});

test("TV-B--08 unsupported action class rejected", () => {
  assert.equal(errCode(() => vAction(set(F.action, "action_class", "refund.create/1"))), "SCHEMA");
});

test("TV-B--09 unknown member rejected", () => {
  assert.equal(errCode(() => vAction(set(F.action, "allow_all", true))), "SCHEMA");
});

test("TV-B--10 missing policy_pin rejected", () => {
  assert.equal(errCode(() => vAction(omit(F.action, "policy_pin"))), "SCHEMA");
});

test("TV-B--11 non-NFC string rejected", () => {
  assert.equal(errCode(() => vAction(set(F.action, "draft.supplier_alias", "é"))), "SCHEMA");
});
