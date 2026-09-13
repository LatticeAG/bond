/** TV-B--51..64, 69..75 — kill projection, host API, http auth, misc. */
const test = require("node:test");
const assert = require("node:assert/strict");
const { Harness, F, core, sdk, makeTrust, SEED, fx } = require("./harness.cjs");
const host = require("@latticeag/bond-host");
const { J, D, H, projectKill, vKillFacts, verifySigned, verifyHttpAuth,
  verifyPackage, verifyAdvisoryBytes, verifyWorldEffect, vConfig, parseJson,
  signObject, b64uEncode } = { ...core, ...sdk };

const set = (o, path, v) => {
  const c = JSON.parse(JSON.stringify(o));
  const keys = path.split(".");
  let t = c;
  for (let i = 0; i < keys.length - 1; i++) t = t[keys[i]];
  t[keys[keys.length - 1]] = v;
  return c;
};
const errCode = (fn) => { try { fn(); return null; } catch (e) { return e.code; } };

test("TV-B--51 kill certificate with audit gap is INCOMPLETE", () => {
  const f = set(F.ek.assertion.body.facts, "audit_gap", true);
  assert.deepEqual(projectKill(f, F.binding, vKillFacts), { ok: false, code: "INCOMPLETE" });
});

test("TV-B--52 kill certificate for another run is RUN_BINDING", () => {
  const f = set(F.ek.assertion.body.facts, "run_id", "run-2");
  assert.deepEqual(projectKill(f, F.binding, vKillFacts), { ok: false, code: "RUN_BINDING" });
});

test("TV-B--53 non-KILL facts in the kill lane are SCHEMA", () => {
  assert.deepEqual(
    projectKill({ kind: "RUN", state: "ACTIVE" }, F.binding, vKillFacts),
    { ok: false, code: "SCHEMA" });
});

// --- host vectors --------------------------------------------------------------

function makeHost() {
  const store = new host.HostStore();
  const handler = host.createHostHandler({
    store, trust: F.trust, now: () => F.t, maxPackageBytes: 8388608,
  });
  handler.grantAllKeys(["operator", "publisher", "auditor"]);
  return { store, handler };
}

function authHeader(body) {
  const unsigned = {
    tenant_id: F.tenant, principal_id: F.principal, key_id: F.httpAuth.key_id,
    request_id: core.newId("bnq"), method: "POST", target: "/v1/certificates",
    body_hash: H(J(body)), issued_at: F.t, expires_at: "2026-09-12T12:05:00.000Z",
  };
  const sig = core.seedSigner(require("./harness.cjs").SEED)(
    new TextEncoder().encode("LAGI-BOND/sign/request/1\n" + D("request", unsigned)));
  return b64uEncode(Buffer.from(J({ ...unsigned, sig: sig.toString("base64url") }), "utf8"));
}

test("TV-B--54 exact publish retry replays with no new revisions", () => {
  const { handler } = makeHost();
  const env = { package: F.P0, expected_host_revision: 0 };
  const body = Buffer.from(J(env), "utf8");
  const req = {
    method: "POST", path: "/v1/certificates", query: "",
    headers: { "bond-auth": F.httpHeader }, body,
  };
  const r1 = handler.handle(req);
  assert.equal(r1.status, 201);
  assert.equal(r1.body.revision, 1);
  const r2 = handler.handle({ ...req }); // exact same nonce + bytes
  assert.equal(r2.status, 200);
  assert.deepEqual(r2.body, r1.body);
});

test("TV-B--55 read of a nonexistent receipt is NOT_FOUND", () => {
  const { handler } = makeHost();
  const env = { package: F.P0, expected_host_revision: 0 };
  handler.handle({
    method: "POST", path: "/v1/certificates", query: "",
    headers: { "bond-auth": F.httpHeader }, body: Buffer.from(J(env), "utf8"),
  });
  // Same-tenant auth for a receipt id that was never published reads as absent.
  const rid = "brc_" + "1".repeat(21);
  const auth = {
    ...F.httpAuth, request_id: core.newId("bnq"), method: "GET",
    target: `/v1/certificates/${rid}?revision=1`,
    body_hash: H(Buffer.alloc(0)),
  };
  delete auth.sig;
  const sig = core.seedSigner(SEED)(
    new TextEncoder().encode("LAGI-BOND/sign/request/1\n" + D("request", auth)));
  const header = b64uEncode(Buffer.from(J({ ...auth, sig: sig.toString("base64url") }), "utf8"));
  const r = handler.handle({
    method: "GET", path: `/v1/certificates/${rid}`, query: "revision=1",
    headers: { "bond-auth": header }, body: null,
  });
  assert.equal(r.status, 404);
  assert.deepEqual(r.body, { error: { code: "NOT_FOUND", retryable: false } });
});

// --- http auth vectors -----------------------------------------------------------

test("TV-B--56 expired http auth is DEADLINE", () => {
  assert.equal(errCode(() =>
    verifyHttpAuth(F.httpAuth, F.trust, "2026-09-12T12:05:00.000Z")), "DEADLINE");
});

test("TV-B--57 oversized decoded auth is LIMIT", () => {
  const header = Buffer.alloc(8193).toString("base64url");
  assert.equal(errCode(() => core.decodeHttpAuth(header)), "LIMIT");
});

test("TV-B--72 fixture http auth verifies", () => {
  verifyHttpAuth(F.httpAuth, F.trust, F.t); // does not throw
  assert.equal(F.httpAuth.method, "POST");
  assert.equal(F.httpAuth.target, "/v1/certificates");
});

// --- advisory vectors ------------------------------------------------------------

test("TV-B--58 hypothetical world lineage is UNSUPPORTED_COMPOSITION", () => {
  assert.equal(errCode(() =>
    verifyWorldEffect({ format: "world-lineage/1", result: { hypothetical: true } })),
    "UNSUPPORTED_COMPOSITION");
});

test("TV-B--59 attach advisory on a closed action bumps revision only", async () => {
  const h = new Harness();
  try {
    const v = await h.toReview();
    const acc = await h.call("accept", {
      request_id: core.newId("bnq"), action_id: F.a, expected_revision: v.revision,
    });
    assert.equal(acc.value.phase, "CLOSED");
    const settlesBefore = h.counters.settles;
    const art = {
      hash: F.advisory.hash, bytes: F.advisory.bytes,
      media_type: F.advisory.media_type, data: F.advisory.data,
    };
    const at = await h.call("attach", {
      request_id: core.newId("bnq"), action_id: F.a,
      expected_revision: acc.value.revision, artifact: art, purpose: "GROUND_ADVISORY",
    });
    assert.equal(at.ok, true);
    assert.equal(at.value.phase, "CLOSED");
    assert.equal(at.value.funds, "RELEASED");
    assert.equal(at.value.revision, acc.value.revision + 1);
    assert.equal(h.counters.settles, settlesBefore);
  } finally { h.close(); }
});

// --- config / migration / recovery -------------------------------------------------

test("TV-B--60 config with allow_all is SCHEMA", () => {
  const cfg = { schema: "bond.config/1", allow_all: true };
  assert.equal(errCode(() => vConfig(cfg)), "SCHEMA");
});

test("TV-B--61 migrate refuses while operations are pending", async () => {
  const { mkdtempSync } = require("node:fs");
  const { tmpdir } = require("node:os");
  const { join } = require("node:path");
  const h = new Harness({ executor: { create: "UNKNOWN", lookup: "UNKNOWN" } });
  const target = mkdtempSync(join(tmpdir(), "bond-mig-"));
  try {
    await h.toReady();
    await h.execute(2); // CREATE unresolved
    h.client.close(); // migration is an offline tool; release the journal lock
    const mig = {
      schema: "bond.migration/1", from_storage: 1, to_storage: 2,
      source_checkpoint: "0".repeat(64), tool_build: "0".repeat(64),
      backup_digest: "0".repeat(64), mode: "COPY_AND_VERIFY",
    };
    assert.equal(errCode(() => sdk.migrateJournal(h.dir, target, mig)), "BAD_STATE");
  } finally { h.close(); }
});

test("TV-B--62 journal corruption quarantines and attempts stop", async () => {
  const h = new Harness();
  try {
    await h.toReady();
    // Corrupt the stored genesis entry bytes.
    const entries = h.client.journal.getEntries(F.a);
    h.client.journal.appendEntry(F.a, 99, "f".repeat(64),
      Buffer.from(entries[0].canonical)); // bogus tail breaks the chain head
    h.reopen();
    const r = await h.recover();
    assert.deepEqual(r.quarantined, [F.a]);
    assert.deepEqual(r.stopAttempted, [F.a]);
    assert.equal(h.counters.dispatches, 0);
  } finally { h.close(); }
});

// --- package / trust pins ----------------------------------------------------------

test("TV-B--63 complete package verifies COMPLETE", () => {
  const v = verifyPackage(Buffer.from(J(F.PC)), F.trust, F.complete.view.head);
  assert.deepEqual(v, {
    integrity: "VALID", completeness: "COMPLETE", currentness: "PINNED_PREFIX",
    simulation: true, insurance: "PAPER_ONLY",
    truth: "ISSUER_ASSERTIONS_NOT_REAL_WORLD_PROOF",
    head: F.complete.view.head, errors: [],
  });
});

test("TV-B--69 every signed object in the complete package verifies", () => {
  let entries = 0, receipts = 0;
  for (const e of F.PC.entries) { verifySigned("entry", e, F.trust, F.tenant); entries++; }
  for (const r of F.PC.receipts) { verifySigned("receipt", r, F.trust, F.tenant); receipts++; }
  assert.equal(entries, 11);
  assert.equal(receipts, 11);
});

test("TV-B--70 assertion kind pin restriction is enforced", () => {
  const trust = set(F.trust, "keys.0.assertion_kinds", ["HOLD"]);
  assert.equal(errCode(() =>
    verifySigned("assertion", F.ep.assertion, trust, F.tenant)), "UNTRUSTED_KEY");
});

test("TV-B--71 in-flight request replays as BUSY", async () => {
  const h = new Harness();
  try {
    const req = core.newId("bnq");
    const i = { request_id: req, expected_revision: 0, action: F.action, run_id: F.run, paper: F.paper };
    // Occupy the request row without finishing: fire two concurrent prepares.
    let release;
    const gate = new Promise((r) => (release = r));
    h.mutate["trellis.observe"] = async () => { await gate; return fx.callFixture(h.set, "trellis.observe", { action_id: F.a, run_id: F.run }); };
    const p1 = h.call("prepare", i);
    const p2 = h.call("prepare", i);
    release();
    const [r1, r2] = await Promise.all([p1, p2]);
    const codes = [r1, r2].map((x) => (x.ok ? "ok" : x.code)).sort();
    assert.deepEqual(codes, ["BUSY", "ok"]);
  } finally { h.close(); }
});

test("TV-B--73 deterministic bedrock request ids", () => {
  assert.deepEqual(fx.bedrockRequestIds(F.a), {
    forward: "brq_f" + "0".repeat(20), undo: "brq_u" + "0".repeat(20),
  });
});

test("TV-B--74 stop of an unknown action is NOT_FOUND", async () => {
  const h = new Harness();
  try {
    const s = await h.call("stop", {
      request_id: core.newId("bnq"), action_id: "bac_111111111111111111111",
    });
    assert.equal(s.ok, false);
    assert.equal(s.code, "NOT_FOUND");
    assert.equal(h.counters.dispatches, 0);
  } finally { h.close(); }
});

test("TV-B--75 scope stop then execute is BAD_STATE", async () => {
  const h = new Harness();
  try {
    await h.toReady();
    const s = await h.call("stop", { request_id: core.newId("bnq"), action_id: null });
    assert.equal(s.ok, true);
    assert.deepEqual(s.value, { scope_stopped: true });
    const e = await h.execute(2);
    assert.equal(e.ok, false);
    assert.equal(e.code, "BAD_STATE");
    assert.equal(h.counters.dispatches, 0);
  } finally { h.close(); }
});

test("TV-B--64 non-SIMUSD asset is SCHEMA", () => {
  const a = set(F.action, "draft.asset", "USD");
  assert.equal(errCode(() => core.vAction(a)), "SCHEMA");
});
