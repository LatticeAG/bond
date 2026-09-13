/** TV-B--33..49, 65..68 — live coordinator lifecycle, idempotency, recovery. */
const test = require("node:test");
const assert = require("node:assert/strict");
const { Harness, F, core, fx } = require("./harness.cjs");

test("TV-B--33 doctor reports missing native capabilities", async () => {
  const h = new Harness({
    capabilityCheck: () => ["MINT_EXCLUSIVE_HOLD_UNAVAILABLE", "VEKREVERT_CONDITIONAL_INVERSE_UNAVAILABLE"],
  });
  try {
    const d = await h.call("doctor", {});
    assert.equal(d.ok, true);
    assert.equal(d.value.ready, false);
    assert.deepEqual(d.value.missing,
      ["MINT_EXCLUSIVE_HOLD_UNAVAILABLE", "VEKREVERT_CONDITIONAL_INVERSE_UNAVAILABLE"]);
  } finally { h.close(); }
});

test("TV-B--34 malformed reserve evidence leaves STAGED/UNKNOWN", async () => {
  const h = new Harness({
    mutate: { "mint.reserve": (i, set) => set.mint.pendingWitness(i) },
  });
  try {
    const p = await h.prepare();
    assert.equal(p.ok, true);
    assert.equal(p.value.phase, "STAGED");
    assert.equal(p.value.funds, "UNKNOWN");
    assert.equal(h.counters.dispatches, 0);
  } finally { h.close(); }
});

test("TV-B--35 execute reaches AWAITING_REVIEW with one dispatch", async () => {
  const h = new Harness();
  try {
    const v = await h.toReview();
    assert.equal(v.phase, "AWAITING_REVIEW");
    assert.equal(v.effect, "APPLIED");
    assert.equal(v.undo, "PLANNED");
    assert.equal(v.funds, "ENCUMBERED");
    assert.equal(h.counters.dispatches, 1);
  } finally { h.close(); }
});

test("TV-B--36 replayed execute request returns stored response", async () => {
  const h = new Harness();
  try {
    await h.toReady();
    const req = core.newId("bnq");
    const i = { request_id: req, action_id: F.a, expected_revision: 2 };
    const e1 = await h.call("execute", i);
    const e2 = await h.call("execute", i);
    assert.deepEqual(e1, e2);
    assert.equal(h.counters.dispatches, 1);
    assert.equal(h.counters.reserves, 1);
  } finally { h.close(); }
});

test("TV-B--37 request id reuse with different input conflicts", async () => {
  const h = new Harness();
  try {
    const req = core.newId("bnq");
    const a2 = JSON.parse(JSON.stringify(F.action));
    a2.action_id = core.newId("bac");
    a2.resource = "drafts/" + a2.action_id;
    a2.draft.quantity = 2;
    const p1 = await h.call("prepare", {
      request_id: req, expected_revision: 0, action: F.action, run_id: F.run, paper: F.paper,
    });
    assert.equal(p1.ok, true);
    const p2 = await h.call("prepare", {
      request_id: req, expected_revision: 0, action: a2, run_id: F.run, paper: F.paper,
    });
    assert.equal(p2.ok, false);
    assert.equal(p2.code, "IDEMPOTENCY_CONFLICT");
    assert.equal(h.counters.dispatches, 0);
  } finally { h.close(); }
});

test("TV-B--38 cancel at READY releases the hold", async () => {
  const h = new Harness();
  try {
    await h.toReady();
    const c = await h.call("cancel", {
      request_id: core.newId("bnq"), action_id: F.a, expected_revision: 2,
    });
    assert.equal(c.ok, true);
    assert.equal(c.value.phase, "CLOSED");
    assert.equal(c.value.effect, "NOT_DISPATCHED");
    assert.equal(c.value.undo, "NOT_NEEDED");
    assert.equal(c.value.funds, "RELEASED");
    assert.equal(h.counters.dispatches, 0);
  } finally { h.close(); }
});

test("TV-B--39 accept at AWAITING_REVIEW releases", async () => {
  const h = new Harness();
  try {
    await h.toReview();
    const acc = await h.call("accept", {
      request_id: core.newId("bnq"), action_id: F.a, expected_revision: 6,
    });
    assert.equal(acc.ok, true);
    assert.equal(acc.value.phase, "CLOSED");
    assert.equal(acc.value.funds, "RELEASED");
    assert.equal(h.counters.dispatches, 1);
  } finally { h.close(); }
});

test("TV-B--40 reject applies the inverse and pays the remedy", async () => {
  const h = new Harness();
  try {
    await h.toReview();
    const r = await h.call("reject", {
      request_id: core.newId("bnq"), action_id: F.a, expected_revision: 6,
      reason: "OPERATOR_REJECTED",
    });
    assert.equal(r.ok, true);
    assert.equal(r.value.phase, "CLOSED");
    assert.equal(r.value.effect, "APPLIED");
    assert.equal(r.value.undo, "APPLIED");
    assert.equal(r.value.funds, "PAID");
    assert.equal(h.counters.dispatches, 1);
  } finally { h.close(); }
});

test("TV-B--41 reject with VERSION_CHANGED inverse still pays", async () => {
  const h = new Harness({ vekrevert: { apply: "VERSION_CHANGED" } });
  try {
    await h.toReview();
    const r = await h.call("reject", {
      request_id: core.newId("bnq"), action_id: F.a, expected_revision: 6,
      reason: "OPERATOR_REJECTED",
    });
    assert.equal(r.ok, true);
    assert.equal(r.value.phase, "CLOSED");
    assert.equal(r.value.undo, "FAILED");
    assert.equal(r.value.funds, "PAID");
  } finally { h.close(); }
});

test("TV-B--42 reject with inverse policy DENY still pays", async () => {
  const h = new Harness({ bedrock: { undo: "DENY" } });
  try {
    await h.toReview();
    const r = await h.call("reject", {
      request_id: core.newId("bnq"), action_id: F.a, expected_revision: 6,
      reason: "OPERATOR_REJECTED",
    });
    assert.equal(r.ok, true);
    assert.equal(r.value.phase, "CLOSED");
    assert.equal(r.value.undo, "FAILED");
    assert.equal(r.value.funds, "PAID");
  } finally { h.close(); }
});

test("TV-B--43 executor UNKNOWN leaves UNCERTAIN", async () => {
  const h = new Harness({ executor: { create: "UNKNOWN" } });
  try {
    await h.toReady();
    const e = await h.execute(2);
    assert.equal(e.ok, true);
    assert.equal(e.value.phase, "UNCERTAIN");
    assert.equal(e.value.effect, "UNKNOWN");
    assert.equal(e.value.undo, "PLANNED");
    assert.equal(e.value.funds, "ENCUMBERED");
    assert.equal(h.counters.dispatches, 1);
  } finally { h.close(); }
});

test("TV-B--44 inverse UNKNOWN leaves UNCERTAIN", async () => {
  const h = new Harness({ vekrevert: { apply: "UNKNOWN", lookup: "UNKNOWN" } });
  try {
    await h.toReview();
    const r = await h.call("reject", {
      request_id: core.newId("bnq"), action_id: F.a, expected_revision: 6,
      reason: "OPERATOR_REJECTED",
    });
    assert.equal(r.ok, true);
    assert.equal(r.value.phase, "UNCERTAIN");
    assert.equal(r.value.effect, "APPLIED");
    assert.equal(r.value.undo, "UNKNOWN");
    assert.equal(r.value.funds, "ENCUMBERED");
  } finally { h.close(); }
});

test("TV-B--45 recover CREATE_SENT with UNKNOWN lookup stays UNCERTAIN", async () => {
  const h = new Harness({
    executor: { create: "UNKNOWN", lookup: "UNKNOWN" },
  });
  try {
    await h.toReady();
    const e = await h.execute(2);
    assert.equal(e.value.phase, "UNCERTAIN");
    const dispatchesBefore = h.counters.dispatches;
    h.reopen();
    await h.recover();
    const v = (await h.view()).value;
    assert.equal(v.phase, "UNCERTAIN");
    assert.deepEqual(v.pending, ["CREATE"]);
    assert.equal(h.counters.dispatches, dispatchesBefore);
  } finally { h.close(); }
});

test("TV-B--46 recover PAY_SENT with PAID lookup closes PAID", async () => {
  // Simulate a settle response lost after the hold was paid: settle applies
  // inside the adapter but the port reports UNKNOWN; lookups are also
  // unavailable until the restart.
  const h = new Harness({
    mutate: {
      "mint.settle": async (i, set) => {
        await fx.callFixture(set, "mint.settle", i);
        return { status: "UNKNOWN" };
      },
      "mint.lookup": async () => ({ status: "UNKNOWN" }),
    },
  });
  try {
    await h.toReview();
    const r = await h.call("reject", {
      request_id: core.newId("bnq"), action_id: F.a, expected_revision: 6,
      reason: "OPERATOR_REJECTED",
    });
    assert.equal(r.ok, true);
    assert.notEqual(r.value.phase, "CLOSED"); // PAY could not be confirmed
    assert.ok(r.value.pending.includes("PAY"));
    const settlesBefore = h.counters.settles;
    h.reopen({ mutate: {} });
    await h.recover();
    const v = (await h.view()).value;
    assert.equal(v.phase, "CLOSED");
    assert.equal(v.funds, "PAID");
    assert.equal(h.counters.settles, settlesBefore); // lookup resolved it
  } finally { h.close(); }
});

test("TV-B--47 recover RESERVE_SENT with HELD lookup reaches READY", async () => {
  const h = new Harness({
    mutate: {
      "mint.reserve": async (i, set) => {
        await fx.callFixture(set, "mint.reserve", i);
        return { status: "UNKNOWN" };
      },
      "mint.lookup": async () => ({ status: "UNKNOWN" }),
    },
  });
  try {
    const p = await h.prepare();
    assert.equal(p.value.phase, "STAGED");
    assert.equal(p.value.funds, "UNKNOWN");
    const reservesBefore = h.counters.reserves;
    h.reopen({ mutate: {} });
    await h.recover();
    const v = (await h.view()).value;
    assert.equal(v.phase, "READY");
    assert.equal(h.counters.reserves, reservesBefore); // no re-reserve
    assert.equal(h.counters.dispatches, 0);
  } finally { h.close(); }
});

test("TV-B--48 stop before execute wins: no dispatch, latch set", async () => {
  const h = new Harness();
  try {
    await h.toReady();
    const s = await h.call("stop", { request_id: core.newId("bnq"), action_id: F.a });
    assert.equal(s.ok, true);
    assert.equal(s.value.stop_latched, true);
    const e = await h.execute((await h.view()).value.revision);
    assert.equal(e.ok, false);
    assert.equal(e.code, "BAD_STATE");
    assert.equal(h.counters.dispatches, 0);
  } finally { h.close(); }
});

test("TV-B--49 stop racing a dispatch lands after admission", async () => {
  let stopPromise = null;
  const h = new Harness({
    executor: { create: "UNKNOWN" },
    onDispatchAdmitted: () => {
      stopPromise = h.call("stop", { request_id: core.newId("bnq"), action_id: F.a });
    },
  });
  try {
    await h.toReady();
    const e = await h.execute(2);
    assert.equal(e.ok, true);
    assert.equal(e.value.phase, "UNCERTAIN");
    const s = await stopPromise;
    assert.equal(s.ok, true);
    const v = (await h.view()).value;
    assert.equal(v.stop_latched, true);
    assert.equal(h.counters.dispatches, 1);
  } finally { h.close(); }
});

test("TV-B--65 denied reserve closes with no funds movement", async () => {
  const h = new Harness({ mint: { noFunds: true } });
  try {
    const p = await h.prepare();
    assert.equal(p.ok, true);
    assert.equal(p.value.phase, "CLOSED");
    assert.equal(p.value.funds, "NONE");
    assert.equal(h.counters.dispatches, 0);
    assert.equal(h.counters.settles, 0);
  } finally { h.close(); }
});

test("TV-B--66 matured hold releases funds while CREATE stays pending", async () => {
  const t = { v: F.t };
  const clock = { now: () => t.v, monotonicMs: () => 0 };
  const h = new Harness({
    clock, executor: { create: "UNKNOWN", lookup: "UNKNOWN" },
  });
  try {
    await h.toReady();
    const e = await h.execute(2);
    assert.equal(e.value.phase, "UNCERTAIN");
    assert.equal(e.value.funds, "ENCUMBERED");
    t.v = "2026-10-28T00:00:00.000Z"; // past long_stop, before trust not_after
    const r = await h.call("reconcile", {
      request_id: core.newId("bnq"), action_id: F.a,
      expected_revision: e.value.revision,
    });
    assert.equal(r.ok, true);
    assert.equal(r.value.phase, "UNCERTAIN");
    assert.equal(r.value.funds, "RELEASED");
    assert.deepEqual(r.value.pending, ["CREATE"]);
  } finally { h.close(); }
});

test("TV-B--67 matured hold from AWAITING_REVIEW closes externally", async () => {
  const t = { v: F.t };
  const clock = { now: () => t.v, monotonicMs: () => 0 };
  const h = new Harness({ clock });
  try {
    const v2 = await h.toReview();
    t.v = "2026-10-28T00:00:00.000Z";
    const r = await h.call("reconcile", {
      request_id: core.newId("bnq"), action_id: F.a, expected_revision: v2.revision,
    });
    assert.equal(r.ok, true);
    assert.equal(r.value.phase, "CLOSED");
    assert.equal(r.value.funds, "RELEASED");
    // Residual effect is visible on the closing receipt.
    const p = await h.call("export", {
      action_id: F.a, through_revision: r.value.revision, include_bytes: false,
    });
    const last = p.value.receipts.at(-1);
    assert.equal(last.body.residual_effect, "DRAFT_PRESENT");
  } finally { h.close(); }
});

test("TV-B--68 inverse applied after external maturity: remedy due, no new payout", async () => {
  const t = { v: F.t };
  const clock = { now: () => t.v, monotonicMs: () => 0 };
  const h = new Harness({ clock });
  try {
    const v2 = await h.toReview();
    // Mint matures the hold externally while the local view still shows
    // ENCUMBERED; the operator then rejects. The inverse lands, the settle
    // fails against the released hold, and a maturity lookup resolves funds.
    t.v = "2026-10-28T00:00:00.000Z";
    const rej = await h.call("reject", {
      request_id: core.newId("bnq"), action_id: F.a,
      expected_revision: v2.revision, reason: "OPERATOR_REJECTED",
    });
    assert.equal(rej.ok, true);
    assert.equal(rej.value.undo, "APPLIED");
    assert.equal(rej.value.funds, "RELEASED"); // matured, never PAID
    const p = await h.call("export", {
      action_id: F.a, through_revision: rej.value.revision, include_bytes: false,
    });
    const last = p.value.receipts.at(-1);
    assert.equal(last.body.remedy, "DUE");
    assert.equal(last.body.assembly, "INCOMPLETE");
  } finally { h.close(); }
});
