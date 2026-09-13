/** TV-B--21..32, 50, 64 — the fixed-order dispatch gate. */
const test = require("node:test");
const assert = require("node:assert/strict");
const { F, core, sdk } = require("./harness.cjs");
const { dispatchGate } = sdk;
const { D, H, J } = core;

const baseHold = {
  kind: "HOLD", hold_id: "hold-1", revision: 2, action_hash: D("action", F.action),
  terms: F.action.terms, state: "ENCUMBERED", exclusive: true,
  operation_key: F.a + ":encumber",
  journal_head: { seq: 2, hash: F.action.adapter_build }, settlement_basis: null,
};

const baseRun = {
  kind: "RUN", run_id: F.run, host_id: F.host, task_ref: F.a, state: "ACTIVE",
  checkpoint: { seq: 1, hash: F.action.adapter_build }, policy_hash: F.action.adapter_build,
  complete_prefix: true,
};

const basePolicy = {
  kind: "POLICY", purpose: "FORWARD", pin: F.pin,
  input_hash: D("request", { x: 1 }), verdict: "ALLOW", reason: "ALLOW_SCOPE",
  evaluated_at: F.t,
};

function gate(over = {}) {
  const o = {
    action: F.action,
    activePin: over.active_policy_version ? { ...F.pin, version: over.active_policy_version } : F.pin,
    policyFacts: over.policy_verdict
      ? { ...basePolicy, verdict: over.policy_verdict, reason: over.policy_reason ?? "HARD_DENY" }
      : basePolicy,
    now: over.now ?? "2026-09-12T12:00:29.000Z",
    clockUncertaintyMs: over.clock_uncertainty_ms ?? 0,
    maxClockUncertaintyMs: 1000,
    runFacts: { ...baseRun, ...(over.run_task_ref ? { task_ref: over.run_task_ref } : {}) },
    runObservedMonoMs: 1000,
    admittedMonoMs: 1000 + (over.run_age_ms ?? 0),
    runFreshnessMs: 250,
    binding: { trellis_run: F.run, trellis_host: F.host, trellis_task_ref: F.a },
    paper: over.paper === undefined ? F.paper : over.paper,
    holdFacts: over.hold_amount_minor
      ? { ...baseHold, terms: { ...F.action.terms, amount_minor: over.hold_amount_minor } }
      : over.hold_action_hash !== undefined || over.hold_exclusive !== undefined
        ? { ...baseHold, action_hash: over.hold_action_hash ?? baseHold.action_hash, exclusive: over.hold_exclusive ?? true }
        : baseHold,
    stopLatched: false, scopeStopped: false, quarantined: false,
    trust: F.trust, tenantId: F.tenant,
  };
  if (over.paper_holder) {
    const p = JSON.parse(JSON.stringify(F.paper));
    p.body.holder = over.paper_holder;
    o.paper = p;
  }
  return () => dispatchGate(o);
}

const errCode = (fn) => { try { fn(); return { allowed: true }; } catch (e) { return { error: e.code, dispatches: 0 }; } };

test("TV-B--21 policy deny blocks dispatch", () => {
  assert.deepEqual(errCode(gate({ policy_verdict: "DENY", policy_reason: "HARD_DENY" })), { error: "POLICY_DENIED", dispatches: 0 });
});

test("TV-B--22 pin mismatch blocks dispatch", () => {
  assert.deepEqual(errCode(gate({ active_policy_version: 2 })), { error: "PIN_MISMATCH", dispatches: 0 });
});

test("TV-B--23 deadline boundary blocks", () => {
  assert.deepEqual(errCode(gate({ now: "2026-09-12T12:00:30.000Z" })), { error: "DEADLINE", dispatches: 0 });
});

test("TV-B--24 one ms before deadline admits", () => {
  assert.deepEqual(errCode(gate({ now: "2026-09-12T12:00:29.999Z" })), { allowed: true });
});

test("TV-B--25 run age 250ms admits", () => {
  assert.deepEqual(errCode(gate({ run_age_ms: 250 })), { allowed: true });
});

test("TV-B--26 run age 251ms is stale", () => {
  assert.deepEqual(errCode(gate({ run_age_ms: 251 })), { error: "RUN_STALE", dispatches: 0 });
});

test("TV-B--27 wrong run task_ref is RUN_BINDING", () => {
  assert.deepEqual(errCode(gate({ run_task_ref: "bac_111111111111111111111" })), { error: "RUN_BINDING", dispatches: 0 });
});

test("TV-B--28 null paper is INSURANCE_REQUIRED", () => {
  assert.deepEqual(errCode(gate({ paper: null })), { error: "INSURANCE_REQUIRED", dispatches: 0 });
});

test("TV-B--29 wrong paper holder is INSURANCE_SCOPE", () => {
  assert.deepEqual(errCode(gate({ paper_holder: "bnp_111111111111111111111" })), { error: "INSURANCE_SCOPE", dispatches: 0 });
});

test("TV-B--30 hold under amount is HOLD_INSUFFICIENT", () => {
  assert.deepEqual(errCode(gate({ hold_amount_minor: "999" })), { error: "HOLD_INSUFFICIENT", dispatches: 0 });
});

test("TV-B--31 hold for wrong action is HOLD_BINDING", () => {
  const Z = "0".repeat(64);
  assert.deepEqual(errCode(gate({ hold_action_hash: Z })), { error: "HOLD_BINDING", dispatches: 0 });
});

test("TV-B--32 non-exclusive hold is HOLD_BINDING", () => {
  assert.deepEqual(errCode(gate({ hold_exclusive: false })), { error: "HOLD_BINDING", dispatches: 0 });
});

test("TV-B--50 clock uncertainty over limit is CLOCK_UNSAFE", () => {
  assert.deepEqual(errCode(gate({ clock_uncertainty_ms: 1001 })), { error: "CLOCK_UNSAFE", dispatches: 0 });
});
