/**
 * Shared conformance harness — builds a BondClient over fixture adapters in a
 * temp journal dir. Counters expose dispatches/payouts for the TV-B vectors.
 */

const { mkdtempSync, rmSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join } = require("node:path");
const core = require("@latticeag/bond-core");
const sdk = require("@latticeag/bond-sdk");
const fx = require("@latticeag/bond-adapters-fixture");
const { F } = require("../../fixtures/f.js");

const SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const KEY_ID = "bnk_conformancekey0000001";

function makeTrust(tenant) {
  return {
    schema: "bond.trust/1",
    keys: [{
      key_id: KEY_ID,
      public_key_hex: core.publicKeyHexFromSeed(SEED),
      roles: ["assertion", "entry", "http", "notice", "paper", "receipt"],
      assertion_kinds: ["EFFECT", "HOLD", "KILL", "NO_HOLD", "POLICY", "RUN"],
      source_profiles: ["fixture/1"],
      tenant_id: tenant ?? F.tenant,
      not_before: "2026-09-01T00:00:00.000Z",
      not_after: "2026-11-01T00:00:00.000Z",
      compromised_at: null,
    }],
    allowed_adapter_builds: [F.action.adapter_build],
    expected_heads: [],
  };
}

function makeConfig(dir) {
  return {
    schema: "bond.config/1", profile: F.profile, tenant_id: F.tenant,
    scope_id: F.scope, principal_id: F.principal, data_dir: dir,
    trust_file: "trust.json", signing_key_ref: "main",
    clock_max_uncertainty_ms: 1000, run_freshness_ms: 250,
    dependency_timeout_ms: 5000, max_pending_actions: 100,
    max_package_bytes: 8388608, insurance_mode: "paper-required",
    scope_binding: {
      bedrock_principal: "bedrock-1", bedrock_scope: F.scope,
      mint_owner: F.action.terms.owner, mint_beneficiary: F.action.terms.beneficiary,
    },
    adapters: [], hosting: { enabled: false },
  };
}

const CTX = {
  tenant_id: F.tenant, principal_id: F.principal,
  scopes: [F.scope], roles: ["operator", "agent", "auditor", "publisher"],
};

class Harness {
  constructor(opts = {}) {
    this.dir = mkdtempSync(join(tmpdir(), "bond-tv-"));
    this.opts = opts;
    this.clock = opts.clock ?? fx.fixedClock(F.t, 0);
    this.signer = core.seedSigner(SEED);
    this.trust = opts.trust ?? makeTrust();
    this.counters = { dispatches: 0, reserves: 0, settles: 0, lookups: 0 };
    this.mutate = opts.mutate ?? {};
    this.#build();
  }

  #build() {
    const o = this.opts;
    // Adapter state survives a simulated restart (it models the world, not us).
    this.set ??= fx.makeFixtureAdapters({
      keyId: KEY_ID, signer: this.signer, clock: this.clock,
      runId: o.runId ?? F.run, hostId: o.hostId ?? F.host,
      buildHash: F.action.adapter_build,
      bedrock: o.bedrock, mint: o.mint, vekrevert: o.vekrevert,
      trellis: o.trellis, executor: o.executor,
    });
    const set = this.set;
    const counters = this.counters;
    const mutate = this.mutate;
    this.ports = {
      call: async (p, i) => {
        if (p === "executor.create") counters.dispatches++;
        if (p === "mint.reserve") counters.reserves++;
        if (p === "mint.settle") counters.settles++;
        if (p.endsWith(".lookup") || p === "trellis.certificate") counters.lookups++;
        if (mutate[p]) return mutate[p](i, set);
        return fx.callFixture(set, p, i);
      },
      bindAction: (id, h) => set.trellis.bindAction(id, h),
      registerTrigger: (ah, th) => set.mint.registerTrigger(ah, th),
    };
    this.client = new sdk.BondClient({
      config: makeConfig(this.dir), trust: this.trust,
      secrets: sdk.fileSecrets({ main: SEED }),
      clock: {
        now: this.clock.now, monotonicMs: this.clock.monotonicMs,
        uncertaintyMs: this.opts.uncertaintyMs ?? (() => 0),
      },
      ports: this.ports,
      activePin: this.opts.activePin ?? (() => F.pin),
      capabilityCheck: this.opts.capabilityCheck ?? (() => []),
      authContext: this.opts.ctx ?? CTX,
      onDispatchAdmitted: this.opts.onDispatchAdmitted,
    });
    set.store.currentFence = this.client.coordinator.fence;
  }

  /** Simulate a process restart: close and rebuild the client on the same dir. */
  reopen(over = {}) {
    this.client.close();
    Object.assign(this.opts, over);
    this.clock = this.opts.clock ?? this.clock;
    this.mutate = this.opts.mutate ?? {};
    this.#build();
    return this;
  }

  async call(method, input) {
    return this.client.call(method, input);
  }

  async recover() {
    return this.client.recover();
  }

  view() {
    return this.client.call("inspect", { action_id: F.a });
  }

  async prepare(over = {}) {
    return this.call("prepare", {
      request_id: core.newId("bnq"), expected_revision: 0,
      action: over.action ?? F.action, run_id: over.run_id ?? F.run,
      paper: over.paper === undefined ? F.paper : over.paper,
      ...over,
    });
  }

  async execute(rev) {
    return this.call("execute", {
      request_id: core.newId("bnq"), action_id: F.a, expected_revision: rev,
    });
  }

  /** Reach the READY state (fixture S1): prepare only. */
  async toReady(over) {
    const p = await this.prepare(over);
    if (!p.ok) throw new Error("prepare failed: " + p.code);
    return p.value;
  }

  /** Reach AWAITING_REVIEW (fixture S2): prepare + execute. */
  async toReview(over) {
    await this.toReady(over);
    const e = await this.execute(2);
    if (!e.ok) throw new Error("execute failed: " + e.code);
    return e.value;
  }

  close() {
    this.client.close();
    rmSync(this.dir, { recursive: true, force: true });
  }
}

module.exports = { Harness, makeTrust, makeConfig, CTX, SEED, KEY_ID, F, core, fx, sdk };
