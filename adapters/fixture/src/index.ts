/**
 * Fixture adapters — honest, visibly labeled simulation of the five Bond
 * dependency surfaces (§6.3 Ports). All evidence is source_profile "fixture/1":
 * the source bytes are exactly J(facts), signed under the assertion domain by
 * the configured fixture key. These adapters simulate semantics only; they are
 * not native compatibility and must never be presented as such.
 */

import {
  Action, Assertion, CapabilityManifest, D, EffectFacts, Evidence, H, Hash, HoldFacts,
  J, KillFacts, NoHoldFacts, PolicyFacts, PortResult, RunFacts, Signer, Terms, Time,
  UndoPlan, ExternalId, newId,
} from "@latticeag/bond-core";

export interface FixtureClock {
  now(): Time;
  monotonicMs(): number;
}

export function fixedClock(t: Time, mono = 0): FixtureClock {
  let m = mono;
  return { now: () => t, monotonicMs: () => (m += 0, m) };
}

export interface FixtureSignerKit {
  keyId: string;
  signer: Signer;
}

function evidenceOf(
  facts: Assertion["facts"], actionHash: Hash, at: Time, kit: FixtureSignerKit,
): Evidence {
  const sourceBytes = Buffer.from(J(facts), "utf8");
  const source = {
    hash: H(sourceBytes), bytes: sourceBytes.length,
    media_type: "application/json" as const, data: sourceBytes.toString("base64url"),
  };
  const body: Assertion = {
    schema: "bond.assertion/1", action_hash: actionHash, observed_at: at,
    source_profile: "fixture/1",
    source: { hash: source.hash, bytes: source.bytes, media_type: source.media_type },
    facts,
  };
  const hash = D("assertion", { body, key_id: kit.keyId });
  const sig = kit.signer(new TextEncoder().encode(`LAGI-BOND/sign/assertion/1\n${hash}`));
  return {
    assertion: { body, key_id: kit.keyId, hash, sig: sig.toString("base64url") },
    source,
  };
}

const known = <T>(v: T): PortResult<T> => ({ status: "KNOWN", value: v });
export const unknownResult = <T>(): PortResult<T> => ({ status: "UNKNOWN" });

// ---------------------------------------------------------------------------
// Bedrock — embedded policy evaluator simulation.
// ---------------------------------------------------------------------------

export interface BedrockBehavior {
  /** Override verdicts by purpose; default allows well-formed requests. */
  forward?: "ALLOW" | "DENY";
  undo?: "ALLOW" | "DENY";
  reason?: string;
}

export class FixtureBedrock {
  constructor(private kit: FixtureSignerKit, private behavior: BedrockBehavior = {}) {}

  evaluate(input: { action: Action; purpose: "FORWARD" | "UNDO"; now: Time }): Evidence {
    const verdict = (input.purpose === "FORWARD" ? this.behavior.forward : this.behavior.undo) ?? "ALLOW";
    const facts: PolicyFacts = {
      kind: "POLICY",
      purpose: input.purpose,
      pin: input.action.policy_pin,
      input_hash: D("request", { action_hash: D("action", input.action), purpose: input.purpose }),
      verdict,
      reason: this.behavior.reason ?? (verdict === "ALLOW" ? "ALLOW_SCOPE" : "HARD_DENY"),
      evaluated_at: input.now,
    };
    return evidenceOf(facts, D("action", input.action), input.now, this.kit);
  }
}

/** Deterministic Bedrock request ids per action (spec §10 vectors). */
export function bedrockRequestIds(actionId: string): { forward: string; undo: string } {
  const suffix = actionId.slice(actionId.indexOf("_") + 1);
  return { forward: "brq_f" + suffix.slice(1), undo: "brq_u" + suffix.slice(1) };
}

// ---------------------------------------------------------------------------
// Mint — exclusive action-liability hold simulation.
// ---------------------------------------------------------------------------

export interface SimHold {
  holdId: ExternalId;
  revision: number;
  state: "HELD" | "ENCUMBERED" | "RELEASED" | "PAID";
  actionHash: Hash;
  terms: Terms;
  settlementBasis: "REQUEST" | "RESERVATION_EXPIRED" | "LONG_STOP" | null;
  /** Registered triggers mint accepts for settlement (accept/reject/abort markers). */
  triggers: Set<string>;
}

export interface MintBehavior {
  /** Return a malformed/unknown response instead of KNOWN evidence. */
  reserve?: "UNKNOWN" | "MALFORMED" | "NO_HOLD";
  encumber?: "UNKNOWN" | "MALFORMED";
  settle?: "UNKNOWN" | "MALFORMED";
  lookup?: "UNKNOWN";
  noFunds?: boolean;
}

export class FixtureMint {
  private holds = new Map<Hash, SimHold>();
  private seq = 0;
  private headHash = "0".repeat(64);
  /** Digest of the mint journal head reported in facts. */
  private journalHead(): { seq: number; hash: string } {
    return { seq: this.seq, hash: this.headHash };
  }
  private bump(): void {
    this.seq += 1;
    this.headHash = H("fixture-mint/" + this.seq + "/" + this.headHash);
  }

  constructor(
    private kit: FixtureSignerKit,
    private clock: FixtureClock,
    private behavior: MintBehavior = {},
  ) {}

  private holdEvidence(h: SimHold, opKey: string): Evidence {
    const facts: HoldFacts = {
      kind: "HOLD", hold_id: h.holdId, revision: h.revision, action_hash: h.actionHash,
      terms: h.terms, state: h.state, exclusive: true, operation_key: opKey,
      journal_head: this.journalHead(), settlement_basis: h.settlementBasis,
    };
    return evidenceOf(facts, h.actionHash, this.clock.now(), this.kit);
  }

  private noHoldEvidence(actionHash: Hash, opKey: string, reason: NoHoldFacts["reason"]): Evidence {
    const facts: NoHoldFacts = {
      kind: "NO_HOLD", operation_key: opKey, authoritative: true, reason,
    };
    return evidenceOf(facts, actionHash, this.clock.now(), this.kit);
  }

  /** Register a settlement trigger digest (accept entry hash, reject entry hash, abort marker). */
  registerTrigger(holdActionHash: Hash, triggerHash: string): void {
    const h = this.holds.get(holdActionHash);
    if (h) h.triggers.add(triggerHash);
  }

  hold(actionHash: Hash): SimHold | undefined {
    return this.holds.get(actionHash);
  }

  /** Serialize the simulated ledger so the CLI's separate processes share one world. */
  exportState(): { holds: [Hash, Record<string, unknown>][], seq: number; headHash: string } {
    return {
      holds: [...this.holds.entries()].map(([k, h]) => [k, { ...h, triggers: [...h.triggers] }]),
      seq: this.seq, headHash: this.headHash,
    };
  }

  importState(s: { holds: [Hash, Record<string, unknown>][]; seq: number; headHash: string }): void {
    this.holds = new Map(s.holds.map(([k, h]) =>
      [k, { ...(h as unknown as SimHold), triggers: new Set(h.triggers as string[]) }]));
    this.seq = s.seq;
    this.headHash = s.headHash;
  }

  async reserve(req: { action_hash: Hash; operation_key: string; terms: Terms }): Promise<PortResult<Evidence>> {
    if (this.behavior.reserve === "UNKNOWN") return unknownResult();
    if (this.behavior.reserve === "MALFORMED") {
      return known({ assertion: { bogus: true }, source: null } as unknown as Evidence);
    }
    const existing = this.holds.get(req.action_hash);
    if (existing) return known(this.holdEvidence(existing, req.operation_key));
    if (this.behavior.reserve === "NO_HOLD" || this.behavior.noFunds) {
      return known(this.noHoldEvidence(req.action_hash, req.operation_key, "INSUFFICIENT_FUNDS"));
    }
    const h: SimHold = {
      holdId: "hold-" + (this.holds.size + 1), revision: 1, state: "HELD",
      actionHash: req.action_hash, terms: req.terms, settlementBasis: null,
      triggers: new Set(),
    };
    this.holds.set(req.action_hash, h);
    this.bump();
    return known(this.holdEvidence(h, req.operation_key));
  }

  async encumber(req: { action_hash: Hash; operation_key: string; hold_id: ExternalId; expected_revision: number }): Promise<PortResult<Evidence>> {
    if (this.behavior.encumber === "UNKNOWN") return unknownResult();
    if (this.behavior.encumber === "MALFORMED") {
      return known({ assertion: { bogus: true }, source: null } as unknown as Evidence);
    }
    const h = this.holds.get(req.action_hash);
    if (!h || h.holdId !== req.hold_id || h.revision !== req.expected_revision || h.state !== "HELD") {
      return known(this.noHoldEvidence(req.action_hash, req.operation_key, "EXPIRED"));
    }
    h.revision += 1;
    h.state = "ENCUMBERED";
    this.bump();
    return known(this.holdEvidence(h, req.operation_key));
  }

  async settle(req: {
    action_hash: Hash; operation_key: string; hold_id: ExternalId;
    expected_revision: number; disposition: "RELEASE" | "PAY"; trigger_hash: Hash;
  }): Promise<PortResult<Evidence>> {
    if (this.behavior.settle === "UNKNOWN") return unknownResult();
    if (this.behavior.settle === "MALFORMED") {
      return known({ assertion: { bogus: true }, source: null } as unknown as Evidence);
    }
    const h = this.holds.get(req.action_hash);
    // A failed settle is UNKNOWN, never a fabricated NO_HOLD: the reducer
    // admits NO_HOLD only on the RESERVE lane, and claiming the hold is absent
    // when it is not would be a dishonest answer.
    if (!h || h.holdId !== req.hold_id || h.revision !== req.expected_revision ||
      (h.state !== "HELD" && h.state !== "ENCUMBERED")) {
      return unknownResult();
    }
    // The fixture enforces the frozen trigger: a registered marker digest must
    // match. Without it, settlement is not permitted — report UNKNOWN.
    if (!h.triggers.has(req.trigger_hash)) {
      return unknownResult();
    }
    h.revision += 1;
    h.state = req.disposition === "PAY" ? "PAID" : "RELEASED";
    h.settlementBasis = "REQUEST";
    this.bump();
    return known(this.holdEvidence(h, req.operation_key));
  }

  async lookup(req: { action_hash: Hash; operation_key: string }): Promise<PortResult<Evidence>> {
    if (this.behavior.lookup === "UNKNOWN") return unknownResult();
    const h = this.holds.get(req.action_hash);
    if (!h) return known(this.noHoldEvidence(req.action_hash, req.operation_key, "EXPIRED"));
    // Simulated maturity: reservation/long-stop expiry releases without request.
    const now = this.clock.now();
    if ((h.state === "HELD" || h.state === "ENCUMBERED") &&
      now > h.terms.reserve_until && h.settlementBasis === null) {
      h.revision += 1;
      h.state = "RELEASED";
      h.settlementBasis = now > h.terms.long_stop ? "LONG_STOP" : "RESERVATION_EXPIRED";
      this.bump();
    }
    return known(this.holdEvidence(h, req.operation_key));
  }

  /** Deterministic pending-witness malformed state for TV-B--34. */
  async pendingWitness(req: { action_hash: Hash; operation_key: string }): Promise<PortResult<Evidence>> {
    const facts = {
      kind: "HOLD", hold_id: "hold-1", revision: 1, action_hash: req.action_hash,
      terms: {}, state: "PENDING_WITNESS", exclusive: true, operation_key: req.operation_key,
      journal_head: { seq: 1, hash: "a".repeat(64) }, settlement_basis: null,
    } as unknown as HoldFacts;
    return known(evidenceOf(facts, req.action_hash, this.clock.now(), this.kit));
  }
}

// ---------------------------------------------------------------------------
// VekRevert — conditional inverse plan/apply/lookup simulation.
// ---------------------------------------------------------------------------

export interface SimDraft {
  resource: string;
  version: ExternalId;
  valueHash: Hash;
  status: "DRAFT";
  exported: boolean;
  deleted: boolean;
}

/** Shared simulated conditional-create/versioned-delete draft store. */
export class FixtureDraftStore {
  records = new Map<string, SimDraft>();
  /** action_hash -> resource index so lookups can find the bound record. */
  byAction = new Map<Hash, string>();
  currentFence = 0;
  get(resource: string): SimDraft | undefined { return this.records.get(resource); }
}

export interface VekBehavior {
  apply?: "UNKNOWN" | "MALFORMED" | "DENY_PLAN" | "VERSION_CHANGED";
  lookup?: "UNKNOWN";
}

export class FixtureVekrevert {
  constructor(
    private kit: FixtureSignerKit,
    private clock: FixtureClock,
    private store: FixtureDraftStore,
    private behavior: VekBehavior = {},
  ) {}

  async plan(input: { action: Action }): Promise<UndoPlan> {
    return {
      schema: "bond.undo-plan/1",
      action_hash: D("action", input.action),
      adapter_build: input.action.adapter_build,
      operation: "draft.delete_if_created_version",
      resource: input.action.resource,
      require_status: "DRAFT",
      require_no_export: true,
      version_source: "FORWARD_RESULT",
      value_hash: H(J(input.action.draft)),
      remedy_minor: "1000",
      asset: "SIMUSD",
      expires_at: input.action.terms.long_stop,
    };
  }

  async apply(req: {
    action_hash: Hash; operation_key: string; action: Action; plan: UndoPlan;
    policy: Evidence; fence: number; created_version: ExternalId; created_value_hash: Hash;
  }): Promise<PortResult<Evidence>> {
    if (this.behavior.apply === "UNKNOWN") return unknownResult();
    const at = this.clock.now();
    const mk = (outcome: EffectFacts["outcome"], reason: EffectFacts["reason"], version: string | null, vh: Hash | null): Evidence =>
      evidenceOf({
        kind: "EFFECT", purpose: "UNDO", operation_key: req.operation_key,
        outcome, resource: req.plan.resource, version, value_hash: vh, reason,
      } satisfies EffectFacts, req.action_hash, at, this.kit);
    if (this.behavior.apply === "DENY_PLAN") return known(mk("NOT_APPLIED", "POLICY_DENIED", null, null));
    if (this.behavior.apply === "VERSION_CHANGED") return known(mk("NOT_APPLIED", "VERSION_CHANGED", null, null));
    if (req.fence !== this.store.currentFence) return known(mk("NOT_APPLIED", "STOPPED_BEFORE_CALL", null, null));
    const rec = this.store.get(req.plan.resource);
    if (!rec || rec.deleted) return known(mk("NOT_APPLIED", "ABSENT", null, null));
    if (rec.exported || rec.version !== req.created_version) {
      return known(mk("NOT_APPLIED", "VERSION_CHANGED", null, null));
    }
    rec.deleted = true;
    return known(mk("APPLIED", "DELETED", rec.version, rec.valueHash));
  }

  async lookup(req: { action_hash: Hash; operation_key: string }): Promise<PortResult<Evidence>> {
    if (this.behavior.lookup === "UNKNOWN") return unknownResult();
    const resource = this.store.byAction.get(req.action_hash);
    const rec = resource ? this.store.get(resource) : undefined;
    if (rec && rec.deleted) {
      return known(evidenceOf({
        kind: "EFFECT", purpose: "UNDO", operation_key: req.operation_key,
        outcome: "APPLIED", resource: rec.resource,
        version: rec.version, value_hash: rec.valueHash, reason: "DELETED",
      } satisfies EffectFacts, req.action_hash, this.clock.now(), this.kit));
    }
    if (!rec) {
      return known(evidenceOf({
        kind: "EFFECT", purpose: "UNDO", operation_key: req.operation_key,
        outcome: "NOT_APPLIED", resource: resource ?? "drafts/unknown",
        version: null, value_hash: null, reason: "ABSENT",
      } satisfies EffectFacts, req.action_hash, this.clock.now(), this.kit));
    }
    // The draft still exists: the conditional inverse has not taken effect.
    // That is an honest UNKNOWN — the apply may never have run.
    return known(evidenceOf({
      kind: "EFFECT", purpose: "UNDO", operation_key: req.operation_key,
      outcome: "UNKNOWN", resource: rec.resource,
      version: null, value_hash: null, reason: "TRANSPORT_UNKNOWN",
    } satisfies EffectFacts, req.action_hash, this.clock.now(), this.kit));
  }
}

// ---------------------------------------------------------------------------
// Trellis — run observation, stop, certificate simulation.
// ---------------------------------------------------------------------------

export interface TrellisBehavior {
  runState?: "ACTIVE" | "STOPPING" | "STOPPED" | "UNCONFIRMED";
  stop?: "UNKNOWN" | "UNCONFIRMED";
  certificate?: "UNKNOWN" | "UNCONFIRMED";
  auditGap?: boolean;
}

export class FixtureTrellis {
  private stopped = false;
  private bound = new Map<string, Hash>(); // action_id -> action_hash
  constructor(
    private kit: FixtureSignerKit,
    private clock: FixtureClock,
    private runId: ExternalId,
    private hostId: ExternalId,
    private behavior: TrellisBehavior = {},
  ) {}

  /** The coordinator binds the action hash when it claims the run at prepare. */
  bindAction(actionId: string, actionHash: Hash): void {
    this.bound.set(actionId, actionHash);
  }

  exportState(): { stopped: boolean; bound: [string, Hash][] } {
    return { stopped: this.stopped, bound: [...this.bound.entries()] };
  }

  importState(s: { stopped: boolean; bound: [string, Hash][] }): void {
    this.stopped = s.stopped;
    this.bound = new Map(s.bound);
  }

  private actionHash(input: { action_id: string }): Hash {
    return this.bound.get(input.action_id) ?? "0".repeat(64);
  }

  async observe(input: { action_id: string; run_id: ExternalId }): Promise<Evidence> {
    const facts: RunFacts = {
      kind: "RUN", run_id: input.run_id, host_id: this.hostId, task_ref: input.action_id,
      state: this.stopped ? "STOPPED" : (this.behavior.runState ?? "ACTIVE"),
      checkpoint: { seq: 1, hash: "a".repeat(64) },
      policy_hash: "a".repeat(64),
      complete_prefix: true,
    };
    return evidenceOf(facts, this.actionHash(input), this.clock.now(), this.kit);
  }

  async stop(input: { action_id: string; run_id: ExternalId; operation_key: string }): Promise<PortResult<Evidence>> {
    if (this.behavior.stop === "UNKNOWN") return unknownResult();
    this.stopped = true;
    return known(this.killEvidence(input, this.behavior.stop === "UNCONFIRMED" ? "UNCONFIRMED" : "CERTIFIED"));
  }

  async certificate(input: { action_id: string; run_id: ExternalId }): Promise<PortResult<Evidence>> {
    if (this.behavior.certificate === "UNKNOWN") return unknownResult();
    if (this.behavior.certificate === "UNCONFIRMED") {
      return known(this.killEvidence(input, "UNCONFIRMED"));
    }
    return known(this.killEvidence(input, "CERTIFIED"));
  }

  private killEvidence(input: { action_id: string; run_id: ExternalId }, state: "CERTIFIED" | "UNCONFIRMED"): Evidence {
    const gap = this.behavior.auditGap === true;
    const facts: KillFacts = {
      kind: "KILL", run_id: input.run_id, host_id: this.hostId, task_ref: input.action_id,
      state: gap ? "UNCONFIRMED" : state,
      stopped_head: !gap && state === "CERTIFIED" ? { seq: 9, hash: "a".repeat(64) } : null,
      gate_closed: !gap && state === "CERTIFIED",
      empty_observed: !gap && state === "CERTIFIED",
      audit_gap: gap,
      external_effects: "NOT_REVERSED",
      remote_replication: "NOT_ATTESTED",
    };
    return evidenceOf(facts, this.actionHash(input), this.clock.now(), this.kit);
  }
}

// ---------------------------------------------------------------------------
// Executor — conditional create against the simulated draft store.
// ---------------------------------------------------------------------------

export interface ExecutorBehavior {
  create?: "UNKNOWN" | "MALFORMED" | "NOT_APPLIED";
  lookup?: "UNKNOWN";
}

export class FixtureExecutor {
  constructor(
    private kit: FixtureSignerKit,
    private clock: FixtureClock,
    private store: FixtureDraftStore,
    private behavior: ExecutorBehavior = {},
  ) {}

  async create(req: {
    action_hash: Hash; operation_key: string; action: Action; plan: UndoPlan;
    policy: Evidence; fence: number;
  }): Promise<PortResult<Evidence>> {
    if (this.behavior.create === "UNKNOWN") return unknownResult();
    const at = this.clock.now();
    const mk = (outcome: EffectFacts["outcome"], reason: EffectFacts["reason"], version: string | null, vh: Hash | null): Evidence =>
      evidenceOf({
        kind: "EFFECT", purpose: "FORWARD", operation_key: req.operation_key,
        outcome, resource: req.action.resource, version, value_hash: vh, reason,
      } satisfies EffectFacts, req.action_hash, at, this.kit);
    if (req.fence !== this.store.currentFence) return known(mk("NOT_APPLIED", "STOPPED_BEFORE_CALL", null, null));
    const existing = this.store.get(req.action.resource);
    if (existing && !existing.deleted) return known(mk("NOT_APPLIED", "VERSION_CHANGED", null, null));
    if (this.behavior.create === "NOT_APPLIED") return known(mk("NOT_APPLIED", "POLICY_DENIED", null, null));
    const rec: SimDraft = {
      resource: req.action.resource, version: "v1",
      valueHash: H(J(req.action.draft)), status: "DRAFT", exported: false, deleted: false,
    };
    this.store.records.set(rec.resource, rec);
    this.store.byAction.set(req.action_hash, rec.resource);
    return known(mk("APPLIED", "CREATED", rec.version, rec.valueHash));
  }

  async lookup(req: { action_hash: Hash; operation_key: string; resource?: string }): Promise<PortResult<Evidence>> {
    if (this.behavior.lookup === "UNKNOWN") return unknownResult();
    const rec = this.store.get(req.resource ?? "");
    const at = this.clock.now();
    if (!rec) {
      return known(evidenceOf({
        kind: "EFFECT", purpose: "FORWARD", operation_key: req.operation_key,
        outcome: "NOT_APPLIED", resource: req.resource ?? "drafts/unknown",
        version: null, value_hash: null, reason: "ABSENT",
      } satisfies EffectFacts, req.action_hash, at, this.kit));
    }
    // The create effect happened even if a later inverse deleted the record.
    return known(evidenceOf({
      kind: "EFFECT", purpose: "FORWARD", operation_key: req.operation_key,
      outcome: "APPLIED", resource: rec.resource, version: rec.version,
      value_hash: rec.valueHash, reason: "CREATED",
    } satisfies EffectFacts, req.action_hash, at, this.kit));
  }
}

// ---------------------------------------------------------------------------
// Capability manifests for the fixture adapters (mode SIMULATED).
// ---------------------------------------------------------------------------

export function fixtureManifest(
  adapter: CapabilityManifest["adapter"],
  buildHash: Hash,
  keyId: string,
): CapabilityManifest {
  const methods: Record<string, string[]> = {
    bedrock: ["bedrock.evaluate"],
    mint: ["mint.encumber", "mint.lookup", "mint.reserve", "mint.settle"],
    vekrevert: ["vekrevert.apply", "vekrevert.lookup", "vekrevert.plan"],
    trellis: ["trellis.certificate", "trellis.observe", "trellis.stop"],
    executor: ["executor.create", "executor.lookup"],
  };
  const guarantees = {
    bedrock: { embedded_policy: true },
    mint: { exclusive_hold: true, action_consume: true, authoritative_lookup: true },
    vekrevert: { conditional_inverse: true, writer_fence: true, authoritative_lookup: true },
    trellis: { bound_local_run: true },
    executor: { writer_fence: true, authoritative_lookup: true },
  }[adapter];
  return {
    schema: "bond.adapter-capabilities/1",
    adapter,
    build_hash: buildHash,
    mode: "SIMULATED",
    source_profile: "fixture/1",
    methods: methods[adapter]!.sort(),
    assertion_key_id: keyId,
    conformance_report_hash: "0".repeat(64),
    guarantees: {
      exclusive_hold: false, action_consume: false, authoritative_lookup: false,
      conditional_inverse: false, writer_fence: false, bound_local_run: false,
      embedded_policy: false, ...guarantees,
    },
  };
}

/** Aggregate of all five fixture adapters behind a Ports-shaped facade. */
export interface FixtureAdapterSet {
  bedrock: FixtureBedrock;
  mint: FixtureMint;
  vekrevert: FixtureVekrevert;
  trellis: FixtureTrellis;
  executor: FixtureExecutor;
  store: FixtureDraftStore;
  clock: FixtureClock;
  manifests: CapabilityManifest[];
}

export function makeFixtureAdapters(opts: {
  keyId: string;
  signer: Signer;
  clock: FixtureClock;
  runId: ExternalId;
  hostId: ExternalId;
  buildHash: Hash;
  bedrock?: BedrockBehavior;
  mint?: MintBehavior;
  vekrevert?: VekBehavior;
  trellis?: TrellisBehavior;
  executor?: ExecutorBehavior;
}): FixtureAdapterSet {
  const kit = { keyId: opts.keyId, signer: opts.signer };
  const store = new FixtureDraftStore();
  const bedrock = new FixtureBedrock(kit, opts.bedrock ?? {});
  const mint = new FixtureMint(kit, opts.clock, opts.mint ?? {});
  const vekrevert = new FixtureVekrevert(kit, opts.clock, store, opts.vekrevert ?? {});
  const trellis = new FixtureTrellis(kit, opts.clock, opts.runId, opts.hostId, opts.trellis ?? {});
  const executor = new FixtureExecutor(kit, opts.clock, store, opts.executor ?? {});
  return {
    bedrock, mint, vekrevert, trellis, executor, store, clock: opts.clock,
    manifests: (["bedrock", "mint", "vekrevert", "trellis", "executor"] as const)
      .map((a) => fixtureManifest(a, opts.buildHash, opts.keyId)),
  };
}

/** Route a port call to the right fixture adapter (used by the coordinator). */
export async function callFixture(
  set: FixtureAdapterSet,
  port: string,
  input: unknown,
): Promise<unknown> {
  switch (port) {
    case "bedrock.evaluate": return set.bedrock.evaluate(input as never);
    case "mint.reserve": return set.mint.reserve(input as never);
    case "mint.encumber": return set.mint.encumber(input as never);
    case "mint.settle": return set.mint.settle(input as never);
    case "mint.lookup": return set.mint.lookup(input as never);
    case "vekrevert.plan": return set.vekrevert.plan(input as never);
    case "vekrevert.apply": return set.vekrevert.apply(input as never);
    case "vekrevert.lookup": return set.vekrevert.lookup(input as never);
    case "trellis.observe": return set.trellis.observe(input as never);
    case "trellis.stop": return set.trellis.stop(input as never);
    case "trellis.certificate": return set.trellis.certificate(input as never);
    case "executor.create": return set.executor.create(input as never);
    case "executor.lookup": return set.executor.lookup(input as never);
    default: throw new Error("unknown port " + port);
  }
}

// ---------------------------------------------------------------------------
// Simulated-world persistence. The CLI invokes each command in a fresh
// process; the fixture world models external services whose state must
// legitimately outlive the Bond process. This file is explicit simulation
// state — it is NOT part of the journal and carries no authority.
// ---------------------------------------------------------------------------

export interface WorldSnapshot {
  mint: ReturnType<FixtureMint["exportState"]>;
  trellis: ReturnType<FixtureTrellis["exportState"]>;
  records: [string, SimDraft][];
  byAction: [Hash, string][];
  currentFence: number;
}

export function snapshotWorld(set: FixtureAdapterSet): WorldSnapshot {
  return {
    mint: set.mint.exportState(),
    trellis: set.trellis.exportState(),
    records: [...set.store.records.entries()].map(([k, v]) => [k, { ...v }]),
    byAction: [...set.store.byAction.entries()],
    currentFence: set.store.currentFence,
  };
}

export function restoreWorld(set: FixtureAdapterSet, s: WorldSnapshot): void {
  set.mint.importState(s.mint);
  set.trellis.importState(s.trellis);
  set.store.records = new Map(s.records.map(([k, v]) => [k, { ...v }]));
  set.store.byAction = new Map(s.byAction);
  set.store.currentFence = s.currentFence;
}
