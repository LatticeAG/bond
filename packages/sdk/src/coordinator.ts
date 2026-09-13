/**
 * Bond coordinator — §5.2 dispatch algorithm, §5.3 idempotency/deadlines,
 * §5.4 crash windows. Single-writer over the SQLite journal; dependency calls
 * happen strictly outside transactions; every admission is idempotent.
 */

import {
  Action, ArtifactRef, Assertion, AuthContext, Blob, BondError, Code, Config, D,
  deepEqual, Doctor, EffectFacts, Entry, EntryBody, Evidence, EventData, Facts, Head,
  HoldFacts, isBondId, J, KillFacts, newId, Notice, Package, PaperReview, PolicyFacts,
  PolicyPin, Result, RunFacts, Signed, Signer, signObject, Terms, Time, TrustFile,
  UndoPlan, Verification, View, verifySigned, parseAssertionBlob, refOf, blobOf,
  ok, fail, timeMs, b64uEncode, vAction, vSigned, vPaperReview, vAssertion, vUndoPlan,
  vBlob, vEntryBody, vFacts, checkPaperConsistency, PACKAGE_LIMITS, applyEntry, initialState,
  toView, pendingOps, computedDisposition, serializeState, deserializeState,
  residualEffect, remedyState, assemblyOf, ReducerEnv, RState, ForkSignal, opKey,
  verifyPackage, parseJsonBytes, ZERO_HASH, H, vReceiptBody, Binding, Op,
} from "@latticeag/bond-core";
import { Journal, ActionRow } from "./journal.js";
import { dispatchGate } from "./gate.js";

export interface Clock {
  now(): Time;
  monotonicMs(): number;
  uncertaintyMs(): number;
}

export function systemClock(): Clock {
  const m0 = performance.now();
  return {
    now: () => new Date().toISOString(),
    monotonicMs: () => performance.now() - m0,
    uncertaintyMs: () => 0,
  };
}

export interface PortCaller {
  call(port: string, input: unknown): Promise<unknown>;
  /** Optional adapter hook: bind action hash for trellis-style observations. */
  bindAction?(actionId: string, actionHash: string): void;
  /** Optional adapter hook: register a settlement trigger digest. */
  registerTrigger?(actionHash: string, triggerHash: string): void;
}

export interface CoordinatorDeps {
  journal: Journal;
  config: Config;
  trust: TrustFile;
  signer: Signer;
  keyId: string;
  clock: Clock;
  ports: PortCaller;
  activePin: () => PolicyPin;
  capabilityCheck: () => string[];
  onDispatchAdmitted?: (actionId: string) => Promise<void> | void;
}

const MAX_DEP_CALLS = 16;
const SOFT_ENTRY_CAP = 192;

export interface LoadedAction {
  row: ActionRow;
  action: Action;
  plan: UndoPlan;
  binding: Binding;
  state: RState;
}

const jbytes = (x: unknown): Buffer => Buffer.from(J(x), "utf8");
const codeOf = (e: unknown): Code => (e instanceof BondError ? e.code : "STORAGE");

export class Coordinator {
  private j: Journal;
  private cfg: Config;
  private trust: TrustFile;
  private signer: Signer;
  private keyId: string;
  private clock: Clock;
  private ports: PortCaller;
  private activePinFn: () => PolicyPin;
  private capCheck: () => string[];
  private onDispatchAdmitted?: (actionId: string) => Promise<void> | void;
  readonly fence: number;
  private mutex: Promise<void> = Promise.resolve();

  constructor(d: CoordinatorDeps) {
    this.j = d.journal;
    this.cfg = d.config;
    this.trust = d.trust;
    this.signer = d.signer;
    this.keyId = d.keyId;
    this.clock = d.clock;
    this.ports = d.ports;
    this.activePinFn = d.activePin;
    this.capCheck = d.capabilityCheck;
    this.onDispatchAdmitted = d.onDispatchAdmitted;
    const cur = this.j.getMetadata("fence_counter");
    this.fence = (cur ? Number(cur.toString()) : 0) + 1;
    this.j.setMetadata("fence_counter", Buffer.from(String(this.fence)));
  }

  private async withMutex<T>(fn: () => Promise<T>): Promise<T> {
    const prev = this.mutex;
    let release!: () => void;
    this.mutex = new Promise((r) => (release = r));
    await prev;
    try {
      return await fn();
    } finally {
      release();
    }
  }

  // --- request identity (§5.3) ------------------------------------------------

  private admit(
    ctx: AuthContext, method: string, input: unknown,
  ): { replay: unknown | null; requestId: string } {
    const reqId = (input as { request_id?: string }).request_id;
    if (!reqId || !isBondId(reqId, "bnq")) throw new BondError("SCHEMA", "bad request_id");
    const hash = D("request", { method, input });
    const existing = this.j.admitRequest(ctx.tenant_id, ctx.principal_id, reqId, hash);
    if (existing === "ADMITTED") {
      this.j.setMetadata(
        `request_input:${ctx.tenant_id}:${ctx.principal_id}:${reqId}`,
        jbytes({ method, input }),
      );
      return { replay: null, requestId: reqId };
    }
    if (existing.request_hash !== hash) throw new BondError("IDEMPOTENCY_CONFLICT");
    if (existing.state === "DONE") {
      return { replay: JSON.parse(Buffer.from(existing.response!).toString("utf8")), requestId: reqId };
    }
    throw new BondError("BUSY", "request in flight");
  }

  private finish<T>(ctx: AuthContext, requestId: string, response: Result<T>): Result<T> {
    this.j.finishRequest(ctx.tenant_id, ctx.principal_id, requestId, jbytes(response));
    return response;
  }

  // --- object/evidence storage -------------------------------------------------

  private storeBlob(bytes: Buffer, mediaType: "application/json" | "application/pdf"): ArtifactRef {
    const hash = this.j.storeObjectBytes(bytes, mediaType);
    return { hash, bytes: bytes.length, media_type: mediaType };
  }

  private storeEvidence(ev: Evidence): ArtifactRef {
    if (ev.source.data !== null) {
      this.j.storeObjectBytes(Buffer.from(ev.source.data, "base64url"), ev.source.media_type);
    }
    const ab = jbytes(ev.assertion);
    const hash = this.j.storeObjectBytes(ab, "application/json");
    return { hash, bytes: ab.length, media_type: "application/json" };
  }

  private resolverFor(a: LoadedAction) {
    return (ref: ArtifactRef): { facts: Facts; evidenceHash: string } | null => {
      const bytes = this.j.getObjectBytes(ref.hash);
      if (!bytes) return null;
      const signed = parseAssertionBlob(bytes);
      verifySigned("assertion", signed, this.trust, a.row.tenant_id);
      if (signed.body.action_hash !== a.row.action_hash) {
        throw new BondError("PROJECTION_INVALID", "assertion binding");
      }
      if (!this.j.hasObject(signed.body.source.hash)) return null;
      return { facts: signed.body.facts, evidenceHash: ref.hash };
    };
  }

  private envFor(a: LoadedAction): ReducerEnv {
    return { action: a.action, plan: a.plan, binding: a.binding, resolve: this.resolverFor(a) };
  }

  // --- entry + receipt commit -------------------------------------------------

  private commitEntry(
    a: LoadedAction,
    kind: keyof EventData,
    data: EventData[keyof EventData],
    actor: string,
    insertRow = false,
  ): { view: View; noop: boolean } {
    return this.j.tx(() => {
      if (insertRow) this.j.insertAction(a.row);
      // Writer-fence takeover: a restarted writer claiming this action bumps
      // the row's fence in the same transaction, so operation rows created
      // below carry the current fence while pre-restart ops keep their
      // stale (rejected-by-executor) creator fence.
      if (a.row.writer_fence !== this.fence) {
        this.j.updateActionFence(a.row.action_id, this.fence);
        a.row.writer_fence = this.fence;
      }
      const body = {
        schema: "bond.entry/1", tenant_id: a.row.tenant_id, action_id: a.row.action_id,
        action_hash: a.row.action_hash, event_id: newId("bnj"),
        seq: a.state.revision + 1, previous_hash: a.state.head.hash,
        recorded_at: this.clock.now(), actor, kind, data,
      } as EntryBody;
      const entry = signObject("entry", body, this.keyId, this.signer);
      const r = applyEntry(
        a.state.revision === 0 ? null : a.state, body, entry.hash, this.envFor(a), "ingest");
      if (r.noop) return { view: toView(a.state), noop: true };
      a.state = r.state;
      a.state.receiptId = a.row.receipt_id;
      a.state.actionId = a.row.action_id;
      const view = toView(a.state);
      const receipt = this.issueReceipt(a, entry, view);
      this.j.appendEntry(a.row.action_id, body.seq, entry.hash, jbytes(entry));
      this.j.appendReceipt(
        a.row.receipt_id, receipt.body.revision, a.row.action_id, receipt.hash, jbytes(receipt));
      for (const op of a.state.ops.values()) {
        this.j.putOperation({
          operation_key: opKey(a.row.action_id, op.kind), action_id: a.row.action_id,
          kind: op.kind, request_hash: "", request: Buffer.alloc(0), state: op.state,
          writer_fence: a.row.writer_fence, last_evidence_hash: null,
        });
      }
      this.j.updateActionProjection(
        a.row.action_id, a.state.revision, jbytes(serializeState(a.state)),
        a.state.stopLatched ? 1 : 0, a.state.quarantined ? 1 : 0,
        a.state.holdFacts?.hold_id ?? null,
      );
      for (const h of collectRefHashes(a, receipt.body)) {
        this.j.setReference(a.row.receipt_id, receipt.body.revision, h);
      }
      return { view, noop: false };
    });
  }

  private issueReceipt(a: LoadedAction, entry: Entry, view: View): Signed<import("@latticeag/bond-core").ReceiptBody> {
    const prev = this.j.getReceipts(a.row.action_id);
    const prevHash = prev.length ? prev[prev.length - 1]!.hash : null;
    const body = {
      schema: "bond.receipt/1" as const, receipt_id: a.row.receipt_id,
      tenant_id: a.row.tenant_id, action_id: a.row.action_id,
      action_hash: a.row.action_hash, revision: entry.body.seq,
      previous_receipt_hash: prevHash, head: { seq: entry.body.seq, hash: entry.hash },
      binding: a.binding, view,
      evidence: a.state.evidenceRefs.map((r) => ({ ...r })),
      issued_at: this.clock.now(), simulation: true as const,
      assembly: assemblyOf(a.state, true), insurance: "PAPER_ONLY" as const,
      residual_effect: residualEffect(a.state), remedy: remedyState(a.state),
      truth: "ISSUER_ASSERTIONS_NOT_REAL_WORLD_PROOF" as const,
    };
    return signObject("receipt", body, this.keyId, this.signer);
  }

  private load(actionId: string): LoadedAction | null {
    const row = this.j.getAction(actionId);
    if (!row) return null;
    return loadRow(this.j, row);
  }

  private mustLoad(actionId: string): LoadedAction {
    const a = this.load(actionId);
    if (!a) throw new BondError("NOT_FOUND");
    return a;
  }

  private headFor(actionId: string): Head | null {
    const row = this.j.getAction(actionId);
    if (!row) return null;
    const st = deserializeState(JSON.parse(Buffer.from(row.projection).toString("utf8")) as Record<string, unknown>);
    return { ...st.head };
  }

  // --- port helpers ------------------------------------------------------------

  private async portCall(port: string, input: unknown): Promise<unknown> {
    try {
      return await this.ports.call(port, input);
    } catch {
      return { status: "UNKNOWN" };
    }
  }

  /**
   * Validate a port's KNOWN evidence: signed assertion under trust, bound to
   * this action, source bytes exactly J(facts) for fixture sources. Returns
   * null for UNKNOWN/malformed — the caller commits DependencyUncertain.
   */
  private checkedPortEvidence(res: unknown, a: LoadedAction): Evidence | null {
    const r = res as { status?: string; value?: unknown } | null;
    if (!r || r.status !== "KNOWN" || r.value === undefined || r.value === null) return null;
    try {
      const ev = r.value as Evidence;
      const signed = vSigned(ev.assertion, "assertion", vAssertion);
      verifySigned("assertion", signed, this.trust, a.row.tenant_id);
      if (signed.body.action_hash !== a.row.action_hash) return null;
      // Facts must be schema-valid; a malformed KNOWN is an UNKNOWN.
      vFacts(signed.body.facts);
      vBlob(ev.source);
      if (ev.source.data === null) return null;
      const srcBytes = Buffer.from(ev.source.data, "base64url");
      if (srcBytes.length !== ev.source.bytes || H(srcBytes) !== ev.source.hash) return null;
      if (signed.body.source.hash !== ev.source.hash) return null;
      if (signed.body.source_profile === "fixture/1" &&
        J(signed.body.facts) !== srcBytes.toString("utf8")) return null;
      return ev;
    } catch {
      return null;
    }
  }

  /** Strictly verified gate-read evidence (throws on failure). */
  private verifiedGateEvidence(ev: Evidence, actionHash: string, kind: Facts["kind"]): Facts {
    const signed = vSigned(ev.assertion, "assertion", vAssertion);
    verifySigned("assertion", signed, this.trust, this.cfg.tenant_id);
    if (signed.body.action_hash !== actionHash || signed.body.facts.kind !== kind) {
      throw new BondError("PROJECTION_INVALID", "gate evidence kind/binding");
    }
    const srcBytes = Buffer.from(ev.source.data!, "base64url");
    if (signed.body.source.hash !== H(srcBytes) || J(signed.body.facts) !== srcBytes.toString("utf8")) {
      throw new BondError("HASH_MISMATCH", "gate source");
    }
    return signed.body.facts;
  }

  /**
   * Absorb a port result into the journal. ForkSignal → RecoveryQuarantined;
   * schema-valid-but-inadmissible evidence (BAD_STATE from the reducer) is a
   * malformed response → DependencyUncertain, never a crash.
   */
  private absorbObservation(a: LoadedAction, op: Op, ev: Evidence | null): void {
    if (ev === null) {
      this.commitEntry(a, "DependencyUncertain", { operation: op }, this.cfg.principal_id);
      return;
    }
    const ref = this.storeEvidence(ev);
    const kind = entryKindForFacts(op, ev.assertion.body.facts);
    try {
      this.commitEntry(a, kind, { evidence: ref }, this.cfg.principal_id);
    } catch (e) {
      if (e instanceof ForkSignal) {
        this.commitEntry(a, "RecoveryQuarantined", { reason: "SOURCE_FORK" }, this.cfg.principal_id);
      } else if (e instanceof BondError && e.code === "BAD_STATE") {
        this.commitEntry(a, "DependencyUncertain", { operation: op }, this.cfg.principal_id);
      } else {
        throw e;
      }
    }
  }

  /**
   * Drive pending operations to resolution via same-key retries/lookups
   * (bounded), then auto-close when economics are resolved.
   */
  private async drivePending(a: LoadedAction): Promise<void> {
    for (let i = 0; i < MAX_DEP_CALLS; i++) {
      const pend = pendingOps(a.state);
      if (pend.length === 0) break;
      let progressed = false;
      for (const op of pend) {
        const done = await this.resolveOp(a, op);
        if (done) { progressed = true; break; }
      }
      if (!progressed) break;
    }
  }

  /**
   * Resolve one pending op: authoritative lookup first (a SENT op may have
   * landed), then a same-key redrive for never-resolved PREPARED work. Lookup
   * failure on a transmitted op marks it honestly UNKNOWN.
   */
  private async resolveOp(a: LoadedAction, op: Op): Promise<boolean> {
    const row = a.state.ops.get(op)!;
    const ev = await this.lookupEvidence(a, op);
    if (ev !== null && resolvesOp(op, ev.assertion.body.facts)) {
      this.absorbObservation(a, op, ev);
      return !isPendingRow(a.state.ops.get(op));
    }
    if (row.state === "PREPARED") {
      // Lookup could not confirm a transmitted effect — safe same-key retry.
      await this.redriveOp(a, op);
      return !isPendingRow(a.state.ops.get(op));
    }
    if (ev === null) {
      this.commitEntry(a, "DependencyUncertain", { operation: op }, this.cfg.principal_id);
    }
    return false;
  }

  private async lookupEvidence(a: LoadedAction, op: Op): Promise<Evidence | null> {
    const key = opKey(a.row.action_id, op);
    const port = op === "CREATE" ? "executor.lookup"
      : op === "UNDO" ? "vekrevert.lookup"
        : op === "STOP" ? "trellis.certificate" : "mint.lookup";
    const res = await this.portCall(port, op === "CREATE"
      ? { action_hash: a.row.action_hash, operation_key: key, resource: a.plan.resource }
      : { action_hash: a.row.action_hash, operation_key: key });
    return this.checkedPortEvidence(res, a);
  }

  /** Re-issue the originating same-key request for a PREPARED operation. */
  private async redriveOp(a: LoadedAction, op: Op): Promise<void> {
    const key = opKey(a.row.action_id, op);
    let res: unknown;
    switch (op) {
      case "RESERVE":
        res = await this.portCall("mint.reserve", {
          action_hash: a.row.action_hash, operation_key: key, terms: a.action.terms,
        });
        break;
      case "ENCUMBER": {
        const h = a.state.holdFacts;
        if (!h) return;
        res = await this.portCall("mint.encumber", {
          action_hash: a.row.action_hash, operation_key: key,
          hold_id: h.hold_id, expected_revision: h.revision,
        });
        break;
      }
      case "RELEASE":
      case "PAY":
        await this.driveSettle(a, op);
        return;
      case "UNDO": {
        // Re-driving presents the op's own creator fence: an UNDO row
        // prepared by a pre-restart writer is stale and the boundary must
        // reject it (§5.3 stale-fence rule for effect-boundary ops).
        const opFence = this.j.getOperations(a.row.action_id)
          .find((o) => o.kind === "UNDO")?.writer_fence ?? a.row.writer_fence;
        const cf = this.forwardAppliedFacts(a);
        res = await this.portCall("vekrevert.apply", {
          action_hash: a.row.action_hash, operation_key: key,
          action: a.action, plan: a.plan, policy: this.undoPolicyEvidence(a),
          fence: opFence,
          created_version: cf?.version ?? "v1",
          created_value_hash: cf?.value_hash ?? a.plan.value_hash,
        });
        break;
      }
      case "STOP":
        res = await this.portCall("trellis.stop", {
          action_id: a.row.action_id, run_id: a.binding.trellis_run, operation_key: key,
        });
        break;
      case "CREATE":
        return; // CREATE transitions to SENT at latch; never PREPARED.
    }
    const ev = this.checkedPortEvidence(res, a);
    this.absorbObservation(a, op, ev);
  }

  /** The UNDO-gate policy evidence committed with ReviewRejected, if any. */
  private undoPolicyEvidence(a: LoadedAction): Evidence | null {
    const entries = this.j.getEntries(a.row.action_id);
    for (let i = entries.length - 1; i >= 0; i--) {
      const e = JSON.parse(Buffer.from(entries[i]!.canonical).toString("utf8"));
      if (e.body.kind === "ReviewRejected" && e.body.data.policy) {
        const bytes = this.j.getObjectBytes(e.body.data.policy.hash);
        if (!bytes) return null;
        const assertion = parseAssertionBlob(bytes);
        const src = this.j.getObjectBytes(assertion.body.source.hash);
        if (!src) return null;
        return {
          assertion,
          source: {
            hash: assertion.body.source.hash, bytes: src.length,
            media_type: assertion.body.source.media_type, data: b64uEncode(src),
          },
        };
      }
    }
    return null;
  }

  private async driveSettle(a: LoadedAction, op: "RELEASE" | "PAY"): Promise<void> {
    const h = a.state.holdFacts;
    if (!h) return;
    const trigger = this.findTrigger(a, op);
    if (trigger === null) return;
    this.ports.registerTrigger?.(a.row.action_hash, trigger);
    const res = await this.portCall("mint.settle", {
      action_hash: a.row.action_hash, operation_key: opKey(a.row.action_id, op),
      hold_id: h.hold_id, expected_revision: h.revision, disposition: op,
      trigger_hash: trigger,
    });
    const ev = this.checkedPortEvidence(res, a);
    if (ev === null) {
      this.commitEntry(a, "DependencyUncertain", { operation: op }, this.cfg.principal_id);
      return;
    }
    this.absorbObservation(a, op, ev);
  }

  /** The settlement trigger = hash of the entry that authorized settlement. */
  private findTrigger(a: LoadedAction, op: "RELEASE" | "PAY"): string | null {
    const entries = this.j.getEntries(a.row.action_id);
    const kinds = op === "PAY"
      ? ["ReviewRejected"]
      : ["ReviewAccepted", "ActionAborted", "StopRequested"];
    for (let i = entries.length - 1; i >= 0; i--) {
      const e = JSON.parse(Buffer.from(entries[i]!.canonical).toString("utf8"));
      if (kinds.includes(e.body.kind)) return entries[i]!.hash;
    }
    return null;
  }

  /**
   * Probe Mint for externally-matured holds (reservation expiry / long stop)
   * whenever a non-terminal hold exists. Maturity is an observation, not an
   * op request — the evidence names the reserve or encumber lane.
   */
  private async probeMaturity(a: LoadedAction): Promise<void> {
    if (a.state.phase === "CLOSED" || a.state.holdFacts === null ||
      a.state.holdTerminal !== null) return;
    const op: Op = a.state.sawEncumbrance ? "ENCUMBER" : "RESERVE";
    const ev = await this.lookupEvidence(a, op);
    if (ev !== null && resolvesOp(op, ev.assertion.body.facts)) {
      this.absorbObservation(a, op, ev);
    }
  }

  /** Auto-close when all non-STOP operations are resolved. */
  private maybeClose(a: LoadedAction): void {
    if (a.state.phase === "CLOSING" && economicsResolved(a.state)) {
      const disp = computedDisposition(a.state);
      if (disp) this.commitEntry(a, "ActionClosed", { disposition: disp }, this.cfg.principal_id);
    }
  }

  private async settleAndClose(a: LoadedAction): Promise<View> {
    await this.drivePending(a);
    await this.probeMaturity(a);
    await this.drivePending(a);
    this.maybeClose(a);
    return toView(a.state);
  }

  // --- calls -------------------------------------------------------------------

  async doctor(ctx: AuthContext): Promise<Result<Doctor>> {
    const missing = this.capCheck();
    return ok({
      ready: missing.length === 0, profile: this.cfg.profile, simulation: true, missing,
    });
  }

  async prepare(ctx: AuthContext, input: {
    request_id: string; expected_revision: 0; action: unknown; run_id: string; paper: unknown;
  }): Promise<Result<View>> {
    let requestId = "";
    try {
      if (!ctx.principal_id) throw new BondError("UNAUTHORIZED");
      const adm = this.admit(ctx, "prepare", input);
      requestId = adm.requestId;
      if (adm.replay) return adm.replay as Result<View>;
      const r = await this.withMutex(() => this.prepareInner(ctx, input));
      return this.finish(ctx, requestId, r);
    } catch (e) {
      const r = fail<View>(codeOf(e), null);
      if (requestId) this.finish(ctx, requestId, r);
      return r;
    }
  }

  private async prepareInner(ctx: AuthContext, input: {
    expected_revision: 0; action: unknown; run_id: string; paper: unknown;
  }): Promise<Result<View>> {
    if (input.expected_revision !== 0) throw new BondError("REVISION_CONFLICT");
    const action = vAction(input.action);
    if (action.tenant_id !== ctx.tenant_id) throw new BondError("FORBIDDEN");
    if (action.principal_id !== ctx.principal_id && !ctx.roles.includes("operator")) {
      throw new BondError("FORBIDDEN", "principal binding");
    }
    if (!ctx.scopes.includes(action.scope_id) && !ctx.roles.includes("operator")) {
      throw new BondError("FORBIDDEN", "scope");
    }
    if (!(timeMs(action.execute_before) > timeMs(this.clock.now()))) {
      throw new BondError("DEADLINE");
    }
    if (this.j.getAction(action.action_id) ||
      this.j.getActionByHash(D("action", action))) {
      throw new BondError("CONFLICT", "action id/hash already staged");
    }
    if (input.paper === null) throw new BondError("INSURANCE_REQUIRED");
    const paper = vSigned(input.paper, "paper", vPaperReview);
    verifySigned("paper", paper, this.trust, ctx.tenant_id);
    checkPaperConsistency(paper.body, action);
    if (action.terms.owner !== this.cfg.scope_binding.mint_owner ||
      action.terms.beneficiary !== this.cfg.scope_binding.mint_beneficiary ||
      action.terms.owner === action.terms.beneficiary) {
      throw new BondError("FORBIDDEN", "payee binding");
    }
    if (!deepEqual(action.policy_pin, this.activePinFn())) throw new BondError("PIN_MISMATCH");
    if (this.j.countNonTerminal(action.scope_id) >= this.cfg.max_pending_actions) {
      throw new BondError("LIMIT", "max pending actions");
    }
    const actionHash = D("action", action);
    // Claim the run for this action before observing so the RUN facts carry
    // the action binding.
    this.ports.bindAction?.(action.action_id, actionHash);
    const runObs = await this.ports.call("trellis.observe", {
      action_id: action.action_id, run_id: input.run_id,
    }) as Evidence;
    const runFacts = this.verifiedGateEvidence(runObs, actionHash, "RUN") as RunFacts;
    if (runFacts.state !== "ACTIVE" || runFacts.run_id !== input.run_id ||
      runFacts.task_ref !== action.action_id) {
      throw new BondError("RUN_BINDING");
    }
    const plan = await this.ports.call("vekrevert.plan", { action }) as UndoPlan;
    if (plan.action_hash !== actionHash || plan.resource !== action.resource ||
      plan.adapter_build !== action.adapter_build ||
      plan.value_hash !== H(J(action.draft)) ||
      plan.expires_at !== action.terms.long_stop) {
      throw new BondError("PROJECTION_INVALID", "plan mismatch");
    }
    const fwd = await this.ports.call("bedrock.evaluate", { action, purpose: "FORWARD", now: this.clock.now() }) as Evidence;
    const polFacts = this.verifiedGateEvidence(fwd, actionHash, "POLICY") as PolicyFacts;
    if (polFacts.purpose !== "FORWARD") throw new BondError("PROJECTION_INVALID", "policy purpose");
    if (polFacts.verdict !== "ALLOW") throw new BondError("POLICY_DENIED", polFacts.reason);

    // All pure preflights passed — commit ActionStaged.
    const actionBlob = this.storeBlob(jbytes(action), "application/json");
    const planBlob = this.storeBlob(jbytes(plan), "application/json");
    const paperBlob = this.storeBlob(jbytes(paper), "application/json");
    const binding: Binding = {
      action: actionBlob, plan: planBlob, paper: paperBlob,
      trellis_run: input.run_id, trellis_host: runFacts.host_id,
      trellis_task_ref: action.action_id,
    };
    const receiptId = newId("brc");
    const st0 = initialState(receiptId, action.action_id);
    const row: ActionRow = {
      action_id: action.action_id, tenant_id: action.tenant_id,
      principal_id: action.principal_id, scope_id: action.scope_id,
      action_hash: actionHash, receipt_id: receiptId, run_id: input.run_id,
      hold_id: null, revision: 0, writer_fence: this.fence,
      stop_latched: 0, quarantined: 0, projection: jbytes(serializeState(st0)),
    };
    const loaded: LoadedAction = { row, action, plan, binding, state: st0 };
    this.commitEntry(loaded, "ActionStaged", { binding }, ctx.principal_id, true);
    // RESERVE
    const res = await this.portCall("mint.reserve", {
      action_hash: actionHash, operation_key: opKey(action.action_id, "RESERVE"),
      terms: action.terms,
    });
    this.absorbObservation(loaded, "RESERVE", this.checkedPortEvidence(res, loaded));
    await this.drivePending(loaded);
    this.maybeClose(loaded);
    return ok(toView(loaded.state));
  }

  async execute(ctx: AuthContext, input: {
    request_id: string; action_id: string; expected_revision: number;
  }): Promise<Result<View>> {
    try {
      const adm = this.admit(ctx, "execute", input);
      if (adm.replay) return adm.replay as Result<View>;
      // The entire mutation is serialized on the dispatch mutex: a racing
      // stop can only land before or after, never across the boundary.
      const r = await this.withMutex(() => this.executeInner(ctx, input));
      return this.finish(ctx, adm.requestId, r);
    } catch (e) {
      return fail(codeOf(e), this.headFor(input.action_id));
    }
  }

  private async executeInner(ctx: AuthContext, input: {
    action_id: string; expected_revision: number;
  }): Promise<Result<View>> {
    // Loaded inside the mutex: state observed here is post-contention.
    const a = this.mustLoad(input.action_id);
    this.authorizeMutation(ctx, a);
    if (input.expected_revision !== a.state.revision) throw new BondError("REVISION_CONFLICT");
    this.checkLatches(a);
    if (a.state.phase === "READY") {
      this.commitEntry(a, "CommitRequested", {
        operation_key: opKey(a.row.action_id, "ENCUMBER"),
      }, ctx.principal_id);
      const h = a.state.holdFacts!;
      const res = await this.portCall("mint.encumber", {
        action_hash: a.row.action_hash, operation_key: opKey(a.row.action_id, "ENCUMBER"),
        hold_id: h.hold_id, expected_revision: h.revision,
      });
      const ev = this.checkedPortEvidence(res, a);
      if (ev === null) {
        this.commitEntry(a, "DependencyUncertain", { operation: "ENCUMBER" }, this.cfg.principal_id);
        return ok(toView(a.state));
      }
      this.absorbObservation(a, "ENCUMBER", ev);
    } else if (!(a.state.phase === "COMMITTING" && a.state.funds === "ENCUMBERED" &&
      pendingOps(a.state).every((o) => o === "STOP"))) {
      throw new BondError("BAD_STATE", "execute phase");
    }
    if (a.state.funds !== "ENCUMBERED") throw new BondError("HOLD_BINDING");
    const r = await this.dispatch(ctx, a);
    return ok(r);
  }

  /** Boundary admission + dispatch (called with the mutation mutex held). */
  private async dispatch(ctx: AuthContext, a: LoadedAction): Promise<View> {
    this.checkLatches(a);
    const now = this.clock.now();
    const runObs = await this.ports.call("trellis.observe", {
      action_id: a.row.action_id, run_id: a.binding.trellis_run,
    }) as Evidence;
    const observedMono = this.clock.monotonicMs();
    const runFacts = this.verifiedGateEvidence(runObs, a.row.action_hash, "RUN") as RunFacts;
    const pol = await this.ports.call("bedrock.evaluate", {
      action: a.action, purpose: "FORWARD", now,
    }) as Evidence;
    const polFacts = this.verifiedGateEvidence(pol, a.row.action_hash, "POLICY") as PolicyFacts;
    const paperBytes = this.j.getObjectBytes(a.binding.paper.hash);
    const paper = paperBytes
      ? vSigned(parseJsonBytes(paperBytes, PACKAGE_LIMITS), "paper", vPaperReview)
      : null;
    // Fixed gate order: stop → pin → verdict → deadline → clock → run → paper → hold.
    dispatchGate({
      action: a.action, activePin: this.activePinFn(), policyFacts: polFacts,
      now, clockUncertaintyMs: this.clock.uncertaintyMs(),
      maxClockUncertaintyMs: this.cfg.clock_max_uncertainty_ms,
      runFacts, runObservedMonoMs: observedMono,
      admittedMonoMs: this.clock.monotonicMs(),
      runFreshnessMs: this.cfg.run_freshness_ms,
      binding: a.binding, paper,
      holdFacts: a.state.holdFacts,
      stopLatched: a.state.stopLatched,
      scopeStopped: this.scopeStopped(a.row.tenant_id, a.row.scope_id),
      quarantined: a.state.quarantined,
      trust: this.trust, tenantId: a.row.tenant_id,
    });
    const polRef = this.storeEvidence(pol);
    const runRef = this.storeEvidence(runObs);
    const holdRef = this.encumberedHoldRef(a);
    const admittedMono = this.clock.monotonicMs();
    this.commitEntry(a, "DispatchLatched", {
      policy: polRef, runtime: runRef, hold: holdRef, fence: this.fence,
      operation_key: opKey(a.row.action_id, "CREATE"),
      timing: {
        boot_id: "boot-" + this.fence,
        runtime_observed_ms: Math.floor(observedMono),
        admitted_ms: Math.floor(admittedMono),
      },
    }, ctx.principal_id);
    if (this.onDispatchAdmitted) await this.onDispatchAdmitted(a.row.action_id);
    // Admission won the mutex: a stop racing in now cannot retract the call.
    const res = await this.portCall("executor.create", {
      action_hash: a.row.action_hash, operation_key: opKey(a.row.action_id, "CREATE"),
      action: a.action, plan: a.plan, policy: pol, fence: a.row.writer_fence,
    });
    const ev = this.checkedPortEvidence(res, a);
    if (ev === null) {
      this.commitEntry(a, "DependencyUncertain", { operation: "CREATE" }, this.cfg.principal_id);
      return toView(a.state);
    }
    this.absorbObservation(a, "CREATE", ev);
    return this.settleAndClose(a);
  }

  private encumberedHoldRef(a: LoadedAction): ArtifactRef {
    for (const r of a.state.evidenceRefs) {
      const b = this.j.getObjectBytes(r.hash);
      if (!b) continue;
      try {
        const s = parseAssertionBlob(b);
        const f = s.body.facts;
        if (f.kind === "HOLD" && (f as HoldFacts).state === "ENCUMBERED") return { ...r };
      } catch { /* not an assertion blob */ }
    }
    throw new BondError("HOLD_BINDING", "no encumbered hold evidence");
  }

  private checkLatches(a: LoadedAction): void {
    if (a.state.quarantined) throw new BondError("BAD_STATE", "quarantined");
    if (a.state.stopLatched) throw new BondError("BAD_STATE", "action stopped");
    if (this.scopeStopped(a.row.tenant_id, a.row.scope_id)) {
      throw new BondError("BAD_STATE", "scope stopped");
    }
  }

  private scopeStopped(tenant: string, scope: string): boolean {
    return this.j.getMetadata(`scope_stop:${tenant}:${scope}`) !== null;
  }

  private authorizeMutation(ctx: AuthContext, a: LoadedAction): void {
    if (ctx.tenant_id !== a.row.tenant_id) throw new BondError("FORBIDDEN");
    if (ctx.principal_id !== a.row.principal_id && !ctx.roles.includes("operator")) {
      throw new BondError("FORBIDDEN");
    }
  }

  private authorizeOperator(ctx: AuthContext, a: LoadedAction): void {
    if (ctx.tenant_id !== a.row.tenant_id) throw new BondError("FORBIDDEN");
    if (!ctx.roles.includes("operator")) throw new BondError("FORBIDDEN", "operator required");
  }

  // --- cancel / accept / reject ------------------------------------------------

  async cancel(ctx: AuthContext, input: {
    request_id: string; action_id: string; expected_revision: number;
  }): Promise<Result<View>> {
    try {
      const adm = this.admit(ctx, "cancel", input);
      if (adm.replay) return adm.replay as Result<View>;
      const view = await this.withMutex(async () => {
        const a = this.mustLoad(input.action_id);
        this.authorizeMutation(ctx, a);
        if (input.expected_revision !== a.state.revision) {
          throw new BondError("REVISION_CONFLICT");
        }
        if (!["STAGED", "READY", "COMMITTING"].includes(a.state.phase)) {
          throw new BondError("BAD_STATE", "cancel phase");
        }
        this.commitEntry(a, "ActionAborted", { reason: "CANCELED" }, ctx.principal_id);
        return this.settleAndClose(a);
      });
      return this.finish(ctx, adm.requestId, ok(view));
    } catch (e) {
      return fail(codeOf(e), this.headFor(input.action_id));
    }
  }

  async accept(ctx: AuthContext, input: {
    request_id: string; action_id: string; expected_revision: number;
  }): Promise<Result<View>> {
    try {
      const adm = this.admit(ctx, "accept", input);
      if (adm.replay) return adm.replay as Result<View>;
      const view = await this.withMutex(async () => {
        const a = this.mustLoad(input.action_id);
        this.authorizeOperator(ctx, a);
        if (input.expected_revision !== a.state.revision) {
          throw new BondError("REVISION_CONFLICT");
        }
        if (a.state.phase !== "AWAITING_REVIEW" || a.state.funds !== "ENCUMBERED") {
          throw new BondError("BAD_STATE", "accept phase");
        }
        this.commitEntry(a, "ReviewAccepted", { principal_id: ctx.principal_id }, ctx.principal_id);
        return this.settleAndClose(a);
      });
      return this.finish(ctx, adm.requestId, ok(view));
    } catch (e) {
      return fail(codeOf(e), this.headFor(input.action_id));
    }
  }

  async reject(ctx: AuthContext, input: {
    request_id: string; action_id: string; expected_revision: number;
    reason: "OPERATOR_REJECTED" | "VALIDATION_FAILED";
  }): Promise<Result<View>> {
    try {
      const adm = this.admit(ctx, "reject", input);
      if (adm.replay) return adm.replay as Result<View>;
      const view = await this.withMutex(() => this.rejectInner(ctx, input));
      return this.finish(ctx, adm.requestId, ok(view));
    } catch (e) {
      return fail(codeOf(e), this.headFor(input.action_id));
    }
  }

  private async rejectInner(ctx: AuthContext, input: {
    action_id: string; expected_revision: number;
    reason: "OPERATOR_REJECTED" | "VALIDATION_FAILED";
  }): Promise<View> {
    const a = this.mustLoad(input.action_id);
    this.authorizeOperator(ctx, a);
    if (input.expected_revision !== a.state.revision) {
      throw new BondError("REVISION_CONFLICT");
    }
    if (a.state.phase !== "AWAITING_REVIEW" || a.state.funds !== "ENCUMBERED") {
      throw new BondError("BAD_STATE", "reject phase");
    }
    if (input.reason !== "OPERATOR_REJECTED" && input.reason !== "VALIDATION_FAILED") {
      throw new BondError("SCHEMA", "bad reason");
    }
    const pol = await this.ports.call("bedrock.evaluate", {
      action: a.action, purpose: "UNDO", now: this.clock.now(),
    }) as Evidence;
    const polFacts = this.verifiedGateEvidence(pol, a.row.action_hash, "POLICY") as PolicyFacts;
    const polRef = polFacts.verdict === "ALLOW" ? this.storeEvidence(pol) : null;
    this.commitEntry(a, "ReviewRejected", {
      principal_id: ctx.principal_id, reason: input.reason, policy: polRef,
    }, ctx.principal_id);
    if (polFacts.verdict !== "ALLOW") {
      const refusal = this.localRefusal(a, "POLICY_DENIED");
      const ref = this.storeEvidence(refusal);
      this.commitEntry(a, "UndoObserved", { evidence: ref }, this.cfg.principal_id);
    } else {
      const cf = this.forwardAppliedFacts(a);
      const res = await this.portCall("vekrevert.apply", {
        action_hash: a.row.action_hash, operation_key: opKey(a.row.action_id, "UNDO"),
        action: a.action, plan: a.plan, policy: pol, fence: a.row.writer_fence,
        created_version: cf?.version ?? "v1",
        created_value_hash: cf?.value_hash ?? a.plan.value_hash,
      });
      const ev = this.checkedPortEvidence(res, a);
      if (ev === null) {
        this.commitEntry(a, "DependencyUncertain", { operation: "UNDO" }, this.cfg.principal_id);
        return toView(a.state);
      }
      this.absorbObservation(a, "UNDO", ev);
    }
    return this.settleAndClose(a);
  }

  private forwardAppliedFacts(a: LoadedAction): EffectFacts | null {
    for (const r of a.state.evidenceRefs) {
      const b = this.j.getObjectBytes(r.hash);
      if (!b) continue;
      try {
        const s = parseAssertionBlob(b);
        const f = s.body.facts;
        if (f.kind === "EFFECT" && (f as EffectFacts).purpose === "FORWARD" &&
          (f as EffectFacts).outcome === "APPLIED") return f as EffectFacts;
      } catch { /* not an assertion blob */ }
    }
    return null;
  }

  /** Locally generated conditional-inverse refusal (never calls the boundary). */
  private localRefusal(a: LoadedAction, reason: EffectFacts["reason"]): Evidence {
    const facts: EffectFacts = {
      kind: "EFFECT", purpose: "UNDO", operation_key: opKey(a.row.action_id, "UNDO"),
      outcome: "NOT_APPLIED", resource: a.plan.resource, version: null, value_hash: null, reason,
    };
    const sourceBytes = jbytes(facts);
    const source = blobOf(sourceBytes, "application/json");
    const body: Assertion = {
      schema: "bond.assertion/1", action_hash: a.row.action_hash,
      observed_at: this.clock.now(), source_profile: "fixture/1",
      source: refOf(source), facts,
    };
    return { assertion: signObject("assertion", body, this.keyId, this.signer), source };
  }

  // --- stop --------------------------------------------------------------------

  async stop(ctx: AuthContext, input: {
    request_id: string; action_id: string | null;
  }): Promise<Result<View | { scope_stopped: true }>> {
    try {
      const adm = this.admit(ctx, "stop", input);
      if (adm.replay) return adm.replay as Result<View | { scope_stopped: true }>;
      if (input.action_id === null) {
        const key = `scope_stop:${ctx.tenant_id}:${this.cfg.scope_id}`;
        this.j.setMetadata(key, jbytes({ principal: ctx.principal_id, at: this.clock.now() }));
        const r: Result<{ scope_stopped: true }> = ok({ scope_stopped: true });
        this.finish(ctx, adm.requestId, r);
        return r;
      }
      // Serialize against the dispatch boundary and reload inside the mutex:
      // a stop racing an in-flight dispatch sees post-contention state.
      const view = await this.withMutex(async () => {
        const a = this.mustLoad(input.action_id!);
        this.authorizeOperator(ctx, a);
        await this.stopAction(ctx, a);
        return toView(a.state);
      });
      return this.finish(ctx, adm.requestId, ok(view));
    } catch (e) {
      return fail(codeOf(e), input.action_id ? this.headFor(input.action_id) : null);
    }
  }

  private async stopAction(ctx: AuthContext, a: LoadedAction): Promise<void> {
    if (a.state.kill === "CERTIFIED") return;
    this.commitEntry(a, "StopRequested", {
      principal_id: ctx.principal_id, operation_key: opKey(a.row.action_id, "STOP"),
    }, ctx.principal_id);
    const res = await this.portCall("trellis.stop", {
      action_id: a.row.action_id, run_id: a.binding.trellis_run,
      operation_key: opKey(a.row.action_id, "STOP"),
    });
    const ev = this.checkedPortEvidence(res, a);
    if (ev === null) {
      const stopOp = a.state.ops.get("STOP");
      if (stopOp && stopOp.state === "SENT") {
        this.commitEntry(a, "DependencyUncertain", { operation: "STOP" }, this.cfg.principal_id);
      }
      return;
    }
    const ref = this.storeEvidence(ev);
    try {
      this.commitEntry(a, "KillObserved", { evidence: ref }, this.cfg.principal_id);
    } catch (e) {
      if (e instanceof ForkSignal) {
        this.commitEntry(a, "RecoveryQuarantined", { reason: "SOURCE_FORK" }, this.cfg.principal_id);
      } else {
        throw e;
      }
    }
    this.maybeClose(a);
  }

  // --- reconcile / inspect / attach / export / verify ----------------------------

  async reconcile(ctx: AuthContext, input: {
    request_id: string; action_id: string; expected_revision: number;
  }): Promise<Result<View>> {
    try {
      const adm = this.admit(ctx, "reconcile", input);
      if (adm.replay) return adm.replay as Result<View>;
      const view = await this.withMutex(async () => {
        const a = this.mustLoad(input.action_id);
        this.authorizeMutation(ctx, a);
        if (input.expected_revision !== a.state.revision) {
          throw new BondError("REVISION_CONFLICT");
        }
        return this.settleAndClose(a);
      });
      return this.finish(ctx, adm.requestId, ok(view));
    } catch (e) {
      return fail(codeOf(e), this.headFor(input.action_id));
    }
  }

  inspect(ctx: AuthContext, input: { action_id: string }): Result<View> {
    try {
      const a = this.mustLoad(input.action_id);
      if (ctx.tenant_id !== a.row.tenant_id) throw new BondError("FORBIDDEN");
      if (ctx.principal_id !== a.row.principal_id && !ctx.roles.includes("operator") &&
        !ctx.roles.includes("auditor")) {
        throw new BondError("FORBIDDEN");
      }
      return ok(toView(a.state));
    } catch (e) {
      return fail(codeOf(e), this.headFor(input.action_id));
    }
  }

  async attach(ctx: AuthContext, input: {
    request_id: string; action_id: string; expected_revision: number;
    artifact: Blob; purpose: "GROUND_ADVISORY" | "WORLD_LINEAGE";
  }): Promise<Result<View>> {
    try {
      const adm = this.admit(ctx, "attach", input);
      if (adm.replay) return adm.replay as Result<View>;
      const view = await this.withMutex(async () => {
        const a = this.mustLoad(input.action_id);
        this.authorizeOperator(ctx, a);
        if (input.expected_revision !== a.state.revision) {
          throw new BondError("REVISION_CONFLICT");
        }
        const artifact = vBlob(input.artifact);
        if (artifact.data === null) throw new BondError("SCHEMA", "artifact bytes required");
        verifyAdvisoryBytes(Buffer.from(artifact.data, "base64url"), input.purpose, a.row.action_hash);
        if (a.state.revision >= SOFT_ENTRY_CAP) throw new BondError("LIMIT", "entry soft cap");
        const ref = this.storeBlob(Buffer.from(artifact.data, "base64url"), artifact.media_type);
        this.commitEntry(a, "EvidenceAttached", { artifact: ref, purpose: input.purpose }, ctx.principal_id);
        return toView(a.state);
      });
      return this.finish(ctx, adm.requestId, ok(view));
    } catch (e) {
      return fail(codeOf(e), this.headFor(input.action_id));
    }
  }

  export(ctx: AuthContext, input: {
    action_id: string; through_revision: number; include_bytes: boolean;
  }): Result<Package> {
    try {
      const a = this.mustLoad(input.action_id);
      if (ctx.tenant_id !== a.row.tenant_id) throw new BondError("FORBIDDEN");
      if (ctx.principal_id !== a.row.principal_id && !ctx.roles.includes("operator") &&
        !ctx.roles.includes("auditor")) {
        throw new BondError("FORBIDDEN");
      }
      if (input.through_revision < 1 || input.through_revision > a.state.revision) {
        throw new BondError("REVISION_CONFLICT");
      }
      const entries = this.j.getEntries(a.row.action_id)
        .filter((e) => e.seq <= input.through_revision);
      const receipts = this.j.getReceipts(a.row.action_id)
        .filter((r) => r.revision <= input.through_revision);
      const blobs = this.exportBlobs(a, input.include_bytes);
      return ok({
        schema: "bond.package/1",
        entries: entries.map((e) => JSON.parse(Buffer.from(e.canonical).toString("utf8"))),
        receipts: receipts.map((r) => JSON.parse(Buffer.from(r.canonical).toString("utf8"))),
        blobs,
      });
    } catch (e) {
      return fail(codeOf(e), this.headFor(input.action_id));
    }
  }

  private exportBlobs(a: LoadedAction, includeBytes: boolean): Blob[] {
    const wanted = new Map<string, { bytes: number; media_type: string }>();
    const addRef = (r: ArtifactRef) => wanted.set(r.hash, { bytes: r.bytes, media_type: r.media_type });
    addRef(a.binding.action); addRef(a.binding.plan); addRef(a.binding.paper);
    const paperBytes = this.j.getObjectBytes(a.binding.paper.hash);
    if (paperBytes) {
      const paper = vSigned(parseJsonBytes(paperBytes, PACKAGE_LIMITS), "paper", vPaperReview);
      addRef(paper.body.document); addRef(paper.body.exclusions_document);
    }
    for (const r of a.state.evidenceRefs) {
      addRef(r);
      const b = this.j.getObjectBytes(r.hash);
      if (b) {
        try {
          const s = parseAssertionBlob(b);
          addRef(s.body.source);
        } catch { /* advisory artifacts have no assertion source */ }
      }
    }
    const blobs: Blob[] = [];
    for (const [h, meta] of [...wanted.entries()].sort(([a], [b]) => a < b ? -1 : 1)) {
      const bytes = this.j.getObjectBytes(h);
      if (!bytes) {
        blobs.push({ hash: h, bytes: meta.bytes, media_type: meta.media_type as Blob["media_type"], data: null });
        continue;
      }
      blobs.push({
        hash: h, bytes: bytes.length,
        media_type: meta.media_type as Blob["media_type"],
        data: includeBytes ? b64uEncode(bytes) : null,
      });
    }
    return blobs;
  }

  verify(ctx: AuthContext, input: { package: unknown; expected_head: Head | null }): Result<Verification> {
    try {
      const pkg = input.package;
      const bytes = Buffer.isBuffer(pkg) ? pkg : jbytes(pkg);
      return ok(verifyPackage(bytes, this.trust, input.expected_head ?? null));
    } catch (e) {
      return fail(codeOf(e), null);
    }
  }

  // --- recovery (§5.4) -----------------------------------------------------------

  /** Verify chains, rebuild projections, resolve pending ops via lookups. */
  async recover(): Promise<{ quarantined: string[]; stopAttempted: string[] }> {
    const quarantined: string[] = [];
    const stopAttempted: string[] = [];
    for (const row of this.j.pendingActions()) {
      try {
        this.verifyActionChain(row);
      } catch {
        quarantined.push(row.action_id);
        this.j.updateActionProjection(row.action_id, row.revision, row.projection,
          row.stop_latched, 1, row.hold_id);
        stopAttempted.push(row.action_id);
        try {
          await this.ports.call("trellis.stop", {
            action_id: row.action_id, run_id: row.run_id,
            operation_key: opKey(row.action_id, "STOP"),
          });
        } catch { /* independent stop path is best-effort; audit gap is recorded */ }
        continue;
      }
      const a = loadRow(this.j, row);
      if (!a.state.quarantined) {
        await this.drivePending(a);
        if (a.state.phase === "CLOSING") this.maybeClose(a);
      }
    }
    // Complete abandoned IN_PROGRESS requests with the recovered durable View.
    for (const r of this.j.abandonedRequests()) {
      const meta = this.j.getMetadata(`request_input:${r.tenant_id}:${r.principal_id}:${r.request_id}`);
      let resp: Result<unknown> = fail("NOT_FOUND", null);
      if (meta) {
        try {
          const m = JSON.parse(Buffer.from(meta).toString("utf8")) as { method: string; input: { action_id?: string } };
          const aid = m.input.action_id;
          if (aid) {
            const a = this.load(aid);
            if (a) resp = ok(toView(a.state));
          }
        } catch { /* keep NOT_FOUND */ }
      }
      this.j.finishRequest(r.tenant_id, r.principal_id, r.request_id, jbytes(resp));
    }
    return { quarantined, stopAttempted };
  }

  private verifyActionChain(row: ActionRow): void {
    const entries = this.j.getEntries(row.action_id);
    let prev = ZERO_HASH;
    for (const e of entries) {
      const parsed = parseJsonBytes(e.canonical, PACKAGE_LIMITS);
      const signed = vSigned(parsed, "entry", vEntryBody);
      if (signed.hash !== e.hash || signed.body.previous_hash !== prev ||
        signed.body.seq !== e.seq) {
        throw new BondError("CHAIN_INVALID", "journal corruption");
      }
      verifySigned("entry", signed, this.trust, row.tenant_id);
      prev = e.hash;
    }
  }
}

// ---------------------------------------------------------------------------

function economicsResolved(st: RState): boolean {
  for (const [, op] of st.ops) {
    if (op.kind !== "STOP" &&
      (op.state === "PREPARED" || op.state === "SENT" || op.state === "UNKNOWN")) {
      return false;
    }
  }
  return true;
}

function isPendingRow(row: { state: string } | undefined): boolean {
  return !!row && (row.state === "PREPARED" || row.state === "SENT" || row.state === "UNKNOWN");
}

/**
 * Does `f` authoritatively resolve `op`? A lookup answering with state behind
 * the op's target (e.g. HELD for the ENCUMBER lane) is not a resolution — the
 * coordinator redrives the original same-key request instead.
 */
function resolvesOp(op: Op, f: Facts): boolean {
  if (f.kind === "NO_HOLD") return false;
  switch (op) {
    case "RESERVE": return f.kind === "HOLD";
    case "ENCUMBER": return f.kind === "HOLD" && f.state !== "HELD";
    case "RELEASE":
    case "PAY":
      return f.kind === "HOLD" && (f.state === "RELEASED" || f.state === "PAID");
    case "CREATE": return f.kind === "EFFECT" && f.purpose === "FORWARD";
    case "UNDO": return f.kind === "EFFECT" && f.purpose === "UNDO";
    case "STOP": return f.kind === "KILL";
  }
}

/** Entry kind carrying an observation, selected by the facts it reports. */
function entryKindForFacts(op: Op, f: Facts): keyof EventData {
  switch (f.kind) {
    case "NO_HOLD": return "HoldObserved";
    case "HOLD":
      return (f.state === "RELEASED" || f.state === "PAID") ? "FundsObserved" : "HoldObserved";
    case "EFFECT": return f.purpose === "FORWARD" ? "EffectObserved" : "UndoObserved";
    case "KILL": return "KillObserved";
    default: throw new BondError("BAD_STATE", "unexpected facts kind for " + op);
  }
}

function collectRefHashes(a: LoadedAction, body: { binding?: Binding; evidence?: ArtifactRef[] }): string[] {
  const out: string[] = [];
  if (a.binding) out.push(a.binding.action.hash, a.binding.plan.hash, a.binding.paper.hash);
  return out;
}

function loadRow(j: Journal, row: ActionRow): LoadedAction {
  const st = deserializeState(
    JSON.parse(Buffer.from(row.projection).toString("utf8")) as Record<string, unknown>);
  st.receiptId = row.receipt_id;
  st.actionId = row.action_id;
  const entries = j.getEntries(row.action_id);
  if (entries.length === 0) throw new BondError("CHAIN_INVALID", "no entries");
  const first = vSigned(parseJsonBytes(entries[0]!.canonical, PACKAGE_LIMITS), "entry", vEntryBody);
  const binding = (first.body.data as EventData["ActionStaged"]).binding;
  const actionBytes = j.getObjectBytes(binding.action.hash);
  const planBytes = j.getObjectBytes(binding.plan.hash);
  if (!actionBytes || !planBytes) throw new BondError("INCOMPLETE", "binding objects missing");
  const action = vAction(parseJsonBytes(actionBytes, PACKAGE_LIMITS));
  const plan = vUndoPlan(parseJsonBytes(planBytes, PACKAGE_LIMITS));
  return { row, action, plan, binding, state: st };
}

/** §7 advisory validation: advisory bytes must be bond.advisory/1 JSON. */
export function verifyAdvisoryBytes(bytes: Buffer, purpose: string, actionHash: string): void {
  let x: unknown;
  try {
    x = parseJsonBytes(bytes, PACKAGE_LIMITS);
  } catch (e) {
    throw e instanceof BondError ? e : new BondError("SCHEMA");
  }
  if (typeof x !== "object" || x === null || Array.isArray(x)) throw new BondError("SCHEMA");
  const o = x as Record<string, unknown>;
  if (o.schema !== "bond.advisory/1") throw new BondError("SCHEMA", "advisory schema");
  if (o.action_hash !== actionHash) throw new BondError("HOLD_BINDING", "advisory action binding");
  if (purpose === "WORLD_LINEAGE") {
    verifyWorldEffect(x);
  }
}

/**
 * §7 advisory gate: a hypothetical world-lineage result is not evidence of a
 * world effect. Fails UNSUPPORTED_COMPOSITION before any attachment.
 */
export function verifyWorldEffect(x: unknown): void {
  const o = x as { result?: { hypothetical?: boolean } } | null;
  if (o !== null && typeof o === "object" && o.result?.hypothetical === true) {
    throw new BondError("UNSUPPORTED_COMPOSITION", "hypothetical lineage is not evidence");
  }
}
