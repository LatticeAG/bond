/**
 * Pure Bond reducer — §4.1 main transition table, §4.2 money/operation
 * machines, §4.3 stop/kill machine. Consumes validated entries plus already
 * signature/native-verified evidence and produces the projected View.
 * Reads no wall clock, network, randomness, or process state.
 */

import { BondError, Head } from "./errors.js";
import { deepEqual, J, ZERO_HASH, isHash } from "./canon.js";
import * as T from "./types.js";

export interface OpRow {
  kind: T.Op;
  state: T.OpState;
}

/** Facts resolved from a verified evidence assertion. */
export interface ResolvedEvidence {
  facts: T.Facts;
  evidenceHash: string; // hash of the assertion blob the event references
}

export interface ReducerEnv {
  action: T.Action;
  plan: T.UndoPlan;
  binding: T.Binding;
  /** Resolve an artifact reference to verified assertion facts; null = missing bytes. */
  resolve(ref: T.ArtifactRef): ResolvedEvidence | null;
}

export interface RState {
  phase: T.Phase;
  effect: T.EffectState;
  undo: T.UndoState;
  funds: T.FundsState;
  kill: T.KillState;
  review: "NONE" | "ACCEPT" | "REJECT";
  stopLatched: boolean;
  quarantined: boolean;
  ops: Map<string, OpRow>; // keyed by Op kind (UNIQUE(action_id,kind))
  markedOps: Set<T.Op>; // ops with committed observation/uncertainty evidence
  evidenceRefs: T.ArtifactRef[]; // sorted, unique by hash
  appliedFacts: Set<string>; // J(facts) already applied (dedup)
  holdFacts: T.HoldFacts | null; // latest verified hold facts
  holdTerminal: "NONE" | "RELEASED" | "PAID" | null;
  terminalBasis: T.HoldFacts["settlement_basis"] | null;
  sawEncumbrance: boolean;
  sawDispatch: boolean;
  killCertifiedHash: string | null; // evidence hash of first CERTIFIED observation
  revision: number;
  head: Head;
  receiptId: string;
  actionId: string;
}

export function opKey(actionId: string, op: T.Op): string {
  return actionId + ":" + op.toLowerCase();
}

export const MONEY_OPS: T.Op[] = ["RESERVE", "ENCUMBER", "RELEASE", "PAY"];

export function pendingOps(st: RState): T.Op[] {
  const out: T.Op[] = [];
  for (const [, row] of st.ops) {
    if (row.state === "PREPARED" || row.state === "SENT" || row.state === "UNKNOWN") {
      out.push(row.kind);
    }
  }
  return [...new Set(out)].sort();
}

export function toView(st: RState): T.View {
  return {
    receipt_id: st.receiptId,
    action_id: st.actionId,
    revision: st.revision,
    phase: st.phase,
    effect: st.effect,
    undo: st.undo,
    funds: st.funds,
    kill: st.kill,
    review: st.review,
    stop_latched: st.stopLatched,
    quarantined: st.quarantined,
    pending: pendingOps(st),
    head: { ...st.head },
  };
}

export function initialState(receiptId: string, actionId: string): RState {
  return {
    phase: "STAGED",
    effect: "NOT_DISPATCHED",
    undo: "PLANNED",
    funds: "NONE",
    kill: "ARMED",
    review: "NONE",
    stopLatched: false,
    quarantined: false,
    ops: new Map(),
    markedOps: new Set(),
    evidenceRefs: [],
    appliedFacts: new Set(),
    holdFacts: null,
    holdTerminal: null,
    terminalBasis: null,
    sawEncumbrance: false,
    sawDispatch: false,
    killCertifiedHash: null,
    revision: 0,
    head: { seq: 0, hash: ZERO_HASH },
    receiptId,
    actionId,
  };
}

export function residualEffect(st: RState): T.ReceiptBody["residual_effect"] {
  if (st.effect === "UNKNOWN" || st.undo === "UNKNOWN") return "UNKNOWN";
  if (st.undo === "FAILED") return "NOT_REVERSED";
  if (st.effect === "APPLIED" && st.undo !== "APPLIED") return "DRAFT_PRESENT";
  return "NONE";
}

export function remedyState(st: RState): T.ReceiptBody["remedy"] {
  if (st.review !== "REJECT") return "NOT_TRIGGERED";
  return st.funds === "PAID" ? "PAID" : "DUE";
}

/** Assembly completeness over derived state (byte presence checked by caller). */
export function assemblyOf(st: RState, bytesComplete: boolean): "COMPLETE" | "INCOMPLETE" {
  const complete =
    st.phase === "CLOSED" &&
    st.kill === "CERTIFIED" &&
    pendingOps(st).length === 0 &&
    !st.quarantined &&
    remedyState(st) !== "DUE" &&
    bytesComplete;
  return complete ? "COMPLETE" : "INCOMPLETE";
}

export function cloneState(st: RState): RState {
  return {
    ...st,
    ops: new Map([...st.ops].map(([k, v]) => [k, { ...v }])),
    markedOps: new Set(st.markedOps),
    evidenceRefs: st.evidenceRefs.map((r) => ({ ...r })),
    appliedFacts: new Set(st.appliedFacts),
    holdFacts: st.holdFacts ? { ...st.holdFacts } : null,
    head: { ...st.head },
  };
}

// --- serialization for the journal projection blob --------------------------

export function serializeState(st: RState): Record<string, unknown> {
  return {
    phase: st.phase, effect: st.effect, undo: st.undo, funds: st.funds,
    kill: st.kill, review: st.review, stopLatched: st.stopLatched,
    quarantined: st.quarantined,
    ops: [...st.ops.values()],
    markedOps: [...st.markedOps],
    evidenceRefs: st.evidenceRefs,
    appliedFacts: [...st.appliedFacts],
    holdFacts: st.holdFacts, holdTerminal: st.holdTerminal,
    terminalBasis: st.terminalBasis,
    sawEncumbrance: st.sawEncumbrance, sawDispatch: st.sawDispatch,
    killCertifiedHash: st.killCertifiedHash,
    revision: st.revision, head: st.head, receiptId: st.receiptId,
    actionId: st.actionId,
  };
}

export function deserializeState(x: Record<string, unknown>): RState {
  const ops = new Map<string, OpRow>();
  for (const o of x.ops as OpRow[]) ops.set(o.kind, { ...o });
  return {
    ...(x as unknown as RState),
    ops,
    markedOps: new Set(x.markedOps as T.Op[]),
    evidenceRefs: x.evidenceRefs as T.ArtifactRef[],
    appliedFacts: new Set(x.appliedFacts as string[]),
  };
}

// ---------------------------------------------------------------------------

export type Mode = "ingest" | "verify";

/** A verified observation contradicting a committed terminal fact. */
export class ForkSignal extends BondError {
  constructor(msg?: string) {
    super("SOURCE_FORK", msg);
  }
}

/** Event references evidence bytes absent from the package/store. */
export class MissingEvidence extends Error {
  constructor() {
    super("missing evidence bytes");
  }
}

function badState(mode: Mode, msg?: string): never {
  throw new BondError(mode === "ingest" ? "BAD_STATE" : "PROJECTION_INVALID", msg);
}

function projInvalid(msg?: string): never {
  throw new BondError("PROJECTION_INVALID", msg);
}

function putOp(st: RState, kind: T.Op, state: T.OpState): void {
  const cur = st.ops.get(kind);
  if (cur) cur.state = state;
  else st.ops.set(kind, { kind, state });
}

function isPending(op: OpRow): boolean {
  return op.state === "PREPARED" || op.state === "SENT" || op.state === "UNKNOWN";
}

function bindOperation(st: RState, env: ReducerEnv, key: string, mode: Mode): OpRow {
  const suffix = key.slice(key.lastIndexOf(":") + 1).toUpperCase();
  const op = st.ops.get(suffix);
  if (!op || key !== opKey(env.action.action_id, op.kind) || op.state === "CANCELED") {
    badState(mode, `operation key ${key} not bound`);
  }
  return op!;
}

function addEvidenceRef(st: RState, ref: T.ArtifactRef): void {
  if (!st.evidenceRefs.some((r) => r.hash === ref.hash)) {
    st.evidenceRefs.push({ ...ref });
    st.evidenceRefs.sort((a, b) => (a.hash < b.hash ? -1 : a.hash > b.hash ? 1 : 0));
  }
}

function isDupFacts(st: RState, facts: T.Facts): boolean {
  return st.appliedFacts.has(J(facts));
}

function markApplied(st: RState, facts: T.Facts, ref: T.ArtifactRef, op?: OpRow): void {
  st.appliedFacts.add(J(facts));
  addEvidenceRef(st, ref);
  if (op) st.markedOps.add(op.kind);
}

function markFactsOnly(st: RState, facts: T.Facts): void {
  st.appliedFacts.add(J(facts));
}

/** Queue the next economic operation when entering/sitting in CLOSING. */
function computeClosingPlan(st: RState): void {
  if (st.funds === "HELD" || st.funds === "ENCUMBERED") {
    const owePay = st.review === "REJECT" &&
      (st.undo === "APPLIED" || st.undo === "FAILED");
    if (owePay) {
      if (!st.ops.has("PAY")) putOp(st, "PAY", "PREPARED");
    } else if (!st.ops.has("RELEASE") && st.holdTerminal === null) {
      putOp(st, "RELEASE", "PREPARED");
    }
  }
}

/** Computed ActionClosed disposition from committed facts (§3.4). */
export function computedDisposition(
  st: RState,
): "NO_HOLD" | "RELEASE" | "PAY" | "EXTERNAL_MATURITY" | null {
  if (st.funds === "NONE") return "NO_HOLD";
  if (st.funds === "PAID") return "PAY";
  if (st.funds === "RELEASED") {
    if (st.terminalBasis === "RESERVATION_EXPIRED" || st.terminalBasis === "LONG_STOP") {
      return "EXTERNAL_MATURITY";
    }
    return "RELEASE";
  }
  return null;
}

/** ActionClosed requires every non-STOP operation resolved. */
function economicsResolved(st: RState): boolean {
  for (const [, op] of st.ops) {
    if (op.kind !== "STOP" && isPending(op)) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// KILL projection (also used directly by conformance vectors).
// ---------------------------------------------------------------------------

export type KillProjection =
  | { ok: true; state: "CERTIFIED" | "UNCONFIRMED" }
  | { ok: false; code: "SCHEMA" | "RUN_BINDING" | "INCOMPLETE" };

/** §3.3 KILL admissibility + binding against the action's Trellis run. */
export function projectKill(
  facts: unknown,
  binding: Pick<T.Binding, "trellis_run" | "trellis_host" | "trellis_task_ref">,
  validate: (x: unknown) => T.KillFacts,
): KillProjection {
  let f: T.KillFacts;
  try {
    f = validate(facts);
  } catch {
    return { ok: false, code: "SCHEMA" };
  }
  if (f.run_id !== binding.trellis_run || f.host_id !== binding.trellis_host ||
    f.task_ref !== binding.trellis_task_ref) {
    return { ok: false, code: "RUN_BINDING" };
  }
  if (f.state === "CERTIFIED") {
    if (f.stopped_head === null || !f.gate_closed || !f.empty_observed || f.audit_gap) {
      return { ok: false, code: "INCOMPLETE" };
    }
    return { ok: true, state: "CERTIFIED" };
  }
  return { ok: true, state: "UNCONFIRMED" };
}

// ---------------------------------------------------------------------------
// Main transition function.
// ---------------------------------------------------------------------------

/**
 * Apply one entry to the projection. `entryHash` is the entry's signed hash.
 * Throws BondError; ForkSignal => caller commits RecoveryQuarantined instead;
 * MissingEvidence => caller marks the package INCOMPLETE.
 */
export function applyEntry(
  st: RState | null,
  entry: T.EntryBody,
  entryHash: string,
  env: ReducerEnv | null,
  mode: Mode,
): { state: RState; noop: boolean } {
  const kind = entry.kind;
  const data = entry.data as Record<string, unknown>;

  if (st === null) {
    if (kind !== "ActionStaged") projInvalid("genesis must be ActionStaged");
    if (entry.seq !== 1 || entry.previous_hash !== ZERO_HASH) projInvalid("bad genesis link");
    const st0 = initialState("", entry.action_id);
    st0.ops.set("RESERVE", { kind: "RESERVE", state: "PREPARED" });
    st0.revision = 1;
    st0.head = { seq: 1, hash: entryHash };
    return { state: st0, noop: false };
  }

  const e = env!;
  const prevPending = new Map([...st.ops].map(([k, o]) => [k, isPending(o)]));

  const needEvidence = (ref: T.ArtifactRef | null | undefined): ResolvedEvidence => {
    if (!ref || !isHash(ref.hash)) badState(mode, "bad evidence ref");
    const r = e.resolve(ref as T.ArtifactRef);
    if (r === null) throw new MissingEvidence();
    return r;
  };

  let noop = false;

  const finish = (s: RState): { state: RState; noop: boolean } => {
    s.revision = entry.seq;
    s.head = { seq: entry.seq, hash: entryHash };
    return { state: s, noop };
  };

  /** An already-applied observation: ingest no-ops it; a committed entry for it is invalid. */
  const dup = (): { state: RState; noop: boolean } => {
    if (mode === "verify") projInvalid("redundant observation entry");
    noop = true;
    return { state: st, noop: true };
  };

  switch (kind) {
    case "ActionStaged":
      projInvalid("duplicate ActionStaged");
      break;

    case "HoldObserved": {
      const ref = (data as T.EventData["HoldObserved"]).evidence;
      const ev = needEvidence(ref);
      if (isDupFacts(st, ev.facts)) return dup();
      const f = ev.facts;
      if (f.kind === "NO_HOLD") {
        // Admissible only for the reserve lane; unlike other evidence it may
        // also resolve a locally CANCELED RESERVE (it proves the cancellation's
        // never-sent assumption correct rather than contradicting it).
        if (f.operation_key !== opKey(e.action.action_id, "RESERVE")) {
          badState(mode, "NO_HOLD admissible only for RESERVE");
        }
        const op = st.ops.get("RESERVE");
        if (!op || op.state === "KNOWN") badState(mode, "NO_HOLD for resolved reserve");
        if (st.holdFacts !== null || st.funds === "HELD" || st.funds === "ENCUMBERED" ||
          st.holdTerminal === "RELEASED" || st.holdTerminal === "PAID") {
          throw new ForkSignal("NO_HOLD contradicts confirmed hold");
        }
        if (st.phase !== "STAGED" && st.phase !== "CLOSING") badState(mode, "NO_HOLD phase");
        st.phase = "CLOSING";
        st.funds = "NONE";
        st.holdTerminal = "NONE";
        op.state = "KNOWN";
        st.markedOps.add("RESERVE");
        if (st.undo === "PLANNED") st.undo = "NOT_NEEDED";
        markApplied(st, f, ref);
        return finish(st);
      }
      if (f.kind !== "HOLD") badState(mode, "HoldObserved requires HOLD or NO_HOLD");
      if (f.state !== "HELD" && f.state !== "ENCUMBERED") badState(mode, "HoldObserved state");
      if (f.action_hash !== entry.action_hash) badState(mode, "hold action_hash mismatch");
      if (!deepEqual(f.terms, e.action.terms)) badState(mode, "hold terms mismatch");
      if (f.exclusive !== true) badState(mode, "hold not exclusive");
      const op = bindOperation(st, e, f.operation_key, mode);
      if (op.kind !== "RESERVE" && op.kind !== "ENCUMBER") badState(mode, "HOLD names wrong op");
      if (st.holdTerminal === "RELEASED" || st.holdTerminal === "PAID") {
        throw new ForkSignal("hold mutation after terminal settlement");
      }
      if (st.holdFacts && st.holdFacts.revision >= f.revision && st.holdFacts.state !== f.state) {
        throw new ForkSignal("hold revision regressed with changed state");
      }
      const opWasPending = prevPending.get(op.kind) === true;
      // Phase legality: the §4.1 rows plus in-flight operation resolution.
      const listed =
        (st.phase === "STAGED" && f.state === "HELD" && op.kind === "RESERVE") ||
        (st.phase === "COMMITTING" && f.state === "ENCUMBERED" && op.kind === "ENCUMBER") ||
        st.phase === "CLOSING";
      if (!listed && !opWasPending) badState(mode, "HoldObserved in non-admissible phase");
      if (st.phase === "CLOSED") badState(mode, "hold after close");
      markApplied(st, f, ref, op);
      st.holdFacts = f;
      st.funds = f.state;
      if (f.state === "ENCUMBERED") st.sawEncumbrance = true;
      op.state = "KNOWN";
      if (st.phase === "STAGED" && f.state === "HELD" && op.kind === "RESERVE") {
        st.phase = "READY";
      } else if (st.phase === "CLOSING") {
        computeClosingPlan(st);
      }
      return finish(st);
    }

    case "CommitRequested": {
      const d = data as T.EventData["CommitRequested"];
      if (st.phase !== "READY") badState(mode, "CommitRequested phase");
      if (st.stopLatched || st.quarantined) badState(mode, "commit under stop/quarantine");
      if (d.operation_key !== opKey(entry.action_id, "ENCUMBER")) badState(mode, "bad commit key");
      st.phase = "COMMITTING";
      putOp(st, "ENCUMBER", "PREPARED");
      return finish(st);
    }

    case "DispatchLatched": {
      const d = data as T.EventData["DispatchLatched"];
      if (st.phase !== "COMMITTING") badState(mode, "DispatchLatched phase");
      if (st.funds !== "ENCUMBERED") projInvalid("dispatch without encumbered hold");
      if (st.sawDispatch) projInvalid("duplicate dispatch marker");
      if (d.operation_key !== opKey(entry.action_id, "CREATE")) badState(mode, "bad create key");
      const pol = needEvidence(d.policy);
      if (pol.facts.kind !== "POLICY" || pol.facts.purpose !== "FORWARD" ||
        pol.facts.verdict !== "ALLOW" || !deepEqual(pol.facts.pin, e.action.policy_pin)) {
        badState(mode, "dispatch policy not verified ALLOW");
      }
      const run = needEvidence(d.runtime);
      if (run.facts.kind !== "RUN" || run.facts.state !== "ACTIVE" ||
        run.facts.run_id !== e.binding.trellis_run ||
        run.facts.host_id !== e.binding.trellis_host ||
        run.facts.task_ref !== e.binding.trellis_task_ref) {
        throw new BondError("RUN_BINDING", "dispatch run binding");
      }
      const hold = needEvidence(d.hold);
      if (hold.facts.kind !== "HOLD" || hold.facts.state !== "ENCUMBERED" ||
        hold.facts.action_hash !== entry.action_hash) {
        throw new BondError("HOLD_BINDING", "dispatch hold binding");
      }
      const t = d.timing;
      if (!(t.admitted_ms >= t.runtime_observed_ms && t.admitted_ms - t.runtime_observed_ms <= 250)) {
        throw new BondError("RUN_STALE", "runtime observation too old at admission");
      }
      addEvidenceRef(st, d.policy);
      addEvidenceRef(st, d.runtime);
      addEvidenceRef(st, d.hold);
      markFactsOnly(st, pol.facts);
      markFactsOnly(st, run.facts);
      markFactsOnly(st, hold.facts);
      st.phase = "EXECUTING";
      st.effect = "PENDING";
      st.sawDispatch = true;
      putOp(st, "CREATE", "SENT");
      st.markedOps.add("CREATE");
      return finish(st);
    }

    case "ActionAborted": {
      if (st.phase !== "STAGED" && st.phase !== "READY" && st.phase !== "COMMITTING") {
        badState(mode, "abort phase");
      }
      st.phase = "CLOSING";
      if (st.undo === "PLANNED") st.undo = "NOT_NEEDED";
      // Cancel only never-transmitted operations; a SENT reserve could have
      // reached Mint and must stay pending until a tombstone resolves it.
      const reserve = st.ops.get("RESERVE");
      if (reserve && reserve.state === "PREPARED") reserve.state = "CANCELED";
      computeClosingPlan(st);
      return finish(st);
    }

    case "EffectObserved": {
      const ref = (data as T.EventData["EffectObserved"]).evidence;
      const ev = needEvidence(ref);
      if (isDupFacts(st, ev.facts)) return dup();
      const f = ev.facts;
      if (f.kind !== "EFFECT" || f.purpose !== "FORWARD") badState(mode, "EffectObserved facts");
      const op = bindOperation(st, e, f.operation_key, mode);
      if (op.kind !== "CREATE") badState(mode, "EffectObserved names non-CREATE op");
      checkEffectBinding(f, e);
      if (st.phase === "CLOSED") badState(mode, "effect after close");
      if (st.phase === "AWAITING_REVIEW") {
        // Any new-facts FORWARD observation contradicts the committed terminal
        // effect (identical facts were deduplicated above).
        throw new ForkSignal("conflicting forward effect");
      }
      markApplied(st, f, ref, op);
      if (f.outcome === "UNKNOWN") {
        if (st.phase !== "EXECUTING" && st.phase !== "UNCERTAIN") badState(mode, "UNKNOWN effect phase");
        op.state = "UNKNOWN";
        st.effect = "UNKNOWN";
        st.phase = "UNCERTAIN";
        st.stopLatched = true;
        return finish(st);
      }
      op.state = "KNOWN";
      if (f.outcome === "APPLIED") {
        st.effect = "APPLIED";
        if (st.phase === "EXECUTING" || st.phase === "UNCERTAIN") st.phase = "AWAITING_REVIEW";
        else if (st.phase !== "CLOSING") badState(mode, "EffectObserved phase");
      } else {
        st.effect = "NOT_APPLIED";
        if (st.undo === "PLANNED") st.undo = "NOT_NEEDED";
        if (st.phase !== "CLOSING") st.phase = "CLOSING";
        computeClosingPlan(st);
      }
      return finish(st);
    }

    case "ReviewAccepted": {
      if (st.phase !== "AWAITING_REVIEW" || st.funds !== "ENCUMBERED") {
        badState(mode, "ReviewAccepted phase/funds");
      }
      st.review = "ACCEPT";
      st.undo = "NOT_NEEDED";
      st.phase = "CLOSING";
      computeClosingPlan(st);
      return finish(st);
    }

    case "ReviewRejected": {
      const d = data as T.EventData["ReviewRejected"];
      if (st.phase !== "AWAITING_REVIEW" || st.funds !== "ENCUMBERED") {
        badState(mode, "ReviewRejected phase/funds");
      }
      if (d.policy !== null) {
        const pol = needEvidence(d.policy);
        if (pol.facts.kind !== "POLICY" || pol.facts.purpose !== "UNDO") {
          badState(mode, "rejection policy evidence not UNDO");
        }
        addEvidenceRef(st, d.policy);
        markFactsOnly(st, pol.facts);
      }
      st.review = "REJECT";
      st.undo = "PENDING";
      st.phase = "COMPENSATING";
      putOp(st, "UNDO", "PREPARED");
      return finish(st);
    }

    case "UndoObserved": {
      const ref = (data as T.EventData["UndoObserved"]).evidence;
      const ev = needEvidence(ref);
      if (isDupFacts(st, ev.facts)) return dup();
      const f = ev.facts;
      if (f.kind !== "EFFECT" || f.purpose !== "UNDO") badState(mode, "UndoObserved facts");
      const op = bindOperation(st, e, f.operation_key, mode);
      if (op.kind !== "UNDO") badState(mode, "UndoObserved names non-UNDO op");
      checkEffectBinding(f, e);
      const opWasPending = prevPending.get("UNDO") === true;
      const preparedLocal = op.state === "PREPARED" && f.outcome === "NOT_APPLIED" &&
        (f.reason === "POLICY_DENIED" || f.reason === "STOPPED_BEFORE_CALL" ||
          f.reason === "DEADLINE_BEFORE_CALL");
      if (!opWasPending && !preparedLocal) badState(mode, "UNDO op not open");
      if (st.phase === "CLOSED") badState(mode, "undo after close");
      if ((st.undo === "APPLIED" || st.undo === "FAILED") && f.outcome !== st.undo) {
        throw new ForkSignal("conflicting terminal undo");
      }
      if (st.phase !== "COMPENSATING" && st.phase !== "UNCERTAIN" && st.phase !== "CLOSING") {
        badState(mode, "UndoObserved phase");
      }
      markApplied(st, f, ref, op);
      if (f.outcome === "UNKNOWN") {
        op.state = "UNKNOWN";
        st.undo = "UNKNOWN";
        st.phase = "UNCERTAIN";
        st.stopLatched = true;
        return finish(st);
      }
      op.state = "KNOWN";
      st.undo = f.outcome === "APPLIED" ? "APPLIED" : "FAILED";
      st.phase = "CLOSING";
      if (st.funds === "ENCUMBERED" && st.review === "REJECT" && !st.ops.has("PAY")) {
        putOp(st, "PAY", "PREPARED");
      }
      computeClosingPlan(st);
      return finish(st);
    }

    case "FundsObserved": {
      const ref = (data as T.EventData["FundsObserved"]).evidence;
      const ev = needEvidence(ref);
      if (isDupFacts(st, ev.facts)) return dup();
      const f = ev.facts;
      if (f.kind !== "HOLD" || (f.state !== "RELEASED" && f.state !== "PAID")) {
        badState(mode, "FundsObserved facts");
      }
      if (f.action_hash !== entry.action_hash) badState(mode, "funds action_hash mismatch");
      if (!deepEqual(f.terms, e.action.terms)) badState(mode, "funds terms mismatch");
      const op = bindOperation(st, e, f.operation_key, mode);
      if (op.kind !== "RELEASE" && op.kind !== "PAY" && op.kind !== "RESERVE" && op.kind !== "ENCUMBER") {
        badState(mode, "FundsObserved names wrong op");
      }
      if (st.phase === "CLOSED") badState(mode, "funds after close");
      if (st.holdTerminal === "RELEASED" || st.holdTerminal === "PAID") {
        throw new ForkSignal("second terminal funds observation");
      }
      const isMaturity =
        f.settlement_basis === "RESERVATION_EXPIRED" || f.settlement_basis === "LONG_STOP";
      const opWasPending = prevPending.get(op.kind) === true;
      if (!isMaturity) {
        if (f.state === "PAID" && !(st.review === "REJECT" && op.kind === "PAY")) {
          throw new ForkSignal("PAID without authorized rejection");
        }
        if (f.state === "RELEASED" && op.kind !== "RELEASE") {
          throw new ForkSignal("REQUEST-released evidence names non-release op");
        }
        if (st.phase !== "CLOSING" && !opWasPending) {
          throw new ForkSignal("unrequested terminal settlement");
        }
      }
      markApplied(st, f, ref, op);
      if (op.state !== "KNOWN") op.state = "KNOWN";
      if (isMaturity) {
        applyMaturity(st, f);
        return finish(st);
      }
      st.funds = f.state;
      st.holdFacts = f;
      st.holdTerminal = f.state;
      st.terminalBasis = "REQUEST";
      return finish(st);
    }

    case "ActionClosed": {
      const d = data as T.EventData["ActionClosed"];
      if (st.phase !== "CLOSING") badState(mode, "ActionClosed phase");
      if (!economicsResolved(st)) badState(mode, "economic work unresolved");
      const disp = computedDisposition(st);
      if (disp === null || d.disposition !== disp) projInvalid("disposition mismatch");
      st.phase = "CLOSED";
      return finish(st);
    }

    case "StopRequested": {
      const d = data as T.EventData["StopRequested"];
      if (d.operation_key !== opKey(entry.action_id, "STOP")) badState(mode, "bad stop key");
      const existing = st.ops.get("STOP");
      if ((existing && isPending(existing)) || st.kill === "CERTIFIED") {
        // Identical STOP already unresolved / certified — in verify mode a
        // redundant entry is still a chain member; in ingest it no-ops.
        if (mode === "verify") projInvalid("redundant stop entry");
        return { state: st, noop: true };
      }
      st.stopLatched = true;
      if (st.kill === "ARMED") st.kill = "REQUESTED";
      putOp(st, "STOP", "SENT");
      if (st.phase === "STAGED" || st.phase === "READY" || st.phase === "COMMITTING") {
        st.phase = "CLOSING";
        if (st.undo === "PLANNED") st.undo = "NOT_NEEDED";
        const reserve = st.ops.get("RESERVE");
        if (reserve && reserve.state === "PREPARED") reserve.state = "CANCELED";
        computeClosingPlan(st);
      }
      return finish(st);
    }

    case "KillObserved": {
      const ref = (data as T.EventData["KillObserved"]).evidence;
      const ev = needEvidence(ref);
      if (isDupFacts(st, ev.facts)) return dup();
      const proj = projectKill(ev.facts, e.binding, (x) => x as T.KillFacts);
      if (!proj.ok) throw new BondError(proj.code, "kill projection failed");
      if (proj.state === "CERTIFIED") {
        if (st.killCertifiedHash !== null && st.killCertifiedHash !== ev.evidenceHash) {
          throw new ForkSignal("second distinct CERTIFIED observation");
        }
        st.killCertifiedHash = ev.evidenceHash;
        st.kill = "CERTIFIED";
        const op = st.ops.get("STOP");
        if (op && isPending(op)) op.state = "KNOWN";
        st.markedOps.add("STOP");
      } else {
        if (st.kill === "CERTIFIED") throw new ForkSignal("UNCONFIRMED after CERTIFIED");
        st.kill = "UNCONFIRMED";
      }
      markApplied(st, ev.facts, ref);
      return finish(st);
    }

    case "EvidenceAttached": {
      const d = data as T.EventData["EvidenceAttached"];
      addEvidenceRef(st, d.artifact);
      return finish(st);
    }

    case "DependencyUncertain": {
      const d = data as T.EventData["DependencyUncertain"];
      const op = st.ops.get(d.operation);
      if (!op || !isPending(op)) badState(mode, "DependencyUncertain for non-pending op");
      st.markedOps.add(d.operation);
      if (d.operation === "CREATE") {
        if (st.phase !== "EXECUTING" && st.phase !== "UNCERTAIN") {
          badState(mode, "DepUnc CREATE phase");
        }
        op.state = "UNKNOWN";
        st.effect = "UNKNOWN";
        st.phase = "UNCERTAIN";
        st.stopLatched = true;
      } else if (d.operation === "UNDO") {
        if (st.phase !== "COMPENSATING" && st.phase !== "UNCERTAIN") {
          badState(mode, "DepUnc UNDO phase");
        }
        op.state = "UNKNOWN";
        st.undo = "UNKNOWN";
        st.phase = "UNCERTAIN";
        st.stopLatched = true;
      } else {
        op.state = "UNKNOWN";
        if (MONEY_OPS.includes(d.operation)) st.funds = "UNKNOWN";
      }
      return finish(st);
    }

    case "RecoveryQuarantined": {
      st.quarantined = true;
      return finish(st);
    }

    default:
      badState(mode, "unknown event kind");
  }
}

// ---------------------------------------------------------------------------

/**
 * §4.2 maturity override: terminal RELEASED evidence with basis
 * RESERVATION_EXPIRED or LONG_STOP. Caller has already applied op bookkeeping.
 */
function applyMaturity(st: RState, facts: T.HoldFacts): void {
  if (facts.settlement_basis === "RESERVATION_EXPIRED") {
    if (st.sawEncumbrance || st.sawDispatch) {
      throw new ForkSignal("expiry after encumbrance");
    }
  }
  st.funds = "RELEASED";
  st.holdFacts = facts;
  st.holdTerminal = "RELEASED";
  st.terminalBasis = facts.settlement_basis;
  // Cancel never-transmitted financial operations; a SENT op stays pending.
  for (const k of MONEY_OPS) {
    const op = st.ops.get(k);
    if (op && op.state === "PREPARED") op.state = "CANCELED";
  }
  const create = st.ops.get("CREATE");
  const undo = st.ops.get("UNDO");
  const effectOpen = st.effect === "PENDING" || st.effect === "UNKNOWN" ||
    (create !== undefined && isPending(create));
  const undoOpen = st.undo === "PENDING" || st.undo === "UNKNOWN" ||
    (undo !== undefined && isPending(undo));
  if (effectOpen || undoOpen) {
    if (st.phase !== "CLOSING" && st.phase !== "CLOSED") st.phase = "UNCERTAIN";
    return;
  }
  if (st.undo === "PLANNED") st.undo = "NOT_NEEDED";
  st.phase = "CLOSING";
}

function checkEffectBinding(f: T.EffectFacts, e: ReducerEnv): void {
  if (f.resource !== e.plan.resource) projInvalid("effect resource mismatch");
  if (f.outcome === "APPLIED") {
    if (f.value_hash !== e.plan.value_hash) projInvalid("effect value_hash mismatch");
    if (f.version === null) projInvalid("APPLIED without version");
    if (f.purpose === "FORWARD" && f.reason !== "CREATED") projInvalid("bad forward reason");
    if (f.purpose === "UNDO" && f.reason !== "DELETED") projInvalid("bad undo reason");
  } else {
    if (f.version !== null || f.value_hash !== null) projInvalid("non-APPLIED carries version");
    const okReasons: Record<string, string[]> = {
      UNKNOWN: ["TRANSPORT_UNKNOWN"],
      NOT_APPLIED: [
        "ABSENT", "VERSION_CHANGED", "POLICY_DENIED", "STOPPED_BEFORE_CALL", "DEADLINE_BEFORE_CALL",
      ],
    };
    const allowed = okReasons[f.outcome] ?? [];
    if (!allowed.includes(f.reason)) projInvalid("bad effect reason");
  }
}
