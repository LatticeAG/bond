/**
 * The dispatch gate — fixed evaluation order (§5.2):
 * schema → authorization → idempotency → expected revision → phase legality →
 * stop latches → policy pin → policy verdict → deadline → clock uncertainty →
 * run binding/freshness → paper → hold binding → hold sufficiency.
 * This function implements pin→sufficiency; the earlier steps are enforced by
 * the caller before invocation. Pure: no I/O. Throws BondError.
 */

import {
  Action, BondError, D, deepEqual, HoldFacts, PaperReview, PolicyFacts,
  PolicyPin, RunFacts, Signed, Terms, timeMs, checkPaperConsistency, TrustFile,
} from "@latticeag/bond-core";

export interface GateInput {
  action: Action;
  /** Embedded evaluator's current pin. */
  activePin: PolicyPin;
  /** Freshly evaluated FORWARD policy facts. */
  policyFacts: PolicyFacts;
  now: string;
  clockUncertaintyMs: number;
  maxClockUncertaintyMs: number;
  /** Fresh RUN facts + observation/admission monotonic times. */
  runFacts: RunFacts;
  runObservedMonoMs: number;
  admittedMonoMs: number;
  runFreshnessMs: number;
  binding: { trellis_run: string; trellis_host: string; trellis_task_ref: string };
  /** Signed paper under review (null => INSURANCE_REQUIRED). */
  paper: Signed<PaperReview> | null;
  /** Latest verified hold facts (must be ENCUMBERED at dispatch). */
  holdFacts: HoldFacts | null;
  stopLatched: boolean;
  scopeStopped: boolean;
  quarantined: boolean;
  trust: TrustFile;
  tenantId: string;
}

export function dispatchGate(g: GateInput): void {
  // stop latches
  if (g.quarantined || g.stopLatched || g.scopeStopped) {
    throw new BondError("BAD_STATE", "latched");
  }
  // policy pin, then verdict
  if (!deepEqual(g.action.policy_pin, g.activePin)) throw new BondError("PIN_MISMATCH");
  if (g.policyFacts.verdict !== "ALLOW") {
    throw new BondError("POLICY_DENIED", g.policyFacts.reason);
  }
  // deadline, then clock uncertainty
  if (!(timeMs(g.action.execute_before) > timeMs(g.now))) throw new BondError("DEADLINE");
  if (g.clockUncertaintyMs > g.maxClockUncertaintyMs) throw new BondError("CLOCK_UNSAFE");
  // run binding + freshness
  const r = g.runFacts;
  if (r.state !== "ACTIVE" || r.run_id !== g.binding.trellis_run ||
    r.host_id !== g.binding.trellis_host || r.task_ref !== g.binding.trellis_task_ref) {
    throw new BondError("RUN_BINDING");
  }
  if (!(g.admittedMonoMs >= g.runObservedMonoMs &&
    g.admittedMonoMs - g.runObservedMonoMs <= g.runFreshnessMs)) {
    throw new BondError("RUN_STALE");
  }
  // paper
  if (g.paper === null) throw new BondError("INSURANCE_REQUIRED");
  checkPaperConsistency(g.paper.body, g.action); // throws INSURANCE_SCOPE
  // hold binding, then sufficiency
  const h = g.holdFacts;
  if (!h || h.action_hash !== actionHashOf(g.action) || h.exclusive !== true ||
    h.state !== "ENCUMBERED" || !holdTermsMatch(h.terms, g.action.terms)) {
    throw new BondError("HOLD_BINDING");
  }
  if (BigInt(h.terms.amount_minor) < BigInt(g.action.terms.amount_minor)) {
    throw new BondError("HOLD_INSUFFICIENT");
  }
}

function holdTermsMatch(h: Terms, a: Terms): boolean {
  return h.asset === a.asset && h.owner === a.owner && h.beneficiary === a.beneficiary &&
    h.task_id === a.task_id && h.reserve_until === a.reserve_until &&
    h.long_stop === a.long_stop && h.trigger === a.trigger;
}

function actionHashOf(a: Action): string {
  return D("action", a);
}
