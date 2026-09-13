/**
 * Closed-schema validators — every object is closed, every property required,
 * absent distinct from null (§3.1). Validators throw BondError("SCHEMA")
 * unless a more specific code is named.
 */

import { BondError } from "./errors.js";
import {
  isU, isHash, isB64u, isTime, isAmount, isExternalId, isBondId, timeMs,
  isResourceSegment, isBindingName,
} from "./canon.js";
import * as T from "./types.js";

function fail(msg?: string): never {
  throw new BondError("SCHEMA", msg);
}

export function isObj(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

/** Exact closed-object key check. */
export function keys(x: Record<string, unknown>, required: readonly string[]): void {
  const want = new Set(required);
  for (const k of Object.keys(x)) if (!want.has(k)) fail(`unexpected member ${k}`);
  for (const k of required) if (!Object.prototype.hasOwnProperty.call(x, k)) fail(`missing member ${k}`);
}

function str(x: unknown): string {
  if (typeof x !== "string") fail("expected string");
  return x;
}

function bool(x: unknown): boolean {
  if (typeof x !== "boolean") fail("expected boolean");
  return x;
}

function lit<V extends string | number | boolean>(x: unknown, v: V): V {
  if (x !== v) fail(`expected ${String(v)}`);
  return v;
}

function oneOf<V extends string>(x: unknown, vs: readonly V[]): V {
  if (typeof x !== "string" || !vs.includes(x as V)) fail("bad enum value");
  return x as V;
}

export function vHash(x: unknown): T.Hash {
  if (!isHash(x)) fail("bad hash");
  return x;
}

export function vU(x: unknown): number {
  if (!isU(x)) fail("bad integer");
  return x;
}

export function vTime(x: unknown): string {
  if (!isTime(x)) fail("bad time");
  return x;
}

export function vAmount(x: unknown): string {
  if (!isAmount(x)) fail("bad amount");
  return x;
}

export function vExternalId(x: unknown): string {
  if (!isExternalId(x)) fail("bad external id");
  return x;
}

export function vB64(x: unknown): string {
  if (!isB64u(x)) fail("bad base64url");
  return x;
}

export function vId(x: unknown, p: Parameters<typeof isBondId>[1]): string {
  if (!isBondId(x, p)) fail(`bad ${p} id`);
  return x;
}

export function vArtifactRef(x: unknown): T.ArtifactRef {
  if (!isObj(x)) fail("artifact ref not object");
  keys(x, ["hash", "bytes", "media_type"]);
  return {
    hash: vHash(x.hash),
    bytes: vU(x.bytes),
    media_type: oneOf(x.media_type, ["application/json", "application/pdf"]),
  };
}

export function vBlob(x: unknown): T.Blob {
  if (!isObj(x)) fail("blob not object");
  keys(x, ["hash", "bytes", "media_type", "data"]);
  const data = x.data;
  if (data !== null && !isB64u(data)) fail("bad blob data");
  return {
    hash: vHash(x.hash),
    bytes: vU(x.bytes),
    media_type: oneOf(x.media_type, ["application/json", "application/pdf"]),
    data: data as string | null,
  };
}

export function vHead(x: unknown): { seq: number; hash: string } {
  if (!isObj(x)) fail("head not object");
  keys(x, ["seq", "hash"]);
  return { seq: vU(x.seq), hash: vHash(x.hash) };
}

export function vPolicyPin(x: unknown): T.PolicyPin {
  if (!isObj(x)) fail();
  keys(x, ["charter_id", "version", "charter_hash", "manifest_hash", "engine"]);
  return {
    charter_id: vExternalId(x.charter_id),
    version: vU(x.version),
    charter_hash: vHash(x.charter_hash),
    manifest_hash: vHash(x.manifest_hash),
    engine: lit(x.engine, "bedrock.eval/1"),
  };
}

export function vDraft(x: unknown): T.Draft {
  if (!isObj(x)) fail();
  keys(x, ["status", "supplier_alias", "catalog_item", "quantity", "quoted_minor", "asset"]);
  const d: T.Draft = {
    status: lit(x.status, "DRAFT"),
    supplier_alias: vExternalId(x.supplier_alias),
    catalog_item: vExternalId(x.catalog_item),
    quantity: vU(x.quantity),
    quoted_minor: vAmount(x.quoted_minor),
    asset: lit(x.asset, "SIMUSD"),
  };
  if (d.quantity < 1 || d.quantity > 100) fail("quantity out of range");
  const q = BigInt(d.quoted_minor);
  if (q < 1n || q > 100000n) fail("quoted amount out of range");
  return d;
}

export function vTerms(x: unknown): T.Terms {
  if (!isObj(x)) fail();
  keys(x, ["asset", "amount_minor", "owner", "beneficiary", "task_id", "reserve_until", "long_stop", "trigger"]);
  return {
    asset: lit(x.asset, "SIMUSD"),
    amount_minor: lit(x.amount_minor, "1000"),
    owner: vExternalId(x.owner),
    beneficiary: vExternalId(x.beneficiary),
    task_id: vExternalId(x.task_id),
    reserve_until: vTime(x.reserve_until),
    long_stop: vTime(x.long_stop),
    trigger: lit(x.trigger, "OPERATOR_REJECTION_OF_CONFIRMED_DRAFT"),
  };
}

/** Full Action validation including the §3.2 structural relations. */
export function vAction(x: unknown): T.Action {
  if (!isObj(x)) fail("action not object");
  keys(x, [
    "schema", "profile", "tenant_id", "scope_id", "action_id", "principal_id",
    "action_class", "resource", "expected", "draft", "terms", "policy_pin",
    "adapter_build", "created_at", "execute_before",
  ]);
  const a: T.Action = {
    schema: lit(x.schema, "bond.action/1"),
    profile: lit(x.profile, "bond.sim-procurement-draft/1"),
    tenant_id: vId(x.tenant_id, "bnt"),
    scope_id: vId(x.scope_id, "bns"),
    action_id: vId(x.action_id, "bac"),
    principal_id: vId(x.principal_id, "bnp"),
    action_class: lit(x.action_class, "procurement.draft.create/1"),
    resource: str(x.resource),
    expected: lit(x.expected, "ABSENT"),
    draft: vDraft(x.draft),
    terms: vTerms(x.terms),
    policy_pin: vPolicyPin(x.policy_pin),
    adapter_build: vHash(x.adapter_build),
    created_at: vTime(x.created_at),
    execute_before: vTime(x.execute_before),
  };
  if (a.resource !== "drafts/" + a.action_id) fail("resource must be drafts/<action_id>");
  const created = timeMs(a.created_at);
  const deadline = timeMs(a.execute_before);
  if (!(created < deadline && deadline <= created + 30000)) fail("invalid execution window");
  const reserve = timeMs(a.terms.reserve_until);
  if (reserve !== created + 300000) fail("reserve_until must be created_at+300000ms");
  const longStop = timeMs(a.terms.long_stop);
  if (!(longStop > reserve)) fail("long_stop must follow reserve expiry");
  if (longStop > created + 45 * 24 * 3600 * 1000) fail("long_stop beyond task posting +45d");
  return a;
}

export function vUndoPlan(x: unknown): T.UndoPlan {
  if (!isObj(x)) fail();
  keys(x, [
    "schema", "action_hash", "adapter_build", "operation", "resource",
    "require_status", "require_no_export", "version_source", "value_hash",
    "remedy_minor", "asset", "expires_at",
  ]);
  return {
    schema: lit(x.schema, "bond.undo-plan/1"),
    action_hash: vHash(x.action_hash),
    adapter_build: vHash(x.adapter_build),
    operation: lit(x.operation, "draft.delete_if_created_version"),
    resource: str(x.resource),
    require_status: lit(x.require_status, "DRAFT"),
    require_no_export: lit(x.require_no_export, true),
    version_source: lit(x.version_source, "FORWARD_RESULT"),
    value_hash: vHash(x.value_hash),
    remedy_minor: lit(x.remedy_minor, "1000"),
    asset: lit(x.asset, "SIMUSD"),
    expires_at: vTime(x.expires_at),
  };
}

export function vPaperReview(x: unknown): T.PaperReview {
  if (!isObj(x)) fail();
  keys(x, [
    "schema", "paper_id", "tenant_id", "holder", "insurer_label", "policy_reference",
    "document", "reviewed_by", "reviewed_at", "effective_at", "expires_at",
    "action_class", "asset", "stated_per_action_limit", "exclusions_document",
    "mode", "insurer_confirmed", "aggregate_availability", "coverage_verdict",
  ]);
  return {
    schema: lit(x.schema, "bond.paper/1"),
    paper_id: vId(x.paper_id, "bni"),
    tenant_id: vId(x.tenant_id, "bnt"),
    holder: vId(x.holder, "bnp"),
    insurer_label: str(x.insurer_label),
    policy_reference: vExternalId(x.policy_reference),
    document: vArtifactRef(x.document),
    reviewed_by: vId(x.reviewed_by, "bnp"),
    reviewed_at: vTime(x.reviewed_at),
    effective_at: vTime(x.effective_at),
    expires_at: vTime(x.expires_at),
    action_class: lit(x.action_class, "procurement.draft.create/1"),
    asset: lit(x.asset, "SIMUSD"),
    stated_per_action_limit: vAmount(x.stated_per_action_limit),
    exclusions_document: vArtifactRef(x.exclusions_document),
    mode: lit(x.mode, "PAPER_ONLY"),
    insurer_confirmed: lit(x.insurer_confirmed, false),
    aggregate_availability: lit(x.aggregate_availability, "NOT_VERIFIED"),
    coverage_verdict: lit(x.coverage_verdict, "NOT_DETERMINED"),
  };
}

/** Paper/action consistency (§3.2); throws INSURANCE_SCOPE on mismatch. */
export function checkPaperConsistency(paper: T.PaperReview, action: T.Action): void {
  const bad = () => { throw new BondError("INSURANCE_SCOPE", "paper inconsistent with action"); };
  if (paper.tenant_id !== action.tenant_id) bad();
  if (paper.holder !== action.principal_id) bad();
  if (paper.action_class !== action.action_class) bad();
  if (paper.asset !== action.terms.asset) bad();
  if (BigInt(paper.stated_per_action_limit) < 1000n) bad();
  const created = timeMs(action.created_at);
  if (!(timeMs(paper.effective_at) <= created && created < timeMs(paper.expires_at))) bad();
}

export function vBinding(x: unknown): T.Binding {
  if (!isObj(x)) fail();
  keys(x, ["action", "plan", "paper", "trellis_run", "trellis_host", "trellis_task_ref"]);
  return {
    action: vArtifactRef(x.action),
    plan: vArtifactRef(x.plan),
    paper: vArtifactRef(x.paper),
    trellis_run: vExternalId(x.trellis_run),
    trellis_host: vExternalId(x.trellis_host),
    trellis_task_ref: vId(x.trellis_task_ref, "bac"),
  };
}

// --- facts ------------------------------------------------------------------

export function vPolicyFacts(x: unknown): T.PolicyFacts {
  if (!isObj(x)) fail();
  keys(x, ["kind", "purpose", "pin", "input_hash", "verdict", "reason", "evaluated_at"]);
  return {
    kind: lit(x.kind, "POLICY"),
    purpose: oneOf(x.purpose, ["FORWARD", "UNDO"]),
    pin: vPolicyPin(x.pin),
    input_hash: vHash(x.input_hash),
    verdict: oneOf(x.verdict, ["ALLOW", "DENY"]),
    reason: str(x.reason),
    evaluated_at: vTime(x.evaluated_at),
  };
}

export function vHoldFacts(x: unknown): T.HoldFacts {
  if (!isObj(x)) fail();
  keys(x, ["kind", "hold_id", "revision", "action_hash", "terms", "state", "exclusive",
    "operation_key", "journal_head", "settlement_basis"]);
  const f: T.HoldFacts = {
    kind: lit(x.kind, "HOLD"),
    hold_id: vExternalId(x.hold_id),
    revision: vU(x.revision),
    action_hash: vHash(x.action_hash),
    terms: vTerms(x.terms),
    state: oneOf(x.state, ["HELD", "ENCUMBERED", "RELEASED", "PAID"]),
    exclusive: lit(x.exclusive, true),
    operation_key: str(x.operation_key),
    journal_head: vHead(x.journal_head),
    settlement_basis: x.settlement_basis === null
      ? null
      : oneOf(x.settlement_basis, ["REQUEST", "RESERVATION_EXPIRED", "LONG_STOP"] as const),
  };
  // §3.3: HELD/ENCUMBERED require null basis; PAID requires REQUEST;
  // RELEASED allows REQUEST, RESERVATION_EXPIRED, or LONG_STOP.
  if ((f.state === "HELD" || f.state === "ENCUMBERED") && f.settlement_basis !== null) fail();
  if (f.state === "PAID" && f.settlement_basis !== "REQUEST") fail();
  return f;
}

export function vNoHoldFacts(x: unknown): T.NoHoldFacts {
  if (!isObj(x)) fail();
  keys(x, ["kind", "operation_key", "authoritative", "reason"]);
  return {
    kind: lit(x.kind, "NO_HOLD"),
    operation_key: str(x.operation_key),
    authoritative: lit(x.authoritative, true),
    reason: oneOf(x.reason, ["INSUFFICIENT_FUNDS", "EXPIRED", "POLICY_DENIED"]),
  };
}

export function vEffectFacts(x: unknown): T.EffectFacts {
  if (!isObj(x)) fail();
  keys(x, ["kind", "purpose", "operation_key", "outcome", "resource", "version", "value_hash", "reason"]);
  const f: T.EffectFacts = {
    kind: lit(x.kind, "EFFECT"),
    purpose: oneOf(x.purpose, ["FORWARD", "UNDO"]),
    operation_key: str(x.operation_key),
    outcome: oneOf(x.outcome, ["APPLIED", "NOT_APPLIED", "UNKNOWN"]),
    resource: str(x.resource),
    version: x.version === null ? null : vExternalId(x.version),
    value_hash: x.value_hash === null ? null : vHash(x.value_hash),
    reason: oneOf(x.reason, [
      "CREATED", "DELETED", "ABSENT", "VERSION_CHANGED", "POLICY_DENIED",
      "TRANSPORT_UNKNOWN", "STOPPED_BEFORE_CALL", "DEADLINE_BEFORE_CALL",
    ]),
  };
  // §3.3: APPLIED requires non-null version and value hash; others require null.
  if (f.outcome === "APPLIED" && (f.version === null || f.value_hash === null)) fail();
  if (f.outcome !== "APPLIED" && (f.version !== null || f.value_hash !== null)) fail();
  return f;
}

export function vRunFacts(x: unknown): T.RunFacts {
  if (!isObj(x)) fail();
  keys(x, ["kind", "run_id", "host_id", "task_ref", "state", "checkpoint", "policy_hash", "complete_prefix"]);
  return {
    kind: lit(x.kind, "RUN"),
    run_id: vExternalId(x.run_id),
    host_id: vExternalId(x.host_id),
    task_ref: vId(x.task_ref, "bac"),
    state: oneOf(x.state, ["ACTIVE", "STOPPING", "STOPPED", "UNCONFIRMED"]),
    checkpoint: vHead(x.checkpoint),
    policy_hash: vHash(x.policy_hash),
    complete_prefix: bool(x.complete_prefix),
  };
}

export function vKillFacts(x: unknown): T.KillFacts {
  if (!isObj(x)) fail();
  keys(x, ["kind", "run_id", "host_id", "task_ref", "state", "stopped_head", "gate_closed",
    "empty_observed", "audit_gap", "external_effects", "remote_replication"]);
  return {
    kind: lit(x.kind, "KILL"),
    run_id: vExternalId(x.run_id),
    host_id: vExternalId(x.host_id),
    task_ref: vId(x.task_ref, "bac"),
    state: oneOf(x.state, ["CERTIFIED", "UNCONFIRMED"]),
    stopped_head: x.stopped_head === null ? null : vHead(x.stopped_head),
    gate_closed: bool(x.gate_closed),
    empty_observed: bool(x.empty_observed),
    audit_gap: bool(x.audit_gap),
    external_effects: lit(x.external_effects, "NOT_REVERSED"),
    remote_replication: lit(x.remote_replication, "NOT_ATTESTED"),
  };
}

export function vFacts(x: unknown): T.Facts {
  if (!isObj(x) || typeof x.kind !== "string") fail();
  switch (x.kind) {
    case "POLICY": return vPolicyFacts(x);
    case "HOLD": return vHoldFacts(x);
    case "NO_HOLD": return vNoHoldFacts(x);
    case "EFFECT": return vEffectFacts(x);
    case "RUN": return vRunFacts(x);
    case "KILL": return vKillFacts(x);
    default: fail("unknown facts kind");
  }
}

const SOURCE_PROFILES = [
  "fixture/1", "bedrock/1", "mint.bond-hold/1",
  "vekrevert.bond-draft/1", "trellis-bundle/1", "bond.draft-store/1",
] as const;

export function vAssertion(x: unknown): T.Assertion {
  if (!isObj(x)) fail();
  keys(x, ["schema", "action_hash", "observed_at", "source_profile", "source", "facts"]);
  return {
    schema: lit(x.schema, "bond.assertion/1"),
    action_hash: vHash(x.action_hash),
    observed_at: vTime(x.observed_at),
    source_profile: oneOf(x.source_profile, SOURCE_PROFILES),
    source: vArtifactRef(x.source),
    facts: vFacts(x.facts),
  };
}

export function vDraftStoreRecord(x: unknown): T.DraftStoreRecord {
  if (!isObj(x)) fail();
  keys(x, ["schema", "action_hash", "scope_id", "writer_fence", "observed_at", "facts"]);
  return {
    schema: lit(x.schema, "bond.draft-store/1"),
    action_hash: vHash(x.action_hash),
    scope_id: vId(x.scope_id, "bns"),
    writer_fence: vU(x.writer_fence),
    observed_at: vTime(x.observed_at),
    facts: vEffectFacts(x.facts),
  };
}

// --- entries ----------------------------------------------------------------

const EVENT_KINDS = [
  "ActionStaged", "HoldObserved", "CommitRequested", "DispatchLatched",
  "ActionAborted", "EffectObserved", "ReviewAccepted", "ReviewRejected",
  "UndoObserved", "FundsObserved", "ActionClosed", "StopRequested",
  "KillObserved", "EvidenceAttached", "DependencyUncertain", "RecoveryQuarantined",
] as const;

function vEventData(kind: T.EventKind, x: unknown): T.EventData[T.EventKind] {
  if (!isObj(x)) fail();
  switch (kind) {
    case "ActionStaged":
      keys(x, ["binding"]);
      return { binding: vBinding(x.binding) };
    case "HoldObserved":
    case "EffectObserved":
    case "UndoObserved":
    case "FundsObserved":
    case "KillObserved":
      keys(x, ["evidence"]);
      return { evidence: vArtifactRef(x.evidence) };
    case "CommitRequested":
      keys(x, ["operation_key"]);
      return { operation_key: str(x.operation_key) };
    case "DispatchLatched": {
      keys(x, ["policy", "runtime", "hold", "fence", "operation_key", "timing"]);
      if (!isObj(x.timing)) fail();
      keys(x.timing, ["boot_id", "runtime_observed_ms", "admitted_ms"]);
      const t = x.timing;
      return {
        policy: vArtifactRef(x.policy),
        runtime: vArtifactRef(x.runtime),
        hold: vArtifactRef(x.hold),
        fence: vU(x.fence),
        operation_key: str(x.operation_key),
        timing: {
          boot_id: vExternalId(t.boot_id),
          runtime_observed_ms: vU(t.runtime_observed_ms),
          admitted_ms: vU(t.admitted_ms),
        },
      };
    }
    case "ActionAborted":
      keys(x, ["reason"]);
      return { reason: oneOf(x.reason, ["CANCELED", "DEADLINE", "DEPENDENCY_DENIED", "STOPPED"]) };
    case "ReviewAccepted":
      keys(x, ["principal_id"]);
      return { principal_id: vId(x.principal_id, "bnp") };
    case "ReviewRejected": {
      keys(x, ["principal_id", "reason", "policy"]);
      return {
        principal_id: vId(x.principal_id, "bnp"),
        reason: oneOf(x.reason, ["OPERATOR_REJECTED", "VALIDATION_FAILED"]),
        policy: x.policy === null ? null : vArtifactRef(x.policy),
      };
    }
    case "ActionClosed":
      keys(x, ["disposition"]);
      return { disposition: oneOf(x.disposition, ["NO_HOLD", "RELEASE", "PAY", "EXTERNAL_MATURITY"]) };
    case "StopRequested":
      keys(x, ["principal_id", "operation_key"]);
      return { principal_id: vId(x.principal_id, "bnp"), operation_key: str(x.operation_key) };
    case "EvidenceAttached":
      keys(x, ["artifact", "purpose"]);
      return {
        artifact: vArtifactRef(x.artifact),
        purpose: oneOf(x.purpose, ["GROUND_ADVISORY", "WORLD_LINEAGE"]),
      };
    case "DependencyUncertain":
      keys(x, ["operation"]);
      return { operation: oneOf(x.operation, ["RESERVE", "ENCUMBER", "CREATE", "UNDO", "RELEASE", "PAY", "STOP"]) };
    case "RecoveryQuarantined":
      keys(x, ["reason"]);
      return { reason: oneOf(x.reason, ["HASH_CHAIN", "WRITER_FENCE", "CLOCK", "SOURCE_FORK"]) };
    default:
      fail("unknown event kind");
  }
}

export function vEntryBody(x: unknown): T.EntryBody {
  if (!isObj(x)) fail("entry body not object");
  keys(x, ["schema", "tenant_id", "action_id", "action_hash", "event_id", "seq",
    "previous_hash", "recorded_at", "actor", "kind", "data"]);
  const kind = oneOf(x.kind, EVENT_KINDS);
  const body = {
    schema: lit(x.schema, "bond.entry/1"),
    tenant_id: vId(x.tenant_id, "bnt"),
    action_id: vId(x.action_id, "bac"),
    action_hash: vHash(x.action_hash),
    event_id: vId(x.event_id, "bnj"),
    seq: vU(x.seq),
    previous_hash: vHash(x.previous_hash),
    recorded_at: vTime(x.recorded_at),
    actor: vId(x.actor, "bnp"),
    kind,
    data: vEventData(kind, x.data),
  };
  return body as T.EntryBody;
}

export function vView(x: unknown): T.View {
  if (!isObj(x)) fail();
  keys(x, ["receipt_id", "action_id", "revision", "phase", "effect", "undo", "funds",
    "kill", "review", "stop_latched", "quarantined", "pending", "head"]);
  if (!Array.isArray(x.pending)) fail();
  const pending = x.pending.map((p) => oneOf(p, ["RESERVE", "ENCUMBER", "CREATE", "UNDO", "RELEASE", "PAY", "STOP"] as const));
  const sorted = [...pending].sort();
  if (pending.length !== new Set(pending).size || pending.some((p, i) => p !== sorted[i])) {
    fail("pending not sorted/unique");
  }
  return {
    receipt_id: vId(x.receipt_id, "brc"),
    action_id: vId(x.action_id, "bac"),
    revision: vU(x.revision),
    phase: oneOf(x.phase, ["STAGED", "READY", "COMMITTING", "EXECUTING", "AWAITING_REVIEW",
      "COMPENSATING", "UNCERTAIN", "CLOSING", "CLOSED"]),
    effect: oneOf(x.effect, ["NOT_DISPATCHED", "PENDING", "APPLIED", "NOT_APPLIED", "UNKNOWN"]),
    undo: oneOf(x.undo, ["PLANNED", "PENDING", "APPLIED", "NOT_NEEDED", "FAILED", "UNKNOWN"]),
    funds: oneOf(x.funds, ["NONE", "HELD", "ENCUMBERED", "RELEASED", "PAID", "UNKNOWN"]),
    kill: oneOf(x.kill, ["ARMED", "REQUESTED", "CERTIFIED", "UNCONFIRMED"]),
    review: oneOf(x.review, ["NONE", "ACCEPT", "REJECT"]),
    stop_latched: bool(x.stop_latched),
    quarantined: bool(x.quarantined),
    pending,
    head: vHead(x.head),
  };
}

export function vReceiptBody(x: unknown): T.ReceiptBody {
  if (!isObj(x)) fail();
  keys(x, ["schema", "receipt_id", "tenant_id", "action_id", "action_hash", "revision",
    "previous_receipt_hash", "head", "binding", "view", "evidence", "issued_at",
    "simulation", "assembly", "insurance", "residual_effect", "remedy", "truth"]);
  if (!Array.isArray(x.evidence)) fail();
  const evidence = x.evidence.map(vArtifactRef);
  const hashes = evidence.map((e) => e.hash);
  const sorted = [...hashes].sort();
  if (hashes.some((h, i) => h !== sorted[i]) || new Set(hashes).size !== hashes.length) {
    fail("evidence not sorted/unique");
  }
  return {
    schema: lit(x.schema, "bond.receipt/1"),
    receipt_id: vId(x.receipt_id, "brc"),
    tenant_id: vId(x.tenant_id, "bnt"),
    action_id: vId(x.action_id, "bac"),
    action_hash: vHash(x.action_hash),
    revision: vU(x.revision),
    previous_receipt_hash: x.previous_receipt_hash === null ? null : vHash(x.previous_receipt_hash),
    head: vHead(x.head),
    binding: vBinding(x.binding),
    view: vView(x.view),
    evidence,
    issued_at: vTime(x.issued_at),
    simulation: lit(x.simulation, true),
    assembly: oneOf(x.assembly, ["COMPLETE", "INCOMPLETE"]),
    insurance: lit(x.insurance, "PAPER_ONLY"),
    residual_effect: oneOf(x.residual_effect, ["NONE", "DRAFT_PRESENT", "NOT_REVERSED", "UNKNOWN"]),
    remedy: oneOf(x.remedy, ["NOT_TRIGGERED", "DUE", "PAID"]),
    truth: lit(x.truth, "ISSUER_ASSERTIONS_NOT_REAL_WORLD_PROOF"),
  };
}

export function vPackage(x: unknown): T.Package {
  if (!isObj(x)) fail();
  keys(x, ["schema", "receipts", "entries", "blobs"]);
  if (!Array.isArray(x.receipts) || !Array.isArray(x.entries) || !Array.isArray(x.blobs)) fail();
  return {
    schema: lit(x.schema, "bond.package/1"),
    receipts: x.receipts as T.Receipt[],
    entries: x.entries as T.Entry[],
    blobs: x.blobs.map(vBlob),
  };
}

export function vNotice(x: unknown): T.Notice {
  if (!isObj(x)) fail();
  keys(x, ["schema", "receipt_id", "revision", "previous_hash", "reason", "recorded_at"]);
  return {
    schema: lit(x.schema, "bond.notice/1"),
    receipt_id: vId(x.receipt_id, "brc"),
    revision: vU(x.revision),
    previous_hash: x.previous_hash === null ? null : vHash(x.previous_hash),
    reason: oneOf(x.reason, ["HOSTING_WITHDRAWN", "KEY_COMPROMISE_REPORTED"]),
    recorded_at: vTime(x.recorded_at),
  };
}

export function vHttpAuth(x: unknown): T.HttpAuth {
  if (!isObj(x)) fail();
  keys(x, ["tenant_id", "principal_id", "key_id", "request_id", "method", "target",
    "body_hash", "issued_at", "expires_at", "sig"]);
  const sig = x.sig;
  if (!isB64u(sig)) fail("bad sig encoding");
  if (Buffer.from(sig as string, "base64url").length !== 64) fail("bad sig length");
  return {
    tenant_id: vId(x.tenant_id, "bnt"),
    principal_id: vId(x.principal_id, "bnp"),
    key_id: vId(x.key_id, "bnk"),
    request_id: vId(x.request_id, "bnq"),
    method: oneOf(x.method, ["GET", "POST"]),
    target: str(x.target),
    body_hash: vHash(x.body_hash),
    issued_at: vTime(x.issued_at),
    expires_at: vTime(x.expires_at),
    sig: sig as string,
  };
}

export function vSigned<S>(x: unknown, kind: string, vBody: (b: unknown) => S): T.Signed<S> {
  if (!isObj(x)) fail();
  keys(x, ["body", "key_id", "hash", "sig"]);
  const sig = x.sig;
  if (!isB64u(sig) || Buffer.from(sig as string, "base64url").length !== 64) fail("bad sig");
  return {
    body: vBody(x.body),
    key_id: vId(x.key_id, "bnk"),
    hash: vHash(x.hash),
    sig: sig as string,
  };
}

// --- config/trust -----------------------------------------------------------

export function vTrustFile(x: unknown): T.TrustFile {
  if (!isObj(x)) fail();
  keys(x, ["schema", "keys", "allowed_adapter_builds", "expected_heads"]);
  if (!Array.isArray(x.keys) || !Array.isArray(x.allowed_adapter_builds) || !Array.isArray(x.expected_heads)) fail();
  lit(x.schema, "bond.trust/1");
  const keysArr: T.TrustKey[] = x.keys.map((k) => {
    if (!isObj(k)) fail();
    keys(k, ["key_id", "public_key_hex", "roles", "assertion_kinds", "source_profiles",
      "tenant_id", "not_before", "not_after", "compromised_at"]);
    if (!Array.isArray(k.roles) || !Array.isArray(k.assertion_kinds) || !Array.isArray(k.source_profiles)) fail();
    return {
      key_id: vId(k.key_id, "bnk"),
      public_key_hex: vHash(k.public_key_hex),
      roles: k.roles.map((r) => oneOf(r, ["receipt", "entry", "paper", "assertion", "notice", "http", "draft-store"])),
      assertion_kinds: k.assertion_kinds.map((a) => oneOf(a, ["POLICY", "HOLD", "NO_HOLD", "EFFECT", "RUN", "KILL"])),
      source_profiles: k.source_profiles.map((p) => oneOf(p, SOURCE_PROFILES)),
      tenant_id: vId(k.tenant_id, "bnt"),
      not_before: vTime(k.not_before),
      not_after: vTime(k.not_after),
      compromised_at: k.compromised_at === null ? null : vTime(k.compromised_at),
    };
  });
  const keyIds = keysArr.map((k) => k.key_id);
  if (keyIds.length !== new Set(keyIds).size || keyIds.some((k, i) => k !== [...keyIds].sort()[i])) {
    fail("trust keys not sorted/unique");
  }
  const pubs = keysArr.map((k) => k.public_key_hex);
  if (pubs.length !== new Set(pubs).size) fail("duplicate public keys");
  const expected_heads = x.expected_heads.map((e) => {
    if (!isObj(e)) fail();
    keys(e, ["receipt_id", "head"]);
    return { receipt_id: vId(e.receipt_id, "brc"), head: vHead(e.head) };
  });
  return {
    schema: "bond.trust/1",
    keys: keysArr,
    allowed_adapter_builds: x.allowed_adapter_builds.map(vHash),
    expected_heads,
  };
}

export function vConfig(x: unknown): T.Config {
  if (!isObj(x)) fail();
  keys(x, ["schema", "profile", "tenant_id", "scope_id", "principal_id", "data_dir",
    "trust_file", "signing_key_ref", "clock_max_uncertainty_ms", "run_freshness_ms",
    "dependency_timeout_ms", "max_pending_actions", "max_package_bytes",
    "insurance_mode", "scope_binding", "adapters", "hosting"]);
  lit(x.schema, "bond.config/1");
  lit(x.profile, "bond.sim-procurement-draft/1");
  if (!isObj(x.scope_binding)) fail();
  keys(x.scope_binding, ["bedrock_principal", "bedrock_scope", "mint_owner", "mint_beneficiary"]);
  if (!Array.isArray(x.adapters)) fail();
  const adapters = x.adapters.map((a) => {
    if (!isObj(a)) fail();
    keys(a, ["id", "mode", "build_hash", "binding"]);
    return {
      id: oneOf(a.id, ["bedrock", "mint", "vekrevert", "trellis", "executor"]),
      mode: oneOf(a.mode, ["fixture", "installed"]),
      build_hash: vHash(a.build_hash),
      binding: isBindingName(a.binding) ? (a.binding as string) : fail("bad binding"),
    };
  });
  const ids = adapters.map((a) => a.id);
  const wantIds = ["bedrock", "executor", "mint", "trellis", "vekrevert"];
  if (ids.length !== 5 || new Set(ids).size !== 5
    || ids.some((id, i) => id !== wantIds[i])) {
    fail("exactly five adapters sorted by id required");
  }
  if (!isObj(x.hosting)) fail();
  let hosting: T.Config["hosting"];
  if (x.hosting.enabled === false) {
    keys(x.hosting, ["enabled"]);
    hosting = { enabled: false };
  } else if (x.hosting.enabled === true) {
    keys(x.hosting, ["enabled", "origin", "credential_key_ref"]);
    const origin = str(x.hosting.origin);
    const u = URL.parse(origin);
    if (u === null || (u.protocol !== "https:" && u.hostname !== "localhost" && u.hostname !== "127.0.0.1")
      || u.pathname !== "/" || u.search !== "" || u.hash !== "" || u.username !== "" || u.password !== "") {
      fail("hosting origin must be bare https origin (loopback http allowed for tests)");
    }
    hosting = { enabled: true, origin, credential_key_ref: str(x.hosting.credential_key_ref) };
  } else {
    fail();
  }
  return {
    schema: "bond.config/1",
    profile: "bond.sim-procurement-draft/1",
    tenant_id: vId(x.tenant_id, "bnt"),
    scope_id: vId(x.scope_id, "bns"),
    principal_id: vId(x.principal_id, "bnp"),
    data_dir: str(x.data_dir),
    trust_file: str(x.trust_file),
    signing_key_ref: str(x.signing_key_ref),
    clock_max_uncertainty_ms: lit(x.clock_max_uncertainty_ms, 1000),
    run_freshness_ms: lit(x.run_freshness_ms, 250),
    dependency_timeout_ms: lit(x.dependency_timeout_ms, 5000),
    max_pending_actions: lit(x.max_pending_actions, 100),
    max_package_bytes: lit(x.max_package_bytes, 8388608),
    insurance_mode: lit(x.insurance_mode, "paper-required"),
    scope_binding: {
      bedrock_principal: vExternalId(x.scope_binding.bedrock_principal),
      bedrock_scope: vExternalId(x.scope_binding.bedrock_scope),
      mint_owner: vExternalId(x.scope_binding.mint_owner),
      mint_beneficiary: vExternalId(x.scope_binding.mint_beneficiary),
    },
    adapters,
    hosting,
  };
}

export function vCapabilityManifest(x: unknown): T.CapabilityManifest {
  if (!isObj(x)) fail();
  keys(x, ["schema", "adapter", "build_hash", "mode", "source_profile", "methods",
    "assertion_key_id", "conformance_report_hash", "guarantees"]);
  lit(x.schema, "bond.adapter-capabilities/1");
  if (!Array.isArray(x.methods) || !isObj(x.guarantees)) fail();
  const g = x.guarantees;
  keys(g, ["exclusive_hold", "action_consume", "authoritative_lookup",
    "conditional_inverse", "writer_fence", "bound_local_run", "embedded_policy"]);
  const methods = x.methods.map(str);
  const sorted = [...methods].sort();
  if (methods.some((m, i) => m !== sorted[i])) fail("methods not sorted");
  return {
    schema: "bond.adapter-capabilities/1",
    adapter: oneOf(x.adapter, ["bedrock", "mint", "vekrevert", "trellis", "executor"]),
    build_hash: vHash(x.build_hash),
    mode: oneOf(x.mode, ["SIMULATED", "VERIFIED_NATIVE"]),
    source_profile: oneOf(x.source_profile, SOURCE_PROFILES),
    methods,
    assertion_key_id: vId(x.assertion_key_id, "bnk"),
    conformance_report_hash: vHash(x.conformance_report_hash),
    guarantees: {
      exclusive_hold: bool(g.exclusive_hold),
      action_consume: bool(g.action_consume),
      authoritative_lookup: bool(g.authoritative_lookup),
      conditional_inverse: bool(g.conditional_inverse),
      writer_fence: bool(g.writer_fence),
      bound_local_run: bool(g.bound_local_run),
      embedded_policy: bool(g.embedded_policy),
    },
  };
}

export function vMigrationFile(x: unknown): T.MigrationFile {
  if (!isObj(x)) fail();
  keys(x, ["schema", "from_storage", "to_storage", "source_checkpoint", "tool_build", "backup_digest", "mode"]);
  return {
    schema: lit(x.schema, "bond.migration/1"),
    from_storage: lit(x.from_storage, 1),
    to_storage: lit(x.to_storage, 2),
    source_checkpoint: vHash(x.source_checkpoint),
    tool_build: vHash(x.tool_build),
    backup_digest: vHash(x.backup_digest),
    mode: lit(x.mode, "COPY_AND_VERIFY"),
  };
}
