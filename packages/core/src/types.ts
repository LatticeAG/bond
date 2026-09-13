/** Normative wire types — BOND_SPEC §3.1–§3.4, §6.1, §6.4, §7.1. */

import { Head } from "./errors.js";

export type U = number;
export type Amount = string;
export type Time = string;
export type Hash = string;
export type B64 = string;
export type Sig = string;
export type ExternalId = string;
export type TenantId = string;
export type ScopeId = string;
export type PrincipalId = string;
export type ActionId = string;
export type ReceiptId = string;
export type RequestId = string;
export type KeyId = string;
export type PaperId = string;
export type EventId = string;

export interface ArtifactRef {
  hash: Hash;
  bytes: U;
  media_type: "application/json" | "application/pdf";
}

export interface Blob extends ArtifactRef {
  data: B64 | null;
}

export interface Signed<T> {
  body: T;
  key_id: KeyId;
  hash: Hash;
  sig: Sig;
}

export type Profile = "bond.sim-procurement-draft/1";
export type Purpose = "FORWARD" | "UNDO";
export type Role = "operator" | "agent" | "auditor" | "publisher";

export interface AuthContext {
  tenant_id: TenantId;
  principal_id: PrincipalId;
  scopes: ScopeId[];
  roles: Role[];
}

export interface Draft {
  status: "DRAFT";
  supplier_alias: ExternalId;
  catalog_item: ExternalId;
  quantity: U;
  quoted_minor: Amount;
  asset: "SIMUSD";
}

export interface Terms {
  asset: "SIMUSD";
  amount_minor: "1000";
  owner: ExternalId;
  beneficiary: ExternalId;
  task_id: ExternalId;
  reserve_until: Time;
  long_stop: Time;
  trigger: "OPERATOR_REJECTION_OF_CONFIRMED_DRAFT";
}

export interface PolicyPin {
  charter_id: ExternalId;
  version: U;
  charter_hash: Hash;
  manifest_hash: Hash;
  engine: "bedrock.eval/1";
}

export interface Action {
  schema: "bond.action/1";
  profile: Profile;
  tenant_id: TenantId;
  scope_id: ScopeId;
  action_id: ActionId;
  principal_id: PrincipalId;
  action_class: "procurement.draft.create/1";
  resource: string;
  expected: "ABSENT";
  draft: Draft;
  terms: Terms;
  policy_pin: PolicyPin;
  adapter_build: Hash;
  created_at: Time;
  execute_before: Time;
}

export interface UndoPlan {
  schema: "bond.undo-plan/1";
  action_hash: Hash;
  adapter_build: Hash;
  operation: "draft.delete_if_created_version";
  resource: string;
  require_status: "DRAFT";
  require_no_export: true;
  version_source: "FORWARD_RESULT";
  value_hash: Hash;
  remedy_minor: "1000";
  asset: "SIMUSD";
  expires_at: Time;
}

export interface PaperReview {
  schema: "bond.paper/1";
  paper_id: PaperId;
  tenant_id: TenantId;
  holder: PrincipalId;
  insurer_label: string;
  policy_reference: ExternalId;
  document: ArtifactRef;
  reviewed_by: PrincipalId;
  reviewed_at: Time;
  effective_at: Time;
  expires_at: Time;
  action_class: "procurement.draft.create/1";
  asset: "SIMUSD";
  stated_per_action_limit: Amount;
  exclusions_document: ArtifactRef;
  mode: "PAPER_ONLY";
  insurer_confirmed: false;
  aggregate_availability: "NOT_VERIFIED";
  coverage_verdict: "NOT_DETERMINED";
}

export interface Binding {
  action: ArtifactRef;
  plan: ArtifactRef;
  paper: ArtifactRef;
  trellis_run: ExternalId;
  trellis_host: ExternalId;
  trellis_task_ref: ActionId;
}

export interface PolicyFacts {
  kind: "POLICY";
  purpose: Purpose;
  pin: PolicyPin;
  input_hash: Hash;
  verdict: "ALLOW" | "DENY";
  reason: string;
  evaluated_at: Time;
}

export interface HoldFacts {
  kind: "HOLD";
  hold_id: ExternalId;
  revision: U;
  action_hash: Hash;
  terms: Terms;
  state: "HELD" | "ENCUMBERED" | "RELEASED" | "PAID";
  exclusive: true;
  operation_key: string;
  journal_head: Head;
  settlement_basis: "REQUEST" | "RESERVATION_EXPIRED" | "LONG_STOP" | null;
}

export interface NoHoldFacts {
  kind: "NO_HOLD";
  operation_key: string;
  authoritative: true;
  reason: "INSUFFICIENT_FUNDS" | "EXPIRED" | "POLICY_DENIED";
}

export type EffectReason =
  | "CREATED" | "DELETED" | "ABSENT" | "VERSION_CHANGED" | "POLICY_DENIED"
  | "TRANSPORT_UNKNOWN" | "STOPPED_BEFORE_CALL" | "DEADLINE_BEFORE_CALL";

export interface EffectFacts {
  kind: "EFFECT";
  purpose: Purpose;
  operation_key: string;
  outcome: "APPLIED" | "NOT_APPLIED" | "UNKNOWN";
  resource: string;
  version: ExternalId | null;
  value_hash: Hash | null;
  reason: EffectReason;
}

export interface RunFacts {
  kind: "RUN";
  run_id: ExternalId;
  host_id: ExternalId;
  task_ref: ActionId;
  state: "ACTIVE" | "STOPPING" | "STOPPED" | "UNCONFIRMED";
  checkpoint: Head;
  policy_hash: Hash;
  complete_prefix: boolean;
}

export interface KillFacts {
  kind: "KILL";
  run_id: ExternalId;
  host_id: ExternalId;
  task_ref: ActionId;
  state: "CERTIFIED" | "UNCONFIRMED";
  stopped_head: Head | null;
  gate_closed: boolean;
  empty_observed: boolean;
  audit_gap: boolean;
  external_effects: "NOT_REVERSED";
  remote_replication: "NOT_ATTESTED";
}

export type SourceProfile =
  | "fixture/1" | "bedrock/1" | "mint.bond-hold/1"
  | "vekrevert.bond-draft/1" | "trellis-bundle/1" | "bond.draft-store/1";

export type AssertionKind = "POLICY" | "HOLD" | "NO_HOLD" | "EFFECT" | "RUN" | "KILL";

export type Facts =
  | PolicyFacts | HoldFacts | NoHoldFacts | EffectFacts | RunFacts | KillFacts;

export interface Assertion {
  schema: "bond.assertion/1";
  action_hash: Hash;
  observed_at: Time;
  source_profile: SourceProfile;
  source: ArtifactRef;
  facts: Facts;
}

export interface Evidence {
  assertion: Signed<Assertion>;
  source: Blob;
}

export interface DraftStoreRecord {
  schema: "bond.draft-store/1";
  action_hash: Hash;
  scope_id: ScopeId;
  writer_fence: U;
  observed_at: Time;
  facts: EffectFacts;
}

export type Phase =
  | "STAGED" | "READY" | "COMMITTING" | "EXECUTING" | "AWAITING_REVIEW"
  | "COMPENSATING" | "UNCERTAIN" | "CLOSING" | "CLOSED";
export type EffectState = "NOT_DISPATCHED" | "PENDING" | "APPLIED" | "NOT_APPLIED" | "UNKNOWN";
export type UndoState = "PLANNED" | "PENDING" | "APPLIED" | "NOT_NEEDED" | "FAILED" | "UNKNOWN";
export type FundsState = "NONE" | "HELD" | "ENCUMBERED" | "RELEASED" | "PAID" | "UNKNOWN";
export type KillState = "ARMED" | "REQUESTED" | "CERTIFIED" | "UNCONFIRMED";
export type Op = "RESERVE" | "ENCUMBER" | "CREATE" | "UNDO" | "RELEASE" | "PAY" | "STOP";

export interface View {
  receipt_id: ReceiptId;
  action_id: ActionId;
  revision: U;
  phase: Phase;
  effect: EffectState;
  undo: UndoState;
  funds: FundsState;
  kill: KillState;
  review: "NONE" | "ACCEPT" | "REJECT";
  stop_latched: boolean;
  quarantined: boolean;
  pending: Op[];
  head: Head;
}

export interface EventData {
  ActionStaged: { binding: Binding };
  HoldObserved: { evidence: ArtifactRef };
  CommitRequested: { operation_key: string };
  DispatchLatched: {
    policy: ArtifactRef;
    runtime: ArtifactRef;
    hold: ArtifactRef;
    fence: U;
    operation_key: string;
    timing: { boot_id: ExternalId; runtime_observed_ms: U; admitted_ms: U };
  };
  ActionAborted: { reason: "CANCELED" | "DEADLINE" | "DEPENDENCY_DENIED" | "STOPPED" };
  EffectObserved: { evidence: ArtifactRef };
  ReviewAccepted: { principal_id: PrincipalId };
  ReviewRejected: {
    principal_id: PrincipalId;
    reason: "OPERATOR_REJECTED" | "VALIDATION_FAILED";
    policy: ArtifactRef | null;
  };
  UndoObserved: { evidence: ArtifactRef };
  FundsObserved: { evidence: ArtifactRef };
  ActionClosed: { disposition: "NO_HOLD" | "RELEASE" | "PAY" | "EXTERNAL_MATURITY" };
  StopRequested: { principal_id: PrincipalId; operation_key: string };
  KillObserved: { evidence: ArtifactRef };
  EvidenceAttached: { artifact: ArtifactRef; purpose: "GROUND_ADVISORY" | "WORLD_LINEAGE" };
  DependencyUncertain: { operation: Op };
  RecoveryQuarantined: { reason: "HASH_CHAIN" | "WRITER_FENCE" | "CLOCK" | "SOURCE_FORK" };
}

export type EventKind = keyof EventData;

export type EntryBody = {
  [K in EventKind]: {
    schema: "bond.entry/1";
    tenant_id: TenantId;
    action_id: ActionId;
    action_hash: Hash;
    event_id: EventId;
    seq: U;
    previous_hash: Hash;
    recorded_at: Time;
    actor: PrincipalId;
    kind: K;
    data: EventData[K];
  };
}[EventKind];

export type Entry = Signed<EntryBody>;

export interface ReceiptBody {
  schema: "bond.receipt/1";
  receipt_id: ReceiptId;
  tenant_id: TenantId;
  action_id: ActionId;
  action_hash: Hash;
  revision: U;
  previous_receipt_hash: Hash | null;
  head: Head;
  binding: Binding;
  view: View;
  evidence: ArtifactRef[];
  issued_at: Time;
  simulation: true;
  assembly: "COMPLETE" | "INCOMPLETE";
  insurance: "PAPER_ONLY";
  residual_effect: "NONE" | "DRAFT_PRESENT" | "NOT_REVERSED" | "UNKNOWN";
  remedy: "NOT_TRIGGERED" | "DUE" | "PAID";
  truth: "ISSUER_ASSERTIONS_NOT_REAL_WORLD_PROOF";
}

export type Receipt = Signed<ReceiptBody>;

export interface Package {
  schema: "bond.package/1";
  receipts: Receipt[];
  entries: Entry[];
  blobs: Blob[];
}

export interface Verification {
  integrity: "VALID" | "INVALID";
  completeness: "COMPLETE" | "INCOMPLETE";
  currentness: "PINNED_PREFIX" | "UNANCHORED_PREFIX";
  simulation: boolean;
  insurance: "PAPER_ONLY";
  truth: "ISSUER_ASSERTIONS_NOT_REAL_WORLD_PROOF";
  head: Head | null;
  errors: string[];
}

export type OpState = "PREPARED" | "SENT" | "KNOWN" | "UNKNOWN" | "CANCELED";

export interface Notice {
  schema: "bond.notice/1";
  receipt_id: ReceiptId;
  revision: U;
  previous_hash: Hash | null;
  reason: "HOSTING_WITHDRAWN" | "KEY_COMPROMISE_REPORTED";
  recorded_at: Time;
}

export interface Doctor {
  ready: boolean;
  profile: Profile;
  simulation: true;
  missing: string[];
}

export interface Mutation {
  request_id: RequestId;
  action_id: ActionId;
  expected_revision: U;
}

export interface Prepare {
  request_id: RequestId;
  expected_revision: 0;
  action: Action;
  run_id: ExternalId;
  paper: Signed<PaperReview> | null;
}

export interface HttpAuth {
  tenant_id: TenantId;
  principal_id: PrincipalId;
  key_id: KeyId;
  request_id: RequestId;
  method: "GET" | "POST";
  target: string;
  body_hash: Hash;
  issued_at: Time;
  expires_at: Time;
  sig: Sig;
}

export interface Publish {
  package: Package;
  expected_host_revision: U;
}

export interface Published {
  receipt_id: ReceiptId;
  revision: U;
  receipt_hash: Hash;
  hosting: "STORED";
}

export interface Hosted {
  package: Package;
  latest_revision: U;
  hosting: "ACTIVE" | "WITHDRAWN";
  notices_head: Head | null;
}

export interface HostError {
  error: { code: string; retryable: boolean };
}

export interface CapabilityManifest {
  schema: "bond.adapter-capabilities/1";
  adapter: "bedrock" | "mint" | "vekrevert" | "trellis" | "executor";
  build_hash: Hash;
  mode: "SIMULATED" | "VERIFIED_NATIVE";
  source_profile: SourceProfile;
  methods: string[];
  assertion_key_id: KeyId;
  conformance_report_hash: Hash;
  guarantees: {
    exclusive_hold: boolean;
    action_consume: boolean;
    authoritative_lookup: boolean;
    conditional_inverse: boolean;
    writer_fence: boolean;
    bound_local_run: boolean;
    embedded_policy: boolean;
  };
}

export type PortResult<T> = { status: "KNOWN"; value: T } | { status: "UNKNOWN" };

export interface OperationRequest {
  action_hash: Hash;
  operation_key: string;
}

export interface EffectRequest extends OperationRequest {
  action: Action;
  plan: UndoPlan;
  policy: Evidence;
  fence: U;
}

export interface Ports {
  "bedrock.evaluate": { input: { action: Action; purpose: Purpose; now: Time }; output: Evidence };
  "mint.reserve": { input: OperationRequest & { terms: Terms }; output: PortResult<Evidence> };
  "mint.encumber": {
    input: OperationRequest & { hold_id: ExternalId; expected_revision: U };
    output: PortResult<Evidence>;
  };
  "mint.settle": {
    input: OperationRequest & {
      hold_id: ExternalId;
      expected_revision: U;
      disposition: "RELEASE" | "PAY";
      trigger_hash: Hash;
    };
    output: PortResult<Evidence>;
  };
  "mint.lookup": { input: OperationRequest; output: PortResult<Evidence> };
  "vekrevert.plan": { input: { action: Action }; output: UndoPlan };
  "vekrevert.apply": {
    input: EffectRequest & { created_version: ExternalId; created_value_hash: Hash };
    output: PortResult<Evidence>;
  };
  "vekrevert.lookup": { input: OperationRequest; output: PortResult<Evidence> };
  "trellis.observe": { input: { action_id: ActionId; run_id: ExternalId }; output: Evidence };
  "trellis.stop": {
    input: { action_id: ActionId; run_id: ExternalId; operation_key: string };
    output: PortResult<Evidence>;
  };
  "trellis.certificate": {
    input: { action_id: ActionId; run_id: ExternalId };
    output: PortResult<Evidence>;
  };
  "executor.create": { input: EffectRequest; output: PortResult<Evidence> };
  "executor.lookup": { input: OperationRequest; output: PortResult<Evidence> };
}

export type PortName = keyof Ports;

export interface AdapterConfig {
  id: "bedrock" | "mint" | "vekrevert" | "trellis" | "executor";
  mode: "fixture" | "installed";
  build_hash: Hash;
  binding: string;
}

export interface Config {
  schema: "bond.config/1";
  profile: Profile;
  tenant_id: TenantId;
  scope_id: ScopeId;
  principal_id: PrincipalId;
  data_dir: string;
  trust_file: string;
  signing_key_ref: string;
  clock_max_uncertainty_ms: 1000;
  run_freshness_ms: 250;
  dependency_timeout_ms: 5000;
  max_pending_actions: 100;
  max_package_bytes: 8388608;
  insurance_mode: "paper-required";
  scope_binding: {
    bedrock_principal: ExternalId;
    bedrock_scope: ExternalId;
    mint_owner: ExternalId;
    mint_beneficiary: ExternalId;
  };
  adapters: AdapterConfig[];
  hosting: { enabled: false } | { enabled: true; origin: string; credential_key_ref: string };
}

export type TrustRole = "receipt" | "entry" | "paper" | "assertion" | "notice" | "http" | "draft-store";

export interface TrustKey {
  key_id: KeyId;
  public_key_hex: Hash;
  roles: TrustRole[];
  assertion_kinds: AssertionKind[];
  source_profiles: SourceProfile[];
  tenant_id: TenantId;
  not_before: Time;
  not_after: Time;
  compromised_at: Time | null;
}

export interface TrustFile {
  schema: "bond.trust/1";
  keys: TrustKey[];
  allowed_adapter_builds: Hash[];
  expected_heads: { receipt_id: ReceiptId; head: Head }[];
}

export interface MigrationFile {
  schema: "bond.migration/1";
  from_storage: 1;
  to_storage: 2;
  source_checkpoint: Hash;
  tool_build: Hash;
  backup_digest: Hash;
  mode: "COPY_AND_VERIFY";
}

export type Calls = {
  doctor: { input: Record<string, never>; output: Doctor };
  prepare: { input: Prepare; output: View };
  execute: { input: Mutation; output: View };
  cancel: { input: Mutation; output: View };
  accept: { input: Mutation; output: View };
  reject: {
    input: Mutation & { reason: "OPERATOR_REJECTED" | "VALIDATION_FAILED" };
    output: View;
  };
  stop: { input: { request_id: RequestId; action_id: ActionId | null }; output: View | { scope_stopped: true } };
  reconcile: { input: Mutation; output: View };
  inspect: { input: { action_id: ActionId }; output: View };
  attach: {
    input: Mutation & { artifact: Blob; purpose: "GROUND_ADVISORY" | "WORLD_LINEAGE" };
    output: View;
  };
  export: { input: { action_id: ActionId; through_revision: U; include_bytes: boolean }; output: Package };
  verify: { input: { package: Package; expected_head: Head | null }; output: Verification };
};
