/**
 * Native adapter bindings — fail-closed ports for real upstream dependencies
 * (§6.3). A native adapter activates only with an installed, operator-approved
 * capability manifest whose required guarantees are present and whose mode is
 * VERIFIED_NATIVE backed by a conformance report. Anything else fails with the
 * named capability diagnostic — never a generic fallback.
 */

import { BondError, CapabilityManifest, TrustFile } from "@latticeag/bond-core";

export const DIAGNOSTICS = {
  mint: "MINT_EXCLUSIVE_HOLD_UNAVAILABLE",
  vekrevert: "VEKREVERT_CONDITIONAL_INVERSE_UNAVAILABLE",
  bedrock: "BEDROCK_EMBEDDED_EVALUATOR_UNAVAILABLE",
  trellis: "TRELLIS_BOUND_RUN_UNAVAILABLE",
  executor: "EXECUTOR_FENCE_UNAVAILABLE",
} as const;

export type AdapterId = keyof typeof DIAGNOSTICS;

const REQUIRED: Record<AdapterId, (keyof CapabilityManifest["guarantees"])[]> = {
  mint: ["exclusive_hold", "action_consume", "authoritative_lookup"],
  vekrevert: ["conditional_inverse", "writer_fence", "authoritative_lookup"],
  bedrock: ["embedded_policy"],
  trellis: ["bound_local_run"],
  executor: ["writer_fence", "authoritative_lookup"],
};

const PORT_METHODS: Record<AdapterId, string[]> = {
  bedrock: ["bedrock.evaluate"],
  executor: ["executor.create", "executor.lookup"],
  mint: ["mint.encumber", "mint.lookup", "mint.reserve", "mint.settle"],
  trellis: ["trellis.certificate", "trellis.observe", "trellis.stop"],
  vekrevert: ["vekrevert.apply", "vekrevert.lookup", "vekrevert.plan"],
};

/**
 * Whether an installed manifest satisfies the adapter's required guarantees,
 * has the exact sorted method set, and is a VERIFIED_NATIVE manifest (not a
 * self-declared flag — the caller installs manifests only after checking a
 * conformance report exists).
 */
export function manifestSatisfies(
  adapter: AdapterId,
  m: CapabilityManifest | null,
  conformanceReportsInstalled: Set<string>,
): boolean {
  if (!m || m.adapter !== adapter) return false;
  const want = [...PORT_METHODS[adapter]].sort();
  if (m.methods.length !== want.length || m.methods.some((x, i) => x !== want[i])) return false;
  if (m.mode !== "VERIFIED_NATIVE") return false;
  if (!conformanceReportsInstalled.has(m.conformance_report_hash)) return false;
  return REQUIRED[adapter].every((g) => m.guarantees[g] === true);
}

/** Sorted capability diagnostics for every unsatisfied adapter. */
export function missingCapabilities(
  manifests: Partial<Record<AdapterId, CapabilityManifest | null>>,
  conformanceReportsInstalled: Set<string> = new Set(),
): string[] {
  const missing: string[] = [];
  for (const id of ["bedrock", "executor", "mint", "trellis", "vekrevert"] as const) {
    if (!manifestSatisfies(id, manifests[id] ?? null, conformanceReportsInstalled)) {
      missing.push(DIAGNOSTICS[id]);
    }
  }
  return missing.sort();
}

export class CapabilityUnavailable extends BondError {
  constructor(adapter: AdapterId) {
    super("UNSUPPORTED_COMPOSITION", DIAGNOSTICS[adapter]);
  }
}

/**
 * A native port binding. `transport` is the authenticated upstream call; when
 * the manifest is unsatisfied or no transport is installed, every port call
 * fails closed with the adapter's capability diagnostic.
 */
export class NativeAdapter {
  constructor(
    readonly id: AdapterId,
    private manifest: CapabilityManifest | null,
    private transport: ((port: string, input: unknown) => Promise<unknown>) | null,
    private conformanceReportsInstalled: Set<string>,
  ) {}

  get satisfied(): boolean {
    return manifestSatisfies(this.id, this.manifest, this.conformanceReportsInstalled);
  }

  async call(port: string, input: unknown): Promise<unknown> {
    if (!PORT_METHODS[this.id].includes(port)) {
      throw new BondError("SCHEMA", `port ${port} not bound to adapter ${this.id}`);
    }
    if (!this.satisfied || this.transport === null) throw new CapabilityUnavailable(this.id);
    return this.transport(port, input);
  }
}
