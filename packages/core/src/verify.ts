/**
 * Offline certificate-package verification (§6.3). Verification order:
 * resource bounds → parse/schema → key-role pins → object digests/signatures
 * → hash linkage → binding integrity → evidence validation → receipt
 * recomputation → anchoring → completeness.
 */

import { BondError, Head } from "./errors.js";
import { H, J, ZERO_HASH, deepEqual, parseJsonBytes, PACKAGE_LIMITS } from "./canon.js";
import {
  vSigned, vEntryBody, vReceiptBody, vAction, vUndoPlan, vPaperReview,
  checkPaperConsistency, vAssertion, vBlob,
} from "./schema.js";
import { verifySigned } from "./sign.js";
import { parseBlob, VerifyOptions, verifySource } from "./evidence.js";
import {
  RState, applyEntry, toView, ReducerEnv, MissingEvidence, residualEffect,
  remedyState, assemblyOf,
} from "./reducer.js";
import * as T from "./types.js";

const TRUTH = "ISSUER_ASSERTIONS_NOT_REAL_WORLD_PROOF";

function result(
  integrity: "VALID" | "INVALID",
  completeness: "COMPLETE" | "INCOMPLETE",
  currentness: "PINNED_PREFIX" | "UNANCHORED_PREFIX",
  head: Head | null,
  errors: string[],
): T.Verification {
  return {
    integrity, completeness, currentness,
    simulation: true, insurance: "PAPER_ONLY", truth: TRUTH, head, errors,
  };
}

/** Verify a certificate package offline. Never trusts issuer claims. */
export function verifyPackage(
  pkgBytes: Buffer,
  trust: T.TrustFile,
  expectedHead: Head | null,
  opts: VerifyOptions = {},
): T.Verification {
  const errors: string[] = [];
  try {
    if (pkgBytes.length > PACKAGE_LIMITS.maxBytes) throw new BondError("LIMIT", "package bytes");
    const pkgRaw = parseJsonBytes(pkgBytes, PACKAGE_LIMITS);
    if (typeof pkgRaw !== "object" || pkgRaw === null || Array.isArray(pkgRaw)) {
      throw new BondError("SCHEMA");
    }
    const o = pkgRaw as Record<string, unknown>;
    if (o.schema !== "bond.package/1") throw new BondError("UNSUPPORTED_VERSION");
    if (!Array.isArray(o.receipts) || !Array.isArray(o.entries) || !Array.isArray(o.blobs)) {
      throw new BondError("SCHEMA");
    }
    if (o.entries.length === 0) throw new BondError("SCHEMA", "empty package");
    if (o.entries.length > PACKAGE_LIMITS.maxEntries ||
      o.receipts.length > PACKAGE_LIMITS.maxReceipts ||
      o.blobs.length > PACKAGE_LIMITS.maxBlobs) {
      throw new BondError("LIMIT", "package member counts");
    }

    // Parse + validate all objects (closed schemas).
    const entries = o.entries.map((e) => vSigned(e, "entry", vEntryBody));
    const receipts = o.receipts.map((r) => vSigned(r, "receipt", vReceiptBody));
    const blobs = new Map<string, T.Blob>();
    for (const bRaw of o.blobs) {
      const b = vBlob(bRaw);
      if (b.data !== null && b.bytes > PACKAGE_LIMITS.maxBlobBytes) {
        throw new BondError("LIMIT", "blob bytes");
      }
      if (blobs.has(b.hash)) throw new BondError("SCHEMA", "duplicate blob");
      blobs.set(b.hash, b);
    }

    const b0 = entries[0]!.body;
    const tenantId = b0.tenant_id;
    const actionId = b0.action_id;
    const actionHash = b0.action_hash;

    // Signatures + hash linkage.
    let prevEntryHash = ZERO_HASH;
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i]!;
      verifySigned("entry", e, trust, tenantId);
      const eb = e.body;
      if (eb.seq !== i + 1 || eb.previous_hash !== prevEntryHash ||
        eb.tenant_id !== tenantId || eb.action_id !== actionId || eb.action_hash !== actionHash) {
        throw new BondError("CHAIN_INVALID", "entry linkage");
      }
      prevEntryHash = e.hash;
    }
    if (receipts.length !== entries.length) {
      throw new BondError("PROJECTION_INVALID", "receipts do not cover entries");
    }
    let prevReceiptHash: string | null = null;
    for (let i = 0; i < receipts.length; i++) {
      const r = receipts[i]!;
      verifySigned("receipt", r, trust, tenantId);
      const rb = r.body;
      if (rb.revision !== i + 1 || rb.previous_receipt_hash !== prevReceiptHash ||
        rb.tenant_id !== tenantId || rb.action_id !== actionId || rb.action_hash !== actionHash ||
        rb.receipt_id !== receipts[0]!.body.receipt_id ||
        rb.head.seq !== i + 1 || rb.head.hash !== entries[i]!.hash) {
        throw new BondError("CHAIN_INVALID", "receipt linkage");
      }
      prevReceiptHash = r.hash;
    }
    const receiptId = receipts[0]!.body.receipt_id;
    const binding = receipts[0]!.body.binding;
    for (const r of receipts) {
      if (!deepEqual(r.body.binding, binding)) {
        throw new BondError("PROJECTION_INVALID", "binding changed mid-chain");
      }
    }

    // Binding integrity: resolve action/plan/paper blobs.
    let incomplete = false;
    const getBlob = (ref: T.ArtifactRef): T.Blob | null => {
      const b = blobs.get(ref.hash);
      if (!b || b.data === null || b.bytes !== ref.bytes || b.media_type !== ref.media_type) {
        return null;
      }
      return b;
    };
    const actionBlob = getBlob(binding.action);
    const planBlob = getBlob(binding.plan);
    const paperBlob = getBlob(binding.paper);
    if (!actionBlob || !planBlob || !paperBlob) {
      incomplete = true;
    }
    let action: T.Action | null = null;
    let plan: T.UndoPlan | null = null;
    if (actionBlob && planBlob) {
      action = vAction(parseJsonBytes(parseBlob(actionBlob), PACKAGE_LIMITS));
      plan = vUndoPlan(parseJsonBytes(parseBlob(planBlob), PACKAGE_LIMITS));
      if (action.action_id !== actionId || action.tenant_id !== tenantId ||
        action.execute_before !== undefined && false) {
        throw new BondError("PROJECTION_INVALID", "action binding mismatch");
      }
      if (plan.action_hash !== actionHash || plan.resource !== action.resource ||
        plan.adapter_build !== action.adapter_build ||
        plan.value_hash !== H(J(action.draft)) ||
        plan.expires_at !== action.terms.long_stop) {
        throw new BondError("PROJECTION_INVALID", "plan binding mismatch");
      }
    }
    if (paperBlob && action) {
      const paper = vSigned(parseJsonBytes(parseBlob(paperBlob), PACKAGE_LIMITS), "paper", vPaperReview);
      verifySigned("paper", paper, trust, tenantId);
      checkPaperConsistency(paper.body, action);
    }

    // Evidence validation + replay.
    const evCache = new Map<string, { facts: T.Facts; evidenceHash: string }>();
    const resolveEvidence = (ref: T.ArtifactRef): { facts: T.Facts; evidenceHash: string } | null => {
      const cached = evCache.get(ref.hash);
      if (cached) return cached;
      const blob = blobs.get(ref.hash);
      if (!blob || blob.data === null) return null;
      let bytes: Buffer;
      try {
        bytes = parseBlob(blob);
      } catch {
        throw new BondError("HASH_MISMATCH", "evidence blob");
      }
      const assertion = vSigned(parseJsonBytes(bytes, PACKAGE_LIMITS), "assertion", vAssertion);
      verifySigned("assertion", assertion, trust, tenantId);
      if (assertion.body.action_hash !== actionHash) {
        throw new BondError("PROJECTION_INVALID", "assertion action binding");
      }
      const srcBlob = blobs.get(assertion.body.source.hash);
      if (!srcBlob || srcBlob.data === null) {
        return null; // source bytes missing: incomplete
      }
      const srcBytes = parseBlob(srcBlob);
      verifySource(assertion.body.facts, assertion.body, srcBytes, trust, tenantId, opts);
      const out = { facts: assertion.body.facts, evidenceHash: ref.hash };
      evCache.set(ref.hash, out);
      return out;
    };

    const env: ReducerEnv | null = action && plan
      ? { action, plan, binding, resolve: resolveEvidence }
      : null;

    let st: RState | null = null;
    let replayOk = env !== null;
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i]!;
      if (env === null) break;
      try {
        const r = applyEntry(st, entry.body, entry.hash, env, "verify");
        st = r.state;
      } catch (e) {
        if (e instanceof MissingEvidence) {
          incomplete = true;
          replayOk = false;
          break;
        }
        throw e;
      }
      st.receiptId = receiptId;
      const rb = receipts[i]!.body;
      const derived = toView(st);
      if (!deepEqual(derived, rb.view)) {
        throw new BondError("PROJECTION_INVALID", `view mismatch at revision ${i + 1}`);
      }
      const derivedEvidence = st.evidenceRefs;
      if (!deepEqual(derivedEvidence, rb.evidence)) {
        throw new BondError("PROJECTION_INVALID", `evidence list mismatch at revision ${i + 1}`);
      }
      if (residualEffect(st) !== rb.residual_effect || remedyState(st) !== rb.remedy) {
        throw new BondError("PROJECTION_INVALID", `residual/remedy mismatch at revision ${i + 1}`);
      }
      if (assemblyOf(st, true) !== rb.assembly) {
        throw new BondError("PROJECTION_INVALID", `assembly mismatch at revision ${i + 1}`);
      }
    }
    if (!replayOk || incomplete) {
      if (incomplete && !errors.includes("INCOMPLETE")) errors.push("INCOMPLETE");
    }

    // Anchoring: a non-null expected head must equal the verified head
    // exactly; otherwise the pin fails closed with CHAIN_INVALID.
    const head: Head = {
      seq: entries[entries.length - 1]!.body.seq,
      hash: entries[entries.length - 1]!.hash,
    };
    let currentness: "PINNED_PREFIX" | "UNANCHORED_PREFIX" = "UNANCHORED_PREFIX";
    if (expectedHead !== null) {
      if (head === null || expectedHead.seq !== head.seq || expectedHead.hash !== head.hash) {
        throw new BondError("CHAIN_INVALID", "expected head does not anchor this prefix");
      }
      currentness = "PINNED_PREFIX";
    }

    const completeness: "COMPLETE" | "INCOMPLETE" =
      !incomplete && st !== null && assemblyOf(st, true) === "COMPLETE" &&
        receipts[receipts.length - 1]!.body.assembly === "COMPLETE"
        ? "COMPLETE"
        : "INCOMPLETE";

    return result("VALID", completeness, currentness, head, errors);
  } catch (e) {
    if (e instanceof BondError) {
      return result("INVALID", "INCOMPLETE", "UNANCHORED_PREFIX", null, [e.code]);
    }
    throw e;
  }
}
