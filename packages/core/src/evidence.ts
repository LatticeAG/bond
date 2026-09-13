/**
 * Evidence verification and construction (§3.3, §3.5). An evidence artifact is
 * a signed Assertion whose `source` ref pins the native source bytes. The
 * supported source profiles in OSS are `fixture/1` (source bytes = J(facts))
 * and `bond.draft-store/1` (source bytes = J(Signed<DraftStoreRecord>) under
 * the draft-store domain). Native upstream profiles require an installed
 * profile verifier; without one the result is UNSUPPORTED_COMPOSITION.
 */

import { BondError } from "./errors.js";
import { H, J, deepEqual, parseJsonBytes, PACKAGE_LIMITS } from "./canon.js";
import { vAssertion, vDraftStoreRecord, vSigned, vBlob } from "./schema.js";
import { verifySigned, Signer, signObject } from "./sign.js";
import * as T from "./types.js";

export interface VerifiedEvidence {
  assertion: T.Signed<T.Assertion>;
  facts: T.Facts;
  sourceBytes: Buffer;
  /** ArtifactRef of the assertion blob (what event data references). */
  evidenceRef: T.ArtifactRef;
  /** Canonical assertion blob stored in objects/packages. */
  evidenceBlob: T.Blob;
}

export type BlobStore = Map<string, Buffer>;

export function blobOf(bytes: Buffer, mediaType: T.ArtifactRef["media_type"]): T.Blob {
  return {
    hash: H(bytes),
    bytes: bytes.length,
    media_type: mediaType,
    data: Buffer.from(bytes).toString("base64url"),
  };
}

export function refOf(b: T.Blob | { hash: string; bytes: number; media_type: string }): T.ArtifactRef {
  return { hash: b.hash, bytes: b.bytes, media_type: b.media_type as T.ArtifactRef["media_type"] };
}

export function jsonBlob(x: unknown): T.Blob {
  return blobOf(Buffer.from(J(x), "utf8"), "application/json");
}

/** Native source-profile verifier installed by an adapter. */
export type SourceVerifier = (
  facts: T.Facts,
  sourceBytes: Buffer,
  assertion: T.Assertion,
  trust: T.TrustFile,
  tenantId: string,
) => void;

export interface VerifyOptions {
  sourceVerifiers?: Partial<Record<T.SourceProfile, SourceVerifier>>;
}

/**
 * Verify the native source bytes against the asserted facts. `fixture/1`
 * requires bytes === J(facts); `bond.draft-store/1` requires a signed
 * DraftStoreRecord whose facts equal the asserted facts.
 */
export function verifySource(
  facts: T.Facts,
  assertion: T.Assertion,
  sourceBytes: Buffer,
  trust: T.TrustFile,
  tenantId: string,
  opts: VerifyOptions = {},
): void {
  switch (assertion.source_profile) {
    case "fixture/1":
      if (J(facts) !== sourceBytes.toString("utf8")) {
        throw new BondError("PROJECTION_INVALID", "fixture source does not match facts");
      }
      return;
    case "bond.draft-store/1": {
      const parsed = vSigned(parseJsonBytes(sourceBytes, PACKAGE_LIMITS), "draft-store", vDraftStoreRecord);
      verifySigned("draft-store", parsed, trust, tenantId);
      if (parsed.body.action_hash !== assertion.action_hash ||
        !deepEqual(parsed.body.facts, facts)) {
        throw new BondError("PROJECTION_INVALID", "draft-store record does not match assertion");
      }
      return;
    }
    default: {
      const v = opts.sourceVerifiers?.[assertion.source_profile];
      if (!v) {
        throw new BondError(
          "UNSUPPORTED_COMPOSITION",
          `no verifier installed for source profile ${assertion.source_profile}`,
        );
      }
      v(facts, sourceBytes, assertion, trust, tenantId);
    }
  }
}

/**
 * Full evidence verification against an action hash and a blob store.
 * Returns the verified evidence, including the canonical assertion blob ref
 * that entries must reference.
 */
export function verifyEvidence(
  signedAssertion: T.Signed<T.Assertion>,
  sourceBlob: T.Blob,
  trust: T.TrustFile,
  tenantId: string,
  expectedActionHash: string,
  opts: VerifyOptions = {},
): VerifiedEvidence {
  verifySigned("assertion", signedAssertion, trust, tenantId);
  if (signedAssertion.body.action_hash !== expectedActionHash) {
    throw new BondError("PROJECTION_INVALID", "assertion bound to different action");
  }
  const sourceBytes = Buffer.from(sourceBlob.data ?? "", "base64url");
  if (sourceBlob.data === null || H(sourceBytes) !== signedAssertion.body.source.hash ||
    sourceBytes.length !== signedAssertion.body.source.bytes) {
    throw new BondError("HASH_MISMATCH", "evidence source bytes");
  }
  verifySource(signedAssertion.body.facts, signedAssertion.body, sourceBytes, trust, tenantId, opts);
  const evidenceBlob = jsonBlob(signedAssertion);
  return {
    assertion: signedAssertion,
    facts: signedAssertion.body.facts,
    sourceBytes,
    evidenceRef: refOf(evidenceBlob),
    evidenceBlob,
  };
}

/**
 * Construct simulation evidence (fixture/1): source bytes are J(facts), the
 * assertion is signed under the "assertion" domain.
 */
export function makeFixtureEvidence(
  facts: T.Facts,
  actionHash: string,
  observedAt: string,
  keyId: string,
  signer: Signer,
): T.Evidence {
  const source = jsonBlob(facts);
  const assertion = signObject("assertion", {
    schema: "bond.assertion/1",
    action_hash: actionHash,
    observed_at: observedAt,
    source_profile: "fixture/1",
    source: refOf(source),
    facts,
  } as T.Assertion, keyId, signer);
  return { assertion, source };
}

/**
 * Construct an installed draft-store observation: the source is a Signed
 * DraftStoreRecord under the "draft-store" domain; the assertion carries
 * source_profile bond.draft-store/1.
 */
export function makeDraftStoreEvidence(
  record: Omit<T.DraftStoreRecord, "schema">,
  storeKeyId: string,
  storeSigner: Signer,
  assertionKeyId: string,
  assertionSigner: Signer,
): T.Evidence {
  const signedRecord = signObject("draft-store", {
    schema: "bond.draft-store/1",
    ...record,
  } as T.DraftStoreRecord, storeKeyId, storeSigner);
  const source = jsonBlob(signedRecord);
  const assertion = signObject("assertion", {
    schema: "bond.assertion/1",
    action_hash: record.action_hash,
    observed_at: record.observed_at,
    source_profile: "bond.draft-store/1",
    source: refOf(source),
    facts: record.facts,
  } as T.Assertion, assertionKeyId, assertionSigner);
  return { assertion, source };
}

/** Parse + validate a signed assertion from stored/package bytes. */
export function parseAssertionBlob(bytes: Buffer): T.Signed<T.Assertion> {
  return vSigned(parseJsonBytes(bytes, PACKAGE_LIMITS), "assertion", vAssertion);
}

export function parseBlob(b: T.Blob): Buffer {
  if (b.data === null) throw new BondError("INCOMPLETE", "blob bytes absent");
  const raw = Buffer.from(b.data, "base64url");
  if (raw.length !== b.bytes || H(raw) !== b.hash) {
    throw new BondError("HASH_MISMATCH", "blob content");
  }
  return raw;
}

export { vBlob };
