/**
 * Signed-object helpers — signature domains, trust-key pinning (§3.5),
 * and HTTP proof-of-possession auth (§6.4).
 */

import { BondError } from "./errors.js";
import { D, DomainKind, b64uDecode, b64uEncode, timeMs, J } from "./canon.js";
import { signMessage, verifyStrict } from "./ed25519.js";
import * as T from "./types.js";

export type Signer = (message: Uint8Array) => Buffer;

export function seedSigner(seedHex: string): Signer {
  const seed = Buffer.from(seedHex, "hex");
  if (seed.length !== 32) throw new BondError("SCHEMA", "seed must be 32 bytes");
  return (m) => signMessage(seed, m);
}

/** Sign `body` under Bond domain `kind`: hash = D(kind,{body,key_id}). */
export function signObject<K extends DomainKind, B>(
  kind: K,
  body: B,
  keyId: string,
  signer: Signer,
): T.Signed<B> {
  const hash = D(kind, { body, key_id: keyId });
  const sig = b64uEncode(signer(new TextEncoder().encode(`LAGI-BOND/sign/${kind}/1\n${hash}`)));
  return { body, key_id: keyId, hash, sig };
}

/** Signing-time field used for key-validity pinning, per object kind. */
function signedAt(kind: DomainKind | "request", body: unknown): string {
  const b = body as Record<string, unknown>;
  switch (kind) {
    case "entry": return b.recorded_at as string;
    case "receipt": return b.issued_at as string;
    case "paper": return b.reviewed_at as string;
    case "assertion": return b.observed_at as string;
    case "notice": return b.recorded_at as string;
    case "draft-store": return b.observed_at as string;
    case "request": return b.issued_at as string;
    default: throw new BondError("SCHEMA", "unsigned kind " + kind);
  }
}

const KIND_ROLE: Record<string, T.TrustRole> = {
  entry: "entry", receipt: "receipt", paper: "paper", assertion: "assertion",
  notice: "notice", http: "http", "draft-store": "draft-store", request: "http",
};

/**
 * Locate trust keys authorized for (kind-role, tenant, signed-at). Per the
 * normative fixture, `key_id` is a label carried by the signer — selection is
 * by trust pins (role/tenant/validity) and the signature itself is the proof.
 * Throws UNTRUSTED_KEY when no installed key satisfies the pins.
 */
export function trustKeys(
  trust: T.TrustFile,
  kind: DomainKind | "request",
  tenantId: string,
  at: string,
): T.TrustKey[] {
  const role = KIND_ROLE[kind];
  if (role === undefined) throw new BondError("UNTRUSTED_KEY", "no role for kind " + kind);
  let t = NaN;
  try {
    t = timeMs(at);
  } catch { /* absent/invalid signed-at: the time pin cannot exclude */ }
  const tt = t;
  return trust.keys.filter((k) =>
    k.tenant_id === tenantId && k.roles.includes(role) &&
    (Number.isNaN(tt) ||
      (timeMs(k.not_before) <= tt && tt <= timeMs(k.not_after) &&
        (k.compromised_at === null || tt < timeMs(k.compromised_at)))));
}

/**
 * Verify a signed object: key-role pin first (§6.3 verify order), then
 * recomputed hash, then strict Ed25519.
 */
export function verifySigned(
  kind: DomainKind,
  signed: T.Signed<unknown>,
  trust: T.TrustFile,
  tenantId: string,
): void {
  let keys = trustKeys(trust, kind, tenantId, signedAt(kind, signed.body));
  if (kind === "assertion") {
    const a = signed.body as T.Assertion;
    keys = keys.filter((k) =>
      k.assertion_kinds.includes(a.facts.kind) &&
      k.source_profiles.includes(a.source_profile));
  }
  if (keys.length === 0) {
    throw new BondError("UNTRUSTED_KEY", `no trusted key for ${kind}`);
  }
  const expected = D(kind, { body: signed.body, key_id: signed.key_id });
  if (expected !== signed.hash) throw new BondError("HASH_MISMATCH", `${kind} hash`);
  const msg = new TextEncoder().encode(`LAGI-BOND/sign/${kind}/1\n${signed.hash}`);
  const sig = b64uDecode(signed.sig);
  if (!keys.some((k) =>
    verifyStrict(msg, sig, Buffer.from(k.public_key_hex, "hex")))) {
    throw new BondError("SIGNATURE_INVALID", `${kind} signature`);
  }
}

/** HTTP request-domain auth verification (§6.4). */
export function verifyHttpAuth(
  auth: T.HttpAuth,
  trust: T.TrustFile,
  now: string,
): void {
  const unsigned: Record<string, unknown> = { ...auth } as Record<string, unknown>;
  delete unsigned.sig;
  const keys = trustKeys(trust, "request", auth.tenant_id, auth.issued_at);
  const tI = timeMs(auth.issued_at);
  const tE = timeMs(auth.expires_at);
  const tN = timeMs(now);
  if (tI > tN + 60000) throw new BondError("CLOCK_UNSAFE", "issued_at beyond allowed skew");
  if (!(tI < tE && tE <= tI + 300000)) throw new BondError("SCHEMA", "invalid auth window");
  if (tN >= tE) throw new BondError("DEADLINE", "auth expired");
  if (keys.length === 0) throw new BondError("UNTRUSTED_KEY", "no http key");
  const hash = D("request", unsigned);
  const msg = new TextEncoder().encode(`LAGI-BOND/sign/request/1\n${hash}`);
  const sig = b64uDecode(auth.sig);
  if (!keys.some((k) => verifyStrict(msg, sig, Buffer.from(k.public_key_hex, "hex")))) {
    throw new BondError("SIGNATURE_INVALID", "request signature");
  }
}

/** Decode an X-Bond-Authorization header value to raw JSON bytes. */
export function decodeHttpAuth(header: string): Buffer {
  const raw = b64uDecode(header);
  if (raw.length > 8192) throw new BondError("LIMIT", "auth header too large");
  return raw;
}

export function encodeHttpAuth(auth: T.HttpAuth): string {
  return b64uEncode(Buffer.from(J(auth), "utf8"));
}
