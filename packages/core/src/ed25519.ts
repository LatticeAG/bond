/**
 * Ed25519 with the spec's strictness profile (§3.5): reject noncanonical
 * points, small-order public keys/R, S >= L, wrong lengths, and Ed25519ph.
 * The signature equation itself is checked by OpenSSL via node:crypto; the
 * point validation below is a direct BigInt implementation of RFC 8032
 * decoding so the same rules can be mirrored byte-for-byte in Python.
 */

import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify, KeyObject } from "node:crypto";

const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const ED_D = (P - 121665n) * inv(121666n) % P;
const ED_I = powMod(2n, (P - 1n) / 4n, P); // sqrt(-1) mod p

type Point = { x: bigint; y: bigint };
const IDENTITY: Point = { x: 0n, y: 1n };
const BASE: Point = {
  x: 15112221349535400772501151409588531511454012693041857206046113283949847762202n,
  y: 46316835694926478169428394003475163141307993866256225615783033603165251855960n,
};

function inv(a: bigint): bigint {
  return powMod((a % P + P) % P, P - 2n, P);
}

function powMod(a: bigint, e: bigint, m: bigint): bigint {
  a = ((a % m) + m) % m;
  let r = 1n;
  while (e > 0n) {
    if (e & 1n) r = (r * a) % m;
    a = (a * a) % m;
    e >>= 1n;
  }
  return r;
}

function edAdd(a: Point, b: Point): Point {
  const den = inv(1n + ED_D * a.x * b.x * a.y * b.y % P);
  const den2 = inv(1n - ED_D * a.x * b.x * a.y * b.y % P);
  return {
    x: ((a.x * b.y + b.x * a.y) % P) * den % P,
    y: ((a.y * b.y + a.x * b.x) % P) * den2 % P,
  };
}

function edMul(p: Point, n: bigint): Point {
  let r = IDENTITY;
  let q = p;
  while (n > 0n) {
    if (n & 1n) r = edAdd(r, q);
    q = edAdd(q, q);
    n >>= 1n;
  }
  return r;
}

function leInt(b: Uint8Array): bigint {
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]!);
  return n;
}

/**
 * Strict point decoding: canonical field element (y < p), sign-bit rules of
 * RFC 8032 (x=0 with sign=1 invalid). Returns null when undecodable.
 */
export function decodePoint(b: Uint8Array): Point | null {
  if (b.length !== 32) return null;
  const yBytes = Uint8Array.from(b);
  const sign = (yBytes[31]! & 0x80) !== 0;
  yBytes[31]! &= 0x7f;
  const y = leInt(yBytes);
  if (y >= P) return null;
  const yy = (y * y) % P;
  const u = (yy - 1n + P) % P;
  const v = (ED_D * yy + 1n) % P;
  // RFC 8032 recover_x: x = u v^3 (u v^7)^((p-5)/8) mod p
  let x = (u * powMod(v, 3n, P) % P) * powMod((u * powMod(v, 7n, P)) % P, (P - 5n) / 8n, P) % P;
  if ((x * x % P) * v % P !== u) {
    x = (x * ED_I) % P;
    if ((x * x % P) * v % P !== u) return null;
  }
  if (x === 0n && sign) return null;
  if ((x & 1n) !== (sign ? 1n : 0n)) x = P - x;
  return { x, y };
}

/** True when the point lies in the 8-element cofactor subgroup. */
export function isSmallOrder(p: Point): boolean {
  const q = edMul(p, 8n);
  return q.x === 0n && q.y === 1n;
}

/**
 * Strict Ed25519 verify: canonical R/A decodings, no small-order points,
 * S < L, then the OpenSSL signature check. Ed25519ph is never attempted —
 * callers always pass the raw message bytes.
 */
export function verifyStrict(message: Uint8Array, sig: Uint8Array, publicKey: Uint8Array): boolean {
  if (sig.length !== 64 || publicKey.length !== 32) return false;
  const s = leInt(sig.subarray(32, 64));
  if (s >= L) return false;
  const r = decodePoint(sig.subarray(0, 32));
  const a = decodePoint(publicKey);
  if (r === null || a === null) return false;
  if (isSmallOrder(r) || isSmallOrder(a)) return false;
  const jwk = {
    kty: "OKP",
    crv: "Ed25519",
    x: Buffer.from(publicKey).toString("base64url"),
  };
  let pub: KeyObject;
  try {
    pub = createPublicKey({ key: jwk, format: "jwk" });
  } catch {
    return false;
  }
  return nodeVerify(null, Buffer.from(message), pub, Buffer.from(sig));
}

/** Deterministic RFC 8032 signing for Bond-produced objects. */
export function signMessage(privateKeyDerSeed: Buffer, message: Uint8Array): Buffer {
  const key = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), privateKeyDerSeed]),
    format: "der",
    type: "pkcs8",
  });
  return nodeSign(null, Buffer.from(message), key);
}

export function publicKeyHexFromSeed(seedHex: string): string {
  const key = createPrivateKey({
    key: Buffer.from("302e020100300506032b657004220420" + seedHex, "hex"),
    format: "der",
    type: "pkcs8",
  });
  return createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
}
