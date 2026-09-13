/**
 * Canonicalization, strict JSON parsing, hashing — BOND_SPEC §3.1, §3.5.
 *
 * J(x) is RFC 8785 canonical JSON restricted to this spec's value subset
 * (null, boolean, nonnegative safe integers, strings, arrays, objects with
 * keys sorted in UTF-16 code-unit order). H is lowercase SHA-256 hex.
 * D(kind,x) = H(UTF8("LAGI-BOND/"+kind+"/1\n") || J(x)).
 */

import { createHash, randomBytes } from "node:crypto";
import { BondError } from "./errors.js";

export const ZERO_HASH = "0".repeat(64);
export const MAX_SAFE_U = 9007199254740991;
export const MAX_AMOUNT = 9223372036854775807n;

export const DOMAIN_KINDS = [
  "action", "plan", "entry", "receipt", "paper",
  "assertion", "request", "notice", "draft-store",
] as const;
export type DomainKind = (typeof DOMAIN_KINDS)[number];

/** RFC 8785 canonical JSON for the spec subset. Throws BondError("SCHEMA"). */
export function J(x: unknown): string {
  if (x === null) return "null";
  if (typeof x === "string") {
    // Reject lone surrogates: they cannot encode to the UTF-8 signed bytes.
    if (/[\ud800-\udfff]/.test(x)) throw new BondError("SCHEMA", "lone surrogate");
    return JSON.stringify(x);
  }
  if (typeof x === "boolean") return x ? "true" : "false";
  if (typeof x === "number") {
    if (!Number.isSafeInteger(x) || x < 0 || Object.is(x, -0)) {
      throw new BondError("SCHEMA", "number outside nonnegative safe-integer subset");
    }
    return String(x);
  }
  if (typeof x === "bigint") {
    if (x < 0n || x > BigInt(MAX_SAFE_U)) throw new BondError("SCHEMA", "bigint out of range");
    return x.toString();
  }
  if (Array.isArray(x)) return "[" + x.map(J).join(",") + "]";
  if (typeof x === "object") {
    const o = x as Record<string, unknown>;
    const keys = Object.keys(o).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + J(o[k])).join(",") + "}";
  }
  throw new BondError("SCHEMA", "unsupported value in canonical JSON");
}

export function JBytes(x: unknown): Buffer {
  return Buffer.from(J(x), "utf8");
}

export function H(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

export function D(kind: DomainKind, x: unknown): string {
  return H("LAGI-BOND/" + kind + "/1\n" + J(x));
}

export function deepEqual(a: unknown, b: unknown): boolean {
  return J(a) === J(b);
}

// ---------------------------------------------------------------------------
// Strict JSON parser. Rejects: invalid UTF-8, BOM, trailing data, duplicate
// keys, non-integer/exponent/negative numeric tokens, integers above
// 2^53-1, unpaired surrogates, non-NFC text, and resource-limit overflows.
// ---------------------------------------------------------------------------

export interface ParseLimits {
  maxBytes: number;
  maxDepth: number;
  maxMembers: number;
}

export const CONTROL_LIMITS: ParseLimits = { maxBytes: 65536, maxDepth: 16, maxMembers: 1024 };
export const PACKAGE_LIMITS = {
  maxBytes: 8388608,
  maxEntries: 256,
  maxReceipts: 256,
  maxBlobs: 64,
  maxBlobBytes: 2097152,
  maxDepth: 16,
  maxMembers: 1024,
};

const WS = new Set([0x20, 0x09, 0x0a, 0x0d]);

class Parser {
  pos = 0;
  members = 0;
  constructor(readonly text: string, readonly lim: ParseLimits) {}

  fail(msg = "invalid JSON"): never {
    throw new BondError("SCHEMA", msg);
  }

  ws(): void {
    while (this.pos < this.text.length && WS.has(this.text.charCodeAt(this.pos))) this.pos++;
  }

  parse(): unknown {
    this.ws();
    const v = this.value(0);
    this.ws();
    if (this.pos !== this.text.length) this.fail("trailing data");
    return v;
  }

  value(depth: number): unknown {
    if (depth > this.lim.maxDepth) throw new BondError("LIMIT", "depth exceeded");
    const c = this.text[this.pos];
    if (c === "{") return this.object(depth);
    if (c === "[") return this.array(depth);
    if (c === '"') return this.string();
    if (c === "t") return this.literal("true", true);
    if (c === "f") return this.literal("false", false);
    if (c === "n") return this.literal("null", null);
    return this.number();
  }

  literal(s: string, v: unknown): unknown {
    if (this.text.startsWith(s, this.pos)) {
      this.pos += s.length;
      return v;
    }
    this.fail();
  }

  number(): number {
    const start = this.pos;
    const t = this.text;
    if (t[this.pos] === "0") {
      this.pos++;
    } else if (t[this.pos]! >= "1" && t[this.pos]! <= "9") {
      while (this.pos < t.length && t[this.pos]! >= "0" && t[this.pos]! <= "9") this.pos++;
    } else {
      this.fail("invalid number token");
    }
    const c = t[this.pos];
    if (c === "." || c === "e" || c === "E" || c === "+" || c === "-") {
      this.fail("non-integer numeric token");
    }
    const tok = t.slice(start, this.pos);
    const n = Number(tok);
    if (!Number.isSafeInteger(n) || n < 0 || n > MAX_SAFE_U) this.fail("integer out of range");
    return n;
  }

  string(): string {
    const t = this.text;
    this.pos++;
    let out = "";
    for (;;) {
      if (this.pos >= t.length) this.fail("unterminated string");
      const c = t.charCodeAt(this.pos);
      if (c === 0x22) {
        this.pos++;
        return out;
      }
      if (c === 0x5c) {
        this.pos++;
        const e = t[this.pos];
        this.pos++;
        switch (e) {
          case '"': out += '"'; break;
          case "\\": out += "\\"; break;
          case "/": out += "/"; break;
          case "b": out += "\b"; break;
          case "f": out += "\f"; break;
          case "n": out += "\n"; break;
          case "r": out += "\r"; break;
          case "t": out += "\t"; break;
          case "u": {
            const hex = t.slice(this.pos, this.pos + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail("bad \\u escape");
            this.pos += 4;
            let cp = parseInt(hex, 16);
            if (cp >= 0xd800 && cp <= 0xdbff) {
              const hi = cp;
              if (t.slice(this.pos, this.pos + 2) !== "\\u") this.fail("unpaired surrogate");
              const hex2 = t.slice(this.pos + 2, this.pos + 6);
              if (!/^[0-9a-fA-F]{4}$/.test(hex2)) this.fail("bad \\u escape");
              const lo = parseInt(hex2, 16);
              if (lo < 0xdc00 || lo > 0xdfff) this.fail("unpaired surrogate");
              this.pos += 6;
              cp = 0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00);
              out += String.fromCodePoint(cp);
            } else if (cp >= 0xdc00 && cp <= 0xdfff) {
              this.fail("unpaired surrogate");
            } else {
              out += String.fromCharCode(cp);
            }
            break;
          }
          default: this.fail("bad escape");
        }
      } else {
        if (c < 0x20) this.fail("unescaped control character");
        out += t[this.pos];
        this.pos++;
      }
    }
  }

  object(depth: number): Record<string, unknown> {
    const t = this.text;
    this.pos++;
    this.ws();
    const o: Record<string, unknown> = {};
    if (t[this.pos] === "}") {
      this.pos++;
      return o;
    }
    for (;;) {
      this.ws();
      if (t[this.pos] !== '"') this.fail("expected object key");
      const k = this.string();
      if (++this.members > this.lim.maxMembers) throw new BondError("LIMIT", "member count exceeded");
      if (Object.prototype.hasOwnProperty.call(o, k)) this.fail("duplicate key");
      this.ws();
      if (t[this.pos] !== ":") this.fail("expected ':'");
      this.pos++;
      this.ws();
      o[k] = this.value(depth + 1);
      this.ws();
      const c = t[this.pos];
      if (c === ",") {
        this.pos++;
        continue;
      }
      if (c === "}") {
        this.pos++;
        return o;
      }
      this.fail("expected ',' or '}'");
    }
  }

  array(depth: number): unknown[] {
    const t = this.text;
    this.pos++;
    this.ws();
    const a: unknown[] = [];
    if (t[this.pos] === "]") {
      this.pos++;
      return a;
    }
    for (;;) {
      a.push(this.value(depth + 1));
      this.ws();
      const c = t[this.pos];
      if (c === ",") {
        this.pos++;
        this.ws();
        continue;
      }
      if (c === "]") {
        this.pos++;
        return a;
      }
      this.fail("expected ',' or ']'");
    }
  }
}

/** Strict JSON parse. Input must be raw UTF-8 bytes. */
export function parseJsonBytes(data: Buffer | Uint8Array, lim: ParseLimits = CONTROL_LIMITS): unknown {
  if (data.length > lim.maxBytes) throw new BondError("LIMIT", "input exceeds byte bound");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(data);
  } catch {
    throw new BondError("SCHEMA", "invalid UTF-8");
  }
  if (text.length === 0) throw new BondError("SCHEMA", "empty input");
  if (text.charCodeAt(0) === 0xfeff) throw new BondError("SCHEMA", "BOM not allowed");
  if (text !== text.normalize("NFC")) throw new BondError("SCHEMA", "input not NFC");
  return new Parser(text, lim).parse();
}

/** Strict JSON parse of a JS string (already decoded). */
export function parseJson(text: string, lim: ParseLimits = CONTROL_LIMITS): unknown {
  return parseJsonBytes(Buffer.from(text, "utf8"), lim);
}

// ---------------------------------------------------------------------------
// Canonical base64url (unpadded), verified by decode/re-encode equality.
// ---------------------------------------------------------------------------

export function b64uEncode(data: Buffer | Uint8Array): string {
  return Buffer.from(data).toString("base64url");
}

export function b64uDecode(s: string): Buffer {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) {
    throw new BondError("SCHEMA", "noncanonical base64url");
  }
  const b = Buffer.from(s, "base64url");
  if (b.toString("base64url") !== s) throw new BondError("SCHEMA", "noncanonical base64url");
  return b;
}

export function isB64u(s: unknown): s is string {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return false;
  try {
    return Buffer.from(s, "base64url").toString("base64url") === s;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Time: valid UTC YYYY-MM-DDTHH:mm:ss.sssZ — no offsets, no leap seconds.
// ---------------------------------------------------------------------------

const TIME_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z$/;

export function isTime(x: unknown): x is string {
  if (typeof x !== "string") return false;
  const m = TIME_RE.exec(x);
  if (!m) return false;
  const ms = Date.parse(x);
  return Number.isFinite(ms);
}

export function timeMs(t: string): number {
  const ms = Date.parse(t);
  if (!Number.isFinite(ms)) throw new BondError("SCHEMA", "invalid time");
  return ms;
}

export function fromMs(ms: number): string {
  return new Date(ms).toISOString();
}

export function isAmount(x: unknown): x is string {
  return typeof x === "string" && /^(0|[1-9][0-9]*)$/.test(x) && BigInt(x) <= MAX_AMOUNT;
}

export function amountLe(a: string, b: string): boolean {
  return BigInt(a) <= BigInt(b);
}

export function isHash(x: unknown): x is string {
  return typeof x === "string" && /^[0-9a-f]{64}$/.test(x);
}

export function isU(x: unknown): x is number {
  return typeof x === "number" && Number.isSafeInteger(x) && x >= 0;
}

export function isExternalId(x: unknown): x is string {
  return typeof x === "string" && /^[A-Za-z0-9:_-]{1,96}$/.test(x);
}

export function isResourceSegment(seg: string): boolean {
  return /^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$/.test(seg) && seg !== "." && seg !== ".."
    && !seg.includes("%") && !seg.includes("\\");
}

// ---------------------------------------------------------------------------
// Bond IDs: nanoid locked alphabet, 21 random suffix chars, fixed prefixes.
// ---------------------------------------------------------------------------

export const ID_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz-";
export const ID_PREFIXES = ["bnt", "bns", "bnp", "bac", "brc", "bnq", "bnk", "bni", "bnj"] as const;
export type IdPrefix = (typeof ID_PREFIXES)[number];

const ID_RE = /^[A-Za-z0-9_-]{21}$/;

export function newId(prefix: IdPrefix): string {
  const bytes = randomBytes(21);
  let suffix = "";
  for (let i = 0; i < 21; i++) suffix += ID_ALPHABET[bytes[i]! & 63];
  return prefix + "_" + suffix;
}

export function isBondId(x: unknown, prefix: IdPrefix): x is string {
  return typeof x === "string" && x.startsWith(prefix + "_") && ID_RE.test(x.slice(prefix.length + 1));
}

export function isBindingName(x: unknown): x is string {
  return typeof x === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(x);
}

export function asciiHashCmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
