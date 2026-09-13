/** Bond error/result model — the complete Code registry of BOND_SPEC §6.1. */

export const CODES = [
  "SCHEMA", "UNSUPPORTED_VERSION", "UNSUPPORTED_COMPOSITION", "UNAUTHORIZED",
  "FORBIDDEN", "NOT_FOUND", "CONFLICT", "IDEMPOTENCY_CONFLICT", "REVISION_CONFLICT",
  "BAD_STATE", "DEADLINE", "POLICY_DENIED", "PIN_MISMATCH", "INSURANCE_REQUIRED",
  "INSURANCE_SCOPE", "HOLD_BINDING", "HOLD_INSUFFICIENT", "RUN_BINDING", "RUN_STALE",
  "INCOMPLETE", "HASH_MISMATCH", "SIGNATURE_INVALID", "UNTRUSTED_KEY", "CHAIN_INVALID",
  "PROJECTION_INVALID", "SOURCE_FORK", "LIMIT", "BUSY", "STORAGE", "CLOCK_UNSAFE",
] as const;

export type Code = (typeof CODES)[number];

export class BondError extends Error {
  readonly code: Code;
  constructor(code: Code, message?: string) {
    super(message ?? code);
    this.name = "BondError";
    this.code = code;
  }
}

export function isCode(x: unknown): x is Code {
  return typeof x === "string" && (CODES as readonly string[]).includes(x);
}

export interface Head {
  seq: number;
  hash: string;
}

export interface Failure {
  ok: false;
  code: Code;
  retryable: boolean;
  head: Head | null;
}

export interface Success<T> {
  ok: true;
  value: T;
}

export type Result<T> = Success<T> | Failure;

export function ok<T>(value: T): Success<T> {
  return { ok: true, value };
}

export function fail<T = never>(code: Code, head: Head | null = null): Failure {
  return { ok: false, code, retryable: code === "BUSY" || code === "STORAGE", head };
}

export function toFailure(e: unknown, head: Head | null = null): Failure {
  if (e instanceof BondError) return fail(e.code, head);
  if (e instanceof Error) return fail("STORAGE", head);
  return fail("STORAGE", head);
}
