/**
 * `bond` — command frontend (§6.5). One canonical JSON object + newline in
 * --json mode; diagnostics on stderr. Exit mapping per the fixed table.
 */

import { readFileSync, writeFileSync, openSync, closeSync, constants } from "node:fs";
import {
  Blob, BondError, Code, D, Head, J, Result, View,
  b64uEncode, isBondId, parseJsonBytes, signObject, vAction,
  vNotice, vPaperReview, vSigned, verifyPackage,
  CONTROL_LIMITS, PACKAGE_LIMITS, H, HttpAuth, encodeHttpAuth,
} from "@latticeag/bond-core";
import { envSecrets, loadConfigFile, loadTrustFile } from "@latticeag/bond-sdk";
import { ensureActivePin, wireClient } from "./wire.js";

const EX3 = new Set<Code>([
  "UNAUTHORIZED", "FORBIDDEN", "UNTRUSTED_KEY", "SIGNATURE_INVALID",
  "POLICY_DENIED", "INSURANCE_REQUIRED", "INSURANCE_SCOPE",
]);
const EX4 = new Set<Code>([
  "CONFLICT", "REVISION_CONFLICT", "IDEMPOTENCY_CONFLICT", "DEADLINE",
  "NOT_FOUND", "LIMIT", "BAD_STATE", "PIN_MISMATCH", "UNSUPPORTED_COMPOSITION",
]);
const EX7 = new Set<Code>([
  "CLOCK_UNSAFE", "RUN_BINDING", "RUN_STALE", "HOLD_BINDING",
  "HOLD_INSUFFICIENT", "HASH_MISMATCH", "CHAIN_INVALID", "PROJECTION_INVALID",
  "SOURCE_FORK",
]);

function codeExit(code: Code): number {
  if (code === "SCHEMA" || code === "UNSUPPORTED_VERSION") return 2;
  if (EX3.has(code)) return 3;
  if (EX4.has(code)) return 4;
  if (code === "INCOMPLETE") return 5;
  if (EX7.has(code)) return 7;
  if (code === "BUSY" || code === "STORAGE") return 8;
  return 7;
}

class Usage extends Error {}

interface Args {
  positional: string[];
  flags: Map<string, string | true>;
}

function parseArgs(argv: string[]): Args {
  const out: Args = { positional: [], flags: new Map() };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      const k = a.slice(2);
      if (out.flags.has(k)) throw new Usage("duplicate --" + k);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        out.flags.set(k, next);
        i++;
      } else {
        out.flags.set(k, true);
      }
    } else if (a.startsWith("-")) {
      throw new Usage("unknown flag " + a);
    } else {
      out.positional.push(a);
    }
  }
  return out;
}

function flag(args: Args, name: string): string | true | undefined {
  return args.flags.get(name);
}

function reqFlag(args: Args, name: string): string {
  const v = args.flags.get(name);
  if (v === undefined || v === true) throw new Usage("--" + name + " required");
  return v;
}

function reqId(args: Args): string {
  const v = reqFlag(args, "request-id");
  if (!isBondId(v, "bnq")) throw new Usage("--request-id must be bnq_*");
  return v;
}

function rev(args: Args): number {
  const v = reqFlag(args, "revision");
  if (!/^[0-9]+$/.test(v)) throw new Usage("--revision must be a nonnegative integer");
  return Number(v);
}

function read(path: string): Buffer {
  try {
    return readFileSync(path);
  } catch {
    throw new BondError("NOT_FOUND", path);
  }
}

function emit(x: unknown, json: boolean, outPath?: string): void {
  const text = json ? J(x) + "\n" : JSON.stringify(x, null, 2) + "\n";
  if (outPath) {
    const fd = openSync(outPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    try {
      writeFileSync(fd, text);
    } finally {
      closeSync(fd);
    }
  } else {
    process.stdout.write(text);
  }
}

function isNonTerminalView(v: View): boolean {
  return v.phase !== "CLOSED" || v.pending.length > 0;
}

/** Exit code for a successful mutation result (pending work => 5). */
function mutationExit(r: Result<View>): number {
  if (!r.ok) return codeExit(r.code);
  return isNonTerminalView(r.value) ? 5 : 0;
}

async function postHost(config: ReturnType<typeof loadConfigFile>, path: string,
  body: unknown, authFields: Omit<HttpAuth, "sig" | "body_hash" | "method" | "target">,
  signer: (m: Uint8Array) => Buffer): Promise<{ status: number; body: unknown }> {
  if (!config.hosting.enabled) throw new BondError("FORBIDDEN", "hosting disabled");
  const bodyBytes = Buffer.from(J(body), "utf8");
  const auth: HttpAuth = {
    ...authFields, method: "POST", target: path,
    body_hash: H(bodyBytes), sig: "",
  };
  const hash = authHash(auth);
  auth.sig = signer(new TextEncoder().encode(`LAGI-BOND/sign/request/1\n${hash}`)).toString("base64url");
  const res = await fetch(config.hosting.origin + path, {
    method: "POST",
    headers: { "content-type": "application/json", "bond-auth": encodeHttpAuth(auth) },
    body: bodyBytes,
  });
  return { status: res.status, body: await res.json() };
}

async function getHost(config: ReturnType<typeof loadConfigFile>, path: string,
  target: string, authFields: Omit<HttpAuth, "sig" | "body_hash" | "method" | "target">,
  signer: (m: Uint8Array) => Buffer): Promise<{ status: number; body: unknown }> {
  if (!config.hosting.enabled) throw new BondError("FORBIDDEN", "hosting disabled");
  const auth: HttpAuth = {
    ...authFields, method: "GET", target,
    body_hash: H(Buffer.alloc(0)), sig: "",
  };
  const hash = authHash(auth);
  auth.sig = signer(new TextEncoder().encode(`LAGI-BOND/sign/request/1\n${hash}`)).toString("base64url");
  const res = await fetch(config.hosting.origin + path, {
    headers: { "bond-auth": encodeHttpAuth(auth) },
  });
  return { status: res.status, body: await res.json() };
}

function authHash(auth: Omit<HttpAuth, "sig">): string {
  const u: Record<string, unknown> = { ...auth } as Record<string, unknown>;
  delete u.sig;
  return D("request", u);
}

function hostErrorExit(status: number, body: unknown): number {
  const code = (body as { error?: { code?: Code } })?.error?.code;
  if (code) return codeExit(code);
  return status >= 500 ? 8 : 4;
}

export async function main(argv: string[]): Promise<number> {
  const json = argv.includes("--json");
  try {
    return await run(argv.filter((a) => a !== "--json"), json);
  } catch (e) {
    if (e instanceof Usage) {
      process.stderr.write("usage: " + e.message + "\n");
      return 2;
    }
    const code = e instanceof BondError ? e.code : "STORAGE";
    if (json) process.stdout.write(J({ error: { code, retryable: code === "BUSY" || code === "STORAGE" } }) + "\n");
    else process.stderr.write(`error ${code}: ${e instanceof Error ? e.message : ""}\n`);
    return codeExit(code);
  }
}

async function run(argv: string[], json: boolean): Promise<number> {
  const args = parseArgs(argv);
  const cmd = args.positional[0];
  if (!cmd) throw new Usage("missing command");
  const configPath = (flag(args, "config") as string) ?? "./bond.config.json";
  const outPath = flag(args, "output") as string | undefined;

  switch (cmd) {
    case "doctor": {
      const w = wireClient(configPath);
      try {
        const r = await w.client.call("doctor", {});
        emit(r.ok ? r.value : r, json, outPath);
        if (r.ok) return r.value.missing.length ? 7 : 0;
        return codeExit(r.code);
      } finally { w.close(); }
    }
    case "prepare": {
      const actionFile = args.positional[1];
      if (!actionFile) throw new Usage("prepare ACTION_FILE");
      const action = vAction(parseJsonBytes(read(actionFile), CONTROL_LIMITS));
      const paper = vSigned(parseJsonBytes(read(reqFlag(args, "paper")), CONTROL_LIMITS),
        "paper", vPaperReview);
      const w = wireClient(configPath);
      try {
        ensureActivePin(w.client, action.policy_pin);
        const r = await w.client.call("prepare", {
          request_id: reqId(args), expected_revision: 0, action,
          run_id: reqFlag(args, "run"), paper,
        });
        emit(r.ok ? r.value : r, json, outPath);
        return mutationExit(r as Result<View>);
      } finally { w.close(); }
    }
    case "execute": case "cancel": case "accept": case "reject": case "reconcile": {
      const id = args.positional[1];
      if (!id || !isBondId(id, "bac")) throw new Usage(cmd + " ACTION_ID");
      const w = wireClient(configPath);
      try {
        const input: Record<string, unknown> = {
          request_id: reqId(args), action_id: id, expected_revision: rev(args),
        };
        if (cmd === "reject") {
          const reason = reqFlag(args, "reason");
          if (reason !== "OPERATOR_REJECTED" && reason !== "VALIDATION_FAILED") {
            throw new Usage("--reason OPERATOR_REJECTED|VALIDATION_FAILED");
          }
          input.reason = reason;
        }
        const r = await w.client.call(cmd as "execute", input as never);
        emit(r.ok ? r.value : r, json, outPath);
        return mutationExit(r as Result<View>);
      } finally { w.close(); }
    }
    case "stop": {
      const scope = flag(args, "scope") === true;
      const id = args.positional[1];
      if (!scope && (!id || !isBondId(id, "bac"))) throw new Usage("stop ACTION_ID | --scope");
      const w = wireClient(configPath);
      try {
        const r = await w.client.call("stop", {
          request_id: reqId(args), action_id: scope ? null : id!,
        });
        emit(r.ok ? r.value : r, json, outPath);
        if (!r.ok) return codeExit(r.code);
        if (scope) return 0;
        return isNonTerminalView(r.value as View) ? 5 : 0;
      } finally { w.close(); }
    }
    case "inspect": {
      const id = args.positional[1];
      if (!id || !isBondId(id, "bac")) throw new Usage("inspect ACTION_ID");
      const w = wireClient(configPath);
      try {
        const r = await w.client.call("inspect", { action_id: id });
        emit(r.ok ? r.value : r, json, outPath);
        return r.ok ? 0 : codeExit(r.code);
      } finally { w.close(); }
    }
    case "attach": {
      const id = args.positional[1];
      const file = args.positional[2];
      if (!id || !isBondId(id, "bac") || !file) throw new Usage("attach ACTION_ID FILE");
      const purpose = reqFlag(args, "purpose");
      if (purpose !== "GROUND_ADVISORY" && purpose !== "WORLD_LINEAGE") {
        throw new Usage("--purpose GROUND_ADVISORY|WORLD_LINEAGE");
      }
      const bytes = read(file);
      const artifact: Blob = {
        hash: H(bytes), bytes: bytes.length,
        media_type: "application/json", data: b64uEncode(bytes),
      };
      const w = wireClient(configPath);
      try {
        const r = await w.client.call("attach", {
          request_id: reqId(args), action_id: id, expected_revision: rev(args),
          artifact, purpose,
        });
        emit(r.ok ? r.value : r, json, outPath);
        return mutationExit(r as Result<View>);
      } finally { w.close(); }
    }
    case "export": {
      const id = args.positional[1];
      if (!id || !isBondId(id, "bac")) throw new Usage("export ACTION_ID");
      const w = wireClient(configPath);
      try {
        const r = await w.client.call("export", {
          action_id: id, through_revision: rev(args),
          include_bytes: flag(args, "hashes-only") !== true,
        });
        emit(r.ok ? r.value : r, json, outPath);
        return r.ok ? 0 : codeExit(r.code);
      } finally { w.close(); }
    }
    case "verify": {
      const file = args.positional[1];
      if (!file) throw new Usage("verify PACKAGE_FILE");
      const trust = loadTrustFile(reqFlag(args, "trust"));
      let head: Head | null = null;
      const headFile = flag(args, "head");
      if (typeof headFile === "string") {
        head = parseJsonBytes(read(headFile), CONTROL_LIMITS) as Head;
      }
      const raw = read(file);
      let v;
      try {
        v = verifyPackage(raw, trust, head);
      } catch (e) {
        const code = e instanceof BondError ? e.code : "STORAGE";
        emit({ integrity: "INVALID", error: code }, json, outPath);
        return 6;
      }
      emit(v, json, outPath);
      if (v.integrity === "INVALID") return 6;
      return v.completeness === "COMPLETE" && v.currentness === "PINNED_PREFIX" ? 0 : 5;
    }
    case "paper-sign": {
      const file = args.positional[1];
      if (!file) throw new Usage("paper-sign REVIEW_FILE");
      const keyRef = reqFlag(args, "key-ref");
      const review = vPaperReview(parseJsonBytes(read(file), CONTROL_LIMITS));
      const config = loadConfigFile(configPath);
      const trust = loadTrustFile(config.trust_file);
      const seed = envSecrets().seed(keyRef);
      const w = wireClient(configPath);
      try {
        for (const ref of [review.document, review.exclusions_document]) {
          const bytes = w.client.journal.getObjectBytes(ref.hash);
          if (!bytes || bytes.length !== ref.bytes) {
            throw new BondError("NOT_FOUND", "paper document bytes absent from object store");
          }
        }
      } finally { w.close(); }
      const { seedSigner, publicKeyHexFromSeed } = await import("@latticeag/bond-core");
      const keyId = trust.keys.find((k) => k.public_key_hex === publicKeyHexFromSeed(seed))?.key_id;
      if (!keyId) throw new BondError("UNTRUSTED_KEY", "paper key untrusted");
      const signed = signObject("paper", review, keyId, seedSigner(seed));
      emit(signed, json, outPath);
      return 0;
    }
    case "publish": case "fetch": case "notice": case "notices": {
      return hostCommand(cmd, args, configPath, json, outPath);
    }
    default:
      throw new Usage("unknown command " + cmd);
  }
}

async function hostCommand(cmd: string, args: Args, configPath: string,
  json: boolean, outPath?: string): Promise<number> {
  const config = loadConfigFile(configPath);
  const trust = loadTrustFile(config.trust_file);
  const secrets = envSecrets();
  const seed = secrets.seed(config.signing_key_ref);
  const { seedSigner, publicKeyHexFromSeed } = await import("@latticeag/bond-core");
  const signer = seedSigner(seed);
  const keyId = trust.keys.find((k) => k.public_key_hex === publicKeyHexFromSeed(seed))?.key_id!;
  const base = {
    tenant_id: config.tenant_id, principal_id: config.principal_id, key_id: keyId,
    request_id: reqId(args), issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 240000).toISOString(),
  };
  const respond = (r: { status: number; body: unknown }): number => {
    emit(r.body, json, outPath);
    if (r.status >= 200 && r.status < 300) return 0;
    return hostErrorExit(r.status, r.body);
  };
  switch (cmd) {
    case "publish": {
      const file = args.positional[1];
      if (!file) throw new Usage("publish PACKAGE_FILE");
      const pkg = parseJsonBytes(read(file), PACKAGE_LIMITS);
      const revS = reqFlag(args, "host-revision");
      if (!/^[0-9]+$/.test(revS)) throw new Usage("--host-revision integer");
      const r = await postHost(config, "/v1/certificates",
        { package: pkg, expected_host_revision: Number(revS) }, base, signer);
      return respond(r);
    }
    case "fetch": {
      const rid = args.positional[1];
      if (!rid || !isBondId(rid, "brc")) throw new Usage("fetch RECEIPT_ID");
      const r = await getHost(config,
        `/v1/certificates/${rid}?revision=${rev(args)}`,
        `/v1/certificates/${rid}?revision=${rev(args)}`, base, signer);
      return respond(r);
    }
    case "notice": {
      const file = args.positional[1];
      if (!file) throw new Usage("notice NOTICE_FILE");
      const keyRef = reqFlag(args, "key-ref");
      const notice = vNotice(parseJsonBytes(read(file), CONTROL_LIMITS));
      const nseed = secrets.seed(keyRef);
      const nkeyId = trust.keys.find((k) => k.public_key_hex === publicKeyHexFromSeed(nseed))?.key_id;
      if (!nkeyId) throw new BondError("UNTRUSTED_KEY", "notice key untrusted");
      const signed = signObject("notice", notice, nkeyId, seedSigner(nseed));
      const r = await postHost(config,
        `/v1/certificates/${notice.receipt_id}/notices`, signed, base, signer);
      return respond(r);
    }
    case "notices": {
      const rid = args.positional[1];
      if (!rid || !isBondId(rid, "brc")) throw new Usage("notices RECEIPT_ID");
      const after = reqFlag(args, "after"), limit = reqFlag(args, "limit");
      if (!/^[0-9]+$/.test(after) || !/^[0-9]+$/.test(limit)) throw new Usage("--after/--limit integer");
      const target = `/v1/certificates/${rid}/notices?after=${after}&limit=${limit}`;
      const r = await getHost(config, target, target, base, signer);
      return respond(r);
    }
    default:
      throw new Usage("unknown host command");
  }
}
