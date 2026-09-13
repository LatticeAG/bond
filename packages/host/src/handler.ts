/**
 * §6.4 certificate-host handler — the entire HTTP surface is five routes.
 * Fixed order: authentication → nonce lookup → CAS → package verification →
 * append. No execution, payout, minting, proxy, deletion, or insurer endpoints.
 */

import {
  ArtifactRef, Blob, BondError, Code, D, H, Hash, HttpAuth, J, JBytes, Notice,
  Package, PaperReview, Signed, TrustFile, b64uDecode, decodeHttpAuth, fail,
  isBondId, isHash, parseJson, parseJsonBytes, timeMs, vHttpAuth, vNotice,
  vPackage, vPaperReview, vSigned, verifyHttpAuth, verifyPackage, verifySigned,
  CONTROL_LIMITS, PACKAGE_LIMITS, J as JStr,
} from "@latticeag/bond-core";
import { HostStore } from "./store.js";

export interface HostRequest {
  method: "GET" | "POST";
  /** Raw path without query (already percent-decoded by the caller). */
  path: string;
  /** Raw query string without '?'. */
  query: string;
  headers: Record<string, string | undefined>;
  body: Buffer | null;
}

export interface HostResponse {
  status: number;
  body: unknown;
  headers?: Record<string, string>;
}

export interface HostDeps {
  store: HostStore;
  trust: TrustFile;
  now: () => string;
  maxPackageBytes: number;
}

const RETRYABLE = new Set<Code>(["BUSY", "STORAGE", "INCOMPLETE", "DEADLINE"]);

function errBody(code: Code): { error: { code: Code; retryable: boolean } } {
  return { error: { code, retryable: RETRYABLE.has(code) } };
}

/** Post-auth code → HTTP status (§6.4 mapping). */
function statusOf(code: Code, duringAuth: boolean): number {
  if (duringAuth) return 401;
  switch (code) {
    case "SCHEMA":
    case "UNSUPPORTED_VERSION": return 400;
    case "UNAUTHORIZED": return 401;
    case "FORBIDDEN":
    case "POLICY_DENIED":
    case "INSURANCE_REQUIRED":
    case "INSURANCE_SCOPE":
    case "UNTRUSTED_KEY":
    case "SIGNATURE_INVALID": return 403;
    case "NOT_FOUND": return 404;
    case "CONFLICT":
    case "IDEMPOTENCY_CONFLICT":
    case "REVISION_CONFLICT":
    case "BAD_STATE":
    case "PIN_MISMATCH":
    case "UNSUPPORTED_COMPOSITION": return 409;
    case "LIMIT": return 413;
    case "BUSY": return 429;
    case "STORAGE": return 503;
    default:
      // Evidence/integrity/chain/deadline failures are unprocessable.
      return 422;
  }
}

function authFail(code: Code): never {
  throw Object.assign(new BondError(code), { authScope: true });
}

export function createHostHandler(deps: HostDeps) {
  const { store, trust, now } = deps;

  /** Parse + verify the Bond-Auth header; throws with authScope for 401. */
  function authenticate(req: HostRequest, bodyBytes: Buffer | null): HttpAuth {
    const header = req.headers["bond-auth"];
    if (!header) authFail("UNAUTHORIZED");
    let raw: Buffer;
    try {
      raw = decodeHttpAuth(header);
    } catch (e) {
      authFail(e instanceof BondError ? e.code : "UNAUTHORIZED");
    }
    let auth: HttpAuth;
    try {
      auth = vHttpAuth(parseJsonBytes(raw!, CONTROL_LIMITS));
    } catch (e) {
      authFail(e instanceof BondError ? e.code : "SCHEMA");
    }
    const target = canonicalTarget(req);
    if (auth!.method !== req.method || auth!.target !== target) authFail("UNAUTHORIZED");
    const bodyHash = req.method === "GET"
      ? H(Buffer.alloc(0))
      : H(JBytes(parseJsonBytes(bodyBytes ?? Buffer.alloc(0), PACKAGE_LIMITS)));
    if (auth!.body_hash !== bodyHash) authFail("UNAUTHORIZED");
    try {
      verifyHttpAuth(auth!, trust, now());
    } catch (e) {
      authFail(e instanceof BondError ? e.code : "UNAUTHORIZED");
    }
    return auth!;
  }

  /** Exact path plus sorted query — no origin, no fragment. */
  function canonicalTarget(req: HostRequest): string {
    const q = parseQuery(req.query);
    const keys = Object.keys(q).sort();
    return req.path + (keys.length ? "?" + keys.map((k) => `${k}=${q[k]}`).join("&") : "");
  }

  function parseQuery(qs: string): Record<string, string> {
    const out: Record<string, string> = {};
    if (qs === "") return out;
    for (const pair of qs.split("&")) {
      const eq = pair.indexOf("=");
      if (eq < 0) throw new BondError("SCHEMA", "bad query pair");
      const k = pair.slice(0, eq), v = pair.slice(eq + 1);
      if (k in out) throw new BondError("SCHEMA", "duplicate query key");
      out[k] = v;
    }
    return out;
  }

  /**
   * Nonce lookup: an exact stored request replays its response (always 200);
   * the same nonce with different bytes conflicts. Returns null when new.
   */
  function nonceReplay(
    auth: HttpAuth, req: HostRequest, bodyBytes: Buffer | null,
  ): HostResponse | null {
    const requestHash = H(Buffer.concat([
      Buffer.from(req.method + "\n" + canonicalTarget(req) + "\n"),
      bodyBytes ?? Buffer.alloc(0),
    ]));
    const seen = store.getNonce(auth.tenant_id, auth.key_id, auth.request_id);
    if (!seen) return null;
    if (seen.requestHash !== requestHash) throw new BondError("IDEMPOTENCY_CONFLICT");
    return { status: 200, body: seen.response.body };
  }

  function recordNonce(auth: HttpAuth, req: HostRequest, bodyBytes: Buffer | null, resp: HostResponse): void {
    const requestHash = H(Buffer.concat([
      Buffer.from(req.method + "\n" + canonicalTarget(req) + "\n"),
      bodyBytes ?? Buffer.alloc(0),
    ]));
    store.putNonce(auth.tenant_id, {
      keyId: auth.key_id, requestId: auth.request_id, requestHash,
      response: { status: resp.status, body: resp.body },
    });
  }

  /** Owner = operator for the tenant or the action's principal; auditor reads. */
  function authorizeRead(auth: HttpAuth, receiptId: string): void {
    const t = store.tenantOf(receiptId);
    if (t === null || t !== auth.tenant_id) throw new BondError("NOT_FOUND");
    const isOwner = auth.principal_id === store.principalOf(receiptId);
    if (!isOwner && !hasRole(auth, "operator") && !hasRole(auth, "auditor")) {
      throw new BondError("FORBIDDEN");
    }
  }

  function hasRole(auth: HttpAuth, role: string): boolean {
    // Roles are carried by trust pins: a key pinned for the tenant with the
    // relevant capability satisfies the role check locally. The host keeps a
    // static role map on the trust key id.
    return (roleMap.get(auth.key_id) ?? []).includes(role);
  }

  const roleMap = new Map<string, string[]>();
  /** Register auth-key roles for host authorization (deployment wiring). */
  function grantRoles(keyId: string, roles: string[]): void {
    roleMap.set(keyId, roles);
  }

  /** Convenience for tests/fixtures: grant the same roles to every trusted key. */
  function grantAllKeys(roles: string[]): void {
    for (const k of trust.keys) roleMap.set(k.key_id, roles);
  }

  function authorizeOperator(auth: HttpAuth, receiptId: string): void {
    const t = store.tenantOf(receiptId);
    if (t === null || t !== auth.tenant_id) throw new BondError("NOT_FOUND");
    if (!hasRole(auth, "operator") && auth.principal_id !== store.principalOf(receiptId)) {
      throw new BondError("FORBIDDEN");
    }
  }

  // --- routes -----------------------------------------------------------------

  function healthz(): HostResponse {
    return { status: 200, body: { status: "ok", protocol: "bond.host/1" } };
  }

  function publish(auth: HttpAuth, bodyBytes: Buffer): HostResponse {
    const env = parseJsonBytes(bodyBytes, {
      ...PACKAGE_LIMITS, maxBytes: deps.maxPackageBytes + 4096,
    }) as Record<string, unknown>;
    if (typeof env !== "object" || env === null || Array.isArray(env)) {
      throw new BondError("SCHEMA");
    }
    const ks = Object.keys(env).sort();
    if (ks.length !== 2 || ks[0] !== "expected_host_revision" || ks[1] !== "package") {
      throw new BondError("SCHEMA", "publish envelope");
    }
    const expected = env.expected_host_revision;
    if (typeof expected !== "number" || !Number.isSafeInteger(expected) || expected < 0) {
      throw new BondError("SCHEMA", "expected_host_revision");
    }
    const pkgBytes = JBytes(env.package);
    if (pkgBytes.length > deps.maxPackageBytes) throw new BondError("LIMIT", "package bytes");
    const pkg = vPackage(env.package);
    if (!hasRole(auth, "publisher") && !hasRole(auth, "operator")) {
      throw new BondError("FORBIDDEN", "publisher required");
    }
    // Package tenant must match authentication; locate it from the first entry.
    const first = pkg.entries[0];
    if (!first || first.body.kind !== "ActionStaged") throw new BondError("SCHEMA", "no genesis");
    const tenant = first.body.tenant_id;
    if (tenant !== auth.tenant_id) throw new BondError("FORBIDDEN", "tenant mismatch");
    const receiptId = pkg.receipts[0]?.body.receipt_id;
    if (!receiptId || !isBondId(receiptId, "brc")) throw new BondError("SCHEMA", "receipt id");
    if (pkg.receipts.some((r) => r.body.receipt_id !== receiptId) ||
      pkg.entries.some((e) => e.body.action_id !== first.body.action_id)) {
      throw new BondError("SCHEMA", "mixed lineage");
    }
    // CAS on stored max revision.
    const maxRev = store.maxRevision(receiptId);
    const existingTenant = store.tenantOf(receiptId);
    if (existingTenant !== null && existingTenant !== auth.tenant_id) {
      // Cross-tenant lineage reads as absent.
      throw new BondError("NOT_FOUND");
    }
    if (expected !== maxRev) throw new BondError("CONFLICT", "expected_host_revision CAS");
    // Verify integrity before touching the store.
    const v = verifyPackage(pkgBytes, trust, null);
    if (v.integrity !== "VALID") {
      throw new BondError(v.errors[0] === "CHAIN_INVALID" ? "CHAIN_INVALID" : "HASH_MISMATCH");
    }
    // Contiguous prefix extension: stored 1..maxRev must match incoming.
    const stored = store.packagesOf(receiptId);
    for (const s of stored) {
      const inc = pkg.receipts.find((r) => r.body.revision === s.revision);
      if (!inc || inc.hash !== s.receiptHash) {
        throw new BondError("CHAIN_INVALID", "does not extend stored prefix");
      }
    }
    const newRevs = pkg.receipts.filter((r) => r.body.revision > maxRev)
      .sort((a, b) => a.body.revision - b.body.revision);
    if (newRevs.length === 0 && maxRev === 0) throw new BondError("SCHEMA", "empty package");
    let prev = maxRev;
    for (const r of newRevs) {
      if (r.body.revision !== prev + 1) throw new BondError("CHAIN_INVALID", "gap in revisions");
      prev = r.body.revision;
    }
    const principal = actionPrincipal(pkg);
    for (const r of newRevs) {
      const prefix = derivePrefix(pkg, r.body.revision);
      store.appendPackage(tenant, principal, receiptId, r.body.revision, r.hash, JBytes(prefix));
    }
    const head = pkg.receipts[pkg.receipts.length - 1]!;
    const resp: HostResponse = {
      status: 201,
      body: {
        receipt_id: receiptId, revision: head.body.revision,
        receipt_hash: head.hash, hosting: "STORED",
      },
    };
    return resp;
  }

  function actionPrincipal(pkg: Package): string {
    for (const b of pkg.blobs) {
      const staged = pkg.entries.find((e) => e.body.kind === "ActionStaged");
      if (!staged) break;
      const binding = (staged.body.data as { binding: { action: ArtifactRef } }).binding;
      if (b.hash !== binding.action.hash || b.data === null) continue;
      const action = parseJson(b64uDecode(b.data).toString("utf8"), CONTROL_LIMITS) as { principal_id: string };
      return action.principal_id;
    }
    return "";
  }

  /** Prefix package: receipts+entries through `rev` plus their blob closure. */
  function derivePrefix(pkg: Package, rev: number): Package {
    const receipts = pkg.receipts.filter((r) => r.body.revision <= rev);
    const entries = pkg.entries.filter((e) => e.body.seq <= rev);
    const want = new Set<string>();
    const last = receipts[receipts.length - 1];
    if (last) {
      want.add(last.body.binding.action.hash);
      want.add(last.body.binding.plan.hash);
      want.add(last.body.binding.paper.hash);
      for (const r of last.body.evidence) want.add(r.hash);
    }
    for (const r of receipts) for (const ev of r.body.evidence) want.add(ev.hash);
    // Paper document + exclusions refs.
    const paperBlob = pkg.blobs.find((b) => last && b.hash === last.body.binding.paper.hash);
    if (paperBlob && paperBlob.data !== null) {
      try {
        const paper = vSigned(
          parseJson(b64uDecode(paperBlob.data).toString("utf8"), CONTROL_LIMITS), "paper", vPaperReview);
        want.add(paper.body.document.hash);
        want.add(paper.body.exclusions_document.hash);
      } catch { /* malformed paper already rejected by verifyPackage */ }
    }
    // Assertion source blobs for evidence refs.
    for (const b of pkg.blobs) {
      if (!want.has(b.hash) || b.data === null) continue;
      try {
        const a = vSigned(parseJson(b64uDecode(b.data).toString("utf8"), CONTROL_LIMITS),
          "assertion", (x) => x as { source: ArtifactRef });
        const src = (a.body as { source?: ArtifactRef }).source;
        if (src && isHash(src.hash)) want.add(src.hash);
      } catch { /* not an assertion blob */ }
    }
    const blobs = pkg.blobs.filter((b) => want.has(b.hash));
    return { schema: "bond.package/1", receipts, entries, blobs };
  }

  function readCertificate(auth: HttpAuth, receiptId: string, query: Record<string, string>): HostResponse {
    if (!isBondId(receiptId, "brc")) throw new BondError("NOT_FOUND");
    const keys = Object.keys(query);
    if (keys.length !== 1 || keys[0] !== "revision") throw new BondError("SCHEMA", "revision required");
    const rev = Number(query.revision);
    if (!Number.isSafeInteger(rev) || rev < 1 || String(rev) !== query.revision) {
      throw new BondError("SCHEMA", "bad revision");
    }
    authorizeRead(auth, receiptId);
    const stored = store.packageAt(receiptId, rev);
    if (!stored) throw new BondError("NOT_FOUND");
    return {
      status: 200,
      body: {
        package: parseJsonBytes(stored.bytes, PACKAGE_LIMITS),
        latest_revision: store.maxRevision(receiptId),
        hosting: store.hostingOf(receiptId),
        notices_head: store.noticesHead(receiptId),
      },
    };
  }

  function postNotice(auth: HttpAuth, receiptId: string, bodyBytes: Buffer): HostResponse {
    if (!isBondId(receiptId, "brc")) throw new BondError("NOT_FOUND");
    authorizeOperator(auth, receiptId);
    const notice = vSigned(parseJsonBytes(bodyBytes, CONTROL_LIMITS), "notice", vNotice);
    verifySigned("notice", notice, trust, auth.tenant_id);
    if (notice.body.receipt_id !== receiptId) throw new BondError("SCHEMA", "notice lineage");
    const head = store.noticesHead(receiptId);
    const expectedRev = head ? head.seq + 1 : 1;
    if (notice.body.revision !== expectedRev) throw new BondError("CONFLICT", "notice revision");
    if (notice.body.previous_hash !== (head ? head.hash : null)) {
      throw new BondError("CHAIN_INVALID", "notice previous_hash");
    }
    store.appendNotice(receiptId, notice);
    store.withdraw(receiptId);
    return { status: 201, body: { notice, hosting: "WITHDRAWN" } };
  }

  function getNotices(auth: HttpAuth, receiptId: string, query: Record<string, string>): HostResponse {
    if (!isBondId(receiptId, "brc")) throw new BondError("NOT_FOUND");
    const keys = Object.keys(query).sort();
    if (keys.length !== 2 || keys[0] !== "after" || keys[1] !== "limit") {
      throw new BondError("SCHEMA", "after+limit required");
    }
    const after = Number(query.after), limit = Number(query.limit);
    if (!Number.isSafeInteger(after) || after < 0 || String(after) !== query.after ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 100 || String(limit) !== query.limit) {
      throw new BondError("SCHEMA", "bad after/limit");
    }
    authorizeRead(auth, receiptId);
    const all = store.noticesOf(receiptId).filter((n) => n.revision > after);
    const page = all.slice(0, limit).map((n) => n.notice);
    return {
      status: 200,
      body: {
        notices: page,
        next_after: all.length > limit ? page[page.length - 1]!.body.revision : null,
      },
    };
  }

  // --- dispatch -----------------------------------------------------------------

  function handle(req: HostRequest): HostResponse {
    try {
      if (req.path.includes("%2F") || req.path.includes("%2f")) {
        throw new BondError("SCHEMA", "encoded slash");
      }
      if (req.method === "GET" && req.path === "/healthz") return healthz();
      const isPost = req.method === "POST";
      if (isPost && req.body && req.body.length > deps.maxPackageBytes + 4096) {
        throw new BondError("LIMIT", "envelope bytes");
      }
      if (isPost && req.path === "/v1/certificates") {
        const auth = authenticate(req, req.body);
        const replay = nonceReplay(auth, req, req.body);
        if (replay) return replay;
        const resp = publish(auth, req.body!);
        recordNonce(auth, req, req.body, resp);
        return resp;
      }
      const certMatch = req.path.match(/^\/v1\/certificates\/([A-Za-z0-9_]+)$/);
      if (req.method === "GET" && certMatch) {
        const auth = authenticate(req, null);
        return readCertificate(auth, certMatch[1]!, parseQuery(req.query));
      }
      const noticeMatch = req.path.match(/^\/v1\/certificates\/([A-Za-z0-9_]+)\/notices$/);
      if (isPost && noticeMatch) {
        const auth = authenticate(req, req.body);
        const replay = nonceReplay(auth, req, req.body);
        if (replay) return replay;
        const resp = postNotice(auth, noticeMatch[1]!, req.body!);
        recordNonce(auth, req, req.body, resp);
        return resp;
      }
      if (req.method === "GET" && noticeMatch) {
        const auth = authenticate(req, null);
        return getNotices(auth, noticeMatch[1]!, parseQuery(req.query));
      }
      throw new BondError("NOT_FOUND");
    } catch (e) {
      const code = e instanceof BondError ? e.code : "STORAGE";
      const duringAuth = (e as { authScope?: boolean }).authScope === true;
      const status = statusOf(code, duringAuth);
      const headers: Record<string, string> = {};
      if (status === 429) headers["retry-after"] = "1";
      return { status, body: errBody(code), headers };
    }
  }

  return { handle, grantRoles, grantAllKeys };
}
