/**
 * SQLite journal — §7.2 schema verbatim, WAL, foreign_keys=ON,
 * synchronous=FULL, busy_timeout=1000, process lock. No dependency call,
 * filesystem write, or Promise await ever happens inside a transaction.
 */

import { DatabaseSync } from "node:sqlite";
import {
  mkdirSync, openSync, closeSync, constants, renameSync, writeSync, fsyncSync, unlinkSync,
  readFileSync, existsSync,
} from "node:fs";
import { BondError, H } from "@latticeag/bond-core";

export const JOURNAL_SCHEMA = `
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS actions (
  action_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, principal_id TEXT NOT NULL,
  scope_id TEXT NOT NULL, action_hash TEXT NOT NULL UNIQUE, receipt_id TEXT NOT NULL UNIQUE,
  run_id TEXT NOT NULL UNIQUE, hold_id TEXT UNIQUE, revision INTEGER NOT NULL,
  writer_fence INTEGER NOT NULL, stop_latched INTEGER NOT NULL CHECK(stop_latched IN (0,1)),
  quarantined INTEGER NOT NULL CHECK(quarantined IN (0,1)), projection BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS objects (hash TEXT PRIMARY KEY, bytes INTEGER NOT NULL, media_type TEXT NOT NULL, durable INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS entries (
  action_id TEXT NOT NULL REFERENCES actions(action_id), seq INTEGER NOT NULL,
  hash TEXT NOT NULL UNIQUE, canonical BLOB NOT NULL, PRIMARY KEY(action_id,seq)
);
CREATE TABLE IF NOT EXISTS receipts (
  receipt_id TEXT NOT NULL, revision INTEGER NOT NULL, action_id TEXT NOT NULL REFERENCES actions(action_id),
  hash TEXT NOT NULL UNIQUE, canonical BLOB NOT NULL, PRIMARY KEY(receipt_id,revision)
);
CREATE TABLE IF NOT EXISTS operations (
  operation_key TEXT PRIMARY KEY, action_id TEXT NOT NULL REFERENCES actions(action_id), kind TEXT NOT NULL,
  request_hash TEXT NOT NULL, request BLOB NOT NULL, state TEXT NOT NULL,
  writer_fence INTEGER NOT NULL, last_evidence_hash TEXT, UNIQUE(action_id,kind)
);
CREATE TABLE IF NOT EXISTS requests (
  tenant_id TEXT NOT NULL, principal_id TEXT NOT NULL, request_id TEXT NOT NULL,
  request_hash TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('IN_PROGRESS','DONE')),
  response BLOB, PRIMARY KEY(tenant_id,principal_id,request_id),
  CHECK((state='IN_PROGRESS' AND response IS NULL) OR (state='DONE' AND response IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS references_to_objects (
  receipt_id TEXT NOT NULL, revision INTEGER NOT NULL, object_hash TEXT NOT NULL REFERENCES objects(hash),
  PRIMARY KEY(receipt_id,revision,object_hash),
  FOREIGN KEY(receipt_id,revision) REFERENCES receipts(receipt_id,revision)
);
CREATE INDEX IF NOT EXISTS actions_scope ON actions(tenant_id,scope_id,revision);
CREATE INDEX IF NOT EXISTS operations_pending ON operations(state,action_id);
`;

export interface ActionRow {
  action_id: string; tenant_id: string; principal_id: string; scope_id: string;
  action_hash: string; receipt_id: string; run_id: string; hold_id: string | null;
  revision: number; writer_fence: number; stop_latched: number; quarantined: number;
  projection: Uint8Array;
}

export interface RequestRow {
  tenant_id: string; principal_id: string; request_id: string;
  request_hash: string; state: "IN_PROGRESS" | "DONE"; response: Uint8Array | null;
}

export class Journal {
  readonly db: DatabaseSync;
  private lockFd: number;
  readonly dir: string;

  constructor(dir: string) {
    this.dir = dir;
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const lockPath = dir + "/owner.lock";
    try {
      this.lockFd = openSync(lockPath, constants.O_CREAT | constants.O_EXCL | constants.O_RDWR, 0o600);
    } catch {
      throw new BondError("BUSY", "journal process lock held");
    }
    this.db = new DatabaseSync(dir + "/journal.sqlite3");
    this.db.exec("PRAGMA journal_mode=WAL");
    this.db.exec("PRAGMA foreign_keys=ON");
    this.db.exec("PRAGMA synchronous=FULL");
    this.db.exec("PRAGMA busy_timeout=1000");
    this.db.exec(JOURNAL_SCHEMA);
  }

  private closed = false;

  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.db.close();
    } finally {
      try {
        closeSync(this.lockFd);
      } finally {
        // Release the lock path so a later open in this process can take it.
        try { unlinkSync(this.dir + "/owner.lock"); } catch { /* gone */ }
      }
    }
  }

  // --- content-addressed object files: objects/sha256/ab/abcdef... ----------

  private objectPath(hash: string): string {
    return this.dir + "/objects/sha256/" + hash.slice(0, 2) + "/" + hash;
  }

  /** Atomic object write: exclusive temp file, fsync, rename. Idempotent. */
  storeObjectBytes(bytes: Buffer, mediaType: string): string {
    const hash = H(bytes);
    const path = this.objectPath(hash);
    if (!existsSync(path)) {
      const dir = this.dir + "/objects/sha256/" + hash.slice(0, 2);
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      const tmp = path + ".tmp." + process.pid;
      const fd = openSync(tmp, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
      try {
        writeSync(fd, bytes);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      renameSync(tmp, path);
    }
    this.putObject(hash, bytes.length, mediaType, 1);
    return hash;
  }

  getObjectBytes(hash: string): Buffer | null {
    const row = this.db.prepare("SELECT bytes FROM objects WHERE hash=?").get(hash) as
      { bytes: number } | undefined;
    if (!row) return null;
    const path = this.objectPath(hash);
    if (!existsSync(path)) return null;
    const bytes = readFileSync(path);
    if (bytes.length !== row.bytes || H(bytes) !== hash) {
      throw new BondError("HASH_MISMATCH", "object store corruption");
    }
    return bytes;
  }

  hasObject(hash: string): boolean {
    return this.db.prepare("SELECT 1 FROM objects WHERE hash=?").get(hash) !== undefined
      && existsSync(this.objectPath(hash));
  }

  /** Synchronous single-writer transaction; no awaits permitted inside fn. */
  tx<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const v = fn();
      this.db.exec("COMMIT");
      return v;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }

  getMetadata(key: string): Buffer | null {
    const r = this.db.prepare("SELECT value FROM metadata WHERE key=?").get(key) as
      { value: Uint8Array } | undefined;
    return r ? Buffer.from(r.value) : null;
  }

  setMetadata(key: string, value: Buffer | Uint8Array): void {
    this.db.prepare("INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
      .run(key, Buffer.from(value));
  }

  getAction(actionId: string): ActionRow | null {
    const r = this.db.prepare("SELECT * FROM actions WHERE action_id=?").get(actionId) as
      ActionRow | undefined;
    return r ?? null;
  }

  getActionByHash(hash: string): ActionRow | null {
    const r = this.db.prepare("SELECT * FROM actions WHERE action_hash=?").get(hash) as
      ActionRow | undefined;
    return r ?? null;
  }

  pendingActions(scopeId?: string): ActionRow[] {
    if (scopeId === undefined) {
      return this.db.prepare("SELECT * FROM actions").all() as unknown as ActionRow[];
    }
    return this.db.prepare("SELECT * FROM actions WHERE scope_id=?").all(scopeId) as unknown as ActionRow[];
  }

  countNonTerminal(scopeId: string): number {
    // Projection JSON stores phase; count those not CLOSED.
    const rows = this.db.prepare("SELECT projection FROM actions WHERE scope_id=?").all(scopeId) as
      { projection: Uint8Array }[];
    let n = 0;
    for (const r of rows) {
      const p = JSON.parse(Buffer.from(r.projection).toString("utf8")) as { phase: string };
      if (p.phase !== "CLOSED") n += 1;
    }
    return n;
  }

  insertAction(a: ActionRow): void {
    this.db.prepare(
      "INSERT INTO actions(action_id,tenant_id,principal_id,scope_id,action_hash,receipt_id,run_id,hold_id,revision,writer_fence,stop_latched,quarantined,projection) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
    ).run(a.action_id, a.tenant_id, a.principal_id, a.scope_id, a.action_hash, a.receipt_id,
      a.run_id, a.hold_id, a.revision, a.writer_fence, a.stop_latched, a.quarantined, a.projection);
  }

  /** Writer-fence takeover: the current writer claims the action row. */
  updateActionFence(actionId: string, fence: number): void {
    this.db.prepare("UPDATE actions SET writer_fence=? WHERE action_id=?")
      .run(fence, actionId);
  }

  updateActionProjection(actionId: string, revision: number, projection: Uint8Array,
    stopLatched: number, quarantined: number, holdId: string | null): void {
    this.db.prepare(
      "UPDATE actions SET revision=?,projection=?,stop_latched=?,quarantined=?,hold_id=COALESCE(?,hold_id) WHERE action_id=?",
    ).run(revision, projection, stopLatched, quarantined, holdId, actionId);
  }

  putObject(hash: string, bytes: number, mediaType: string, durable: number): void {
    this.db.prepare(
      "INSERT INTO objects(hash,bytes,media_type,durable) VALUES(?,?,?,?) ON CONFLICT(hash) DO NOTHING",
    ).run(hash, bytes, mediaType, durable);
  }

  appendEntry(actionId: string, seq: number, hash: string, canonical: Buffer): void {
    this.db.prepare("INSERT INTO entries(action_id,seq,hash,canonical) VALUES(?,?,?,?)")
      .run(actionId, seq, hash, canonical);
  }

  appendReceipt(receiptId: string, revision: number, actionId: string, hash: string, canonical: Buffer): void {
    this.db.prepare("INSERT INTO receipts(receipt_id,revision,action_id,hash,canonical) VALUES(?,?,?,?,?)")
      .run(receiptId, revision, actionId, hash, canonical);
  }

  getEntries(actionId: string): { seq: number; hash: string; canonical: Buffer }[] {
    return this.db.prepare("SELECT seq,hash,canonical FROM entries WHERE action_id=? ORDER BY seq")
      .all(actionId) as { seq: number; hash: string; canonical: Buffer }[];
  }

  getReceipts(actionId: string): { revision: number; hash: string; canonical: Buffer }[] {
    return this.db.prepare("SELECT revision,hash,canonical FROM receipts WHERE action_id=? ORDER BY revision")
      .all(actionId) as { revision: number; hash: string; canonical: Buffer }[];
  }

  putOperation(op: {
    operation_key: string; action_id: string; kind: string; request_hash: string;
    request: Buffer; state: string; writer_fence: number; last_evidence_hash: string | null;
  }): void {
    this.db.prepare(
      "INSERT INTO operations(operation_key,action_id,kind,request_hash,request,state,writer_fence,last_evidence_hash) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(operation_key) DO UPDATE SET state=excluded.state,last_evidence_hash=excluded.last_evidence_hash",
    ).run(op.operation_key, op.action_id, op.kind, op.request_hash, op.request, op.state,
      op.writer_fence, op.last_evidence_hash);
  }

  getOperations(actionId: string): { kind: string; state: string; operation_key: string; request: Buffer; writer_fence: number }[] {
    return this.db.prepare("SELECT kind,state,operation_key,request,writer_fence FROM operations WHERE action_id=?")
      .all(actionId) as { kind: string; state: string; operation_key: string; request: Buffer; writer_fence: number }[];
  }

  admitRequest(tenant: string, principal: string, requestId: string, hash: string): RequestRow | "ADMITTED" {
    const existing = this.db.prepare(
      "SELECT * FROM requests WHERE tenant_id=? AND principal_id=? AND request_id=?",
    ).get(tenant, principal, requestId) as RequestRow | undefined;
    if (existing) return existing;
    this.db.prepare(
      "INSERT INTO requests(tenant_id,principal_id,request_id,request_hash,state,response) VALUES(?,?,?,?,?,NULL)",
    ).run(tenant, principal, requestId, hash, "IN_PROGRESS");
    return "ADMITTED";
  }

  getRequest(tenant: string, principal: string, requestId: string): RequestRow | null {
    return (this.db.prepare(
      "SELECT * FROM requests WHERE tenant_id=? AND principal_id=? AND request_id=?",
    ).get(tenant, principal, requestId) as RequestRow | undefined) ?? null;
  }

  finishRequest(tenant: string, principal: string, requestId: string, response: Buffer): void {
    this.db.prepare(
      "UPDATE requests SET state='DONE',response=? WHERE tenant_id=? AND principal_id=? AND request_id=?",
    ).run(response, tenant, principal, requestId);
  }

  abandonedRequests(): RequestRow[] {
    return this.db.prepare("SELECT * FROM requests WHERE state='IN_PROGRESS'").all() as unknown as RequestRow[];
  }

  setReference(receiptId: string, revision: number, objectHash: string): void {
    this.db.prepare(
      "INSERT INTO references_to_objects(receipt_id,revision,object_hash) VALUES(?,?,?) ON CONFLICT DO NOTHING",
    ).run(receiptId, revision, objectHash);
  }
}
