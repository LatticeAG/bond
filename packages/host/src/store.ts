/**
 * Certificate-host store — in-memory realization of the §6.4 persistence
 * shape: packages / package bytes / nonces / notices. Immutable once written.
 */

import { BondError, Hash, Head, Package, Signed, Notice, H, J } from "@latticeag/bond-core";

export interface StoredPackage {
  receiptId: string;
  revision: number;
  receiptHash: Hash;
  packageHash: Hash;
  bytes: Buffer;
}

export interface StoredNonce {
  keyId: string;
  requestId: string;
  requestHash: Hash;
  response: { status: number; body: unknown };
}

export interface StoredNotice {
  receiptId: string;
  revision: number;
  hash: Hash;
  notice: Signed<Notice>;
}

export class HostStore {
  /** receipt_id -> ordered packages by revision. */
  private packages = new Map<string, StoredPackage[]>();
  /** tenant:key:request_id -> stored nonce record. */
  private nonces = new Map<string, StoredNonce>();
  /** receipt_id -> ordered notices. */
  private notices = new Map<string, StoredNotice[]>();
  /** receipt_id -> "ACTIVE" | "WITHDRAWN". */
  private hosting = new Map<string, "ACTIVE" | "WITHDRAWN">();
  /** receipt_id -> tenant that published it (lineage ownership). */
  private tenants = new Map<string, string>();
  /** receipt_id -> action principal_id (owner principal). */
  private principals = new Map<string, string>();

  private nonceKey(tenant: string, keyId: string, requestId: string): string {
    return `${tenant}:${keyId}:${requestId}`;
  }

  getNonce(tenant: string, keyId: string, requestId: string): StoredNonce | null {
    return this.nonces.get(this.nonceKey(tenant, keyId, requestId)) ?? null;
  }

  putNonce(tenant: string, n: StoredNonce): void {
    this.nonces.set(this.nonceKey(tenant, n.keyId, n.requestId), n);
  }

  packagesOf(receiptId: string): StoredPackage[] {
    return this.packages.get(receiptId) ?? [];
  }

  /** Current stored max revision (0 when absent). */
  maxRevision(receiptId: string): number {
    const l = this.packagesOf(receiptId);
    return l.length ? l[l.length - 1]!.revision : 0;
  }

  packageAt(receiptId: string, revision: number): StoredPackage | null {
    return this.packagesOf(receiptId).find((p) => p.revision === revision) ?? null;
  }

  appendPackage(tenant: string, principal: string, receiptId: string, revision: number,
    receiptHash: Hash, pkgBytes: Buffer): void {
    const pkg: StoredPackage = {
      receiptId, revision, receiptHash,
      packageHash: H(pkgBytes), bytes: pkgBytes,
    };
    const l = this.packages.get(receiptId);
    if (l) {
      l.push(pkg);
      l.sort((a, b) => a.revision - b.revision);
    } else {
      this.packages.set(receiptId, [pkg]);
    }
    if (!this.hosting.has(receiptId)) this.hosting.set(receiptId, "ACTIVE");
    this.tenants.set(receiptId, tenant);
    this.principals.set(receiptId, principal);
  }

  tenantOf(receiptId: string): string | null {
    return this.tenants.get(receiptId) ?? null;
  }

  principalOf(receiptId: string): string | null {
    return this.principals.get(receiptId) ?? null;
  }

  hostingOf(receiptId: string): "ACTIVE" | "WITHDRAWN" | null {
    return this.hosting.get(receiptId) ?? null;
  }

  withdraw(receiptId: string): void {
    if (!this.hosting.has(receiptId)) throw new BondError("NOT_FOUND");
    this.hosting.set(receiptId, "WITHDRAWN");
  }

  noticesOf(receiptId: string): StoredNotice[] {
    return this.notices.get(receiptId) ?? [];
  }

  noticesHead(receiptId: string): Head | null {
    const l = this.noticesOf(receiptId);
    return l.length ? { seq: l[l.length - 1]!.revision, hash: l[l.length - 1]!.hash } : null;
  }

  appendNotice(receiptId: string, notice: Signed<Notice>): void {
    const l = this.notices.get(receiptId) ?? [];
    l.push({ receiptId, revision: notice.body.revision, hash: notice.hash, notice });
    l.sort((a, b) => a.revision - b.revision);
    this.notices.set(receiptId, l);
  }
}
