/**
 * Storage migration tool — COPY_AND_VERIFY only (§7.4). Refuses while any
 * action has unresolved dependency work or is not terminally closed: a
 * migration mid-flight could strand an operation the copy cannot continue.
 */

import {
  BondError, MigrationFile, deserializeState, pendingOps, parseJsonBytes,
  vSigned, vEntryBody, vReceiptBody, PACKAGE_LIMITS, ZERO_HASH,
} from "@latticeag/bond-core";
import { Journal } from "./journal.js";
import { cpSync } from "node:fs";

export interface MigrateResult {
  migrated: boolean;
  source_modified: boolean;
}

/**
 * Verify every stored action's entry chain (seq/previous_hash/hash linkage)
 * and receipt chain, require every action CLOSED with no pending operations,
 * then copy the journal directory verbatim. The source is never modified.
 */
export function migrateJournal(sourceDir: string, targetDir: string, _mig: MigrationFile): MigrateResult {
  const j = new Journal(sourceDir);
  try {
    for (const row of j.pendingActions()) {
      const st = deserializeState(
        JSON.parse(Buffer.from(row.projection).toString("utf8")) as Record<string, unknown>);
      if (pendingOps(st).length > 0 || st.phase !== "CLOSED") {
        throw new BondError("BAD_STATE", "pending or non-terminal actions block migration");
      }
      // Verify the entry chain linkage without trust pins: structural
      // integrity is the migration check; trust verification is verify's job.
      let prev = ZERO_HASH;
      let seq = 0;
      for (const e of j.getEntries(row.action_id)) {
        const signed = vSigned(parseJsonBytes(e.canonical, PACKAGE_LIMITS), "entry", vEntryBody);
        if (signed.hash !== e.hash || signed.body.previous_hash !== prev ||
          signed.body.seq !== e.seq || e.seq !== seq + 1) {
          throw new BondError("CHAIN_INVALID", "entry chain corrupt");
        }
        prev = e.hash;
        seq = e.seq;
      }
      let prevR: string | null = null;
      let rev = 0;
      for (const r of j.getReceipts(row.action_id)) {
        const signed = vSigned(
          parseJsonBytes(r.canonical, PACKAGE_LIMITS), "receipt", vReceiptBody);
        if (signed.hash !== r.hash || signed.body.previous_receipt_hash !== prevR ||
          r.revision !== rev + 1) {
          throw new BondError("CHAIN_INVALID", "receipt chain corrupt");
        }
        prevR = r.hash;
        rev = r.revision;
      }
    }
    cpSync(sourceDir, targetDir, { recursive: true });
    return { migrated: true, source_modified: false };
  } finally {
    j.close();
  }
}
