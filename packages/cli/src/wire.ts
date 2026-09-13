/**
 * CLI wiring — build a BondClient from a config file + env secrets. Fixture
 * adapters are honest labeled simulation; "installed" mode resolves to the
 * native stubs which fail closed with capability diagnostics.
 */

import { createPrivateKey, createPublicKey, sign as nodeSign } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  AuthContext, BondError, Config, J, PolicyPin, TrustFile, parseJsonBytes,
} from "@latticeag/bond-core";
import {
  BondClient, envSecrets, loadConfigFile, loadTrustFile, systemClock, PortCaller,
} from "@latticeag/bond-sdk";
import {
  makeFixtureAdapters, callFixture, FixtureAdapterSet, fixedClock,
  restoreWorld, snapshotWorld, WorldSnapshot,
} from "@latticeag/bond-adapters-fixture";

export interface Wired {
  client: BondClient;
  fixtures: FixtureAdapterSet | null;
  missing: string[];
  close: () => void;
}

const NATIVE_REQUIRED: Record<string, string> = {
  bedrock: "BEDROCK_EMBEDDED_EVALUATOR_UNAVAILABLE",
  mint: "MINT_EXCLUSIVE_HOLD_UNAVAILABLE",
  vekrevert: "VEKREVERT_CONDITIONAL_INVERSE_UNAVAILABLE",
  trellis: "TRELLIS_BOUND_RUN_UNAVAILABLE",
  executor: "EXECUTOR_FENCE_UNAVAILABLE",
};

export function wireClient(configPath: string): Wired {
  const config = loadConfigFile(configPath);
  const trust = loadTrustFile(config.trust_file);
  const secrets = envSecrets();
  const seed = secrets.seed(config.signing_key_ref);
  const pub = publicKeyOf(seed);
  const keyId = trust.keys.find((k) => k.public_key_hex === pub)?.key_id;
  if (!keyId) throw new BondError("UNTRUSTED_KEY", "signing key not in trust file");

  const missing: string[] = [];
  for (const id of ["bedrock", "mint", "vekrevert", "trellis", "executor"] as const) {
    const a = config.adapters.find((x) => x.id === id);
    if (!a || a.mode !== "fixture") missing.push(NATIVE_REQUIRED[id]!);
  }

  let fixtures: FixtureAdapterSet | null = null;
  let ports: PortCaller;
  if (missing.length === 0) {
    const signer = (m: Uint8Array) => signWithSeed(seed, m);
    fixtures = makeFixtureAdapters({
      keyId, signer, clock: fixedClock(new Date().toISOString()),
      runId: "run-cli", hostId: "host-cli",
      buildHash: config.adapters[0]!.build_hash,
    });
    const set = fixtures;
    // The simulated world models external services: it survives across the
    // CLI's separate processes in a sibling file, never inside the journal.
    const worldPath = join(dirname(config.data_dir), "bond.fixture-world.json");
    if (existsSync(worldPath)) {
      try {
        restoreWorld(set, JSON.parse(readFileSync(worldPath, "utf8")) as WorldSnapshot);
      } catch { /* a corrupt world file fails closed: adapters start empty */ }
    }
    const save = () =>
      writeFileSync(worldPath, JSON.stringify(snapshotWorld(set)), { mode: 0o600 });
    ports = {
      call: async (p, i) => {
        const r = await callFixture(set, p, i);
        save();
        return r;
      },
      bindAction: (id, h) => { set.trellis.bindAction(id, h); save(); },
      registerTrigger: (ah, th) => { set.mint.registerTrigger(ah, th); save(); },
    };
  } else {
    // Any non-fixture capability fails closed: ports answer UNKNOWN and the
    // doctor surface reports each missing diagnostic.
    ports = { call: () => Promise.resolve({ status: "UNKNOWN" }) };
  }

  const ctx: AuthContext = {
    tenant_id: config.tenant_id, principal_id: config.principal_id,
    scopes: [config.scope_id],
    roles: ["operator", "agent", "auditor", "publisher"],
  };

  let client!: BondClient;
  client = new BondClient({
    config, trust, secrets, clock: systemClock(), ports,
    activePin: () => installedPin(client),
    capabilityCheck: () => missing,
    authContext: ctx,
  });
  if (fixtures) {
    // This process's writer fence supersedes any restored world value.
    fixtures.store.currentFence = client.coordinator.fence;
  }
  return { client, fixtures, missing, close: () => client.close() };
}

/**
 * The operator-installed policy pin is journaled at first prepare (the CLI
 * frontend installs the pin it was configured with); afterwards all actions
 * must match it or fail PIN_MISMATCH.
 */
function installedPin(client: BondClient): PolicyPin {
  const raw = client.journal.getMetadata("active_policy_pin");
  if (!raw) throw new BondError("PIN_MISMATCH", "no policy installed");
  return parseJsonBytes(Buffer.from(raw)) as PolicyPin;
}

export function ensureActivePin(client: BondClient, pin: PolicyPin): void {
  if (!client.journal.getMetadata("active_policy_pin")) {
    client.journal.setMetadata("active_policy_pin", Buffer.from(J(pin), "utf8"));
  }
}

function signWithSeed(seedHex: string, m: Uint8Array): Buffer {
  const key = createPrivateKey({
    key: Buffer.from("302e020100300506032b657004220420" + seedHex, "hex"),
    format: "der", type: "pkcs8",
  });
  return nodeSign(null, Buffer.from(m), key);
}

function publicKeyOf(seedHex: string): string {
  const key = createPrivateKey({
    key: Buffer.from("302e020100300506032b657004220420" + seedHex, "hex"),
    format: "der", type: "pkcs8",
  });
  return createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
}
