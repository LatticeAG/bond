/**
 * BondClient — host-facing facade. `call(method, input)` dispatches to the
 * coordinator; constructor wires config, trust, adapters, journal, clock.
 */

import { readFileSync } from "node:fs";
import {
  AuthContext, BondError, Calls, Config, PolicyPin, Result,
  TrustFile, parseJsonBytes, vConfig, vTrustFile, CONTROL_LIMITS, seedSigner,
  publicKeyHexFromSeed,
} from "@latticeag/bond-core";
import { Journal } from "./journal.js";
import { Coordinator, Clock, PortCaller, systemClock } from "./coordinator.js";

export interface SecretProvider {
  /** Resolve a named secret reference to a 32-byte Ed25519 seed (hex). */
  seed(ref: string): string;
}

/** Env-var secret provider for tests/dev: ref name -> BOND_SEED_<NAME>. */
export function envSecrets(prefix = "BOND_SEED_"): SecretProvider {
  return {
    seed(ref: string): string {
      const v = process.env[prefix + ref.toUpperCase().replace(/[^A-Z0-9]/g, "_")];
      if (!v || !/^[0-9a-f]{64}$/i.test(v)) {
        throw new BondError("UNAUTHORIZED", `secret ref ${ref} unavailable`);
      }
      return v.toLowerCase();
    },
  };
}

export function fileSecrets(map: Record<string, string>): SecretProvider {
  return {
    seed(ref: string): string {
      const v = map[ref];
      if (!v || !/^[0-9a-f]{64}$/i.test(v)) {
        throw new BondError("UNAUTHORIZED", `secret ref ${ref} unavailable`);
      }
      return v.toLowerCase();
    },
  };
}

export interface ClientDeps {
  config: Config;
  trust: TrustFile;
  secrets: SecretProvider;
  clock: Clock;
  ports: PortCaller;
  activePin: () => PolicyPin;
  capabilityCheck: () => string[];
  authContext: AuthContext;
  onDispatchAdmitted?: (actionId: string) => Promise<void> | void;
}

export class BondClient {
  readonly coordinator: Coordinator;
  readonly journal: Journal;
  private ctx: AuthContext;

  constructor(deps: ClientDeps) {
    this.journal = new Journal(deps.config.data_dir);
    const seed = deps.secrets.seed(deps.config.signing_key_ref);
    const signer = seedSigner(seed);
    const keyId = deps.trust.keys.find((k) =>
      k.public_key_hex === publicKeyHexFromSeed(seed)
    )?.key_id;
    if (!keyId) throw new BondError("UNTRUSTED_KEY", "signing key not in trust file");
    this.ctx = deps.authContext;
    this.coordinator = new Coordinator({
      journal: this.journal, config: deps.config, trust: deps.trust,
      signer, keyId, clock: deps.clock, ports: deps.ports,
      activePin: deps.activePin, capabilityCheck: deps.capabilityCheck,
      onDispatchAdmitted: deps.onDispatchAdmitted,
    });
  }

  async recover(): Promise<{ quarantined: string[]; stopAttempted: string[] }> {
    return this.coordinator.recover();
  }

  async call<M extends keyof Calls>(
    method: M, input: Calls[M]["input"],
  ): Promise<Result<Calls[M]["output"]>> {
    const c = this.coordinator;
    switch (method) {
      case "doctor": return c.doctor(this.ctx) as Promise<Result<Calls[M]["output"]>>;
      case "prepare": return c.prepare(this.ctx, input as never) as never;
      case "execute": return c.execute(this.ctx, input as never) as never;
      case "cancel": return c.cancel(this.ctx, input as never) as never;
      case "accept": return c.accept(this.ctx, input as never) as never;
      case "reject": return c.reject(this.ctx, input as never) as never;
      case "stop": return c.stop(this.ctx, input as never) as never;
      case "reconcile": return c.reconcile(this.ctx, input as never) as never;
      case "inspect": return Promise.resolve(c.inspect(this.ctx, input as never)) as never;
      case "attach": return c.attach(this.ctx, input as never) as never;
      case "export": return Promise.resolve(c.export(this.ctx, input as never)) as never;
      case "verify": return Promise.resolve(c.verify(this.ctx, input as never)) as never;
      default: throw new BondError("SCHEMA", "unknown method");
    }
  }

  close(): void {
    this.journal.close();
  }
}

export function loadConfigFile(path: string): Config {
  const x = parseJsonBytes(readFileSync(path), CONTROL_LIMITS);
  return vConfig(x);
}

export function loadTrustFile(path: string): TrustFile {
  const x = parseJsonBytes(readFileSync(path), CONTROL_LIMITS);
  return vTrustFile(x);
}
