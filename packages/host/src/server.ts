/**
 * Loopback HTTP server for the certificate host — binds 127.0.0.1 only.
 * Deployment to the real Workers/DO surface is `deployHosted` (stub).
 */

import { createServer, Server } from "node:http";
import { BondError, TrustFile } from "@latticeag/bond-core";
import { HostStore } from "./store.js";
import { createHostHandler, HostRequest, HostResponse } from "./handler.js";

export interface HostedServer {
  server: Server;
  port: () => number;
  close: () => Promise<void>;
}

export async function serveLoopback(deps: {
  store: HostStore; trust: TrustFile; now?: () => string; maxPackageBytes?: number;
  port?: number; roles?: Record<string, string[]>;
}): Promise<HostedServer & { handle: (r: HostRequest) => HostResponse }> {
  const store = deps.store;
  const { handle, grantRoles } = createHostHandler({
    store, trust: deps.trust,
    now: deps.now ?? (() => new Date().toISOString()),
    maxPackageBytes: deps.maxPackageBytes ?? 8388608,
  });
  for (const [k, roles] of Object.entries(deps.roles ?? {})) grantRoles(k, roles);
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) {
        if (typeof v === "string") headers[k.toLowerCase()] = v;
      }
      const resp = handle({
        method: (req.method === "POST" ? "POST" : "GET"),
        // Raw path; the handler rejects encoded slashes.
        path: url.pathname,
        // Preserve raw query order/duplicates for strict parsing.
        query: url.search.startsWith("?") ? url.search.slice(1) : "",
        headers,
        body: chunks.length ? Buffer.concat(chunks) : null,
      });
      res.writeHead(resp.status, { "content-type": "application/json", ...resp.headers });
      res.end(JSON.stringify(resp.body));
    });
  });
  await new Promise<void>((resolve) => server.listen(deps.port ?? 0, "127.0.0.1", resolve));
  return {
    server,
    handle,
    port: () => (server.address() as { port: number }).port,
    close: () => new Promise((r) => server.close(() => r())),
  };
}

/**
 * Deployment of the real hosted surface (Cloudflare Workers + per-tenant
 * Durable Object index) is outside the OSS core. Fail closed with a pointer.
 */
export function deployHosted(): never {
  const e = new Error(
    "Hosted certificate deployment (Workers ingress + per-tenant DO index) is not " +
    "part of the OSS core build. See BOND_SPEC_EXTREME.md §6.4 and " +
    "https://devin.ai/support for the hosted offering.");
  e.name = "NotImplemented";
  throw e;
}
