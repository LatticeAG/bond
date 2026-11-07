const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { makeTrust, makeConfig } = require("./harness.cjs");
const { F } = require("../../fixtures/f.js");

test("CLI JSON reports invalid trust key ID details", () => {
  const dir = fs.mkdtempSync(path.join(process.cwd(), ".bond-cli-test-"));
  try {
    const trust = makeTrust();
    trust.keys[0].key_id = "bnk_clikey0000000000001";
    const trustPath = path.join(dir, "trust.json");
    fs.writeFileSync(trustPath, JSON.stringify(trust));
    const result = spawnSync(process.execPath,
      ["packages/cli/bin/bond.js", "verify", "unused.json", "--trust", trustPath, "--json"],
      { encoding: "utf8" });
    assert.equal(result.status, 2);
    assert.deepEqual(JSON.parse(result.stdout),
      { error: { code: "SCHEMA", message: "bad bnk id", retryable: false } });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI fixture clock permits the golden action and preserves real deadlines", () => {
  const dir = fs.mkdtempSync(path.join(process.cwd(), ".bond-cli-test-"));
  try {
    const trustPath = path.join(dir, "trust.json");
    fs.writeFileSync(trustPath, JSON.stringify(makeTrust()));
    fs.writeFileSync(path.join(dir, "action.json"), JSON.stringify(F.action));
    fs.writeFileSync(path.join(dir, "paper.json"), JSON.stringify(F.paper));
    // The golden paper is signed by the fixture key ID.
    const trust = F.trust;
    fs.writeFileSync(trustPath, JSON.stringify(trust));
    const config = makeConfig(path.join(dir, "data"));
    config.trust_file = trustPath;
    config.adapters = ["bedrock", "executor", "mint", "trellis", "vekrevert"].map(id =>
      ({ id, mode: "fixture", build_hash: F.action.adapter_build, binding: id }));
    const configPath = path.join(dir, "config.json");
    const run = () => spawnSync(process.execPath, [path.resolve("packages/cli/bin/bond.js"),
      "--config", configPath, "prepare", path.join(dir, "action.json"), "--paper",
      path.join(dir, "paper.json"), "--request-id", F.q, "--run", F.run, "--json"],
      { encoding: "utf8", env: { ...process.env, BOND_SEED_MAIN: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" } });
    config.fixture_clock = F.action.execute_before;
    fs.writeFileSync(configPath, JSON.stringify(config));
    const expired = run();
    assert.equal(expired.status, 4);
    assert.equal(JSON.parse(expired.stdout).code, "DEADLINE");
    config.fixture_clock = F.t;
    config.data_dir = path.join(dir, "fresh-data");
    fs.writeFileSync(configPath, JSON.stringify(config));
    const result = run();
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(JSON.parse(result.stdout).phase, "READY");
    assert.equal(result.stderr, "");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI suppresses only the SQLite experimental warning", () => {
  const result = spawnSync(process.execPath, ["-e", `
    process.emitWarning("other warning", "ExperimentalWarning");
    process.argv = [process.execPath, "bond", "unknown"];
    require("./packages/cli/bin/bond.js");
  `], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /other warning/);
  assert.match(result.stderr, /unknown/);
  assert.doesNotMatch(result.stderr, /SQLite is an experimental feature/);
});
