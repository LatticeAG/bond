const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { makeTrust } = require("./harness.cjs");

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
