#!/usr/bin/env node
const { main } = require("../dist/main.js");
main(process.argv.slice(2)).then((code) => process.exit(code)).catch((e) => {
  process.stderr.write("fatal: " + (e && e.message ? e.message : String(e)) + "\n");
  process.exit(8);
});
