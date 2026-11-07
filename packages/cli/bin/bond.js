#!/usr/bin/env node
// Node 22 emits this warning when the built-in SQLite module is loaded.
const emitWarning = process.emitWarning;
process.emitWarning = function (warning, ...args) {
  const type = typeof args[0] === "object" ? args[0]?.type : args[0];
  if (warning === "SQLite is an experimental feature and might change at any time" &&
      type === "ExperimentalWarning") return;
  return emitWarning.call(this, warning, ...args);
};
const { main } = require("../dist/main.js");
main(process.argv.slice(2)).then((code) => process.exit(code)).catch((e) => {
  process.stderr.write("fatal: " + (e && e.message ? e.message : String(e)) + "\n");
  process.exit(8);
});
