import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const forbidden = /\b(?:codex_command|use_codex_sandbox)\b/i;

function jsFiles(dir) {
  return readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".js") && entry.name !== "no-codex-deps.test.js")
    .map((entry) => join(dir, entry.name));
}

test("source has no Codex CLI sandbox dependency artifacts", () => {
  for (const file of [...jsFiles("src"), ...jsFiles("test")]) {
    const text = readFileSync(file, "utf8");
    assert.equal(forbidden.test(text), false, `${file} contains a forbidden Codex CLI dependency artifact`);
  }
});
