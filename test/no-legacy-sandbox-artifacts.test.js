import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const legacyName = "co" + "dex";
const forbidden = new RegExp(`\\b(?:${legacyName}_command|use_${legacyName}_sandbox)\\b`, "i");

function jsFiles(dir) {
  return readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".js") && entry.name !== "no-legacy-sandbox-artifacts.test.js")
    .map((entry) => join(dir, entry.name));
}

test("source has no legacy sandbox dependency artifacts", () => {
  for (const file of [...jsFiles("src"), ...jsFiles("test")]) {
    const text = readFileSync(file, "utf8");
    assert.equal(forbidden.test(text), false, `${file} contains a forbidden legacy sandbox dependency artifact`);
  }
});
