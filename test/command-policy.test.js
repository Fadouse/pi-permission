import test from "node:test";
import assert from "node:assert/strict";
import { assessCommand, commandMatchesPrefix, isBannedPrefixRule, isDangerousCommand, isTrustedCommand, parseCommand } from "../src/command-policy.js";

test("parses simple shell segments", () => {
  const parsed = parseCommand("git status && ls -la | grep src; pwd");
  assert.equal(parsed.complex, false);
  assert.deepEqual(parsed.commands, [["git", "status"], ["ls", "-la"], ["grep", "src"], ["pwd"]]);
});

test("detects complex shell syntax for prefix safety", () => {
  assert.equal(parseCommand("cat <<EOF\nsecret\nEOF").complex, true);
  assert.equal(commandMatchesPrefix("cargo test > out", ["cargo", "test"]), false);
});

test("trusted commands match Codex-style read-only set", () => {
  assert.equal(isTrustedCommand("ls -la && git diff"), true);
  assert.equal(isTrustedCommand("find . -name '*.js'"), false, "globs make prefix/trust matching complex");
  assert.equal(isTrustedCommand("find . -delete"), false);
  assert.equal(isTrustedCommand("git reset --hard"), false);
});

test("dangerous command heuristics catch destructive operations", () => {
  assert.equal(isDangerousCommand("rm -rf build"), true);
  assert.equal(isDangerousCommand("sudo cat /etc/shadow"), true);
  assert.equal(isDangerousCommand("git clean -fd"), true);
});

test("prefix approvals match only non-complex token prefixes", () => {
  assert.equal(commandMatchesPrefix("cargo test --all", ["cargo", "test"]), true);
  assert.equal(commandMatchesPrefix("cargo build", ["cargo", "test"]), false);
  assert.equal(commandMatchesPrefix("cargo test > out", ["cargo", "test"]), false);
});

test("prefix approvals do not match shell compounds", () => {
  assert.equal(commandMatchesPrefix("cargo test && rm -rf build", ["cargo", "test"]), false);
  assert.equal(commandMatchesPrefix("rm -rf build; cargo test", ["cargo", "test"]), false);
  const result = assessCommand("cargo test && rm -rf build", [{ rule: ["cargo", "test"], scope: "project" }]);
  assert.equal(result.matchedPrefix, undefined);
  assert.equal(result.dangerous, true);
});

test("bans broad interpreter and dangerous persistent prefixes", () => {
  assert.equal(isBannedPrefixRule(["python3", "-c"]), true);
  assert.equal(isBannedPrefixRule(["git"]), true);
  assert.equal(isBannedPrefixRule(["cargo", "test"]), false);
});

test("assessment returns matching prefix", () => {
  const result = assessCommand("cargo test unit", [{ rule: ["cargo", "test"], scope: "project" }]);
  assert.equal(result.matchedPrefix.scope, "project");
});
