import test from "node:test";
import assert from "node:assert/strict";
import { flagsConfig, mergeConfig } from "../src/config.js";

test("config merges defaults, project and flags with additive add_dir", () => {
  const cfg = mergeConfig(
    { sandbox_mode: "read-only", approval_policy: "never", add_dir: ["a"] },
    { sandbox_mode: "workspace-write", add_dir: ["b"] },
    { approval_policy: "untrusted", add_dir: "c,d" }
  );
  assert.equal(cfg.sandbox_mode, "workspace-write");
  assert.equal(cfg.approval_policy, "untrusted");
  assert.deepEqual(cfg.add_dir, ["a", "b", "c", "d"]);
});

test("unless-trusted aliases to untrusted", () => {
  assert.equal(mergeConfig({ approval_policy: "unless-trusted" }).approval_policy, "untrusted");
});

test("auto_review normalizes reviewer aliases", () => {
  const cfg = mergeConfig({ approvals_reviewer: "auto-review" });
  assert.equal(cfg.approvals_reviewer, "auto_review");
});

test("auto-review preset config matches reviewer mode", () => {
  const cfg = mergeConfig({ sandbox_mode: "workspace-write", approval_policy: "on-request", approvals_reviewer: "auto_review", network_access: false });
  assert.equal(cfg.sandbox_mode, "workspace-write");
  assert.equal(cfg.approval_policy, "on-request");
  assert.equal(cfg.approvals_reviewer, "auto_review");
  assert.equal(cfg.network_access, false);
});

test("auto-review flag maps to workspace-write on-request auto_review", () => {
  const pi = {
    getFlag(name) {
      return name === "auto-review";
    }
  };
  assert.deepEqual(flagsConfig(pi), {
    sandbox_mode: "workspace-write",
    approval_policy: "on-request",
    approvals_reviewer: "auto_review",
    network_access: false
  });
});
