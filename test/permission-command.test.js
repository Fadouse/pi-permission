import test from "node:test";
import assert from "node:assert/strict";
import { parsePermissionCommand, splitPermissionArgs } from "../src/permission-command.js";

test("permission command enables persistent auto_review preset", () => {
  const action = parsePermissionCommand("auto-review openai/gpt-4.1-mini");
  assert.equal(action.type, "update");
  assert.deepEqual(action.updater({}), {
    sandbox_mode: "workspace-write",
    approval_policy: "on-request",
    approvals_reviewer: "auto_review",
    network_access: false,
    auto_review_model: "openai/gpt-4.1-mini"
  });
});

test("permission command clears dedicated auto_review model", () => {
  const action = parsePermissionCommand("model clear");
  assert.deepEqual(action.updater({ auto_review_model: "openai/gpt-4.1-mini" }), {});
});

test("permission command parses raw key value settings", () => {
  const action = parsePermissionCommand("set sandbox=read-only approval=never reviewer=user network=false add_dir=../a,../b");
  assert.deepEqual(action.updater({}), {
    sandbox_mode: "read-only",
    approval_policy: "never",
    approvals_reviewer: "user",
    network_access: false,
    add_dir: ["../a", "../b"]
  });
});

test("permission command appends add-dir entries", () => {
  const action = parsePermissionCommand("add-dir ../shared,../cache");
  assert.deepEqual(action.updater({ add_dir: ["../shared"] }), { add_dir: ["../shared", "../cache"] });
});

test("permission argument splitter supports quoted paths", () => {
  assert.deepEqual(splitPermissionArgs('add-dir "../shared dir" ../cache'), ["add-dir", "../shared dir", "../cache"]);
});
