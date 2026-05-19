import test from "node:test";
import assert from "node:assert/strict";
import { bubblewrapArgs, sandboxBackend, sandboxFailureText } from "../src/sandbox.js";

const cwd = process.cwd();

test("uses supported native backend", () => {
  const backend = sandboxBackend({ sandbox_mode: "workspace-write" });
  assert.ok(["bubblewrap", "seatbelt", "unsupported"].includes(backend));
});

test("bubblewrap read-only mounts host root read-only", () => {
  const args = bubblewrapArgs({ sandbox_mode: "read-only", network_access: false }, cwd, "true");
  assert.deepEqual(args.slice(0, 6), ["--die-with-parent", "--unshare-all", "--new-session", "--ro-bind", "/", "/"]);
  assert.equal(args.includes("--bind"), false);
  assert.equal(args.includes("--share-net"), false);
});

test("bubblewrap workspace-write binds cwd writable", () => {
  const args = bubblewrapArgs({ sandbox_mode: "workspace-write", network_access: true, add_dir: [] }, cwd, "true");
  assert.equal(args.includes("--share-net"), true);
  const bindIndex = args.indexOf("--bind");
  assert.notEqual(bindIndex, -1);
  assert.equal(args[bindIndex + 1], cwd);
  assert.equal(args[bindIndex + 2], cwd);
});

test("unsupported platforms fail closed message", () => {
  assert.match(sandboxFailureText({ sandbox_mode: "read-only" }), /sandbox|danger-full-access/);
});
