import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, symlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkPathAccess, isWithin, realish, writableRoots } from "../src/path-policy.js";

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "pi-perm-"));
  const outside = mkdtempSync(join(tmpdir(), "pi-perm-out-"));
  mkdirSync(join(root, "sub"));
  symlinkSync(outside, join(root, "escape"), "dir");
  return { root, outside, cleanup: () => { rmSync(root, { recursive: true, force: true }); rmSync(outside, { recursive: true, force: true }); } };
}

test("workspace-write allows cwd writes", () => {
  const f = fixture();
  try {
    const config = { sandbox_mode: "workspace-write", add_dir: [] };
    assert.equal(checkPathAccess({ path: "sub/file.txt", cwd: f.root, config, access: "write" }).allowed, true);
  } finally { f.cleanup(); }
});

test("read-only blocks writes", () => {
  const f = fixture();
  try {
    const config = { sandbox_mode: "read-only", add_dir: [] };
    const decision = checkPathAccess({ path: "file.txt", cwd: f.root, config, access: "write" });
    assert.equal(decision.allowed, false);
    assert.match(decision.reason, /read-only/);
  } finally { f.cleanup(); }
});

test("workspace-write blocks symlink escapes", () => {
  const f = fixture();
  try {
    const config = { sandbox_mode: "workspace-write", add_dir: [], allow_tmp_write: false };
    const decision = checkPathAccess({ path: "escape/file.txt", cwd: f.root, config, access: "write" });
    assert.equal(decision.allowed, false);
  } finally { f.cleanup(); }
});

test("add_dir allows additional writable root", () => {
  const f = fixture();
  try {
    const config = { sandbox_mode: "workspace-write", add_dir: [f.outside] };
    const decision = checkPathAccess({ path: join(f.outside, "file.txt"), cwd: f.root, config, access: "write" });
    assert.equal(decision.allowed, true);
    assert.equal(writableRoots(f.root, config).some((root) => isWithin(realish(join(f.outside, "file.txt")), root)), true);
  } finally { f.cleanup(); }
});

test("workspace-write path policy mirrors temp write allowance", () => {
  const f = fixture();
  try {
    const enabled = { sandbox_mode: "workspace-write", add_dir: [], allow_tmp_write: true };
    const disabled = { sandbox_mode: "workspace-write", add_dir: [], allow_tmp_write: false };
    assert.equal(checkPathAccess({ path: join(tmpdir(), "pi-perm-temp-file"), cwd: f.root, config: enabled, access: "write" }).allowed, true);
    assert.equal(checkPathAccess({ path: join(tmpdir(), "pi-perm-temp-file"), cwd: f.root, config: disabled, access: "write" }).allowed, false);
  } finally { f.cleanup(); }
});
