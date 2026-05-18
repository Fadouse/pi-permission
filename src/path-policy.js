import { existsSync, realpathSync } from "node:fs";
import { dirname, resolve, relative, isAbsolute } from "node:path";
import { homedir, tmpdir } from "node:os";

export function expandPath(input, cwd = process.cwd()) {
  let p = String(input || "");
  if (p.startsWith("@")) p = p.slice(1);
  if (p === "~" || p.startsWith("~/")) p = resolve(homedir(), p.slice(2));
  return isAbsolute(p) ? resolve(p) : resolve(cwd, p);
}

function nearestExisting(path) {
  let cur = path;
  while (!existsSync(cur)) {
    const parent = dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return cur;
}

export function realish(path) {
  const existing = nearestExisting(path);
  const resolvedExisting = existsSync(existing) ? realpathSync.native(existing) : existing;
  return resolve(resolvedExisting, relative(existing, path));
}

export function isWithin(path, root) {
  const rel = relative(root, path);
  return rel === "" || (!!rel && !rel.startsWith("..") && !isAbsolute(rel));
}

export function writableRoots(cwd, config) {
  const roots = [expandPath(cwd, cwd), ...(config.add_dir || []).map((p) => expandPath(p, cwd))];
  if (config.sandbox_mode === "workspace-write" && config.allow_tmp_write !== false) roots.push(tmpdir(), "/tmp");
  return [...new Set(roots.map(realish))];
}

export function matchesPattern(path, patterns = []) {
  return patterns.some((pattern) => {
    if (!pattern) return false;
    if (pattern instanceof RegExp) return pattern.test(path);
    const s = String(pattern);
    if (s.startsWith("re:")) return new RegExp(s.slice(3)).test(path);
    return path.includes(s);
  });
}

export function checkPathAccess({ path, cwd, config, access }) {
  const abs = realish(expandPath(path, cwd));
  if (access === "read" && matchesPattern(abs, config.deny_read_patterns)) {
    return { allowed: false, reason: `read denied by configured pattern: ${path}`, path: abs };
  }
  if (access === "write" && matchesPattern(abs, config.deny_write_patterns)) {
    return { allowed: false, reason: `write denied by configured pattern: ${path}`, path: abs };
  }
  if (access === "read") return { allowed: true, path: abs };
  if (config.sandbox_mode === "danger-full-access") return { allowed: true, path: abs };
  if (config.sandbox_mode === "read-only") return { allowed: false, reason: "read-only sandbox blocks file writes", path: abs };
  const roots = writableRoots(cwd, config);
  if (roots.some((root) => isWithin(abs, root))) return { allowed: true, path: abs };
  return { allowed: false, reason: `workspace-write sandbox allows writes only under: ${roots.join(", ")}`, path: abs };
}
