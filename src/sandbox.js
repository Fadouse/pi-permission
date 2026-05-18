import { spawn } from "node:child_process";
import { access } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import { expandPath, realish } from "./path-policy.js";

export async function hasCommand(command) {
  const path = process.env.PATH || "";
  const exts = process.platform === "win32" ? [".exe", ".cmd", ".bat", ""] : [""];
  for (const dir of path.split(process.platform === "win32" ? ";" : ":")) {
    for (const ext of exts) {
      try { await access(`${dir}/${command}${ext}`); return true; } catch {}
    }
  }
  return false;
}

export function sandboxBackend(config = {}) {
  if (config.sandbox_mode === "danger-full-access") return "none";
  if (process.platform === "linux") return "bubblewrap";
  if (process.platform === "darwin") return "seatbelt";
  return "unsupported";
}

export async function isSandboxAvailable(config = {}) {
  const backend = sandboxBackend(config);
  if (backend === "none") return true;
  if (backend === "bubblewrap") return hasCommand(config.bubblewrap_command || "bwrap");
  if (backend === "seatbelt") return hasCommand(config.sandbox_exec_command || "sandbox-exec");
  return false;
}

function unique(paths) {
  return [...new Set(paths.filter(Boolean).map((p) => realish(resolve(p))))];
}

function writableRoots(config, cwd) {
  if (config.sandbox_mode !== "workspace-write") return [];
  const roots = [cwd, ...(config.add_dir || []).map((p) => expandPath(p, cwd))];
  if (config.allow_tmp_write !== false) roots.push(tmpdir(), "/tmp");
  return unique(roots).filter((p) => existsSync(p));
}

export function bubblewrapArgs(config, cwd, command) {
  const args = [
    "--die-with-parent",
    "--unshare-all",
    "--new-session",
    "--ro-bind", "/", "/",
    "--dev", "/dev",
    "--proc", "/proc",
    "--chdir", cwd
  ];
  if (config.network_access) args.push("--share-net");
  for (const root of writableRoots(config, cwd)) args.push("--bind", root, root);
  args.push("--", "sh", "-lc", command);
  return args;
}

function macSeatbeltProfile(config, cwd) {
  const roots = writableRoots(config, cwd);
  const writeRules = roots.map((root) => `(subpath ${JSON.stringify(root)})`).join("\n    ");
  const network = config.network_access ? "(allow network*)" : "";
  const write = config.sandbox_mode === "workspace-write" && roots.length
    ? `(allow file-write*\n    ${writeRules})`
    : "";
  return `(version 1)
(deny default)
(allow process*)
(allow sysctl-read)
(allow file-read*)
${network}
${write}
(deny file-write* (subpath \"/System\") (subpath \"/usr\") (subpath \"/bin\") (subpath \"/sbin\"))`;
}

export function seatbeltArgs(config, cwd, command) {
  return ["-p", macSeatbeltProfile(config, cwd), "sh", "-lc", command];
}

export function nativeSandboxCommand(config, cwd, command) {
  const backend = sandboxBackend(config);
  if (backend === "bubblewrap") return { file: config.bubblewrap_command || "bwrap", args: bubblewrapArgs(config, cwd, command) };
  if (backend === "seatbelt") return { file: config.sandbox_exec_command || "sandbox-exec", args: seatbeltArgs(config, cwd, command) };
  throw new Error(sandboxFailureText(config));
}

export function createSandboxOperations(config) {
  return {
    async exec(command, cwd, options) {
      const backend = sandboxBackend(config);
      if (backend === "none") return spawnStreaming(process.platform === "win32" ? "cmd.exe" : "sh", process.platform === "win32" ? ["/d", "/s", "/c", command] : ["-lc", command], cwd, options);
      const sandbox = nativeSandboxCommand(config, cwd, command);
      return spawnStreaming(sandbox.file, sandbox.args, cwd, options);
    }
  };
}

export function spawnStreaming(file, args, cwd, options = {}) {
  return new Promise((resolve) => {
    const child = spawn(file, args, { cwd, env: options.env || process.env, windowsHide: true });
    let timeout;
    let settled = false;
    const finish = (exitCode) => {
      if (settled) return;
      settled = true;
      if (timeout) clearTimeout(timeout);
      resolve({ exitCode });
    };
    child.stdout?.on("data", options.onData || (() => {}));
    child.stderr?.on("data", options.onData || (() => {}));
    child.on("error", (err) => {
      options.onData?.(Buffer.from(`pi-permission: failed to start ${file}: ${err.message}\n`));
      finish(127);
    });
    child.on("close", (code, signal) => finish(signal ? null : code));
    if (options.signal) {
      if (options.signal.aborted) child.kill();
      else options.signal.addEventListener("abort", () => child.kill(), { once: true });
    }
    if (options.timeout) timeout = setTimeout(() => child.kill(), options.timeout * 1000);
  });
}

export function sandboxFailureText(config) {
  const backend = sandboxBackend(config);
  if (backend === "unsupported") return `No native sandbox backend is available for ${process.platform}; use an external sandbox or explicitly set sandbox_mode=danger-full-access.`;
  const binary = backend === "bubblewrap" ? (config.bubblewrap_command || "bwrap") : (config.sandbox_exec_command || "sandbox-exec");
  return `Native ${backend} sandbox is required for sandbox_mode=${config.sandbox_mode}, but ${binary} is not available. Install it or explicitly set sandbox_mode=danger-full-access.`;
}
