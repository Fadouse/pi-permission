import { appendFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";

export async function audit(config, cwd, event) {
  if (!config.audit) return;
  const path = resolve(cwd, config.audit_path || ".pi/permissions-audit.jsonl");
  const record = { ts: new Date().toISOString(), ...event };
  try {
    await mkdir(dirname(path), { recursive: true });
    await appendFile(path, JSON.stringify(record) + "\n");
  } catch {
    // Audit failures must not change permission decisions.
  }
}
