import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { homedir } from "node:os";
import { DEFAULT_CONFIG, normalizeApprovalPolicy, normalizeApprovalsReviewer, normalizeSandboxMode } from "./types.js";

export function globalConfigPath() {
  return resolve(homedir(), ".pi/agent/permissions.json");
}
export function projectConfigPath(cwd = process.cwd()) {
  return resolve(cwd, ".pi/permissions.json");
}

export function readJson(path) {
  if (!existsSync(path)) return {};
  try { return JSON.parse(readFileSync(path, "utf8")); }
  catch (error) { throw new Error(`Invalid JSON in ${path}: ${error.message}`); }
}

function arr(value) {
  if (value == null || value === "") return [];
  if (Array.isArray(value)) return value.map(String);
  return String(value).split(/[,:]/).map((v) => v.trim()).filter(Boolean);
}

export function mergeConfig(...configs) {
  const merged = { ...DEFAULT_CONFIG };
  for (const cfg of configs) {
    if (!cfg || typeof cfg !== "object") continue;
    for (const [key, value] of Object.entries(cfg)) {
      if (value === undefined) continue;
      if (key === "add_dir") merged.add_dir = [...(merged.add_dir || []), ...arr(value)];
      else if (key === "approved_prefixes") merged.approved_prefixes = [...(merged.approved_prefixes || []), ...(Array.isArray(value) ? value : [])];
      else merged[key] = value;
    }
  }
  merged.sandbox_mode = normalizeSandboxMode(merged.sandbox_mode);
  merged.approval_policy = normalizeApprovalPolicy(merged.approval_policy);
  merged.approvals_reviewer = normalizeApprovalsReviewer(merged.approvals_reviewer || "user");
  merged.add_dir = [...new Set(arr(merged.add_dir))];
  merged.approved_prefixes = Array.isArray(merged.approved_prefixes) ? merged.approved_prefixes : [];
  return merged;
}

export function flagsConfig(pi) {
  const cfg = {};
  const sandbox = pi.getFlag("sandbox");
  const approval = pi.getFlag("ask-for-approval");
  const addDir = pi.getFlag("add-dir");
  const bypass = pi.getFlag("dangerously-bypass-approvals-and-sandbox");
  const reviewer = pi.getFlag("approvals-reviewer");
  const autoReview = pi.getFlag("auto-review");
  const autoReviewModel = pi.getFlag("auto-review-model");
  if (sandbox) cfg.sandbox_mode = sandbox;
  if (approval) cfg.approval_policy = approval;
  if (reviewer) cfg.approvals_reviewer = reviewer;
  if (autoReviewModel) cfg.auto_review_model = autoReviewModel;
  if (autoReview) {
    cfg.sandbox_mode = "workspace-write";
    cfg.approval_policy = "on-request";
    cfg.approvals_reviewer = "auto_review";
    cfg.network_access = false;
  }
  if (addDir) cfg.add_dir = arr(addDir);
  if (bypass) {
    cfg.sandbox_mode = "danger-full-access";
    cfg.approval_policy = "never";
  }
  return cfg;
}

export function loadConfig(cwd = process.cwd(), pi) {
  const global = readJson(globalConfigPath());
  const project = readJson(projectConfigPath(cwd));
  return mergeConfig(DEFAULT_CONFIG, global, project, pi ? flagsConfig(pi) : {});
}

export function saveProjectConfig(cwd, updater) {
  const path = projectConfigPath(cwd);
  const current = readJson(path);
  const next = updater({ ...current });
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(next, null, 2) + "\n");
  return next;
}
