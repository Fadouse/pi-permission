import { APPROVAL_POLICIES, APPROVALS_REVIEWERS, SANDBOX_MODES, normalizeApprovalPolicy, normalizeApprovalsReviewer, normalizeSandboxMode } from "./types.js";

const BOOLEAN_KEYS = new Set(["network_access", "allow_tmp_write", "audit", "fail_closed_without_sandbox", "status_line"]);
const NUMBER_KEYS = new Set(["auto_review_timeout_ms", "auto_review_max_tokens"]);
const STRING_KEYS = new Set(["auto_review_model", "auto_review_reasoning", "sandbox_backend", "bubblewrap_command", "sandbox_exec_command", "persist_approvals"]);
const LIST_KEYS = new Set(["add_dir"]);
const KEY_ALIASES = new Map([
  ["sandbox", "sandbox_mode"],
  ["approval", "approval_policy"],
  ["ask-for-approval", "approval_policy"],
  ["ask_for_approval", "approval_policy"],
  ["reviewer", "approvals_reviewer"],
  ["approvals-reviewer", "approvals_reviewer"],
  ["auto-review-model", "auto_review_model"],
  ["model", "auto_review_model"],
  ["network", "network_access"],
  ["tmp", "allow_tmp_write"],
  ["status-line", "status_line"],
]);

export const PERMISSION_COMMAND_USAGE = `Usage:
  /permission                         Show current settings
  /permission auto-review [model]     Enable auto_review persistently
  /permission auto-review off         Disable auto_review reviewer
  /permission user                    Use interactive user approvals
  /permission sandbox <mode>          Set read-only|workspace-write|danger-full-access
  /permission approval <policy>       Set untrusted|on-failure|on-request|never
  /permission reviewer <reviewer>     Set user|auto_review
  /permission model <provider/model>  Set dedicated auto_review model
  /permission model clear             Use current session model
  /permission add-dir <path[,path]>   Persist additional writable roots
  /permission clear-add-dir           Clear additional writable roots
  /permission set key=value [...]     Set raw permission config keys`;

export function splitPermissionArgs(input) {
  const args = [];
  const pattern = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let match;
  while ((match = pattern.exec(String(input || "")))) {
    args.push(match[1] ?? match[2] ?? match[3]);
  }
  return args;
}

export function parsePermissionCommand(input) {
  const args = splitPermissionArgs(input);
  const [commandRaw, ...rest] = args;
  const command = normalizeToken(commandRaw || "show");

  if (["", "show", "status"].includes(command)) return { type: "show" };
  if (["help", "-h", "--help"].includes(command)) return { type: "help", message: PERMISSION_COMMAND_USAGE };

  if (["auto-review", "auto_review", "autoreview"].includes(command)) {
    const [first, second] = rest;
    if (["off", "false", "disable", "disabled", "0"].includes(normalizeToken(first || ""))) {
      return update("Disabled auto_review; approvals_reviewer=user", () => ({ approvals_reviewer: "user" }));
    }
    const model = first && !["on", "true", "enable", "enabled", "1"].includes(normalizeToken(first)) ? first : second;
    return update("Enabled auto_review: workspace-write + on-request + model reviewer", () => ({
      sandbox_mode: "workspace-write",
      approval_policy: "on-request",
      approvals_reviewer: "auto_review",
      network_access: false,
      ...(model ? { auto_review_model: model } : {})
    }));
  }

  if (["user", "manual"].includes(command)) {
    return update("Approval reviewer set to user", () => ({ approvals_reviewer: "user" }));
  }

  if (command === "sandbox") {
    const mode = requireValue(rest[0], "sandbox mode");
    return update(`sandbox_mode=${normalizeSandboxMode(mode)}`, () => ({ sandbox_mode: normalizeSandboxMode(mode) }));
  }

  if (["approval", "ask-for-approval", "ask_for_approval"].includes(command)) {
    const policy = requireValue(rest[0], "approval policy");
    return update(`approval_policy=${normalizeApprovalPolicy(policy)}`, () => ({ approval_policy: normalizeApprovalPolicy(policy) }));
  }

  if (command === "reviewer") {
    const reviewer = requireValue(rest[0], "reviewer");
    return update(`approvals_reviewer=${normalizeApprovalsReviewer(reviewer)}`, () => ({ approvals_reviewer: normalizeApprovalsReviewer(reviewer) }));
  }

  if (command === "model") {
    const model = requireValue(rest[0], "model or clear");
    if (["clear", "none", "default"].includes(normalizeToken(model))) {
      return update("auto_review_model cleared; using current session model", (current) => {
        const next = { ...current };
        delete next.auto_review_model;
        return next;
      });
    }
    return update(`auto_review_model=${model}`, () => ({ auto_review_model: model }));
  }

  if (["add-dir", "add_dir", "adddir"].includes(command)) {
    const dirs = parseList(rest.join(","));
    if (!dirs.length) throw new Error("Missing add-dir path");
    return update(`add_dir+=${dirs.join(",")}`, (current) => ({ add_dir: [...new Set([...(Array.isArray(current.add_dir) ? current.add_dir : []), ...dirs])] }));
  }

  if (["clear-add-dir", "clear_add_dir", "clear-adddir"].includes(command)) {
    return update("add_dir cleared", () => ({ add_dir: [] }));
  }

  if (command === "set") {
    if (!rest.length) throw new Error(`Missing key=value pairs\n${PERMISSION_COMMAND_USAGE}`);
    return update("Permission settings updated", () => parseKeyValuePairs(rest));
  }

  if (SANDBOX_MODES.includes(commandRaw)) {
    return update(`sandbox_mode=${commandRaw}`, () => ({ sandbox_mode: commandRaw }));
  }
  if (APPROVAL_POLICIES.includes(commandRaw)) {
    return update(`approval_policy=${commandRaw}`, () => ({ approval_policy: commandRaw }));
  }
  if (APPROVALS_REVIEWERS.includes(commandRaw) || commandRaw === "auto-review") {
    const reviewer = normalizeApprovalsReviewer(commandRaw);
    return update(`approvals_reviewer=${reviewer}`, () => ({ approvals_reviewer: reviewer }));
  }

  throw new Error(`Unknown /permission command: ${commandRaw}\n${PERMISSION_COMMAND_USAGE}`);
}

export function formatPermissionStatus(config, store, configPath) {
  return `pi-permission
sandbox_mode=${config.sandbox_mode}
approval_policy=${config.approval_policy}
approvals_reviewer=${config.approvals_reviewer}
auto_review_model=${config.auto_review_model || "(current session model)"}
network_access=${Boolean(config.network_access)}
add_dir=${(config.add_dir || []).join(", ") || "(none)"}
status_line=${Boolean(config.status_line)}
approved_prefixes=${store?.allPrefixes?.().length ?? 0}
project_config=${configPath}`;
}

function update(message, updater) {
  return { type: "update", message, updater };
}

function requireValue(value, label) {
  if (!value) throw new Error(`Missing ${label}\n${PERMISSION_COMMAND_USAGE}`);
  return value;
}

function parseKeyValuePairs(pairs) {
  const patch = {};
  for (const pair of pairs) {
    const index = pair.indexOf("=");
    if (index <= 0) throw new Error(`Expected key=value, got: ${pair}`);
    const key = normalizeKey(pair.slice(0, index));
    const value = pair.slice(index + 1);
    patch[key] = parseConfigValue(key, value);
  }
  return patch;
}

function parseConfigValue(key, value) {
  if (key === "sandbox_mode") return normalizeSandboxMode(value);
  if (key === "approval_policy") return normalizeApprovalPolicy(value);
  if (key === "approvals_reviewer") return normalizeApprovalsReviewer(value);
  if (BOOLEAN_KEYS.has(key)) return parseBoolean(value);
  if (NUMBER_KEYS.has(key)) return parseNumber(value, key);
  if (LIST_KEYS.has(key)) return parseList(value);
  if (STRING_KEYS.has(key)) return value;
  throw new Error(`Unsupported permission config key: ${key}`);
}

function normalizeKey(key) {
  const normalized = String(key).trim().replaceAll("-", "_");
  return KEY_ALIASES.get(String(key).trim()) || KEY_ALIASES.get(normalized) || normalized;
}

function normalizeToken(value) {
  return String(value || "").trim().toLowerCase().replaceAll("_", "-");
}

function parseBoolean(value) {
  const normalized = normalizeToken(value);
  if (["1", "true", "yes", "on", "enable", "enabled"].includes(normalized)) return true;
  if (["0", "false", "no", "off", "disable", "disabled"].includes(normalized)) return false;
  throw new Error(`Expected boolean, got: ${value}`);
}

function parseNumber(value, key) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) throw new Error(`Expected non-negative number for ${key}, got: ${value}`);
  return parsed;
}

function parseList(value) {
  return String(value || "").split(/[,:]/).map((item) => item.trim()).filter(Boolean);
}
