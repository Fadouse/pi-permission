export const SANDBOX_MODES = ["read-only", "workspace-write", "danger-full-access"];
export const APPROVAL_POLICIES = ["untrusted", "on-failure", "on-request", "never"];
export const APPROVALS_REVIEWERS = ["user", "auto_review"];

export const DEFAULT_CONFIG = Object.freeze({
  sandbox_mode: "workspace-write",
  approval_policy: "on-request",
  approvals_reviewer: "user",
  auto_review_model: undefined,
  auto_review_use_model: true,
  auto_review_timeout_ms: 45000,
  auto_review_max_tokens: 512,
  auto_review_reasoning: "low",
  add_dir: [],
  network_access: false,
  sandbox_backend: "native",
  bubblewrap_command: "bwrap",
  sandbox_exec_command: "sandbox-exec",
  allow_tmp_write: true,
  fail_closed_without_sandbox: true,
  audit: true,
  audit_path: ".pi/permissions-audit.jsonl",
  persist_approvals: "project",
  approved_prefixes: [],
  deny_read_patterns: [],
  deny_write_patterns: []
});

export function normalizeApprovalPolicy(value) {
  if (value === "unless-trusted") return "untrusted";
  if (APPROVAL_POLICIES.includes(value)) return value;
  throw new Error(`Invalid approval_policy: ${value}`);
}

export function normalizeApprovalsReviewer(value) {
  if (value === "auto-review") return "auto_review";
  if (APPROVALS_REVIEWERS.includes(value)) return value;
  throw new Error(`Invalid approvals_reviewer: ${value}`);
}

export function normalizeSandboxMode(value) {
  if (SANDBOX_MODES.includes(value)) return value;
  throw new Error(`Invalid sandbox_mode: ${value}`);
}
