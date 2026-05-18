export function buildPermissionPrompt(config, store) {
  const roots = ["cwd", ...(config.add_dir || []), ...(config.sandbox_mode === "workspace-write" && config.allow_tmp_write !== false ? ["system temp"] : [])].join(", ");
  const prefixes = store?.allPrefixes?.() || config.approved_prefixes || [];
  const prefixText = prefixes.length
    ? prefixes.map((p) => `- ${JSON.stringify(p.rule || p)} (${p.scope || "configured"})`).join("\n")
    : "- none";
  return `\n\n<pi-permission>\nPermission profile:\n- sandbox_mode=${config.sandbox_mode}\n- approval_policy=${config.approval_policy}\n- approvals_reviewer=${config.approvals_reviewer || "user"}\n- workspace_write_roots=${roots}\n- network=${config.network_access ? "enabled" : "restricted"}\n- approved_prefixes:\n${prefixText}\n\nRules:\n- Default to sandboxed bash. Use unsandboxed bash only when necessary.\n- For unsandboxed bash, set sandbox_permissions=\"require_escalated\" and provide justification.\n- If approvals_reviewer=auto_review, approval requests are model-reviewed; obey denials and choose a safer alternative.\n- read-only: no file writes.\n- workspace-write: writes only in listed roots; network only if enabled.\n- danger-full-access: no sandbox; avoid destructive actions unless explicitly requested.\n- untrusted: only trusted read-only commands auto-run.\n- on-request: ask before unsandboxed or dangerous actions.\n- on-failure: retry unsandboxed only after sandbox denial.\n- never: never ask; report blocked actions.\n</pi-permission>`.trimEnd();
}
