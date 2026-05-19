# pi-permission

Native permission and sandbox extension for pi.

## What it implements

- Sandbox modes: `read-only`, `workspace-write`, `danger-full-access`.
- Approval policies: `untrusted`, `on-failure`, `on-request`, `never`.
- Approval reviewers: `user`, `auto_review`.
- Bash tool escalation fields:
  - `sandbox_permissions: "require_escalated"`
  - `escalation_reason` (optional, <=80 chars; use only for a very short why)
  - `justification` (backward-compatible alias)
  - `prefix_rule`
- Native sandbox backend implemented by this plugin (Linux `bubblewrap`; macOS `sandbox-exec`/Seatbelt when available; unsupported platforms fail closed unless `danger-full-access`).
- Path gating for pi `write`/`edit` matching sandbox mode.
- `/permission`, `/permissions`, and `/permissions-rules` commands.
- Audit log at `.pi/permissions-audit.jsonl` by default.

## Install

```bash
pi install npm:@fadouse/pi-permission
```

## Usage

```bash
pi -e ./src/index.js --sandbox workspace-write --ask-for-approval on-request
pi -e . --sandbox read-only --ask-for-approval never
pi -e . --dangerously-bypass-approvals-and-sandbox
pi -e . --auto-review
pi -e . --sandbox workspace-write --ask-for-approval on-request --approvals-reviewer auto_review
```

`--add-dir` accepts comma/colon-separated writable roots for `workspace-write`.

## Config

Global: `~/.pi/agent/permissions.json`
Project: `.pi/permissions.json`

```json
{
  "sandbox_mode": "workspace-write",
  "approval_policy": "on-request",
  "approvals_reviewer": "auto_review",
  "auto_review_model": "openai/gpt-4.1-mini",
  "auto_review_timeout_ms": 45000,
  "add_dir": ["../shared"],
  "network_access": false,
  "allow_tmp_write": true,
  "status_line": false,
  "bubblewrap_command": "bwrap",
  "approved_prefixes": [
    { "rule": ["cargo", "test"], "scope": "project" }
  ]
}
```

Project config overrides global config; CLI flags override both. Use `/permission` (or `/permissions`) to persist project settings without editing JSON manually:

```text
/permission                         # show current settings
/permission auto-review             # persist workspace-write + on-request + auto_review
/permission auto-review openai/gpt-4.1-mini
/permission user                    # persist interactive user approvals
/permission sandbox read-only
/permission approval never
/permission model clear             # use current session model for auto_review
/permission add-dir ../shared
/permission set network=false auto_review_timeout_ms=45000
/permission set status_line=true      # opt in to footer status display
```

## Auto Review Mode

`auto_review` uses `workspace-write`, `on-request`, restricted network, and a model reviewer for approval requests. Low-risk requests can be approved automatically; higher-risk or uncertain reviews include risk level, complexity, and refusal reason, then prompt the user for the final allow/deny decision when an interactive UI is available. Without an interactive UI, non-allow reviews and reviewer failures remain fail-closed.

Enable it with `--auto-review`, `--approvals-reviewer auto_review`, `/permission auto-review`, or `/permissions auto-review`. By default the reviewer uses the active pi model; set `auto_review_model`, `--auto-review-model provider/model-id`, or `/permission model provider/model-id` to use a dedicated reviewer model. The reviewer must return strict JSON with `outcome`, `risk_level`, `complexity`, `rationale`, and optional `refusal_reason`.

## Native sandbox behavior

This package enforces the permission model directly in pi:

- Linux: `bubblewrap` with read-only root, writable cwd/`add_dir` roots (and temp when `allow_tmp_write` is true) in `workspace-write`, and network namespace isolation unless `network_access` is true.
- macOS: `sandbox-exec` Seatbelt profile when available.
- Windows/unsupported: fail closed unless the user explicitly selects `danger-full-access`.

Non-bash pi tools cannot be placed inside the process sandbox by pi today, so `write` and `edit` are preflight-gated with the same read-only/workspace-write root policy, including temp writes when `allow_tmp_write` is enabled.

## Acknowledgements

Thanks to OpenAI Codex CLI for inspiring the permission-model design and portions of the implementation approach. Codex CLI GitHub repository: https://github.com/openai/codex
