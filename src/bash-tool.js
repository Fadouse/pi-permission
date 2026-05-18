import { createBashTool, createLocalBashOperations } from "@earendil-works/pi-coding-agent";
import { assessCommand, isBannedPrefixRule, normalizePrefixRule } from "./command-policy.js";
import { createSandboxOperations, isSandboxAvailable, sandboxFailureText } from "./sandbox.js";
import { audit } from "./audit.js";
import { formatReviewDecision, reviewApprovalRequestWithModel, shouldAutoReview } from "./auto-review.js";

export const bashPermissionSchema = {
  type: "object",
  additionalProperties: false,
  required: ["command"],
  properties: {
    command: { type: "string", description: "Bash command to execute" },
    timeout: { type: "number", description: "Timeout in seconds (optional, no default timeout)" },
    sandbox_permissions: {
      enum: ["require_escalated"],
      description: "Set to require_escalated to request unsandboxed execution under the active permission policy."
    },
    justification: { type: "string", description: "Required when requesting escalated/unsandboxed execution." },
    prefix_rule: {
      type: "array",
      items: { type: "string" },
      description: "Optional argv prefix the user may approve for future matching commands."
    }
  }
};

function textResult(text, details = {}) {
  return { content: [{ type: "text", text }], details };
}

async function promptApproval(ctx, { command, reason, justification, prefixRule, store, allowPersistence, config }) {
  if (shouldAutoReview(config)) {
    const review = await reviewApprovalRequestWithModel({ type: "bash", command, reason, justification }, ctx, config);
    const decision = formatReviewDecision(review);
    ctx.ui.notify?.(decision, review.outcome === "allow" ? "info" : "warning");
    return review.outcome === "allow"
      ? { allowed: true, scope: "auto_review", review }
      : { allowed: false, reason: decision, review };
  }
  if (!ctx.hasUI) return { allowed: false, reason: `${reason} (no interactive UI available)` };
  const options = ["Allow once", "Deny"];
  if (allowPersistence && prefixRule?.length && !isBannedPrefixRule(prefixRule)) {
    options.splice(1, 0, "Allow prefix for session", "Allow prefix for project");
  }
  const choice = await ctx.ui.select(
    `Permission request\n\nCommand:\n  ${command}\n\nReason: ${reason}${justification ? `\nJustification: ${justification}` : ""}`,
    options,
    { timeout: 120000 }
  );
  if (choice === "Allow once") return { allowed: true, scope: "once" };
  if (choice === "Allow prefix for session") {
    store.addSessionPrefix(prefixRule, justification || reason);
    return { allowed: true, scope: "session-prefix" };
  }
  if (choice === "Allow prefix for project") {
    store.addProjectPrefix(prefixRule, justification || reason);
    return { allowed: true, scope: "project-prefix" };
  }
  return { allowed: false, reason: "Denied by user" };
}

export function isLikelySandboxFailure(error) {
  const message = String(error?.message || error || "");
  return /(?:Read-only file system|Operation not permitted|Network is unreachable|Temporary failure in name resolution|failed to start bwrap|failed to start sandbox-exec|bwrap:|sandbox-exec:|No native .* sandbox)/i.test(message);
}

export async function shouldRunUnsandboxed({ command, params, config, store, ctx }) {
  if (config.sandbox_mode === "danger-full-access") return { decision: "unsandboxed", reason: "danger-full-access" };
  const wantsEscalation = params.sandbox_permissions === "require_escalated";
  const assessment = assessCommand(command, store.allPrefixes());
  if (store.isOnceApproved(command)) return { decision: wantsEscalation ? "unsandboxed" : "sandboxed", reason: "approved once" };

  if (config.approval_policy === "never") {
    if (wantsEscalation) return { decision: "reject", reason: "approval required by policy, but approval_policy is never" };
    return { decision: "sandboxed", reason: "never policy relies on sandbox" };
  }

  if (assessment.dangerous) {
    const approval = await promptApproval(ctx, {
      command,
      reason: "command is potentially dangerous",
      justification: params.justification,
      prefixRule: normalizePrefixRule(params.prefix_rule || []),
      store,
      allowPersistence: false,
      config
    });
    if (!approval.allowed) return { decision: "reject", reason: approval.reason };
    store.rememberOnce(command);
    return { decision: wantsEscalation ? "unsandboxed" : "sandboxed", reason: approval.scope };
  }

  if (assessment.matchedPrefix) return { decision: wantsEscalation ? "unsandboxed" : "sandboxed", reason: "approved prefix" };

  if (config.approval_policy === "untrusted" && !assessment.trusted) {
    const prefixRule = normalizePrefixRule(params.prefix_rule?.length ? params.prefix_rule : assessment.commands[0] || []);
    const approval = await promptApproval(ctx, {
      command,
      reason: "command is not in the trusted read-only set",
      justification: params.justification,
      prefixRule,
      store,
      allowPersistence: true,
      config
    });
    if (!approval.allowed) return { decision: "reject", reason: approval.reason };
    store.rememberOnce(command);
    return { decision: wantsEscalation ? "unsandboxed" : "sandboxed", reason: approval.scope };
  }

  if (wantsEscalation) {
    const prefixRule = normalizePrefixRule(params.prefix_rule || assessment.commands[0] || []);
    const approval = await promptApproval(ctx, {
      command,
      reason: "command requested unsandboxed execution",
      justification: params.justification,
      prefixRule,
      store,
      allowPersistence: true,
      config
    });
    if (!approval.allowed) return { decision: "reject", reason: approval.reason };
    return { decision: "unsandboxed", reason: approval.scope };
  }

  return { decision: "sandboxed", reason: "default sandboxed execution" };
}

function makeBashTools(cwd, config) {
  const local = createBashTool(cwd, { operations: createLocalBashOperations() });
  const sandboxed = createBashTool(cwd, {
    operations: config.sandbox_mode === "danger-full-access" ? createLocalBashOperations() : createSandboxOperations(config)
  });
  return { local, sandboxed };
}

export function registerPermissionedBash(pi, config, store, cwd) {
  const template = createBashTool(cwd, { operations: createSandboxOperations(config) });
  pi.registerTool({
    ...template,
    name: "bash",
    label: `bash (${config.sandbox_mode})`,
    description: `${template.description}\n\nThis bash tool is governed by pi-permission and uses a native sandbox. Use sandbox_permissions=\"require_escalated\" plus justification to request unsandboxed execution.`,
    parameters: bashPermissionSchema,
    promptGuidelines: [
      `Bash runs with sandbox_mode=${config.sandbox_mode} and approval_policy=${config.approval_policy}.`,
      "Request escalation only with sandbox_permissions=\"require_escalated\" and a concise justification."
    ],
    async execute(toolCallId, params, signal, onUpdate, ctx) {
      const command = String(params.command || "");
      if (!command.trim()) return textResult("No command provided", { blocked: true });
      if (config.sandbox_mode !== "danger-full-access" && !(await isSandboxAvailable(config)) && config.fail_closed_without_sandbox) {
        const reason = sandboxFailureText(config);
        await audit(config, ctx.cwd, { tool: "bash", command, outcome: "blocked", reason });
        return textResult(reason, { blocked: true });
      }
      const routing = await shouldRunUnsandboxed({ command, params, config, store, ctx });
      if (routing.decision === "reject") {
        await audit(config, ctx.cwd, { tool: "bash", command, outcome: "blocked", reason: routing.reason });
        return textResult(`Permission denied: ${routing.reason}`, { blocked: true });
      }
      const { local, sandboxed } = makeBashTools(ctx.cwd, config);
      const selected = routing.decision === "unsandboxed" ? local : sandboxed;
      await audit(config, ctx.cwd, { tool: "bash", command, outcome: "execute", mode: routing.decision, reason: routing.reason });
      try {
        return await selected.execute(toolCallId, { command, timeout: params.timeout }, signal, onUpdate, ctx);
      } catch (error) {
        if (config.approval_policy === "on-failure" && routing.decision === "sandboxed" && config.sandbox_mode !== "danger-full-access" && isLikelySandboxFailure(error)) {
          const approval = await promptApproval(ctx, {
            command,
            reason: `sandboxed execution failed: ${error.message}`,
            justification: params.justification,
            prefixRule: normalizePrefixRule(params.prefix_rule || []),
            store,
            allowPersistence: false,
            config
          });
          if (approval.allowed) {
            const { local: retryLocal } = makeBashTools(ctx.cwd, config);
            await audit(config, ctx.cwd, { tool: "bash", command, outcome: "retry-unsandboxed", reason: approval.scope });
            return await retryLocal.execute(toolCallId, { command, timeout: params.timeout }, signal, onUpdate, ctx);
          }
        }
        throw error;
      }
    }
  });
}
