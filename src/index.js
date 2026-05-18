import { loadConfig, projectConfigPath, saveProjectConfig } from "./config.js";
import { ApprovalStore } from "./approval-store.js";
import { checkPathAccess } from "./path-policy.js";
import { registerPermissionedBash } from "./bash-tool.js";
import { buildPermissionPrompt } from "./system-prompt.js";
import { audit } from "./audit.js";
import { formatReviewDecision, reviewApprovalRequestWithModel, shouldAutoReview } from "./auto-review.js";
import { formatPermissionStatus, parsePermissionCommand, PERMISSION_COMMAND_USAGE } from "./permission-command.js";

function registerFlags(pi) {
  pi.registerFlag("sandbox", { type: "string", description: "Sandbox mode: read-only, workspace-write, danger-full-access" });
  pi.registerFlag("ask-for-approval", { type: "string", description: "Approval policy: untrusted, on-failure, on-request, never" });
  pi.registerFlag("approvals-reviewer", { type: "string", description: "Approval reviewer: user or auto_review" });
  pi.registerFlag("auto-review", { type: "boolean", description: "Enable auto_review mode: workspace-write + on-request + automatic approval review" });
  pi.registerFlag("auto-review-model", { type: "string", description: "Reviewer model as provider/model-id; defaults to current model" });
  pi.registerFlag("add-dir", { type: "string", description: "Additional writable roots for workspace-write (comma/colon separated)" });
  pi.registerFlag("dangerously-bypass-approvals-and-sandbox", { type: "boolean", description: "Bypass approvals and sandbox: danger-full-access + never" });
}

function pathFromTool(event) {
  if (event.toolName === "write" || event.toolName === "read") return event.input.path;
  if (event.toolName === "edit") return event.input.path;
  return undefined;
}

async function maybeApprovePath(ctx, config, store, toolName, path, reason) {
  if (shouldAutoReview(config)) {
    const review = await reviewApprovalRequestWithModel({ type: "file", toolName, path, reason }, ctx, config);
    const decision = formatReviewDecision(review);
    ctx.ui.notify?.(decision, review.outcome === "allow" ? "info" : "warning");
    return review.outcome === "allow"
      ? { allowed: true, reason: decision, review }
      : { allowed: false, reason: decision, review };
  }
  if (config.approval_policy === "never" || !ctx.hasUI) return { allowed: false, reason };
  const choice = await ctx.ui.select(
    `File permission request\n\nTool: ${toolName}\nPath: ${path}\nReason: ${reason}`,
    ["Allow once", "Deny"],
    { timeout: 120000 }
  );
  return choice === "Allow once" ? { allowed: true, reason: "approved once" } : { allowed: false, reason: "Denied by user" };
}

function updateStatus(ctx, config) {
  ctx.ui.setStatus?.(
    "pi-permission",
    config.status_line ? `${config.sandbox_mode}/${config.approval_policy}/${config.approvals_reviewer}` : undefined
  );
}

export default function piPermission(pi) {
  registerFlags(pi);
  let config;
  let store;

  function refreshState(cwd) {
    const next = loadConfig(cwd, pi);
    if (config) {
      for (const key of Object.keys(config)) delete config[key];
      Object.assign(config, next);
    } else {
      config = next;
    }
    if (store) {
      store.config = config;
      store.cwd = cwd;
    } else {
      store = new ApprovalStore(config, cwd, pi);
    }
    return { config, store };
  }

  pi.on("session_start", (_event, ctx) => {
    refreshState(ctx.cwd);
    updateStatus(ctx, config);
  });

  pi.on("before_agent_start", (event, ctx) => {
    refreshState(ctx.cwd);
    return { systemPrompt: `${event.systemPrompt}\n\n${buildPermissionPrompt(config, store)}` };
  });

  pi.on("tool_call", async (event, ctx) => {
    refreshState(ctx.cwd);
    const path = pathFromTool(event);
    if (!path) return undefined;
    const writeTools = new Set(["write", "edit"]);
    const access = writeTools.has(event.toolName) ? "write" : "read";
    const decision = checkPathAccess({ path, cwd: ctx.cwd, config, access });
    if (decision.allowed) return undefined;
    let approval = { allowed: false, reason: decision.reason };
    if (access === "write" && config.sandbox_mode !== "read-only") {
      approval = await maybeApprovePath(ctx, config, store, event.toolName, decision.path, decision.reason);
    }
    if (!approval.allowed) {
      await audit(config, ctx.cwd, { tool: event.toolName, path: decision.path, outcome: "blocked", reason: approval.reason });
      return { block: true, reason: approval.reason };
    }
    await audit(config, ctx.cwd, { tool: event.toolName, path: decision.path, outcome: "approved", reason: approval.reason });
    return undefined;
  });

  pi.on("user_bash", async (_event, ctx) => {
    refreshState(ctx.cwd);
    if (config.sandbox_mode === "danger-full-access") return undefined;
    // User ! commands use the built-in bash renderer; force the same native sandbox operations for parity.
    const { createSandboxOperations } = await import("./sandbox.js");
    return { operations: createSandboxOperations(config) };
  });

  const permissionCommand = {
    description: "Show or persist pi permission settings: /permission [auto-review|user|sandbox <mode>|approval <policy>|set key=value]",
    handler: async (args, ctx) => {
      refreshState(ctx.cwd);
      let action;
      try {
        action = parsePermissionCommand(args);
      } catch (error) {
        ctx.ui.notify(error instanceof Error ? error.message : String(error), "error");
        return;
      }
      if (action.type === "help") {
        ctx.ui.notify(action.message || PERMISSION_COMMAND_USAGE, "info");
        return;
      }
      if (action.type === "show") {
        ctx.ui.notify(formatPermissionStatus(config, store, projectConfigPath(ctx.cwd)), "info");
        return;
      }
      saveProjectConfig(ctx.cwd, (current) => ({ ...current, ...action.updater(current) }));
      refreshState(ctx.cwd);
      updateStatus(ctx, config);
      ctx.ui.notify(`${action.message}\nSaved to ${projectConfigPath(ctx.cwd)}\n\n${formatPermissionStatus(config, store, projectConfigPath(ctx.cwd))}`, "info");
    }
  };

  pi.registerCommand("permission", permissionCommand);
  pi.registerCommand("permissions", permissionCommand);

  pi.registerCommand("permissions-rules", {
    description: "List or clear approved command prefix rules: /permissions-rules [clear]",
    handler: async (args, ctx) => {
      refreshState(ctx.cwd);
      if (args.trim() === "clear") {
        store.clearProjectPrefixes();
        ctx.ui.notify("Project approved prefixes cleared", "info");
        return;
      }
      const rules = store.allPrefixes();
      ctx.ui.notify(rules.length ? rules.map((r, i) => `${i + 1}. ${(r.rule || r).join(" ")} [${r.scope || "configured"}]`).join("\n") : "No approved prefixes", "info");
    }
  });

  // Register once; bash execution constructs per-call tools using runtime ctx.cwd.
  refreshState(process.cwd());
  registerPermissionedBash(pi, config, store, process.cwd());
}
