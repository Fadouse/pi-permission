import { isBannedPrefixRule, normalizePrefixRule } from "./command-policy.js";
import { saveProjectConfig } from "./config.js";

export class ApprovalStore {
  constructor(config, cwd, pi) {
    this.config = config;
    this.cwd = cwd;
    this.pi = pi;
    this.sessionPrefixes = [];
    this.onceCommands = new Set();
  }

  allPrefixes() {
    return [...(this.config.approved_prefixes || []), ...this.sessionPrefixes];
  }

  rememberOnce(command) {
    this.onceCommands.add(command);
  }

  isOnceApproved(command) {
    return this.onceCommands.has(command);
  }

  addSessionPrefix(rule, reason) {
    const tokens = normalizePrefixRule(rule);
    if (isBannedPrefixRule(tokens)) throw new Error(`Refusing unsafe persistent/session prefix rule: ${tokens.join(" ")}`);
    const entry = { rule: tokens, scope: "session", reason, created_at: new Date().toISOString() };
    this.sessionPrefixes.push(entry);
    try { this.pi?.appendEntry?.("pi-permission.approval", entry); } catch {}
    return entry;
  }

  addProjectPrefix(rule, reason) {
    const tokens = normalizePrefixRule(rule);
    if (isBannedPrefixRule(tokens)) throw new Error(`Refusing unsafe persistent prefix rule: ${tokens.join(" ")}`);
    const entry = { rule: tokens, scope: "project", reason, created_at: new Date().toISOString() };
    saveProjectConfig(this.cwd, (cfg) => {
      cfg.approved_prefixes = Array.isArray(cfg.approved_prefixes) ? cfg.approved_prefixes : [];
      if (!cfg.approved_prefixes.some((p) => JSON.stringify(p.rule || p) === JSON.stringify(tokens))) cfg.approved_prefixes.push(entry);
      return cfg;
    });
    this.config.approved_prefixes.push(entry);
    try { this.pi?.appendEntry?.("pi-permission.approval", entry); } catch {}
    return entry;
  }

  clearProjectPrefixes() {
    saveProjectConfig(this.cwd, (cfg) => ({ ...cfg, approved_prefixes: [] }));
    this.config.approved_prefixes = [];
  }
}
