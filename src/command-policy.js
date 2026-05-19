const SHELL_META_RE = /(?:<<|>>|>|<|\$\(|`|\$\{|\*|\?|\[|\]|\n)/;
const DANGEROUS_COMMANDS = new Set([
  "rm", "rmdir", "mv", "cp", "dd", "mkfs", "mount", "umount", "chmod", "chown", "chgrp",
  "sudo", "su", "doas", "git", "curl", "wget", "ssh", "scp", "rsync", "python", "python3",
  "node", "npm", "pnpm", "yarn", "bun", "pip", "pip3", "perl", "ruby", "php", "bash", "sh", "zsh",
  "powershell", "pwsh", "osascript"
]);
const BANNED_PREFIX_HEADS = new Set([
  "bash", "sh", "zsh", "/bin/bash", "/bin/sh", "/bin/zsh", "sudo", "su", "doas", "env",
  "python", "python3", "py", "node", "perl", "ruby", "php", "lua", "osascript", "powershell", "pwsh", "git"
]);
const TRUSTED_SIMPLE = new Set(["pwd", "ls", "cat", "head", "tail", "wc", "grep", "rg", "awk", "sort", "uniq", "cut", "tr", "printf", "echo", "date", "whoami", "id", "uname", "realpath", "readlink"]);
const TRUSTED_GIT = new Set(["status", "diff", "log", "show", "branch", "rev-parse", "ls-files", "grep"]);

export function splitShellSegments(command) {
  const segments = [];
  let current = "";
  let quote = null;
  let escaped = false;
  let complex = SHELL_META_RE.test(command);
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    const next = command[i + 1] || "";
    if (escaped) { current += ch; escaped = false; continue; }
    if (ch === "\\") { current += ch; escaped = true; continue; }
    if (quote) {
      current += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; current += ch; continue; }
    if ((ch === "&" && next === "&") || (ch === "|" && next === "|")) {
      if (current.trim()) segments.push(current.trim());
      current = "";
      i++;
      continue;
    }
    if (ch === ";" || ch === "|") {
      if (current.trim()) segments.push(current.trim());
      current = "";
      continue;
    }
    current += ch;
  }
  if (quote) complex = true;
  if (current.trim()) segments.push(current.trim());
  return { segments, complex };
}

export function tokenize(segment) {
  const tokens = [];
  let current = "";
  let quote = null;
  let escaped = false;
  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i];
    if (escaped) { current += ch; escaped = false; continue; }
    if (ch === "\\") { escaped = true; continue; }
    if (quote) {
      if (ch === quote) quote = null;
      else current += ch;
      continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; continue; }
    if (/\s/.test(ch)) {
      if (current) { tokens.push(current); current = ""; }
      continue;
    }
    current += ch;
  }
  if (current) tokens.push(current);
  return tokens;
}

export function parseCommand(command) {
  const { segments, complex } = splitShellSegments(command);
  const commands = segments.map(tokenize).filter((tokens) => tokens.length > 0);
  return { commands, complex };
}

function baseName(cmd) {
  return (cmd || "").split(/[\\/]/).pop() || cmd;
}

export function isDangerousCommandTokens(tokens) {
  if (!tokens.length) return false;
  const cmd = baseName(tokens[0]);
  if (cmd === "rm" && tokens.some((t) => /^-.*[rf]/.test(t) || t === "--recursive" || t === "--force")) return true;
  if (cmd === "git" && ["reset", "clean", "checkout", "restore", "rebase", "push"].includes(tokens[1])) return true;
  if (["chmod", "chown", "chgrp"].includes(cmd) && tokens.some((t) => t.includes("-R") || t === "777")) return true;
  return DANGEROUS_COMMANDS.has(cmd) && !isTrustedCommandTokens(tokens);
}

export function isTrustedCommandTokens(tokens) {
  if (!tokens.length) return false;
  const cmd = baseName(tokens[0]);
  if (cmd === "find") return !tokens.some((t) => ["-delete", "-exec", "-execdir"].includes(t));
  if (cmd === "sed") return !tokens.includes("-i") && !tokens.some((t) => t.startsWith("-i"));
  if (cmd === "git") return TRUSTED_GIT.has(tokens[1]);
  if (cmd === "awk") return true;
  return TRUSTED_SIMPLE.has(cmd);
}

export function isTrustedCommand(command) {
  const parsed = parseCommand(command);
  return !parsed.complex && parsed.commands.length > 0 && parsed.commands.every(isTrustedCommandTokens);
}

export function isDangerousCommand(command) {
  const parsed = parseCommand(command);
  return parsed.commands.some(isDangerousCommandTokens) || /\b(?:rm\s+-rf|sudo|mkfs|dd\s+if=|:\(\)\s*\{)/.test(command);
}

export function normalizePrefixRule(rule) {
  if (typeof rule === "string") return tokenize(rule);
  if (Array.isArray(rule)) return rule.map(String).filter(Boolean);
  return [];
}

export function isBannedPrefixRule(rule) {
  const tokens = normalizePrefixRule(rule);
  if (!tokens.length) return true;
  const cmd = baseName(tokens[0]);
  if (BANNED_PREFIX_HEADS.has(cmd)) return true;
  return isDangerousCommandTokens(tokens);
}

export function commandMatchesPrefix(command, prefixRule) {
  const prefix = normalizePrefixRule(prefixRule);
  if (!prefix.length) return false;
  const parsed = parseCommand(command);
  // Prefix approvals are for one argv prefix, not arbitrary shell compounds.
  if (parsed.complex || parsed.commands.length !== 1) return false;
  const [tokens] = parsed.commands;
  return prefix.every((part, i) => tokens[i] === part);
}

export function matchingPrefix(command, prefixes = []) {
  return prefixes.find((p) => commandMatchesPrefix(command, p.rule || p));
}

export function assessCommand(command, prefixes = []) {
  const parsed = parseCommand(command);
  const prefix = matchingPrefix(command, prefixes);
  return {
    trusted: !parsed.complex && parsed.commands.length > 0 && parsed.commands.every(isTrustedCommandTokens),
    dangerous: isDangerousCommand(command),
    complex: parsed.complex,
    commands: parsed.commands,
    matchedPrefix: prefix
  };
}
