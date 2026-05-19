export const MAX_ESCALATION_REASON_LENGTH = 80;

export function normalizeEscalationReason(value, maxLength = MAX_ESCALATION_REASON_LENGTH) {
  const text = String(value ?? "").replace(/\s+/g, " ").trim();
  if (!text) return "";
  if (text.length <= maxLength) return text;
  return `${text.slice(0, Math.max(0, maxLength - 1))}…`;
}
