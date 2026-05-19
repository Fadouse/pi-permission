import test from "node:test";
import assert from "node:assert/strict";
import { MAX_ESCALATION_REASON_LENGTH, normalizeEscalationReason } from "../src/escalation-reason.js";

test("normalizes short escalation reasons", () => {
  assert.equal(normalizeEscalationReason("  retry without sandbox\nfor network  "), "retry without sandbox for network");
});

test("truncates long escalation reasons", () => {
  const reason = normalizeEscalationReason("x".repeat(MAX_ESCALATION_REASON_LENGTH + 20));
  assert.equal(reason.length, MAX_ESCALATION_REASON_LENGTH);
  assert.match(reason, /…$/);
});
