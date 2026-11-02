import assert from "node:assert/strict";
import test from "node:test";
import { loadTs } from "./_ts.mjs";
import { readRecord, record } from "./_records.mjs";

// REQ-AGENT-028 (GitHub #86): a Vector Agent that is switched off is not started. The console must say that it is off, that
// nothing was asked of the language model, and that it is a setting and not a failure.
const requirements = readRecord("requirements", "agent-off-means-off.md");
const activity = await loadTs("src/lib/runActivity.ts");

const skipped = (reason) => ({
  ts: "2026-11-01T10:00:00Z", actor: "worker", action: "agent_event", decision: null, reason,
  payload: { event: "agent_phase_skipped" },
});

test("REQ-AGENT-028 the skipped agent phase reads as a setting, in words", () => {
  record.match(requirements, /## REQ-AGENT-028:/);
  const a = activity.translateActivity(skipped("ai_testing_not_enabled"), "agent");
  assert.equal(a.title, "Vector Agent: off for this engagement");
  assert.equal(a.outcome, "Skipped");
  assert.match(a.summary, /no request was made to the language model/);
});

test("REQ-AGENT-028 negative: a skipped agent is not shown as a failure or as blocked", () => {
  for (const reason of ["ai_testing_not_enabled", "ai_testing_forbidden", "automation_forbidden", "bounty_program_missing"]) {
    const a = activity.translateActivity(skipped(reason), "agent");
    assert.notEqual(a.tone, "danger", reason);
    assert.notEqual(a.tone, "attention", reason);
    assert.ok(!a.countsAsBlocked, `${reason} must not count as a blocked action`);
  }
});

test("REQ-AGENT-028 each reason has a sentence of its own", () => {
  for (const reason of ["ai_testing_not_enabled", "ai_testing_forbidden", "automation_forbidden", "bounty_program_missing"]) {
    assert.notEqual(activity.reasonExplanation(reason), reason, `${reason} has no sentence`);
  }
});
