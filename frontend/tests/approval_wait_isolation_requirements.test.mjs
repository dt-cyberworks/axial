import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { loadTs } from "./_ts.mjs";
import { readRecord, record } from "./_records.mjs";

// REQ-APPROVAL-008 (GitHub #83): a wait for one decision does not stop the run's other actions. The console must say what
// is true: with the live-wait reason only ONE action waits; a parked run or a review pause has stopped altogether.
const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");
const requirements = readRecord("requirements", "approval-wait-isolation.md");
const activity = await loadTs("src/lib/runActivity.ts");

const run = (fields) => ({ id: "r1", state: "waiting_approval", phase: "fingerprint", state_reason: null, ...fields });
const summary = (fields) => activity.summarizeRun(run(fields), []);

test("REQ-APPROVAL-008 a live wait says that one action waits and the scan carries on", () => {
  record.match(requirements, /## REQ-APPROVAL-008:/);
  const s = summary({ state_reason: "approval_wait" });
  assert.match(s.headline, /One action is waiting for your decision, the scan carries on/);
  assert.match(s.detail, /The rest of .* keeps running/);
  assert.match(s.detail, /only if you approve it/);
  assert.doesNotMatch(s.detail, /remains stopped/, "the old text said the whole phase stopped");
  assert.ok(s.attentionItems >= 1, "a decision is still needed, so the run still asks for attention");
});

test("REQ-APPROVAL-008 negative: any other waiting_approval keeps the text that says the run has stopped", () => {
  for (const state_reason of [null, "asset_review_pending", "something_else"]) {
    const s = summary({ state_reason });
    assert.match(s.headline, /The scan is waiting for an operator decision/, String(state_reason));
    assert.match(s.detail, /remains stopped/, String(state_reason));
  }
});

test("REQ-APPROVAL-008 a running run is not described as waiting", () => {
  assert.match(summary({ state: "running", state_reason: "approval_wait" }).headline, /The scan is running/);
});

test("REQ-APPROVAL-008 the reason has a text of its own, and scan_run_not_active no longer says the run ended", () => {
  assert.doesNotMatch(activity.reasonExplanation("approval_wait"), /Unexplained/);
  assert.match(activity.reasonExplanation("approval_wait"), /The rest of the scan carries on/);
  const refused = activity.reasonExplanation("scan_run_not_active");
  assert.doesNotMatch(refused, /Unexplained|no longer running/);
  assert.match(refused, /parked/);
  assert.match(refused, /paused for a review/);
});

test("REQ-APPROVAL-008 the run header shows the reason in words, not the code", () => {
  const page = read("frontend/src/pages/RunDetail.tsx");
  assert.match(page, /run\.state_reason === "approval_wait" \? "one action waits for your decision"/);
});
