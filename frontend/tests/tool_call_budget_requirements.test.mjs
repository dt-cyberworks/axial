import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { readRecord, record } from "./_records.mjs";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirements = readRecord("requirements", "tool-call-budget.md");
const panel = read("frontend/src/components/ToolCallBudgetPanel.tsx");
const settings = read("frontend/src/pages/Settings.tsx");
const client = read("frontend/src/api/client.ts");
const activity = read("frontend/src/lib/runActivity.ts");

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-BUDGET-001 the budget is a global setting with the server's bounds, saved on its own", () => {
  record.match(requirements, /## REQ-BUDGET-001:/);
  assert.match(client, /getToolCallBudget: \(\) => request<ToolCallBudget>\("\/settings\/tool-call-budget"\)/);
  assert.match(client, /updateToolCallBudget: \(value: number\)/);
  assert.match(client, /method: "PUT", body: JSON\.stringify\(\{ value \}\)/);
  assert.match(client, /export interface ToolCallBudget \{\s*value: number;\s*min: number;\s*max: number;/);
  assert.match(panel, /type="number" min=\{min\} max=\{max\} step=\{1\}/);
  assert.match(panel, /Number\.isInteger\(parsed\) && parsed >= min && parsed <= max/);
  assert.match(settings, /<ToolCallBudgetPanel \/>/);
});

test("REQ-BUDGET-001 [negative] it is global only: no engagement screen offers a budget", () => {
  for (const file of [
    "frontend/src/pages/EngagementEdit.tsx", "frontend/src/pages/EngagementWizard.tsx",
    "frontend/src/pages/MonitorWizard.tsx", "frontend/src/pages/EngagementDetail.tsx",
    "frontend/src/components/CapabilitiesEditor.tsx", "frontend/src/components/ScheduleControl.tsx",
  ]) {
    const text = read(file);
    // no control: nothing that reads or writes the global setting, no panel, no input of a budget
    assert.doesNotMatch(text, /ToolCallBudget|tool-call-budget|tool_call_budget/i, file);
    // the only mention of a run's budget allowed on an engagement screen is the read-only
    // "used/max" column of the runs table
    const mentions = text.split("\n").filter((line) => /budget_tool_calls_max/.test(line));
    for (const line of mentions) {
      assert.match(line, /<td>\{run\.budget_tool_calls_used\}\/\{run\.budget_tool_calls_max\}<\/td>/, `${file}: ${line.trim()}`);
    }
  }
  // the panel does not take an engagement
  assert.doesNotMatch(panel, /engagementId|engagement\.id/);
  assert.match(panel, /not set per engagement/);
});

test("REQ-BUDGET-001 the panel says when a new value applies and what exhaustion does", () => {
  assert.match(panel, /applies to runs that start after you save it/);
  assert.match(panel, /a run that is already going keeps the budget it started with/);
  assert.match(panel, /reduced coverage/);
  assert.match(panel, /never widens scope/);
});

test("REQ-BUDGET-002 the console explains exhaustion as the budget, not as a failing tool", () => {
  record.match(requirements, /## REQ-BUDGET-002:/);
  assert.match(activity, /tool_call_budget=exhausted_\\d\+_denied/);
  assert.match(activity, /The run used up its tool-call budget/);
  assert.match(activity, /does NOT mean those services are clean/);
  assert.match(activity, /Admin → Operational settings/);
});

let failed = 0;
for (const { name, fn } of tests) {
  try {
    fn();
    console.log(`ok - ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`not ok - ${name}`);
    console.error(error.stack || error.message || error);
  }
}
if (failed) {
  console.error(`${failed} requirement test(s) failed`);
  process.exit(1);
}
console.log(`${tests.length} requirement test(s) passed`);
