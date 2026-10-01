import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = read("docs/requirements/scan-pipeline.md");
const client = read("frontend/src/api/client.ts");
const runDetail = read("frontend/src/pages/RunDetail.tsx");
const planView = read("frontend/src/components/ScanPlanView.tsx");
const depth = read("frontend/src/components/ScanDepth.tsx");
const edit = read("frontend/src/pages/EngagementEdit.tsx");
const wizard = read("frontend/src/pages/EngagementWizard.tsx");
const runs = read("frontend/src/lib/runs.ts");
const activity = read("frontend/src/lib/runActivity.ts");

function requirement(id) {
  assert.match(requirementDoc, new RegExp(`## ${id}:`), `${id} must be documented before it is tested`);
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-PIPE-005 scan depth is a two-way choice set in the wizard and changeable in the engagement settings", () => {
  requirement("REQ-PIPE-005");
  assert.match(client, /export type ScanProfile = "standard" \| "thorough"/);
  assert.match(client, /scan_profile: ScanProfile;/, "the engagement carries its depth");
  assert.match(client, /scan_profile\?: ScanProfile;/, "the depth is an update field");
  for (const source of [edit, wizard]) {
    assert.match(source, /<ScanDepth value=\{scanProfile\} onChange=\{setScanProfile\}/, "both screens offer the choice");
    assert.match(source, /scan_profile: scanProfile/, "and send it");
  }
  assert.match(depth, /value: "standard"/);
  assert.match(depth, /value: "thorough"/);
  assert.match(depth, /Neither widens scope|widens scope, tool grants/, "the help says the depth never widens what is allowed");
});

test("REQ-PIPE-017 the thorough depth says it adds a deep content-discovery sweep and the plan explains that check", () => {
  requirement("REQ-PIPE-017");
  assert.match(depth, /deep sweep of about 30,000 likely paths/, "the choice tells the operator what thorough costs");
  assert.match(planView, /"thorough:deep_content_discovery": "Thorough depth: deep sweep/, "the plan gives the check a plain-language reason");
});

test("REQ-PIPE-010 the run detail has a Plan tab that refreshes while the run executes", () => {
  requirement("REQ-PIPE-010");
  assert.match(client, /scanRunPlan: \(id: string, runId: string\) => request<ScanPlan>\(`\/engagements\/\$\{id\}\/scan-runs\/\$\{runId\}\/plan`\)/);
  assert.match(runDetail, /type Tab = "progress" \| "plan" \| "diff" \| "agent" \| "activity"/);
  assert.match(runDetail, /refetchInterval: isRunning \? 3000 : false/, "polls while the run is active");
  assert.match(runDetail, /\{tab === "plan" && <ScanPlanView plan=\{plan\} \/>\}/);
});

test("REQ-PIPE-010 the plan shows every surface with its class, technologies, and per check the reason, state, time and findings", () => {
  requirement("REQ-PIPE-010");
  for (const field of ["service_class", "profile", "check.reason", "check.state", "check.duration_s", "check.findings"]) {
    assert.ok(planView.includes(field), `the plan view renders ${field}`);
  }
  assert.match(planView, /<th>Check<\/th><th>State<\/th><th>Why<\/th><th>Templates<\/th><th>Time<\/th><th>Findings<\/th>/);
  assert.match(planView, /skipped/, "skipped checks are listed, not hidden");
  assert.match(planView, /switch_off: "Switched off for this engagement"/, "a skip says why in plain words");
  assert.match(planView, /web_alias_of:/);
});

test("REQ-PIPE-006 a partial or failed check never reads as clean in the plan or the run header", () => {
  requirement("REQ-PIPE-006");
  assert.match(planView, /a short findings list for those\s+does not mean the service is clean/);
  assert.match(runDetail, /coverage_partial:/);
  assert.match(runDetail, /partial coverage/);
  assert.match(activity, /coverage_partial:/);
  assert.match(activity, /NOT a clean bill of health|does NOT mean the examined surface is clean/);
});

test("REQ-PIPE-014 the validate phase is gone from the console", () => {
  requirement("REQ-PIPE-014");
  assert.doesNotMatch(runs, /"validate"|validate:\s*\{/, "no validate phase id, label or copy entry");
  assert.match(runs, /"agent", "score", "report"\]/);
});

test("REQ-PIPE-013 the fingerprint step no longer lists nikto", () => {
  requirement("REQ-PIPE-013");
  const fingerprintLine = runs.split("\n").find((l) => l.trim().startsWith("fingerprint:"));
  assert.ok(fingerprintLine && !fingerprintLine.includes("nikto"), "nikto is not part of the fingerprint phase");
});

let failed = 0;
for (const { name, fn } of tests) {
  try { fn(); console.log(`ok - ${name}`); } catch (e) { failed += 1; console.error(`not ok - ${name}\n${e.stack}`); }
}
console.log(`# ${tests.length - failed} requirement test(s) passed`);
if (failed) process.exit(1);
