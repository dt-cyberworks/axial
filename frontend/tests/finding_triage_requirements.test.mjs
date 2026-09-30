import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = read("docs/requirements/finding-triage.md");
// The findings list, the shared detail panel (triage), and the shared status helpers.
const findingsSection = read("frontend/src/components/FindingsSection.tsx");
const findingsLib = read("frontend/src/lib/findings.ts");
const findings = [findingsSection, read("frontend/src/components/FindingDetail.tsx"), findingsLib].join("\n");
const client = read("frontend/src/api/client.ts");

function requirement(id) {
  assert.match(requirementDoc, new RegExp(`## ${id}:`), `${id} must be documented before it is tested`);
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-TRIAGE-003 findings list has one tab per status, open by default", () => {
  requirement("REQ-TRIAGE-003");
  for (const status of ["open", "accepted_risk", "false_positive", "resolved"]) {
    assert.match(findings, new RegExp(`status: "${status}"`), `tab for ${status}`);
  }
  // REQ-CONSOLE-013 moved the status into the URL; anything unknown or missing still means "open".
  assert.match(findingsSection, /const statusFilter = parseFindingStatus\(searchParams\.get\("status"\)\)/);
  assert.match(findingsLib, /export function parseFindingStatus\(value: string \| null\): FindingStatus \{\s*return STATUS_TABS\.some\(\(tab\) => tab\.status === value\) \? \(value as FindingStatus\) : "open";/,
    "Open is the default tab");
  assert.match(findings, /counts_by_status/, "tabs show per-status counts");
  assert.match(findings, /role="tablist"/, "tabs are exposed as a tablist");
});

test("REQ-TRIAGE-001/003 triage calls the PATCH endpoint and requires a reason to dismiss", () => {
  requirement("REQ-TRIAGE-001");
  assert.match(client, /triageFinding:[\s\S]*?method: "PATCH"/, "client sends PATCH");
  assert.match(findings, /NOTE_REQUIRED: FindingStatus\[\] = \["accepted_risk", "false_positive"\]/);
  assert.match(findings, /disabled=\{pending \|\| note\.trim\(\)\.length < 3\}/, "confirm stays disabled without a reason");
  for (const label of ["Mark resolved", "Accept risk…", "Mark false positive…", "Reopen"]) {
    assert.ok(findings.includes(label), `offers "${label}"`);
  }
});

test("REQ-TRIAGE-003 detail view shows who changed the status, when, and why", () => {
  assert.match(findings, /status_changed_by/);
  assert.match(findings, /status_changed_at/);
  assert.match(findings, /status_note/);
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
