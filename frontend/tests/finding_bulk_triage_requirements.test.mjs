import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { readRecord, record } from "./_records.mjs";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirements = readRecord("requirements", "finding-triage.md");
const client = read("frontend/src/api/client.ts");
const bar = read("frontend/src/components/BulkTriageBar.tsx");
const section = read("frontend/src/components/FindingsSection.tsx");
const lib = read("frontend/src/lib/findings.ts");

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-TRIAGE-005 the list offers a selection, only to the owner or an administrator", () => {
  record.match(requirements, /## REQ-TRIAGE-005:/);
  assert.match(section, /Select all findings in this view/);
  assert.match(section, /aria-label=\{`Select finding: \$\{finding\.title\}`\}/);
  assert.match(section, /\{canManage && \(\s*<BulkTriageBar /);
  assert.match(section, /\{canManage && \(\s*<td className="select-cell"/);
  assert.match(section, /\{canManage && \(\s*<th className="select-cell">/);
});

test("REQ-TRIAGE-005 the selection belongs to the list in view and is dropped when the view changes", () => {
  assert.match(section, /useEffect\(\(\) => \{ setSelected\(new Set\(\)\); \}, \[statusFilter, severityFilter, engagementId\]\)/);
});

test("REQ-TRIAGE-005 a finding's detail can select the other findings with the same title, nothing more", () => {
  assert.match(lib, /export function sameTitleIds\(findings: Finding\[\], finding: Finding\): string\[\]/);
  assert.match(lib, /other\.id !== finding\.id && other\.title === finding\.title/);
  assert.match(section, /with the same title/);
  // it only selects; the decision still goes through the confirmation of the bar
  assert.doesNotMatch(section, /bulkTriageFindings/);
});

test("REQ-TRIAGE-005 the confirmation states the count, requires the reason and says it is not a rule", () => {
  assert.match(bar, /This sets <strong>\{count\} finding/);
  assert.match(bar, /note\.trim\(\)\.length < 3/);
  assert.match(bar, /still reported as open/);
  assert.match(bar, /Each finding is changed and recorded on its own/);
  assert.match(client, /bulkTriageFindings: \(id: string, body: \{ finding_ids: string\[\]; status: FindingStatus; note\?: string \}\)/);
  assert.match(client, /`\/engagements\/\$\{id\}\/findings\/triage`, \{ method: "POST"/);
});

test("REQ-TRIAGE-005 [negative] there is no rule, pattern or filter in the request", () => {
  assert.doesNotMatch(client, /findings\/triage[^`]*\?/);
  const call = /bulkTriageFindings: [\s\S]{0,300}/.exec(client)?.[0] ?? "";
  assert.doesNotMatch(call, /pattern|rule|filter|title_like|match_title/i);
  // the rendered text and code, not the comments that explain why there is none
  const code = bar.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  assert.doesNotMatch(code, /suppress|always|from now on|auto-?mark/i);
});

test("REQ-TRIAGE-006 undo is offered right after a bulk change and says what was left alone", () => {
  record.match(requirements, /## REQ-TRIAGE-006:/);
  assert.match(bar, /undoBulkTriage\(engagementId, bulkId\)/);
  assert.match(bar, />\s*\{undo\.isPending \? "Undoing…" : "Undo"\}/);
  assert.match(bar, /changed again since and were left as they are/);
  assert.match(client, /`\/engagements\/\$\{id\}\/findings\/triage\/\$\{bulkId\}\/undo`, \{ method: "POST" \}/);
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
