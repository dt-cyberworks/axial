import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { readRecord, record } from "./_records.mjs";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirements = readRecord("requirements", "run-inventory-diff.md");
const panel = read("frontend/src/components/InventoryDiffPanel.tsx");
const run = read("frontend/src/pages/RunDetail.tsx");
const client = read("frontend/src/api/client.ts");

test("REQ-DIFF-001 the Diff tab shows hosts and ports next to the findings, against the named previous run", () => {
  record.match(requirements, /## REQ-DIFF-001:/);
  assert.match(run, /<InventoryDiffPanel inventory=\{diff\?\.inventory\} engagementId=\{id!\} \/>/);
  for (const group of ["New hosts", "Newly open ports", "Changed services", "Hosts no longer seen", "Ports no longer open"]) {
    assert.match(panel, new RegExp(group));
  }
  assert.match(panel, /Compared with <Link to=\{`\/engagements\/\$\{engagementId\}\/runs\/\$\{inventory\.previous_run_id\}`\}>the previous full run<\/Link>/);
  assert.match(client, /export interface InventoryDiff \{/);
});

test("REQ-DIFF-002 [negative] a run that did not look everywhere shows no 'gone' or 'closed' list, and says why", () => {
  record.match(requirements, /## REQ-DIFF-002:/);
  assert.match(panel, /\{!inventory\.run_coverage_reduced && \(\s*<>\s*<Group title="▼ Hosts no longer seen"/);
  assert.match(panel, /does not say that a host or\s+port is gone: that may only mean it was not looked at/);
});

test("REQ-DIFF-002 [negative] a missing snapshot reads as 'not recorded', never as an empty result", () => {
  assert.match(panel, /no_snapshot: "Hosts and ports were not recorded for this run or for the run it would be compared with/);
  assert.match(panel, /no_baseline: "There is no earlier full run to compare with/);
  assert.match(panel, /\{inventory\.available && \(\s*<div className="diff-grid">/);
});
