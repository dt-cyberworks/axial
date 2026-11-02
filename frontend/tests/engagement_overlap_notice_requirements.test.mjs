import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { readRecord, record } from "./_records.mjs";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirements = readRecord("requirements", "engagement-identity-egress.md");
const detail = read("frontend/src/pages/EngagementDetail.tsx");
const wizard = read("frontend/src/pages/EngagementWizard.tsx");
const monitor = read("frontend/src/pages/MonitorWizard.tsx");
const client = read("frontend/src/api/client.ts");

test("REQ-EGRESS-011 the activation answer carries a notice and the console shows it after activation", () => {
  record.match(requirements, /## REQ-EGRESS-011:/);
  assert.match(client, /scope_overlap_notice\?: string \| null;/);
  assert.match(detail, /activateEngagementMutation\.data\?\.scope_overlap_notice/);
  assert.match(detail, /aria-label="Shared hosts"/);
  assert.match(detail, /overlapNotice && !isDraft/);
});

test("REQ-EGRESS-011 both wizards hand the notice to the engagement page they land on", () => {
  for (const source of [wizard, monitor]) {
    assert.match(source, /const activated = await api\.activateEngagement\(engagementId\);/);
    assert.match(source, /state: \{ scopeOverlapNotice: activated\.scope_overlap_notice \?\? null \}/);
  }
  assert.match(detail, /location\.state as \{ scopeOverlapNotice\?: string \| null \}/);
});

test("REQ-EGRESS-011 [negative] the page shows a notice only when there is one, and never on a draft", () => {
  assert.match(detail, /\{overlapNotice && !isDraft && \(/);
  assert.doesNotMatch(detail, /scope_overlap_notice\s*\|\|\s*"/);
});
