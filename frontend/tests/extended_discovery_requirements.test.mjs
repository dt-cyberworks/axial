import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirementDoc = read("docs/requirements/extended-discovery.md");
const switches = read("frontend/src/components/DiscoverySwitches.tsx");
const section = read("frontend/src/components/DiscoverySection.tsx");
const keys = read("frontend/src/components/SubfinderKeys.tsx");
const wizard = read("frontend/src/pages/EngagementWizard.tsx");
const edit = read("frontend/src/pages/EngagementEdit.tsx");
const detail = read("frontend/src/pages/EngagementDetail.tsx");
const settings = read("frontend/src/pages/Settings.tsx");
const client = read("frontend/src/api/client.ts");

function requirement(id) {
  assert.match(requirementDoc, new RegExp(`## ${id}:`), `${id} must be documented before it is tested`);
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("REQ-COVER-007 four switches with a one-sentence description and the documented defaults", () => {
  requirement("REQ-COVER-007");
  for (const key of ["subfinder_enabled", "crawling_enabled", "oob_enabled", "screenshots_enabled"]) {
    assert.match(switches, new RegExp(`key: "${key}"`), `${key} has a switch`);
    assert.match(client, new RegExp(`${key}: boolean;`), `${key} is typed on Engagement`);
  }
  assert.equal([...switches.matchAll(/help: "/g)].length, 4, "every switch has a help sentence");
  assert.match(switches, /subfinder_enabled: true,\s*crawling_enabled: false,\s*oob_enabled: false,\s*screenshots_enabled: false/);
});

test("REQ-COVER-007 the wizard sends the switches and shows them in the reviews", () => {
  requirement("REQ-COVER-007");
  assert.match(wizard, /<DiscoverySwitches flags=\{discoveryFlags\}/);
  assert.match(wizard, /\.\.\.discoveryFlags,/, "create request carries the flags");
  assert.equal([...wizard.matchAll(/discoveryFlagSummary\(discoveryFlags\)/g)].length, 2, "guardrail review and authorization checklist");
});

test("REQ-COVER-007 the edit page changes the switches at any status, not only in draft", () => {
  requirement("REQ-COVER-007");
  assert.match(edit, /<DiscoverySwitches flags=\{discoveryFlags\} onChange=\{setDiscoveryFlags\} \/>/, "not disabled by draft state");
  const before = edit.split("...(isDraft ?")[0];
  assert.match(before, /\.\.\.discoveryFlags,/, "flags are sent outside the draft-only envelope block");
});

test("REQ-COVER-007 the engagement summary lists which switches are on", () => {
  requirement("REQ-COVER-007");
  assert.match(detail, /Discovery extras: \{engagement \? discoveryFlagSummary\(engagement\)/);
});

test("REQ-COVER-003/006 endpoints and screenshots are shown from same-origin, cookie-authenticated URLs", () => {
  requirement("REQ-COVER-003");
  requirement("REQ-COVER-006");
  assert.match(client, /\/engagements\/\$\{id\}\/endpoints/);
  assert.match(client, /\/engagements\/\$\{id\}\/screenshots\/\$\{screenshotId\}\/image/);
  assert.match(section, /<img\s/);
  assert.match(section, /rel="noopener noreferrer"/);
  assert.match(detail, /<DiscoverySection engagementId=\{id\}/);
});

test("REQ-COVER-001 subfinder keys are write-only and only sent when typed", () => {
  requirement("REQ-COVER-001");
  assert.match(keys, /type="password"/);
  assert.match(keys, /autoComplete="off"/);
  assert.doesNotMatch(keys, /value=\{p\.key\b/, "the stored key is never rendered");
  assert.match(client, /"\/settings\/subfinder"/);
  assert.match(settings, /<SubfinderKeys \/>/);
});

let failed = 0;
for (const { name, fn } of tests) {
  try { fn(); console.log(`ok - ${name}`); } catch (error) {
    failed += 1; console.error(`not ok - ${name}`); console.error(error.stack || error.message || error);
  }
}
if (failed) { console.error(`${failed} requirement test(s) failed`); process.exit(1); }
console.log(`${tests.length} requirement test(s) passed`);
