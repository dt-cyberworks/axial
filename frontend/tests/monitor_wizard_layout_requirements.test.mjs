import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { readRecord, record } from "./_records.mjs";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirements = readRecord("requirements", "operator-console-usability-fixes.md");
const css = read("frontend/src/styles.css");
const monitor = read("frontend/src/pages/MonitorWizard.tsx");
const engagement = read("frontend/src/pages/EngagementWizard.tsx");

test("REQ-WIZARD-001 the monitoring wizard's scope row has its own four-column template", () => {
  record.match(requirements, /## REQ-WIZARD-001:/);
  assert.match(monitor, /className="scope-row no-ports"/);
  assert.match(css, /\.scope-row\.no-ports \{ grid-template-columns: 110px 150px minmax\(180px, 1fr\) auto; \}/);
});

test("REQ-WIZARD-001 [negative] the shared seven-column grid and the engagement wizard row are unchanged", () => {
  assert.match(css, /\.scope-row \{ display: grid; grid-template-columns: 110px 150px minmax\(180px, 1fr\) 90px 90px auto auto;/);
  assert.match(engagement, /className="scope-row"/);
  assert.doesNotMatch(engagement, /no-ports/);
});

test("REQ-WIZARD-001 the phone breakpoint collapses the modifier too (it would win by specificity)", () => {
  assert.match(css, /\.scope-row, \.scope-row\.no-ports \{ grid-template-columns: 1fr; \}/);
});
