import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { readRecord, record } from "./_records.mjs";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirements = readRecord("requirements", "oob-template-coverage.md");
const view = read("frontend/src/components/ScanPlanView.tsx");
const client = read("frontend/src/api/client.ts");
const activity = read("frontend/src/lib/runActivity.ts");

test("REQ-OOB-001 the plan view names the template classes that did not run for lack of an interaction server", () => {
  record.match(requirements, /## REQ-OOB-001:/);
  assert.match(client, /not_run_classes\?: \{ label: string; services: number \}\[\];/);
  assert.match(client, /template_class\?: string \| null;/);
  assert.match(view, /const notRun = plan\.not_run_classes \?\? \[\];/);
  assert.match(view, /aria-label="Template classes not run"/);
  assert.match(view, /these template classes did not run/);
  assert.match(view, /\{c\.label\} \(on \{c\.services\} service/);
  assert.match(view, /check\.template_class && /);
});

test("REQ-OOB-001 [negative] the notice only appears when a class was named, and says what is not affected", () => {
  assert.match(view, /\{notRun\.length > 0 && \(/);
  assert.match(view, /Templates that do not need a callback are not affected/);
  assert.match(view, /does not mean the targets are free of blind vulnerabilities/);
});

test("REQ-OOB-001 the skip reason no longer reads as a missing feature only", () => {
  assert.match(activity, /oob_unavailable: "The platform's interaction server is not set up, so the templates that confirm through a callback/);
  assert.match(activity, /Templates that do not need a callback ran as usual/);
  assert.match(view, /oob_unavailable: "Interaction server not deployed: the callback templates did not run"/);
});
