import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "../..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

const requirement = read("docs/requirements/engagement-creation-double-submit-guard.md");
const wizard = read("frontend/src/pages/EngagementWizard.tsx");

assert.match(requirement, /## REQ-ENGCREATE-001:/);

// The button must be disabled for the whole in-flight duration, not only
// while required fields are empty - found live 2026-08-09: two clicks
// silently created two duplicate draft engagements before this existed.
assert.match(
  wizard,
  /disabled=\{isCreating \|\| !title \|\| !authorizedFrom \|\| !authorizedUntil\}/,
  "the Create button must be disabled while a create request is in flight",
);
assert.match(wizard, /isCreating \? "Creating…" : "Save draft and continue"/, "the button must show a distinct in-progress label");

// Defense in depth: the handler itself must refuse to fire a second request
// even if something dispatches it a second way.
assert.match(wizard, /if \(isCreating\) return;/, "handleCreateEngagement must early-return while already creating");
assert.match(wizard, /setIsCreating\(true\)/);
assert.match(wizard, /finally \{\s*setIsCreating\(false\);\s*\}/s, "the guard must reset on failure so a retry is possible");

console.log("ok - REQ-ENGCREATE-001 engagement creation guards against duplicate submission");
