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
// A first create still reads "Creating…" / "Save draft and continue"; once the
// session owns a draft (REQ-ENGCREATE-002) the same button edits it instead.
assert.match(
  wizard,
  /isCreating \? \(engagementId \? "Saving…" : "Creating…"\) : engagementId \? "Save changes and continue" : "Save draft and continue"/,
  "the button must show a distinct in-progress label, and say it edits when a draft already exists",
);

// Defense in depth: the handler itself must refuse to fire a second request
// even if something dispatches it a second way.
assert.match(wizard, /if \(isCreating\) return;/, "handleCreateEngagement must early-return while already creating");
assert.match(wizard, /setIsCreating\(true\)/);
assert.match(wizard, /finally \{\s*setIsCreating\(false\);\s*\}/s, "the guard must reset on failure so a retry is possible");

console.log("ok - REQ-ENGCREATE-001 engagement creation guards against duplicate submission");

// REQ-ENGCREATE-002 (GitHub issue #46): going back to step 1 and saving again
// used to POST a second draft and orphan the first.
assert.match(requirement, /## REQ-ENGCREATE-002:/);

const createHandler = wizard.slice(
  wizard.indexOf("async function handleCreateEngagement()"),
  wizard.indexOf("// GitHub issue #46: resume a draft"),
);
assert.ok(createHandler.length > 200, "handleCreateEngagement must be found");
assert.match(
  createHandler,
  /engagementId\s*\?\s*await api\.updateEngagement\(engagementId,[\s\S]*?:\s*await api\.createEngagement\(/,
  "with a draft in this session step 1 must PATCH it; only without one may it POST",
);
assert.equal((createHandler.match(/api\.createEngagement\(/g) ?? []).length, 1, "there is exactly one create call, behind the engagementId branch");
assert.match(createHandler, /emergency_contact: emergencyContact \|\| null/, "a cleared contact must be sent as null on the PATCH path");

// Step 3 re-saves must be idempotent: POST /scope-assets does not deduplicate.
const syncAssets = wizard.slice(wizard.indexOf("async function syncScopeAssets"), wizard.indexOf("async function handleSaveAssetsAndGrants"));
assert.match(syncAssets, /savedAssets/, "step 3 must compare against the rows it already saved");
assert.match(syncAssets, /api\.deleteScopeAsset\(/, "an edited saved row is replaced, not duplicated");
assert.match(syncAssets, /finally \{\s*setSavedAssets\(tracked\);\s*\}/s, "progress is kept when a call fails part-way");
const saveStep3 = wizard.slice(wizard.indexOf("async function handleSaveAssetsAndGrants"), wizard.indexOf("async function handleActivate"));
assert.doesNotMatch(saveStep3, /api\.addScopeAsset\(/, "step 3 must not POST every row directly");
assert.match(saveStep3, /syncScopeAssets\(engagementId\)/);

// A reload resumes the draft from the URL instead of orphaning it.
assert.match(wizard, /setSearchParams\(\{ draft: eng\.id \}/, "the draft id is kept in the URL");
assert.match(wizard, /searchParams\.get\("draft"\)/, "the wizard resumes a draft from ?draft=");
assert.match(wizard, /eng\.status !== "draft"/, "only a draft can be resumed");

console.log("ok - REQ-ENGCREATE-002 one wizard session edits one draft and re-saves are idempotent");
