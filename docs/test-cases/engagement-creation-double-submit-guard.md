---
title: Engagement creation double-submit guard verification
status: ready
risk: R2
owner: security-engineering
---

# Engagement Creation Double-Submit Guard Verification

Verifies [`../requirements/engagement-creation-double-submit-guard.md`](../requirements/engagement-creation-double-submit-guard.md).

## TC-ENGCREATE-001: The Create button and its handler both guard against double submission

Requirements:

- REQ-ENGCREATE-001

Automated tests:

- `frontend/tests/engagement_creation_double_submit.test.mjs`

Objective:

Structurally confirm the guard exists in both the button's `disabled`
expression and the handler itself, matching this project's convention of
source-level requirement tests for the operator console (real component
rendering/interaction tests are not part of this test tier).

Expected results:

- The Create button's `disabled` expression includes `isCreating`, not only
  the form-validity checks that existed before.
- The button's label switches to a distinct in-progress state ("Creating…")
  while `isCreating` is true.
- `handleCreateEngagement` early-returns when `isCreating` is already true,
  before any state mutation or network call.
- `isCreating` is set before the `createEngagement` call and reset in a
  `finally` block, so a failed create can be retried.

## TC-ENGCREATE-002: Step 1 edits the existing draft, step 3 re-saves are idempotent, a draft resumes from the URL

Requirements:

- REQ-ENGCREATE-002

Automated tests:

- `frontend/tests/engagement_creation_double_submit.test.mjs`

Objective:

Confirm structurally that the wizard cannot create a second draft for the same
session and cannot duplicate scope rows, and confirm the real behavior in a
browser against the dev stack (recorded below).

Expected results:

- `handleCreateEngagement` calls `api.updateEngagement(engagementId, ...)` when
  a draft exists and has exactly one `api.createEngagement(...)` call, in the
  other branch; a cleared contact is sent as `null` on the PATCH path.
- Step 3 goes through `syncScopeAssets`: it compares against the saved rows,
  replaces edited ones with `api.deleteScopeAsset` + add, and records progress
  in a `finally` block. `handleSaveAssetsAndGrants` no longer calls
  `api.addScopeAsset` directly.
- The draft id is written to and read from the `?draft=` URL parameter, and a
  non-draft engagement is refused.
- Live (dev, Playwright): create a draft in step 1, continue to step 2, click
  "Window" in the sidebar and save again: exactly one engagement with that
  title exists. Save step 3, go back and save it again: no duplicate scope rows.
  Reload on `?draft=<id>`: the fields, scope and grants come back at step 2.

Live result (2026-09-30, dev stack, real Chrome through Playwright, 15 of 15
checks passed): the first save created one draft and put its id in the URL;
going back to step 1 through the sidebar showed "Save changes and continue" and
saving again created no second draft and changed the existing one; a cleared
emergency contact was cleared on the server; saving step 3 twice left exactly
one scope row; editing the saved row replaced it instead of duplicating it;
opening `/new?draft=<id>` resumed at step 2 with the title, scope row and
grants restored and created nothing; an unknown draft id showed "Could not
resume that draft" and created nothing. The throwaway drafts were removed
through `DELETE /engagements/{id}`.
