---
title: Engagement creation guards against duplicate submission
status: verified
risk: R2
owner: security-engineering
---

**Deployed to int 2026-08-09** via isolated worktree (5 files: `EngagementWizard.tsx`,
`scan_envelope_requirements.test.mjs`, `engagement_creation_double_submit.test.mjs`,
`package.json`, this doc + its test-case doc) — excluded the in-flight agent
terminology rename and the then-unapproved REQ-APPROVAL-006 R4 fix, both untouched.
`tsc` clean, `test:requirements` 10/10 pass, built bundle confirmed live on
scan-int.example.org with the new "Creating…" label present. The two pre-existing
duplicate empty "pentest ground" drafts were deleted from int's database.

# Engagement Creation Double-Submit Guard

## REQ-ENGCREATE-001: The wizard's Create button cannot fire more than one request per click sequence

Context: found live 2026-08-09 - johannes created one engagement targeting
`pentest-ground.com` and ended up with three, all titled identically,
created within 15 seconds of each other (same owner). Root cause:
`EngagementWizard.tsx`'s "Create engagement" button had no
submission-in-progress guard at all - its `disabled` attribute only checked
form-field validity, never whether a create request was already in flight.
Two clicks (impatience, a slow network, or a genuine double-click) fired two
full `POST /engagements` calls before the first response ever arrived to
advance the wizard past step 1, silently creating duplicate draft
engagements with the identical title and no way for the operator to tell,
from the button alone, that anything had gone wrong.

**Risk class: R2** (a frontend data-integrity/UX fix - no Scope Gateway,
authorization, or egress change; does not touch what an engagement is
authorized to do, only how many empty duplicates of it can accidentally be
created).

Acceptance criteria:

- The Create button is disabled for the full duration of the create request
  (`isCreating`), not only while required fields are empty, and shows a
  distinct "Creating…" label while disabled this way.
- `handleCreateEngagement` itself early-returns if a creation is already in
  flight, as defense in depth on top of the disabled button - in case
  anything else ever dispatches the handler a second way.
- The guard resets on failure (so a genuinely failed create can be retried)
  and does not need to reset on success (the wizard navigates to step 2).
- [Regression test] a structural check on the button's `disabled` expression
  and the handler's early-return guard, matching this codebase's existing
  convention of source-level requirement tests for the operator console
  (`frontend/tests/*.test.mjs`).

Not fixed as part of this: `POST /engagements` itself has no
server-side idempotency key or dedup check - two *genuinely concurrent*
requests from two different tabs/devices could still both succeed. Out of
scope here (this fixes the single-click-storm case, which is what was
actually observed and is the overwhelmingly common cause); a server-side
idempotency key would be a separate, larger change if this ever recurs
despite the client-side guard.

## REQ-ENGCREATE-002: One wizard session edits one draft; saving a step again never duplicates

Context: GitHub issue #46, found live 2026-09-30 on dev. Two drafts with the
same title and owner were created 96 seconds apart, so the in-flight guard of
REQ-ENGCREATE-001 was not involved: the operator had returned to step 1 through
the step sidebar and pressed "Save draft and continue" again. That handler
always called `POST /engagements` and overwrote the wizard's `engagementId`, so
every later call targeted the new draft and the first was left behind with no
scope and no tools. Step 3 had the same flaw one level down: it re-sent every
scope row, and `POST /scope-assets` does not deduplicate, so going back and
saving step 3 again duplicated the scope.

**Risk class: R2** (frontend data-integrity fix: no change to scope semantics,
authorization, the gateway or egress; the server-side endpoints are unchanged).

Acceptance criteria:

- Once the wizard session has a draft (`engagementId` is set), step 1 updates
  that draft with `PATCH /engagements/{id}` and never sends a second
  `POST /engagements`. A cleared emergency contact is sent as `null`, because
  PATCH only applies the fields it receives.
- The step-1 button says "Save changes and continue" (and "Saving…" while in
  flight) when it edits an existing draft. Its first-create wording and the
  REQ-ENGCREATE-001 guards are unchanged.
- Saving step 3 again sends only scope rows that are new or were edited since
  the last save. An edited saved row is replaced (delete, then add); an
  unchanged row is not sent again. If a call fails part-way, what already went
  through is remembered, so a retry does not repeat it.
- The draft id is kept in the URL (`/new?draft=<id>`). Opening that
  URL after a reload or after navigating away resumes the draft: the step-1
  fields, the scope rows and the saved tool grants are loaded from the server
  and the wizard continues at step 2, without creating another draft.
- [Negative test] Only a draft can be resumed. An engagement that is no longer
  a draft, or an id the caller cannot open (the server answers 404), clears the
  URL parameter and shows a message instead of creating or changing anything.
- [Regression test] Source-level checks on the handler's `engagementId`
  branch, the single `createEngagement` call, the step-3 sync and the resume
  path (`frontend/tests/engagement_creation_double_submit.test.mjs`).

Not part of this: the 409 that `POST /engagements/{id}/activate` returns when
the new allow scope overlaps another active engagement (REQ-CONCUR-003) is
expected behavior. Dashboard handling of abandoned, empty drafts is a separate
improvement.
