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
