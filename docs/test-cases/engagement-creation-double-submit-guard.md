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
