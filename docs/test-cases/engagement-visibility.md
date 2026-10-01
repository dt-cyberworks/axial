---
title: Engagement visibility and owner-only changes verification
status: ready
risk: R3
owner: security-engineering
---

# Engagement Visibility and Owner-only Changes Verification

Verifies [`../requirements/engagement-visibility.md`](../requirements/engagement-visibility.md)
(GitHub issue #47). Negative tests come first in spirit: every refusal also proves that
nothing was written.

## TC-IAM-021: Every engagement has an owner

Requirements:

- REQ-IAM-021

Automated tests:

- `control-plane/tests/integration/test_engagement_visibility.py`
- `control-plane/tests/integration/test_engagement_ownership_http.py`

Objective:

Prove the database refuses an ownerless engagement, the migration adopts legacy rows and stops
safely, and every creation path sets an owner.

Expected results:

- Inserting an engagement without an owner raises an integrity error.
- Migration 0038 on a database with ownerless engagements gives them to the oldest **active**
  administrator (a disabled or newer admin, and any operator, is passed over), restores `NOT NULL`,
  and a second run changes nothing.
- With ownerless engagements and no active administrator the migration fails with
  "no active administrator" and leaves the rows and the column as they were.
- The operator endpoint sets the caller as owner and ignores a client-supplied one; the benchmark
  endpoint uses the oldest active administrator and answers 409 (creating nothing) when none exists.
- Reassigning an owner is admin-only, needs an existing user and rejects `null`.

## TC-IAM-022: Every signed-in user can read every engagement

Requirements:

- REQ-IAM-022

Automated tests:

- `control-plane/tests/integration/test_engagement_visibility.py`
- `control-plane/tests/integration/test_engagement_ownership_http.py`
- `control-plane/tests/integration/test_cross_engagement_findings.py`
- `control-plane/tests/integration/test_surface_graph.py`
- `control-plane/tests/integration/test_scan_plan.py`
- `control-plane/tests/integration/test_extended_discovery.py`

Objective:

Prove reading is open to every signed-in user, on every read route of the real application, and
closed to everyone else.

Expected results:

- The list and the detail carry `owner_name`, `owner_email`, `owner_user_id` and a `can_manage`
  flag that is true for the owner and admins only.
- Every `GET` route under `/engagements/{id}` (the sweep enumerates them) answers a non-owner
  neither 401 nor 403 nor "engagement not found"; findings, audit, runs, summary, scope, grants,
  configuration and reports equal what the owner receives.
- `GET /findings` lists every engagement's findings; `mine=true` narrows list, total and counts;
  an engagement filter shows another user's engagement, and combined with `mine` shows nothing.
- No credentials, or a disabled account's session, reads nothing (401). An unknown id is 404.
- The pending-approval queue lists only the owner's (and for an admin all) approvals.

## TC-IAM-023: Only the owner or an administrator can change an engagement

Requirements:

- REQ-IAM-023

Automated tests:

- `control-plane/tests/integration/test_engagement_visibility.py`
- `control-plane/tests/integration/test_global_settings_authorization.py`
- `control-plane/tests/integration/test_finding_triage.py`
- `control-plane/tests/integration/test_tool_grants_after_creation.py`

Objective:

Prove the single rule refuses every change by a non-owner with 403 before anything is written, on
every route, and cannot be forgotten by a future route.

Expected results:

- The rule: reads pass for everyone; writes pass for the owner and admins; a non-owner gets 403; an
  unknown id is 404 for any method; an admin turned operator loses the right at once.
- The sweep sends every `POST`/`PUT`/`PATCH`/`DELETE` route under `/engagements/{id}` as a
  non-owner and gets 403 with the documented message for each; the table counts, the engagement row
  and the audit log are identical before and after.
- A wiring test fails if any route with `{engagement_id}` lacks the dependency.
- A non-owner approving or rejecting gets 403 whatever the approval's state and writes nothing
  (not even `expired`); an approval that does not exist is 404; an admin can decide.
- Reassigning an owner by the owner or anyone else is 403; the former owner keeps read access and
  loses change access.

## TC-IAM-024: The activation overlap error names the engagement

Requirements:

- REQ-IAM-024

Automated tests:

- `control-plane/tests/integration/test_engagement_visibility.py`
- `control-plane/tests/integration/test_scope_overlap_activation.py`

Objective:

Prove the refusal is unchanged and now names the engagement and its owner.

Expected results:

- The 409 starts with the established sentence and names the title, the owner's name and email.
- With more than three conflicts exactly three are named and "and N more" follows.
- The same holds when an allow row is added to an already-active engagement.
- Without an overlap, activation succeeds and names nothing; the existing overlap tests pass unchanged.

## TC-IAM-025: The console shows ownership and read-only state

Requirements:

- REQ-IAM-025

Automated tests:

- `frontend/tests/engagement_visibility_requirements.test.mjs`
- `frontend/tests/console_information_architecture.test.mjs`

Objective:

Prove the console lists owners, filters by "mine", and offers no change control the server would
refuse, and that a new place that changes an engagement is noticed.

Expected results:

- The API types carry the owner fields and `can_manage`; the overview has the Owner column and the
  Only mine filter whose "mine" means "owned by me", and the numbers follow it.
- Edit, Delete, activation, attestation, tool grants, Start run, Generate report, triage, the Lens
  request, Stop scan, the asset-review decision and the audit override are each behind the flag; an
  unknown flag means no.
- A client function that changes an engagement used in a file not on the reviewed list fails the test.
- Live (dev): a second operator sees the other's engagement read-only and a direct change returns 403.
