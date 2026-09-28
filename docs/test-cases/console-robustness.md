---
title: Console robustness and first-use clarity verification
status: ready
risk: R1
owner: product-engineering
---

# Console Robustness Verification

Verifies [`../requirements/console-robustness.md`](../requirements/console-robustness.md).
The source-level checks below run in CI; the behavior was also checked in a
real browser against a local stack (unknown engagement, unknown run, unknown
path, empty overview, wizard step 1, readiness failure).

## TC-CONSOLE-008: Not-found and readiness states

Requirements:

- REQ-CONSOLE-008

Automated tests:

- `frontend/tests/console_robustness_requirements.test.mjs`

Objective:

Prove the console never presents a missing engagement or run as a working
page, and never shows "ready" without the server saying so.

Expected results:

- Not-found pages for engagements and runs, driven by `ApiError.status`.
- The readiness banner's four states in order: error, loading, blocked, ready; the old two-state form is gone.

## TC-CONSOLE-009: 404 route

Requirements:

- REQ-CONSOLE-009

Automated tests:

- `frontend/tests/console_robustness_requirements.test.mjs`

Objective:

Prove unknown paths render a 404 page.

Expected results:

- A catch-all route renders `NotFound`.

## TC-CONSOLE-010: Onboarding

Requirements:

- REQ-CONSOLE-010

Automated tests:

- `frontend/tests/console_robustness_requirements.test.mjs`

Objective:

Prove the empty overview explains engagements and links to the wizard.

Expected results:

- Onboarding panel with the explanation, three steps, and the wizard link when there are no engagements.

## TC-CONSOLE-011: Wizard step 1

Requirements:

- REQ-CONSOLE-011

Automated tests:

- `frontend/tests/console_robustness_requirements.test.mjs`
- `frontend/tests/engagement_creation_double_submit.test.mjs`

Objective:

Prove step 1 says it saves a draft, folds the expert options, and keeps its double-submit guard.

Expected results:

- "Save draft and continue", the draft note, and a collapsed "Advanced options" section; the in-progress label test still passes.

## TC-CONSOLE-012: User-facing text

Requirements:

- REQ-CONSOLE-012

Automated tests:

- `frontend/tests/console_robustness_requirements.test.mjs`

Objective:

Prove activation errors and `make help` are plain English and destructive targets are marked.

Expected results:

- No retired-chapter references in activation errors; English `make help` with the data-loss warning; logout aligned.
