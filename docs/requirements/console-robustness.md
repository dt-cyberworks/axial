---
title: Console robustness and first-use clarity
status: implemented
risk: R1
owner: product-engineering
---

# Console Robustness and First-Use Clarity

Context: a browser tour of the integration environment during the
2026-09-27 review found screens that invent a state instead of showing
one — most seriously, opening an engagement that does not exist rendered a
full engagement page whose pre-flight banner said "All pre-flight checks
pass" — and a first-use experience that explained nothing. Continues
REQ-CONSOLE-001..007 in [`console-layout-and-navigation.md`](console-layout-and-navigation.md).

**Risk class: R1** (UI and user-facing text only; no API or data change).

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

## REQ-CONSOLE-008: Missing records and unknown readiness are shown as such

Acceptance criteria:

- Opening an engagement that does not exist, has a malformed id, or
  belongs to another user shows "Engagement not found" with a way back —
  no engagement header, actions, or sections.
- The same applies to a scan run that is not part of the engagement.
- A load failure other than "not found" says so and offers a retry.
- Nothing else about the engagement is requested (or polled) until the
  engagement itself has loaded.
- [Negative test] The pre-flight banner is green only when the server
  reported the engagement ready: while the check is loading it says so,
  and if the check fails it shows an error — never "All pre-flight checks
  pass".
- API errors carry their HTTP status (`ApiError`), so "not found" (404, or
  422 for a malformed id) is told apart from other failures.

## REQ-CONSOLE-009: Unknown paths show a 404 page

Acceptance criteria:

- Any path inside the console that matches no route shows a "Page not
  found" page with a link to the overview, instead of an empty frame.

## REQ-CONSOLE-010: A first-time user is told what to do

Acceptance criteria:

- With no engagements, the overview explains in plain words what an
  engagement is (scope, test window, tools; nothing scanned before
  authorization and activation), lists the three steps to a first scan,
  and links to the wizard.

## REQ-CONSOLE-011: The wizard's first step says what it does

Acceptance criteria:

- Step 1's button reads "Save draft and continue", with a note that it
  saves a draft and that nothing is scanned before authorization and
  activation in step 5. Its in-progress label ("Creating…") and
  double-submit guard are unchanged (REQ in
  [`engagement-creation-double-submit-guard.md`](engagement-creation-double-submit-guard.md)).
- The optional expert switches (bounded UDP discovery, Vector Agent
  proposals, asset review pause) are grouped under a collapsed "Advanced
  options" section; their defaults are unchanged (all off).
- The emergency-contact field explains what it is for.

## REQ-CONSOLE-012: Plain, consistent user-facing text

Acceptance criteria:

- Engagement activation errors are plain English and name the fix (for
  example "add at least one in-scope target first"), instead of German
  text citing chapters of retired specification documents.
- `make help` is English throughout, and marks the targets that delete
  data (`down`, and `lab-test` without `KEEP_UP=1`).
- The sidebar's "Log out" entry is aligned like the other navigation
  entries.
- The engagement header's risk signal shows the highest open severity in
  English ("Critical" … "Info", or "None open"), not the API's internal
  German traffic-light value ("ROT", "BLAU"), which also merged critical
  with high and "nothing open" with low.

Security invariants:

- None changed. REQ-CONSOLE-008 removes a misleading "ready" signal; the
  start button's own guard (disabled unless the server says ready) was
  already correct and is unchanged.
