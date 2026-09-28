---
title: Continuous monitoring and change alerts
status: backlog
risk: R3
owner: product-engineering
---

# Continuous Monitoring and Change Alerts

From the 2026-09-27 review (finding A5): the scanner has no scheduled
re-scans and no alerting, which are the two things that make attack
surface *management* out of an assessment tool. The run-over-run diff
(`scan_diff.py`) already computes new / no-longer-seen findings and is the
right foundation.

## REQ-MON-001: Scheduled re-scans inside the authorized window

The system shall re-run an engagement's scan on a schedule the operator
sets, only while the engagement is active and inside its authorized
window.

Acceptance criteria:

- An engagement can have a schedule (for example daily, weekly) set by its
  owner; the default is none.
- A scheduled run goes through exactly the same readiness checks, Scope
  Gateway, and budgets as a manual run, and is audited as scheduled.
- [Negative test] No scheduled run starts outside the authorized window,
  for a paused/revoked/completed engagement, or while another run is
  active; each skip is visible with its reason.
- The schedule stops by itself when the authorized window ends.

## REQ-MON-002: Alerts on new assets and new findings

The system shall notify the engagement owner when a run discovers a new
in-scope asset or a new finding at or above a chosen severity.

Acceptance criteria:

- Notification channels: e-mail and a generic webhook (HMAC-signed body).
- An alert names the engagement, what is new, and links to the console; it
  contains no evidence, credentials, or raw tool output.
- Triaged findings (accepted risk, false positive) do not alert again.
- Delivery failures are retried and visible; they never fail the run.

Value and context:

- Continuous discovery and change alerts are the core value of an ASM
  product for customers and for bug-bounty hunters (new subdomain = new
  opportunity).

Open questions and dependencies:

- Legal: does an unattended scheduled scan need an explicit clause in the
  rules of engagement / customer contract? (`docs/legal.md`)
- Which e-mail transport (SMTP relay vs. provider API); secrets handling.
- Should bug-bounty programs cap the schedule (for example no more than
  daily) by program policy?
- Worker capacity on a single small host (see the IONOS sizing notes).

Implementation authorization:

- None until this requirement is promoted out of `backlog` through SDLC
  review by johannes.

Backlog decision log:

- 2026-09-27 — proposed by the review agent as the highest-value product
  gap; awaiting johannes's decision on scope and the legal question.

Security invariants:

- A schedule never widens scope or bypasses the gateway, window, budgets,
  or approvals; scheduled runs are indistinguishable from manual ones in
  what they may do.
- Alerts carry no sensitive evidence; webhooks are signed.
