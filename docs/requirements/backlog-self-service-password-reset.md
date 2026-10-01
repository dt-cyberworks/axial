---
title: Self-service password reset by e-mail
status: backlog
risk: R4
owner: product-engineering
---

# Self-service Password Reset by E-mail

Today a forgotten password is recovered only by an administrator
(`POST /admin/users/{id}/reset-password`, REQ-IAM-008 / REQ-IAM-015), who
relays a temporary password out-of-band. REQ-IAM-008 deliberately left out any
e-mail/SMTP dependency "in this iteration", and the user manual says there is
no self-service reset. This record captures the follow-up so the decision is
not lost; nothing here is authorized for implementation.

## REQ-IAM-020: A user can reset a forgotten password through an e-mailed link

The system shall let a user who has forgotten their password request a
single-use reset link by e-mail and choose a new password, without an
administrator, while keeping the second factor in force.

Acceptance criteria:

- The sign-in page offers "Forgot password?" only when an e-mail transport is
  configured; with none configured the behavior is unchanged from today.
- The request response is identical whether or not the e-mail belongs to an
  account (no account enumeration), including timing.
- A reset token is random, single-use, stored only as a hash, and expires
  after a short fixed time (proposed: 30 minutes); requesting a new one
  invalidates the previous one.
- Completing a reset sets the new password, revokes all of the user's
  sessions, clears the failed-login lockout, and writes an account audit entry
  for the request and the completion.
- A reset never disables, bypasses, or resets MFA: the next sign-in still
  requires the authenticator code.
- [Negative test] An expired, already-used, tampered, or other user's token is
  rejected without changing the password; requests are rate-limited per
  account and per source address; a disabled account receives no usable link;
  the e-mail contains no password and no secret other than the link.

Value and context:

- Removes the dependency on a human admin being reachable; the only admin
  locking themselves out has already happened twice (see the int account
  resets of 2026-09-15 and 2026-09-27).
- Shares an e-mail transport with the alert channel in REQ-MON-002.

Open questions and dependencies:

- E-mail transport: SMTP relay (IONOS offers one) vs. provider API;
  credentials stored encrypted in admin-only settings like the LLM key
  (REQ-IAM-013).
- Whether a reset should also be possible for a user who has lost their MFA
  device (proposed: no; that stays an admin action).
- Same dependency as REQ-MON-002 (`backlog-continuous-monitoring.md`); decide
  the transport once for both.
- Requires an explicit change to the REQ-IAM-008 "no e-mail/SMTP dependency"
  statement and to the manual pages that say the system sends no e-mail.

Implementation authorization:

- None until this requirement is promoted out of `backlog` through SDLC review
  (typically `backlog` → `draft` → `reviewed` → `approved`). R4: needs negative
  tests and human security review before it counts as done.

Backlog decision log:

- 2026-10-01 — raised by johannes as an expected feature; confirmed absent
  from the codebase. Proposed design above; johannes chose to leave it in the
  backlog for now.

Security invariants:

- Account-takeover resistance: MFA stays mandatory after a reset; tokens are
  single-use, short-lived, and hashed at rest.
- No account enumeration through the request endpoint.
- The e-mail transport secret is stored encrypted and is admin-only.
