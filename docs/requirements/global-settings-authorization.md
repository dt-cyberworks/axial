---
title: Admin-only global settings and owner-first approval decisions
status: implemented
risk: R3
owner: security-engineering
---

# Admin-Only Global Settings and Owner-First Approval Decisions

Context: the 2026-09-27 review found that the console hides the global
settings from non-admins, but the API did not. `/settings/*` required only
an authenticated user, so any operator could change settings that act on
every other user's engagements — most seriously the LLM endpoint: pointing
`base_url` at a server they control would hand them every engagement's
agent traffic plus the configured API key, and make the control plane send
requests from its internal network. Two smaller account and approval
issues were found in the same pass.

**Risk class: R3** (authorization). Extends REQ-IAM-007/008. Needs human
security review.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

## REQ-IAM-013: Global settings are admin-only at the API

Acceptance criteria:

- Every `/settings/*` endpoint (LLM endpoint and key, NVD key, scan
  policy, tool policy, agent prompt, agent iteration and token budgets,
  approval timeout) requires the `admin` role, for reading and writing.
- [Negative test] An `operator` gets `403` on every read and every write,
  and a write leaves the stored value unchanged — in particular, an
  operator cannot redirect the LLM endpoint.
- Without credentials the endpoints answer `401`.
- An `admin` can read and write them as before.
- Per-engagement configuration (`/engagements/{id}/config`) is unchanged:
  it stays with the engagement's owner.

## REQ-IAM-014: Approval decisions check ownership before anything else

> **Amended by REQ-IAM-023 (johannes, 2026-10-01, GitHub issue #47, `docs/requirements/engagement-visibility.md`).**
> Every engagement is readable by everyone now, so a non-owner's refusal is `403`
> (the check still comes first, before any state is revealed or written); `404`
> remains for an approval that does not exist.

Acceptance criteria:

- [Negative test] Approving or rejecting another user's approval answers
  `403` whatever that approval's state — no `409` revealing it was already
  decided or has expired. An approval that does not exist answers
  `404 approval not found`.
- [Negative test] A non-owner's request never writes to the approval, not
  even to mark an expired one `expired`.
- The owner (or an admin) still gets `409` for an approval that is no
  longer pending.

## REQ-IAM-015: An admin password reset lets the user back in

Acceptance criteria:

- Resetting a user's password clears their failed-login counter and any
  active lockout, so the temporary password works immediately.
- [Negative test] A user locked out by failed attempts can log in with the
  admin-issued temporary password right after the reset.

Security invariants:

- Deny is the default: the settings router carries the admin dependency
  once, for every current and future settings endpoint.
- Tenant isolation (REQ-IAM-007) now covers global configuration too.
