---
title: Operator control actions
status: implemented
risk: R3
owner: product-engineering
---

# Operator Control Action Requirements

## REQ-ENG-001: Engagement deletion is complete, atomic, and auditable

An operator may permanently delete an engagement only when no scan is active.
Deletion must remove the complete mutable engagement data graph without leaving
foreign-key failures or partial data, while retaining the append-only audit proof.

Acceptance criteria:
- A newly created engagement always starts in `draft`; the create request cannot
  directly grant a more permissive lifecycle status.
- `DELETE /engagements/{id}` returns 204 for an existing engagement with no run
  in `running` or `waiting_approval`. A missing engagement returns 404.
- The delete decision is independent of the engagement lifecycle status:
  `draft`, `awaiting_signature`, `active`, `paused`, `completed`, and `revoked`
  are deletable without an active run. Runs in `done`, `failed`, or `aborted`
  are terminal and do not block deletion.
- A running or approval-waiting run returns 409; no dependent data is deleted and
  no successful-deletion audit entry is written, regardless of the engagement
  lifecycle status.
- The deletion removes scope/grants/config, programs, approvals, resolved hosts,
  DNS records, discovered assets, services, findings, finding observations, agent
  steps, and scan runs in foreign-key-safe leaf-to-root order.
- Deletion and the `engagement_deleted` append-only audit event commit atomically.
  A missed dependency or audit failure rolls back the deletion.
- Audit rows are deliberately retained after the engagement row is gone and the
  retained event includes the engagement ID, title, previous status, operator
  action, reason, and hash-chain fields.
- A successful 204 removes the engagement and its stale detail/run data from the
  operator console cache without requiring a page reload.
