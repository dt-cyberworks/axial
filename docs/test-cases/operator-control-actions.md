---
title: Operator control action verification
status: ready
risk: R3
owner: engineering
---

# Operator control action verification

## TC-ENG-001: Complete and safe engagement deletion

Requirements:

- REQ-ENG-001

Automated tests:

- `control-plane/tests/integration/test_engagement_delete.py`
- `frontend/tests/operator_control_actions.test.mjs`

Objective:

Verify that the full engagement dependency graph is deleted atomically, the
audit proof is retained, active-run deletion fails without partial changes, and
the successful UI mutation evicts stale cached data.

Expected results:

- A complete terminal engagement graph deletes with HTTP 204 and no FK error.
- `finding_observation` and `agent_step` are removed before their parents.
- An active run yields 409 and leaves engagement/run/audit state unchanged.
- The retained deletion audit row remains hash-chain compatible.

## TC-ENG-002: Engagement lifecycle create/delete matrix

Requirements:

- REQ-ENG-001

Automated tests:

- `control-plane/tests/integration/test_engagement_delete.py`

Objective:

Verify that creation always starts in `draft` and that deletion behavior is
consistent across `draft`, `awaiting_signature`, `active`, `paused`,
`completed`, and `revoked`.

Expected results:

- Every newly created engagement is persisted as `draft`.
- Every engagement status can be deleted when no scan run exists.
- Terminal runs in `done`, `failed`, or `aborted` do not block deletion in any
  engagement status.
- Runs in `running` or `waiting_approval` block deletion with HTTP 409 in every
  engagement status and preserve the engagement, run, and audit state.

