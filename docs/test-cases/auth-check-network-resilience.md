---
title: Auth check network resilience verification
status: ready
risk: R2
owner: security-engineering
---

# Auth Check Network Resilience Verification

Verifies [`../requirements/auth-check-network-resilience.md`](../requirements/auth-check-network-resilience.md).

## TC-IAM-012: The session check retries on network failure and shows a recoverable error otherwise

Requirements:

- REQ-IAM-012

Automated tests:

- `frontend/tests/auth_check_network_resilience.test.mjs`

Objective:

Structurally confirm `AuthenticatedShell` in `frontend/src/App.tsx` retries
the `/auth/me` check only for network-level failures, and falls back to a
visible, recoverable error state - not a blank render - once retries are
exhausted, matching this project's convention of source-level requirement
tests for the operator console (real component rendering/interaction tests
are not part of this test tier).

Expected results:

- The `useQuery` for `["me"]` has a `retry` predicate that checks the error
  is a `TypeError` and caps at a bounded attempt count, plus a `retryDelay`.
- An `isError` branch renders `AuthLayout` with the failure message and a
  "Retry" button wired to `refetch`, before the pre-existing
  `if (!me) return null;` fallback.
- The Retry button is disabled while a retry is in flight (`isFetching`).
