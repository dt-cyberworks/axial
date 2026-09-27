---
title: FIFO scheduling for the shared Nmap gateway
status: implemented
risk: R4
owner: security-engineering
---

# FIFO scheduling for the shared Nmap gateway

## REQ-SCAN-012: Concurrent raw scans wait fairly without widening egress

When one engagement is using the shared Compose raw-egress gateway, a raw scan
from another engagement shall wait in a bounded FIFO queue instead of failing
with a lease-busy error.

Acceptance criteria:

- A run obtains a bounded FIFO reservation before the control plane issues and
  the gateway activates its signed raw-egress lease; waiting grants no target
  network access.
- Only the queue head may activate a lease, and the lease scan-run identity
  must match the current opaque reservation.
- The active lease begins immediately before Nmap dispatch and is revoked in a
  `finally` path immediately afterwards; a missing heartbeat closes the
  firewall policy within a short watchdog interval.
- Releasing, cancelling, timing out, or abandoning a reservation advances the
  next live waiter without allowing it to replace an active target.
- Queue length and wait time are bounded. Capacity, gateway, token, policy, or
  cleanup failures remain fail-closed and are never reported as a clean scan.
- Automated tests cover FIFO order, cross-engagement isolation, cancellation,
  stale reservations, matching activation, heartbeat expiry, and cleanup.

Value and context:

- Operators can run engagements concurrently without a harmless infrastructure
  contention being misreported as a target scan failure.

Open questions and dependencies:

- Production Kubernetes can use per-job network namespaces; this FIFO contract
  is specifically required for the shared Compose gateway.

Implementation authorization:

- Explicitly authorized by the repository owner in the 2026-07-26 request to
  create and implement this backlog item; normal R4 review/release gates remain.

Backlog decision log:

- 2026-07-26 — requested by the repository owner and promoted in the same
  change for implementation with FIFO fairness and minimum lease lifetime.

Security invariants:

- Scope Gateway authorization, deny precedence, exact materialized IP binding,
  runner isolation, deny-all baseline, and fail-closed cleanup remain mandatory.
