---
title: Nmap scheduling and TCP/UDP profile verification
status: ready
risk: R4
owner: security-engineering
---

# Nmap scheduling and profiles

## TC-SCAN-011: Bounded UDP is opt-in, exact, and truthful

Requirements:

- REQ-SCAN-011

Automated tests:

- `control-plane/tests/integration/test_raw_egress_lease.py`
- `raw-egress-gateway/tests/test_gateway.py`
- `worker/tests/test_raw_nmap.py`
- `worker/tests/test_scan_integrity.py`
- `frontend/tests/scan_envelope_requirements.test.mjs`

Objective:

Prove UDP is disabled by default, cannot be widened, uses a signed exact L4
envelope, and retains ambiguous Nmap states without calling them open.

Expected results:

- Disabled and bug-bounty UDP profiles are denied before dispatch.
- The fixed nine-port profile and UDP rate ceiling are identical in the lease,
  nftables rule, worker invocation, and UI.
- Open, closed, filtered, and open-or-filtered counts are durable; only
  confirmed-open ports enter UDP version detection and service persistence.

## TC-SCAN-012: Shared raw gateway schedules runs FIFO

Requirements:

- REQ-SCAN-012

Automated tests:

- `raw-egress-gateway/tests/test_gateway.py`
- `worker/tests/test_raw_egress_client.py`
- `worker/tests/test_scan_integrity.py`

Objective:

Prove concurrent engagements wait fairly without receiving target egress and
that an abandoned active lease is removed promptly.

Expected results:

- Reservations are promoted in FIFO order and a non-head run cannot activate.
- Waiting, cancellation, stale reservations, and capacity remain bounded.
- Deactivation closes the policy immediately; missing heartbeat closes it via
  watchdog and advances the next waiter.

## TC-SCAN-013: Persisted engagement TCP envelope cannot be widened

Requirements:

- REQ-SCAN-013

Automated tests:

- `control-plane/tests/integration/test_engagement_scan_envelope.py`
- `control-plane/tests/integration/test_raw_egress_lease.py`
- `worker/tests/test_raw_nmap.py`
- `worker/tests/test_scan_integrity.py`
- `frontend/tests/scan_envelope_requirements.test.mjs`

Objective:

Prove a single port or contiguous range selected at creation is authoritative
for authorization, egress, Nmap discovery, evidence, and review.

Expected results:

- Defaults are `1-65535`; equal bounds produce a single port.
- Invalid/reversed values and post-activation changes fail closed.
- The signed lease, nftables set, discovery invocation, and audit evidence use
  exactly the persisted range.
