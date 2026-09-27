---
title: Raw-egress lease lifecycle stability verification
status: ready
risk: R3
owner: security-engineering
---

# Raw-Egress Lease Lifecycle Stability Verification

Verifies [`../requirements/raw-egress-lease-stability.md`](../requirements/raw-egress-lease-stability.md).
R3: negative paths (live run/lease not affected) are required.

## TC-RAWLEASE-001: Stale runs are reaped; live runs are not

Requirements:

- REQ-RAWLEASE-001

Automated tests:

- `control-plane/tests/integration/test_scan_run_reaper.py`

Objective:

Verify the control plane reaps `running`/`waiting_approval` runs with a stale
`heartbeat_at`, unblocking new scans, while never reaping a run with a fresh
heartbeat.

Expected results:

- A run with `heartbeat_at` older than the threshold becomes `aborted` (reason
  reaped) with `finished_at` set; a new run can then be created.
- A run with a fresh `heartbeat_at` is left untouched and still blocks a new run
  (409).
- The heartbeat endpoint refreshes `heartbeat_at`.

## TC-RAWLEASE-002: Lease release is idempotent

Requirements:

- REQ-RAWLEASE-002

Automated tests:

- `raw-egress-gateway/tests/test_gateway.py`

Objective:

Verify deactivate/release never errors on an already-gone or superseded lease and
never leaves a foreign policy installed, while a valid deactivate still clears.

Expected results:

- Deactivate with no active lease, or with a superseding lease active, returns
  without raising and does not clear the foreign lease's policy.
- Release of an already-removed reservation returns without raising.
- A valid deactivate of the current lease clears the policy and frees the slot.

## TC-RAWLEASE-003: Activation reclaims a dead-heartbeat lease

Requirements:

- REQ-RAWLEASE-003

Automated tests:

- `raw-egress-gateway/tests/test_gateway.py`

Objective:

Verify a lapsed-heartbeat holder is reclaimed on a new activation, a live holder
still blocks, and `status()` reconciles a dead lease.

Expected results:

- With the installed lease's `heartbeat_deadline` in the past, a new reservation's
  activation reclaims the slot and installs its own policy.
- With a live heartbeat, a different lease still raises `raw_egress_lease_busy`.
- `status()` on a dead-heartbeat lease reports no active lease (reconciled).

## TC-RAWLEASE-004: A reservation survives a long, multi-stage scan

Requirements:

- REQ-RAWLEASE-004

Automated tests:

- `raw-egress-gateway/tests/test_gateway.py`

Objective:

Verify a reservation backed by regular heartbeat activity never idle-expires
across two sequential lease acquisitions spanning longer than the idle timeout,
while a genuinely abandoned reservation still expires.

Expected results:

- Repeated `heartbeat()` calls spanning more than the reservation idle timeout,
  followed by `deactivate()` and an immediate second `activate()` under the same
  reservation (a different protocol/profile), succeed — no
  `reservation_not_granted`.
- A reservation with no activity at all is still pruned after the idle timeout
  and its slot is granted to the next waiter.
