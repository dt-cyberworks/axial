# Architecture: Raw-Egress Lease Lifecycle Stability

Implements [`../requirements/raw-egress-lease-stability.md`](../requirements/raw-egress-lease-stability.md).

## Principle

Make the existing single-slot FIFO lease **crash-consistent** without changing
its security envelope. Three independent recovery mechanisms, each cheap and
locally testable. No new concurrency, no new architecture.

## 1. Scan-run heartbeat + lazy reaper (REQ-RAWLEASE-001)

- **Data model (migration 0009):** `scan_run.heartbeat_at TIMESTAMPTZ DEFAULT now()`.
- **Worker refreshes it** while making progress: on every `ScanRunUpdate` (phase/
  state) — server-side bump — and via a dedicated heartbeat call from the
  raw-egress lease heartbeat loop, so a long Nmap (minutes) keeps its run alive.
- **Lazy reaper** `reap_stale_runs(db, engagement_id)`: transitions any
  `running`/`waiting_approval` run with `heartbeat_at < now - STALE_RUN_SECONDS`
  to `aborted` (`state_reason="reaped_stale_heartbeat"`, `finished_at=now`). It is
  called at the top of scan-run creation and in scan-readiness. No scheduler is
  required — reaping happens exactly when a new scan is requested (when the
  unblock is needed). `STALE_RUN_SECONDS` is a bounded setting (default 300s;
  longer than the worker's heartbeat interval, shorter than an abandoned run's
  useful life).

Endpoint: `POST /internal/engagements/{id}/scan-runs/{run_id}/heartbeat`.

## 2. Idempotent lease release (REQ-RAWLEASE-002)

`RawEgressGateway.deactivate` / `release` become best-effort:
- Deactivate returns silently when there is no active lease, when the active lease
  is a *different* (superseding) lease, or when the caller's reservation was
  superseded. It clears the policy **only** when the caller owns the current lease.
- Release returns silently when the reservation is already gone.

This never installs or clears a foreign lease; it only prevents cleanup from
erroring and stranding state.

## 3. Activation reclaims a dead-heartbeat lease (REQ-RAWLEASE-003)

`RawEgressGateway.activate` and `status` gain a `_reconcile_locked(now)` step:
if `self._active` exists and `now >= self._active.heartbeat_deadline`, the holder
is dead → clear its policy and free the slot before proceeding. The busy check
then blocks only on a **live** lease (`heartbeat_deadline > now`) that is a
different lease id — same-lease re-activation stays idempotent.

## 4. Reservation keepalive across multi-stage scans (REQ-RAWLEASE-004)

Discovered post-deployment: `_nmap_scan()` acquires one reservation and uses it
for two *sequential* lease activations — TCP discovery+service, then a separate
targeted-UDP lease. The TCP leg alone can legitimately run past
`RESERVATION_IDLE_SECONDS` (a full 1-65535 scan now takes minutes, by design of
REQ-RAWLEASE-00x's own rate/timeout fix). Previously only `reserve()` refreshed
the reservation's liveness clock, so a long-but-active TCP leg let the
reservation go "idle" on paper, and the immediately-following UDP `activate()`
failed with `reservation_not_granted` (HTTP 403) even though the same caller had
been continuously heartbeating the whole time.

Fix: `_check_reservation_locked` (called by both `activate()` and `heartbeat()`)
now refreshes `self._reservation.last_seen` on every successful check. Any
activity under the reservation — not just the initial `reserve()` — counts as
liveness. A reservation with no activity at all is unaffected and still
idle-expires.

## Requirement → change map

| Requirement | Change |
|---|---|
| REQ-RAWLEASE-001 | migration 0009, `heartbeat_at`, worker heartbeat, `reap_stale_runs` in scan-create/readiness |
| REQ-RAWLEASE-002 | idempotent `deactivate`/`release` in `raw-egress-gateway/app/gateway.py` |
| REQ-RAWLEASE-003 | `_reconcile_locked` in `activate`/`status`, liveness-based busy check |
| REQ-RAWLEASE-004 | `_check_reservation_locked` refreshes `last_seen` on every activate/heartbeat |

## Non-goals

- No multi-slot concurrency, no per-engagement ephemeral runners (that is the
  `REQ-RUNNER-003` production end-state; deferred until real concurrent load).
- No background scheduler; reaping is lazy/on-demand.
