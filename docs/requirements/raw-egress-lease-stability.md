---
title: Raw-egress lease lifecycle stability (self-healing)
status: implemented
risk: R3
owner: security-engineering
---

# Raw-Egress Lease Lifecycle Stability

This document is the requirement source for making the raw-egress (raw Nmap)
lease/reservation lifecycle **self-healing**, so a crashed, hung, or abandoned
scan can never permanently jam raw scanning.

Context: raw Nmap egress is gated by a single-slot FIFO lease against the
`raw-egress-gateway` (shared network namespace, nftables allow-set). A scan run
acquires a reservation, then a signed lease, activates it (installs the nftables
allow for one target), heartbeats it, and releases it. Observed instability:

1. A `scan_run` stuck in `running`/`waiting_approval` (worker crashed or hung)
   permanently blocks new scans for that engagement (the "one active run" guard),
   requiring a manual DB edit.
2. Releasing a lease that was superseded or already gone returns an error
   (`403`/`lease_not_active`), so best-effort cleanup fails and leaves state
   inconsistent.
3. Lease activation blocks on the full signed TTL (up to 30 min) rather than
   liveness, so a dead-but-not-yet-expired holder can briefly reject a new run.

The single-slot design and every security invariant (one target reachable at a
time, signed lease, deny-precedence, TTL) are preserved. This only makes the
lifecycle recover from failure. Tests must verify these requirements directly.

**Risk class: R3** — touches raw-egress enforcement and scan-run lifecycle;
requires negative tests. No new offensive capability is added; the change only
reclaims stuck state and makes release idempotent.

---

## REQ-RAWLEASE-001: Abandoned scan runs are reaped and never permanently block new scans

A scan run that stops making progress (worker crashed or hung) must not block
new scans for its engagement indefinitely.

Acceptance criteria:
- `scan_run` carries a `heartbeat_at` timestamp that the worker refreshes while a
  run makes progress (phase/state updates and during long raw-egress operations).
- Before a new run is created (and in scan-readiness), the control plane reaps any
  `running`/`waiting_approval` run for that engagement whose `heartbeat_at` is
  older than a bounded staleness threshold: it transitions to `aborted` with a
  reason indicating it was reaped, and `finished_at` is set.
- After reaping a stale run, a new scan can start (the "one active run" guard no
  longer blocks); a genuinely active run (fresh heartbeat) still blocks with 409.
- Reaping is idempotent and only ever affects runs past the staleness threshold;
  a live run is never reaped.

Security invariants:
- Reaping only changes run bookkeeping; it never authorizes a target or bypasses
  the Scope Gateway. A reaped run's lease is freed, never reassigned to a target.

## REQ-RAWLEASE-002: Lease release is idempotent

Releasing/deactivating a raw-egress lease must be best-effort and idempotent, so
worker cleanup after any outcome cannot error or leave the slot stuck.

Acceptance criteria:
- Deactivating when no lease is active, when the active lease is a different
  (superseding) lease, or when the caller's reservation was already superseded
  returns success without raising — it never leaves a foreign lease installed.
- Releasing a reservation that is already gone returns success.
- A valid deactivate of the *current* lease still clears the nftables policy and
  frees the slot exactly as before (no regression).

## REQ-RAWLEASE-003: Activation reclaims a dead-heartbeat lease

Lease activation must treat a holder whose heartbeat has lapsed as reclaimable,
rather than blocking on the full signed TTL.

Acceptance criteria:
- If the currently-installed lease's `heartbeat_deadline` has passed, a new,
  reservation-holding activation reclaims the slot (clears the stale policy) and
  installs its own lease, instead of returning `raw_egress_lease_busy`.
- A lease whose heartbeat is still valid continues to block a different lease with
  `raw_egress_lease_busy` (no change to the live-contention behavior).
- Re-activating the same lease id remains idempotent (returns the active lease).
- The gateway `status()` reflects reality: a dead-heartbeat lease is reconciled
  (reported cleared), not shown as active forever.

## REQ-RAWLEASE-004: A reservation stays alive for the duration of active use

A reservation (the FIFO queue slot backing a scan run's raw-egress access) must
not idle-expire while its holder is actively using it, even across more than one
lease acquisition under the same reservation (e.g. a TCP discovery+service scan
followed by a separate targeted-UDP scan for the same host).

Context: `execute_configured_tcp_scan` and `execute_targeted_udp_scan` share one
reservation acquired once per `_nmap_scan()` call, but each is a *separate* lease
activation. A full TCP discovery+service pass can legitimately run longer than
the reservation's idle timeout; if only the initial `reserve()` call ever
refreshed liveness, the reservation could be pruned as "idle" between the TCP
leg's `deactivate()` and the UDP leg's `activate()`, even though the caller never
stopped working — failing the second leg with `reservation_not_granted`.

Acceptance criteria:
- Every successful `activate()` or `heartbeat()` under a reservation refreshes its
  liveness, so a reservation backed by regular heartbeats never idle-expires
  regardless of total elapsed wall-clock time.
- A reservation with **no** activity (never activated, never heartbeated) still
  idle-expires after the existing timeout — this requirement does not disable
  reclamation of genuinely abandoned reservations.
- A second lease acquired under the same reservation immediately after the first
  is deactivated (e.g. TCP discovery+service, then targeted UDP) succeeds without
  a spurious `reservation_not_granted` denial.
