---
title: Operational stability for concurrent multi-user engagements verification
status: ready
risk: R3
owner: security-engineering
---

# Operational Stability for Concurrent Multi-User Engagements Verification

Verifies [`../requirements/operational-stability-for-concurrent-engagements.md`](../requirements/operational-stability-for-concurrent-engagements.md).
R3: negative paths (no cross-lease/cross-engagement leakage) are required.

## TC-CONCUR-001: Dedicated-endpoint tool results are never cached across runs

Requirements:

- REQ-CONCUR-001

Automated tests:

- `worker/tests/test_tool_cache_disabled.py`
- `tool-runner/tests/test_runner_auth.py`

Objective:

Verify every tool body builder that targets a dedicated HexStrike endpoint
(nmap, nuclei, nikto, subfinder, amass, wafw00f) explicitly disables
HexStrike's result cache, and that a structural check over the tool→endpoint
registry itself catches a future tool that forgets to.

Expected results:

- `_nmap_body`, `_nuclei_body`, `_nikto_body`, `_subfinder_body`, `_amass_body`,
  `_wafw00f_body` all return `use_cache: false`.
- Iterating `_ENDPOINTS` and calling every registered body builder confirms
  `use_cache` is `false` for each, without relying on a fixed tool-name list.
- The patched HexStrike `execute_command()` executes the same command twice
  even when the caller asks for the cache, and stores nothing; a changed
  upstream anchor makes the patch fail loudly.
- Live: a resumed scan's nikto/nmap calls take their real run time, not ~20 ms.

## TC-CONCUR-002: Raw-network egress supports multiple concurrent, mutually isolated leases

Requirements:

- REQ-CONCUR-002

Automated tests:

- `raw-egress-gateway/tests/test_gateway.py`

Objective:

Verify the raw-egress-gateway's lease scheduler supports
`RAW_EGRESS_MAX_CONCURRENT_LEASES` concurrent slots, each with independent
lifecycle state, and that the nftables enforcement for each slot is
structurally isolated from every other slot's address/port sets - never a
shared set whose members could combine across leases.

Expected results:

- Two reservations are both granted (not queued) when
  `max_concurrent_leases=2`; a third reservation queues FIFO until a slot
  frees.
- Two concurrent leases activate into two distinct slots; `policy.applied`
  records each lease's own (slot, address, ports, ttl, protocol) tuple.
- Negative/isolation test: `NftPolicyManager.initialize()`'s generated
  nftables script contains each slot's own address-set/port-set pairing
  (`@allowed_v4_0 ... @allowed_tcp_ports_0`, `@allowed_v4_1 ...
  @allowed_tcp_ports_1`) and never a cross-slot pairing
  (`@allowed_v4_0 ... @allowed_tcp_ports_1` is absent, and vice versa).
  `apply(slot, ...)` for one slot never appears in another slot's generated
  script (each slot's target address/port never leaks into another slot's
  flush/add script).
- Deactivating one of two concurrently active leases frees only its own slot
  (`policy.cleared_slots == [that slot]`) and leaves the other lease active
  and enforced, confirmed via `status()`.
- `status()` reports `max_concurrent_leases`, `active_lease_count`,
  `free_slots`, `reserved_slots`, and `queue_length` reflecting true
  occupancy.
- All pre-existing single-slot lifecycle guarantees (FIFO ordering, dead
  -heartbeat reclaim, idempotent deactivate, reservation survival across a
  long multi-stage scan, abandoned-reservation pruning) continue to pass
  unchanged with the default `max_concurrent_leases=1`.

## TC-CONCUR-003: Overlapping engagement scope is caught at activation, not mid-scan

Requirements:

- REQ-CONCUR-003

Automated tests:

- `control-plane/tests/integration/test_scope_overlap_activation.py`

Objective:

Verify that activating an engagement (or adding active-mode allow scope to an
already-active engagement) is refused when its allow-scope overlaps another
currently active engagement's allow-scope - any owner - and that this check
does not fire for non-overlapping scope, non-active other engagements, or
passive-only scope additions.

Expected results:

- Two engagements with disjoint allow-scope domains both activate
  successfully.
- Activation is rejected (409) when the new engagement's allow-scope exactly
  matches another already-active engagement's allow-scope domain.
- Activation is rejected when the new engagement's allow-scope is a subdomain
  of (or a superdomain of) another already-active engagement's allow-scope
  domain.
- Activation is rejected when the new engagement's allow CIDR overlaps another
  already-active engagement's allow CIDR.
- Activation is NOT blocked by overlapping scope belonging to an engagement
  that is not currently active (e.g. still `draft`).
- Adding an active-mode allow scope-asset to an already-active engagement is
  rejected (409, and the asset is not persisted) when it overlaps another
  active engagement's allow-scope; adding the same value as passive-only
  (`active_allowed=False`) is not blocked.

## TC-CONCUR-004: Audit trail attributes actions to the real actor

Requirements:

- REQ-CONCUR-004

Automated tests:

- `control-plane/tests/integration/test_audit_attribution.py`

Objective:

Verify representative operator-initiated `audit_log` writes in
`engagements.py` record the authenticated caller's real identity
(`user:<email>`) rather than the generic literal `"operator"`, and that a
structural guard prevents the literal from silently reappearing.

Expected results:

- `update_engagement`, `add_scope_asset`, `delete_scope_asset`, and
  `cancel_scan_run` each write an `audit_log` row whose `actor` equals
  `f"user:{caller.email}"`.
- No `actor="operator"` literal remains anywhere in
  `control-plane/app/api/engagements.py`.

## TC-CONCUR-005: An admin cannot lock the platform out of admin access

Requirements:

- REQ-CONCUR-005

Automated tests:

- `control-plane/tests/integration/test_admin_last_admin_guard.py`

Objective:

Verify `PATCH /admin/users/{id}` rejects a role or status change that would
leave zero active admin accounts, while never restricting admin management
when another active admin exists or the target is not currently an active
admin.

Expected results:

- Demoting the sole active admin to `operator` is rejected (409); the admin's
  role is unchanged.
- Disabling the sole active admin is rejected (409); the admin's status is
  unchanged.
- Demoting or disabling an admin succeeds once a second active admin exists.
- A no-op-shaped update to the sole admin (re-affirming `role=admin,
  status=active`) is never blocked.
- Changes to a non-admin user, or to an admin who is not yet `active`
  (still `invited`), are never blocked by this guard.
