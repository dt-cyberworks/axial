---
title: Operational stability for concurrent multi-user engagements
status: verified
risk: R3
owner: security-engineering
---

# Operational Stability for Concurrent Multi-User Engagements

Now that individual accounts with per-user engagement ownership exist
(`docs/requirements/authentication-and-authorization.md`, REQ-IAM-002..011),
multiple people can genuinely run multiple engagements at the same time.
This document covers what was found reviewing the Scope Gateway, the raw
-egress-gateway, the egress-proxy, and the tool-runner backend for
assumptions that only held under single-operator, effectively-sequential
usage.

**Risk class: R3** (`docs/engineering/sdlc.md` §2: "Scope Gateway, auth,
audit, runner, proxy, secrets" — REQ-CONCUR-002 changes the raw-egress
-gateway's nftables enforcement, the deny-all network boundary itself).
REQ-CONCUR-002 specifically requires a negative test proving no cross-lease
port/target leakage, and — per the SDLC — cannot be self-approved; it needed
human security review before being considered fully closed, same as the
egress-proxy port-scope fix (REQ-FIDELITY-005) earlier in this project.

**Security review:** approved by johannes (project/security owner) on
2026-07-27, after review of the negative isolation test
(`test_nft_policy_separates_slots_no_cross_product` and
`test_two_concurrent_leases_activate_into_independent_slots` in
`raw-egress-gateway/tests/test_gateway.py`) and live verification against the
deployed container (`nft list table inet asm_raw` showing per-slot set
isolation; two concurrent leases activating into distinct slots with
`/health` reporting correct occupancy).

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

---

## REQ-CONCUR-001: Tool results are never served from another run's cache

Context: HexStrike's `execute_command()` caches by `hash(command_string)`
alone (no engagement/scan_run scoping), defaults caching to ON, with a
1-hour TTL, in a single process-wide cache shared by every engagement that
hits the shared `tool-runner` container. Our own code already disabled this
correctly for the tools routed through the generic `/api/command` endpoint
(httpx, testssl, http_request, ffuf) but not for the six tools with
dedicated HexStrike endpoints (nmap, nuclei, nikto, subfinder, amass,
wafw00f) — those silently accepted the cached default.

Acceptance criteria:
- Every tool body builder that targets a dedicated HexStrike endpoint
  explicitly sends `use_cache: false`.
- A structural test iterates the tool→endpoint registry itself (not a fixed
  list of tool names) so a newly added dedicated-endpoint tool that forgets
  this fails the test suite, not silently reintroduces stale results.
- The tool-runner itself never serves or stores a cached result, whatever a
  caller sends: the build-time HexStrike patch switches caching off inside
  `execute_command()`, the one function every endpoint uses. (Found live
  2026-09-29: the dedicated `/api/tools/*` endpoints never read `use_cache`
  from the request, so the body flag above had no effect and a resumed scan
  received nmap/nikto/nuclei results replayed in ~20 ms, audited as fresh
  executions.) A changed upstream anchor fails the image build.

## REQ-CONCUR-002: Raw-network (Nmap) egress supports multiple concurrent, mutually isolated leases

Context: the raw-egress-gateway's lease scheduler (`app/gateway.py`) holds
exactly one active lease and one pending reservation as single-valued state
(`self._active`, `self._reservation`), enforced by a single deny-all nftables
`output` chain whose `allowed_v4`/`allowed_v6`/`allowed_tcp_ports`/
`allowed_udp_ports` sets are flushed and re-populated for that one lease.
This was an appropriate model for one operator running one nmap at a time;
with multiple concurrent engagements it becomes a hard serialization point —
only one raw-network operation across the *entire deployment* can run,
others wait in the FIFO queue (up to `RAW_EGRESS_QUEUE_WAIT_SECONDS`) or
fail.

Naively extending the existing shared sets to hold multiple addresses/ports
at once would be a real security regression: the current `output` chain
rule ANDs one address set with one port set
(`ip daddr @allowed_v4 tcp dport @allowed_tcp_ports accept`), a cross
-product match. Two concurrent leases would each leak the other's port
range onto their own target IP.

Acceptance criteria:
- Up to `RAW_EGRESS_MAX_CONCURRENT_LEASES` (default 2, operator-configured,
  bounded 1-8) independently active leases are supported at once, each
  tracked by its own `scan_run_id`, with its own idle/heartbeat/expiry
  lifecycle unaffected by any other concurrent lease's state.
- Each lease's permitted (address, port-range, protocol) is enforced by a
  dedicated nftables construct scoped to only that lease — never a shared
  set whose members can combine across leases. Verified by a negative test:
  two concurrent leases for different targets/ports each reach only their
  own leased target on only their own leased ports, never the other's.
- When all slots are occupied, further requests queue FIFO exactly as
  today, just against N slots instead of 1.
- Releasing, expiring, or reaping one lease frees exactly its own slot and
  never disturbs another active lease's enforcement state.
- `/health` reports current occupied/total slot counts (operational
  visibility into the new capacity, not just up/down).

## REQ-CONCUR-003: Overlapping engagement scope is caught at activation, not mid-scan

Context: the egress-proxy resolves the engagement for a request that
carries no explicit engagement identifier (several HTTP tools cannot be
told to send a custom header through their built-in proxy support) by
finding "the one active engagement whose allow-scope matches this host."
If two active engagements — from any two users — both authorize the same
host, this is deliberately fail-closed (`ambiguous_host`, every such
request denied for both) rather than fail-open. That is the right safety
property, but today an operator only discovers the conflict as a confusing
runtime scan failure, potentially well into a run. With multiple
independent users, two people scoping overlapping infrastructure is a
realistic occurrence, not a hypothetical.

Acceptance criteria:
- Activating an engagement (or adding an active-mode allow scope-asset to
  an already-active one) checks for an overlapping allow-scope match
  against every *other* currently active engagement (any owner) and
  refuses with a clear, actionable error identifying that the conflict
  exists (not which other engagement/owner, to avoid leaking one user's
  engagement details to another) rather than silently succeeding into a
  state that will fail at scan time.
- This is a creation/activation-time check only — it does not change the
  egress-proxy's own runtime resolution or its fail-closed behavior, which
  remains the actual enforcement boundary.

## REQ-CONCUR-004: Audit trail attributes actions to the real actor

Context: several `audit_log` write sites (outside what REQ-IAM-002 already
updated for engagement create/update, approvals, and asset-review
decisions) still record the generic literal string `"operator"` rather than
the authenticated caller's identity. With genuinely distinct people now
holding accounts, "who did what" is a real accountability question this
gap undermines.

Acceptance criteria:
- Every operator-initiated `audit_log` write in `engagements.py` records
  `f"user:{user.email}"` (or equivalent identity), not the literal string
  `"operator"`.
- No behavior change to what is audited or when — this is strictly an
  attribution-accuracy fix.

## REQ-CONCUR-005: An admin cannot lock the platform out of admin access

Context: `PATCH /admin/users/{id}` has no protection against demoting or
disabling the last remaining active admin account, which would leave no
one able to manage users through the application itself (recovery would
require server access to re-run `bootstrap_admin.py`).

Acceptance criteria:
- A request that would result in zero active admin accounts (demoting the
  last admin to operator, or disabling the last active admin) is rejected
  with a clear error instead of applied.
- This check only ever blocks the *last* admin transition — it does not
  restrict normal admin management when more than one active admin exists.
