---
title: Per-target TCP port scoping
status: verified
risk: R3
owner: security-engineering
---

# Per-Target TCP Port Scoping

Context: the engagement wizard asked for a single TCP port range before any
target existed, applying identically to every target in the engagement.
Real engagements often need different port authorizations per target (a
public web domain scoped to 443 only, an office IP range scoped to all
ports). Decided with johannes (2026-08-09): per-target ranges, bounded by
the engagement's existing range acting as an outer **ceiling** - a target
can narrow it, never widen it, re-derived fresh at every enforcement point
rather than validated once and trusted.

**Risk class: R3.** This changes both independent enforcement paths that
make up the Scope Gateway's defense-in-depth (`egress-proxy` and
`raw_egress_lease.py`). A UI that lets an operator set a narrower per-target
range which then silently isn't enforced would be actively misleading, so
the data model/UI and every enforcement point shipped together. Per the SDLC
this cannot be self-approved and needs human security review.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

**Security review:** approved by johannes (project/security owner) on
2026-08-09, after full test suites (control-plane 353, egress-proxy 35,
worker 377), `tsc` clean, and live end-to-end verification against a real
Postgres and a real running egress-proxy (not mocks) - see
`per-target-port-scoping-and-int-fixes.md` in memory for the exact commands.

## REQ-PORTSCOPE-001: Per-target port range, validated as a ceiling subset at write time

Acceptance criteria:

- `scope_asset` gains nullable `port_from`/`port_to`. `NULL` (the default,
  and every pre-existing row's backfilled value) means "inherit the
  engagement's `tcp_port_from`/`tcp_port_to` ceiling in full" - zero
  behavior change for every engagement that doesn't use this.
- Adding a scope asset with a port range that is not a subset of the
  engagement's current ceiling is rejected (422) at write time.
- This write-time check is a fast-feedback convenience only, never the sole
  protection - see REQ-PORTSCOPE-002/003, which re-derive the effective
  range independently at enforcement time regardless of what was validated
  at write time.

## REQ-PORTSCOPE-002: egress-proxy enforces the per-target effective range

Acceptance criteria:

- `evaluate()`'s port check uses each matched allow-asset's own range
  (intersected with the ceiling fresh on every call), not the flat
  engagement range - a port is allowed if it falls within *any* matched
  asset's effective range, mirroring the existing "any allow match
  legitimizes the host" semantics for names.
- [Negative test] a port inside the engagement ceiling but outside one
  specific target's own narrower range is blocked, even though the
  identical port is allowed for a *different* target in the same engagement
  with a wider range.
- [Negative test] narrowing the engagement ceiling after a target's own
  range was already set immediately narrows that target too - proves the
  range is re-derived on every call, not cached from write time.
- A target with no port override still gets exactly the ceiling - unchanged
  behavior for every existing engagement.

## REQ-PORTSCOPE-003: Raw-egress (nmap) leases resolve per-target

Acceptance criteria:

- `issue_raw_egress_lease` resolves `authorized_target` to its matching
  scope-asset(s) (same domain/wildcard/ip/cidr matching semantics as
  egress-proxy, independently implemented - defense-in-depth, matching this
  codebase's existing duplication between the two services) and uses the
  intersected effective range(s), never the flat engagement range directly.
- `full_tcp` requires the *specific target's* effective range to be exactly
  the unrestricted (1, 65535) - a wide engagement ceiling does not grant a
  full sweep against a target whose own scope narrows it.
- `configured_tcp` builds one nmap port-list segment per matched asset's
  effective range (standard, valid nmap `-p` syntax; bounded to 8 segments
  in `args_safety.py`), not a collapsed min/max envelope that would
  over-authorize the gap between disjoint ranges.
- [Negative test] a target's own range cannot survive intact if it's wider
  than the current ceiling, even bypassing the write-time check (direct DB
  write) - the enforcement path itself re-intersects, not just the API.
- [Negative test] `full_tcp` is denied for a target whose own range is
  narrower than the ceiling, even though the ceiling alone is unrestricted.

## REQ-PORTSCOPE-004: Worker HTTP tool dispatch targets the per-target effective range

Acceptance criteria:

- `/internal/engagements/{id}/scan-envelope` accepts an optional `host`
  query param; when given, returns that target's effective range (same
  helper as REQ-PORTSCOPE-003) instead of the flat engagement range.
- The fingerprint phase resolves this per discovered host inside its loop,
  not once for the whole engagement - two targets in the same run with
  different per-target ranges each get their own web-tool target port.
- Not itself an enforcement point (egress-proxy and raw_egress_lease still
  decide independently) - a host matched by several scope-asset rows with
  genuinely different ranges has no single well-defined port to prefer, so
  it falls back to the ceiling unchanged rather than guessing.
