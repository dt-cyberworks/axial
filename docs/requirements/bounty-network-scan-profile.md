---
title: Per-program network-scan capability model for bug-bounty engagements
status: reviewed
risk: R4
owner: security-engineering
---

# Bug-Bounty Network-Scan Capability Model Requirements

This document is the requirement source for GitHub issue #37: an explicit,
opt-in per-program network-scanning capability model for `source=bug_bounty`
engagements, replacing the previous fixed rule ("only the liveness-only
`host_discovery` sweep is ever exempted from the raw-nmap block,
REQ-CIDRDISC-005"). Tests must verify these requirements directly. Do not
weaken tests to match implementation; update implementation when it violates
this document.

**R4 classification (per `docs/engineering/sdlc.md` and the issue's own
suggested severity):** this is new active-scanning capability with real
blast-radius potential. Per `CLAUDE.md`/`AGENTS.md`, an automated agent
cannot approve its own R4 exception - explicit human security review and
authorization is required before any profile broader than `host_discovery`
is used against a real (non-lab) bug-bounty engagement. This document's
`status: reviewed` (not `approved`/`verified`) reflects that: implementation,
tests, and live verification against the dev stack are complete, but the
human sign-off gate itself is outside this document's control and is tracked
separately (see the closing comment on GitHub issue #37).

## Deliberate scope reduction from the issue's full proposal

The issue's own "Proposed model" section lists a considerably larger
6-tier capability surface: `tcp_syn_scan_profile` with a `custom` tier and an
`approved_tcp_ports` port-list field, a separate `extended` (top-1,000) tier,
`service_detection_allowed`, `raw_max_concurrent_hosts`,
`scanner_source_ip_identification`, and separate UDP/OS-detection/NSE
toggles, plus a pre-scan traffic/time-estimate widget and a per-run
operator-visible coverage-tier report.

This implementation deliberately ships a smaller, real, fully-tested surface
instead:

- Three tiers only - `none` (default) / `common` / `full` - not five. `common`
  reuses the engagement's own already-configured scope-asset TCP port ranges
  (the existing `configured_tcp` port profile) rather than inventing a new
  "top-N port list" concept; there is no `extended`/`custom` tier and no new
  `approved_tcp_ports` field.
- No `service_detection_allowed`, no UDP/OS-detection/NSE toggles - a
  bug-bounty engagement still only ever reaches TCP SYN discovery/scanning,
  exactly as for every other raw-nmap profile these tiers unlock
  (`configured_tcp`/`full_tcp`, both pre-existing, TCP-only profiles).
- No `raw_max_concurrent_hosts` and no pre-scan traffic/time-estimate widget.
  Concurrency and total runtime are already bounded by the pre-existing,
  global `raw-egress-gateway` slot count (`num_slots`) and per-lease TTL
  mechanisms (`docs/requirements/raw-egress-lease-stability.md`) - a new
  per-program concurrency control would duplicate an existing bound rather
  than close a real gap.
- No `scanner_source_ip_identification` field and no per-run
  operator-visible "which tiers were actually used" report.
- The authorization PDF (`control-plane/app/api/engagements.py`'s
  `_authorization_pdf`) is unchanged - it does not currently describe the
  bounty-program policy at all (no `automation_allowed`/`max_rps`/etc.), so
  adding only the network-scan tier to it would be an inconsistent partial
  fix to a pre-existing, broader gap that predates this issue.

These are tracked as an explicit, documented reduction - not a silent
under-delivery - consistent with this codebase's established pattern for
scoping down a large bundled proposal into a smaller, real, verifiable
capability (see `docs/requirements/cidr-host-discovery.md`'s own REQ-CIDRDISC
amendments for a prior example of the same pattern).

## REQ-BOUNTYSCAN-001: An Explicit, Opt-In Per-Program Network-Scan Tier Replaces The Fixed Host-Discovery-Only Rule

Context: `raw_egress_lease.py::issue_raw_egress_lease`'s bug_bounty block
previously had exactly one exemption (`host_discovery`, REQ-CIDRDISC-005) -
`configured_tcp`/`full_tcp` were unconditionally denied
`raw_nmap_not_permitted_for_bug_bounty` for every bug_bounty engagement, with
no way to opt in even when a program's own rules of engagement explicitly
permit broader scanning (e.g. an unqualified "automated tooling: max N
requests/sec" clause with no port-scan prohibition, as documented for REQ-
CIDRDISC-005's own real-world example).

Acceptance criteria:
- `BountyProgram` gains a `tcp_syn_scan_profile` column/field,
  `Literal["none", "common", "full"]`, defaulting to `"none"`.
- `"none"` (the default) preserves REQ-CIDRDISC-005's original behavior
  exactly: only `host_discovery` is exempted from the raw-nmap block.
- `"common"` additionally exempts `configured_tcp` (the engagement's own
  already-configured scope-asset port ranges via `_effective_port_ranges_
  for_target` - reusing that existing mechanism, not a new port-list
  concept).
- `"full"` additionally exempts `full_tcp` (all 65535 TCP ports), gated by
  REQ-BOUNTYSCAN-003 below.
- `targeted_udp` and `raw_tcp_probe` remain unconditionally denied for
  `bug_bounty` regardless of `tcp_syn_scan_profile` - a deliberately
  unaddressed follow-on (no tier in this model unlocks them), not an
  oversight.
- The exemption still additionally requires `BountyProgram.automation_
  allowed = true`, exactly as REQ-CIDRDISC-005 already required - the new
  tier narrows/widens WHICH port profile is exempted, it does not replace
  that existing consent gate.
- **NEGATIVE**: a program with `tcp_syn_scan_profile="none"` (including every
  pre-existing row, via the column default) is denied `configured_tcp`/
  `full_tcp` exactly as before this change - explicit regression guard.
- **NEGATIVE**: `tcp_syn_scan_profile="common"` does not exempt `full_tcp`.
- **NEGATIVE**: `targeted_udp`/`raw_tcp_probe` are denied for `bug_bounty`
  regardless of `tcp_syn_scan_profile`.

## REQ-BOUNTYSCAN-002: A Program's Raw Packet Rate Cap Is A Distinct Field From Its HTTP Request Rate

Context: `_issue_host_discovery_lease` used `BountyProgram.max_rps` (an
HTTP-request-rate concept, REQ-RATE-004) to tighten the raw nmap `--max-rate`
flag - conflating an HTTP-rate statement with a raw-packet-rate cap, exactly
the defect this issue's "Policy distinction" section calls out
("An HTTP request rate and a raw-packet rate are different units and must be
configured separately").

Acceptance criteria:
- `BountyProgram` gains a `raw_max_packets_per_second` field, distinct from
  `max_rps`, optional (`None` by default).
- When set, `raw_max_packets_per_second` - not `max_rps` - governs the raw
  nmap `--max-rate` for every raw-egress lease issued for that program
  (`host_discovery`, `configured_tcp`, `full_tcp` alike), via a single shared
  `_effective_raw_max_rate()` helper.
- When unset (`None`), the raw rate falls back to `max_rps`-based tightening
  - the pre-existing behavior - for backward compatibility with a program
  that never sets the new field.
- **NEGATIVE**: setting `raw_max_packets_per_second` does not change
  `max_rps`'s own, separate, HTTP-tool-facing behavior (REQ-RATE-004) - the
  two fields are read independently by their respective call sites.

## REQ-BOUNTYSCAN-003: The `full` Tier Requires Recorded Authorization Evidence, Never Inferred From `automation_allowed` Alone

Context: the issue is explicit that a full 65535-port TCP scan is a
materially different commitment from "automated tooling is permitted" and
must not be inferred from that boolean or from any rate figure alone.

Acceptance criteria:
- `BountyProgram` gains a `network_scan_authorization_evidence` free-text
  field.
- `tcp_syn_scan_profile="full"` is rejected at schema-validation time (before
  the row can even be persisted) unless `network_scan_authorization_
  evidence` is a non-empty (post-`strip()`) string.
- The gateway independently re-checks the same condition at lease-issuance
  time (`full_tcp_requires_authorization_evidence` denial reason) - never
  trusting the schema-level check alone, consistent with this codebase's
  existing double-enforcement pattern (e.g. port-range-within-ceiling is
  checked both at scope-asset-creation time and fresh on every lease).
- **NEGATIVE**: `tcp_syn_scan_profile="full"` with a blank/whitespace-only
  evidence string is rejected identically to a missing one.
- **NEGATIVE**: `automation_allowed=true` and a high `max_rps`/`raw_max_
  packets_per_second` alone, without evidence, still deny `full_tcp`.

## REQ-BOUNTYSCAN-004: The Raw Rate Cap Is Enforced By A Real Kernel-Level Limiter, Not Only Nmap's Own Cooperation

Context: the issue's own "Why the rate math matters" section notes nmap's
`--max-rate` is a best-effort control that "may temporarily exceed its
target ... and does not itself constrain every later detection feature" -
insufficient as the sole enforcement for a written packet-budget commitment,
especially once `common`/`full` profiles make the raw lease path reachable
for `bug_bounty` engagements at all (previously only the narrow, fixed
two-port `host_discovery` sweep was reachable).

Acceptance criteria:
- `raw-egress-gateway`'s `NftPolicyManager.apply()` installs a genuine
  kernel-enforced nftables rate limit (`limit rate N/second`) scoped to the
  lease's granted address/port/protocol, in addition to (not instead of)
  nmap's own `--max-rate` flag.
- The limit is independently updatable per lease (a later lease on the same
  concurrency slot can install a different rate) without requiring the
  previous rule/limit object to be torn down out of band first.
- **NEGATIVE**: a raw packet rate above the configured cap is rejected by the
  kernel enforcement layer even when the leased `nmap` invocation's own
  `--max-rate` flag is set correctly - proving the hard limit does not depend
  on nmap's cooperation. Verified directly against the real `nft` binary
  inside a running `raw-egress-gateway` container (not only against a mocked
  rule-generation string), since nftables has real constraints on updating a
  live rule/limit object that a purely textual test cannot surface.
- Clearing a lease (`NftPolicyManager.clear()`) removes the rate-limited rule
  along with the rest of that slot's policy.
