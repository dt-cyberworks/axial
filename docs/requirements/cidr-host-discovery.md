---
title: CIDR/IP-range host discovery
status: implemented
risk: R3
owner: security-engineering
---

# CIDR/IP-Range Host Discovery Requirements

This document is the requirement source for turning an `ip`/`cidr` scope asset
into concrete, probed targets. Tests must verify these requirements directly.
Do not weaken tests to match implementation; update implementation when it
violates this document.

Context: found while reviewing a real Intigriti program (Port of
Antwerp-Bruges) whose scope includes two `IpRange` entries (`188.118.8.0/25`,
`94.107.237.192/26`) alongside domain/URL scope. This platform's `ScopeAsset`
model, Scope Gateway, and raw-egress `NetworkPolicy` rendering all already
recognize `ip`/`cidr` as first-class asset types with real
`ipaddress`-based containment checks (`authorize.py`, `raw_egress_policy.py`),
but the automated discovery task only ever seeds its target list from
`domain`/`wildcard` scope assets (`worker/app/tasks/discovery.py`). An
engagement scoped purely by IP range currently gets zero automated targets: the
Scope Gateway would correctly *allow* a tool call against a host inside the
range if one were made, but nothing in the pipeline ever makes one.

## REQ-CIDRDISC-001: A Host-Discovery Sweep Is Authorized As One Gateway Call Against The Whole Range

`_matches_asset_value` in `authorize.py` currently requires `call.target` to
be a single concrete address for `ip`/`cidr` assets
(`ipaddress.ip_address(target) in ipaddress.ip_network(asset.value)`); a
CIDR-shaped target raises `ValueError` and is denied as out of scope.
Meanwhile `raw_egress_policy.py` already renders network-level access to the
whole CIDR block for nmap. This requirement connects the two: a single
liveness-sweep tool call, scoped to the whole range, gets one gateway
decision - not one authorize() call per candidate host.

Acceptance criteria:
- Discovery adds active-allowed `ip`/`cidr` scope assets to its target list
  alongside existing `domain`/`wildcard` handling.
- A host-discovery tool call (category `recon`, mode `active`) whose `target`
  is a CIDR string is authorized when that network is equal to, or a subnet
  of, an active `ip`/`cidr` allow scope asset - extending
  `_matches_asset_value`, not expanding the range into per-IP calls.
- Existing gateway checks (time window, tool grant/whitelist, bug-bounty
  program rules, rate limit, budget) apply to this call unchanged - this
  requirement only extends step 2 (scope matching), not the rest of the
  chain.
- **NEGATIVE**: a discovery target network that is not a subnet of any active
  `ip`/`cidr` allow asset (wider, overlapping-but-not-contained, or
  unrelated) is denied `target_out_of_scope`.
- **NEGATIVE**: an explicit `deny` rule covering part of the range still takes
  precedence for any host inside it that the sweep finds live - deny-beats-allow
  is enforced when the host is recorded (REQ-CIDRDISC-003), not only at
  sweep-authorization time.

## REQ-CIDRDISC-002: The Sweep Is Liveness-Only And Honors The Engagement's Rate Cap

Acceptance criteria:
- The discovery-phase tool for `ip`/`cidr` assets performs host-liveness
  detection only (e.g. `nmap -sn`) - no service/version detection or
  vulnerability probing. Deeper probing of any specific live host happens
  through the normal fingerprint/vuln pipeline, authorized per-host like any
  other target.
- The sweep's own pacing respects the engagement's effective rate cap the same
  way REQ-RATE-004 does for `nuclei`/`ffuf`: nmap's rate flag (`--max-rate`) is
  set to the bug-bounty program's `max_rps` when that cap is lower than nmap's
  own default pace; unchanged otherwise.
- **NEGATIVE**: a non-`bug_bounty` engagement's sweep pacing is unaffected -
  same default rate as before this change.

**Amended 2026-08-12 (GitHub issue #36):** the fixed TCP-SYN discovery
probe set (`-PS80,443`, no ICMP, no other ports) is deliberate and matches
the raw-egress-gateway's own nftables policy for this lease - not a defect.
But a host that answers on neither 80 nor 443 (an SSH-only host, or a web
service fronted on a different port) is silently absent from sweep results
with no operator-visible distinction from a genuinely dead address. This
amendment requires that limitation be surfaced, not fixed by widening the
probe set (a broader/configurable discovery profile is deliberately a
separate, larger, explicitly-authorized capability - tracked as GitHub
issue #37, not part of this amendment).

Additional acceptance criteria (2026-08-12 amendment):
- The engagement scope-assets view (wizard's Scope step and the engagement
  edit page) shows a clear note whenever any `cidr`-type scope asset is
  present, stating that host discovery only probes TCP 80/443 and that a
  host silent on both is indistinguishable in the results from one that
  does not exist.
- This is a static, always-shown fact about the fixed probe set - it does
  not depend on any particular run's outcome, and does not claim a run
  degraded (unlike the unrelated `coverage_degraded:` run-state-reason
  mechanism, REQ-SCAN-014, which specifically means a load-bearing tool was
  attempted and never succeeded - a fully successful host-discovery sweep
  is not "degraded," it is simply narrow by design).
- **NEGATIVE**: the note does not appear for an engagement with no
  `cidr`-type scope asset at all.

## REQ-CIDRDISC-003: Live Hosts Become Discovered Assets And Feed The Existing Pipeline Unmodified

Acceptance criteria:
- Each host the sweep reports live is recorded as a `discovered_asset` with
  `asset_type=ip`, with `in_scope` computed the same way domain-derived
  discovery is (allow match minus deny precedence - REQ-ASSETREVIEW-007's
  model extended to IP-type candidates).
- When `engagement.asset_review_enabled=true`, live hosts join the same single
  batch review popup as domain-derived candidates (REQ-ASSETREVIEW-002) - not
  a separate per-IP flow.
- When `asset_review_enabled=false` (default), live hosts proceed straight to
  `fingerprint` exactly like domain-derived discovery does today - reusing
  REQ-ASSETREVIEW-001's existing opt-in behavior; no new gate is introduced.
- Once recorded in scope, an individual discovered IP requires no further code
  changes downstream: the existing single-address `_matches_asset_value` path
  authorizes fingerprint/vuln tool calls against it exactly as it does today
  for a directly-entered `ip` scope asset.

## REQ-CIDRDISC-005: The Liveness Sweep Is Narrowly Exempted From The Bug-Bounty Raw-Nmap Block

Context: `raw_egress_lease.py::issue_raw_egress_lease` unconditionally denies every
raw nmap call (`reason=raw_nmap_not_permitted_for_bug_bounty`) for
`source=bug_bounty` engagements, before any scope check. This exists because
raw TCP/ICMP traffic cannot carry REQ-AUTH-006's mandatory self-identification
header the way HTTP-proxied tools can - the platform's compliance guarantee is
that no unidentifiable traffic reaches a bug-bounty target, enforced by
blocking raw nmap outright rather than trying to inject identification into
something structurally unable to carry it.

Decision confirmed by johannes (2026-08-12), reasoning from a real example
(Port of Antwerp-Bruges on Intigriti): a program that lists bare IP ranges as
in-scope targets (not fronted by any domain) cannot be meaningfully tested
without some form of network-level discovery first - the program including
raw ranges in scope at all is itself evidence it anticipates this kind of
testing. Combined with an explicit, unqualified "automated tooling: max N
requests/sec" permission and no prohibition of port/network scanning in the
published rules of engagement, a rate-capped liveness-only sweep is
considered authorized. This reasoning does **not** extend to full/configured
TCP port scans or the raw-protocol probes (redis-probe, activemq-banner,
activemq-openwire-probe) - those remain blocked for bug_bounty engagements
exactly as today; nothing reviewed here speaks to them.

Acceptance criteria:
- `issue_raw_egress_lease`'s bug_bounty block gains a narrow, explicit
  exception: `port_profile == "host_discovery"` (the new liveness-only
  profile from REQ-CIDRDISC-002) is exempted from
  `raw_nmap_not_permitted_for_bug_bounty`; every other port profile
  (`full_tcp`, `configured_tcp`, `targeted_udp`, `raw_tcp_probe`) is denied
  for `bug_bounty` exactly as before this change - unchanged, not widened.
- The exemption additionally requires `BountyProgram.automation_allowed` to be
  true for this engagement (the existing, separate automation-consent gate in
  `authorize.py` step 3 already enforces this for any automated call; the
  raw-egress lease path re-checks it explicitly here rather than relying on
  it being checked exactly once elsewhere, since this lease path has its own
  independent `authorize()` call).
- The sweep's `--max-rate` is bound to `BountyProgram.max_rps` exactly like
  REQ-CIDRDISC-002 already requires for the general case - for a bug_bounty
  engagement this is not optional tightening, it is the specific basis for
  the exemption being granted at all.
- **NEGATIVE**: a `bug_bounty` engagement with `automation_allowed=false`
  still gets `automation_forbidden`/equivalent denial for a host-discovery
  sweep, even though the raw-nmap block itself is exempted - the exemption
  narrows WHICH raw-nmap check applies, it does not skip the rest of the
  gateway chain.
- **NEGATIVE**: `full_tcp`/`configured_tcp`/`targeted_udp`/`raw_tcp_probe`
  requests for a `bug_bounty` engagement are denied
  `raw_nmap_not_permitted_for_bug_bounty` exactly as before - regression test
  proving this requirement did not widen the existing block for any other
  profile.

## REQ-CIDRDISC-004: Adding A CIDR To Scope Is Itself Sufficient Authorization - No Per-IP Manual Approval

Decision confirmed by johannes (2026-08-12): the operator adding a CIDR to
engagement scope is itself the authorization for every address inside it.
Requiring a further manual-approval step per discovered IP would be redundant
scope-widening friction that the CIDR grant already covers.

Acceptance criteria:
- Discovering a live host inside an already-allowed CIDR does not, on its own,
  create an `ApprovalRequest` or otherwise pause the run - it is governed only
  by the existing, opt-in, batch asset-review gate (REQ-ASSETREVIEW-001/002)
  when enabled, or proceeds directly when it is not.
- **NEGATIVE**: this does not weaken any existing per-call approval
  requirement for state-changing tools (e.g. `http_request` state-changing
  detection, `activemq-openwire-probe`) once a specific discovered IP is
  targeted - those checks in `authorize.py` are unchanged; only the
  liveness-discovery step and recording a host as in-scope are exempt from a
  new approval gate.

## REQ-CIDRDISC-006: A Partial Deny Exception Inside An Allowed CIDR Does Not Block Sweeping The Rest Of It

Context: reported as GitHub issue #34. REQ-CIDRDISC-001's own negative
criterion above ("an explicit deny rule covering part of the range still
takes precedence ... deny-beats-allow is enforced when the host is recorded,
not only at sweep-authorization time") was correct as written, but its
consequence for *authorization* was never separately specified: because
`_network_is_allowed_by_current_policy` (`raw_egress_lease.py`) checks the
requested network for ANY overlap with a deny exception, not just exact
containment, a sweep request for the ORIGINAL full CIDR is itself denied
once any address inside it is denied - not just the address recorded as
out-of-scope. Since asset review deselecting a false-positive host is the
intended, expected way a deny exception like this gets created, this made
the platform's own correct-by-design workflow permanently disable
rediscovery of the rest of a legitimately authorized range.

Acceptance criteria:
- A `cidr` scope asset with a deny exception covering only part of it
  remains sweepable for the rest of the range: the worker requests the
  maximal deny-avoiding sub-networks of the original CIDR (computed via
  `ipaddress.Network.address_exclude`) instead of the original CIDR
  verbatim, and issues one lease per sub-network.
- The denied address's network space is never included in any sub-range
  lease request, and therefore never granted raw-egress-gateway firewall
  access (`Policy.apply` enforces exactly a lease's own `resolved_target`) -
  this is an enforcement-layer guarantee, not merely an authorization-check
  outcome.
- A newly-live host elsewhere in the (reduced) range is discoverable on a
  later run.
- **NEGATIVE (unchanged, regression guard)**: the control-plane authorization
  check (`_network_is_allowed_by_current_policy`) still denies a sweep
  request for the ORIGINAL full CIDR when a deny exception overlaps it - the
  fix works around this by having the worker request smaller sub-ranges,
  not by loosening this check. A lease request for the exact original,
  still-overlapping CIDR must continue to be denied
  `resolved_target_not_in_current_raw_policy`.
- **NEGATIVE**: a deny exception that exactly matches (or fully contains) the
  requested CIDR yields zero sub-ranges to sweep - not a partial, incorrect
  authorization.
- **NEGATIVE**: an unrelated deny exception (different network, no overlap)
  does not change the sweep - the original CIDR is requested in a single
  lease, exactly as before this requirement.
