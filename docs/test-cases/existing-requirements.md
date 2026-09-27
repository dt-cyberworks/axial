---
title: Existing requirement verification
status: ready
risk: R3
owner: engineering
---

# Existing requirement verification

## TC-AUTH-001: Operator authorization requirements

Requirements:

- REQ-AUTH-001
- REQ-AUTH-002
- REQ-AUTH-003
- REQ-AUTH-004
- REQ-AUTH-005
- REQ-AUTH-006

Automated tests:

- `frontend/tests/operator_authorization_requirements.test.mjs`
- `control-plane/tests/integration/test_bounty_program.py`
- `worker/tests/test_bounty_ident_injection.py`

Objective:

Verify that the normal operator flow uses authorization language, hides
internal source details, provides the authorization PDF workflow, and - the
narrow, deliberate amendment (GitHub issue #12) - lets an operator configure
a bug-bounty program's policy through one opt-in toggle without reintroducing
a general source picker, while the platform actually honors that program's
mandatory self-identification on every HTTP-proxied tool, including HTTPS.

Expected results:

- Every listed requirement is asserted by the executable requirement test.
- The bounty-program toggle is present in both the wizard's `Tools` step and
  the engagement edit page, sets `source="bug_bounty"` and submits the
  program policy only when explicitly checked, and never adds a wizard step
  or a general source-picker control.
- `POST /{engagement_id}/bounty-program` upserts (replaces any existing row
  for that engagement) rather than accumulating duplicates; `GET
  /{engagement_id}/bounty-program` returns the current policy or null.
- The worker's `tool_runner_client.py` injects the configured identification
  header (and, where the tool supports it, a User-Agent override) into
  every one of `httpx`, `nikto`, `wafw00f`, `testssl`, `nuclei`,
  `http_request`, `ffuf` when the target engagement is `bug_bounty` - and
  injects nothing at all otherwise.
- NEGATIVE: an agent-supplied `http_request` header with the same name as
  the mandatory identification header (or `User-Agent`) is superseded by the
  platform's configured value, never left as the agent's own value and never
  sent twice.
- NEGATIVE: a bounty-ident lookup failure degrades to sending the request
  unidentified rather than aborting the scan.

## TC-TOOL-001: Tool grant requirements

Requirements:

- REQ-TOOL-001
- REQ-TOOL-002
- REQ-TOOL-003

Automated tests:

- `frontend/tests/tool_grants_requirements.test.mjs`

Objective:

Verify that passive grants reflect real passive capabilities and remain a
gateway-enforced permission.

Expected results:

- Unsupported passive grants are not offered or persisted.
- The gateway denies a passive call without the correct grant.

## TC-TOOL-002: Agent tool availability

Requirements:

- REQ-TOOL-004
- REQ-TOOL-005

Automated tests:

- `control-plane/tests/integration/test_enabled_tools_dispatchable.py`
- `worker/tests/test_agent.py`

Objective:

Verify that the agent sees only campaign-enabled tools that have a real worker
dispatch path.

Expected results:

- Enabled tools are intersected with dispatchable tools.
- Effective campaign configuration is reflected in agent context.

## TC-EGRESS-001: Egress binding and failure visibility

Requirements:

- REQ-EGRESS-001
- REQ-EGRESS-002

Automated tests:

- `control-plane/tests/integration/test_gateway_lab.py`
- `worker/tests/test_egress_visibility.py`

Objective:

Verify engagement-bound egress enforcement and ensure a proxy denial is
reported as an error rather than an empty scan result.

Expected results:

- Out-of-scope traffic is denied.
- Denial remains visible to the worker and operator.

## TC-RATE-001: Scan rate policy

Requirements:

- REQ-RATE-001
- REQ-RATE-002
- REQ-RATE-003
- REQ-RATE-004

Automated tests:

- `frontend/tests/scan_rate_policy_requirements.test.mjs`
- `control-plane/tests/integration/test_gateway_agent_budget.py`
- `control-plane/tests/integration/test_bounty_program.py`
- `worker/tests/test_bounty_ident_injection.py`

Objective:

Verify configurable rate limits, optional throttle-and-retry behavior, the
continued availability of hard denial, and that a bug-bounty program's rate
cap is also honored inside `nuclei`/`ffuf`'s own internal pacing, not only at
gateway/proxy dispatch.

Expected results:

- Policy values are bounded and applied by the gateway.
- Throttling never becomes an authorization bypass.
- A bug-bounty engagement's configured `max_rps`, when tighter than a tool's
  hardcoded default, is reflected in that tool's own rate flag; a
  non-bug-bounty engagement or lookup failure leaves the hardcoded default
  unchanged.

## TC-RUN-001: Scan-run workflow and transparency

Requirements:

- REQ-RUN-001
- REQ-RUN-002
- REQ-RUN-003
- REQ-RUN-004
- REQ-RUN-005
- REQ-RUN-006
- REQ-DOC-001

Automated tests:

- `frontend/tests/live_activity_progress_requirements.test.mjs`
- `frontend/tests/agent_step_transparency_requirements.test.mjs`
- `control-plane/tests/integration/test_scan_run_control.py`
- `worker/tests/test_agent.py`
- `worker/tests/test_scan_integrity.py`

Objective:

Verify scan preflight, cancellation, phase presentation, navigation,
agent-step persistence, and user documentation.

Expected results:

- Blocking conditions prevent enqueueing.
- Scans in `running` and `waiting_approval` become terminal immediately; in-flight exact-run tool process groups are terminated, cancellation status fails closed, and terminal runs remain unchanged with HTTP 409.
- Historical active rows with an existing cancellation request are reconciled idempotently, including only exact-run approvals.
- Persisted agent steps and phase state are inspectable.

## TC-LIVE-001: Live phase activity

Requirements:

- REQ-LIVE-001
- REQ-LIVE-002
- REQ-LIVE-003
- REQ-LIVE-004
- REQ-LIVE-005
- REQ-LIVE-006

Automated tests:

- `frontend/tests/live_activity_progress_requirements.test.mjs`

Objective:

Verify bounded, run-scoped, phase-first activity with human language, truthful
execution outcomes, understandable evidence handoffs, and progressive detail.

Expected results:

- Activity is grouped by phase and the current phase opens automatically.
- Human titles distinguish authorization, terminal execution, blocks, pauses,
  approvals, incomplete model results, and conclusions.
- Target, audited IP, port range, service count, and bounded error context are
  visible when the corresponding evidence exists.
- DNS materialization host/IP counts are derived from the audited resolved-list
  evidence, so a successful resolution is never shown as "0 hostnames / 0 IPs".
- Routine events are hidden by default and can be enabled explicitly.
- Run-window filtering, run-ID filtering, reconnect de-duplication, stream
  history, memory, and phase details remain bounded.
- Full raw evidence remains available through the Audit view.

## TC-AGENT-001: Vector and Lens agent presentation

Requirements:

- REQ-AGENT-001
- REQ-LENS-001
- REQ-LENS-002
- REQ-LENS-003

Automated tests:

- `frontend/tests/agent_lens_requirements.test.mjs`
- `control-plane/tests/integration/test_lens_agent.py`

Objective:

Verify operator-facing Vector Agent naming and evidence-grounded, cached Lens
Agent explanations.

Expected results:

- Legacy agent naming is absent from operator-facing UI.
- Lens explanations use finding evidence and are formatted safely.

## TC-CIDRDISC-001: CIDR/IP-range host discovery

Requirements:

- REQ-CIDRDISC-001
- REQ-CIDRDISC-002
- REQ-CIDRDISC-003
- REQ-CIDRDISC-004
- REQ-CIDRDISC-005
- REQ-CIDRDISC-006

Automated tests:

- `control-plane/tests/test_scope_matching.py`
- `control-plane/tests/test_args_safety.py`
- `control-plane/tests/integration/test_raw_egress_lease.py`
- `raw-egress-gateway/tests/test_gateway.py`
- `worker/tests/test_nmap_parse.py`
- `worker/tests/test_raw_nmap.py`
- `worker/tests/test_scan_integrity.py`
- `worker/tests/test_discovery_ip_cidr.py`
- `worker/tests/test_asset_review.py`
- `frontend/tests/host_discovery_coverage_transparency.test.mjs`

Objective:

Verify that an `ip`/`cidr` scope asset produces automated targets: a single
`ip` asset registers directly, and a `cidr` asset is first swept for live
hosts via one gateway-authorized, liveness-only (`nmap -sn`) sweep against
the whole range - not one gateway call per candidate host, and not a port
scan. Verify the sweep is exempted from the pre-existing
`raw_nmap_not_permitted_for_bug_bounty` block only for the `host_discovery`
profile and only when the bounty program's own policy permits automation,
paced to its `max_rps`; every other raw-nmap profile (full/configured TCP,
UDP, raw-protocol probes) remains denied for `bug_bounty` engagements
unchanged. Verify discovered live hosts carry their real `asset_type` through
the asset-review gate and into the fingerprint phase, and that deny
precedence (including a deny rule covering only part of a swept range) is
enforced when a live host is recorded, not only at sweep-authorization time.

Expected results:

- A range-shaped authorization target is accepted only for the deterministic
  `nmap`/`fingerprint`/`active` host-discovery call; every other call shape
  with `target_is_range` set is denied.
- A sweep is authorized only when its requested network is equal to, or a
  subnet of, an active `ip`/`cidr` allow scope asset; a wider or disjoint
  request is denied, as is a scope asset without `active_allowed`.
- The sweep's own rate flag reflects the engagement's/program's cap; a
  `bug_bounty` engagement's other raw-nmap profiles are unaffected (still
  denied) by the `host_discovery` exemption.
- Live hosts become `ip`-typed `discovered_asset` rows and reach the same
  candidate list domain-derived assets do, unaffected by the opt-in
  asset-review gate when it is disabled, and correctly excluded via a
  correctly-typed deny row when a candidate is excluded during review.
- A previously live-discovered host survives a run whose sweep is skipped,
  denied, or fails to dispatch.
- The wizard's Scope step and the engagement edit page's scope-assets
  section show a note about the fixed 80/443 discovery-probe set whenever a
  `cidr`-type scope asset is present, and do not show it otherwise.

## TC-MIXEDSCOPE-001: One engagement with domain + IP + CIDR scope together

Requirements:

- REQ-CIDRDISC-001
- REQ-CIDRDISC-002
- REQ-CIDRDISC-003
- REQ-CIDRDISC-005
- REQ-CIDRDISC-006
- REQ-ASSETREVIEW-003
- REQ-ASSETREVIEW-004

Automated tests:

- `worker/tests/test_mixed_scope_discovery.py`
- `control-plane/tests/integration/test_mixed_scope_engagement.py`

Objective:

Coverage for GitHub issue #38: every existing requirement above was
previously proven only in isolation (a single scope type per test) - this
test case exercises one engagement containing a `domain`, a direct `ip`,
and a `cidr` (with a deny exception inside it) TOGETHER, which is exactly
the combination whose cross-mechanism interactions (issue #34's CIDR-
sweep-blocked-by-partial-deny regression among them) isolated single-type
tests cannot catch.

Expected results:

- `discovery.run()` against a mixed-scope engagement returns candidates of
  every present type (domain apex, a mocked passive-source subdomain,
  the direct `ip`, and CIDR-swept live hosts) in one pass, correctly
  excluding a denied address inside the CIDR without losing any other live
  host in the same range (issue #34, reproduced here in a genuinely mixed
  context rather than an ip/cidr-only one) - and confirmed not merely by
  the final candidate list but by inspecting every sub-range lease request
  made, none of which cover the denied address.
- A second discovery run still finds a newly-live host in the same CIDR
  alongside the engagement's unrelated domain and direct-ip targets, with
  the pre-existing deny still in place.
- The Scope Gateway allows an active call against all three scope types on
  the same engagement, and denies an unrelated target of each type
  (different domain, different IP, different CIDR).
- A single asset-review batch spanning domain- and ip-typed candidates
  creates a deny row carrying EACH excluded candidate's own `asset_type`
  (not a one-size-fits-all guess) when decided; the Scope Gateway then
  denies exactly the excluded candidate while an unexcluded sibling of the
  same type, and the engagement's untouched domain/ip scope, remain
  allowed.
- A `bug_bounty`-source mixed-scope engagement still permits only the
  liveness-only `host_discovery` raw-nmap profile and denies `full_tcp`
  (REQ-CIDRDISC-005), unaffected by - and not itself affecting - the same
  engagement's ordinary domain-target gateway authorization.

## TC-SCOPEVAL-001: Scope-asset input validation and maximum CIDR size

Requirements:

- REQ-SCOPEVAL-001
- REQ-SCOPEVAL-002

Automated tests:

- `control-plane/tests/test_scope_asset_validation.py`
- `control-plane/tests/integration/test_scope_asset_max_cidr_size.py`

Objective:

Verify that scope-asset creation rejects malformed `rule`/`asset_type`/
`value` input with a clear 422 instead of silently accepting it, that
`ip`/`cidr` values are canonicalized (host bits cleared, equivalent
representations normalized to the same stored value), that IPv6 is
explicitly rejected rather than silently accepted and untested, and that a
`cidr` value's address count is bounded by a configurable maximum enforced
at creation time.

Expected results:

- An invalid `rule`/`asset_type`, or a malformed domain/wildcard/ip/cidr
  value, is rejected with 422 naming the offending value - a bare, dotless
  hostname (the lab environment's own internal Docker hostnames) and an
  existing bare-fnmatch wildcard pattern remain accepted, unchanged.
- `10.0.0.5/24` and `10.0.0.0/24` are stored as the identical canonical
  value; a bare address for `asset_type=cidr` is accepted as a degenerate
  `/32`.
- An IPv6 `ip`/`cidr` value is rejected with a clear reason.
- A `cidr` value whose address count exceeds
  `Settings.max_host_discovery_addresses` is rejected with 422 naming the
  count and the configured limit; a value at or under the limit is
  accepted; the check does not apply to `domain`/`ip`/`cloud_account`
  values.

## TC-BOUNTYSCAN-001: Per-program network-scan capability model for bug-bounty engagements

Requirements:

- REQ-BOUNTYSCAN-001
- REQ-BOUNTYSCAN-002
- REQ-BOUNTYSCAN-003
- REQ-BOUNTYSCAN-004
- REQ-CIDRDISC-005

Automated tests:

- `control-plane/tests/integration/test_raw_egress_lease.py`
- `control-plane/tests/integration/test_bounty_program.py`
- `raw-egress-gateway/tests/test_gateway.py`
- `raw-egress-gateway/tests/test_rate_limit_real_nft.py`
- `frontend/tests/network_scan_profile_requirements.test.mjs`

Objective:

Coverage for GitHub issue #37 (R4): verify that a `bug_bounty` program's
`tcp_syn_scan_profile` ("none"/"common"/"full") replaces the previous fixed
host-discovery-only exemption with an explicit, opt-in per-program tier;
that a program's raw packet-rate cap (`raw_max_packets_per_second`) is a
distinct field from its HTTP request rate (`max_rps`, REQ-RATE-004) and is
never conflated; that the `full` tier is refused, both at schema-validation
time and independently again at lease-issuance time, without a recorded
`network_scan_authorization_evidence` reason; and that the configured raw
rate is enforced by a genuine kernel-level nftables rate limit, not only by
nmap's own cooperative `--max-rate` flag.

Expected results:

- `tcp_syn_scan_profile="none"` (the column default, matching every
  pre-existing `BountyProgram` row) denies `configured_tcp`/`full_tcp`
  exactly as before this change - regression guard.
- `tcp_syn_scan_profile="common"` allows `configured_tcp` but still denies
  `full_tcp`.
- `tcp_syn_scan_profile="full"` with a non-empty `network_scan_authorization_
  evidence` allows `full_tcp`; without it (missing or blank), both the
  Pydantic schema and the gateway's own lease-issuance check reject it
  (`full_tcp_requires_authorization_evidence`).
- `targeted_udp`/`raw_tcp_probe` remain denied for `bug_bounty` regardless of
  `tcp_syn_scan_profile`.
- When `raw_max_packets_per_second` is set, it - not `max_rps` - governs the
  raw nmap rate for every raw-egress lease on that program; when unset, the
  pre-existing `max_rps`-based fallback applies unchanged.
- `NftPolicyManager.apply()` installs a real `limit rate N/second` nftables
  rule scoped to the lease's slot, verified against the actual `nft` binary
  inside a running `raw-egress-gateway` container - including that a later
  lease on the same slot can install a different rate without the prior
  rule/limit object needing to be torn down out of band first (a genuine
  nftables constraint on named limit objects that a purely textual/mocked
  test cannot surface). `NftPolicyManager.clear()` removes it.

