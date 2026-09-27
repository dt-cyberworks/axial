---
title: Per-target TCP port scoping verification
status: ready
risk: R3
owner: security-engineering
---

# Per-Target TCP Port Scoping Verification

Verifies [`../requirements/per-target-port-scoping.md`](../requirements/per-target-port-scoping.md).
R3: the negative tests proving a per-target range actually narrows enforcement
(not just validated at write time) are the primary evidence.

## TC-PORTSCOPE-001: Write-time subset validation

Requirements:

- REQ-PORTSCOPE-001

Automated tests:

- `control-plane/tests/integration/test_scope_asset_port_scoping.py`

Objective:

Confirm the API rejects a scope-asset port range wider than the engagement's
current ceiling, and accepts one that fits.

Expected results:

- `test_scope_asset_port_range_wider_than_ceiling_is_rejected` - 422.
- `test_scope_asset_port_range_within_the_ceiling_is_accepted` - 201, values
  persisted as given.
- `test_scope_asset_with_no_port_override_is_always_accepted` - accepted
  unconditionally, since inheriting the ceiling always fits.

## TC-PORTSCOPE-002: egress-proxy enforces the per-target effective range

Requirements:

- REQ-PORTSCOPE-002

Automated tests:

- `egress-proxy/tests/test_port_scope.py`

Objective:

Prove the egress-proxy's independent network-layer enforcement narrows per
target, not just per engagement, and that the narrowing is re-derived fresh
on every call rather than cached from when the asset was created.

Expected results:

- `test_target_with_no_port_override_still_gets_the_full_ceiling` - backward
  compat, zero behavior change.
- `test_negative_target_specific_range_narrower_than_ceiling_blocks_a_port_the_ceiling_would_allow` -
  the core negative test.
- `test_negative_narrowing_the_ceiling_after_the_fact_immediately_narrows_a_target_too` -
  proves re-derivation, not a one-time check.
- `test_port_allowed_if_it_falls_within_any_matched_allow_assets_range` - two
  matched allow-assets with different ranges both apply (any-match
  semantics), not a collapsed envelope.

## TC-PORTSCOPE-003: Raw-egress (nmap) leases resolve per-target

Requirements:

- REQ-PORTSCOPE-003

Automated tests:

- `control-plane/tests/integration/test_raw_egress_lease.py`
- `control-plane/tests/test_args_safety.py`

Objective:

Prove nmap lease issuance resolves the specific target's effective range
(not the flat engagement range), that `full_tcp` requires the target itself
to be genuinely unrestricted, and that the args-safety gate accepts the
resulting multi-segment `-p` syntax within bounds.

Expected results:

- `test_target_specific_port_range_narrows_the_ceiling` - the lease's port
  list reflects the target's own narrower range.
- `test_negative_target_range_cannot_widen_beyond_the_ceiling_even_if_the_row_is_bad` -
  enforcement-time re-intersection holds even against a row that bypassed
  write-time validation (direct DB write in the test).
- `test_negative_full_tcp_denied_for_a_target_narrowed_below_the_ceiling` - a
  wide ceiling does not grant `full_tcp` for a target whose own range is
  narrower.
- `test_multiple_matched_assets_produce_one_nmap_port_segment_each` - two
  matched assets with disjoint ranges produce two segments, not a merged
  envelope that would over-authorize the gap between them.
- `test_configured_tcp_allows_a_bounded_comma_separated_segment_list` /
  `test_full_tcp_rejects_a_segment_list_even_if_it_sums_to_the_full_range` -
  the args-safety gate's own bounds hold for the new multi-segment shape.

## TC-PORTSCOPE-004: Worker HTTP dispatch targets the per-target range

Requirements:

- REQ-PORTSCOPE-004

Automated tests:

- `worker/tests/test_fingerprint_port_targeting.py`
- `control-plane/tests/integration/test_scope_asset_port_scoping.py`

Objective:

Confirm the fingerprint phase asks for and uses each discovered host's own
effective range, not a single value fetched once for the whole engagement
run, and that the endpoint it calls resolves that range correctly (or falls
back to the ceiling when there's nothing specific to resolve).

Expected results:

- `test_run_resolves_the_envelope_per_host_not_once_for_the_whole_engagement` -
  two targets in one run with different envelopes each get their own
  web-tool target port; `get_scan_envelope` is called once per host with
  that host's own value, not once for the engagement.
- `test_run_fetches_envelope_and_threads_single_port_to_all_web_tools` (pre-
  existing, still green) - single-target behavior is unchanged.
- `test_scan_envelope_endpoint_resolves_the_matched_targets_own_range` /
  `test_scan_envelope_endpoint_falls_back_to_the_ceiling_for_an_unmatched_host` /
  `test_scan_envelope_endpoint_without_host_returns_the_flat_ceiling_unchanged` -
  the endpoint itself, not just the worker's use of it.
