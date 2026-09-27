---
title: Post-discovery asset review gate verification
status: ready
risk: R3
owner: security-engineering
---

# Post-Discovery Asset Review Gate Verification

Verifies [`../requirements/asset-review-gate.md`](../requirements/asset-review-gate.md).
R3: negative paths (narrowing-only, fail-closed timeout, opt-in default) are required.

## TC-ASSETREVIEW-001: Opt-in default; disabled engagements are unaffected

Requirements:

- REQ-ASSETREVIEW-001

Automated tests:

- `worker/tests/test_asset_review.py`
- `control-plane/tests/integration/test_asset_review.py`

Objective:

Verify the review is only offered when explicitly enabled, and that a
disabled engagement's pipeline behaves exactly as before (no pause created).

Expected results:

- `asset_review_enabled=false` (default): `asset_review_required` reports
  `false`; the worker gate is a no-op (no review created, discovered list
  unchanged).
- `asset_review_enabled=true`: `asset_review_required` reports `true`.

## TC-ASSETREVIEW-002: Review pauses the run and lists exact in-scope candidates

Requirements:

- REQ-ASSETREVIEW-002

Automated tests:

- `control-plane/tests/integration/test_asset_review.py`

Objective:

Verify creating a review pauses the run with a distinguishable reason, stores
exactly the given candidate snapshot, and a decision resumes the run.

Expected results:

- Creating a review sets `scan_run.state=waiting_approval`,
  `state_reason=asset_review_pending`, and persists the candidate snapshot
  unchanged.
- Creating a review twice for the same run is idempotent (same id returned).
- Submitting a decision resumes the run (`state=running`,
  `state_reason=None`).

## TC-ASSETREVIEW-003: Deselection creates a real, enforced deny rule

Requirements:

- REQ-ASSETREVIEW-003

Automated tests:

- `control-plane/tests/integration/test_asset_review.py`

Objective:

Verify an excluded candidate becomes a genuine, Gateway-enforced `scope_asset`
deny row and its `discovered_asset.in_scope` is corrected, idempotently.

Expected results:

- Excluding a host creates a `scope_asset` deny row for it and sets
  `discovered_asset.in_scope=false`.
- A direct `authorize()` call against that host is denied afterward, even
  though it still structurally matches an allow rule (deny beats allow) —
  proving Gateway enforcement, not just a pipeline-level skip.
- Excluding the same value across two separate reviews creates only one deny
  row, not a duplicate.
- Resubmitting a decision for an already-decided review is rejected (409).

## TC-ASSETREVIEW-004: The gate cannot widen scope

Requirements:

- REQ-ASSETREVIEW-004

Automated tests:

- `control-plane/tests/integration/test_asset_review.py`

Objective:

Verify the decision endpoint can only narrow the original candidate set —
never introduce a new deny/allow target and never create scope noise for a
kept candidate.

Expected results:

- An `excluded_values` entry outside the original candidate list is silently
  dropped: no `scope_asset` row is created for it, and the request still
  succeeds.
- A candidate that stays selected (not excluded) produces no new
  `scope_asset` row — the total row count is unchanged.

## TC-ASSETREVIEW-005: Scope assets are listable/removable post-creation

Requirements:

- REQ-ASSETREVIEW-005

Automated tests:

- `control-plane/tests/integration/test_asset_review.py`

Objective:

Verify scope-asset rows (including auto-generated deny rows) remain visible
and removable via the API after the engagement is created, not only during
the wizard.

Expected results:

- `DELETE /engagements/{id}/scope-assets/{asset_id}` removes a row.
- Removing a deny row makes a subsequent `authorize()` call for that host
  succeed again (an allow rule still matches).
- Newly added scope-asset rows show up in the listing endpoint.

## TC-ASSETREVIEW-006: An unanswered or cancelled review fails closed

Requirements:

- REQ-ASSETREVIEW-006

Automated tests:

- `worker/tests/test_asset_review.py`

Objective:

Verify the worker gate never proceeds with the full candidate set when the
review is not positively decided — it returns `None`, and the pipeline caller
must abort the run.

Expected results:

- A review report of `expired` makes `gate()` return `None`.
- `is_cancel_requested=true` observed while waiting makes `gate()` return
  `None` immediately, without polling further.
- A failure to even create the review (e.g. control plane unreachable) also
  makes `gate()` return `None` (fail closed), not raise or proceed with all
  candidates.
- A `submitted` decision returns the discovered list filtered to the
  surviving (non-excluded) assets.

## TC-ASSETREVIEW-007: Discovery in-scope computation respects deny precedence

Requirements:

- REQ-ASSETREVIEW-007

Automated tests:

- `worker/tests/test_discovery_scope.py`

Objective:

Verify `discovery.run()`'s in-scope computation now considers deny rules
(domain and wildcard), not only allow matching, and that allow-domain
matching is case-insensitive (DNS names are case-insensitive by
specification).

Expected results:

- A name matching both an allow-domain rule and an explicit deny-domain rule
  computes `in_scope=false`.
- A name matching an allow rule and a deny-wildcard rule also computes
  `in_scope=false`.
- A name matching only allow (no deny) is unaffected (`in_scope=true` as
  before).
- An allow-domain scope value entered with any capitalization still computes
  `in_scope=true` for the apex domain and its subdomains, matching the
  already-lowercased discovered names
  (`test_allow_domain_scope_matching_is_case_insensitive`) - found live via
  the UAT scan-journey tier, see the addendum in
  `docs/requirements/asset-review-gate.md`.
