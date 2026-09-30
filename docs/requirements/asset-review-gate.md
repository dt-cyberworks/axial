---
title: Post-discovery asset review gate
status: implemented
risk: R3
owner: security-engineering
---

# Post-Discovery Asset Review Gate

This document is the requirement source for an optional, per-engagement pause
between the `discovery` and `fingerprint` phases that lets the operator review
the discovered, in-scope asset list and exclude specific hosts/IPs before the
rest of the pipeline (fingerprint, correlate, Vector Agent, validate, score,
report) is allowed to touch them.

Context: `discovery`'s in-scope computation is pattern-based (a discovered name
matches an allow domain/wildcard rule). If a customer's DNS is poorly managed
(e.g. a stale subdomain now pointing at infrastructure the customer no longer
controls, or a wildcard allow rule over-matching), a discovered asset can be
*structurally* in-scope without being something the operator actually wants
scanned. This gate adds a human checkpoint exactly where that risk surfaces,
without changing the deterministic scope model itself.

**Risk class: R3** — this feature creates real `scope_asset` deny rules
(enforced by the Scope Gateway) and gates pipeline progression. It requires
negative tests proving the gate can only *narrow* scope, never widen it, and
that a review timeout fails closed.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

---

## REQ-ASSETREVIEW-001: The review is opt-in per engagement

Acceptance criteria:
- `engagement.asset_review_enabled` (boolean, default `false`) controls whether
  the pause is offered. Settable at creation (wizard) and afterward (engagement
  edit).
- When `false` (the default), the pipeline behaves exactly as before: no pause,
  no behavior change. Existing engagements are unaffected until explicitly
  opted in.

## REQ-ASSETREVIEW-002: The run pauses after discovery and lists in-scope candidates

Acceptance criteria:
- For an engagement with the review enabled, after `discovery` completes and
  before `fingerprint` starts, the scan run enters `state=waiting_approval`
  with `state_reason=asset_review_pending`, and a review record is created
  listing exactly the discovered assets that are currently in-scope for this
  run (the same set that would otherwise silently proceed).
- The Run detail view shows a popup listing every candidate asset, all
  pre-selected (opt-out model): the operator deselects the ones that should
  NOT proceed, then submits.
- On submit, the run resumes with only the assets that remained selected;
  deselected assets are excluded from this run's fingerprint/agent/etc. phases.

## REQ-ASSETREVIEW-003: Deselection creates a real, enforced deny rule

Acceptance criteria:
- Deselecting an asset creates (or reuses, idempotently) a `scope_asset` row
  with `rule=deny` for that exact host/IP. Deny beats allow (existing
  invariant) — a subsequent Scope Gateway `authorize()` call against that host
  is denied, not merely skipped by this one pipeline run.
- The corresponding `discovered_asset.in_scope` is also set to `false`, so
  future discovery passes compute it as out-of-scope directly (no repeated,
  noisy denied calls).
- The new deny rule is visible and removable from the engagement's scope-asset
  configuration (engagement edit view) like any other scope rule — REQ-ASSETREVIEW-005.

## REQ-ASSETREVIEW-004: The gate can only narrow scope, never widen it

Acceptance criteria:
- The decision endpoint accepts only exclusions from the exact candidate set
  generated at review-creation time; it cannot introduce a new target, widen
  an existing rule, or re-include something the deterministic scope computation
  did not already mark in-scope.
- Selecting "keep" for a candidate is a no-op (it already has an allow match by
  construction) — no new scope_asset row is created for kept assets.

## REQ-ASSETREVIEW-005: Scope assets are viewable and editable after creation

Acceptance criteria:
- The engagement edit view lists all current `scope_asset` rows (allow and
  deny, with source/reason where available) and lets the operator add or
  remove rows after the engagement has been created — not only during the
  initial wizard.
- Removing an auto-generated deny row (e.g. reverting an earlier exclusion)
  takes effect immediately for subsequent Gateway decisions.

## REQ-ASSETREVIEW-006: An unanswered review fails closed

Acceptance criteria:
- If the operator does not submit a decision within the review's expiry window,
  the run aborts with a clear `state_reason` (e.g. `asset_review_expired`) — it
  never silently proceeds with the full candidate set.
- A cancelled run while a review is pending stops waiting immediately (same
  cooperative-cancel guarantee as REQ-RUN-001) without executing anything.

## REQ-ASSETREVIEW-007: Discovery's in-scope computation respects deny precedence

Discovery's in-scope computation currently considers only allow-domain
matching. This is a defense-in-depth gap this feature depends on closing:

Acceptance criteria:
- A discovered name matching an explicit `deny` rule (domain, wildcard, or
  exact) is computed as `in_scope=false`, even if it also matches an `allow`
  rule (deny beats allow — the existing gateway-wide invariant, now also
  applied at discovery time, not only at active-call time).
- Allow-domain matching is case-insensitive: an allow scope value entered with
  any capitalization (e.g. `Pentest-Ground.com`) still computes `in_scope=true`
  for the already-lowercased discovered names that are the same domain or its
  subdomains — DNS names are case-insensitive by specification, so a scope
  value's capitalization must never change what is considered in-scope.

**Addendum (2026-07-28):** found live via the new UAT harness's scan-journey
tier (`docs/requirements/user-acceptance-testing.md`, REQ-UAT-003): an allow
scope value entered with uppercase letters left `root_values`/`real_domains`
in `worker/app/tasks/discovery.py` un-lowercased, while every discovered
value is already lowercased - so `in_scope` computed `false` for the exact
same domain, and the agent phase logged "no in-scope assets" and no-opped
even though the tool-based scan itself ran and recorded findings normally.
This also silently affected passive-source subdomain matching
(`name.endswith(domain)` comparisons), not only the agent no-op. Fixed by
lowercasing `root_values` at the point it's built. Regression test:
`test_allow_domain_scope_matching_is_case_insensitive` in
`worker/tests/test_discovery_scope.py` (proven to fail against the old code
and pass against the fix). Pending deployment to production - the fix lives
in the worker's Docker image and needs a rebuild, not a hot-reload.

## REQ-ASSETREVIEW-009: Only current, active-eligible candidates leave discovery

**Security review (R3):** approved by johannes (project/security owner) on
2026-09-29. A real dev scan against `cloud.example.com` is still owed at deploy time.

GitHub issue #33: discovery computed `in_scope` per candidate but returned
every candidate anyway, re-added previously known IPs without re-checking the
scope, ignored `active_allowed` on single `ip` assets, matched passive-source
names without a label boundary, and could only ever set `in_scope` to true.
The Scope Gateway still denied every active call, but asset review, the
fingerprint phase, and the agent saw a broader, staler list than the scope.

Acceptance criteria:

- Discovery returns (to asset review and fingerprinting) only values that the
  current scope allows, that no deny rule covers, and that an
  `active_allowed` allow rule covers. Domain and wildcard matching is the
  gateway's own (a wildcard covers subdomains, not the bare root).
- [Negative test] A single `ip` asset with `active_allowed=false` is never a
  candidate, like a passive-only `cidr` asset is never swept.
- [Negative test] A previously discovered IP or name that no current allow
  rule covers, or that a new deny rule covers, is not a candidate on the
  next run and its stored `in_scope` is set to false.
- [Negative test] Passive-source names are matched on a label boundary:
  `badexample.com` never enters the pool for `example.com`.
- `discovered_asset.in_scope` follows the current scope both ways (demoted
  and promoted again), so the agent's in-scope pool reflects the current
  scope. Demoted values stay in the inventory.
- The asset-review dialog says the listed hosts are the ones the current
  scope allows for active testing.

