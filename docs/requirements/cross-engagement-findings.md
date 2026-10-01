---
title: Cross-engagement findings API and edge routing
status: implemented
risk: R3
owner: security-engineering
---

# Cross-Engagement Findings

Context: the console's new findings list (REQ-CONSOLE-016) needs one API
call that returns findings from several engagements. Every other findings
endpoint has the engagement id in its path, where the router-wide ownership
check (`enforce_engagement_ownership`) applies. This endpoint has no
engagement id in its path, so that check does **not** apply, and the handler
itself must restrict the rows to what the caller may see. That is why this
is R3: a mistake here discloses other users' findings.

**Risk class: R3** (authorization of a new data path; edge routing).
Negative tests and a human security review are required.

**Security review:** approved by johannes (project/security owner) on
2026-09-29 ("I approve all changes"), after the negative tests and the
mutation checks listed in the linked test cases. Live verification on the
dev stack is still owed at deploy time and is recorded in the test case.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

## REQ-PORTFOLIO-001: List findings across the caller's engagements

> **Amended by REQ-IAM-022 (johannes, 2026-10-01, GitHub issue #47, `docs/requirements/engagement-visibility.md`).**
> The list covers every engagement (everyone reads everything); the new `mine=true`
> parameter narrows it to the caller's own, and each finding carries its engagement's
> owner. Reading never changes anything, so triage still goes through the
> engagement's own endpoint, which only the owner or an admin may call.

Acceptance criteria:

- `GET /findings` returns findings from every engagement, the same rule as
  the engagement list (REQ-IAM-022); `mine=true` keeps only the caller's own.
- Query parameters: `status` (default `open`), `severity`, `engagement_id`,
  `q` (text search), `limit` (1–200, default 50), `offset` (default 0).
  Unknown `status` or `severity` values are rejected with `422`.
- The response has `items` (each finding with the same fields as the
  engagement findings list, plus `engagement_title`), `total` (all matches,
  not only this page), and `counts_by_status` / `counts_by_severity` for
  the same filters without the status / severity filter.
- Order: severity (critical first, missing severity last), then risk score
  (highest first), then newest first.
- `q` matches the finding title or the target name, case-insensitive, as
  literal text (`%` and `_` have no wildcard meaning).
- [Negative test] An operator never receives another user's findings: not
  in the default list, not in any count, not with `engagement_id` set to
  another user's engagement (an empty result, the same as for an id that
  does not exist), and not through `q`.
- [Negative test] Without a valid session the endpoint answers `401`.
- The endpoint is read-only.

## REQ-PORTFOLIO-002: The edge routes `/findings` like the other shared paths

Acceptance criteria:

- In `edge/Caddyfile` and `edge-shared/Caddyfile`, `/findings*` is sent to
  the control plane for API requests and serves the console for browser
  navigation (`Accept: text/html`), exactly like `/engagements*`.
- It gets the same cache policy as the other shared paths (`no-store` and
  `Vary: Accept`, REQ-WEBSEC-003) and is never compressed (issue #13).
- [Negative test] A test fails if the path lists inside either Caddyfile
  disagree with each other (shared-path cache rule, console fallback,
  compression exclusion, API matcher), so a future prefix cannot be added
  to one list and forgotten in another.

Security invariants:

- The `mine` filter is part of the database query, not applied to
  results afterwards, so `total` and the counts always agree with the page.
- Triage stays on the engagement-scoped endpoint, where the router-wide
  access rule applies (a change is the owner's or an admin's, REQ-IAM-023);
  this endpoint changes nothing.

Verification log:

- 2026-09-29 — implemented with negative tests, a mutation check, and real
  Caddy routing tests (see
  [`../test-cases/cross-engagement-findings.md`](../test-cases/cross-engagement-findings.md)).
  **Human security review by johannes: approved 2026-09-29.**
