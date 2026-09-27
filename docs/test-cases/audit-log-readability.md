---
title: Audit log readability verification
status: ready
risk: R2
owner: engineering
---

# Audit Log Readability Verification

Verifies [`../requirements/audit-log-readability.md`](../requirements/audit-log-readability.md).

## TC-AUDITUI-001: One chronological, searchable, paginated audit projection

Requirements:

- REQ-AUDITUI-001

Automated tests:

- `control-plane/tests/integration/test_audit_list.py`

Objective:

Verify the `GET /engagements/{id}/audit` endpoint returns the engagement's audit
entries newest-first, supports free-text and field filters and cursor
pagination, is scoped to the engagement, and never mutates the log.

Expected results:

- Entries are returned newest-first for the engagement only; an unrelated
  engagement id returns none.
- Free-text `q` matches text in the JSON payload (e.g. a hostname or tool name),
  not only the top-level string columns.
- `decision` (case-insensitive) and `actor`/`action` filters narrow the result.
- `limit` + `before` cursor pages backward with no overlap and reports
  `has_more`/`next_before` correctly.
- Repeated list/search calls leave the `audit_log` row count unchanged (the
  projection is read-only).

## TC-AUDITUI-002: Filter facets and plain-language rendering

Requirements:

- REQ-AUDITUI-002

Automated tests:

- `control-plane/tests/integration/test_audit_list.py`

Objective:

Verify the backend exposes the distinct actor/action values for filter
dropdowns, and that the audit view (frontend/src/pages/Audit.tsx, covered by the
frontend tsc --noEmit build gate) renders each entry as a single readable line
with the raw payload available on demand.

Expected results:

- `GET /engagements/{id}/audit/facets` returns the distinct actors and actions
  present for the engagement.
- The audit page compiles and renders one time-ordered list where each row is a
  human-readable summary (actor + what happened + target/outcome), decisions
  are visually distinguished, and each row expands to the raw actor/action/
  reason/payload; denied entries show a plain-language explanation and, where
  applicable, the operator override action.

## TC-AUDITUI-003: Actor and action filter to multiple values

Requirements:

- REQ-AUDITUI-003

Automated tests:

- `control-plane/tests/integration/test_audit_multi_filter.py`
- `frontend/tests/audit_multi_select_filter.test.mjs`

Objective:

Verify multi-value filtering narrows correctly on the server, stays backward
compatible with the single-value form, and that the client models the selection
in the direction that keeps a live audit log fail-visible.

Expected results:

- Two `actor` values return entries for both actors and exclude all others;
  the same holds for `action`.
- Actor and action filters combine as AND across facets.
- A single value behaves exactly as the old equality filter did.
- Omitting the parameter returns all entries for the engagement.
- The number of values honored per facet in one request is bounded.
- Filtering does not alter, reorder, or re-hash any audit row.
- The client tracks excluded values (so a newly appearing actor stays visible)
  and skips the request entirely when a facet has every value unchecked.
