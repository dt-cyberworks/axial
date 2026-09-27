---
title: Audit log readability (unified searchable chronological view)
status: implemented
risk: R2
owner: engineering
---

# Audit Log Readability

Context: the engagement audit view splits events into three separate panels
(network egress / gateway / policy) fed by the SSE stream. To understand "what
did the system actually do, in order", an operator has to mentally interleave
three tables, and there is no way to search. The audit data is rich and correct
(append-only, hash-chained `audit_log`); the presentation is the problem.

This requirement replaces that view with a single chronological, searchable,
human-readable log — like reading an application log — without changing what is
recorded or the audit integrity guarantees.

**Risk class: R2** (a new read-only API endpoint over existing audit data plus
a UI change; no change to authorization, audit writing, or the hash chain).
The endpoint is mounted under the existing authenticated, ownership-checked
engagement router, so an operator can only read their own engagements' audit
(admins any), exactly as today.

## REQ-AUDITUI-001: One chronological, searchable audit log

The engagement audit view presents the audit as a single readable log rather
than separate per-category tables.

Acceptance criteria:

- The engagement audit view presents **one** time-ordered list of audit
  entries (newest first), not separate per-category tables.
- A free-text search box filters entries server-side across actor, action,
  decision, reason, and the JSON payload text (e.g. a hostname, tool name,
  target, or scan_run_id can be searched for).
- Entries can additionally be filtered by decision (allow / deny / pending),
  actor, and action.
- The list pages backward through history on demand (cursor by timestamp), so
  the full audit is reachable, not just the most recent window.
- Filtering/search never changes what exists in the audit log; it is a
  read-only projection. The append-only hash-chained `audit_log` and its
  writers are unchanged.

## REQ-AUDITUI-002: Each entry reads as a plain-language line

Each entry is understandable on its own, without knowledge of the internal
event taxonomy, and the underlying evidence stays available.

Acceptance criteria:

- Every entry renders as a concise, human-readable one-line summary of what the
  system did (who, what action, on what, and the outcome), understandable
  without knowing the internal event taxonomy — e.g. "Gateway ALLOW — nuclei on
  app.example.com (vuln/active)", "Egress DENY — GET metadata.internal
  (blocked_link_local_address)", "Agent proposed http_request on
  app.example.com".
- Decisions are visually distinguished (allow / deny / pending / neutral).
- The raw entry (actor, action, reason, full payload, timestamp) remains
  available on demand (expandable) so no evidence is hidden.
- The backend supplies a REST endpoint
  `GET /engagements/{id}/audit` (filter + search + cursor pagination) and a
  facets endpoint for the available actor/action filter values; both require
  the same authentication and engagement ownership as every other engagement
  route.

## REQ-AUDITUI-003: Actor and action filter to multiple values at once

Context: reported 2026-08-09 - the actor and action filters were single-select
`<select>` dropdowns backed by single-string state, and the backend matched
them with strict equality (`AuditLog.actor == actor`). An operator could
therefore narrow to exactly one actor or one action, but could never express
"show everything except these two" without stepping through each remaining
value one at a time.

Acceptance criteria:

- `GET /engagements/{id}/audit` accepts repeated `actor` and `action` query
  parameters (`?actor=a&actor=b`) and matches with `IN` rather than `=`.
- A single value behaves exactly as the previous equality filter did, so
  existing callers, saved links, and the page's own auto-refresh keep working
  unchanged.
- Omitting the parameter continues to mean "no filter on this facet".
- The number of values accepted per facet in one request is bounded, so a
  hand-crafted request cannot build an unbounded `IN` list.
- The UI presents each facet as a checkbox list (spreadsheet-style column
  filter) with every value checked by default, plus "Select all" / "Clear all",
  and a trigger showing `4/6` when the selection is partial.
- Client state tracks EXCLUDED values, not selected ones: the log is live and
  new actors/actions appear while the page is open, and a selected-set model
  would default every newly-seen value to hidden - silently dropping events out
  of an audit view. Anything new is visible until the operator excludes it.
- Unchecking every value of a facet shows no entries and issues no request,
  rather than sending an empty list (indistinguishable on the wire from "no
  filter") and misleadingly showing everything.
- The free-text search and the decision filter are unchanged.

Security invariants:

- Still read-only over existing audit data: no change to what is recorded, to
  the hash chain, or to the ownership check enforced by the router this
  endpoint is mounted on. Values are bound as query parameters via SQLAlchemy
  `IN`, never interpolated into SQL.
