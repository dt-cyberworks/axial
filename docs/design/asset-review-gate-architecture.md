# Architecture: Post-Discovery Asset Review Gate

Implements [`../requirements/asset-review-gate.md`](../requirements/asset-review-gate.md).

## Principle

Reuse the existing pause primitive (`scan_run.state=waiting_approval`, already
used for HTTP-write approvals) for a second, distinct kind of human-in-the-loop
decision. No new `scan_phase`/`scan_state` enum values are needed — pausing
mid-phase for an operator decision is already the established pattern
(REQ-APPROVAL-003 does this within the `agent` phase without a dedicated phase
value; this does the same between `discovery` and `fingerprint`).

The decision is never a widening action: the endpoint only accepts *exclusions*
from an already-computed in-scope candidate set. Structurally, there is no
parameter through which new scope could be added — narrowing-only is enforced
by the request shape, not by a runtime check alone.

## Data model (migration 0013)

`engagement.asset_review_enabled BOOLEAN NOT NULL DEFAULT false` — REQ-ASSETREVIEW-001.

New table `asset_review_request` (mirrors `approval_request`'s shape):

| column | type | note |
|---|---|---|
| `id` | uuid pk | |
| `engagement_id` | uuid fk | |
| `scan_run_id` | uuid fk, unique | one review per run |
| `candidate_assets` | jsonb | `[{asset_id, value, asset_type}]` snapshot at creation |
| `state` | text | `pending` \| `submitted` \| `expired` \| `cancelled` |
| `excluded_values` | jsonb, nullable | set on submit |
| `expires_at` | timestamptz | |
| `decided_at` | timestamptz, nullable | |
| `decided_by` | text, nullable | |

Snapshotting `candidate_assets` at creation (rather than re-querying
`discovered_asset` at decision time) keeps the reviewed set stable even if
discovery data changes concurrently, and gives TC-ASSETREVIEW-004 a fixed
universe to validate exclusions against.

## Pipeline wiring (worker)

`worker/app/tasks/pipeline.py`, between `discovery.run()` and `fingerprint.run()`:

```python
discovered = discovery.run(engagement_id)
client.update_scan_run(scan_run_id, phase="fingerprint")  # phase advances; state may still pause below
if _stopped(): ...
discovered = asset_review.gate(engagement_id, str(scan_run_id), discovered)
if discovered is None:
    client.update_scan_run(scan_run_id, state="aborted", state_reason="asset_review_expired")
    return {...}
services = fingerprint.run(engagement_id, discovered, scan_run_id=str(scan_run_id))
```

New `worker/app/tasks/asset_review.py`, mirroring `_await_approval`'s
poll-and-wait shape:

- `gate(engagement_id, scan_run_id, discovered) -> list[dict] | None`:
  - `is_required(engagement_id)` (internal `GET .../asset-review-required`) — if
    `false`, returns `discovered` unchanged immediately (no behavior change,
    REQ-ASSETREVIEW-001).
  - Otherwise creates a review (`POST .../scan-runs/{run_id}/asset-review` with
    the in-scope subset of `discovered`), sets the run to
    `waiting_approval`/`asset_review_pending`, and polls
    `GET /internal/asset-reviews/{id}` every `_REVIEW_POLL_SECONDS` (3s) up to
    `_REVIEW_MAX_WAIT_SECONDS` (900s, matching the HTTP-approval wait), checking
    `is_cancel_requested` each iteration (fails closed on cancel, immediately).
  - On `submitted`: sets state back to `running`, returns `discovered` filtered
    to exclude the reviewed-out values.
  - On `expired`/`cancelled`/timeout: returns `None` (caller aborts the run —
    REQ-ASSETREVIEW-006).

## Control-plane endpoints

Internal (worker-facing, `x-asm-internal-token`):
- `GET /internal/engagements/{id}/asset-review-required` → `{"required": bool}`
- `POST /internal/engagements/{id}/scan-runs/{run_id}/asset-review` → creates the
  pending review from the current in-scope `discovered_asset` set, pauses the run.
- `GET /internal/asset-reviews/{id}` → poll target; lazily flips to `expired`
  past `expires_at` (mirrors the existing approval lazy-expiry pattern).

Public (operator-facing):
- `GET /engagements/{id}/asset-reviews?state=pending` → list (0 or 1 typically),
  for the Run detail popup to poll (mirrors `listApprovals`).
- `POST /engagements/{id}/asset-reviews/{id}/decide` body
  `{"excluded_values": [...]}`:
  - Filters `excluded_values` to the intersection with `candidate_assets`
    (REQ-ASSETREVIEW-004 — anything else is silently dropped, not an error).
  - For each surviving excluded value: idempotently ensure a `scope_asset`
    `deny` row (domain or ip per the candidate's `asset_type`), and set the
    matching `discovered_asset.in_scope=false`.
  - Marks the review `submitted`, resumes the run (`state=running`).
- `DELETE /engagements/{id}/scope-assets/{asset_id}` (new — REQ-ASSETREVIEW-005,
  previously missing entirely from the API).

## Discovery deny-precedence fix (REQ-ASSETREVIEW-007)

`worker/app/tasks/discovery.py`'s `run()` already fetches all `scope_assets`
(allow and deny) via `client.list_scope_assets`. Today it only ever consults the
`allow` subset for the `in_scope` computation. Add a deny check using the same
domain/wildcard matching shape already used for allow, evaluated *first* (deny
beats allow, mirroring `authorize.py`'s `_matches_asset_value`): a name matching
an explicit deny row is `in_scope=false` regardless of any allow match.

## Frontend

- Wizard + Engagement edit: `asset_review_enabled` checkbox alongside
  `ai_testing_allowed`.
- New **scope-asset editor** on Engagement edit (list all rows with rule/type/
  value/active_allowed, add row, delete row) — did not exist post-creation
  before this feature (REQ-ASSETREVIEW-005).
- `RunDetail.tsx`: polls pending asset-reviews for the engagement (parallel to
  the existing approval poll) and renders an `AssetReviewModal` — checklist,
  all pre-checked, "Continue with selected" submits the *deselected* subset as
  `excluded_values`.
- Documentation: engagement flag, the pause/popup, and the new scope editor.

## Requirement → change map

| Requirement | Change |
|---|---|
| REQ-ASSETREVIEW-001 | `engagement.asset_review_enabled`, wizard/edit checkbox, `is_required` short-circuit |
| REQ-ASSETREVIEW-002 | `asset_review_request` table, pipeline pause, `AssetReviewModal` |
| REQ-ASSETREVIEW-003 | `decide` endpoint's deny-row + `in_scope` update |
| REQ-ASSETREVIEW-004 | `decide` endpoint's candidate-intersection filter |
| REQ-ASSETREVIEW-005 | scope-asset editor UI + new `DELETE` endpoint |
| REQ-ASSETREVIEW-006 | fail-closed `gate()` return `None` on expiry/cancel |
| REQ-ASSETREVIEW-007 | `discovery.py` deny-aware `in_scope` computation |
