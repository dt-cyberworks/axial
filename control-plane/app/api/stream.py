import asyncio
import datetime as dt
import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sse_starlette.sse import EventSourceResponse
from sqlalchemy import String, cast, distinct, or_, select
from sqlalchemy.orm import Session

from app.db.base import SessionLocal, get_db
from app.models.audit import AuditLog
from app.models.scan_run import ScanRun

router = APIRouter(prefix="/engagements", tags=["stream"])

_POLL_INTERVAL_SECONDS = 1.0


def _validate_run(db: Session, engagement_id: uuid.UUID, scan_run_id: uuid.UUID) -> None:
    """Fail fast with a normal 404 response before the SSE stream opens,
    rather than inside the generator loop where an exception would just
    kill the stream instead of producing a clean HTTP error."""
    run = db.get(ScanRun, scan_run_id)
    if run is None or run.engagement_id != engagement_id:
        raise HTTPException(404, "scan_run not found for this engagement")


def _run_scoped_clause(db: Session, engagement_id: uuid.UUID, scan_run_id: uuid.UUID):
    """REQ-FIDELITY-002: an event tagged with THIS run's scan_run_id always
    matches; an event tagged with a DIFFERENT run's scan_run_id never matches
    (no cross-run leakage even if timestamps overlap); an event carrying no
    scan_run_id at all (some audit actions predate that field) falls back to
    the run's own time window.

    Called fresh on every poll (not once at connect time): for an active run
    the time-window's upper bound is "now" and must not be frozen at
    connection-open time, or any untagged event created after that moment -
    i.e. most of a freshly-opened run's activity - would never be included.
    Returns None if the run has since vanished (defensive only; `_validate_run`
    already fails the request fast if it never existed)."""
    run = db.get(ScanRun, scan_run_id)
    if run is None or run.engagement_id != engagement_id:
        return None
    window_end = run.finished_at or dt.datetime.now(dt.timezone.utc)
    run_id_text = str(scan_run_id)
    tagged = AuditLog.payload["scan_run_id"].astext
    return or_(
        tagged == run_id_text,
        (tagged.is_(None)) & (AuditLog.ts >= run.started_at) & (AuditLog.ts <= window_end),
    )


@router.get("/{engagement_id}/stream")
async def stream(
    engagement_id: uuid.UUID,
    actions: str | None = Query(default=None, description="Comma-separated audit actions to include"),
    history: bool = Query(default=True, description="Send recent history before following new events"),
    limit: int = Query(default=300, ge=0, le=1000, description="Maximum history rows to send"),
    scan_run_id: uuid.UUID | None = Query(default=None, description="Scope history+live events to one run"),
):
    """SSE audit stream with server-side filtering.

    The UI has two very different consumers: Live Scan needs a lightweight
    operational feed, while Audit may request denser evidence. Filtering and a
    bounded initial history prevent high-volume proxy/tool events from flooding
    the browser. An optional scan_run_id scopes both the initial history and
    the live tail to one run, so an older run's Activity view is not starved
    by a newer run's event volume, and events from a different run never leak
    in (REQ-FIDELITY-002).
    """
    action_set = {a.strip() for a in actions.split(",") if a.strip()} if actions else None
    if scan_run_id is not None:
        with SessionLocal() as _db:
            _validate_run(_db, engagement_id, scan_run_id)

    def serialize(row: AuditLog) -> dict:
        return {
            "ts": row.ts.isoformat(),
            "actor": row.actor,
            "action": row.action,
            "decision": row.decision,
            "reason": row.reason,
            "payload": row.payload,
        }

    async def event_generator():
        last_ts = None if history else dt.datetime.now(dt.timezone.utc)
        first_poll = True
        while True:
            with SessionLocal() as db:
                # Recomputed every poll (not once at connect time): for an
                # active run, _run_scoped_clause's time-window fallback bound
                # is "now", which would otherwise freeze at connection-open
                # time and silently exclude any untagged event created later
                # in the run - i.e. most of a freshly-opened run's activity.
                run_clause = _run_scoped_clause(db, engagement_id, scan_run_id) if scan_run_id is not None else None
                stmt = select(AuditLog).where(AuditLog.engagement_id == engagement_id)
                if action_set:
                    stmt = stmt.where(AuditLog.action.in_(action_set))
                if run_clause is not None:
                    stmt = stmt.where(run_clause)
                if last_ts is not None:
                    stmt = stmt.where(AuditLog.ts > last_ts)
                    rows = db.scalars(stmt.order_by(AuditLog.ts.asc())).all()
                elif first_poll and limit:
                    recent = db.scalars(stmt.order_by(AuditLog.ts.desc()).limit(limit)).all()
                    rows = list(reversed(recent))
                else:
                    rows = db.scalars(stmt.order_by(AuditLog.ts.asc())).all()

                first_poll = False
                for row in rows:
                    last_ts = row.ts
                    yield {"event": "audit_entry", "data": json.dumps(serialize(row))}
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)

    return EventSourceResponse(event_generator())


_DECISIONS = {"ALLOW", "DENY", "PENDING", "THROTTLE"}


# REQ-AUDITUI-003: bounds the IN-list a single request can build. The facet
# endpoint is the only intended source of these values and realistic
# engagements have well under 100 distinct actors/actions, so this only ever
# truncates a hand-crafted request.
_MAX_FACET_FILTER_VALUES = 100


def _facet_values(raw: object) -> list[str]:
    """Normalize a repeatable facet query parameter into a bounded str list.

    A bare string is treated as one value, not as an iterable of characters.
    That keeps the pre-multi-select calling convention (`actor="gateway"`)
    working identically for direct callers - silently returning "no filter"
    for a string would turn a narrowing request into "show everything", which
    is the wrong direction to fail in an audit view.

    Drops empty strings, so a client appending a blank parameter does not
    accidentally filter on `actor = ""` and show an empty log, and tolerates
    anything else (including FastAPI's unset `Query` default) as "no filter".
    """
    if isinstance(raw, str):
        raw = [raw]
    elif not isinstance(raw, (list, tuple)):
        return []
    return [value for value in raw if isinstance(value, str) and value][:_MAX_FACET_FILTER_VALUES]


@router.get("/{engagement_id}/audit")
def list_audit(
    engagement_id: uuid.UUID,
    q: str | None = None,
    actor: list[str] | None = Query(None),
    action: list[str] | None = Query(None),
    decision: str | None = None,
    limit: int = 100,
    before: dt.datetime | None = None,
    db: Session = Depends(get_db),
):
    """REQ-AUDITUI-001: one chronological, searchable projection of this
    engagement's append-only audit log. Read-only - it never mutates the log or
    its hash chain. Newest first, cursor-paginated by timestamp. Auth +
    engagement ownership are enforced by the router this is mounted on.

    Free-text ``q`` matches actor/action/reason/decision and the payload text;
    ``decision`` is ALLOW|DENY|PENDING|THROTTLE; ``before`` is a timestamp
    cursor (return only entries strictly older).

    REQ-AUDITUI-003: ``actor`` and ``action`` are repeatable
    (``?actor=a&actor=b``) and match with ``IN``, so an operator can exclude
    one or two values and keep the rest instead of stepping through them one
    at a time. A single value still behaves exactly as the previous
    equality filter did, so existing callers and saved links keep working."""
    limit = max(1, min(int(limit), 500))
    stmt = select(AuditLog).where(AuditLog.engagement_id == engagement_id)
    actors = _facet_values(actor)
    actions = _facet_values(action)
    if actors:
        stmt = stmt.where(AuditLog.actor.in_(actors))
    if actions:
        stmt = stmt.where(AuditLog.action.in_(actions))
    if decision and decision.upper() in _DECISIONS:
        stmt = stmt.where(AuditLog.decision == decision.upper())
    if before is not None:
        stmt = stmt.where(AuditLog.ts < before)
    if q and q.strip():
        like = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(
                AuditLog.actor.ilike(like),
                AuditLog.action.ilike(like),
                AuditLog.reason.ilike(like),
                AuditLog.decision.ilike(like),
                cast(AuditLog.payload, String).ilike(like),
            )
        )
    rows = db.scalars(stmt.order_by(AuditLog.ts.desc(), AuditLog.id.desc()).limit(limit + 1)).all()
    has_more = len(rows) > limit
    rows = list(rows[:limit])
    return {
        "entries": [
            {
                "id": str(r.id),
                "ts": r.ts.isoformat(),
                "actor": r.actor,
                "action": r.action,
                "decision": r.decision,
                "reason": r.reason,
                "payload": r.payload,
            }
            for r in rows
        ],
        "has_more": has_more,
        "next_before": rows[-1].ts.isoformat() if (rows and has_more) else None,
    }


@router.get("/{engagement_id}/audit/facets")
def audit_facets(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    """REQ-AUDITUI-002: the distinct actor/action values present for this
    engagement, so the log view can offer meaningful filter dropdowns instead
    of a hardcoded taxonomy."""
    actors = db.scalars(
        select(distinct(AuditLog.actor)).where(AuditLog.engagement_id == engagement_id).order_by(AuditLog.actor)
    ).all()
    actions = db.scalars(
        select(distinct(AuditLog.action)).where(AuditLog.engagement_id == engagement_id).order_by(AuditLog.action)
    ).all()
    return {"actors": [a for a in actors if a], "actions": [a for a in actions if a]}
