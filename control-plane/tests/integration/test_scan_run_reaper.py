"""TC-RAWLEASE-001: verwaiste Laeufe werden geerntet, lebendige nicht.

Prueft reap_stale_runs + den Heartbeat-Endpunkt: ein running-Lauf mit veraltetem
heartbeat_at wird auf 'aborted' gesetzt (entblockt neue Scans), ein Lauf mit
frischem Heartbeat bleibt unangetastet und blockiert weiterhin.
"""

from __future__ import annotations

import datetime as dt

import uuid as uuid_module

from tests.integration.owners import make_owner
from app.api.internal import create_scan_run, heartbeat_scan_run, internal_reap_all_stale_runs
from app.models.engagement import Engagement
from app.models.scan_run import ScanRun
from app.scan_lifecycle import reap_all_stale_runs, reap_stale_runs
from app.schemas.internal import ScanRunCreate


def _second_engagement(db) -> Engagement:
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        owner_user_id=make_owner(db).id,
        title=f"Reaper test {uuid_module.uuid4().hex[:8]}", source="lab", status="active",
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
    )
    db.add(eng)
    db.commit()
    db.refresh(eng)
    return eng


def _run(db, eng_id, *, heartbeat_age_seconds: int, state: str = "running") -> ScanRun:
    now = dt.datetime.now(dt.timezone.utc)
    run = ScanRun(
        engagement_id=eng_id, phase="fingerprint", state=state,
        started_at=now - dt.timedelta(seconds=heartbeat_age_seconds + 10),
        heartbeat_at=now - dt.timedelta(seconds=heartbeat_age_seconds),
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def test_reaps_stale_run_but_not_fresh(db, lab_engagement):
    """GitHub issue #18: only one running/waiting_approval scan_run per
    engagement is now a real database invariant
    (uq_scan_run_one_active_per_engagement) - the stale and fresh runs can no
    longer coexist as two active rows on ONE engagement (exactly what that
    invariant now prevents), so this uses two engagements instead. The
    reaping logic itself (heartbeat_at < cutoff, scoped by engagement_id) is
    unchanged and equally well proven this way."""
    other = _second_engagement(db)
    stale = _run(db, lab_engagement.id, heartbeat_age_seconds=10_000)   # weit ueber stale_run_seconds
    fresh = _run(db, other.id, heartbeat_age_seconds=1)

    reaped_lab = reap_stale_runs(db, lab_engagement.id)
    reaped_other = reap_stale_runs(db, other.id)

    db.refresh(stale)
    db.refresh(fresh)
    assert reaped_lab == 1
    assert reaped_other == 0
    assert stale.state == "aborted"
    assert stale.state_reason == "reaped_stale_heartbeat"
    assert stale.finished_at is not None
    assert fresh.state == "running"          # frischer Heartbeat -> unangetastet


def test_stale_run_no_longer_blocks_new_run(db, lab_engagement):
    _run(db, lab_engagement.id, heartbeat_age_seconds=10_000)
    # Vorher: der aktive Lauf wuerde 409 ausloesen. Der Reaper (in create_scan_run)
    # erntet ihn zuerst, sodass ein neuer Lauf entstehen kann.
    new = create_scan_run(lab_engagement.id, ScanRunCreate(), db)
    assert new.state == "running"
    active = [r for r in db.query(ScanRun).filter(ScanRun.engagement_id == lab_engagement.id)
              if r.state in ("running", "waiting_approval")]
    assert len(active) == 1 and active[0].id == new.id


def test_fresh_run_still_blocks_new_run(db, lab_engagement):
    _run(db, lab_engagement.id, heartbeat_age_seconds=1)
    try:
        create_scan_run(lab_engagement.id, ScanRunCreate(), db)
        assert False, "expected 409 for an active fresh run"
    except Exception as exc:  # HTTPException(409)
        assert "409" in str(getattr(exc, "status_code", "")) or getattr(exc, "status_code", None) == 409


def test_heartbeat_endpoint_refreshes_and_unstales(db, lab_engagement):
    run = _run(db, lab_engagement.id, heartbeat_age_seconds=10_000)
    heartbeat_scan_run(run.id, db)               # frisches Lebenszeichen
    db.refresh(run)
    # Jetzt frisch -> Reaper laesst ihn in Ruhe
    assert reap_stale_runs(db, lab_engagement.id) == 0
    assert run.state == "running"


# --- GitHub issue #29: periodic (all-engagement) reaping, independent of ---
# any inbound request scoped to one specific engagement.

def test_reap_all_stale_runs_reaps_across_every_engagement(db, lab_engagement):
    other = _second_engagement(db)
    stale_a = _run(db, lab_engagement.id, heartbeat_age_seconds=10_000)
    stale_b = _run(db, other.id, heartbeat_age_seconds=10_000)

    reaped = reap_all_stale_runs(db)

    db.refresh(stale_a)
    db.refresh(stale_b)
    assert reaped == 2
    assert stale_a.state == "aborted" and stale_a.state_reason == "reaped_stale_heartbeat"
    assert stale_b.state == "aborted" and stale_b.state_reason == "reaped_stale_heartbeat"


def test_reap_all_stale_runs_leaves_fresh_runs_alone(db, lab_engagement):
    other = _second_engagement(db)
    fresh = _run(db, lab_engagement.id, heartbeat_age_seconds=1)
    stale = _run(db, other.id, heartbeat_age_seconds=10_000)

    reaped = reap_all_stale_runs(db)

    db.refresh(fresh)
    db.refresh(stale)
    assert reaped == 1
    assert fresh.state == "running"
    assert stale.state == "aborted"


def test_internal_reap_stale_endpoint_returns_the_count(db, lab_engagement):
    _run(db, lab_engagement.id, heartbeat_age_seconds=10_000)
    _run(db, _second_engagement(db).id, heartbeat_age_seconds=10_000)
    assert internal_reap_all_stale_runs(db) == {"reaped": 2}
    # Idempotent: nothing left to reap on a second call.
    assert internal_reap_all_stale_runs(db) == {"reaped": 0}
