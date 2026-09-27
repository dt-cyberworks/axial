"""GitHub issue #18: starting a scan was a check-then-insert race with no
lock and no database invariant - concurrent requests could both pass the
"no active run" check and both insert a running row. These tests exercise
GENUINE concurrency (real threads, each with its own DB session/transaction
against the same Postgres) rather than sequential calls, since the bug only
manifests when two transactions overlap."""

from __future__ import annotations

import datetime as dt
import threading

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker

from app.api.internal import create_scan_run
from app.models.engagement import Engagement
from app.models.scan_run import ScanRun
from app.scan_lifecycle import ScanRunAlreadyActive, start_scan_run
from app.schemas.internal import ScanRunCreate


def _engagement(db) -> Engagement:
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        title="Scan-start race test", source="lab", status="active",
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
    )
    db.add(eng)
    db.commit()
    db.refresh(eng)
    return eng


def _run_concurrently(engine, n: int, call):
    """Run `call(session)` in `n` threads, each with its OWN session on the
    real engine, released to fire together via a barrier so their
    transactions genuinely overlap (not a sequential simulation)."""
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)
    barrier = threading.Barrier(n)
    results: list[tuple[bool, object]] = [None] * n  # type: ignore[list-item]

    def worker(index: int) -> None:
        session = SessionLocal()
        try:
            barrier.wait(timeout=10)
            try:
                value = call(session)
                results[index] = (True, value)
            except Exception as exc:  # noqa: BLE001 - captured, asserted below
                results[index] = (False, exc)
        finally:
            session.rollback()
            session.close()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    return results


def test_concurrent_start_scan_run_produces_exactly_one_active_row(db, engine):
    """Acceptance criterion: N concurrent scan-start attempts for one
    engagement produce exactly one active scan_run and N-1 denials."""
    eng = _engagement(db)
    n = 8

    def attempt(session):
        # Return the plain id, not the ORM instance - the instance would be
        # detached (and, since this harness rolls back/closes each thread's
        # session in `finally`, expired) by the time the main thread inspects it.
        return start_scan_run(session, eng.id).id

    results = _run_concurrently(engine, n, attempt)

    successes = [r for ok, r in results if ok]
    failures = [r for ok, r in results if not ok]
    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}: {results}"
    assert len(failures) == n - 1
    assert all(isinstance(exc, ScanRunAlreadyActive) for exc in failures)

    active = db.query(ScanRun).filter(
        ScanRun.engagement_id == eng.id, ScanRun.state.in_(["running", "waiting_approval"]),
    ).all()
    assert len(active) == 1
    assert active[0].id == successes[0]


def test_concurrent_create_scan_run_internal_calls_produce_one_row_and_clean_409s(db, engine):
    """Acceptance criterion: two concurrent create_scan_run internal calls
    produce one row and one 409 - not an unhandled IntegrityError 500."""
    eng = _engagement(db)
    n = 5

    def attempt(session):
        return create_scan_run(eng.id, ScanRunCreate(), session)

    results = _run_concurrently(engine, n, attempt)

    successes = [r for ok, r in results if ok]
    failures = [r for ok, r in results if not ok]
    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}: {results}"
    assert len(failures) == n - 1
    for exc in failures:
        assert isinstance(exc, HTTPException), f"expected a clean HTTPException, got {type(exc)}: {exc}"
        assert exc.status_code == 409

    active = db.query(ScanRun).filter(
        ScanRun.engagement_id == eng.id, ScanRun.state.in_(["running", "waiting_approval"]),
    ).all()
    assert len(active) == 1


def test_the_unique_index_itself_rejects_a_second_active_row(db):
    """Direct proof the database invariant exists and is not merely an
    application-level convention - a raw second insert (bypassing
    start_scan_run's own SELECT fast-path entirely) still fails."""
    from sqlalchemy.exc import IntegrityError

    eng = _engagement(db)
    db.add(ScanRun(engagement_id=eng.id, phase="discovery", state="running"))
    db.commit()

    db.add(ScanRun(engagement_id=eng.id, phase="discovery", state="waiting_approval"))
    with pytest.raises(IntegrityError, match="uq_scan_run_one_active_per_engagement"):
        db.commit()
    db.rollback()


def test_a_terminal_run_does_not_block_a_new_active_one(db):
    """Regression guard: the index is a PARTIAL index (only running/
    waiting_approval) - a done/failed/aborted run for the same engagement
    must never block starting a new one."""
    eng = _engagement(db)
    for state in ("done", "failed", "aborted"):
        db.add(ScanRun(engagement_id=eng.id, phase="report", state=state))
    db.commit()

    run = start_scan_run(db, eng.id)  # must not raise
    assert run.state == "running"
