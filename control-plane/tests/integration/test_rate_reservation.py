"""REQ-RATE-005 (GitHub issue #40): a rate slot is reserved, atomically,
before the call goes ahead.

Every concurrency test releases all callers at the same instant through a
barrier, each with its own database session (like separate workers), so a
count-then-act race would show up as more slots granted than the limit.
"""

from __future__ import annotations

import datetime as dt
import threading

from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from tests.integration.owners import make_owner
from app.api.internal import reserve_proxy_rate_slot
from app.gateway.authorize import ToolCall, authorize
from app.gateway.rate_reservation import reserve
from app.models.audit import AuditLog
from app.models.engagement import BountyProgram, ToolGrant
from app.models.rate_reservation import RateReservation
from app.models.scan_run import ScanRun
from app.settings_store import set_scan_policy

CALLERS = 12


def _concurrently(engine, work):
    """Run work(session) in CALLERS threads that all start together."""
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)
    barrier = threading.Barrier(CALLERS)
    results, errors = [], []

    def run():
        session = SessionLocal()
        try:
            barrier.wait(timeout=10)
            results.append(work(session))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            session.close()

    threads = [threading.Thread(target=run) for _ in range(CALLERS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not errors, errors
    assert len(results) == CALLERS
    return results


def _count(db, engagement_id, path) -> int:
    db.expire_all()
    return db.scalar(select(func.count()).select_from(RateReservation).where(
        RateReservation.engagement_id == engagement_id, RateReservation.path == path))


def _call(engagement_id, scan_run_id=None) -> ToolCall:
    return ToolCall(engagement_id=engagement_id, tool="httpx", category="fingerprint", mode="active",
                    target="metasploitable2", args={}, scan_run_id=scan_run_id)


def _bounty(db, engagement_id, max_rps: float) -> None:
    db.add(BountyProgram(engagement_id=engagement_id, platform="test", program_ref="p",
                         automation_allowed=True, ai_testing_allowed=False, max_rps=max_rps, max_concurrency=2))
    db.commit()


# --- the guarantee: concurrent callers never exceed the limit -----------------------

def test_negative_concurrent_reservations_never_exceed_the_limit(engine, db, lab_engagement):
    def work(session):
        slot = reserve(session, lab_engagement.id, "gateway", 0.2)  # 1 slot per 5 s
        session.commit()
        return slot.allowed

    granted = sum(_concurrently(engine, work))

    assert granted == 1
    assert _count(db, lab_engagement.id, "gateway") == 1


def test_negative_concurrent_reservations_at_several_per_second_stay_within_the_threshold(engine, db, lab_engagement):
    def work(session):
        slot = reserve(session, lab_engagement.id, "gateway", 3)
        session.commit()
        return slot.allowed

    granted = sum(_concurrently(engine, work))

    assert 1 <= granted <= 3  # never more than the threshold, even if the window rolls over
    assert _count(db, lab_engagement.id, "gateway") == granted


def test_negative_concurrent_gateway_calls_never_exceed_the_limit(engine, db, lab_engagement):
    set_scan_policy(db, max_rps=0.2, auto_throttle_enabled=False)

    decisions = _concurrently(engine, lambda session: authorize(session, _call(lab_engagement.id)))

    assert sum(1 for d in decisions if d.allowed) == 1
    assert {d.reason for d in decisions if not d.allowed} == {"rate_limited"}
    db.expire_all()
    allowed_rows = db.scalar(select(func.count()).select_from(AuditLog).where(
        AuditLog.engagement_id == lab_engagement.id, AuditLog.decision == "ALLOW"))
    assert allowed_rows == 1


def test_negative_concurrent_gateway_calls_get_a_wait_when_auto_slow_down_is_on(engine, db, lab_engagement):
    set_scan_policy(db, max_rps=0.2, auto_throttle_enabled=True)

    decisions = _concurrently(engine, lambda session: authorize(session, _call(lab_engagement.id)))

    assert sum(1 for d in decisions if d.allowed) == 1
    waiting = [d for d in decisions if not d.allowed]
    assert {d.reason for d in waiting} == {"rate_limited_wait"}
    assert all(d.is_throttled and 0.1 <= d.retry_after_seconds <= 5.0 for d in waiting)


def test_negative_concurrent_proxy_reservations_never_exceed_the_limit(engine, db, lab_engagement):
    _bounty(db, lab_engagement.id, 0.2)

    def work(session):
        return reserve_proxy_rate_slot(lab_engagement.id, db=session)["allowed"]

    assert sum(_concurrently(engine, work)) == 1
    assert _count(db, lab_engagement.id, "proxy") == 1


# --- separation --------------------------------------------------------------------

def test_the_gateway_and_the_proxy_have_their_own_counter(db, lab_engagement):
    assert reserve(db, lab_engagement.id, "gateway", 0.2).allowed
    assert reserve(db, lab_engagement.id, "proxy", 0.2).allowed
    assert not reserve(db, lab_engagement.id, "gateway", 0.2).allowed
    assert not reserve(db, lab_engagement.id, "proxy", 0.2).allowed


def test_engagements_are_counted_separately(db, lab_engagement):
    from app.models.engagement import Engagement
    now = dt.datetime.now(dt.timezone.utc)
    other = Engagement(owner_user_id=make_owner(db).id, title="Other", source="lab", status="active",
                       authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1))
    db.add(other)
    db.flush()
    assert reserve(db, lab_engagement.id, "gateway", 0.2).allowed
    assert reserve(db, other.id, "gateway", 0.2).allowed


def test_slots_older_than_the_retention_are_pruned(db, lab_engagement):
    assert reserve(db, lab_engagement.id, "gateway", 5).allowed
    db.execute(RateReservation.__table__.update().values(ts=dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)))
    db.commit()
    assert reserve(db, lab_engagement.id, "gateway", 5).allowed
    db.commit()
    assert _count(db, lab_engagement.id, "gateway") == 1  # only the new one is left


# --- a call that does not go ahead gives its slot back --------------------------------

def test_an_allowed_call_keeps_its_slot(db, lab_engagement):
    set_scan_policy(db, max_rps=5, auto_throttle_enabled=False)
    assert authorize(db, _call(lab_engagement.id)).allowed
    assert _count(db, lab_engagement.id, "gateway") == 1


def test_negative_a_call_that_hits_the_budget_gives_its_slot_back(db, lab_engagement):
    set_scan_policy(db, max_rps=5, auto_throttle_enabled=False)
    run = ScanRun(engagement_id=lab_engagement.id, phase="agent", state="running",
                  budget_tool_calls_max=0, budget_tool_calls_used=0)
    db.add(run)
    db.commit()

    decision = authorize(db, _call(lab_engagement.id, scan_run_id=run.id))

    assert decision.reason == "budget_exhausted"
    assert _count(db, lab_engagement.id, "gateway") == 0


def test_negative_a_call_that_waits_for_approval_gives_its_slot_back(db, lab_engagement):
    set_scan_policy(db, max_rps=5, auto_throttle_enabled=False)
    for grant in db.scalars(select(ToolGrant).where(ToolGrant.engagement_id == lab_engagement.id,
                                                    ToolGrant.mode == "active")):
        grant.requires_manual_approval = True
    db.commit()

    decision = authorize(db, _call(lab_engagement.id))

    assert decision.is_pending
    assert _count(db, lab_engagement.id, "gateway") == 0


def test_negative_a_denied_call_does_not_reserve_a_slot(db, lab_engagement):
    decision = authorize(db, ToolCall(engagement_id=lab_engagement.id, tool="httpx", category="fingerprint",
                                      mode="active", target="clean-nginx", args={}))  # explicit deny rule
    assert not decision.allowed
    assert _count(db, lab_engagement.id, "gateway") == 0


# --- the proxy endpoint ------------------------------------------------------------

def test_negative_the_proxy_endpoint_refuses_without_a_bounty_program(db, lab_engagement):
    answer = reserve_proxy_rate_slot(lab_engagement.id, db=db)
    assert answer["allowed"] is False
    assert answer["reason"] == "bounty_program_missing"
    assert _count(db, lab_engagement.id, "proxy") == 0


def test_the_proxy_endpoint_takes_the_limit_from_the_program(db, lab_engagement):
    _bounty(db, lab_engagement.id, 0.2)
    first = reserve_proxy_rate_slot(lab_engagement.id, db=db)
    second = reserve_proxy_rate_slot(lab_engagement.id, db=db)
    assert first["allowed"] is True and first["retry_after_seconds"] is None
    assert second["allowed"] is False and second["reason"] == "rate_limited"
    assert 0.1 <= second["retry_after_seconds"] <= 5.0
