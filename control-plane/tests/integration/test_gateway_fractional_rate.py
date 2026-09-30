"""GitHub issue #19 against the reservation primitive (issue #40, REQ-RATE-005):
the unit tests in test_rate_window.py prove the window-width formula; this
proves the real reservation, on a real Postgres, honours it for a fractional
max_rps."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import select, update

from app.gateway.rate_reservation import reserve
from app.models.rate_reservation import RateReservation


def _age_all(db, engagement_id, seconds: float) -> None:
    """Make every reserved slot look `seconds` older."""
    db.execute(update(RateReservation).where(RateReservation.engagement_id == engagement_id)
               .values(ts=RateReservation.ts - dt.timedelta(seconds=seconds)))
    db.commit()


def test_negative_one_recent_call_blocks_the_next_for_the_whole_widened_window(db, lab_engagement):
    """max_rps=0.2 -> ceil(1/0.2)=5 second window. A call 3 seconds ago is
    still inside that window and must still block - the old fixed 1-second
    window would have already cleared it."""
    assert reserve(db, lab_engagement.id, "gateway", 0.2).allowed
    db.commit()
    _age_all(db, lab_engagement.id, 3)

    second = reserve(db, lab_engagement.id, "gateway", 0.2)

    assert not second.allowed
    assert 0.1 <= second.retry_after_seconds <= 5.0


def test_a_call_older_than_the_widened_window_no_longer_blocks(db, lab_engagement):
    assert reserve(db, lab_engagement.id, "gateway", 0.2).allowed
    db.commit()
    _age_all(db, lab_engagement.id, 6)  # older than the 5s window

    assert reserve(db, lab_engagement.id, "gateway", 0.2).allowed


def test_the_first_call_is_never_blocked_regardless_of_how_small_max_rps_is(db, lab_engagement):
    assert reserve(db, lab_engagement.id, "gateway", 0.01).allowed


def test_rates_at_or_above_one_keep_the_original_fixed_one_second_window(db, lab_engagement):
    # max_rps=2.5 -> threshold 2 inside 1 second
    assert reserve(db, lab_engagement.id, "gateway", 2.5).allowed
    assert reserve(db, lab_engagement.id, "gateway", 2.5).allowed
    assert not reserve(db, lab_engagement.id, "gateway", 2.5).allowed
    db.commit()
    # 1.5s later both slots are outside the (unchanged) 1-second window
    _age_all(db, lab_engagement.id, 1.5)
    assert reserve(db, lab_engagement.id, "gateway", 2.5).allowed


def test_a_refused_call_reserves_nothing(db, lab_engagement):
    assert reserve(db, lab_engagement.id, "gateway", 0.2).allowed
    assert not reserve(db, lab_engagement.id, "gateway", 0.2).allowed
    db.commit()
    rows = db.scalars(select(RateReservation).where(RateReservation.engagement_id == lab_engagement.id)).all()
    assert len(rows) == 1
