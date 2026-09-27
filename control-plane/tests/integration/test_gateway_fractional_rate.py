"""GitHub issue #19: _rate_retry_after against a real Postgres AuditLog
table - the unit-level _effective_rate_window tests (test_rate_window.py)
prove the window-width formula; this proves the actual gateway rate check
built on top of it denies correctly for a fractional max_rps."""

from __future__ import annotations

import datetime as dt
import uuid

from app.gateway.authorize import _rate_retry_after
from app.models.audit import AuditLog


def _tool_call_row(db, engagement_id, ts):
    row = AuditLog(
        engagement_id=engagement_id, actor="gateway", action="tool_call", decision="ALLOW",
        reason="all_checks_passed", payload={}, prev_hash=None, row_hash=f"test-{uuid.uuid4().hex}",
        ts=ts,
    )
    db.add(row)


def test_negative_one_recent_call_blocks_the_next_for_the_whole_widened_window(db, lab_engagement):
    """max_rps=0.2 -> ceil(1/0.2)=5 second window. A call 3 seconds ago is
    still inside that window and must still block - the old fixed 1-second
    window would have already cleared it."""
    now = dt.datetime.now(dt.timezone.utc)
    _tool_call_row(db, lab_engagement.id, now - dt.timedelta(seconds=3))
    db.commit()

    retry_after = _rate_retry_after(db, lab_engagement.id, max_rps=0.2)

    assert retry_after is not None, "expected the widened window to still be blocking"


def test_a_call_older_than_the_widened_window_no_longer_blocks(db, lab_engagement):
    now = dt.datetime.now(dt.timezone.utc)
    _tool_call_row(db, lab_engagement.id, now - dt.timedelta(seconds=6))  # older than the 5s window
    db.commit()

    retry_after = _rate_retry_after(db, lab_engagement.id, max_rps=0.2)

    assert retry_after is None


def test_no_recent_calls_is_never_blocked_regardless_of_how_small_max_rps_is(db, lab_engagement):
    assert _rate_retry_after(db, lab_engagement.id, max_rps=0.01) is None


def test_rates_at_or_above_one_keep_the_original_fixed_one_second_window(db, lab_engagement):
    now = dt.datetime.now(dt.timezone.utc)
    _tool_call_row(db, lab_engagement.id, now - dt.timedelta(milliseconds=500))
    _tool_call_row(db, lab_engagement.id, now - dt.timedelta(milliseconds=200))
    db.commit()

    # max_rps=2.5 -> threshold=2, both calls inside the 1s window -> blocked
    assert _rate_retry_after(db, lab_engagement.id, max_rps=2.5) is not None
    # a 1.5s-old call is outside the (unchanged) 1-second window for max_rps>=1
    db.query(AuditLog).filter(AuditLog.engagement_id == lab_engagement.id).delete()
    _tool_call_row(db, lab_engagement.id, now - dt.timedelta(seconds=1, milliseconds=500))
    db.commit()
    assert _rate_retry_after(db, lab_engagement.id, max_rps=2.5) is None
