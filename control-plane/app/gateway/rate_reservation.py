"""GitHub issue #40 (REQ-RATE-005): reserve a rate-limit slot before acting.

The gateway and the egress proxy used to count recent ALLOW rows in the audit
log and then decide, with nothing reserved in between: concurrent callers
could all read the same count and all proceed. Here a caller takes a
transaction-scoped advisory lock for (engagement, path), counts the slots
reserved in the window, and inserts its own slot before the lock is released
on commit. The audit log stays the record of what happened; it is not the
counter any more.

The gateway calls this in-process (its own transaction commits with the audit
entry); the egress proxy, which is read-only on the database by design, calls
it through POST /internal/engagements/{id}/rate-reservation. Each path has its
own counter, and both use the same window and threshold, so identical inputs
give identical verdicts.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import math
import uuid
from dataclasses import dataclass

from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session

from app.models.rate_reservation import RateReservation

PATHS = ("gateway", "proxy")
_RETENTION = dt.timedelta(hours=1)
_MAX_RETRY_AFTER_SECONDS = 5.0


def effective_rate_window(max_rps: float) -> float:
    """GitHub issue #19: a fixed 1-second window cannot express "less than 1
    request per second" - any positive integer threshold within 1 second still
    permits at least 1 req/s. Below 1 rps the window widens to ceil(1/max_rps)
    seconds with a threshold of 1, i.e. "no reserved slot in the last N
    seconds"."""
    return 1.0 if max_rps >= 1 else float(math.ceil(1.0 / max_rps))


def _threshold(max_rps: float) -> int:
    return max(1, int(max_rps))


def _lock_key(engagement_id: uuid.UUID, path: str) -> int:
    # Distinct from the audit log's per-engagement lock key (gateway/audit.py):
    # callers take this lock first and the audit lock second, never the reverse.
    digest = hashlib.sha256(f"rate-reservation:{path}:{engagement_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big") & 0x7FFF_FFFF_FFFF_FFFF


@dataclass
class Reservation:
    allowed: bool
    retry_after_seconds: float | None = None
    reservation_id: int | None = None


def reserve(db: Session, engagement_id: uuid.UUID, path: str, max_rps: float) -> Reservation:
    """Reserve one slot, or say how long to wait. The caller commits: until
    then the lock is held, so no other caller can count past this slot."""
    if path not in PATHS:
        raise ValueError(f"unknown rate path {path!r}")
    window = effective_rate_window(max_rps)
    db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _lock_key(engagement_id, path)})
    # The database clock, so every process agrees on "now".
    now = db.scalar(text("SELECT clock_timestamp()"))
    db.execute(delete(RateReservation).where(
        RateReservation.engagement_id == engagement_id, RateReservation.path == path,
        RateReservation.ts < now - _RETENTION,
    ))
    window_start = now - dt.timedelta(seconds=window)
    in_window = db.scalars(
        select(RateReservation.ts).where(
            RateReservation.engagement_id == engagement_id, RateReservation.path == path,
            RateReservation.ts >= window_start,
        ).order_by(RateReservation.ts.asc())
    ).all()
    if len(in_window) >= _threshold(max_rps):
        retry_at = in_window[0] + dt.timedelta(seconds=window)
        retry_after = max(0.1, min((retry_at - now).total_seconds() + 0.05, _MAX_RETRY_AFTER_SECONDS))
        return Reservation(allowed=False, retry_after_seconds=retry_after)
    slot = RateReservation(engagement_id=engagement_id, path=path, ts=now)
    db.add(slot)
    db.flush()
    return Reservation(allowed=True, reservation_id=slot.id)


def release(db: Session, reservation: Reservation | None) -> None:
    """Give a slot back before commit when the call ends up not going ahead
    (for example it now waits for approval), so it does not use up the rate."""
    if reservation is not None and reservation.reservation_id is not None:
        db.execute(delete(RateReservation).where(RateReservation.id == reservation.reservation_id))
        db.flush()
        reservation.reservation_id = None
