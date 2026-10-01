"""Hash-verketteter, append-only Audit-Trail (Architektur Kap. 3.4).

row_hash = sha256(prev_hash || canonical_json(row)) macht nachtraegliche
Aenderungen erkennbar - der Nachweis gegenueber Kunde, Bug-Bounty-Betreiber
und Berufshaftpflicht, dass jede Aktion im Scope lag und wann sie
freigegeben wurde.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import NamedTuple

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models.audit import AuditLog


def _canonical_json(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


_TS_STEP = timedelta(microseconds=1)


def _hash_row(prev_hash: str | None, row: dict) -> str:
    return hashlib.sha256(((prev_hash or "") + _canonical_json(row)).encode("utf-8")).hexdigest()


def _append(db: Session, engagement_id: uuid.UUID, entries: list[dict]) -> list[AuditLog]:
    """Chain and insert `entries` (actor/action/decision/reason/payload) in order
    under ONE per-engagement lock and ONE commit.

    Timestamps strictly increase: the predecessor lookup and the live-stream
    cursor (`ts > last_ts`) both order by ts, so two rows must never share one.
    """
    # One transaction-scoped lock per engagement serializes the read of the
    # predecessor and the insert. PostgreSQL releases it on commit/rollback.
    lock_key = int.from_bytes(engagement_id.bytes[:8], "big") & 0x7FFFFFFFFFFFFFFF
    db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_key})
    tail = db.execute(
        select(AuditLog.row_hash, AuditLog.ts)
        .where(AuditLog.engagement_id == engagement_id)
        .order_by(AuditLog.ts.desc(), AuditLog.id.desc())
        .limit(1)
    ).first()
    prev_hash, prev_ts = (tail.row_hash, tail.ts) if tail else (None, None)

    written: list[AuditLog] = []
    for entry in entries:
        ts = datetime.now(timezone.utc)
        if prev_ts is not None and ts <= prev_ts:
            ts = prev_ts + _TS_STEP
        row = {
            "engagement_id": str(engagement_id),
            "actor": entry["actor"],
            "action": entry["action"],
            "decision": entry["decision"],
            "reason": entry["reason"],
            "payload": entry["payload"],
            "ts": ts.isoformat(),
        }
        row_hash = _hash_row(prev_hash, row)
        log = AuditLog(
            engagement_id=engagement_id,
            actor=entry["actor"],
            action=entry["action"],
            decision=entry["decision"],
            reason=entry["reason"],
            payload=entry["payload"],
            prev_hash=prev_hash,
            row_hash=row_hash,
            ts=ts,
        )
        db.add(log)
        written.append(log)
        prev_hash, prev_ts = row_hash, ts
    db.commit()
    return written


def append_audit_log(
    db: Session,
    *,
    engagement_id: uuid.UUID,
    actor: str,
    action: str,
    decision: str | None,
    reason: str | None,
    payload: dict,
) -> AuditLog:
    (entry,) = _append(db, engagement_id, [
        {"actor": actor, "action": action, "decision": decision, "reason": reason, "payload": payload},
    ])
    db.refresh(entry)
    return entry


def append_audit_logs(db: Session, *, engagement_id: uuid.UUID, entries: list[dict]) -> int:
    """GitHub issue #49: many events of one engagement in one lock acquisition and
    one commit (the egress proxy sends 100+ per second). All or nothing: either
    every entry is chained and persisted, or none is and the caller must treat the
    whole batch as unaudited. Each entry needs actor, action, decision, reason, payload."""
    if not entries:
        return 0
    return len(_append(db, engagement_id, entries))


class ChainCheck(NamedTuple):
    ok: bool
    rows: int
    first_bad_row: uuid.UUID | None = None
    problem: str | None = None


def verify_audit_chain(db: Session, engagement_id: uuid.UUID) -> ChainCheck:
    """REQ-AUDIT-002: recompute every row's hash and check each row points at its
    predecessor's hash. Detects a modified, removed, inserted or reordered row."""
    expected_prev: str | None = None
    count = 0
    # Plain columns, not ORM entities: the session's identity map would hand back
    # a row as it was loaded earlier, and an integrity check must see what is
    # stored now.
    rows = db.execute(
        select(
            AuditLog.id, AuditLog.engagement_id, AuditLog.actor, AuditLog.action, AuditLog.decision,
            AuditLog.reason, AuditLog.payload, AuditLog.prev_hash, AuditLog.row_hash, AuditLog.ts,
        )
        .where(AuditLog.engagement_id == engagement_id)
        .order_by(AuditLog.ts.asc(), AuditLog.id.asc())
        .execution_options(yield_per=1000)
    )
    for row in rows:
        count += 1
        if row.prev_hash != expected_prev:
            return ChainCheck(False, count, row.id, "prev_hash does not match the preceding row")
        recomputed = _hash_row(row.prev_hash, {
            "engagement_id": str(row.engagement_id),
            "actor": row.actor,
            "action": row.action,
            "decision": row.decision,
            "reason": row.reason,
            "payload": row.payload,
            "ts": row.ts.astimezone(timezone.utc).isoformat(),
        })
        if recomputed != row.row_hash:
            return ChainCheck(False, count, row.id, "row content does not match its hash")
        expected_prev = row.row_hash
    return ChainCheck(True, count)
