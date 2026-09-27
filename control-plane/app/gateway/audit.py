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
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models.audit import AuditLog


def _canonical_json(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


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
    # One transaction-scoped lock per engagement serializes the read of the
    # predecessor and the insert. PostgreSQL releases it on commit/rollback.
    lock_key = int.from_bytes(engagement_id.bytes[:8], "big") & 0x7FFFFFFFFFFFFFFF
    db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_key})
    prev_hash = db.scalar(
        select(AuditLog.row_hash)
        .where(AuditLog.engagement_id == engagement_id)
        .order_by(AuditLog.ts.desc())
        .limit(1)
    )
    ts = datetime.now(timezone.utc)
    row = {
        "engagement_id": str(engagement_id),
        "actor": actor,
        "action": action,
        "decision": decision,
        "reason": reason,
        "payload": payload,
        "ts": ts.isoformat(),
    }
    row_hash = hashlib.sha256(((prev_hash or "") + _canonical_json(row)).encode("utf-8")).hexdigest()

    entry = AuditLog(
        engagement_id=engagement_id,
        actor=actor,
        action=action,
        decision=decision,
        reason=reason,
        payload=payload,
        prev_hash=prev_hash,
        row_hash=row_hash,
        ts=ts,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
