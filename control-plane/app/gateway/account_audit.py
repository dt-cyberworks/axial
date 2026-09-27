"""Hash-verketteter, append-only Account-/Security-Audit-Trail (REQ-IAM-009).

Spiegelt app/gateway/audit.py's row_hash = sha256(prev_hash || canonical_json(row))
Konstruktion exakt, aber mit EINER globalen Kette statt einer Kette pro
Engagement - Login/MFA/Session/Admin-Ereignisse haben kein Engagement und
duerfen die per-Engagement-Rechtsbeweiskette (audit_log) nicht verwaessern
oder umbauen. append_audit_log selbst bleibt unveraendert.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models.user import AccountAuditLog

# Fester Advisory-Lock-Key: EINE globale Kette, kein Engagement zum Ableiten.
_LOCK_KEY = 0x4143434F554E5441  # "ACCOUNTA" als Hex-Konstante, beliebig aber stabil


def _canonical_json(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def append_account_audit_log(
    db: Session,
    *,
    actor_user_id: uuid.UUID | None,
    action: str,
    outcome: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
    payload: dict | None = None,
) -> AccountAuditLog:
    db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _LOCK_KEY})
    prev_hash = db.scalar(
        select(AccountAuditLog.row_hash).order_by(AccountAuditLog.ts.desc()).limit(1)
    )
    ts = datetime.now(timezone.utc)
    row = {
        "actor_user_id": str(actor_user_id) if actor_user_id else None,
        "action": action,
        "outcome": outcome,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "payload": payload or {},
        "ts": ts.isoformat(),
    }
    row_hash = hashlib.sha256(((prev_hash or "") + _canonical_json(row)).encode("utf-8")).hexdigest()

    entry = AccountAuditLog(
        actor_user_id=actor_user_id,
        action=action,
        outcome=outcome,
        ip_address=ip_address,
        user_agent=user_agent,
        payload=payload or {},
        prev_hash=prev_hash,
        row_hash=row_hash,
        ts=ts,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
