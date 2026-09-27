from concurrent.futures import ThreadPoolExecutor
import hashlib
import json

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.gateway.audit import append_audit_log
from app.models.audit import AuditLog


def test_concurrent_appends_form_one_chain(engine, db, lab_engagement):
    engagement_id = lab_engagement.id
    SessionLocal = sessionmaker(bind=engine, future=True)

    def append(index: int):
        with SessionLocal() as session:
            append_audit_log(
                session,
                engagement_id=engagement_id,
                actor="test",
                action="concurrent",
                decision="ALLOW",
                reason=str(index),
                payload={"index": index},
            )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(append, range(16)))

    rows = db.scalars(select(AuditLog).where(AuditLog.engagement_id == engagement_id)).all()
    assert len(rows) == 16
    by_prev = {}
    for row in rows:
        assert row.prev_hash not in by_prev
        by_prev[row.prev_hash] = row

    current = by_prev[None]
    visited = set()
    while current:
        assert current.row_hash not in visited
        visited.add(current.row_hash)
        current = by_prev.get(current.row_hash)
    assert len(visited) == len(rows)

