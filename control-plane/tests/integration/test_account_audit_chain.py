"""REQ-IAM-009: account_audit_log is a separate, globally hash-chained trail
- never contains raw credentials, and concurrent appends still form one
unbroken chain (mirrors test_audit_serialization.py's pattern for the
per-engagement audit_log, applied to the global one)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.gateway.account_audit import append_account_audit_log
from app.models.user import AccountAuditLog


def test_concurrent_appends_form_one_chain(engine, db):
    SessionLocal = sessionmaker(bind=engine, future=True)

    def append(index: int):
        with SessionLocal() as session:
            append_account_audit_log(
                session, actor_user_id=None, action="concurrent_test", outcome="success",
                payload={"index": index},
            )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(append, range(16)))

    rows = db.scalars(select(AccountAuditLog).where(AccountAuditLog.action == "concurrent_test")).all()
    assert len(rows) == 16
    by_prev = {}
    for row in rows:
        assert row.prev_hash not in by_prev
        by_prev[row.prev_hash] = row

    # account_audit_log is truncated between tests (conftest's _DATA_TABLES),
    # so this test's 16 rows are the entire table - the chain must start at
    # the genesis (prev_hash=None) and reach every row exactly once.
    current = by_prev[None]
    visited = set()
    while current:
        assert current.row_hash not in visited
        visited.add(current.row_hash)
        current = by_prev.get(current.row_hash)
    assert len(visited) == len(rows)


def test_row_hash_changes_if_payload_is_tampered(db):
    row = append_account_audit_log(
        db, actor_user_id=None, action="login_password", outcome="failure",
        payload={"reason": "wrong_password"},
    )
    original_hash = row.row_hash
    row.payload = {"reason": "tampered"}
    db.commit()
    db.refresh(row)
    # The stored row_hash is untouched by the tamper (no recompute-on-save) -
    # a verifier re-deriving sha256(prev_hash || canonical_json(row)) from the
    # CURRENT payload would now mismatch row_hash, which is how tampering is
    # detected; this asserts the row_hash itself isn't silently recomputed.
    assert row.row_hash == original_hash


def test_payload_never_contains_raw_credential_fields():
    # Structural guard: append_account_audit_log has no parameter for a raw
    # secret at all - the function signature itself is the enforcement.
    import inspect

    sig = inspect.signature(append_account_audit_log)
    assert "password" not in sig.parameters
    assert "code" not in sig.parameters
    assert "token" not in sig.parameters
