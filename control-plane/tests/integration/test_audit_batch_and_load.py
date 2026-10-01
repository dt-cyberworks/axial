"""TC-PIPE-019/020 (GitHub issue #49): the egress proxy's audit events are written
in batches under one lock, the hash chain verifies after every kind of write, and
a flood of them can neither starve the control plane's small pool nor block a
cancel check."""

from __future__ import annotations

import datetime as dt
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from app.api import internal
from app.api.internal import (
    internal_proxy_audit, internal_proxy_audit_batch, reserve_proxy_rate_slot, scan_run_cancel_requested,
)
from app.config import get_settings
from app.gateway.audit import append_audit_log, append_audit_logs, verify_audit_chain
from app.models.audit import AuditLog
from app.models.scan_run import ScanRun
from app.schemas.internal import ProxyAuditBatchIn, ProxyAuditEventIn


def _entries(n: int, tag: str = "b") -> list[dict]:
    return [
        {"actor": "egress-proxy", "action": "network_request", "decision": "ALLOW",
         "reason": "in_scope", "payload": {"tag": tag, "i": i}}
        for i in range(n)
    ]


def _rows(db, eng_id):
    db.expire_all()
    return db.scalars(
        select(AuditLog).where(AuditLog.engagement_id == eng_id).order_by(AuditLog.ts, AuditLog.id)
    ).all()


# --- the batch write -------------------------------------------------------------

def test_a_batch_is_one_verifiable_chain_with_strictly_increasing_timestamps(db, lab_engagement):
    assert append_audit_logs(db, engagement_id=lab_engagement.id, entries=_entries(50)) == 50
    rows = _rows(db, lab_engagement.id)
    assert len(rows) == 50
    assert rows[0].prev_hash is None
    for previous, row in zip(rows, rows[1:]):
        assert row.prev_hash == previous.row_hash
        assert row.ts > previous.ts, "two audit rows must never share a timestamp"
    check = verify_audit_chain(db, lab_engagement.id)
    assert check.ok and check.rows == 50


def test_a_batch_continues_the_existing_chain(db, lab_engagement):
    append_audit_log(db, engagement_id=lab_engagement.id, actor="gateway", action="tool_call",
                     decision="ALLOW", reason="ok", payload={"x": 1})
    append_audit_logs(db, engagement_id=lab_engagement.id, entries=_entries(5))
    append_audit_log(db, engagement_id=lab_engagement.id, actor="gateway", action="tool_call",
                     decision="DENY", reason="no", payload={})
    assert verify_audit_chain(db, lab_engagement.id).ok


def test_an_empty_batch_writes_nothing(db, lab_engagement):
    assert append_audit_logs(db, engagement_id=lab_engagement.id, entries=[]) == 0
    assert _rows(db, lab_engagement.id) == []


def test_negative_a_batch_is_all_or_nothing(db, lab_engagement):
    bad = _entries(3) + [{"actor": "egress-proxy"}]  # the last entry is malformed
    with pytest.raises(KeyError):
        append_audit_logs(db, engagement_id=lab_engagement.id, entries=bad)
    db.rollback()
    assert _rows(db, lab_engagement.id) == [], "a failed batch must leave no part of itself behind"


def test_concurrent_single_and_batch_writers_form_one_chain(engine, db, lab_engagement):
    eid = lab_engagement.id
    Session = sessionmaker(bind=engine, future=True)

    def single(i: int):
        with Session() as s:
            append_audit_log(s, engagement_id=eid, actor="gateway", action="tool_call",
                             decision="ALLOW", reason=str(i), payload={"single": i})

    def batch(i: int):
        with Session() as s:
            append_audit_logs(s, engagement_id=eid, entries=_entries(10, tag=f"batch{i}"))

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(single, i) for i in range(12)] + [pool.submit(batch, i) for i in range(6)]
        for f in futures:
            f.result()
    check = verify_audit_chain(db, eid)
    assert check.ok, check
    assert check.rows == 12 + 60


# --- the verifier (REQ-AUDIT-002) ------------------------------------------------

def _seed(db, eng_id, n=6):
    append_audit_logs(db, engagement_id=eng_id, entries=_entries(n))
    return _rows(db, eng_id)


def test_negative_verify_detects_a_modified_row(engine, db, lab_engagement):
    rows = _seed(db, lab_engagement.id)
    with engine.begin() as conn:
        conn.execute(text("UPDATE audit_log SET reason='tampered' WHERE id=:id"), {"id": rows[2].id})
    check = verify_audit_chain(db, lab_engagement.id)
    assert not check.ok and check.first_bad_row == rows[2].id


def test_negative_verify_detects_a_removed_row(engine, db, lab_engagement):
    rows = _seed(db, lab_engagement.id)
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM audit_log WHERE id=:id"), {"id": rows[3].id})
    check = verify_audit_chain(db, lab_engagement.id)
    assert not check.ok and check.first_bad_row == rows[4].id


def test_negative_verify_detects_an_inserted_row(engine, db, lab_engagement):
    rows = _seed(db, lab_engagement.id)
    forged_ts = rows[2].ts + (rows[3].ts - rows[2].ts) / 2
    with engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO audit_log (engagement_id, actor, action, decision, reason, payload, prev_hash, row_hash, ts)"
            " VALUES (:e, 'forger', 'x', 'ALLOW', 'x', '{}'::jsonb, :p, :h, :ts)"),
            {"e": lab_engagement.id, "p": rows[2].row_hash, "h": "f" * 64, "ts": forged_ts})
    assert not verify_audit_chain(db, lab_engagement.id).ok


def test_negative_verify_detects_reordered_rows(engine, db, lab_engagement):
    rows = _seed(db, lab_engagement.id)
    with engine.begin() as conn:
        conn.execute(text("UPDATE audit_log SET ts=:t WHERE id=:id"), {"t": rows[4].ts, "id": rows[1].id})
        conn.execute(text("UPDATE audit_log SET ts=:t WHERE id=:id"), {"t": rows[1].ts, "id": rows[4].id})
    assert not verify_audit_chain(db, lab_engagement.id).ok


def test_verify_accepts_an_engagement_with_no_rows(db, lab_engagement):
    check = verify_audit_chain(db, lab_engagement.id)
    assert check.ok and check.rows == 0


# --- the endpoints ---------------------------------------------------------------

def test_the_batch_endpoint_stores_bounded_events_with_the_proxy_as_actor(db, lab_engagement):
    events = [ProxyAuditEventIn(decision="ALLOW", reason="r" * 300, payload={"k" * 100: "v" * 900})] * 3
    out = internal_proxy_audit_batch(lab_engagement.id, ProxyAuditBatchIn(events=events), db)
    assert out == {"ok": True, "count": 3}
    rows = _rows(db, lab_engagement.id)
    assert {r.actor for r in rows} == {"egress-proxy"} and {r.action for r in rows} == {"network_request"}
    assert all(len(r.reason) == 100 for r in rows)
    assert all(len(k) == 64 and len(v) == 500 for r in rows for k, v in r.payload.items())
    assert verify_audit_chain(db, lab_engagement.id).ok


def test_negative_one_invalid_decision_rejects_the_whole_batch(db, lab_engagement):
    events = [ProxyAuditEventIn(decision="ALLOW", reason="a"), ProxyAuditEventIn(decision="MAYBE", reason="b")]
    with pytest.raises(HTTPException) as exc:
        internal_proxy_audit_batch(lab_engagement.id, ProxyAuditBatchIn(events=events), db)
    assert exc.value.status_code == 422
    assert _rows(db, lab_engagement.id) == []


def test_negative_a_batch_for_an_unknown_engagement_is_404(db):
    with pytest.raises(HTTPException) as exc:
        internal_proxy_audit_batch(uuid.uuid4(), ProxyAuditBatchIn(events=[ProxyAuditEventIn(decision="ALLOW", reason="a")]), db)
    assert exc.value.status_code == 404


def test_negative_the_batch_size_is_bounded():
    with pytest.raises(ValueError):
        ProxyAuditBatchIn(events=[ProxyAuditEventIn(decision="ALLOW", reason="a")] * 201)
    with pytest.raises(ValueError):
        ProxyAuditBatchIn(events=[])


def test_the_single_event_endpoint_still_works(db, lab_engagement):
    internal_proxy_audit(lab_engagement.id, ProxyAuditEventIn(decision="DENY", reason="out_of_scope", payload={"h": "x"}), db)
    rows = _rows(db, lab_engagement.id)
    assert len(rows) == 1 and rows[0].decision == "DENY"


# --- bulk slots keep the pool free for the control path --------------------------

@pytest.fixture()
def small_slots(monkeypatch):
    def install(slots: int, wait: float):
        monkeypatch.setattr(internal, "_bulk_db_slots", threading.BoundedSemaphore(slots))
        monkeypatch.setattr(get_settings(), "internal_bulk_wait_seconds", wait)
    return install


def test_negative_bulk_writers_without_a_free_slot_get_503_and_write_nothing(db, lab_engagement, small_slots):
    small_slots(slots=1, wait=0.05)
    assert internal._bulk_db_slots.acquire(timeout=1)  # someone else holds the only slot
    try:
        with pytest.raises(HTTPException) as exc:
            internal_proxy_audit_batch(lab_engagement.id, ProxyAuditBatchIn(events=[ProxyAuditEventIn(decision="ALLOW", reason="a")]), db)
        assert exc.value.status_code == 503
        with pytest.raises(HTTPException) as exc:
            internal_proxy_audit(lab_engagement.id, ProxyAuditEventIn(decision="ALLOW", reason="a"), db)
        assert exc.value.status_code == 503
        with pytest.raises(HTTPException) as exc:
            reserve_proxy_rate_slot(lab_engagement.id, db)
        assert exc.value.status_code == 503
    finally:
        internal._bulk_db_slots.release()
    assert _rows(db, lab_engagement.id) == []


def test_the_slot_is_released_after_every_call(db, lab_engagement, small_slots):
    small_slots(slots=1, wait=0.05)
    for _ in range(5):
        internal_proxy_audit(lab_engagement.id, ProxyAuditEventIn(decision="ALLOW", reason="a"), db)
    with pytest.raises(HTTPException):  # a failing call must release it too
        internal_proxy_audit(uuid.uuid4(), ProxyAuditEventIn(decision="ALLOW", reason="a"), db)
    internal_proxy_audit(lab_engagement.id, ProxyAuditEventIn(decision="ALLOW", reason="a"), db)


def test_a_flood_of_proxy_audit_writes_does_not_delay_cancel_checks(engine, db, lab_engagement, small_slots):
    """The #49 failure in miniature: a pool of 3 connections, a dozen threads
    flooding the proxy-audit endpoints, and a worker polling cancel-requested.
    Before the bulk slots the flooders held every connection and the poll waited
    for the pool timeout; now it must answer well inside the worker's 2 s."""
    url = engine.url.render_as_string(hide_password=False)
    small = create_engine(url, pool_size=2, max_overflow=1, pool_timeout=10, future=True)
    Session = sessionmaker(bind=small, autoflush=False, future=True)
    small_slots(slots=2, wait=0.2)

    now = dt.datetime.now(dt.timezone.utc)
    run = ScanRun(engagement_id=lab_engagement.id, phase="fingerprint", state="running",
                  started_at=now, heartbeat_at=now, attempt=1)
    db.add(run)
    db.commit()
    db.refresh(run)
    run_id = run.id

    stop = threading.Event()
    refused = []

    def flood():
        event = ProxyAuditEventIn(decision="ALLOW", reason="in_scope", payload={"p": "x"})
        while not stop.is_set():
            with Session() as s:
                try:
                    internal_proxy_audit_batch(lab_engagement.id, ProxyAuditBatchIn(events=[event] * 20), s)
                except HTTPException as exc:
                    refused.append(exc.status_code)

    threads = [threading.Thread(target=flood, daemon=True) for _ in range(12)]
    for t in threads:
        t.start()
    latencies = []
    try:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            started = time.monotonic()
            with Session() as s:
                assert scan_run_cancel_requested(run_id, db=s, attempt=1) == {"cancel_requested": False}
            latencies.append(time.monotonic() - started)
            time.sleep(0.05)
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=10)
        small.dispose()
    assert len(latencies) > 10
    assert max(latencies) < 1.0, f"a cancel check waited {max(latencies):.2f}s behind the audit flood"
    # What did get through is still one intact chain.
    assert verify_audit_chain(db, lab_engagement.id).ok


def test_the_cancel_poll_refreshes_a_stale_heartbeat_but_not_a_fresh_one(db, lab_engagement):
    now = dt.datetime.now(dt.timezone.utc)
    run = ScanRun(engagement_id=lab_engagement.id, phase="fingerprint", state="running",
                  started_at=now - dt.timedelta(minutes=5), heartbeat_at=now - dt.timedelta(seconds=5), attempt=1)
    db.add(run)
    db.commit()
    before = run.heartbeat_at
    scan_run_cancel_requested(run.id, db=db, attempt=1)
    db.refresh(run)
    assert run.heartbeat_at == before, "a poll within 15 s of the last heartbeat must not write the row"
    run.heartbeat_at = now - dt.timedelta(seconds=60)
    db.commit()
    scan_run_cancel_requested(run.id, db=db, attempt=1)
    db.refresh(run)
    assert run.heartbeat_at > now - dt.timedelta(seconds=5), "REQ-RESUME-004: a stale heartbeat is still refreshed"
