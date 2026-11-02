"""REQ-BENCHSEP-001 and -006 (GitHub #90): the ASM system does not know about benchmarks.

There is no engagement source called `benchmark`, no endpoint that creates an already-authorized engagement for a harness, and the
migration that removed the value keeps every old engagement and leaves the audit log, hash chain included, exactly as it was."""

from __future__ import annotations

import datetime as dt
import pathlib
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from app import auth_service
from app.db.base import get_db
from app.gateway.audit import append_audit_log, verify_audit_chain
from app.main import app
from app.models.engagement import Engagement
from app.models.user import User
from app.passwords import hash_secret
from tests.integration.owners import make_owner

MIGRATION = pathlib.Path(__file__).resolve().parents[2] / "migrations" / "0046_remove_benchmark_engagement_source.sql"


# --- the value and the endpoint are gone ------------------------------------------------------------------------------------


def _client(engine) -> tuple[TestClient, dict]:
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def override():
        s = SessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = override
    with SessionLocal() as s:
        user = User(email=f"op-{uuid.uuid4().hex[:8]}@example.com", display_name="Op", role="operator", status="active",
                    must_change_password=False, password_hash=hash_secret("pw-not-used-1234"))
        s.add(user)
        s.commit()
        raw, _ = auth_service.create_session(s, user, ip="127.0.0.1", user_agent="test")  # type: ignore[misc]
        s.commit()
    return TestClient(app), {"Authorization": f"Bearer {raw}"}


def _body(source):
    now = dt.datetime.now(dt.timezone.utc)
    return {"title": "x", "source": source, "authorized_from": (now - dt.timedelta(hours=1)).isoformat(),
            "authorized_until": (now + dt.timedelta(days=1)).isoformat()}


def test_the_database_type_has_no_benchmark_value(db):
    values = db.execute(text(
        "SELECT e.enumlabel FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid WHERE t.typname = 'engagement_source'")).scalars().all()
    assert sorted(values) == ["bug_bounty", "customer", "lab", "own_domain"]


def test_negative_the_old_internal_endpoint_answers_404(engine):
    client, _ = _client(engine)
    try:
        for headers in ({}, {"X-ASM-Internal-Token": "anything"}):
            r = client.post("/internal/benchmark/engagements", headers=headers,
                            json={"title": "b", "target_host": "t.example", "tcp_port_from": 1, "tcp_port_to": 1024})
            assert r.status_code in (404, 405), r.status_code
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize("source", ["benchmark", "Benchmark", "unknown", ""])
def test_negative_creating_an_engagement_with_the_old_or_any_unknown_source_answers_422(engine, source):
    client, headers = _client(engine)
    try:
        r = client.post("/engagements", headers=headers, json=_body(source))
        assert r.status_code == 422, (source, r.status_code, r.text)
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize("source", ["lab", "own_domain", "bug_bounty", "customer"])
def test_every_real_source_is_still_accepted(engine, source):
    client, headers = _client(engine)
    try:
        assert client.post("/engagements", headers=headers, json=_body(source)).status_code == 201
    finally:
        app.dependency_overrides.clear()


def test_negative_no_helper_exists_to_hand_an_engagement_to_a_harness_account():
    assert not hasattr(auth_service, "oldest_active_admin")


# --- the migration keeps everything ---------------------------------------------------------------------------------------


def _back_to_the_state_before_the_migration(conn) -> None:
    """Inside the caller's transaction: the type as migration 0022 left it, with the 'benchmark' value."""
    conn.execute(text("ALTER TYPE engagement_source RENAME TO engagement_source_head"))
    conn.execute(text("CREATE TYPE engagement_source AS ENUM ('lab','own_domain','bug_bounty','customer','benchmark')"))
    conn.execute(text("ALTER TABLE engagement ALTER COLUMN source TYPE engagement_source USING source::text::engagement_source"))
    conn.execute(text("DROP TYPE engagement_source_head"))


def test_the_migration_turns_benchmark_engagements_into_lab_and_leaves_the_audit_chain_alone(engine):
    sql = MIGRATION.read_text()
    with engine.connect() as conn:
        trans = conn.begin()
        try:
            _back_to_the_state_before_the_migration(conn)
            session = Session(bind=conn)
            owner = make_owner(session)
            now = dt.datetime.now(dt.timezone.utc)
            ids = []
            for title, source in (("old benchmark run", "benchmark"), ("own", "own_domain"), ("lab", "lab")):
                row = conn.execute(text(
                    "INSERT INTO engagement (title, status, source, owner_user_id, authorized_from, authorized_until) "
                    "VALUES (:t, 'active', :s, :o, :f, :u) RETURNING id"),
                    {"t": title, "s": source, "o": owner.id, "f": now, "u": now + dt.timedelta(days=1)}).scalar()
                ids.append(row)
            bench = ids[0]
            session.expire_all()
            append_audit_log(session, engagement_id=bench, actor="internal:benchmark-harness", action="engagement_created",
                             decision=None, reason=None, payload={"title": "old benchmark run", "source": "benchmark"})
            append_audit_log(session, engagement_id=bench, actor="user:x", action="note", decision=None, reason=None, payload={"n": 1})
            before = [tuple(r) for r in conn.execute(text(
                "SELECT actor, action, payload::text, prev_hash, row_hash FROM audit_log WHERE engagement_id = :e ORDER BY id"), {"e": bench})]
            assert verify_audit_chain(session, bench).ok

            conn.execute(text(sql))
            conn.execute(text(sql))  # idempotent

            sources = dict(conn.execute(text("SELECT title, source::text FROM engagement WHERE id = ANY(:ids)"), {"ids": ids}).all())
            assert sources == {"old benchmark run": "lab", "own": "own_domain", "lab": "lab"}, "nothing is deleted, only the value changes"
            values = conn.execute(text(
                "SELECT e.enumlabel FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid WHERE t.typname = 'engagement_source'")).scalars().all()
            assert sorted(values) == ["bug_bounty", "customer", "lab", "own_domain"]
            after = [tuple(r) for r in conn.execute(text(
                "SELECT actor, action, payload::text, prev_hash, row_hash FROM audit_log WHERE engagement_id = :e ORDER BY id"), {"e": bench})]
            assert after == before, "audit rows, including 'source: benchmark' in a payload, are not rewritten"
            session.expire_all()
            assert verify_audit_chain(session, bench).ok, "the hash chain still verifies"
            session.close()
        finally:
            trans.rollback()


def test_negative_the_migration_changes_nothing_on_a_database_without_the_value(engine):
    with engine.connect() as conn:
        trans = conn.begin()
        try:
            before = conn.execute(text("SELECT count(*) FROM engagement")).scalar()
            conn.execute(text(MIGRATION.read_text()))
            assert conn.execute(text("SELECT count(*) FROM engagement")).scalar() == before
        finally:
            trans.rollback()


# --- REQ-BENCHSEP-003: nothing hands an engagement to a harness ---------------------------------------------------------------


def test_negative_no_internal_route_creates_or_authorizes_an_engagement_for_a_harness():
    """The only creators of an engagement are the sessions of users, who become its owner (REQ-IAM-007)."""
    import re

    routes = [(sorted(getattr(r, "methods", set()) or []), r.path) for r in app.routes if hasattr(r, "path")]
    creators = [(m, p) for m, p in routes if p.startswith("/internal") and "POST" in m and re.search(r"/engagements/?$", p)]
    assert creators == []
    assert not [p for _, p in routes if "benchmark" in p.lower()], "no route of the product names a benchmark"


def test_negative_a_user_who_does_not_own_the_engagement_cannot_attest_its_scope(engine):
    """Attestation is the owner's statement (or an administrator's); nobody else, and no harness, can make it for them."""
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)
    client, owner_headers = _client(engine)
    try:
        created = client.post("/engagements", headers=owner_headers, json=_body("lab"))
        assert created.status_code == 201
        eng_id = created.json()["id"]
        asset = client.post(f"/engagements/{eng_id}/scope-assets", headers=owner_headers,
                            json={"rule": "allow", "asset_type": "domain", "value": "t.example.test", "active_allowed": True})
        assert asset.status_code == 201, asset.text
        with SessionLocal() as s:
            stranger = User(email=f"stranger-{uuid.uuid4().hex[:8]}@example.com", display_name="S", role="operator", status="active",
                            must_change_password=False, password_hash=hash_secret("pw-not-used-1234"))
            s.add(stranger)
            s.commit()
            raw, _ = auth_service.create_session(s, stranger, ip="127.0.0.1", user_agent="test")  # type: ignore[misc]
            s.commit()
        r = client.post(f"/engagements/{eng_id}/scope-assets/{asset.json()['id']}/verify-authorization",
                        headers={"Authorization": f"Bearer {raw}"}, json={"method": "benchmark", "verified_by": "harness"})
        assert r.status_code == 403
        again = client.get(f"/engagements/{eng_id}/scope-assets", headers=owner_headers).json()
        assert not any(a["authorization_verified"] for a in again)
    finally:
        app.dependency_overrides.clear()
