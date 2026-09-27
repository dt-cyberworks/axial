"""REQ-IAM-002/007 at the HTTP layer: require_user and
enforce_engagement_ownership are wired as ROUTER-LEVEL dependencies
(app/api/__init__.py), so they only actually run through the real FastAPI
routing pipeline - a TestClient is required to prove them, unlike the rest
of this suite which calls handler functions directly."""

from __future__ import annotations

import datetime as dt

from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app import auth_service
from app.db.base import get_db
from app.main import app
from app.models.engagement import Engagement
from app.models.user import User
from app.passwords import hash_secret


def _client(engine) -> TestClient:
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def _override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    return TestClient(app)


def _user(db, *, role="operator", email=None) -> User:
    user = User(
        email=email or f"http-{dt.datetime.now(dt.timezone.utc).timestamp()}@example.com",
        display_name="HTTP Test User", role=role, status="active",
        must_change_password=False, password_hash=hash_secret("irrelevant-not-used"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _engagement(db, owner: User, title="Owned") -> Engagement:
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        title=title, source="own_domain", status="active",
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
        owner_user_id=owner.id,
    )
    db.add(eng)
    db.commit()
    db.refresh(eng)
    return eng


def test_no_credentials_is_401(engine, db):
    client = _client(engine)
    try:
        resp = client.get("/engagements")
        assert resp.status_code == 401
    finally:
        app.dependency_overrides.clear()


def test_owner_can_see_their_own_engagement(engine, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    raw_token, _ = auth_service.create_session(db, owner, ip=None, user_agent=None)
    client = _client(engine)
    try:
        resp = client.get(f"/engagements/{eng.id}", headers={"Authorization": f"Bearer {raw_token}"})
        assert resp.status_code == 200
        assert resp.json()["id"] == str(eng.id)
    finally:
        app.dependency_overrides.clear()


def test_non_owner_gets_404_not_403(engine, db):
    owner = _user(db, email="owner-a@example.com")
    other = _user(db, email="owner-b@example.com")
    eng = _engagement(db, owner)
    raw_token, _ = auth_service.create_session(db, other, ip=None, user_agent=None)
    client = _client(engine)
    try:
        resp = client.get(f"/engagements/{eng.id}", headers={"Authorization": f"Bearer {raw_token}"})
        assert resp.status_code == 404
    finally:
        app.dependency_overrides.clear()


def test_admin_can_see_any_engagement(engine, db):
    owner = _user(db, email="owner-c@example.com")
    admin = _user(db, role="admin", email="admin-x@example.com")
    eng = _engagement(db, owner)
    raw_token, _ = auth_service.create_session(db, admin, ip=None, user_agent=None)
    client = _client(engine)
    try:
        resp = client.get(f"/engagements/{eng.id}", headers={"Authorization": f"Bearer {raw_token}"})
        assert resp.status_code == 200
    finally:
        app.dependency_overrides.clear()


def test_list_engagements_is_scoped_to_owner_unless_admin(engine, db):
    owner = _user(db, email="owner-d@example.com")
    other = _user(db, email="owner-e@example.com")
    mine = _engagement(db, owner, title="Mine")
    _engagement(db, other, title="Theirs")
    raw_token, _ = auth_service.create_session(db, owner, ip=None, user_agent=None)
    client = _client(engine)
    try:
        resp = client.get("/engagements", headers={"Authorization": f"Bearer {raw_token}"})
        assert resp.status_code == 200
        titles = {e["title"] for e in resp.json()}
        assert titles == {"Mine"}
    finally:
        app.dependency_overrides.clear()


def test_created_engagement_owner_is_always_the_caller_not_client_supplied(engine, db):
    owner = _user(db, email="owner-f@example.com")
    raw_token, _ = auth_service.create_session(db, owner, ip=None, user_agent=None)
    client = _client(engine)
    try:
        now = dt.datetime.now(dt.timezone.utc)
        resp = client.post(
            "/engagements", headers={"Authorization": f"Bearer {raw_token}"},
            json={
                "title": "New one", "source": "own_domain",
                "authorized_from": now.isoformat(), "authorized_until": (now + dt.timedelta(days=1)).isoformat(),
                "owner_user_id": "00000000-0000-0000-0000-000000000000",  # must be ignored
            },
        )
        assert resp.status_code == 201
        created = db.get(Engagement, resp.json()["id"])
        assert created.owner_user_id == owner.id
    finally:
        app.dependency_overrides.clear()


def test_non_admin_cannot_reach_admin_routes(engine, db):
    operator = _user(db, email="notadmin@example.com")
    raw_token, _ = auth_service.create_session(db, operator, ip=None, user_agent=None)
    client = _client(engine)
    try:
        resp = client.get("/admin/users", headers={"Authorization": f"Bearer {raw_token}"})
        assert resp.status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_admin_can_reach_admin_routes(engine, db):
    admin = _user(db, role="admin", email="realadmin@example.com")
    raw_token, _ = auth_service.create_session(db, admin, ip=None, user_agent=None)
    client = _client(engine)
    try:
        resp = client.get("/admin/users", headers={"Authorization": f"Bearer {raw_token}"})
        assert resp.status_code == 200
    finally:
        app.dependency_overrides.clear()
