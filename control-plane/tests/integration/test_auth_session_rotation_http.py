"""GitHub issue #26: proves the session-revocation/rotation behaviour at the
real HTTP layer, not just via direct auth_service calls - a TestClient is
needed because require_user/session resolution runs as router-level
dependency injection (see test_engagement_ownership_http.py's docstring for
the same reasoning)."""

from __future__ import annotations

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app import auth_service
from app.db.base import get_db
from app.main import app
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


def _admin(db) -> User:
    user = User(
        email=f"admin-rot-{id(db)}@example.com", display_name="Admin", role="admin", status="active",
        must_change_password=False, password_hash=hash_secret("irrelevant-not-used"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _enrolled_user_with_password(db, admin, email) -> tuple[User, str]:
    from app.api.admin import create_user
    from app.schemas.auth import AdminCreateUserIn

    class _Req:
        def __init__(self):
            self.headers = {}
            self.client = None

    out = create_user(AdminCreateUserIn(email=email, display_name="Rot User", role="operator"), _Req(), actor=admin, db=db)
    user = db.get(User, out.user.id)
    password = "a-strong-real-password-123"

    challenge = auth_service.create_login_challenge(db, user, "set_password")
    user = auth_service.set_first_password(db, challenge.id, password, ip=None, user_agent=None)
    enroll_challenge = auth_service.create_login_challenge(db, user, "mfa_enroll")
    user, raw_secret, _ = auth_service.begin_mfa_enrollment(db, enroll_challenge.id)
    auth_service.confirm_mfa_enrollment(db, enroll_challenge.id, pyotp.TOTP(raw_secret).now(), ip=None, user_agent=None)
    return user, password


def test_change_password_sets_a_fresh_cookie_and_evicts_the_old_token(engine, db):
    admin = _admin(db)
    user, password = _enrolled_user_with_password(db, admin, "http-changepw@example.com")
    old_token, _ = auth_service.create_session(db, user, ip=None, user_agent=None)

    client = _client(engine)
    try:
        resp = client.post(
            "/auth/change-password",
            headers={"Authorization": f"Bearer {old_token}"},
            json={"current_password": password, "new_password": "a-new-http-password-123456"},
        )
        assert resp.status_code == 200
        assert "session_token" not in resp.json()  # REQ-IAM-018: the cookie carries it
        new_token = resp.cookies["session"]
        assert new_token and new_token != old_token

        # The token used to MAKE this call is now dead...
        stale = client.get("/auth/me", headers={"Authorization": f"Bearer {old_token}"})
        assert stale.status_code == 401

        # ...but the caller isn't locked out: the new token works.
        fresh = client.get("/auth/me", headers={"Authorization": f"Bearer {new_token}"})
        assert fresh.status_code == 200
        assert fresh.json()["email"] == user.email
    finally:
        app.dependency_overrides.clear()


def test_change_password_evicts_a_different_devices_session_too(engine, db):
    admin = _admin(db)
    user, password = _enrolled_user_with_password(db, admin, "http-changepw-otherdevice@example.com")
    calling_token, _ = auth_service.create_session(db, user, ip=None, user_agent=None)
    other_device_token, _ = auth_service.create_session(db, user, ip="9.9.9.9", user_agent="other-device")

    client = _client(engine)
    try:
        resp = client.post(
            "/auth/change-password",
            headers={"Authorization": f"Bearer {calling_token}"},
            json={"current_password": password, "new_password": "a-new-http-password-654321"},
        )
        assert resp.status_code == 200

        other_device = client.get("/auth/me", headers={"Authorization": f"Bearer {other_device_token}"})
        assert other_device.status_code == 401
    finally:
        app.dependency_overrides.clear()


def test_change_password_with_wrong_current_password_does_not_touch_sessions(engine, db):
    admin = _admin(db)
    user, password = _enrolled_user_with_password(db, admin, "http-changepw-wrongpw@example.com")
    calling_token, _ = auth_service.create_session(db, user, ip=None, user_agent=None)

    client = _client(engine)
    try:
        resp = client.post(
            "/auth/change-password",
            headers={"Authorization": f"Bearer {calling_token}"},
            json={"current_password": "totally-wrong", "new_password": "a-new-http-password-000000"},
        )
        assert resp.status_code == 401

        # A failed attempt must not revoke the existing, still-valid session.
        still_works = client.get("/auth/me", headers={"Authorization": f"Bearer {calling_token}"})
        assert still_works.status_code == 200
    finally:
        app.dependency_overrides.clear()
