"""REQ-INSTALL-004 at the real HTTP layer: a fresh install whose MFA encryption key
is empty answered POST /auth/mfa/enroll with a 500 while /health stayed green, so
nobody could ever finish enrollment (found 2026-10-01 on a clean VM). It must be a
503 that names the fix, must store nothing, and must work again once a key is set.
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app.api.admin import create_user
from app.config import get_settings
from app.db.base import get_db
from app.main import app
from app.models.user import User
from app.schemas.auth import AdminCreateUserIn

FIRST_REAL_PW = "a-strong-real-pw-123"


class _Req:
    def __init__(self):
        self.headers = {}
        self.client = None


def _client(engine) -> TestClient:
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def _override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    return TestClient(app, raise_server_exceptions=False)


def _reach_the_enroll_step(client: TestClient, db, admin_user) -> tuple[User, str]:
    out = create_user(AdminCreateUserIn(email="first.user@example.com", display_name="First", role="operator"),
                      _Req(), actor=admin_user, db=db)
    user = db.get(User, out.user.id)
    login = client.post("/auth/login", json={"email": user.email, "password": out.temporary_password})
    assert login.status_code == 200 and login.json()["status"] == "set_password", login.text
    set_first = client.post("/auth/password/set-first",
                            json={"challenge_id": login.json()["challenge_id"], "new_password": FIRST_REAL_PW})
    assert set_first.status_code == 200 and set_first.json()["status"] == "mfa_enroll", set_first.text
    return user, set_first.json()["challenge_id"]


def test_negative_enrollment_answers_503_not_500_without_a_key_stores_nothing_and_recovers(
    engine, db, admin_user, monkeypatch,
):
    client = _client(engine)
    try:
        user, challenge_id = _reach_the_enroll_step(client, db, admin_user)

        monkeypatch.setattr(get_settings(), "mfa_encryption_key", "")
        response = client.post("/auth/mfa/enroll", json={"challenge_id": challenge_id})
        assert response.status_code == 503, response.text
        detail = response.json()["detail"]
        assert "MFA_ENCRYPTION_KEY" in detail and "make env" in detail
        db.expire_all()
        assert db.get(User, user.id).totp_secret_encrypted is None, "nothing may be stored on failure"

        # Setting the key (as `make env` does) fixes it: the very same challenge now works.
        monkeypatch.undo()
        retry = client.post("/auth/mfa/enroll", json={"challenge_id": challenge_id})
        assert retry.status_code == 200 and retry.json()["secret"], retry.text
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_negative_a_malformed_key_is_a_503_that_does_not_echo_it(engine, db, admin_user, monkeypatch):
    client = _client(engine)
    try:
        _, challenge_id = _reach_the_enroll_step(client, db, admin_user)
        sentinel = "SENTINEL-not-a-fernet-key-987654"
        monkeypatch.setattr(get_settings(), "mfa_encryption_key", sentinel)
        response = client.post("/auth/mfa/enroll", json={"challenge_id": challenge_id})
        assert response.status_code == 503, response.text
        assert sentinel not in response.text
    finally:
        app.dependency_overrides.pop(get_db, None)
