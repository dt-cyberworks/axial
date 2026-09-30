"""REQ-IAM-018/019 (GitHub issue #41): the session token never reaches
JavaScript, and a browser-ambient (cookie) credential needs proof of origin
for state-changing requests."""

from __future__ import annotations

import time
import uuid

import pyotp
import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app import auth_service
from app.db.base import get_db
from app.main import app
from app.models.engagement import Engagement
from app.models.user import User
from app.passwords import hash_secret

PASSWORD = "-".join(["a", "strong", "test", "password", "123"])
HOST = "http://testserver"  # what TestClient sends as Host
CONSOLE = {"x-requested-with": "asm-console"}
ENGAGEMENT = {"title": "csrf probe", "source": "own_domain",
              "authorized_from": "2026-01-01T00:00:00Z", "authorized_until": "2031-01-01T00:00:00Z"}


@pytest.fixture()
def client(engine):
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def _override_get_db():
        s = SessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


def _user(db, role="operator") -> User:
    user = User(email=f"csrf-{uuid.uuid4().hex[:10]}@example.com", display_name="CSRF", role=role, status="active",
                must_change_password=False, password_hash=hash_secret(PASSWORD))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _enrolled(db) -> tuple[User, str]:
    """A user that completed password + MFA enrollment, plus its TOTP secret."""
    user = _user(db)
    challenge = auth_service.create_login_challenge(db, user, "mfa_enroll")
    user, secret, _ = auth_service.begin_mfa_enrollment(db, challenge.id)
    auth_service.confirm_mfa_enrollment(db, challenge.id, pyotp.TOTP(secret).now(), ip=None, user_agent=None)
    return user, secret


def _session_cookie(db, user) -> str:
    return auth_service.create_session(db, user, ip=None, user_agent=None)[0]


def _create_engagement(client, cookie, headers=None):
    client.cookies.clear()
    return client.post(
        "/engagements", cookies={"session": cookie}, headers=headers or {},
        json=ENGAGEMENT,
    )


def _engagement_titles(db) -> list[str]:
    db.expire_all()
    return [e.title for e in db.query(Engagement).filter(Engagement.title == "csrf probe")]


# --- REQ-IAM-018: no token in any /auth body ----------------------------------------

def _response_fields(model, seen=None) -> set[str]:
    seen = seen or set()
    if model in seen or not hasattr(model, "model_fields"):
        return set()
    seen.add(model)
    names = set(model.model_fields)
    for field in model.model_fields.values():
        for arg in (getattr(field.annotation, "__args__", None) or (field.annotation,)):
            names |= _response_fields(arg, seen)
    return names


def test_negative_no_auth_response_model_has_a_token_field():
    checked = 0
    for route in app.routes:
        if isinstance(route, APIRoute) and route.path.startswith("/auth") and route.response_model is not None:
            model = route.response_model
            for arg in getattr(model, "__args__", None) or (model,):
                fields = _response_fields(arg)
                assert not any("token" in f.lower() for f in fields), f"{route.path} returns a token field: {fields}"
            checked += 1
    assert checked >= 8  # the check really walked the auth routes


def test_sign_in_sets_the_httponly_cookie_and_returns_no_token(client, db):
    user, secret = _enrolled(db)
    login = client.post("/auth/login", json={"email": user.email, "password": PASSWORD})
    assert login.status_code == 200, login.text
    verify = client.post("/auth/login/mfa", json={
        "challenge_id": login.json()["challenge_id"], "code": pyotp.TOTP(secret).at(time.time() + 30)})
    assert verify.status_code == 200, verify.text
    assert "token" not in verify.text.lower()
    set_cookie = verify.headers["set-cookie"].lower()
    assert "session=" in set_cookie and "httponly" in set_cookie and "samesite=strict" in set_cookie
    assert client.get("/auth/me").status_code == 200  # the cookie alone signs the browser in


def test_change_password_rotates_the_cookie_and_returns_no_token(client, db):
    user = _user(db)
    old = _session_cookie(db, user)
    client.cookies.set("session", old)
    resp = client.post("/auth/change-password", headers=CONSOLE,
                       json={"current_password": PASSWORD, "new_password": "a-new-strong-password-4567"})
    assert resp.status_code == 200, resp.text
    assert "token" not in resp.text.lower()
    new = resp.cookies["session"]
    assert new != old
    assert client.get("/auth/me").status_code == 200  # the jar now holds the new cookie
    client.cookies.clear()
    client.cookies.set("session", old)
    assert client.get("/auth/me").status_code == 401  # the old one is dead


# --- REQ-IAM-019: proof of origin ---------------------------------------------------

def test_negative_cookie_post_without_the_custom_header_is_rejected(client, db):
    cookie = _session_cookie(db, _user(db))
    resp = _create_engagement(client, cookie)
    assert resp.status_code == 403
    assert _engagement_titles(db) == []


def test_negative_cookie_post_from_a_foreign_origin_is_rejected(client, db):
    cookie = _session_cookie(db, _user(db))
    resp = _create_engagement(client, cookie, {**CONSOLE, "origin": "https://evil.example"})
    assert resp.status_code == 403
    assert _engagement_titles(db) == []


def test_negative_cookie_post_with_a_foreign_referer_is_rejected(client, db):
    cookie = _session_cookie(db, _user(db))
    resp = _create_engagement(client, cookie, {**CONSOLE, "referer": "https://evil.example/page"})
    assert resp.status_code == 403
    assert _engagement_titles(db) == []


def test_negative_a_null_origin_is_rejected(client, db):
    cookie = _session_cookie(db, _user(db))
    assert _create_engagement(client, cookie, {**CONSOLE, "origin": "null"}).status_code == 403


def test_negative_a_lookalike_origin_is_rejected(client, db):
    cookie = _session_cookie(db, _user(db))
    assert _create_engagement(client, cookie, {**CONSOLE, "origin": "http://testserver.evil.example"}).status_code == 403


def test_negative_an_unauthenticated_request_is_still_401_not_403(client):
    assert client.post("/engagements", json={"title": "x", "source": "own_domain"}).status_code == 401


def test_same_origin_cookie_post_with_the_header_is_accepted(client, db):
    cookie = _session_cookie(db, _user(db))
    resp = _create_engagement(client, cookie, {**CONSOLE, "origin": HOST})
    assert resp.status_code in (200, 201), resp.text
    assert _engagement_titles(db) == ["csrf probe"]


def test_trusted_dev_origin_is_accepted(client, db):
    cookie = _session_cookie(db, _user(db))
    resp = _create_engagement(client, cookie, {**CONSOLE, "origin": "http://localhost:5173"})
    assert resp.status_code in (200, 201), resp.text


def test_the_forwarded_host_counts_only_from_a_trusted_proxy(client, db):
    cookie = _session_cookie(db, _user(db))
    # TestClient's peer is "testclient" (not an IP), so it is not a trusted proxy:
    # a claimed forwarded host must not make a foreign origin acceptable.
    headers = {**CONSOLE, "origin": "https://evil.example", "x-forwarded-host": "evil.example"}
    assert _create_engagement(client, cookie, headers).status_code == 403


def test_safe_methods_need_no_header(client, db):
    cookie = _session_cookie(db, _user(db))
    client.cookies.clear()
    assert client.get("/engagements", cookies={"session": cookie}).status_code == 200
    assert client.get("/auth/me", cookies={"session": cookie}, headers={"origin": "https://evil.example"}).status_code == 200


def test_bearer_authenticated_requests_are_exempt(client, db):
    cookie = _session_cookie(db, _user(db))
    client.cookies.clear()
    resp = client.post("/engagements", headers={"Authorization": f"Bearer {cookie}"},
                       json=ENGAGEMENT)
    assert resp.status_code in (200, 201), resp.text


def test_cookie_sign_out_follows_the_same_rules(client, db):
    user = _user(db)
    cookie = _session_cookie(db, user)
    client.cookies.clear()
    assert client.post("/auth/logout", cookies={"session": cookie}).status_code == 403
    assert client.get("/auth/me", cookies={"session": cookie}).status_code == 200  # still signed in
    ok = client.post("/auth/logout", cookies={"session": cookie}, headers=CONSOLE)
    assert ok.status_code == 204
    assert client.get("/auth/me", cookies={"session": cookie}).status_code == 401
