"""REQ-IAM-016/017 (GitHub issue #31): per-source-IP rate limit on the login
steps, and a client address the client cannot choose.

Starlette's TestClient always reports the peer as "testclient", so a tiny
ASGI wrapper sets the peer address from a test-only header.
"""

from __future__ import annotations

import os
import socket
import uuid

import pytest
import redis
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request

from app import rate_limit
from app.config import get_settings
from app.db.base import get_db
from app.main import app
from app.models.user import User
from app.passwords import hash_secret

LIMIT = 5
PASSWORD = "correct horse battery staple"


def _with_peer(asgi_app):
    async def wrapped(scope, receive, send):
        if scope["type"] == "http":
            headers = [(k, v) for k, v in scope["headers"] if k != b"x-test-peer"]
            peer = next((v.decode() for k, v in scope["headers"] if k == b"x-test-peer"), None)
            scope = dict(scope, headers=headers, client=(peer, 50000) if peer else scope.get("client"))
        await asgi_app(scope, receive, send)
    return wrapped


@pytest.fixture()
def client(engine, monkeypatch):
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def _override_get_db():
        s = SessionLocal()
        try:
            yield s
        finally:
            s.close()

    monkeypatch.setattr(get_settings(), "login_rate_limit_attempts", LIMIT)
    monkeypatch.setattr(get_settings(), "login_rate_limit_window_seconds", 300)
    app.dependency_overrides[get_db] = _override_get_db
    yield TestClient(_with_peer(app))
    app.dependency_overrides.clear()


def _login(client, *, peer: str, email: str = "nobody@example.com", password: str = "wrong", forwarded: str | None = None):
    headers = {"x-test-peer": peer}
    if forwarded is not None:
        headers["x-forwarded-for"] = forwarded
    return client.post("/auth/login", json={"email": email, "password": password}, headers=headers)


def _user(db) -> User:
    user = User(email=f"rl-{uuid.uuid4().hex[:10]}@example.com", display_name="Rate limit", role="operator",
                status="active", must_change_password=False, password_hash=hash_secret(PASSWORD))
    db.add(user)
    db.commit()
    return user


# --- REQ-IAM-016: the limit ------------------------------------------------------

def test_negative_a_burst_from_one_address_is_throttled_across_many_accounts(client):
    for i in range(LIMIT):
        assert _login(client, peer="203.0.113.7", email=f"user{i}@example.com").status_code == 401
    blocked = _login(client, peer="203.0.113.7", email="user-next@example.com")
    assert blocked.status_code == 429
    assert 1 <= int(blocked.headers["retry-after"]) <= 300
    assert "too many sign-in attempts" in blocked.json()["detail"]


def test_a_different_address_is_not_affected(client, db):
    user = _user(db)
    for i in range(LIMIT + 2):  # other accounts: stays clear of the per-account lockout
        _login(client, peer="203.0.113.7", email=f"spray{i}@example.com")
    assert _login(client, peer="203.0.113.7", email=user.email, password=PASSWORD).status_code == 429
    # The same account from another address: the password check runs normally.
    ok = _login(client, peer="198.51.100.20", email=user.email, password=PASSWORD)
    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] in {"mfa_enroll", "mfa_verify"}


def test_negative_the_throttle_does_not_lock_the_account(client, db):
    """Being throttled is not a failed login: the account's own lockout
    counter must not move, or the limit would become a lockout lever."""
    user = _user(db)
    for _ in range(LIMIT):
        _login(client, peer="203.0.113.7", email="someone-else@example.com")
    for _ in range(10):
        assert _login(client, peer="203.0.113.7", email=user.email).status_code == 429
    db.refresh(user)
    assert (user.failed_password_count or 0) == 0


def test_every_login_step_counts_against_the_same_address(client):
    fake = str(uuid.uuid4())
    peer = {"x-test-peer": "203.0.113.8"}
    client.post("/auth/login/mfa", json={"challenge_id": fake, "code": "000000"}, headers=peer)
    client.post("/auth/password/set-first", json={"challenge_id": fake, "new_password": "x" * 16}, headers=peer)
    client.post("/auth/mfa/enroll", json={"challenge_id": fake}, headers=peer)
    client.post("/auth/mfa/enroll/confirm", json={"challenge_id": fake, "code": "000000"}, headers=peer)
    assert _login(client, peer="203.0.113.8").status_code == 401  # the 5th attempt
    assert _login(client, peer="203.0.113.8").status_code == 429


def test_signed_in_requests_are_not_limited(client):
    for _ in range(LIMIT + 3):
        assert client.get("/auth/me", headers={"x-test-peer": "203.0.113.9"}).status_code == 401  # not 429


# --- REQ-IAM-017: the address -------------------------------------------------------

def test_negative_a_direct_client_cannot_pick_its_own_address(client):
    for i in range(LIMIT):
        _login(client, peer="203.0.113.7", forwarded=f"192.0.2.{i}")
    # Rotating X-Forwarded-For from an untrusted peer does not reset anything.
    assert _login(client, peer="203.0.113.7", forwarded="192.0.2.99").status_code == 429


def test_behind_the_edge_each_forwarded_client_has_its_own_window(client):
    for _ in range(LIMIT + 1):
        _login(client, peer="172.18.0.5", forwarded="203.0.113.50")
    assert _login(client, peer="172.18.0.5", forwarded="203.0.113.50").status_code == 429
    assert _login(client, peer="172.18.0.5", forwarded="203.0.113.51").status_code == 401


def _request(peer: str | None, forwarded: str | None = None) -> Request:
    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded is not None else []
    return Request({"type": "http", "headers": headers, "client": (peer, 1) if peer else None})


@pytest.mark.parametrize("peer,forwarded,expected", [
    ("203.0.113.7", None, "203.0.113.7"),                       # direct, no header
    ("203.0.113.7", "192.0.2.1", "203.0.113.7"),                # untrusted peer: header ignored
    ("172.18.0.5", "198.51.100.4", "198.51.100.4"),             # the edge on a Docker network
    ("127.0.0.1", "198.51.100.4", "198.51.100.4"),              # the edge on the host
    ("172.18.0.5", "192.0.2.1, 198.51.100.4", "198.51.100.4"),  # nearest untrusted hop wins
    ("172.18.0.5", "198.51.100.4, 10.0.0.9", "198.51.100.4"),   # trusted hops are skipped
    ("172.18.0.5", "not-an-ip", "172.18.0.5"),                  # malformed: fall back to the peer
    ("172.18.0.5", "10.0.0.9", "10.0.0.9"),                     # all private: the client is internal
])
def test_client_ip(peer, forwarded, expected):
    assert rate_limit.client_ip(_request(peer, forwarded)) == expected


# --- Redis: shared counts, and the fallback when it is down ---------------------------

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_without_redis_the_per_process_window_still_throttles_and_redis_is_not_retried(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "redis_url", f"redis://127.0.0.1:{_free_port()}/0")
    monkeypatch.setattr(rate_limit, "_redis_skip_until", 0.0)
    calls = []
    real = rate_limit._redis_hit
    monkeypatch.setattr(rate_limit, "_redis_hit", lambda *a: calls.append(1) or real(*a))
    for _ in range(LIMIT):
        assert _login(client, peer="203.0.113.60").status_code == 401
    assert _login(client, peer="203.0.113.60").status_code == 429
    assert len(calls) == 1  # one failed Redis attempt, then the breaker keeps it off


@pytest.mark.skipif(not os.environ.get("TEST_REDIS_URL"), reason="TEST_REDIS_URL not set - Redis path skipped")
def test_with_redis_the_count_is_shared_between_processes(client, monkeypatch):
    url = os.environ["TEST_REDIS_URL"]
    redis.Redis.from_url(url).flushdb()
    monkeypatch.setattr(get_settings(), "redis_url", url)
    monkeypatch.setattr(rate_limit, "_redis_skip_until", 0.0)
    for i in range(LIMIT):
        # A fresh client and empty local state each time: only Redis carries the count,
        # like separate workers or replicas would.
        rate_limit._local.reset()
        monkeypatch.setattr(rate_limit, "_redis_client", None)
        assert _login(client, peer="203.0.113.70", email=f"u{i}@example.com").status_code == 401
    assert _login(client, peer="203.0.113.70").status_code == 429
    ttl = redis.Redis.from_url(url).ttl("asm:login-rate:203.0.113.70")
    assert 0 < ttl <= 300
    assert rate_limit._local._windows == {}  # the local fallback was never used
