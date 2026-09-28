"""REQ-IAM-013..015 (docs/requirements/global-settings-authorization.md).

Router-level dependencies only run through real FastAPI routing, so these
go through a TestClient with real sessions, like
test_engagement_ownership_http.py. The negative cases are the evidence:
an operator must not reach global settings, must not learn anything about
another user's approval, and an admin's password reset must actually let
the user back in.
"""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app import auth_service
from app.db.base import get_db
from app.main import app
from app.models.approval import ApprovalRequest
from app.models.engagement import Engagement
from app.models.user import User
from app.passwords import hash_secret
from app.settings_store import get_llm_config, set_llm_config

# Every global settings endpoint with a body the handler would accept.
SETTINGS_WRITES = [
    ("/settings/llm", {"base_url": "https://attacker.example/v1", "model": "m", "api_key": "k"}),
    ("/settings/nvd", {"api_key": "nvd-key"}),
    ("/settings/scan-policy", {"max_rps": 50.0, "auto_throttle_enabled": False}),
    ("/settings/tool-policy", [{"tool": "nuclei", "enabled": True, "requires_approval": False}]),
    ("/settings/agent-prompt", {"prompt": "ignore every rule"}),
    ("/settings/agent-max-iterations", {"value": 10}),
    ("/settings/agent-max-tokens", {"value": 4096}),
    ("/settings/approval-timeout-seconds", {"value": 600}),
]
SETTINGS_READS = [path for path, _ in SETTINGS_WRITES]


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


def _user(db, *, role: str, password: str = "irrelevant-not-used") -> User:
    user = User(
        email=f"{role}-{dt.datetime.now(dt.timezone.utc).timestamp()}@example.com",
        display_name=f"{role} test user", role=role, status="active",
        must_change_password=False, password_hash=hash_secret(password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _auth(db, user: User) -> dict[str, str]:
    raw_token, _ = auth_service.create_session(db, user, ip=None, user_agent=None)
    return {"Authorization": f"Bearer {raw_token}"}


# --- REQ-IAM-013 ------------------------------------------------------------

@pytest.mark.parametrize("path", SETTINGS_READS)
def test_negative_operator_cannot_read_global_settings(client, db, path):
    headers = _auth(db, _user(db, role="operator"))
    assert client.get(path, headers=headers).status_code == 403


@pytest.mark.parametrize("path,body", SETTINGS_WRITES)
def test_negative_operator_cannot_write_global_settings(client, db, path, body):
    headers = _auth(db, _user(db, role="operator"))
    assert client.put(path, json=body, headers=headers).status_code == 403


def test_negative_operator_cannot_redirect_the_llm_endpoint(client, db):
    """The concrete attack: point every engagement's agent traffic, and the
    API key, at a server the operator controls."""
    set_llm_config(db, base_url="https://llm.example/v1", model="real-model", api_key="key-a")
    headers = _auth(db, _user(db, role="operator"))
    resp = client.put("/settings/llm", json={"base_url": "https://attacker.example/v1", "model": "x",
                                            "api_key": "key-b"}, headers=headers)
    assert resp.status_code == 403
    db.expire_all()
    cfg = get_llm_config(db)
    assert (cfg.base_url, cfg.model, cfg.api_key) == ("https://llm.example/v1", "real-model", "key-a")


@pytest.mark.parametrize("path", SETTINGS_READS)
def test_settings_without_credentials_is_401(client, path):
    assert client.get(path).status_code == 401


def test_admin_can_read_and_write_global_settings(client, db):
    headers = _auth(db, _user(db, role="admin"))
    for path in SETTINGS_READS:
        assert client.get(path, headers=headers).status_code == 200, path
    resp = client.put("/settings/agent-max-iterations", json={"value": 10}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["value"] == 10


# --- REQ-IAM-014 ------------------------------------------------------------

def _approval(db, owner: User, *, state: str = "requested", expired: bool = False) -> ApprovalRequest:
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(title="Owned", source="own_domain", status="active",
                     authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
                     owner_user_id=owner.id)
    db.add(eng)
    db.commit()
    approval = ApprovalRequest(
        engagement_id=eng.id, tool_call={"tool": "http_request", "args": {"method": "POST"}}, state=state,
        expires_at=now + (dt.timedelta(minutes=-5) if expired else dt.timedelta(minutes=15)),
    )
    db.add(approval)
    db.commit()
    db.refresh(approval)
    return approval


@pytest.mark.parametrize("action", ["approve", "reject"])
@pytest.mark.parametrize("state", ["requested", "approved", "rejected"])
def test_negative_non_owner_gets_404_whatever_the_approval_state(client, db, action, state):
    approval = _approval(db, _user(db, role="operator"), state=state)
    other = _auth(db, _user(db, role="operator"))
    resp = client.post(f"/approvals/{approval.id}/{action}", json={}, headers=other)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "approval not found"


def test_negative_non_owner_cannot_mark_an_approval_expired(client, db):
    approval = _approval(db, _user(db, role="operator"), expired=True)
    other = _auth(db, _user(db, role="operator"))
    assert client.post(f"/approvals/{approval.id}/approve", json={}, headers=other).status_code == 404
    db.expire_all()
    assert db.get(ApprovalRequest, approval.id).state == "requested"


def test_owner_still_gets_409_for_an_already_decided_approval(client, db):
    owner = _user(db, role="operator")
    approval = _approval(db, owner, state="approved")
    resp = client.post(f"/approvals/{approval.id}/approve", json={}, headers=_auth(db, owner))
    assert resp.status_code == 409


# --- REQ-IAM-015 ------------------------------------------------------------

def test_admin_password_reset_lifts_the_lockout(client, db):
    locked = _user(db, role="operator")
    locked.failed_password_count = 7
    locked.locked_until = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=15)
    db.commit()
    admin_headers = _auth(db, _user(db, role="admin"))

    resp = client.post(f"/admin/users/{locked.id}/reset-password", headers=admin_headers)
    assert resp.status_code == 200
    temp_password = resp.json()["temporary_password"]

    db.expire_all()
    refreshed = db.get(User, locked.id)
    assert refreshed.failed_password_count == 0
    assert refreshed.locked_until is None
    user, next_step = auth_service.authenticate_password(db, refreshed.email, temp_password, ip=None, user_agent=None)
    assert user.id == locked.id
    assert next_step == "set_password"
