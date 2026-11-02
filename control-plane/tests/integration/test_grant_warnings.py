"""REQ-GRANT-002 / TC-GRANT-002 (GitHub issue #58): a discovery switch that is on while the tool grant it
needs is missing is a warning before the run, and the gateway still refuses the call. The switch never
creates authority."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app import auth_service, scan_readiness
from app.db.base import get_db
from app.gateway.authorize import ToolCall, authorize
from app.main import app
from app.models.engagement import Engagement, ScopeAsset, ToolGrant
from app.models.user import User
from app.passwords import hash_secret

TARGET = "app.example.test"


@pytest.fixture
def client(engine):
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def _override():
        s = SessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _override
    yield TestClient(app)
    app.dependency_overrides.clear()


def _user(db) -> User:
    user = User(email=f"u-{uuid.uuid4().hex[:10]}@example.com", display_name="U", role="operator", status="active",
                must_change_password=False, password_hash=hash_secret("x"))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _engagement(db, owner, *, grants, **switches):
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        title="Switches", source="own_domain", status="active",
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
        owner_user_id=owner.id, **switches,
    )
    db.add(eng)
    db.flush()
    db.add(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain", value=TARGET,
                      active_allowed=True, authorization_verified=True))
    for category, mode in grants:
        db.add(ToolGrant(engagement_id=eng.id, tool_category=category, mode=mode, requires_manual_approval=False))
    db.commit()
    db.refresh(eng)
    return eng


def _codes(r):
    return [w.code for w in r.warnings]


def test_the_subfinder_switch_without_the_passive_grant_is_a_warning(db):
    eng = _engagement(db, _user(db), grants=[("fingerprint", "active"), ("recon", "active")], subfinder_enabled=True)
    r = scan_readiness.evaluate(db, eng.id)
    assert _codes(r) == ["subfinder_without_passive_grant"]
    w = r.warnings[0]
    assert "recon / passive" in w.message and "Passive subdomain sources" in w.message and "subfinder will be skipped" in w.message
    assert w.action == "tool_grants"
    assert r.ready, "a warning must not stop a run"


def test_negative_the_switch_does_not_create_authority_the_gateway_still_refuses(db):
    eng = _engagement(db, _user(db), grants=[("fingerprint", "active"), ("recon", "active")], subfinder_enabled=True)
    decision = authorize(db, ToolCall(engagement_id=eng.id, tool="subfinder", category="recon", mode="passive", target=TARGET))
    assert not decision.allowed and decision.reason == "no_tool_grant"


def test_the_grant_present_means_no_warning_and_the_call_is_allowed(db):
    eng = _engagement(db, _user(db), grants=[("fingerprint", "active"), ("recon", "passive")], subfinder_enabled=True)
    assert scan_readiness.evaluate(db, eng.id).warnings == []
    assert authorize(db, ToolCall(engagement_id=eng.id, tool="subfinder", category="recon", mode="passive", target=TARGET)).allowed


def test_negative_the_grant_without_the_switch_warns_of_nothing_and_the_call_is_refused_by_the_switch(db):
    eng = _engagement(db, _user(db), grants=[("fingerprint", "active"), ("recon", "passive")], subfinder_enabled=False)
    assert scan_readiness.evaluate(db, eng.id).warnings == []
    decision = authorize(db, ToolCall(engagement_id=eng.id, tool="subfinder", category="recon", mode="passive", target=TARGET))
    assert not decision.allowed and decision.reason == "subfinder_not_enabled"


def test_every_switch_with_a_grant_of_its_own_is_checked(db):
    eng = _engagement(
        db, _user(db), grants=[("recon", "passive")],
        subfinder_enabled=False, crawling_enabled=True, screenshots_enabled=True, oob_enabled=True,
    )
    codes = _codes(scan_readiness.evaluate(db, eng.id))
    assert codes == ["crawling_without_grant", "screenshots_without_grant", "oob_without_grant"]
    eng2 = _engagement(
        db, _user(db), grants=[("fingerprint", "active"), ("vuln", "active")],
        subfinder_enabled=False, crawling_enabled=True, screenshots_enabled=True, oob_enabled=True,
    )
    assert scan_readiness.evaluate(db, eng2.id).warnings == []


def test_negative_a_warning_never_replaces_a_blocker(db):
    # No active grant at all: the run is blocked (a blocker), and the missing passive grant is also a warning.
    eng = _engagement(db, _user(db), grants=[], subfinder_enabled=True)
    r = scan_readiness.evaluate(db, eng.id)
    assert not r.ready and [b.code for b in r.blockers] == ["no_active_tool_grant"]
    assert _codes(r) == ["subfinder_without_passive_grant"]


def test_the_endpoint_returns_the_warnings(client, db):
    owner = _user(db)
    eng = _engagement(db, owner, grants=[("fingerprint", "active")], subfinder_enabled=True)
    token, _ = auth_service.create_session(db, owner, ip=None, user_agent=None)
    body = client.get(f"/engagements/{eng.id}/scan-readiness", headers={"Authorization": f"Bearer {token}"}).json()
    assert body["ready"] is True
    assert [w["code"] for w in body["warnings"]] == ["subfinder_without_passive_grant"]
    assert body["warnings"][0]["action"] == "tool_grants"
