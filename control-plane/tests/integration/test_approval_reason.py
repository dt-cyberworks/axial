"""REQ-APPROVAL-002 (GitHub #80): the reason of a request reaches the approval record and the audit row, bounded and
redacted, and an approval that carries one is still claimed as the exact call that was approved."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app import auth_service
from app.config import get_settings
from app.db.base import get_db
from app.gateway.authorize import ToolCall, authorize
from app.main import app
from app.models.approval import ApprovalRequest
from app.models.audit import AuditLog
from app.models.engagement import Engagement, ScopeAsset, ToolGrant
from app.models.scan_run import ScanRun
from app.models.user import User
from app.passwords import hash_secret
from app.schemas.internal import MAX_REASON_CHARS, ToolCallIn

HOST = "app.example.test"
REASON = "The egress proxy needs a disambiguating Host header for a bare IP, so the default server answers."


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


def _setup(db, *, approval_required=True):
    owner = _user(db)
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(title="E", source="own_domain", status="active", operating_mode="assessment", ai_testing_allowed=True,
                     authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=30), owner_user_id=owner.id)
    db.add(eng)
    db.flush()
    db.add(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain", value="example.test",
                      active_allowed=True, authorization_verified=True))
    db.add(ToolGrant(engagement_id=eng.id, tool_category="vuln", mode="active", requires_manual_approval=approval_required))
    run = ScanRun(engagement_id=eng.id, phase="agent", state="running", attempt=1)
    db.add(run)
    db.commit()
    db.refresh(eng)
    db.refresh(run)
    return owner, eng, run


def _get_call(eng, run, **over) -> ToolCall:
    base = dict(engagement_id=eng.id, tool="http_request", category="vuln", mode="active", target=HOST,
                args={"method": "GET", "path": "/", "headers": {"Host": "3.74.27.213"}}, is_automated=True, phase="agent",
                rationale=REASON, scan_run_id=run.id)
    base.update(over)
    return ToolCall(**base)


def _audit_rows(db, eng, action="tool_call"):
    db.expire_all()
    return list(db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id, AuditLog.action == action)))


# ------------------------------------------------------------- the wire schema bounds and redacts


def test_the_reason_is_cut_to_a_fixed_length_and_secrets_are_masked():
    body = ToolCallIn(tool="http_request", category="vuln", mode="active", target=HOST,
                      rationale="x" * (MAX_REASON_CHARS + 500))
    assert len(body.rationale) == MAX_REASON_CHARS
    secret = "Sent Authorization: Bearer abcdef0123456789 and Cookie: session=SECRETVALUE, token eyJhbGciOiJIUzI1NiJ9.aaaaaaaaaaaaaaaa.bbbb"
    cleaned = ToolCallIn(tool="http_request", category="vuln", mode="active", target=HOST, rationale=secret).rationale
    assert "abcdef0123456789" not in cleaned and "SECRETVALUE" not in cleaned and "eyJhbGci" not in cleaned
    assert "<redacted>" in cleaned


def test_the_risk_text_is_bounded_and_redacted_too_and_other_fields_are_left_alone():
    body = ToolCallIn(tool="http_request", category="vuln", mode="active", target=HOST,
                      risk={"level": "low", "description": "uses password=hunter2 " + "y" * 3000})
    assert body.risk["level"] == "low" and "hunter2" not in body.risk["description"] and len(body.risk["description"]) <= MAX_REASON_CHARS
    assert ToolCallIn(tool="t", category="vuln", mode="active", target=HOST).rationale is None
    assert ToolCallIn(tool="t", category="vuln", mode="active", target=HOST, risk=None).risk is None


# ------------------------------------------------------------- the approval and the audit row carry the reason


def test_a_get_that_needs_approval_stores_the_agents_reason_in_the_approval_and_the_audit_row(db):
    owner, eng, run = _setup(db)
    decision = authorize(db, _get_call(eng, run))
    assert decision.is_pending and decision.approval_request_id is not None
    approval = db.get(ApprovalRequest, decision.approval_request_id)
    assert approval.tool_call["rationale"] == REASON and approval.tool_call["risk"] is None
    pending = [r for r in _audit_rows(db, eng) if r.decision == "PENDING"]
    assert pending and pending[0].payload["rationale"] == REASON


def test_a_get_with_a_reason_is_still_claimed_as_the_exact_call_that_was_approved(client, db):
    owner, eng, run = _setup(db)
    approval_id = authorize(db, _get_call(eng, run)).approval_request_id
    token, _ = auth_service.create_session(db, owner, ip=None, user_agent=None)
    ok = client.post(f"/approvals/{approval_id}/approve", json={}, headers={"Authorization": f"Bearer {token}"})
    assert ok.status_code == 200, ok.text
    claim = client.post(f"/internal/approvals/{approval_id}/claim", headers={"x-asm-internal-token": get_settings().internal_api_token}).json()
    assert claim["allowed"] is True and claim["tool_call"]["rationale"] == REASON


def test_negative_an_approved_get_cannot_be_used_with_another_reason_or_another_path(db):
    owner, eng, run = _setup(db)
    approval_id = authorize(db, _get_call(eng, run)).approval_request_id
    approval = db.get(ApprovalRequest, approval_id)
    approval.state = "approved"
    db.commit()
    changed_reason = authorize(db, _get_call(eng, run, rationale="a different reason"), approved_request_id=approval_id)
    assert changed_reason.allowed is False and changed_reason.reason == "approval_call_mismatch"
    other_path = authorize(db, _get_call(eng, run, args={"method": "GET", "path": "/admin", "headers": {"Host": "3.74.27.213"}}),
                           approved_request_id=approval_id)
    assert other_path.allowed is False and other_path.reason == "approval_call_mismatch"
    assert db.get(ApprovalRequest, approval_id).state == "approved"  # a mismatch uses nothing up


def test_a_call_without_a_reason_stores_none_and_is_still_decided_as_before(db):
    owner, eng, run = _setup(db)
    decision = authorize(db, _get_call(eng, run, rationale=None))
    assert decision.is_pending
    assert db.get(ApprovalRequest, decision.approval_request_id).tool_call["rationale"] is None


def test_over_the_wire_a_long_reason_with_a_secret_is_stored_cut_and_masked(client, db):
    owner, eng, run = _setup(db)
    payload = {"tool": "http_request", "category": "vuln", "mode": "active", "target": HOST, "phase": "agent",
               "args": {"method": "GET", "path": "/"}, "scan_run_id": str(run.id), "is_automated": True,
               "rationale": "Saw Cookie: session=TOPSECRET in the answer. " + "z" * 3000}
    r = client.post(f"/internal/engagements/{eng.id}/gateway/authorize", json=payload,
                    headers={"x-asm-internal-token": get_settings().internal_api_token})
    assert r.status_code == 200 and r.json()["is_pending"] is True
    stored = db.get(ApprovalRequest, uuid.UUID(r.json()["approval_request_id"])).tool_call["rationale"]
    assert len(stored) <= MAX_REASON_CHARS and "TOPSECRET" not in stored and "<redacted>" in stored
