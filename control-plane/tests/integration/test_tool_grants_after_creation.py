"""TC-TOOL-006..008 (GitHub issue #48): tool categories can be granted and taken away
after an engagement has left draft, without resetting a campaign's on/off choices,
and every change is confirmed where it widens authority, refused while a scan runs,
audited and enforced by the gateway on the very next call."""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app import auth_service, scan_readiness
from app.api.engagements import (
    _authorization_config_payload, add_tool_grant, get_engagement_config, list_tool_grants, remove_tool_grant,
)
from app.db.base import get_db
from app.gateway.audit import verify_audit_chain
from app.gateway.authorize import ToolCall, authorize
from app.main import app
from app.models.audit import AuditLog
from app.models.engagement import Engagement, ScopeAsset, ToolApprovalPolicy, ToolGrant
from app.models.scan_run import ScanRun
from app.schemas.engagement import ToolGrantCreate

TARGET = "app.example.test"


def _engagement(db, owner, *, status="active", grants=()):
    """An engagement as if it was created without ticking any tool category."""
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        title="No grants", source="own_domain", status=status,
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
        owner_user_id=owner.id,
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


def _grant(db, eng, user, category="vuln", mode="active", *, confirm=False, manual=()):
    return add_tool_grant(
        eng.id, ToolGrantCreate(tool_category=category, mode=mode, requires_manual_approval=False,
                                manual_tools=list(manual), confirm_widening=confirm), db, user=user)


def _gateway(db, eng, tool="nuclei", category="vuln", mode="active"):
    return authorize(db, ToolCall(engagement_id=eng.id, tool=tool, category=category, mode=mode, target=TARGET))


def _audit(db, eng, action):
    db.expire_all()
    return db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id, AuditLog.action == action)
                      .order_by(AuditLog.ts)).all()


def _grants(db, eng):
    db.expire_all()
    return {(g.tool_category, g.mode) for g in db.scalars(select(ToolGrant).where(ToolGrant.engagement_id == eng.id))}


def _run(db, eng, state="running"):
    now = dt.datetime.now(dt.timezone.utc)
    run = ScanRun(engagement_id=eng.id, phase="fingerprint", state=state, started_at=now, heartbeat_at=now, attempt=1)
    db.add(run)
    db.commit()
    return run


# --- REQ-TOOL-006: grants can be added after creation --------------------------------------

def test_a_category_can_be_granted_after_activation_and_clears_the_readiness_blocker(db, test_user):
    eng = _engagement(db, test_user)
    before = scan_readiness.evaluate(db, eng.id)
    blocker = next(b for b in before.blockers if b.code == "no_active_tool_grant")
    assert blocker.action == "tool_grants", "the blocker says where to fix it"
    assert "Tool grants" in blocker.message

    _grant(db, eng, test_user, "vuln", "active", confirm=True)
    assert not any(b.code == "no_active_tool_grant" for b in scan_readiness.evaluate(db, eng.id).blockers)
    assert _gateway(db, eng).reason != "no_tool_grant"


def test_negative_widening_an_active_engagement_needs_an_explicit_confirmation(db, test_user):
    eng = _engagement(db, test_user)
    with pytest.raises(HTTPException) as exc:
        _grant(db, eng, test_user, "vuln", "active")
    assert exc.value.status_code == 409 and "confirmation_required" in exc.value.detail
    assert _grants(db, eng) == set(), "nothing is written without the confirmation"
    assert _audit(db, eng, "tool_grant_added") == []
    assert _gateway(db, eng).reason == "no_tool_grant"


def test_a_draft_needs_no_confirmation_because_the_wizard_has_nothing_to_widen(db, test_user):
    eng = _engagement(db, test_user, status="draft")
    _grant(db, eng, test_user, "vuln", "active")
    assert ("vuln", "active") in _grants(db, eng)


def test_a_passive_grant_and_a_repeated_save_of_an_existing_grant_are_not_widening(db, test_user):
    eng = _engagement(db, test_user, grants=[("vuln", "active")])
    _grant(db, eng, test_user, "recon", "passive")          # OSINT only
    _grant(db, eng, test_user, "vuln", "active")            # already granted: same authority
    assert {("recon", "passive"), ("vuln", "active")} <= _grants(db, eng)
    assert [a.payload["confirmed_widening"] for a in _audit(db, eng, "tool_grant_added")] == [False, False]


def test_negative_a_grant_with_an_unknown_category_or_mode_is_rejected_before_it_reaches_the_database():
    with pytest.raises(ValidationError):
        ToolGrantCreate(tool_category="everything", mode="active")
    with pytest.raises(ValidationError):
        ToolGrantCreate(tool_category="vuln", mode="sometimes")


def test_negative_grants_of_a_completed_or_revoked_engagement_cannot_be_changed(db, test_user):
    for status in ("completed", "revoked"):
        eng = _engagement(db, test_user, status=status, grants=[("vuln", "active")])
        with pytest.raises(HTTPException) as exc:
            _grant(db, eng, test_user, "recon", "passive", confirm=True)
        assert exc.value.status_code == 409
        with pytest.raises(HTTPException) as exc:
            remove_tool_grant(eng.id, "vuln", "active", db, user=test_user)
        assert exc.value.status_code == 409
        assert _grants(db, eng) == {("vuln", "active")}


# --- REQ-TOOL-007: a grant can be removed, and the gateway follows on the next call ----------

def test_a_removed_grant_is_denied_by_the_gateway_from_the_next_call(db, test_user):
    eng = _engagement(db, test_user, grants=[("vuln", "active")])
    assert _gateway(db, eng).allowed
    remove_tool_grant(eng.id, "vuln", "active", db, user=test_user)
    decision = _gateway(db, eng)
    assert not decision.allowed and decision.reason == "no_tool_grant"


def test_removing_a_grant_that_does_not_exist_is_404(db, test_user):
    eng = _engagement(db, test_user)
    with pytest.raises(HTTPException) as exc:
        remove_tool_grant(eng.id, "vuln", "active", db, user=test_user)
    assert exc.value.status_code == 404


def test_negative_force_on_for_a_tool_never_replaces_the_category_grant(db, test_user):
    """A campaign override can only switch a tool inside what the grants allow."""
    eng = _engagement(db, test_user)
    db.add(ToolApprovalPolicy(engagement_id=eng.id, tool_name="nuclei", enabled=True, requires_manual_approval=False))
    db.commit()
    assert _gateway(db, eng).reason == "no_tool_grant"


def test_grants_survive_a_removal_of_another_one(db, test_user):
    eng = _engagement(db, test_user, grants=[("vuln", "active"), ("fingerprint", "active")])
    remove_tool_grant(eng.id, "vuln", "active", db, user=test_user)
    assert _grants(db, eng) == {("fingerprint", "active")}


# --- REQ-TOOL-008: saving grants does not reset campaign switches ------------------------------

def test_resaving_grants_keeps_a_campaign_force_off(db, test_user):
    eng = _engagement(db, test_user, status="draft", grants=[("fingerprint", "active")])
    db.add(ToolApprovalPolicy(engagement_id=eng.id, tool_name="testssl", enabled=False, requires_manual_approval=False))
    db.commit()
    _grant(db, eng, test_user, "fingerprint", "active")          # the "Save tool grants" click
    row = db.get(ToolApprovalPolicy, {"engagement_id": eng.id, "tool_name": "testssl"})
    assert row is not None and row.enabled is False, "the Force off chosen on the Edit page must survive"


def test_resaving_grants_keeps_a_force_on_and_sets_only_the_approval_flag(db, test_user):
    eng = _engagement(db, test_user, status="draft", grants=[("fingerprint", "active")])
    db.add(ToolApprovalPolicy(engagement_id=eng.id, tool_name="httpx", enabled=True, requires_manual_approval=False))
    db.commit()
    _grant(db, eng, test_user, "fingerprint", "active", manual=["httpx", "nmap"])
    db.expire_all()
    httpx_row = db.get(ToolApprovalPolicy, {"engagement_id": eng.id, "tool_name": "httpx"})
    nmap_row = db.get(ToolApprovalPolicy, {"engagement_id": eng.id, "tool_name": "nmap"})
    assert httpx_row.enabled is True and httpx_row.requires_manual_approval is True
    assert nmap_row.enabled is None and nmap_row.requires_manual_approval is True


def test_a_tool_that_no_longer_needs_approval_and_has_no_switch_goes_back_to_the_global_policy(db, test_user):
    eng = _engagement(db, test_user, status="draft", grants=[("fingerprint", "active")])
    db.add(ToolApprovalPolicy(engagement_id=eng.id, tool_name="nmap", requires_manual_approval=True))
    db.commit()
    _grant(db, eng, test_user, "fingerprint", "active", manual=[])
    db.expire_all()
    assert db.get(ToolApprovalPolicy, {"engagement_id": eng.id, "tool_name": "nmap"}) is None


def test_the_grant_list_reports_the_manual_tools_that_were_saved(db, test_user):
    eng = _engagement(db, test_user, status="draft")
    _grant(db, eng, test_user, "fingerprint", "active", manual=["nmap"])
    saved = {(g.tool_category, g.mode): g for g in list_tool_grants(eng.id, db)}
    assert saved[("fingerprint", "active")].manual_tools == ["nmap"]


# --- scan running --------------------------------------------------------------------------------

def test_negative_nothing_is_added_while_a_scan_is_running_and_nothing_is_written(db, test_user):
    eng = _engagement(db, test_user, grants=[("fingerprint", "active")])
    _run(db, eng)
    with pytest.raises(HTTPException) as exc:
        _grant(db, eng, test_user, "vuln", "active", confirm=True)
    assert exc.value.status_code == 409 and "scan_run_active" in exc.value.detail
    with pytest.raises(HTTPException):
        _grant(db, eng, test_user, "fingerprint", "active", manual=["nmap"])  # a change is an addition too
    assert _grants(db, eng) == {("fingerprint", "active")}
    assert _audit(db, eng, "tool_grant_added") == []


def test_a_grant_can_be_removed_while_a_scan_is_running_and_the_next_call_is_denied(db, test_user):
    eng = _engagement(db, test_user, grants=[("vuln", "active")])
    _run(db, eng, "waiting_approval")
    remove_tool_grant(eng.id, "vuln", "active", db, user=test_user)
    assert _gateway(db, eng).reason == "no_tool_grant"
    assert _audit(db, eng, "tool_grant_removed")[0].payload["scan_run_active"] is True


def test_a_finished_scan_does_not_block_adding_a_grant(db, test_user):
    eng = _engagement(db, test_user)
    _run(db, eng, "done")
    _grant(db, eng, test_user, "vuln", "active", confirm=True)


# --- audit -----------------------------------------------------------------------------------------

def test_every_add_and_remove_is_audited_with_actor_category_mode_and_the_kind_of_change(db, test_user):
    eng = _engagement(db, test_user)
    _grant(db, eng, test_user, "vuln", "active", confirm=True, manual=["nuclei"])
    remove_tool_grant(eng.id, "vuln", "active", db, user=test_user)

    added = _audit(db, eng, "tool_grant_added")[0]
    assert added.actor == f"user:{test_user.email}" and added.decision == "ALLOW"
    assert added.payload["tool_category"] == "vuln" and added.payload["mode"] == "active"
    assert added.payload["manual_tools"] == ["nuclei"] and added.payload["confirmed_widening"] is True
    assert added.payload["engagement_status"] == "active"
    removed = _audit(db, eng, "tool_grant_removed")[0]
    assert removed.actor == f"user:{test_user.email}"
    assert removed.payload["tool_category"] == "vuln" and removed.payload["mode"] == "active"
    assert verify_audit_chain(db, eng.id).ok


# --- export ------------------------------------------------------------------------------------------

def test_the_authorization_export_shows_the_current_grants_and_campaign_switches(db, test_user):
    eng = _engagement(db, test_user, grants=[("fingerprint", "active")])
    db.add(ToolApprovalPolicy(engagement_id=eng.id, tool_name="testssl", enabled=False, requires_manual_approval=False))
    db.commit()
    _grant(db, eng, test_user, "vuln", "active", confirm=True)
    remove_tool_grant(eng.id, "fingerprint", "active", db, user=test_user)

    assets = db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id)).all()
    grants = db.scalars(select(ToolGrant).where(ToolGrant.engagement_id == eng.id)).all()
    policies = db.scalars(select(ToolApprovalPolicy).where(ToolApprovalPolicy.engagement_id == eng.id)).all()
    payload = _authorization_config_payload(eng, assets, grants, policies)
    assert [(g["category"], g["mode"]) for g in payload["tool_grants"]] == [("vuln", "active")]
    assert payload["campaign_tool_switches"] == [{"tool": "testssl", "enabled": False}]


# --- why a tool cannot run -----------------------------------------------------------------------------

def test_the_config_says_why_a_tool_is_not_available(db, test_user):
    eng = _engagement(db, test_user, grants=[("fingerprint", "active")])
    db.add(ToolApprovalPolicy(engagement_id=eng.id, tool_name="testssl", enabled=False, requires_manual_approval=False))
    db.commit()
    tools = {t["tool"]: t for t in get_engagement_config(eng.id, db)["tools"]}

    assert tools["nuclei"]["granted"] is False and tools["nuclei"]["unavailable_reason"] == "category_not_granted"
    assert tools["httpx"]["granted"] is True and tools["httpx"]["unavailable_reason"] is None
    assert tools["testssl"]["granted"] is True and tools["testssl"]["unavailable_reason"] == "off_for_campaign"
    not_installed = [t for t in tools.values() if not t["installed"]]
    assert not_installed and all(t["unavailable_reason"] == "not_installed" for t in not_installed)


def test_a_passive_tool_needs_the_passive_grant_not_the_active_one(db, test_user):
    eng = _engagement(db, test_user, grants=[("recon", "active")])
    assert {t["tool"]: t for t in get_engagement_config(eng.id, db)["tools"]}["subfinder"]["granted"] is False
    _grant(db, eng, test_user, "recon", "passive")
    assert {t["tool"]: t for t in get_engagement_config(eng.id, db)["tools"]}["subfinder"]["granted"] is True


# --- over HTTP: ownership (REQ-IAM-007) ----------------------------------------------------------------

def _client(engine) -> TestClient:
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def _override_get_db():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _override_get_db
    return TestClient(app)


def _token(db, user):
    return {"Authorization": f"Bearer {auth_service.create_session(db, user, ip=None, user_agent=None)[0]}"}


def test_negative_a_non_owner_can_neither_add_nor_remove_a_grant(engine, db, test_user):
    from app.models.user import User
    from app.passwords import hash_secret

    other = User(email="intruder@example.com", display_name="Other", role="operator", status="active",
                 must_change_password=False, password_hash=hash_secret("irrelevant-not-used"))
    db.add(other)
    db.commit()
    eng = _engagement(db, test_user, grants=[("vuln", "active")])
    client = _client(engine)
    try:
        headers = _token(db, other)
        added = client.post(f"/engagements/{eng.id}/tool-grants", headers=headers,
                            json={"tool_category": "recon", "mode": "active", "confirm_widening": True})
        removed = client.delete(f"/engagements/{eng.id}/tool-grants/vuln/active", headers=headers)
        # REQ-IAM-023: the engagement is readable by everyone, so a refused change is 403.
        assert added.status_code == 403 and removed.status_code == 403
        assert client.get(f"/engagements/{eng.id}/tool-grants", headers=headers).status_code == 200
    finally:
        app.dependency_overrides.clear()
    assert _grants(db, eng) == {("vuln", "active")}
    assert _audit(db, eng, "tool_grant_added") == [] and _audit(db, eng, "tool_grant_removed") == []


def test_the_owner_and_an_admin_can_add_and_remove_a_grant_over_http(engine, db, test_user, admin_user):
    eng = _engagement(db, test_user)
    client = _client(engine)
    try:
        created = client.post(f"/engagements/{eng.id}/tool-grants", headers=_token(db, test_user),
                              json={"tool_category": "vuln", "mode": "active", "confirm_widening": True})
        assert created.status_code == 201
        assert client.delete(f"/engagements/{eng.id}/tool-grants/vuln/active", headers=_token(db, admin_user)).status_code == 204
        assert client.delete(f"/engagements/{eng.id}/tool-grants/vuln/active", headers=_token(db, test_user)).status_code == 404
        bad = client.post(f"/engagements/{eng.id}/tool-grants", headers=_token(db, test_user),
                          json={"tool_category": "everything", "mode": "active"})
        assert bad.status_code == 422
        assert client.delete(f"/engagements/{eng.id}/tool-grants/everything/active", headers=_token(db, test_user)).status_code == 422
    finally:
        app.dependency_overrides.clear()
    assert [a.actor for a in _audit(db, eng, "tool_grant_removed")] == [f"user:{admin_user.email}"]
