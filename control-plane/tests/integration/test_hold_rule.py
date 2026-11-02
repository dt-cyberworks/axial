"""REQ-MODE-008 (GitHub #79): a held host gets no request from anything until the owner releases it.

Found on int (2026-10-20): the Vector Agent saw a held host in its list of targets, called it a coverage gap, and the
gateway let five requests through. The pipeline respected the hold; the agent and the gateway did not. Part A: the
worker's views leave held hosts out. Part B: the gateway denies an active call to a held host (`asset_held_for_review`),
before any approval, so an approval can never override it."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.db.base import get_db
from app.gateway import dns_materialization, hold_rule
from app.gateway.authorize import ToolCall, authorize
from app.main import app
from app.models.approval import ApprovalRequest
from app.models.asset import DiscoveredAsset
from app.models.audit import AuditLog
from app.models.engagement import Engagement, ScopeAsset, ToolGrant
from app.models.resolved_host import ResolvedHost
from app.models.scan_run import ScanRun
from app.models.user import User
from app.passwords import hash_secret

NOW = dt.datetime.now(dt.timezone.utc)
HELD = "dev.example.test"
FREE = "www.example.test"


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


def _owner(db) -> User:
    user = User(email=f"u-{uuid.uuid4().hex[:10]}@example.com", display_name="U", role="operator", status="active",
                must_change_password=False, password_hash=hash_secret("x"))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _engagement(db, owner, *, mode="monitoring", approval=False):
    eng = Engagement(title="E", source="own_domain", status="active", operating_mode=mode, ai_testing_allowed=True,
                     authorized_from=NOW - dt.timedelta(hours=1), authorized_until=NOW + dt.timedelta(days=30),
                     owner_user_id=owner.id, target_review_state="confirmed" if mode == "monitoring" else None)
    db.add(eng)
    db.flush()
    db.add(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain", value="example.test",
                      active_allowed=True, authorization_verified=True))
    for category in ("vuln", "fingerprint"):
        db.add(ToolGrant(engagement_id=eng.id, tool_category=category, mode="active", requires_manual_approval=approval))
    run = ScanRun(engagement_id=eng.id, phase="agent", state="running", attempt=1)
    db.add(run)
    db.commit()
    db.refresh(eng)
    db.refresh(run)
    return eng, run


def _asset(db, eng, value, *, held=False) -> DiscoveredAsset:
    asset = DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value=value, in_scope=True, discovered_via="ct",
                            first_seen=NOW - dt.timedelta(days=3))
    if held:
        asset.hold_state, asset.held_at = "held", NOW - dt.timedelta(days=1)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def _get(eng, run, target, *, phase="agent", tool="http_request", args=None, category="vuln", **kw) -> ToolCall:
    return ToolCall(engagement_id=eng.id, tool=tool, category=category, mode="active", target=target,
                    args=args if args is not None else {"method": "GET", "path": "/"}, is_automated=True, phase=phase,
                    scan_run_id=run.id, **kw)


def _internal() -> dict:
    return {"x-asm-internal-token": get_settings().internal_api_token}


# ------------------------------------------------------------- Part B: the gateway rule


def test_an_agent_request_to_a_held_host_is_denied_and_audited(db):
    eng, run = _engagement(db, _owner(db))
    _asset(db, eng, HELD, held=True)
    decision = authorize(db, _get(eng, run, HELD))
    assert decision.allowed is False and decision.reason == "asset_held_for_review" and not decision.is_pending
    rows = list(db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id, AuditLog.action == "tool_call")))
    assert [(r.decision, r.reason) for r in rows] == [("DENY", "asset_held_for_review")]


@pytest.mark.parametrize("tool, category, args, phase", [
    ("http_request", "vuln", {"method": "GET", "path": "/"}, "agent"),
    ("http_request", "vuln", {"method": "POST", "path": "/login", "body": "a=1"}, "agent"),
    ("ffuf", "vuln", {"wordlist": "quickhits", "path": "/FUZZ"}, "agent"),
    ("httpx", "fingerprint", {}, "fingerprint"),
    ("nuclei", "vuln", {"mode": "takeover"}, "fingerprint"),
    ("testssl", "fingerprint", {}, "fingerprint"),
])
def test_every_active_tool_is_denied_for_a_held_host_in_the_agent_and_the_pipeline_phase(db, tool, category, args, phase):
    eng, run = _engagement(db, _owner(db), approval=True)  # approval is required: still no request is created
    _asset(db, eng, HELD, held=True)
    call = _get(eng, run, HELD, tool=tool, category=category, args=args, phase=phase,
                rationale="r", risk={"level": "low", "description": "d"})
    decision = authorize(db, call)
    assert decision.reason == "asset_held_for_review" and decision.allowed is False and decision.is_pending is False
    assert db.scalar(select(ApprovalRequest).where(ApprovalRequest.engagement_id == eng.id)) is None


def test_negative_an_approval_cannot_override_the_hold(db):
    eng, run = _engagement(db, _owner(db), approval=True)
    asset = _asset(db, eng, HELD)  # released at the time of the request
    pending = authorize(db, _get(eng, run, HELD, rationale="r"))
    assert pending.is_pending and pending.approval_request_id is not None
    approval = db.get(ApprovalRequest, pending.approval_request_id)
    approval.state = "approved"
    asset.hold_state = "held"  # held again before the approved request runs
    db.commit()
    claimed = authorize(db, _get(eng, run, HELD, rationale="r"), approved_request_id=approval.id)
    assert claimed.allowed is False and claimed.reason == "asset_held_for_review"
    assert db.get(ApprovalRequest, approval.id).state == "approved"  # nothing was consumed


def test_a_released_host_passes_the_rule(db):
    eng, run = _engagement(db, _owner(db))
    asset = _asset(db, eng, HELD, held=True)
    assert authorize(db, _get(eng, run, HELD)).reason == "asset_held_for_review"
    asset.hold_state = "released"
    db.commit()
    assert authorize(db, _get(eng, run, HELD)).allowed is True


def test_another_host_of_the_engagement_and_a_lookalike_name_are_not_affected(db):
    eng, run = _engagement(db, _owner(db))
    _asset(db, eng, HELD, held=True)
    _asset(db, eng, FREE)
    assert authorize(db, _get(eng, run, FREE)).allowed is True
    assert authorize(db, _get(eng, run, "xdev.example.test")).reason != "asset_held_for_review"
    assert authorize(db, _get(eng, run, "dev.example.test.evil.test")).reason == "target_out_of_scope"


def test_a_host_of_the_same_name_held_in_another_engagement_is_not_affected(db):
    owner = _owner(db)
    eng_a, run_a = _engagement(db, owner)
    eng_b, run_b = _engagement(db, owner)
    _asset(db, eng_a, HELD, held=True)
    _asset(db, eng_b, HELD)
    assert authorize(db, _get(eng_a, run_a, HELD)).reason == "asset_held_for_review"
    assert authorize(db, _get(eng_b, run_b, HELD)).allowed is True


def test_an_assessment_has_no_held_hosts_and_is_not_affected(db):
    eng, run = _engagement(db, _owner(db), mode="assessment")
    _asset(db, eng, HELD)
    assert authorize(db, _get(eng, run, HELD)).allowed is True


@pytest.mark.parametrize("target", ["dev.example.test", "DEV.Example.Test", "dev.example.test."])
def test_case_and_a_trailing_dot_name_the_held_host(db, target):
    eng, run = _engagement(db, _owner(db))
    _asset(db, eng, HELD, held=True)
    decision = authorize(db, _get(eng, run, target))
    assert decision.reason == "asset_held_for_review", (target, decision.reason)


@pytest.mark.parametrize("target", [
    "dev.example.test:8443", "DEV.EXAMPLE.TEST.:443", "https://dev.example.test/login?x=1", "http://user:pw@dev.example.test:8080/a#f",
])
def test_port_and_url_forms_name_the_held_host_and_are_never_allowed(db, target):
    """The scope step does not accept these forms as a target at all (they are denied there). The hold rule still
    names the same host for each of them, so that a future widening of the scope step cannot open a way around it."""
    eng, run = _engagement(db, _owner(db))
    _asset(db, eng, HELD, held=True)
    assert hold_rule.normalize_host(target) == HELD
    assert hold_rule.is_held_host(db, eng.id, target) is True
    decision = authorize(db, _get(eng, run, target))
    assert decision.allowed is False and decision.reason in ("target_out_of_scope", "asset_held_for_review")


def test_a_held_host_stored_in_another_case_or_with_a_trailing_dot_is_still_held(db):
    """Names are stored as discovered; the rule compares them case-insensitively and without a trailing dot."""
    eng, run = _engagement(db, _owner(db))
    _asset(db, eng, "Dev.Example.Test.", held=True)
    for target in ("dev.example.test", "DEV.EXAMPLE.TEST", "dev.example.test."):
        assert authorize(db, _get(eng, run, target)).reason == "asset_held_for_review", target


def test_normalizing_leaves_an_ip_literal_and_a_bare_ipv6_alone():
    assert hold_rule.normalize_host("203.0.113.7:8080") == "203.0.113.7"
    assert hold_rule.normalize_host("[2001:db8::1]:443") == "2001:db8::1"
    assert hold_rule.normalize_host("2001:db8::1") == "2001:db8::1"
    assert hold_rule.normalize_host("") == ""


def test_a_passive_call_is_not_blocked_by_the_rule(db):
    """The rule is about active calls: a passive source never touches the host."""
    eng, run = _engagement(db, _owner(db))
    _asset(db, eng, HELD, held=True)
    db.add(ToolGrant(engagement_id=eng.id, tool_category="recon", mode="passive", requires_manual_approval=False))
    db.commit()
    call = ToolCall(engagement_id=eng.id, tool="subfinder", category="recon", mode="passive", target="example.test",
                    args={}, scan_run_id=run.id)
    assert authorize(db, call).reason != "asset_held_for_review"


# ------------------------------------------------------------- Part A: the worker's views


def test_the_agents_host_list_and_context_leave_held_hosts_out(client, db):
    eng, run = _engagement(db, _owner(db))
    held, free = _asset(db, eng, HELD, held=True), _asset(db, eng, FREE)
    everything = client.get(f"/internal/engagements/{eng.id}/discovered-assets", params={"in_scope": "true"}, headers=_internal()).json()
    assert {a["value"] for a in everything} == {HELD, FREE}  # the default is unchanged
    assert {a["value"]: a["hold_state"] for a in everything}[HELD] == "held"
    narrowed = client.get(f"/internal/engagements/{eng.id}/discovered-assets",
                          params={"in_scope": "true", "exclude_held": "true"}, headers=_internal()).json()
    assert [a["value"] for a in narrowed] == [FREE]
    context = client.get(f"/internal/engagements/{eng.id}/agent-context", headers=_internal()).json()
    assert [h["host"] for h in context["hosts"]] == [FREE]
    held.hold_state = "released"
    db.commit()
    again = client.get(f"/internal/engagements/{eng.id}/agent-context", headers=_internal()).json()
    assert {h["host"] for h in again["hosts"]} == {HELD, FREE}  # a released host is back on the list


def test_a_held_host_is_not_resolved_for_the_run_and_a_released_one_is(db, monkeypatch):
    monkeypatch.setattr(dns_materialization, "_resolve", lambda name: ["203.0.113.9"])
    eng, run = _engagement(db, _owner(db))
    held = _asset(db, eng, HELD, held=True)
    _asset(db, eng, FREE)
    dns_materialization.materialize(db, eng.id, scan_run_id=run.id)
    names = {r.hostname for r in db.scalars(select(ResolvedHost).where(ResolvedHost.engagement_id == eng.id))}
    assert FREE in names and HELD not in names
    held.hold_state = "released"
    db.commit()
    dns_materialization.materialize(db, eng.id, scan_run_id=run.id)
    assert HELD in {r.hostname for r in db.scalars(select(ResolvedHost).where(ResolvedHost.engagement_id == eng.id))}
