"""REQ-HANDOVER-001..008 (GitHub #84): a deeper test of a monitored target starts from the monitor.

One action on a monitor creates a DRAFT assessment with what the monitor knows filled in, links the two, and gives the
assessment's agent a read-only summary of what monitoring found. It authorizes nothing: every test that names something
"never carried over" asserts it on the created rows, with the monitor set to a non-default value so that a copy would show."""

from __future__ import annotations

import datetime as dt
import json
import types
import uuid
from unittest import mock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from app import auth_service
from app import handover as handover_module
from app.config import get_settings
from app.db.base import get_db
from app.gateway.authorize import _matching_rules
from app.main import app
from app.models.asset import DiscoveredAsset, Service
from app.models.audit import AuditLog
from app.models.engagement import Customer, Engagement, ScopeAsset, ToolApprovalPolicy, ToolGrant
from app.models.finding import Finding
from app.models.monitoring import NotificationTarget, RunInventorySnapshot
from app.models.scan_run import ScanRun
from app.models.user import User
from app.passwords import hash_secret

NOW = dt.datetime.now(dt.timezone.utc)
WIN_FROM, WIN_UNTIL = NOW + dt.timedelta(days=1), NOW + dt.timedelta(days=8)


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


def _user(db, name, role="operator") -> User:
    u = User(email=f"{name}-{uuid.uuid4().hex[:8]}@example.com", display_name=name.title(), role=role, status="active",
             must_change_password=False, password_hash=hash_secret("x"))
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def _auth(db, user) -> dict:
    token, _ = auth_service.create_session(db, user, ip=None, user_agent=None)
    return {"Authorization": f"Bearer {token}"}


def _internal() -> dict:
    return {"x-asm-internal-token": get_settings().internal_api_token}


def _scope(db, eng, rule, kind, value, **kw):
    db.add(ScopeAsset(engagement_id=eng.id, rule=rule, asset_type=kind, value=value,
                      active_allowed=rule == "allow", authorization_verified=rule == "allow",
                      authorization_method="owner_attestation" if rule == "allow" else None, **kw))


def _asset(db, eng, value, *, kind="domain", held=False, in_scope=True) -> DiscoveredAsset:
    a = DiscoveredAsset(engagement_id=eng.id, asset_type=kind, value=value, in_scope=in_scope, discovered_via="ct",
                        first_seen=NOW - dt.timedelta(days=5), last_seen=NOW - dt.timedelta(days=2))
    if held:
        a.hold_state, a.held_at = "held", NOW - dt.timedelta(days=3)
    db.add(a)
    db.flush()
    return a


def _finding(db, eng, asset, title, *, severity="low", status="open", service=None, evidence=None):
    db.add(Finding(engagement_id=eng.id, asset_id=asset.id, service_id=service.id if service else None,
                   category="misconfig", title=title, confidence="validated", severity=severity, status=status,
                   evidence=evidence or {}, fingerprint=f"{asset.value}|{title}|{uuid.uuid4().hex[:6]}"))


@pytest.fixture
def world(db):
    owner, other, admin = _user(db, "owner"), _user(db, "other"), _user(db, "admin", "admin")
    customer = Customer(name="Sirkos GmbH", contact_email="it@sirkos.example.test")
    db.add(customer)
    db.flush()
    # A monitor with a NON-DEFAULT value in every field the handover must not carry.
    mon = Engagement(
        title="Sirkos Application", source="own_domain", status="active", operating_mode="monitoring",
        customer_id=customer.id, emergency_contact="oncall@sirkos.example.test", owner_user_id=owner.id,
        authorized_from=NOW - dt.timedelta(days=10), authorized_until=NOW + dt.timedelta(days=355),
        tcp_port_from=1, tcp_port_to=10000, ai_testing_allowed=False, scan_profile="light",
        scope_doc_sha256="a" * 64, scope_signed_by="Sirkos CEO", scope_signed_at=NOW - dt.timedelta(days=9),
        review_at=NOW + dt.timedelta(days=300), state_changing_requests=True, fragility_breaker=False,
        schedule_every_days=7, schedule_set_at=NOW - dt.timedelta(days=1), new_asset_policy="hold",
        agent_prompt_override="monitor prompt", agent_max_iterations_override=50, agent_max_tokens_override=4096,
        approval_timeout_seconds_override=120, subfinder_enabled=False, crawling_enabled=True, oob_enabled=True,
        screenshots_enabled=True, udp_discovery_enabled=True, asset_review_enabled=False,
        target_review_state="confirmed", targets_confirmed_at=NOW - dt.timedelta(days=8), targets_confirmed_by="owner",
    )
    db.add(mon)
    db.flush()
    _scope(db, mon, "allow", "domain", "example.test", port_from=443, port_to=8443, path_pattern="/app/*")
    _scope(db, mon, "allow", "ip", "203.0.113.10")
    _scope(db, mon, "deny", "domain", "secret.example.test")
    _scope(db, mon, "deny", "ip", "203.0.113.99")
    db.add(ToolGrant(engagement_id=mon.id, tool_category="fingerprint", mode="active", requires_manual_approval=False))
    db.add(ToolGrant(engagement_id=mon.id, tool_category="recon", mode="passive", requires_manual_approval=False))
    db.add(ToolApprovalPolicy(engagement_id=mon.id, tool_name="nuclei", requires_manual_approval=True, enabled=True))
    db.add(NotificationTarget(engagement_id=mon.id, kind="webhook", url="https://hooks.example.test/x", min_severity="high"))
    www = _asset(db, mon, "www.example.test")
    dev = _asset(db, mon, "dev.example.test", held=True)
    _asset(db, mon, "203.0.113.10", kind="ip")
    _asset(db, mon, "elsewhere.other.test", in_scope=False)
    s443 = Service(asset_id=www.id, port=443, protocol="tcp", product="nginx", version="1.25.3")
    db.add(s443)
    db.flush()
    _finding(db, mon, www, "Missing HSTS", service=s443, evidence={"secret": "SESSION=abc123"})
    _finding(db, mon, www, "Old finding that was fixed", status="resolved")
    _finding(db, mon, dev, "Admin panel exposed", severity="medium")
    good = ScanRun(engagement_id=mon.id, phase="report", state="done", health="ok", trigger="scheduled",
                   started_at=NOW - dt.timedelta(days=2), finished_at=NOW - dt.timedelta(days=2) + dt.timedelta(minutes=9))
    bad = ScanRun(engagement_id=mon.id, phase="report", state="done", health="degraded", trigger="scheduled",
                  started_at=NOW - dt.timedelta(days=1), finished_at=NOW - dt.timedelta(days=1) + dt.timedelta(minutes=2))
    db.add_all([good, bad])
    db.flush()
    for run, rows in ((good, [("www.example.test:443/tcp", "nginx", "1.25.3"), ("www.example.test:80/tcp", "nginx", "1.25.3"),
                              ("dev.example.test:8080/tcp", "express", "4.18")]),
                      (bad, [("www.example.test:9999/tcp", "ghost", "0")])):
        for key, product, version in rows:
            db.add(RunInventorySnapshot(scan_run_id=run.id, kind="service", key=key, engagement_id=mon.id,
                                        data={"product": product, "version": version}))
    db.commit()
    return types.SimpleNamespace(owner=owner, other=other, admin=admin, mon=mon, customer=customer, www=www, dev=dev)


def _body(**over):
    body = {"authorized_from": WIN_FROM.isoformat(), "authorized_until": WIN_UNTIL.isoformat(), "hosts": ["www.example.test"]}
    body.update(over)
    return body


def _start(client, db, world, who=None, **over):
    return client.post(f"/engagements/{world.mon.id}/handover", headers=_auth(db, who or world.owner), json=_body(**over))


def _created(db, response) -> Engagement:
    assert response.status_code == 201, response.text
    db.expire_all()
    return db.get(Engagement, uuid.UUID(response.json()["id"]))


def _count(db, model=Engagement) -> int:
    return db.scalar(select(func.count()).select_from(model))


# ============================================================ REQ-HANDOVER-001: who, from what, audited


def test_the_owner_creates_a_draft_assessment_linked_to_the_monitor(client, db, world):
    r = _start(client, db, world)
    eng = _created(db, r)
    assert eng.operating_mode == "assessment" and eng.status == "draft"
    assert eng.owner_user_id == world.owner.id and eng.handover_from_id == world.mon.id
    assert eng.title == "Test: Sirkos Application"
    assert eng.authorized_from == WIN_FROM and eng.authorized_until == WIN_UNTIL
    assert eng.customer_id == world.customer.id and eng.emergency_contact == "oncall@sirkos.example.test"
    assert (eng.tcp_port_from, eng.tcp_port_to) == (1, 10000)
    assert eng.source == "own_domain"


def test_an_administrator_may_start_it_and_becomes_the_owner_of_the_draft(client, db, world):
    eng = _created(db, _start(client, db, world, who=world.admin, title="Deep test"))
    assert eng.owner_user_id == world.admin.id and eng.title == "Deep test"


def test_negative_another_operator_may_read_but_not_start_it_and_nothing_is_created(client, db, world):
    before = _count(db)
    r = _start(client, db, world, who=world.other)
    assert r.status_code == 403
    assert _count(db) == before
    assert client.get(f"/engagements/{world.mon.id}", headers=_auth(db, world.other)).status_code == 200


def test_negative_the_handler_refuses_a_non_owner_by_itself_not_only_through_the_router(db, world):
    """A second layer: called directly, without the router's ownership dependency, the handler still says 403."""
    from fastapi import HTTPException

    from app.api.engagements import start_handover
    from app.schemas.handover import HandoverIn

    body = HandoverIn(authorized_from=WIN_FROM, authorized_until=WIN_UNTIL, hosts=["www.example.test"])
    before = _count(db)
    with pytest.raises(HTTPException) as post:
        start_handover(world.mon.id, body, db=db, user=world.other)
    assert post.value.status_code == 403
    assert _count(db) == before


def test_negative_without_a_session_it_is_401(client, db, world):
    assert client.post(f"/engagements/{world.mon.id}/handover", json=_body()).status_code == 401


@pytest.mark.parametrize("status, ok", [("active", True), ("paused", True), ("draft", False), ("completed", False),
                                         ("revoked", False)])
def test_only_an_active_or_paused_monitor_can_be_the_source(client, db, world, status, ok):
    """A revoked authorization must not seed a new engagement."""
    world.mon.status = status
    db.commit()
    r = _start(client, db, world)
    assert r.status_code == (201 if ok else 409), r.text
    if not ok:
        assert r.json()["detail"] == "handover_monitor_not_active"


def test_negative_an_assessment_is_not_a_source(client, db, world):
    plain = Engagement(title="Plain assessment", source="own_domain", status="active", operating_mode="assessment",
                       owner_user_id=world.owner.id, authorized_from=NOW - dt.timedelta(hours=1),
                       authorized_until=NOW + dt.timedelta(days=1))
    db.add(plain)
    db.commit()
    r = client.post(f"/engagements/{plain.id}/handover", headers=_auth(db, world.owner), json=_body())
    assert r.status_code == 409 and r.json()["detail"] == "handover_monitor_not_active"
    assert client.get(f"/engagements/{plain.id}/handover-preview", headers=_auth(db, world.owner)).status_code == 409


@pytest.mark.parametrize("source", ["bug_bounty"])
def test_negative_a_bug_bounty_source_is_refused(client, db, world, source):
    """The draft would otherwise lose the program's rules: a looser engagement than its origin."""
    world.mon.source = source
    db.commit()
    before = _count(db)
    r = _start(client, db, world)
    assert r.status_code == 409 and r.json()["detail"] == "handover_source_unsupported"
    assert _count(db) == before


@pytest.mark.parametrize("source", ["lab", "customer", "own_domain"])
def test_the_draft_copies_the_monitors_source(client, db, world, source):
    world.mon.source = source
    db.commit()
    assert _created(db, _start(client, db, world)).source == source


def test_negative_a_customer_draft_still_needs_the_signed_scope_document_which_is_not_carried(client, db, world):
    world.mon.source = "customer"
    db.commit()
    eng = _created(db, _start(client, db, world))
    assert (eng.scope_doc_sha256, eng.scope_signed_by, eng.scope_signed_at) == (None, None, None)
    headers = _auth(db, world.owner)
    for row in db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id, ScopeAsset.rule == "allow")):
        assert client.post(f"/engagements/{eng.id}/scope-assets/{row.id}/verify-authorization", headers=headers,
                           json={"method": "operator_attestation"}).status_code == 200
    r = client.post(f"/engagements/{eng.id}/activate", headers=headers)
    assert r.status_code == 409, r.text
    db.expire_all()
    assert db.get(Engagement, eng.id).status == "draft"


def test_more_than_one_assessment_may_start_from_one_monitor(client, db, world):
    a, b = _created(db, _start(client, db, world)), _created(db, _start(client, db, world))
    assert a.id != b.id and a.handover_from_id == b.handover_from_id == world.mon.id


def test_the_handover_is_audited_on_both_engagements(client, db, world):
    eng = _created(db, _start(client, db, world))
    rows = {(r.engagement_id, r.action): r for r in db.scalars(select(AuditLog))}
    on_monitor = rows[(world.mon.id, "handover_created")]
    on_new = rows[(eng.id, "handover_source")]
    assert on_monitor.payload["assessment_id"] == str(eng.id) and on_monitor.actor.endswith(world.owner.email)
    assert on_new.payload["monitor_id"] == str(world.mon.id) and on_new.payload["scope_mode"] == "hosts"
    assert (eng.id, "engagement_created") in rows


def _monitor_state(db, mon):
    db.expire_all()
    return {
        "row": {c.name: getattr(mon, c.name) for c in Engagement.__table__.columns},
        "counts": {m.__name__: db.scalar(select(func.count()).select_from(m).where(m.engagement_id == mon.id))
                   for m in (ScopeAsset, ToolGrant, ToolApprovalPolicy, ScanRun, Finding, DiscoveredAsset, RunInventorySnapshot,
                             NotificationTarget)},
        "audit": sorted(r.action for r in db.scalars(select(AuditLog).where(AuditLog.engagement_id == mon.id))
                        if r.action != "handover_created"),
    }


def test_negative_the_monitor_is_not_changed_and_no_run_starts(client, db, world):
    before, runs_before = _monitor_state(db, world.mon), _count(db, ScanRun)
    eng = _created(db, _start(client, db, world))
    assert _monitor_state(db, world.mon) == before
    assert _count(db, ScanRun) == runs_before
    assert db.scalar(select(func.count()).select_from(ScanRun).where(ScanRun.engagement_id == eng.id)) == 0


# ============================================================ REQ-HANDOVER-002: never carried over


def test_negative_nothing_that_authorizes_anything_is_carried_over(client, db, world):
    eng = _created(db, _start(client, db, world, scope_mode="same_scope", hosts=[]))
    rows = list(db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id)))
    assert rows, "the scope was copied"
    for row in rows:
        assert row.authorization_verified is False and row.authorization_method is None, (row.rule, row.value)
        assert row.active_allowed is False, (row.rule, row.value)
    assert eng.status == "draft"
    assert (eng.scope_doc_sha256, eng.scope_signed_by, eng.scope_signed_at) == (None, None, None)
    assert eng.review_at is None


def test_negative_the_monitors_capabilities_consent_schedule_and_overrides_are_not_carried_over(client, db, world):
    eng = _created(db, _start(client, db, world))
    assert eng.state_changing_requests is False and eng.fragility_breaker is True
    assert eng.schedule_every_days is None and eng.schedule_set_at is None and eng.schedule_anchor_at is None
    assert eng.new_asset_policy == "auto"
    assert (eng.target_review_state, eng.target_review_run_id, eng.targets_confirmed_at, eng.targets_confirmed_by) == \
        (None, None, None, None)
    assert (eng.agent_prompt_override, eng.agent_max_iterations_override, eng.agent_max_tokens_override,
            eng.approval_timeout_seconds_override) == (None, None, None, None)
    # The discovery switches are the defaults of a new assessment, not the monitor's.
    assert (eng.subfinder_enabled, eng.crawling_enabled, eng.oob_enabled, eng.screenshots_enabled,
            eng.udp_discovery_enabled, eng.asset_review_enabled) == (True, False, False, False, False, False)


def test_negative_no_tool_grant_policy_notification_run_finding_or_inventory_is_copied(client, db, world):
    eng = _created(db, _start(client, db, world))
    for model in (ToolGrant, ToolApprovalPolicy, NotificationTarget, ScanRun, Finding, DiscoveredAsset, Service,
                  RunInventorySnapshot):
        if hasattr(model, "engagement_id"):
            n = db.scalar(select(func.count()).select_from(model).where(model.engagement_id == eng.id))
            assert n == 0, f"{model.__name__} was copied to the new engagement"


# ============================================================ REQ-HANDOVER-003: hosts, window, deny


def test_the_chosen_hosts_become_allow_rows_of_their_own_with_no_path_and_nothing_attested(client, db, world):
    eng = _created(db, _start(client, db, world, hosts=["www.example.test", "203.0.113.10", "WWW.Example.Test."]))
    allow = sorted((r.asset_type, r.value) for r in db.scalars(
        select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id, ScopeAsset.rule == "allow")))
    assert allow == [("domain", "www.example.test"), ("ip", "203.0.113.10")], "normalized, de-duplicated, typed"
    for r in db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id, ScopeAsset.rule == "allow")):
        assert r.path_pattern is None and r.port_from is None and r.port_to is None


def test_the_monitors_deny_rules_are_always_carried(client, db, world):
    eng = _created(db, _start(client, db, world))
    deny = sorted((r.asset_type, r.value) for r in db.scalars(
        select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id, ScopeAsset.rule == "deny")))
    assert deny == [("domain", "secret.example.test"), ("ip", "203.0.113.99")]


def test_negative_a_chosen_host_that_a_deny_rule_matches_is_refused_and_nothing_is_created(client, db, world):
    before = _count(db)
    for host in ("secret.example.test", "203.0.113.99"):
        assert _matching_rules(db, world.mon.id, host, None, "deny"), "the gateway's own matcher denies it"
        r = _start(client, db, world, hosts=["www.example.test", host])
        assert r.status_code == 422 and r.json()["detail"] == "handover_host_denied", (host, r.text)
    assert _count(db) == before


def test_a_subdomain_of_a_deny_rule_is_judged_exactly_as_the_gateway_judges_it(client, db, world):
    host = "x.secret.example.test"
    denied = bool(_matching_rules(db, world.mon.id, host, None, "deny"))
    r = _start(client, db, world, hosts=[host])
    assert (r.status_code == 422) == denied, r.text


def test_negative_a_host_the_monitor_neither_knows_nor_covers_is_refused(client, db, world):
    before = _count(db)
    r = _start(client, db, world, hosts=["www.example.test", "evil.test"])
    assert r.status_code == 422 and r.json()["detail"] == "handover_host_unknown"
    # a discovered asset that the monitor itself marked out of scope is not selectable either
    r2 = _start(client, db, world, hosts=["elsewhere.other.test"])
    assert r2.status_code == 422 and r2.json()["detail"] == "handover_host_unknown"
    assert _count(db) == before


def test_a_host_covered_by_a_monitor_allow_rule_but_not_discovered_is_accepted(client, db, world):
    assert _created(db, _start(client, db, world, hosts=["api.example.test"]))


def test_a_held_host_may_be_chosen_and_the_monitors_hold_is_not_released(client, db, world):
    eng = _created(db, _start(client, db, world, hosts=["dev.example.test"]))
    assert db.scalar(select(func.count()).select_from(ScopeAsset).where(
        ScopeAsset.engagement_id == eng.id, ScopeAsset.value == "dev.example.test")) == 1
    db.expire_all()
    assert db.get(DiscoveredAsset, world.dev.id).hold_state == "held"


def test_same_scope_copies_the_allow_rows_with_their_port_ranges_and_paths(client, db, world):
    eng = _created(db, _start(client, db, world, scope_mode="same_scope", hosts=[]))
    allow = {(r.asset_type, r.value): (r.path_pattern, r.port_from, r.port_to) for r in db.scalars(
        select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id, ScopeAsset.rule == "allow"))}
    assert allow == {("domain", "example.test"): ("/app/*", 443, 8443), ("ip", "203.0.113.10"): (None, None, None)}


@pytest.mark.parametrize("body, code", [
    ({"hosts": []}, "handover_hosts_required"),
    ({"scope_mode": "same_scope", "hosts": ["www.example.test"]}, "handover_hosts_not_allowed"),
])
def test_the_hosts_must_match_the_scope_mode(client, db, world, body, code):
    before = _count(db)
    r = _start(client, db, world, **body)
    assert r.status_code == 422 and r.json()["detail"] == code
    assert _count(db) == before


def test_negative_the_window_is_required_and_must_be_ordered(client, db, world):
    before = _count(db)
    ordered = _start(client, db, world, authorized_from=WIN_UNTIL.isoformat(), authorized_until=WIN_FROM.isoformat())
    assert ordered.status_code == 422 and ordered.json()["detail"] == "handover_window_invalid"
    equal = _start(client, db, world, authorized_from=WIN_FROM.isoformat(), authorized_until=WIN_FROM.isoformat())
    assert equal.status_code == 422 and equal.json()["detail"] == "handover_window_invalid"
    for missing in ("authorized_from", "authorized_until"):
        body = _body()
        body.pop(missing)
        r = client.post(f"/engagements/{world.mon.id}/handover", headers=_auth(db, world.owner), json=body)
        assert r.status_code == 422, missing
    assert _count(db) == before


def test_the_monitors_window_is_not_inherited(client, db, world):
    eng = _created(db, _start(client, db, world))
    assert eng.authorized_until != world.mon.authorized_until and eng.authorized_until == WIN_UNTIL


# ============================================================ REQ-HANDOVER-004: a normal draft, set up for depth


def test_the_draft_is_set_up_for_depth_and_is_not_active(client, db, world):
    eng = _created(db, _start(client, db, world))
    assert eng.scan_profile == "thorough" and eng.ai_testing_allowed is True and eng.status == "draft"


def test_negative_a_draft_from_a_handover_cannot_be_activated_without_attestation(client, db, world):
    """Activation applies every existing rule: the copied scope is not attested, so it refuses."""
    eng = _created(db, _start(client, db, world))
    r = client.post(f"/engagements/{eng.id}/activate", headers=_auth(db, world.owner))
    assert r.status_code == 409, r.text
    db.expire_all()
    assert db.get(Engagement, eng.id).status == "draft"


# ============================================================ REQ-HANDOVER-006: preview and overlap


def test_the_preview_lists_what_the_monitor_knows_and_what_is_carried(client, db, world):
    r = client.get(f"/engagements/{world.mon.id}/handover-preview", headers=_auth(db, world.owner))
    assert r.status_code == 200, r.text
    body = r.json()
    hosts = {h["host"]: h for h in body["hosts"]}
    assert set(hosts) == {"www.example.test", "dev.example.test", "203.0.113.10"}, "out-of-scope discovered hosts are not offered"
    assert hosts["www.example.test"]["held"] is False and hosts["dev.example.test"]["held"] is True
    assert hosts["www.example.test"]["services"] == 2 and hosts["dev.example.test"]["services"] == 1, \
        "only the latest HEALTHY run counts (the degraded run's 9999/tcp is ignored)"
    assert hosts["www.example.test"]["open_findings"] == 1 and hosts["dev.example.test"]["open_findings"] == 1
    assert hosts["www.example.test"]["asset_type"] == "domain" and hosts["203.0.113.10"]["asset_type"] == "ip"
    assert sorted(d["value"] for d in body["deny_rows"]) == ["203.0.113.99", "secret.example.test"]
    assert body["monitor"]["title"] == "Sirkos Application"
    assert body["defaults"] == {"scan_profile": "thorough", "ai_testing_allowed": True}
    assert body["carried"] and body["not_carried"]
    assert any("authorization" in line.lower() for line in body["not_carried"])


def test_a_denied_host_is_listed_as_not_selectable_and_names_the_rule(client, db, world):
    _asset(db, world.mon, "secret.example.test")
    db.commit()
    body = client.get(f"/engagements/{world.mon.id}/handover-preview", headers=_auth(db, world.owner)).json()
    denied = {h["host"]: h["denied_by"] for h in body["hosts"]}
    assert denied["secret.example.test"] == "secret.example.test" and denied["www.example.test"] is None


def test_the_preview_is_a_read_like_every_other_and_open_to_every_signed_in_user(client, db, world):
    """REQ-IAM-022: it shows only what anyone can already read about the monitor; starting is the owner's (above)."""
    for who in (world.other, world.owner, world.admin):
        assert client.get(f"/engagements/{world.mon.id}/handover-preview", headers=_auth(db, who)).status_code == 200
    assert client.get(f"/engagements/{world.mon.id}/handover-preview").status_code == 401


@pytest.mark.parametrize("require_token, expected", [(True, "both_may_run"), (False, "monitor_must_pause")])
def test_the_overlap_follows_the_installations_identity_setting(client, db, world, require_token, expected):
    with mock.patch.object(handover_module, "get_settings", return_value=types.SimpleNamespace(egress_require_token=require_token)):
        body = client.get(f"/engagements/{world.mon.id}/handover-preview", headers=_auth(db, world.owner)).json()
    assert body["overlap"] == expected


@pytest.mark.parametrize("require_token", [True, False])
def test_negative_the_handover_never_changes_the_monitor_whatever_the_overlap(client, db, world, require_token):
    before = _monitor_state(db, world.mon)
    with mock.patch.object(handover_module, "get_settings", return_value=types.SimpleNamespace(egress_require_token=require_token)):
        _created(db, _start(client, db, world))
    after = _monitor_state(db, world.mon)
    assert after["row"]["status"] == before["row"]["status"] == "active"
    assert after == before


# ============================================================ REQ-HANDOVER-007/008: linked, separate, nothing flows back


def test_the_link_is_visible_both_ways(client, db, world):
    eng = _created(db, _start(client, db, world))
    one = client.get(f"/engagements/{eng.id}", headers=_auth(db, world.other)).json()
    assert one["handover_from"] == {"id": str(world.mon.id), "title": "Sirkos Application", "status": "active"}
    listed = client.get(f"/engagements/{world.mon.id}/handovers", headers=_auth(db, world.other)).json()
    assert [(x["id"], x["title"], x["status"]) for x in listed] == [(str(eng.id), "Test: Sirkos Application", "draft")]
    assert listed[0]["owner_name"] == "Owner" and "authorized_from" in listed[0] and "authorized_until" in listed[0]
    assert client.get(f"/engagements/{world.mon.id}", headers=_auth(db, world.owner)).json()["handover_from"] is None


def test_an_engagement_without_a_link_has_no_handover_from(client, db, world):
    assert client.get(f"/engagements", headers=_auth(db, world.owner)).status_code == 200
    rows = {e["id"]: e for e in client.get("/engagements", headers=_auth(db, world.owner)).json()}
    assert rows[str(world.mon.id)]["handover_from"] is None


def test_negative_pausing_or_revoking_the_monitor_does_not_change_the_assessment_and_the_reverse(client, db, world):
    eng = _created(db, _start(client, db, world))
    eng_before = {c.name: getattr(eng, c.name) for c in Engagement.__table__.columns}
    assert client.post(f"/engagements/{world.mon.id}/pause", headers=_auth(db, world.owner)).status_code == 200
    assert client.post(f"/engagements/{world.mon.id}/revoke", headers=_auth(db, world.owner)).status_code == 200
    db.expire_all()
    assert {c.name: getattr(db.get(Engagement, eng.id), c.name) for c in Engagement.__table__.columns} == eng_before
    assert client.get(f"/engagements/{eng.id}", headers=_auth(db, world.owner)).json()["handover_from"]["status"] == "revoked"


def test_negative_revoking_the_assessment_does_not_change_the_monitor(client, db, world):
    eng = _created(db, _start(client, db, world))
    before = _monitor_state(db, world.mon)
    assert client.post(f"/engagements/{eng.id}/revoke", headers=_auth(db, world.owner)).status_code == 200
    assert _monitor_state(db, world.mon) == before


def test_deleting_the_monitor_leaves_the_assessment_and_empties_the_link(client, db, world):
    eng = _created(db, _start(client, db, world))
    r = client.delete(f"/engagements/{world.mon.id}", headers=_auth(db, world.owner))
    assert r.status_code in (200, 204), r.text
    db.expire_all()
    kept = db.get(Engagement, eng.id)
    assert kept is not None and kept.handover_from_id is None and kept.title == "Test: Sirkos Application"
    assert db.scalar(select(func.count()).select_from(ScopeAsset).where(ScopeAsset.engagement_id == eng.id)) >= 3


def test_negative_an_assessment_finding_changes_nothing_on_the_monitor(client, db, world):
    eng = _created(db, _start(client, db, world))
    before = _monitor_state(db, world.mon)
    r = client.post(f"/internal/engagements/{eng.id}/findings", headers=_internal(),
                    json={"category": "exposure", "title": "Missing HSTS", "confidence": "validated"})
    assert r.status_code in (200, 201), r.text
    assert _monitor_state(db, world.mon) == before


# ============================================================ REQ-HANDOVER-005: the agent starts from what monitoring found


def _agent_context(client, eng_id) -> dict:
    r = client.get(f"/internal/engagements/{eng_id}/agent-context", headers=_internal())
    assert r.status_code == 200, r.text
    return r.json()


def test_the_agent_gets_the_monitors_services_and_open_findings_for_the_assessments_own_hosts(client, db, world):
    eng = _created(db, _start(client, db, world, hosts=["www.example.test"]))
    known = _agent_context(client, eng.id)["known_from_monitor"]
    assert known["source"]["id"] == str(world.mon.id) and known["source"]["title"] == "Sirkos Application"
    assert "not verified" in known["note"].lower() and "earlier unattended run" in known["note"].lower()
    assert known["as_of"]
    assert [h["host"] for h in known["hosts"]] == ["www.example.test"], "only hosts of the assessment's own scope"
    host = known["hosts"][0]
    assert sorted((s["port"], s["protocol"], s["product"], s["version"]) for s in host["services"]) == \
        [(80, "tcp", "nginx", "1.25.3"), (443, "tcp", "nginx", "1.25.3")], "the healthy run's services, not the degraded run's"
    assert [f["title"] for f in host["findings"]] == ["Missing HSTS"], "open findings only"
    assert host["findings"][0]["severity"] == "low"


def test_negative_the_summary_carries_no_evidence_request_response_or_credential(client, db, world):
    eng = _created(db, _start(client, db, world, hosts=["www.example.test"]))
    text = json.dumps(_agent_context(client, eng.id)["known_from_monitor"])
    assert "SESSION=abc123" not in text and "evidence" not in text and "secret" not in text.lower()


def test_negative_a_host_outside_the_assessments_own_scope_is_not_in_the_summary(client, db, world):
    eng = _created(db, _start(client, db, world, hosts=["www.example.test"]))
    text = json.dumps(_agent_context(client, eng.id)["known_from_monitor"])
    assert "dev.example.test" not in text and "Admin panel exposed" not in text, "the monitor knows it; the assessment may not touch it"


def test_a_held_host_the_owner_chose_is_in_the_summary(client, db, world):
    eng = _created(db, _start(client, db, world, hosts=["dev.example.test"]))
    hosts = _agent_context(client, eng.id)["known_from_monitor"]["hosts"]
    assert [h["host"] for h in hosts] == ["dev.example.test"]
    assert [f["title"] for f in hosts[0]["findings"]] == ["Admin panel exposed"]


def test_negative_a_host_the_assessment_denies_is_not_in_the_summary(client, db, world):
    eng = _created(db, _start(client, db, world, hosts=["www.example.test"]))
    _scope(db, eng, "deny", "domain", "www.example.test")
    db.commit()
    assert _agent_context(client, eng.id)["known_from_monitor"]["hosts"] == []


def test_negative_an_engagement_without_a_link_or_with_a_link_to_a_non_monitor_gets_no_section(client, db, world):
    plain = Engagement(title="Plain", source="own_domain", status="active", operating_mode="assessment", owner_user_id=world.owner.id,
                       authorized_from=NOW - dt.timedelta(hours=1), authorized_until=NOW + dt.timedelta(days=1))
    db.add(plain)
    db.commit()
    assert "known_from_monitor" not in _agent_context(client, plain.id)
    other_assessment = Engagement(title="Other", source="own_domain", status="active", operating_mode="assessment",
                                  owner_user_id=world.owner.id, handover_from_id=plain.id,
                                  authorized_from=NOW - dt.timedelta(hours=1), authorized_until=NOW + dt.timedelta(days=1))
    db.add(other_assessment)
    db.commit()
    assert "known_from_monitor" not in _agent_context(client, other_assessment.id), "a link to a non-monitor is ignored"


def test_the_summary_is_capped(client, db, world):
    for i in range(handover_module.MAX_FINDINGS_PER_HOST + 20):
        _finding(db, world.mon, world.www, f"Extra finding {i}")
    for i in range(handover_module.MAX_SERVICES_PER_HOST + 20):
        run = db.scalar(select(ScanRun).where(ScanRun.engagement_id == world.mon.id, ScanRun.health == "ok"))
        db.add(RunInventorySnapshot(scan_run_id=run.id, kind="service", key=f"www.example.test:{20000 + i}/tcp",
                                    engagement_id=world.mon.id, data={"product": "x", "version": "1"}))
    db.commit()
    eng = _created(db, _start(client, db, world, hosts=["www.example.test"]))
    host = _agent_context(client, eng.id)["known_from_monitor"]["hosts"][0]
    assert len(host["findings"]) == handover_module.MAX_FINDINGS_PER_HOST
    assert len(host["services"]) == handover_module.MAX_SERVICES_PER_HOST


def test_the_summary_changes_no_decision_the_gateway_still_judges_the_assessments_own_scope(client, db, world):
    """A host in the summary is not thereby authorized: the draft is not active, so nothing may be called for it."""
    from app.gateway.authorize import ToolCall, authorize

    eng = _created(db, _start(client, db, world, hosts=["www.example.test"]))
    run = ScanRun(engagement_id=eng.id, phase="agent", state="running", attempt=1)
    db.add(run)
    db.commit()
    decision = authorize(db, ToolCall(engagement_id=eng.id, tool="httpx", category="fingerprint", mode="active",
                                      target="www.example.test", args={}, is_automated=True, phase="agent", scan_run_id=run.id))
    assert decision.allowed is False and decision.reason in ("engagement_not_active", "ai_testing_not_enabled", "no_tool_grant")
