"""REQ-BASE-007/008 (GitHub #78): choosing a held host in Review targets releases it, and a host in scope that a
run did not test is reported. The case that was found on int (2026-10-20): the owner kept `dev` ticked, the host
stayed held, its inbox item stayed open and the scan silently skipped it."""

from __future__ import annotations

import datetime as dt
import io
import uuid

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app import auth_service, celery_client, monitoring, scan_plan
from app.db.base import get_db
from app.main import app
from app.models.asset import DiscoveredAsset
from app.models.audit import AuditLog
from app.models.dns_record import DnsRecord
from app.models.engagement import Engagement, ScopeAsset, ToolGrant
from app.models.monitoring import InboxItem
from app.models.scan_plan import ScanSurface
from app.models.scan_run import ScanRun
from app.models.user import User
from app.passwords import hash_secret
from app.pdf_report import render_report_pdf
from app.report_builder import build_report_model

NOW = dt.datetime.now(dt.timezone.utc)
ROOT_IP = "203.0.113.10"


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


@pytest.fixture(autouse=True)
def _no_broker(monkeypatch):
    monkeypatch.setattr(celery_client, "enqueue_scan", lambda engagement_id, scan_run_id, **kw: "task-1")


def _user(db, role="operator") -> User:
    user = User(email=f"u-{uuid.uuid4().hex[:10]}@example.com", display_name="U", role=role, status="active",
                must_change_password=False, password_hash=hash_secret("x"))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _auth(db, user) -> dict:
    token, _ = auth_service.create_session(db, user, ip=None, user_agent=None)
    return {"Authorization": f"Bearer {token}"}


def _monitor(db, owner) -> Engagement:
    eng = Engagement(title="M", source="own_domain", status="active", operating_mode="monitoring",
                     target_review_state="awaiting_selection", new_asset_policy="hold",
                     authorized_from=NOW - dt.timedelta(hours=1), authorized_until=NOW + dt.timedelta(days=30),
                     owner_user_id=owner.id)
    db.add(eng)
    db.flush()
    db.add(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain", value="example.test",
                      active_allowed=True, authorization_verified=True))
    db.add(ToolGrant(engagement_id=eng.id, tool_category="fingerprint", mode="active", requires_manual_approval=False))
    db.commit()
    db.refresh(eng)
    return eng


def _host(db, eng, name, ips=(ROOT_IP,), *, held=False, resolved=True, first_seen=None) -> DiscoveredAsset:
    asset = DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value=name, in_scope=True, discovered_via="passive-osint")
    if held:
        asset.hold_state, asset.held_at = "held", NOW - dt.timedelta(days=5)
    asset.first_seen = first_seen if first_seen is not None else NOW - dt.timedelta(days=3)
    db.add(asset)
    db.flush()
    db.add(DnsRecord(engagement_id=eng.id, asset_id=asset.id, fqdn=name, cname_chain=[], terminal_ips=list(ips),
                     dns_status="resolved" if resolved else "nxdomain", hosting_provider="TestHost" if ips else None))
    if held:
        monitoring.open_inbox_item(db, eng.id, "held_asset", f"held_asset:{name}", f"New host {name} was found and is held.",
                                   {"asset_id": str(asset.id), "value": name})
    db.commit()
    db.refresh(asset)
    return asset


def _setup(db):
    owner = _user(db)
    eng = _monitor(db, owner)
    hosts = {
        "root": _host(db, eng, "example.test"),
        "www": _host(db, eng, "www.example.test"),
        "dev": _host(db, eng, "dev.example.test", held=True),   # held before this flow existed: the case of #78
        "old": _host(db, eng, "old.example.test", held=True),
    }
    return owner, eng, hosts


def _confirm(client, db, user, eng, selected, **extra):
    body = {"selected_asset_ids": [str(h.id) for h in selected], **extra}
    return client.post(f"/engagements/{eng.id}/targets/confirm", json=body, headers=_auth(db, user))


def _audit(db, eng, action):
    db.expire_all()
    return list(db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id, AuditLog.action == action)))


def _open_held_items(db, eng):
    db.expire_all()
    return {i.dedupe_key for i in db.scalars(select(InboxItem).where(
        InboxItem.engagement_id == eng.id, InboxItem.kind == "held_asset", InboxItem.state == "open"))}


# ------------------------------------------------------------- REQ-BASE-007


def test_choosing_a_held_host_releases_it_audits_it_and_clears_its_inbox_item(client, db):
    owner, eng, h = _setup(db)
    r = _confirm(client, db, owner, eng, [h["root"], h["www"], h["dev"]], confirm_widening=True)
    assert r.status_code == 200, r.text
    assert r.json()["released"] == 1 and r.json()["excluded"] == 1  # `old` was not chosen

    db.expire_all()
    dev = db.get(DiscoveredAsset, h["dev"].id)
    assert dev.hold_state == "released" and dev.released_by == owner.email and dev.released_at is not None
    assert "held_asset:dev.example.test" not in _open_held_items(db, eng)
    assert [a.reason for a in _audit(db, eng, "asset_released")] == ["targets_confirmed"]
    assert _audit(db, eng, "asset_released")[0].payload["host"] == "dev.example.test"
    confirmed = _audit(db, eng, "targets_confirmed")[0]
    assert confirmed.payload["released"] == 1 and confirmed.payload["excluded"] == 1


def test_the_pipelines_hold_evaluation_now_lets_the_chosen_host_through_and_still_holds_the_other(db):
    """What the worker asks before it fingerprints: checked on the pipeline's own rule, not only on the row."""
    owner, eng, h = _setup(db)
    run = ScanRun(engagement_id=eng.id, phase="fingerprint", state="done", attempt=1, trigger="manual")
    db.add(run)
    db.commit()
    candidates = [{"asset_id": str(h["dev"].id)}, {"asset_id": str(h["old"].id)}]
    before = monitoring.evaluate_hold(db, run, candidates)
    assert before["held"] == [str(h["dev"].id), str(h["old"].id)] and before["released"] == []

    from app import targets

    targets.confirm(db, eng, selected_ids=[h["root"].id, h["www"].id, h["dev"].id], policy=None,
                    actor_email=owner.email, confirm_widening=True, enqueue=lambda *a, **k: "t")
    after = monitoring.evaluate_hold(db, run, candidates)
    assert after["released"] == [str(h["dev"].id)] and after["held"] == [str(h["old"].id)]


def test_negative_without_the_widening_confirmation_nothing_changes(client, db):
    owner, eng, h = _setup(db)
    r = _confirm(client, db, owner, eng, [h["root"], h["www"], h["dev"]])
    assert r.status_code == 409 and "confirmation_required" in r.text
    db.expire_all()
    assert db.get(DiscoveredAsset, h["dev"].id).hold_state == "held"
    assert "held_asset:dev.example.test" in _open_held_items(db, eng)
    assert _audit(db, eng, "asset_released") == [] and _audit(db, eng, "targets_confirmed") == []
    assert db.get(Engagement, eng.id).target_review_state == "awaiting_selection"


def test_negative_during_an_active_run_nothing_changes(client, db):
    owner, eng, h = _setup(db)
    db.add(ScanRun(engagement_id=eng.id, phase="fingerprint", state="running", attempt=1, trigger="manual"))
    db.commit()
    r = _confirm(client, db, owner, eng, [h["root"], h["www"], h["dev"]], confirm_widening=True)
    assert r.status_code == 409 and "scan_run_active" in r.text
    db.expire_all()
    assert db.get(DiscoveredAsset, h["dev"].id).hold_state == "held"


def test_negative_a_held_host_that_is_not_chosen_stays_held_and_is_excluded_and_never_widens(client, db):
    owner, eng, h = _setup(db)
    r = _confirm(client, db, owner, eng, [h["root"], h["www"]])  # narrowing only: no confirmation needed
    assert r.status_code == 200 and r.json()["released"] == 0 and r.json()["excluded"] == 2
    db.expire_all()
    for key in ("dev", "old"):
        assert db.get(DiscoveredAsset, h[key].id).hold_state == "held"
    denied = {a.value for a in db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id, ScopeAsset.rule == "deny"))}
    assert denied == {"dev.example.test", "old.example.test"}
    assert _audit(db, eng, "asset_released") == []


def test_negative_a_non_owner_cannot_release_and_an_unknown_id_releases_nothing(client, db):
    owner, eng, h = _setup(db)
    stranger = _user(db)
    assert _confirm(client, db, stranger, eng, [h["root"], h["dev"]], confirm_widening=True).status_code == 403
    body = {"selected_asset_ids": [str(h["root"].id), str(h["dev"].id), str(uuid.uuid4())], "confirm_widening": True}
    r = client.post(f"/engagements/{eng.id}/targets/confirm", json=body, headers=_auth(db, owner))
    assert r.status_code == 404
    db.expire_all()
    assert db.get(DiscoveredAsset, h["dev"].id).hold_state == "held"  # atomic: the valid half did not go through
    assert "held_asset:dev.example.test" in _open_held_items(db, eng)
    assert _audit(db, eng, "asset_released") == [] and _audit(db, eng, "target_excluded") == []


def test_a_denied_and_held_host_that_is_chosen_again_is_included_and_released(client, db):
    owner, eng, h = _setup(db)
    assert _confirm(client, db, owner, eng, [h["root"], h["www"]]).status_code == 200  # excludes dev and old
    for run in db.scalars(select(ScanRun).where(ScanRun.engagement_id == eng.id)):  # the first scan has finished
        run.state = "done"
    db.commit()
    r = _confirm(client, db, owner, eng, [h["root"], h["www"], h["dev"]], confirm_widening=True)
    assert r.status_code == 200 and r.json()["included"] == 1 and r.json()["released"] == 1
    db.expire_all()
    assert db.get(DiscoveredAsset, h["dev"].id).hold_state == "released"
    assert "dev.example.test" not in {a.value for a in db.scalars(select(ScopeAsset).where(ScopeAsset.rule == "deny"))}


def test_the_target_list_marks_held_hosts(client, db):
    owner, eng, h = _setup(db)
    view = client.get(f"/engagements/{eng.id}/targets", headers=_auth(db, owner)).json()
    held = {c["value"]: c["held"] for c in view["candidates"]}
    assert held == {"example.test": False, "www.example.test": False, "dev.example.test": True, "old.example.test": True}
    assert view["counts"]["held"] == 2


# ------------------------------------------------------------- REQ-BASE-008


def _finished_run(db, eng, *, minutes_ago=120, **kw) -> ScanRun:
    started = NOW - dt.timedelta(minutes=minutes_ago)
    run = ScanRun(engagement_id=eng.id, phase="report", state="done", started_at=started,
                  finished_at=started + dt.timedelta(minutes=10), trigger="manual", scan_profile="standard", **kw)
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _surface(db, eng, run, host, port=443):
    db.add(ScanSurface(scan_run_id=run.id, engagement_id=eng.id, host=host, port=port, service_class="web"))
    db.commit()


def test_a_host_in_scope_that_a_run_did_not_test_is_listed_with_its_reason(db):
    owner, eng, h = _setup(db)
    _host(db, eng, "gone.example.test", (), resolved=False)
    _host(db, eng, "late.example.test", first_seen=NOW + dt.timedelta(hours=1))  # found after the run ended
    run = _finished_run(db, eng)
    _surface(db, eng, run, "www.example.test")
    got = {i["host"]: i["reason"] for i in scan_plan.untested_hosts(db, run)}
    assert got == {"dev.example.test": "held", "old.example.test": "held", "gone.example.test": "no_address",
                   "example.test": "no_open_port"}
    assert "www.example.test" not in got and "late.example.test" not in got  # tested; found too late to be tested


@pytest.mark.parametrize("case", ["baseline", "passive", "restricted", "running", "failed"])
def test_negative_a_run_that_does_not_look_at_hosts_judges_none(db, case):
    owner, eng, h = _setup(db)
    run = _finished_run(db, eng)
    if case == "baseline":
        run.trigger = "baseline"
    elif case == "passive":
        run.scan_profile = "passive"
    elif case == "restricted":
        run.retest_items = [{"host": "www.example.test", "check": "ffuf"}]
    elif case == "running":
        run.state = "running"
    elif case == "failed":
        run.state = "failed"
    db.commit()
    assert scan_plan.untested_hosts(db, run) == []


def test_a_host_limited_run_judges_only_its_hosts(db):
    owner, eng, h = _setup(db)
    run = _finished_run(db, eng, scope_hosts=["dev.example.test"])
    assert [i["host"] for i in scan_plan.untested_hosts(db, run)] == ["dev.example.test"]


def test_the_plan_endpoint_lists_them_and_the_worker_view_does_not(client, db):
    owner, eng, h = _setup(db)
    run = _finished_run(db, eng)
    _surface(db, eng, run, "www.example.test")
    plan = client.get(f"/engagements/{eng.id}/scan-runs/{run.id}/plan", headers=_auth(db, owner)).json()
    hosts = {i["host"] for i in plan["untested_hosts"]}
    assert {"dev.example.test", "old.example.test", "example.test"} <= hosts
    assert all(i["text"] for i in plan["untested_hosts"])
    internal = client.get(f"/internal/scan-runs/{run.id}/plan",
                          headers={"x-asm-internal-token": __import__("app.config", fromlist=["get_settings"]).get_settings().internal_api_token}).json()
    assert internal["untested_hosts"] == []


def test_the_report_names_the_hosts_and_the_summary_counts_them(db):
    owner, eng, h = _setup(db)
    run = _finished_run(db, eng)
    _surface(db, eng, run, "www.example.test")
    model = build_report_model(db, eng, run)
    assert model.coverage is not None and len(model.coverage.untested) == 3
    assert "3 hosts in scope were not tested by this run" in model.executive_summary.coverage_note
    text = "\n".join(page.extract_text() for page in PdfReader(io.BytesIO(render_report_pdf(model))).pages)
    assert "Hosts in scope that were not tested" in text
    assert "held back by the monitor" in text and "dev.example.test" in text


def test_a_run_that_tested_every_host_adds_nothing_to_the_report(db):
    owner, eng, h = _setup(db)
    for key in ("dev", "old"):
        db.get(DiscoveredAsset, h[key].id).in_scope = False
    db.commit()
    run = _finished_run(db, eng)
    for host in ("example.test", "www.example.test"):
        _surface(db, eng, run, host)
    model = build_report_model(db, eng, run)
    assert model.coverage is not None and model.coverage.untested == []
    assert "not tested by this run" not in (model.executive_summary.coverage_note or "")
