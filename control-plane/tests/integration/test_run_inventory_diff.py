"""REQ-DIFF-001..004 / TC-DIFF-001..004 (GitHub #65): the Diff tab's host and port comparison."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app import auth_service, monitoring, scan_diff
from app.db.base import get_db
from app.main import app
from app.models.asset import DiscoveredAsset
from app.models.engagement import Engagement
from app.models.monitoring import RunInventorySnapshot
from app.models.scan_run import ScanRun
from app.models.user import User
from app.passwords import hash_secret

NOW = dt.datetime.now(dt.timezone.utc)


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


def _engagement(db, owner, mode="assessment"):
    eng = Engagement(title=f"D-{mode}", source="own_domain", status="active", operating_mode=mode,
                     authorized_from=NOW - dt.timedelta(days=5), authorized_until=NOW + dt.timedelta(days=30),
                     owner_user_id=owner.id)
    db.add(eng)
    db.commit()
    db.refresh(eng)
    return eng


def _run(db, eng, days_ago, *, state="done", reason=None, scope_hosts=None, trigger="manual", services=None):
    start = NOW - dt.timedelta(days=days_ago)
    run = ScanRun(engagement_id=eng.id, phase="report", state=state, state_reason=reason, started_at=start,
                  finished_at=start + dt.timedelta(minutes=5), trigger=trigger, scope_hosts=scope_hosts,
                  checkpoint={"services": services or []})
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _asset(db, eng, value, run, held=False):
    asset = DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value=value, in_scope=True,
                            discovered_via="passive-osint", first_seen=run.started_at,
                            last_seen=run.started_at + dt.timedelta(minutes=1), hold_state="held" if held else None)
    db.add(asset)
    db.commit()
    return asset


def _snap(db, run, assets=(), services=()):
    for key in assets:
        db.add(RunInventorySnapshot(scan_run_id=run.id, engagement_id=run.engagement_id, kind="asset", key=key, data={}))
    for key, product, version in services:
        db.add(RunInventorySnapshot(scan_run_id=run.id, engagement_id=run.engagement_id, kind="service", key=key,
                                    data={"product": product, "version": version}))
    db.commit()


def _two_runs(db, eng):
    r1, r2 = _run(db, eng, 2), _run(db, eng, 1)
    _snap(db, r1, assets=["a.example.com", "b.example.com"],
          services=[("a.example.com:80/tcp", "nginx", "1.24"), ("a.example.com:22/tcp", "OpenSSH", "9.6"),
                    ("b.example.com:443/tcp", "Apache", "2.4.58")])
    _snap(db, r2, assets=["a.example.com", "c.example.com"],
          services=[("a.example.com:80/tcp", "nginx", "1.26"), ("a.example.com:8080/tcp", "Jetty", "11"),
                    ("b.example.com:443/tcp", "Apache", "2.4.58")])
    return r1, r2


def test_new_and_gone_hosts_opened_and_closed_ports_and_changed_services(db):
    eng = _engagement(db, _user(db))
    r1, r2 = _two_runs(db, eng)
    inv = scan_diff.compute_inventory_diff(db, r2)
    assert inv["available"] is True and inv["previous_run_id"] == str(r1.id)
    assert [a["key"] for a in inv["assets_new"]] == ["c.example.com"]
    assert [a["key"] for a in inv["assets_gone"]] == ["b.example.com"]
    assert [p["key"] for p in inv["ports_opened"]] == ["a.example.com:8080/tcp"] and inv["ports_opened"][0]["product"] == "Jetty"
    assert [p["key"] for p in inv["ports_closed"]] == ["a.example.com:22/tcp"]
    assert inv["services_changed"] == [{"key": "a.example.com:80/tcp", "from": {"product": "nginx", "version": "1.24"},
                                        "to": {"product": "nginx", "version": "1.26"}}]


def test_the_findings_diff_carries_the_inventory_against_the_same_run(db):
    eng = _engagement(db, _user(db))
    r1, r2 = _two_runs(db, eng)
    diff = scan_diff.compute_diff(db, r2)
    assert diff["has_baseline"] and diff["previous_run_id"] == diff["inventory"]["previous_run_id"] == str(r1.id)


def test_the_first_run_has_no_baseline_and_lists_nothing(db):
    eng = _engagement(db, _user(db))
    r1 = _run(db, eng, 1)
    _snap(db, r1, assets=["a.example.com"])
    inv = scan_diff.compute_diff(db, r1)["inventory"]
    assert inv["available"] is False and inv["reason"] == "no_baseline"
    assert inv["assets_new"] == [] and inv["assets_gone"] == []


def test_negative_a_run_with_reduced_coverage_never_says_something_is_gone(db):
    eng = _engagement(db, _user(db))
    r1 = _run(db, eng, 2)
    r2 = _run(db, eng, 1, reason="coverage_partial:nuclei=1")
    _snap(db, r1, assets=["a.example.com", "b.example.com"], services=[("a.example.com:22/tcp", "OpenSSH", "9.6")])
    _snap(db, r2, assets=["a.example.com", "c.example.com"], services=[("a.example.com:80/tcp", "nginx", "1.26")])
    inv = scan_diff.compute_inventory_diff(db, r2)
    assert inv["run_coverage_reduced"] is True
    assert [a["key"] for a in inv["assets_new"]] == ["c.example.com"] and [p["key"] for p in inv["ports_opened"]] == ["a.example.com:80/tcp"]
    assert inv["assets_gone"] == [] and inv["ports_closed"] == []


def test_negative_a_run_limited_to_some_hosts_never_says_something_is_gone(db):
    eng = _engagement(db, _user(db))
    r1 = _run(db, eng, 2)
    r2 = _run(db, eng, 1, scope_hosts=["a.example.com"])
    _snap(db, r1, assets=["a.example.com", "b.example.com"])
    _snap(db, r2, assets=["a.example.com"])
    inv = scan_diff.compute_inventory_diff(db, r2)
    assert inv["run_coverage_reduced"] is True and inv["assets_gone"] == []


def test_negative_a_run_or_baseline_without_a_snapshot_is_not_recorded_not_everything_gone(db):
    eng = _engagement(db, _user(db))
    r1 = _run(db, eng, 2)  # finished before snapshots were taken for every engagement: no rows
    r2 = _run(db, eng, 1)
    _snap(db, r2, assets=["a.example.com"])
    inv = scan_diff.compute_inventory_diff(db, r2)
    assert inv["available"] is False and inv["reason"] == "no_snapshot" and inv["assets_gone"] == []
    inv_back = scan_diff.compute_inventory_diff(db, r1)
    assert inv_back["reason"] in ("no_baseline", "no_snapshot")


def test_negative_a_failed_run_is_never_the_baseline(db):
    eng = _engagement(db, _user(db))
    r1 = _run(db, eng, 3)
    failed = _run(db, eng, 2, state="failed")
    r3 = _run(db, eng, 1)
    _snap(db, r1, assets=["a.example.com"])
    _snap(db, failed, assets=[])
    _snap(db, r3, assets=["a.example.com", "b.example.com"])
    inv = scan_diff.compute_inventory_diff(db, r3)
    assert inv["previous_run_id"] == str(r1.id) and [a["key"] for a in inv["assets_new"]] == ["b.example.com"]


def test_an_assessment_run_is_snapshotted_when_it_finishes_and_a_failed_one_is_not(db):
    owner = _user(db)
    eng = _engagement(db, owner, "assessment")
    run = _run(db, eng, 1, services=[{"target": "a.example.com", "port": 443, "protocol": "tcp", "product_name": "nginx", "version": "1.26"}])
    _asset(db, eng, "a.example.com", run)
    monitoring.on_run_finished(db, run)
    rows = {(r.kind, r.key) for r in db.query(RunInventorySnapshot).filter_by(scan_run_id=run.id)}
    assert ("asset", "a.example.com") in rows and ("service", "a.example.com:443/tcp") in rows

    failed = _run(db, eng, 0, state="failed")
    _asset(db, eng, "z.example.com", failed)
    monitoring.on_run_finished(db, failed)
    assert db.query(RunInventorySnapshot).filter_by(scan_run_id=failed.id).count() == 0


def test_an_assessment_creates_no_change_events_or_inbox_items(db):
    from app.models.monitoring import ChangeEvent, InboxItem

    owner = _user(db)
    eng = _engagement(db, owner, "assessment")
    r1, r2 = _run(db, eng, 2), _run(db, eng, 1)
    _asset(db, eng, "a.example.com", r1)
    monitoring.on_run_finished(db, r1)
    _asset(db, eng, "b.example.com", r2)
    monitoring.on_run_finished(db, r2)
    assert db.query(ChangeEvent).filter_by(engagement_id=eng.id).count() == 0
    assert db.query(InboxItem).filter_by(engagement_id=eng.id).count() == 0


def test_a_held_new_host_is_flagged_held(db):
    eng = _engagement(db, _user(db))
    r1, r2 = _run(db, eng, 2), _run(db, eng, 1)
    _snap(db, r1, assets=["a.example.com"])
    db.add(RunInventorySnapshot(scan_run_id=r2.id, engagement_id=eng.id, kind="asset", key="a.example.com", data={}))
    db.add(RunInventorySnapshot(scan_run_id=r2.id, engagement_id=eng.id, kind="asset", key="held.example.com", data={"held": True}))
    db.commit()
    inv = scan_diff.compute_inventory_diff(db, r2)
    assert inv["assets_new"] == [{"key": "held.example.com", "held": True}]


def test_the_endpoint_returns_the_inventory_and_refuses_a_foreign_run(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    r1, r2 = _two_runs(db, eng)
    token, _ = auth_service.create_session(db, owner, ip=None, user_agent=None)
    h = {"Authorization": f"Bearer {token}"}
    body = client.get(f"/engagements/{eng.id}/scan-runs/{r2.id}/diff", headers=h).json()
    assert body["inventory"]["available"] is True and [a["key"] for a in body["inventory"]["assets_new"]] == ["c.example.com"]
    other = _engagement(db, owner)
    assert client.get(f"/engagements/{other.id}/scan-runs/{r2.id}/diff", headers=h).status_code == 404
