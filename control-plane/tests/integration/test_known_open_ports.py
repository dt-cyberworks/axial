"""TC-PORTSCAN-004 (control plane): which TCP ports did the recent earlier runs find open on an
address? The worker compares a new port scan against this answer (GitHub issue #60)."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.db.base import get_db
from app.main import app
from app.models.engagement import Engagement
from app.models.scan_plan import ScanSurface
from app.models.scan_run import ScanRun

IP = "192.0.2.10"


@pytest.fixture
def api(engine, db):
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def _override_get_db():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


def _internal():
    return {"X-ASM-Internal-Token": get_settings().internal_api_token}


def _engagement(db, owner):
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(title="E", source="own_domain", status="active", owner_user_id=owner.id,
                     authorized_from=now - dt.timedelta(days=30), authorized_until=now + dt.timedelta(days=30))
    db.add(eng)
    db.commit()
    db.refresh(eng)
    return eng


def _run(db, eng, days_ago, ports, ip=IP, state="done"):
    started = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days_ago)
    run = ScanRun(engagement_id=eng.id, started_at=started, state=state, phase="report")
    db.add(run)
    db.commit()
    db.refresh(run)
    for port in ports:
        db.add(ScanSurface(
            scan_run_id=run.id, engagement_id=eng.id, host="a.example", ip=ip, port=port,
            service_class="web" if port in (80, 443) else "tls_service",
        ))
    db.commit()
    return run


def _ask(api, eng, current, ip=IP):
    return api.get(
        f"/internal/engagements/{eng.id}/known-open-ports", params={"ip": ip, "scan_run_id": str(current.id)},
        headers=_internal(),
    )


def test_req_portscan_004_the_answer_is_the_union_of_the_newest_three_earlier_runs(api, db, test_user):
    eng = _engagement(db, test_user)
    _run(db, eng, 9, [22, 80])          # too old: only the newest three count
    _run(db, eng, 3, [80, 443, 465])
    _run(db, eng, 2, [443, 465, 587])
    _run(db, eng, 1, [465, 587, 993])
    current = _run(db, eng, 0, [], state="running")
    body = _ask(api, eng, current).json()
    assert body["ip"] == IP and body["ports"] == [80, 443, 465, 587, 993]
    assert len(body["runs"]) == 3


def test_req_portscan_004_the_running_run_and_later_runs_are_never_counted(api, db, test_user):
    eng = _engagement(db, test_user)
    earlier = _run(db, eng, 2, [443])
    current = _run(db, eng, 1, [8080], state="running")  # its own surfaces do not count against itself
    _run(db, eng, 0, [9999])                              # a run that started later is not "earlier"
    assert _ask(api, eng, current).json() == {"ip": IP, "ports": [443], "runs": [str(earlier.id)]}


def test_req_portscan_004_only_the_asked_address_counts(api, db, test_user):
    eng = _engagement(db, test_user)
    _run(db, eng, 2, [443], ip="198.51.100.7")
    current = _run(db, eng, 0, [], state="running")
    assert _ask(api, eng, current).json()["ports"] == []


def test_req_portscan_004_an_engagements_answer_never_includes_another_engagements_ports(api, db, test_user):
    mine, other = _engagement(db, test_user), _engagement(db, test_user)
    _run(db, other, 2, [443, 8443])
    current = _run(db, mine, 0, [], state="running")
    assert _ask(api, mine, current).json()["ports"] == []


def test_negative_req_portscan_004_bad_input_is_refused(api, db, test_user):
    eng = _engagement(db, test_user)
    current = _run(db, eng, 0, [], state="running")
    assert _ask(api, eng, current, ip="not-an-ip").status_code == 422
    assert _ask(api, eng, current, ip="192.0.2.0/24").status_code == 422
    other = _engagement(db, test_user)
    foreign = _run(db, other, 0, [], state="running")
    assert api.get(f"/internal/engagements/{eng.id}/known-open-ports",
                   params={"ip": IP, "scan_run_id": str(foreign.id)}, headers=_internal()).status_code == 404
    assert api.get(f"/internal/engagements/{eng.id}/known-open-ports",
                   params={"ip": IP, "scan_run_id": str(uuid.uuid4())}, headers=_internal()).status_code == 404


def test_negative_req_portscan_004_the_endpoint_needs_the_internal_token(api, db, test_user):
    eng = _engagement(db, test_user)
    current = _run(db, eng, 0, [], state="running")
    url = f"/internal/engagements/{eng.id}/known-open-ports"
    assert api.get(url, params={"ip": IP, "scan_run_id": str(current.id)}).status_code in (401, 403)
