"""REQ-EGRESS-006 (GitHub #81): the control plane mints a run identity only for a run that may still send traffic."""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.db.base import get_db
from app.gateway import egress_identity
from app.main import app
from app.models.engagement import Engagement
from app.models.scan_run import ScanRun
from tests.integration.owners import make_owner

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


def _internal():
    return {"X-ASM-Internal-Token": get_settings().internal_api_token}


def _run(db, *, status="active", state="running", cancel=False) -> ScanRun:
    eng = Engagement(title="T", source="own_domain", status=status, owner_user_id=make_owner(db).id,
                     authorized_from=NOW - dt.timedelta(hours=1), authorized_until=NOW + dt.timedelta(days=1))
    db.add(eng)
    db.flush()
    run = ScanRun(engagement_id=eng.id, phase="fingerprint", state=state, cancel_requested=cancel, trigger="manual")
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


@pytest.mark.parametrize("state", ["running", "waiting_approval"])
def test_an_active_run_gets_a_token_that_proves_exactly_its_engagement_and_run(client, db, state):
    run = _run(db, state=state)
    response = client.post(f"/internal/scan-runs/{run.id}/egress-token", headers=_internal())
    assert response.status_code == 200
    body = response.json()
    settings = get_settings()
    assert body["expires_in"] == settings.egress_run_token_ttl_seconds
    proved = egress_identity.verify(settings.egress_run_token_secret, body["token"])
    assert (proved.engagement_id, proved.scan_run_id) == (str(run.engagement_id), str(run.id))
    assert proved.expires_at - proved.issued_at == settings.egress_run_token_ttl_seconds
    assert body["engagement_id"] == str(run.engagement_id) and body["scan_run_id"] == str(run.id)


def test_each_run_gets_its_own_identity(client, db):
    first, second = _run(db), _run(db)
    tokens = [client.post(f"/internal/scan-runs/{r.id}/egress-token", headers=_internal()).json()["token"] for r in (first, second)]
    secret = get_settings().egress_run_token_secret
    assert egress_identity.verify(secret, tokens[0]).scan_run_id == str(first.id)
    assert egress_identity.verify(secret, tokens[1]).scan_run_id == str(second.id)
    assert egress_identity.verify(secret, tokens[0]).engagement_id != egress_identity.verify(secret, tokens[1]).engagement_id


@pytest.mark.parametrize("state", ["done", "failed", "aborted"])
def test_negative_a_run_that_is_not_active_gets_no_token(client, db, state):
    run = _run(db, state=state)
    response = client.post(f"/internal/scan-runs/{run.id}/egress-token", headers=_internal())
    assert response.status_code == 409 and "token" not in response.json()


def test_negative_a_run_whose_cancellation_was_requested_gets_no_token(client, db):
    run = _run(db, cancel=True)
    response = client.post(f"/internal/scan-runs/{run.id}/egress-token", headers=_internal())
    assert response.status_code == 409 and response.json()["detail"] == "scan_run_not_active"


@pytest.mark.parametrize("status", ["draft", "awaiting_signature", "paused", "completed", "revoked"])
def test_negative_a_run_of_an_engagement_that_is_not_active_gets_no_token(client, db, status):
    run = _run(db, status=status)
    response = client.post(f"/internal/scan-runs/{run.id}/egress-token", headers=_internal())
    assert response.status_code == 409 and response.json()["detail"] == "engagement_not_active"


def test_negative_an_unknown_run_is_404(client):
    response = client.post("/internal/scan-runs/00000000-0000-4000-8000-000000000000/egress-token", headers=_internal())
    assert response.status_code == 404


def test_negative_the_endpoint_needs_the_internal_token(client, db):
    run = _run(db)
    assert client.post(f"/internal/scan-runs/{run.id}/egress-token").status_code in (401, 403)
    assert client.post(f"/internal/scan-runs/{run.id}/egress-token", headers={"X-ASM-Internal-Token": "wrong"}).status_code in (401, 403)
