"""TC-AGENT-027: the OpenWire probe's callback-token infrastructure.

The public /callback/openwire/{token} endpoint is deliberately fetched by an
untrusted, potentially-compromised target - every test here treats it that
way: an invalid/expired/already-consumed token must be indistinguishable
from any other 404, and nothing about the calling request is ever stored.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app.api.internal import internal_create_openwire_callback_token, internal_get_openwire_callback_status
from app.db.base import get_db
from app.main import app
from app.models.openwire_callback import OpenwireCallbackToken
from app.schemas.internal import OpenwireCallbackTokenCreate


def test_create_returns_a_token_bound_to_the_engagement(db, lab_engagement):
    body = OpenwireCallbackTokenCreate(scan_run_id=None)
    out = internal_create_openwire_callback_token(lab_engagement.id, body, db)
    assert out.token
    assert out.callback_url.endswith(f"/callback/openwire/{out.token}")
    row = db.get(OpenwireCallbackToken, out.token)
    assert row is not None
    assert row.engagement_id == lab_engagement.id
    assert row.triggered_at is None


def test_the_token_has_real_entropy():
    """~256 bits, matching this codebase's own session-token generator
    (app/sessions.py) - not a short or predictable value."""
    body = OpenwireCallbackTokenCreate()
    import inspect

    from app.api import internal as internal_module
    source = inspect.getsource(internal_module.internal_create_openwire_callback_token)
    assert "token_urlsafe(32)" in source


def test_negative_an_unknown_engagement_is_rejected(db):
    body = OpenwireCallbackTokenCreate()
    with pytest.raises(HTTPException) as exc:
        internal_create_openwire_callback_token(uuid.uuid4(), body, db)
    assert exc.value.status_code == 404


def test_negative_a_scan_run_from_another_engagement_is_rejected(db, lab_engagement):
    from app.models.engagement import Engagement
    from app.models.scan_run import ScanRun

    other = Engagement(
        title="Other", source="lab", status="active",
        authorized_from=dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1),
        authorized_until=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1),
    )
    db.add(other)
    db.flush()
    foreign_run = ScanRun(engagement_id=other.id, state="running", phase="agent")
    db.add(foreign_run)
    db.commit()
    db.refresh(foreign_run)

    body = OpenwireCallbackTokenCreate(scan_run_id=foreign_run.id)
    with pytest.raises(HTTPException) as exc:
        internal_create_openwire_callback_token(lab_engagement.id, body, db)
    assert exc.value.status_code == 422


def test_poll_reports_not_triggered_before_any_fetch(db, lab_engagement):
    body = OpenwireCallbackTokenCreate()
    created = internal_create_openwire_callback_token(lab_engagement.id, body, db)
    status = internal_get_openwire_callback_status(lab_engagement.id, created.token, db)
    assert status.triggered is False
    assert status.triggered_at is None


def test_negative_polling_a_token_from_another_engagement_404s(db, lab_engagement):
    from app.models.engagement import Engagement

    other = Engagement(
        title="Other2", source="lab", status="active",
        authorized_from=dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1),
        authorized_until=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1),
    )
    db.add(other)
    db.commit()
    db.refresh(other)

    created = internal_create_openwire_callback_token(lab_engagement.id, OpenwireCallbackTokenCreate(), db)
    with pytest.raises(HTTPException) as exc:
        internal_get_openwire_callback_status(other.id, created.token, db)
    assert exc.value.status_code == 404


# --- The genuinely public callback receiver ---------------------------------

@pytest.fixture
def public_client(engine):
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def _override_get_db():
        s = SessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _override_get_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


def test_a_valid_token_is_marked_triggered_and_served_inert_xml(db, lab_engagement, public_client):
    created = internal_create_openwire_callback_token(lab_engagement.id, OpenwireCallbackTokenCreate(), db)
    db.commit()

    resp = public_client.get(f"/callback/openwire/{created.token}")

    assert resp.status_code == 200
    assert "text/xml" in resp.headers["content-type"]
    assert "<beans" in resp.text
    # No bean definition, no ProcessBuilder, no second-stage payload - see
    # REQ-AGENT-027 and worker/app/openwire_payload.py's own docstring for
    # why this is a deliberate safety choice, not an oversight.
    assert "<bean " not in resp.text and "<bean>" not in resp.text and "<bean/>" not in resp.text
    assert "ProcessBuilder" not in resp.text

    status = internal_get_openwire_callback_status(lab_engagement.id, created.token, db)
    assert status.triggered is True
    assert status.triggered_at is not None


def test_negative_an_unknown_token_returns_a_generic_404(public_client):
    resp = public_client.get("/callback/openwire/this-token-was-never-issued")
    assert resp.status_code == 404


def test_negative_an_expired_token_returns_the_same_generic_404(db, lab_engagement, public_client):
    created = internal_create_openwire_callback_token(lab_engagement.id, OpenwireCallbackTokenCreate(), db)
    row = db.get(OpenwireCallbackToken, created.token)
    row.expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)
    db.commit()

    resp = public_client.get(f"/callback/openwire/{created.token}")
    assert resp.status_code == 404


def test_negative_a_repeat_fetch_of_an_already_triggered_token_404s(db, lab_engagement, public_client):
    """Single-use: the first hit is already the proof; a token must not be a
    standing, replayable probe of our own infrastructure."""
    created = internal_create_openwire_callback_token(lab_engagement.id, OpenwireCallbackTokenCreate(), db)
    db.commit()

    first = public_client.get(f"/callback/openwire/{created.token}")
    second = public_client.get(f"/callback/openwire/{created.token}")

    assert first.status_code == 200
    assert second.status_code == 404


def test_the_public_endpoint_requires_no_authentication(public_client, db, lab_engagement):
    """The whole point - a probed target cannot present ANY of this
    platform's own credentials. No Authorization header, no internal token,
    no session cookie, no engagement-ownership check."""
    created = internal_create_openwire_callback_token(lab_engagement.id, OpenwireCallbackTokenCreate(), db)
    db.commit()
    resp = public_client.get(f"/callback/openwire/{created.token}")  # no auth headers at all
    assert resp.status_code == 200


def test_negative_the_callback_route_is_not_registered_under_internal_or_authenticated_routers():
    """Wiring guard: this must be reachable without require_user or the
    internal token - a route registered under the wrong router would either
    401/403 a real target or (worse) silently require credentials no target
    could ever supply, making the whole probe permanently non-functional."""
    from app.api import api_router

    matching = [r for r in api_router.routes if getattr(r, "path", "") == "/callback/openwire/{token}"]
    assert matching, "route not registered"
    dependant = matching[0].dependant
    dep_names = {getattr(d.call, "__name__", "") for d in dependant.dependencies}
    assert "require_user" not in dep_names
    assert "require_internal_token" not in dep_names
