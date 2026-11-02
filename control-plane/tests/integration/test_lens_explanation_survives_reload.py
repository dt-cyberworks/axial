"""REQ-LENS-004 (GitHub issue #82): a Lens Agent analysis the server has saved comes back in both finding lists.

The console shows the text from its own state only until the list reloads; after that (and after closing and
reopening the finding, or reloading the page) it reads the text from `evidence.lens_agent` in the list
response. These tests prove that half of the contract through the HTTP stack, with real sessions, and only the
LLM call replaced. The browser half is `frontend/browser_tests/finding_lens_stays_open.py`.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app import auth_service
from app.api import findings as findings_api
from app.api.internal import add_finding
from app.db.base import get_db
from app.main import app
from app.models.engagement import Engagement
from app.models.finding import Finding
from app.models.user import User
from app.passwords import hash_secret
from app.schemas.internal import FindingIn

EXPLANATION = "## What it is\nA missing browser security header.\n\n## What to do\nSet the header."


@pytest.fixture()
def client(engine):
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def _override_get_db():
        s = SessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


def _user(db, role: str = "operator") -> User:
    user = User(email=f"{role}-{uuid.uuid4().hex[:12]}@example.com", display_name="Lens Test",
                role=role, status="active", must_change_password=False,
                password_hash=hash_secret("irrelevant-not-used"))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _auth(db, user: User) -> dict[str, str]:
    raw_token, _ = auth_service.create_session(db, user, ip=None, user_agent=None)
    return {"Authorization": f"Bearer {raw_token}"}


@pytest.fixture()
def owned_finding(db):
    owner = _user(db)
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(title="Lens reload", source="own_domain", status="active",
                     authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
                     owner_user_id=owner.id)
    db.add(eng)
    db.commit()
    db.refresh(eng)
    resp = add_finding(eng.id, FindingIn(
        asset_id=None, service_id=None, category="misconfig", title="Missing Security Headers",
        confidence="validated", evidence={"tool": "nikto"}, exposure_factor=1.0, business_factor=0.5,
        severity_override="low",
    ), db)
    return owner, eng, db.get(Finding, resp["id"])


def _explain(client, headers, eng, finding):
    return client.post(f"/engagements/{eng.id}/findings/{finding.id}/lens-explanation", headers=headers)


def _lens_in(client, headers, eng, finding):
    """The saved Lens entry of the finding in each list, or None, as the console would read it."""
    portfolio = client.get("/findings", headers=headers, params={"engagement_id": str(eng.id)})
    own = client.get(f"/engagements/{eng.id}/findings", headers=headers)
    assert portfolio.status_code == 200, portfolio.text
    assert own.status_code == 200, own.text
    from_portfolio = next(item for item in portfolio.json()["items"] if item["id"] == str(finding.id))
    from_engagement = next(item for item in own.json() if item["id"] == str(finding.id))
    return (from_portfolio["evidence"] or {}).get("lens_agent"), (from_engagement["evidence"] or {}).get("lens_agent")


def test_the_saved_analysis_is_in_both_finding_lists_and_the_second_request_costs_no_call(client, db, monkeypatch, owned_finding):
    owner, eng, finding = owned_finding
    headers = _auth(db, owner)
    calls = []
    monkeypatch.setattr(findings_api, "_call_lens_agent", lambda *_: calls.append(1) or (EXPLANATION, "test-model", False))

    assert _lens_in(client, headers, eng, finding) == (None, None), "nothing is saved before the first request"

    first = _explain(client, headers, eng, finding)
    assert first.status_code == 200, first.text
    assert first.json()["source"] == "llm"

    portfolio, engagement = _lens_in(client, headers, eng, finding)
    for saved in (portfolio, engagement):
        assert saved["explanation"] == EXPLANATION
        assert saved["truncated"] is False
        assert saved["model"] == "test-model"

    # Reopening the finding must not need the provider again: the console shows the saved text and the
    # server answers a repeated request from the same copy.
    again = _explain(client, headers, eng, finding)
    assert again.json()["source"] == "cached"
    assert again.json()["explanation"] == EXPLANATION
    assert calls == [1]


def test_a_failed_request_saves_nothing_so_a_later_one_can_still_succeed(client, db, monkeypatch, owned_finding):
    owner, eng, finding = owned_finding
    headers = _auth(db, owner)

    def provider_down(*_):
        raise HTTPException(status_code=503, detail="no LLM provider configured")

    monkeypatch.setattr(findings_api, "_call_lens_agent", provider_down)
    failed = _explain(client, headers, eng, finding)
    assert failed.status_code == 503
    assert _lens_in(client, headers, eng, finding) == (None, None)

    monkeypatch.setattr(findings_api, "_call_lens_agent", lambda *_: (EXPLANATION, "test-model", False))
    retried = _explain(client, headers, eng, finding)
    assert retried.status_code == 200
    assert retried.json()["source"] == "llm"
    assert all(saved["explanation"] == EXPLANATION for saved in _lens_in(client, headers, eng, finding))


def test_another_operator_reads_the_saved_text_but_cannot_ask_for_one(client, db, monkeypatch, owned_finding):
    """REQ-IAM-025 [negative]: everyone reads the finding lists, only the owner (or an admin) spends a provider call."""
    owner, eng, finding = owned_finding
    reader = _user(db)
    monkeypatch.setattr(findings_api, "_call_lens_agent", lambda *_: (EXPLANATION, "test-model", False))

    refused = _explain(client, _auth(db, reader), eng, finding)
    assert refused.status_code == 403
    assert _lens_in(client, _auth(db, reader), eng, finding) == (None, None), "a refused request saves nothing"

    assert _explain(client, _auth(db, owner), eng, finding).status_code == 200
    for saved in _lens_in(client, _auth(db, reader), eng, finding):
        assert saved["explanation"] == EXPLANATION
