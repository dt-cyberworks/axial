"""REQ-PORTFOLIO-001 (docs/requirements/cross-engagement-findings.md).

GET /findings carries no engagement_id in its path, so the router-wide
ownership check never runs for it. These tests prove the handler's own
ownership filter: through the HTTP stack, with real sessions.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app import auth_service
from app.api.internal import add_finding
from app.db.base import get_db
from app.main import app
from app.models.asset import DiscoveredAsset
from app.models.engagement import Engagement
from app.models.finding import Finding
from app.models.scan_run import ScanRun
from app.models.user import User
from app.passwords import hash_secret
from app.schemas.internal import FindingIn


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
    user = User(email=f"{role}-{uuid.uuid4().hex[:12]}@example.com", display_name="Portfolio Test",
                role=role, status="active", must_change_password=False,
                password_hash=hash_secret("irrelevant-not-used"))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _auth(db, user: User) -> dict[str, str]:
    raw_token, _ = auth_service.create_session(db, user, ip=None, user_agent=None)
    return {"Authorization": f"Bearer {raw_token}"}


def _engagement(db, owner: User, title: str = "Portfolio") -> Engagement:
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(title=title, source="own_domain", status="active",
                     authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
                     owner_user_id=owner.id)
    db.add(eng)
    db.commit()
    db.refresh(eng)
    return eng


def _asset(db, eng: Engagement, value: str) -> DiscoveredAsset:
    asset = DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value=value, in_scope=True,
                            discovered_via="test")
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def _finding(db, eng: Engagement, title: str, severity: str = "medium", *,
             asset: DiscoveredAsset | None = None, business_factor: float = 0.5) -> Finding:
    resp = add_finding(eng.id, FindingIn(
        asset_id=asset.id if asset else None, service_id=None, category="misconfig", title=title,
        confidence="validated", evidence={"tool": "nuclei"}, exposure_factor=1.0,
        business_factor=business_factor, severity_override=severity,
    ), db)
    return db.get(Finding, resp["id"])


def _titles(resp) -> list[str]:
    assert resp.status_code == 200, resp.text
    return [item["title"] for item in resp.json()["items"]]


@pytest.fixture()
def two_operators(db):
    """Operator A and operator B, each with one engagement and findings."""
    a, b = _user(db), _user(db)
    eng_a, eng_b = _engagement(db, a, "A's shop"), _engagement(db, b, "B's bank")
    _finding(db, eng_a, "A: directory listing", "medium")
    _finding(db, eng_a, "A: outdated TLS", "high")
    _finding(db, eng_b, "B-SECRET: exposed admin panel", "critical", asset=_asset(db, eng_b, "admin.b-bank.example"))
    return a, b, eng_a, eng_b


# --- visibility (REQ-IAM-022, GitHub issue #47): everyone reads everything; `mine` narrows --------------

def test_an_operator_sees_the_findings_of_every_engagement_with_their_owner(client, db, two_operators):
    a, b, eng_a, eng_b = two_operators
    resp = client.get("/findings", headers=_auth(db, a))
    assert sorted(_titles(resp)) == ["A: directory listing", "A: outdated TLS", "B-SECRET: exposed admin panel"]
    body = resp.json()
    assert body["total"] == 3
    assert {item["engagement_id"] for item in body["items"]} == {str(eng_a.id), str(eng_b.id)}
    assert {item["engagement_owner"] for item in body["items"]} == {"Portfolio Test"}
    # The counts cover the same rows as the page.
    assert body["counts_by_severity"]["critical"] == 1
    assert body["counts_by_status"]["open"] == 3


def test_mine_narrows_the_list_the_total_and_the_counts_to_the_callers_engagements(client, db, two_operators):
    a, _b, eng_a, _eng_b = two_operators
    resp = client.get("/findings", params={"mine": "true"}, headers=_auth(db, a))
    assert sorted(_titles(resp)) == ["A: directory listing", "A: outdated TLS"]
    body = resp.json()
    assert body["total"] == 2
    assert {item["engagement_id"] for item in body["items"]} == {str(eng_a.id)}
    assert body["counts_by_severity"]["critical"] == 0
    assert body["counts_by_status"]["open"] == 2


def test_an_engagement_filter_shows_another_users_engagement_but_not_with_mine(client, db, two_operators):
    a, _b, _eng_a, eng_b = two_operators
    headers = _auth(db, a)
    shown = client.get("/findings", params={"engagement_id": str(eng_b.id)}, headers=headers)
    assert _titles(shown) == ["B-SECRET: exposed admin panel"]
    narrowed = client.get("/findings", params={"engagement_id": str(eng_b.id), "mine": "true"}, headers=headers)
    unknown = client.get("/findings", params={"engagement_id": str(uuid.uuid4())}, headers=headers)
    assert narrowed.status_code == unknown.status_code == 200
    assert narrowed.json() == unknown.json()
    assert narrowed.json()["items"] == [] and narrowed.json()["total"] == 0
    assert sum(narrowed.json()["counts_by_status"].values()) == 0


def test_search_finds_another_users_findings_unless_narrowed_to_mine(client, db, two_operators):
    a, _b, _eng_a, _eng_b = two_operators
    headers = _auth(db, a)
    for q in ("B-SECRET", "admin.b-bank", "exposed admin panel"):
        assert _titles(client.get("/findings", params={"q": q}, headers=headers)) == ["B-SECRET: exposed admin panel"], q
        narrowed = client.get("/findings", params={"q": q, "mine": "true"}, headers=headers)
        assert _titles(narrowed) == [] and narrowed.json()["total"] == 0, q


def test_negative_without_a_session_the_endpoint_answers_401(client, two_operators):
    assert client.get("/findings").status_code == 401
    assert client.get("/findings", headers={"Authorization": "Bearer not-a-real-token"}).status_code == 401


def test_admin_sees_findings_of_all_engagements(client, db, two_operators):
    _a, _b, eng_a, eng_b = two_operators
    admin = _user(db, "admin")
    resp = client.get("/findings", params={"limit": 200}, headers=_auth(db, admin))
    ours = {item["title"] for item in resp.json()["items"] if item["engagement_id"] in {str(eng_a.id), str(eng_b.id)}}
    assert ours == {"A: directory listing", "A: outdated TLS", "B-SECRET: exposed admin panel"}


# --- filters, order, paging ------------------------------------------------------

def test_negative_unknown_status_severity_and_bad_paging_are_rejected(client, db, two_operators):
    headers = _auth(db, two_operators[0])
    for params in ({"status": "closed"}, {"severity": "urgent"}, {"limit": 0}, {"limit": 201}, {"offset": -1}):
        assert client.get("/findings", params=params, headers=headers).status_code == 422, params


def test_order_is_severity_then_risk_score_and_paging_keeps_the_total(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    _finding(db, eng, "low one", "low")
    _finding(db, eng, "critical one", "critical")
    _finding(db, eng, "high, lower risk", "high", business_factor=0.2)
    _finding(db, eng, "high, higher risk", "high", business_factor=0.9)
    headers = _auth(db, owner)
    assert _titles(client.get("/findings", headers=headers)) == [
        "critical one", "high, higher risk", "high, lower risk", "low one"]
    page = client.get("/findings", params={"limit": 2, "offset": 2}, headers=headers)
    assert _titles(page) == ["high, lower risk", "low one"]
    assert page.json()["total"] == 4 and page.json()["limit"] == 2 and page.json()["offset"] == 2


def test_items_carry_the_engagement_title_and_the_usual_finding_fields(client, db):
    owner = _user(db)
    eng = _engagement(db, owner, "Customer portal")
    db.add(ScanRun(engagement_id=eng.id, state="running"))  # observations belong to a run
    db.commit()
    _finding(db, eng, "Missing HSTS", "low", asset=_asset(db, eng, "portal.example"))
    item = client.get("/findings", headers=_auth(db, owner)).json()["items"][0]
    assert item["engagement_title"] == "Customer portal"
    assert item["asset_value"] == "portal.example"
    assert item["status"] == "open" and item["severity"] == "low"
    assert item["last_seen"] is not None


def test_filters_by_status_severity_and_engagement_with_matching_counts(client, db):
    owner = _user(db)
    eng1, eng2 = _engagement(db, owner, "one"), _engagement(db, owner, "two")
    _finding(db, eng1, "one-high", "high")
    _finding(db, eng1, "one-medium", "medium")
    dismissed = _finding(db, eng2, "two-high", "high")
    headers = _auth(db, owner)
    assert client.patch(f"/engagements/{eng2.id}/findings/{dismissed.id}",
                        json={"status": "false_positive", "note": "lab fixture"}, headers=headers).status_code == 200

    body = client.get("/findings", params={"severity": "high"}, headers=headers).json()
    assert [i["title"] for i in body["items"]] == ["one-high"]
    # counts_by_status ignores the status filter but keeps the severity filter ...
    assert body["counts_by_status"] == {"open": 1, "accepted_risk": 0, "false_positive": 1, "resolved": 0}
    # ... counts_by_severity ignores the severity filter but keeps the status filter.
    assert body["counts_by_severity"] == {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0}

    assert _titles(client.get("/findings", params={"status": "false_positive"}, headers=headers)) == ["two-high"]
    assert sorted(_titles(client.get("/findings", params={"engagement_id": str(eng1.id)}, headers=headers))) == [
        "one-high", "one-medium"]


def test_search_matches_title_or_target_case_insensitively_and_literally(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    _finding(db, eng, "Directory listing enabled", asset=_asset(db, eng, "shop.example"))
    _finding(db, eng, "Coverage 100% of paths", asset=_asset(db, eng, "blog.example"))
    _finding(db, eng, "Outdated jQuery")
    headers = _auth(db, owner)
    assert _titles(client.get("/findings", params={"q": "DIRECTORY"}, headers=headers)) == ["Directory listing enabled"]
    assert _titles(client.get("/findings", params={"q": "shop.exa"}, headers=headers)) == ["Directory listing enabled"]
    # % and _ are text, not wildcards.
    assert _titles(client.get("/findings", params={"q": "%"}, headers=headers)) == ["Coverage 100% of paths"]
    assert _titles(client.get("/findings", params={"q": "_"}, headers=headers)) == []
    # Blank search is no filter.
    assert len(_titles(client.get("/findings", params={"q": "   "}, headers=headers))) == 3
