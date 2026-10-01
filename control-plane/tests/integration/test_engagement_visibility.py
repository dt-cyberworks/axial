"""REQ-IAM-021..024 (GitHub issue #47, R3): every signed-in user reads every engagement,
only its owner or an administrator changes it, no engagement is ownerless, and the
activation overlap error names the engagement in the way.

The rule lives in ONE place (`app.security.enforce_engagement_access`, wired once on the
public router). These tests prove it three ways: the rule itself, every engagement route
of the real app (so a route added later cannot forget it), and the effects (nothing is
written when a non-owner tries)."""

from __future__ import annotations

import datetime as dt
import pathlib
import uuid

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request

from app import auth_service
from app.api.engagements import activate_engagement, add_scope_asset, create_engagement
from app.api.internal import internal_create_benchmark_engagement
from app.db.base import get_db
from app.main import app
from app.models.approval import ApprovalRequest
from app.models.engagement import Engagement, ScopeAsset
from app.models.user import User
from app.passwords import hash_secret
from app.schemas.engagement import EngagementCreate, ScopeAssetCreate
from app.schemas.internal import BenchmarkEngagementCreate
from app.security import NOT_OWNER_DETAIL, enforce_engagement_access

MIGRATION = pathlib.Path(__file__).resolve().parents[2] / "migrations" / "0038_engagement_owner_required.sql"
READS = ("GET", "HEAD", "OPTIONS")
WRITES = ("POST", "PUT", "PATCH", "DELETE")


# ----------------------------------------------------------------------------------- helpers

def _client(engine) -> TestClient:
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def _override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    # A route that fails for an unrelated reason must not hide the access answer: a server error is a status.
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture()
def client(engine):
    yield _client(engine)
    app.dependency_overrides.clear()


def _user(db, *, role="operator", name="Test Person", status="active", created_at=None) -> User:
    user = User(
        email=f"{role}-{uuid.uuid4().hex[:10]}@example.com", display_name=name, role=role, status=status,
        must_change_password=False, password_hash=hash_secret("irrelevant-not-used"),
    )
    if created_at is not None:
        user.created_at = created_at
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _headers(db, user: User) -> dict[str, str]:
    raw, _ = auth_service.create_session(db, user, ip=None, user_agent=None)
    return {"Authorization": f"Bearer {raw}"}


def _engagement(db, owner: User, *, title="Owned", status="active") -> Engagement:
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        title=title, source="own_domain", status=status, owner_user_id=owner.id,
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
    )
    db.add(eng)
    db.commit()
    db.refresh(eng)
    return eng


def _request(method: str, engagement_id: object) -> Request:
    return Request({"type": "http", "method": method, "headers": [], "path_params": {"engagement_id": str(engagement_id)}})


def _routes() -> list[tuple[str, str]]:
    found = []
    for route in app.routes:
        if isinstance(route, APIRoute) and route.path.startswith("/engagements/{engagement_id}"):
            found += [(method, route.path) for method in sorted(route.methods - {"HEAD", "OPTIONS"})]
    return sorted(found)


def _fill(path: str, engagement_id: uuid.UUID) -> str:
    out = path.replace("{engagement_id}", str(engagement_id))
    while "{" in out:
        start = out.index("{")
        out = out[:start] + str(uuid.uuid4()) + out[out.index("}") + 1:]
    return out


# -------------------------------------------------------------------- the rule itself (REQ-IAM-022/023)

@pytest.mark.parametrize("method", READS)
def test_a_non_owner_may_read(db, method):
    owner, other = _user(db), _user(db)
    eng = _engagement(db, owner)
    assert enforce_engagement_access(_request(method, eng.id), other, db) is None


@pytest.mark.parametrize("method", WRITES)
def test_negative_a_non_owner_may_not_change_it(db, method):
    owner, other = _user(db), _user(db)
    eng = _engagement(db, owner)
    with pytest.raises(HTTPException) as refused:
        enforce_engagement_access(_request(method, eng.id), other, db)
    assert refused.value.status_code == 403 and refused.value.detail == NOT_OWNER_DETAIL


@pytest.mark.parametrize("method", READS + WRITES)
def test_the_owner_and_an_admin_may_do_everything(db, method):
    owner, admin = _user(db), _user(db, role="admin")
    eng = _engagement(db, owner)
    assert enforce_engagement_access(_request(method, eng.id), owner, db) is None
    assert enforce_engagement_access(_request(method, eng.id), admin, db) is None


@pytest.mark.parametrize("method", READS + WRITES)
def test_negative_an_unknown_engagement_is_404_for_a_non_admin_whatever_the_method(db, method):
    with pytest.raises(HTTPException) as refused:
        enforce_engagement_access(_request(method, uuid.uuid4()), _user(db), db)
    assert refused.value.status_code == 404


def test_a_request_without_an_engagement_in_the_path_is_not_this_rules_business(db):
    request = Request({"type": "http", "method": "POST", "headers": [], "path_params": {}})
    assert enforce_engagement_access(request, _user(db), db) is None
    assert enforce_engagement_access(_request("POST", "not-a-uuid"), _user(db), db) is None


def test_negative_an_ownership_change_of_the_account_does_not_survive_a_role_downgrade(db):
    """The rule reads the caller's role at request time: an admin turned operator loses the right at once."""
    owner, was_admin = _user(db), _user(db, role="admin")
    eng = _engagement(db, owner)
    assert enforce_engagement_access(_request("DELETE", eng.id), was_admin, db) is None
    was_admin.role = "operator"
    db.commit()
    with pytest.raises(HTTPException) as refused:
        enforce_engagement_access(_request("DELETE", eng.id), was_admin, db)
    assert refused.value.status_code == 403


# ------------------------------------------------ every engagement route of the real app (REQ-IAM-023)

def test_the_sweep_finds_the_routes_it_is_meant_to_sweep():
    routes = _routes()
    writes = [r for r in routes if r[0] in WRITES]
    reads = [r for r in routes if r[0] == "GET"]
    assert len(writes) >= 15 and len(reads) >= 20, (len(writes), len(reads))
    assert ("PATCH", "/engagements/{engagement_id}") in writes and ("DELETE", "/engagements/{engagement_id}") in writes
    assert ("POST", "/engagements/{engagement_id}/scan") in writes
    assert ("PATCH", "/engagements/{engagement_id}/findings/{finding_id}") in writes
    assert ("GET", "/engagements/{engagement_id}/audit") in reads


def test_every_engagement_route_is_behind_the_access_rule():
    """A route mounted outside the public router would skip the rule: find it here, not in production."""
    def depends_on(dependant, call) -> bool:
        return any(dep.call is call or depends_on(dep, call) for dep in dependant.dependencies)

    unguarded = [
        f"{sorted(route.methods)} {route.path}" for route in app.routes
        if isinstance(route, APIRoute) and "{engagement_id}" in route.path
        and not route.path.startswith("/internal") and not depends_on(route.dependant, enforce_engagement_access)
    ]
    assert unguarded == []


@pytest.mark.parametrize("method, path", [r for r in _routes() if r[0] in WRITES])
def test_negative_every_changing_route_refuses_a_non_owner_with_403(client, db, method, path):
    owner, other = _user(db), _user(db)
    eng = _engagement(db, owner)
    resp = client.request(method, _fill(path, eng.id), headers=_headers(db, other), json={})
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"] == NOT_OWNER_DETAIL


@pytest.mark.parametrize("method, path", [r for r in _routes() if r[0] == "GET" and not r[1].endswith("/stream")])
def test_every_reading_route_lets_a_non_owner_in(client, db, method, path):
    """Read-only for everyone: not 401, not 403, and never the 'engagement not found' of the old rule.
    (The live stream is covered by the rule's own tests above: it only differs by being long-lived.)"""
    owner, other = _user(db), _user(db)
    eng = _engagement(db, owner)
    resp = client.request(method, _fill(path, eng.id), headers=_headers(db, other))
    assert resp.status_code not in (401, 403), (resp.status_code, resp.text[:200])
    if resp.status_code == 404:
        assert resp.json().get("detail") != "engagement not found"


def test_negative_nothing_is_written_when_a_non_owner_tries_every_changing_route(client, db):
    owner, other = _user(db), _user(db)
    eng = _engagement(db, owner)
    tables = ("engagement", "scope_asset", "tool_grant", "tool_approval_policy", "scan_run", "report", "finding",
              "audit_log", "bounty_program", "asset_review_request", "approval_request", "app_user")

    def snapshot() -> dict:
        db.expire_all()
        counts = {t: db.execute(text(f"SELECT count(*) FROM {t}")).scalar() for t in tables if t != "engagement"}
        row = db.execute(text("SELECT title, status, owner_user_id::text, scan_profile FROM engagement WHERE id = :i"),
                         {"i": eng.id}).one()
        return counts | {"engagement": tuple(row)}

    before = snapshot()
    headers = _headers(db, other)
    for method, path in (r for r in _routes() if r[0] in WRITES):
        assert client.request(method, _fill(path, eng.id), headers=headers, json={"title": "taken"}).status_code == 403
    assert snapshot() == before  # nothing of the engagement, its scope, grants, runs or audit log moved


# ---------------------------------------------------------------------------- reading and owner data

def test_the_list_and_the_detail_carry_the_owner_and_what_the_caller_may_do(client, db):
    owner = _user(db, name="Olive Owner")
    other = _user(db, name="Otto Other")
    admin = _user(db, role="admin", name="Ada Admin")
    eng = _engagement(db, owner, title="Olive's shop")
    expected = {owner: True, other: False, admin: True}
    for caller, may in expected.items():
        listed = {e["title"]: e for e in client.get("/engagements", headers=_headers(db, caller)).json()}
        assert listed["Olive's shop"]["can_manage"] is may
        assert listed["Olive's shop"]["owner_name"] == "Olive Owner" and listed["Olive's shop"]["owner_email"] == owner.email
        detail = client.get(f"/engagements/{eng.id}", headers=_headers(db, caller)).json()
        assert detail["can_manage"] is may and detail["owner_user_id"] == str(owner.id)


def test_a_non_owner_reads_the_same_findings_audit_and_reports_as_the_owner(client, db):
    owner, other = _user(db), _user(db)
    eng = _engagement(db, owner)
    for path in ("findings", "audit", "scan-runs", "summary", "scope-assets", "tool-grants", "config", "reports"):
        mine = client.get(f"/engagements/{eng.id}/{path}", headers=_headers(db, owner))
        theirs = client.get(f"/engagements/{eng.id}/{path}", headers=_headers(db, other))
        assert theirs.status_code == mine.status_code == 200, (path, theirs.status_code, mine.status_code)
        if path != "audit":  # the audit log differs by the sessions' own requests, nothing else
            assert theirs.json() == mine.json(), path


def test_negative_without_credentials_or_with_a_disabled_account_nothing_is_read(client, db):
    owner, leaver = _user(db), _user(db)
    eng = _engagement(db, owner)
    headers = _headers(db, leaver)
    assert client.get(f"/engagements/{eng.id}", headers=headers).status_code == 200
    leaver.status = "disabled"
    db.commit()
    assert client.get(f"/engagements/{eng.id}").status_code == 401
    assert client.get("/engagements").status_code == 401
    assert client.get(f"/engagements/{eng.id}", headers=headers).status_code == 401


def test_the_pending_approval_queue_stays_the_owners_own(client, db):
    owner, other, admin = _user(db), _user(db), _user(db, role="admin")
    eng = _engagement(db, owner)
    now = dt.datetime.now(dt.timezone.utc)
    approval = ApprovalRequest(engagement_id=eng.id, state="requested", expires_at=now + dt.timedelta(minutes=15),
                               tool_call={"tool": "http_request", "args": {"method": "POST"}})
    db.add(approval)
    db.commit()
    ids = {u.id: [a["id"] for a in client.get("/approvals", headers=_headers(db, u)).json()] for u in (owner, other, admin)}
    assert ids[owner.id] == [str(approval.id)] and ids[admin.id] == [str(approval.id)]
    assert ids[other.id] == []  # readable engagement, but not their action queue
    assert client.post(f"/approvals/{approval.id}/approve", json={}, headers=_headers(db, other)).status_code == 403
    assert client.post(f"/approvals/{approval.id}/approve", json={}, headers=_headers(db, admin)).status_code == 200


# ------------------------------------------------------------------------------ owner reassignment

def test_only_an_admin_reassigns_an_owner_and_never_to_nobody(client, db):
    owner, other, admin = _user(db), _user(db), _user(db, role="admin")
    eng = _engagement(db, owner)
    body = {"owner_user_id": str(other.id)}
    assert client.put(f"/engagements/{eng.id}/owner", json=body, headers=_headers(db, other)).status_code == 403
    owner_try = client.put(f"/engagements/{eng.id}/owner", json=body, headers=_headers(db, owner))
    assert owner_try.status_code == 403 and owner_try.json()["detail"] == "admin role required"
    assert client.put(f"/engagements/{eng.id}/owner", json={"owner_user_id": None}, headers=_headers(db, admin)).status_code == 422
    assert client.put(f"/engagements/{eng.id}/owner", json={"owner_user_id": str(uuid.uuid4())},
                      headers=_headers(db, admin)).status_code == 404
    done = client.put(f"/engagements/{eng.id}/owner", json=body, headers=_headers(db, admin))
    assert done.status_code == 200 and done.json()["owner_user_id"] == str(other.id)
    assert done.json()["owner_email"] == other.email
    # The new owner may now change it; the former owner may not, but still reads.
    assert client.patch(f"/engagements/{eng.id}", json={"title": "Now mine"}, headers=_headers(db, other)).status_code == 200
    assert client.patch(f"/engagements/{eng.id}", json={"title": "Not mine"}, headers=_headers(db, owner)).status_code == 403
    assert client.get(f"/engagements/{eng.id}", headers=_headers(db, owner)).status_code == 200


# ------------------------------------------------------------- no engagement without an owner (REQ-IAM-021)

def test_negative_the_database_refuses_an_engagement_without_an_owner(db):
    now = dt.datetime.now(dt.timezone.utc)
    db.add(Engagement(title="Nobody's", source="own_domain", status="draft",
                      authorized_from=now, authorized_until=now + dt.timedelta(days=1)))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_the_owner_of_a_created_engagement_is_the_caller_and_the_response_says_so(client, db):
    caller = _user(db, name="Cara Caller")
    now = dt.datetime.now(dt.timezone.utc)
    resp = client.post("/engagements", headers=_headers(db, caller), json={
        "title": "New one", "source": "own_domain", "authorized_from": now.isoformat(),
        "authorized_until": (now + dt.timedelta(days=1)).isoformat(), "owner_user_id": str(uuid.uuid4()),
    })
    assert resp.status_code == 201
    assert resp.json()["owner_user_id"] == str(caller.id) and resp.json()["can_manage"] is True
    assert resp.json()["owner_name"] == "Cara Caller"


def _migrate_ownerless(engine, ownerless_rows: int, admins: list[tuple[str, str, str]]):
    """Re-run migration 0038 on a database that has ownerless engagements, then put the schema back."""
    sql = MIGRATION.read_text()
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE engagement ALTER COLUMN owner_user_id DROP NOT NULL"))
        for email, role, created in admins:
            conn.execute(text(
                "INSERT INTO app_user (email, display_name, password_hash, role, status, must_change_password, created_at)"
                " VALUES (:e, :e, 'x', :r, 'active', false, :c)"), {"e": email, "r": role, "c": created})
        for i in range(ownerless_rows):
            conn.execute(text(
                "INSERT INTO engagement (title, status, source, authorized_from, authorized_until)"
                " VALUES (:t, 'active', 'own_domain', now(), now() + interval '1 day')"), {"t": f"legacy-{i}"})
    return sql


def _restore_schema(engine):
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM scope_asset WHERE engagement_id IN (SELECT id FROM engagement WHERE owner_user_id IS NULL)"))
        conn.execute(text("DELETE FROM engagement WHERE owner_user_id IS NULL"))
        conn.execute(text("ALTER TABLE engagement ALTER COLUMN owner_user_id SET NOT NULL"))


def test_the_migration_gives_ownerless_engagements_to_the_oldest_active_admin(engine, db):
    try:
        sql = _migrate_ownerless(engine, 2, [
            ("newer-admin@example.com", "admin", "2026-02-01T00:00:00Z"),
            ("oldest-admin@example.com", "admin", "2026-01-01T00:00:00Z"),
            ("older-operator@example.com", "operator", "2025-12-01T00:00:00Z"),
        ])
        with engine.begin() as conn:
            conn.execute(text("UPDATE app_user SET status = 'disabled' WHERE email = 'older-operator@example.com'"))
            conn.execute(text(sql))
            owners = {r[0] for r in conn.execute(text("SELECT u.email FROM engagement e JOIN app_user u ON u.id = e.owner_user_id"))}
            nullable = conn.execute(text(
                "SELECT is_nullable FROM information_schema.columns WHERE table_name='engagement' AND column_name='owner_user_id'")).scalar()
            conn.execute(text(sql))  # idempotent: a second run changes nothing and does not fail
        assert owners == {"oldest-admin@example.com"} and nullable == "NO"
    finally:
        _restore_schema(engine)


def test_negative_the_migration_stops_and_changes_nothing_when_no_administrator_exists(engine, db):
    try:
        sql = _migrate_ownerless(engine, 1, [("only-operator@example.com", "operator", "2026-01-01T00:00:00Z")])
        with pytest.raises(Exception, match="no active administrator"):
            with engine.begin() as conn:
                conn.execute(text(sql))
        with engine.begin() as conn:
            assert conn.execute(text("SELECT count(*) FROM engagement WHERE owner_user_id IS NULL")).scalar() == 1
            assert conn.execute(text(
                "SELECT is_nullable FROM information_schema.columns WHERE table_name='engagement' AND column_name='owner_user_id'"
            )).scalar() == "YES"
    finally:
        _restore_schema(engine)


def test_the_benchmark_harness_creates_its_engagement_under_the_oldest_active_admin(db):
    _user(db, role="admin", name="Newer", created_at=dt.datetime(2026, 3, 1, tzinfo=dt.timezone.utc))
    oldest = _user(db, role="admin", name="Oldest", created_at=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
    _user(db, role="admin", name="Gone", status="disabled", created_at=dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc))
    _user(db, role="operator", name="Operator", created_at=dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc))
    created = internal_create_benchmark_engagement(
        BenchmarkEngagementCreate(title="bench", target_host="bench.example.test", tcp_port_from=1, tcp_port_to=1024), db)
    assert db.get(Engagement, uuid.UUID(created["id"])).owner_user_id == oldest.id


def test_negative_the_benchmark_harness_without_any_active_admin_creates_nothing(db):
    _user(db, role="operator")
    with pytest.raises(HTTPException) as refused:
        internal_create_benchmark_engagement(
            BenchmarkEngagementCreate(title="bench", target_host="bench.example.test", tcp_port_from=1, tcp_port_to=1024), db)
    assert refused.value.status_code == 409
    assert db.query(Engagement).count() == 0


# ----------------------------------------------------------------- the overlap error names it (REQ-IAM-024)

def _draft(db, owner: User, title: str) -> Engagement:
    now = dt.datetime.now(dt.timezone.utc)
    return create_engagement(EngagementCreate(
        title=title, source="own_domain", authorized_from=now - dt.timedelta(hours=1),
        authorized_until=now + dt.timedelta(days=1)), user=owner, db=db)


def _allow(db, eng, value: str) -> None:
    db.add(ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain", value=value,
                      active_allowed=True, authorization_verified=True))
    db.commit()


def _activate_active(db, owner: User, title: str, value: str) -> Engagement:
    eng = _draft(db, owner, title)
    _allow(db, eng, value)
    activate_engagement(eng.id, db, user=owner)
    return eng


def test_the_activation_conflict_names_the_engagement_and_its_owner(db):
    blocker_owner = _user(db, name="Bea Blocker")
    mine = _user(db, name="Alex Applicant")
    _activate_active(db, blocker_owner, "Bea's shop", "shop.example.test")
    draft = _draft(db, mine, "Alex's copy")
    _allow(db, draft, "shop.example.test")
    with pytest.raises(HTTPException) as refused:
        activate_engagement(draft.id, db, user=mine)
    assert refused.value.status_code == 409
    detail = refused.value.detail
    assert detail.startswith("allow-scope overlaps another currently active engagement's allow-scope")
    assert '"Bea\'s shop"' in detail and "owner Bea Blocker" in detail and blocker_owner.email in detail
    db.refresh(draft)
    assert draft.status == "draft"


def test_the_conflict_names_at_most_three_and_counts_the_rest(db):
    owner = _user(db, name="Many Owner")
    for i in range(4):
        _activate_active(db, owner, f"Blocker {i}", f"b{i}.example.test")
    draft = _draft(db, _user(db), "Wide")
    _allow(db, draft, "example.test")
    with pytest.raises(HTTPException) as refused:
        activate_engagement(draft.id, db, user=owner)
    detail = refused.value.detail
    assert detail.count("(owner Many Owner") == 3 and detail.endswith("resolve the conflict with its owner before activating")
    assert "and 1 more" in detail


def test_adding_overlapping_scope_to_an_active_engagement_names_it_too(db):
    blocker = _user(db, name="Bea Blocker")
    mine = _user(db, name="Alex Applicant")
    _activate_active(db, blocker, "Bea's shop", "shop.example.test")
    other = _activate_active(db, mine, "Alex's site", "alex.example.test")
    with pytest.raises(HTTPException) as refused:
        add_scope_asset(other.id, ScopeAssetCreate(rule="allow", asset_type="domain", value="shop.example.test",
                                                    active_allowed=True, authorization_verified=True), db, user=mine)
    assert refused.value.status_code == 409 and "Bea's shop" in refused.value.detail


def test_negative_without_an_overlap_nothing_is_refused_and_nothing_is_named(db):
    _activate_active(db, _user(db), "Elsewhere", "elsewhere.example.test")
    mine = _user(db)
    draft = _draft(db, mine, "Mine")
    _allow(db, draft, "mine.example.test")
    activated = activate_engagement(draft.id, db, user=mine)
    assert activated.status == "active" and activated.can_manage is True
