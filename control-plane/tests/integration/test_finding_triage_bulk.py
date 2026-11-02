"""REQ-TRIAGE-005/006: triage many findings in one action, and undo it as a unit.

The point of the negative tests: a bulk action is only a faster way to make the same decision for
EXISTING findings, each as itself. It must be atomic, owner-only, audited per finding, and it must
never reach a finding that does not exist yet or one the caller did not name."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app import auth_service
from app.api.internal import add_finding
from app.db.base import get_db
from app.gateway.audit import verify_audit_chain
from app.main import app
from app.models.asset import DiscoveredAsset
from app.models.audit import AuditLog
from app.models.engagement import Engagement
from app.models.finding import Finding
from app.models.scan_run import ScanRun
from app.models.user import User
from app.passwords import hash_secret
from app.schemas.internal import FindingIn

TITLE = "TLS: cert_trust - certificate does not match supplied URI"


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
    user = User(email=f"{role}-{uuid.uuid4().hex[:8]}@example.com", display_name="Bulk Test", role=role,
                status="active", must_change_password=False, password_hash=hash_secret("not-used"))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _auth(db, user: User) -> dict[str, str]:
    raw_token, _ = auth_service.create_session(db, user, ip=None, user_agent=None)
    return {"Authorization": f"Bearer {raw_token}"}


def _engagement(db, owner: User) -> Engagement:
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(title="Bulk", source="own_domain", status="active",
                     authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
                     owner_user_id=owner.id)
    db.add(eng)
    db.commit()
    db.refresh(eng)
    return eng


def _host(db, eng: Engagement, name: str) -> DiscoveredAsset:
    asset = DiscoveredAsset(engagement_id=eng.id, asset_type="domain", value=name, in_scope=True,
                            discovered_via="test")
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def _observe(db, eng: Engagement, host: str, title: str = TITLE) -> Finding:
    """What the worker does after a scan: report one raw finding on one host."""
    asset = _host(db, eng, host) if not db.scalar(
        select(DiscoveredAsset).where(DiscoveredAsset.engagement_id == eng.id, DiscoveredAsset.value == host)
    ) else db.scalar(select(DiscoveredAsset).where(DiscoveredAsset.engagement_id == eng.id, DiscoveredAsset.value == host))
    resp = add_finding(eng.id, FindingIn(
        asset_id=asset.id, service_id=None, category="misconfig", title=title, confidence="validated",
        evidence={"tool": "testssl"}, exposure_factor=1.0, business_factor=0.5, severity_override="high",
    ), db)
    return db.get(Finding, resp["id"])


def _many(db, eng: Engagement, n: int, title: str = TITLE) -> list[Finding]:
    return [_observe(db, eng, f"host{i}.example.test", title) for i in range(n)]


def _by_id(db, eng: Engagement) -> dict:
    db.expire_all()
    return {f.id: f for f in db.scalars(select(Finding).where(Finding.engagement_id == eng.id))}


def _bulk(client, db, eng, owner, findings, status="false_positive", note="Expected: internal alias name"):
    return client.post(
        f"/engagements/{eng.id}/findings/triage",
        json={"finding_ids": [str(f.id) for f in findings], "status": status, "note": note},
        headers=_auth(db, owner),
    )


# ------------------------------------------------ REQ-TRIAGE-005: the action


def test_many_findings_get_the_decision_each_as_itself(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    findings = _many(db, eng, 6)
    r = _bulk(client, db, eng, owner, findings)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["changed"] == 6 and body["unchanged"] == 0 and body["status"] == "false_positive"
    rows = _by_id(db, eng)
    for f in findings:
        row = rows[f.id]
        assert row.status == "false_positive" and row.status_note == "Expected: internal alias name"
        assert row.status_changed_by == owner.email and row.status_changed_at is not None

    triage = db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id,
                                               AuditLog.action == "finding_triage")).all()
    assert len(triage) == 6, "one audit row per finding"
    assert {a.payload["bulk_id"] for a in triage} == {body["bulk_id"]}
    assert all(a.actor == f"user:{owner.email}" and a.payload["from"] == "open"
               and a.payload["to"] == "false_positive" for a in triage)
    summary = db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id,
                                                AuditLog.action == "finding_triage_bulk")).one()
    assert summary.payload["changed"] == 6 and summary.payload["bulk_id"] == body["bulk_id"]
    assert verify_audit_chain(db, eng.id).ok


def test_duplicate_ids_are_ignored(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    first, second = _many(db, eng, 2)
    r = _bulk(client, db, eng, owner, [first, first, second, first])
    assert r.status_code == 200 and r.json()["changed"] == 2
    assert len(db.scalars(select(AuditLog).where(AuditLog.action == "finding_triage",
                                                 AuditLog.engagement_id == eng.id)).all()) == 2


def test_a_finding_already_in_that_status_is_left_alone_and_not_audited_again(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    first, second, third = _many(db, eng, 3)
    assert _bulk(client, db, eng, owner, [first], note="first decision here").status_code == 200
    r = _bulk(client, db, eng, owner, [first, second, third], note="second decision here")
    body = r.json()
    assert body["changed"] == 2 and body["unchanged"] == 1
    rows = _by_id(db, eng)
    assert rows[first.id].status_note == "first decision here"  # not overwritten
    assert len(db.scalars(select(AuditLog).where(AuditLog.action == "finding_triage",
                                                 AuditLog.engagement_id == eng.id)).all()) == 3


@pytest.mark.parametrize("status", ["resolved", "open"])
def test_resolved_and_reopen_need_no_note(client, db, status):
    owner = _user(db)
    eng = _engagement(db, owner)
    findings = _many(db, eng, 2)
    if status == "open":
        assert _bulk(client, db, eng, owner, findings, status="resolved", note=None).status_code == 200
    r = _bulk(client, db, eng, owner, findings, status=status, note=None)
    assert r.status_code == 200 and r.json()["changed"] == 2


# ------------------------------------------------------------- negatives


@pytest.mark.parametrize("status", ["false_positive", "accepted_risk"])
@pytest.mark.parametrize("note", [None, "", "  ", "ok"])
def test_negative_dismissing_many_findings_still_requires_a_reason(client, db, status, note):
    owner = _user(db)
    eng = _engagement(db, owner)
    findings = _many(db, eng, 3)
    r = _bulk(client, db, eng, owner, findings, status=status, note=note)
    assert r.status_code == 422
    assert {f.status for f in _by_id(db, eng).values()} == {"open"}


def test_negative_the_request_is_atomic_when_one_id_is_not_this_engagements(client, db):
    owner = _user(db)
    eng, other = _engagement(db, owner), _engagement(db, owner)
    mine = _many(db, eng, 3)
    foreign = _observe(db, other, "elsewhere.example.test")
    r = _bulk(client, db, eng, owner, [*mine, foreign])
    assert r.status_code == 404
    assert {f.status for f in _by_id(db, eng).values()} == {"open"}
    assert _by_id(db, other)[foreign.id].status == "open"
    assert db.scalars(select(AuditLog).where(AuditLog.action.like("finding_triage%"))).all() == []


def test_negative_an_unknown_id_fails_everything(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    mine = _many(db, eng, 2)
    ghost = Finding(id=uuid.uuid4())
    r = _bulk(client, db, eng, owner, [*mine, ghost])
    assert r.status_code == 404
    assert {f.status for f in _by_id(db, eng).values()} == {"open"}


def test_negative_a_non_owner_cannot_bulk_triage(client, db):
    owner, other = _user(db), _user(db)
    eng = _engagement(db, owner)
    findings = _many(db, eng, 3)
    r = _bulk(client, db, eng, other, findings)
    assert r.status_code == 403
    assert {f.status for f in _by_id(db, eng).values()} == {"open"}


def test_an_admin_can(client, db):
    owner, admin = _user(db), _user(db, role="admin")
    eng = _engagement(db, owner)
    findings = _many(db, eng, 2)
    r = _bulk(client, db, eng, admin, findings)
    assert r.status_code == 200 and r.json()["changed"] == 2


def test_negative_limits_and_bad_input_are_422(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    h = _auth(db, owner)
    url = f"/engagements/{eng.id}/findings/triage"
    one = _many(db, eng, 1)[0]
    assert client.post(url, json={"finding_ids": [], "status": "resolved"}, headers=h).status_code == 422
    too_many = [str(uuid.uuid4()) for _ in range(501)]
    assert client.post(url, json={"finding_ids": too_many, "status": "resolved"}, headers=h).status_code == 422
    assert client.post(url, json={"finding_ids": [str(one.id)], "status": "deleted"}, headers=h).status_code == 422
    assert client.post(url, json={"finding_ids": ["not-a-uuid"], "status": "resolved"}, headers=h).status_code == 422
    assert client.post(url, json={"status": "resolved"}, headers=h).status_code == 422
    assert _by_id(db, eng)[one.id].status == "open"


def test_exactly_500_is_accepted(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    one = _many(db, eng, 1)[0]
    ids = [str(one.id)] + [str(uuid.uuid4()) for _ in range(499)]
    # 499 of them do not exist: the size is fine, the content is refused
    r = client.post(f"/engagements/{eng.id}/findings/triage",
                    json={"finding_ids": ids, "status": "resolved"}, headers=_auth(db, owner))
    assert r.status_code == 404


# -------------------------- the decision is about THESE findings, not a rule


def test_negative_the_same_vulnerability_on_a_new_host_is_a_new_open_finding(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    marked = _many(db, eng, 3)
    assert _bulk(client, db, eng, owner, marked).status_code == 200

    new = _observe(db, eng, "brand-new.example.test")  # same title, a host not seen before
    rows = _by_id(db, eng)
    assert rows[new.id].status == "open"
    assert sorted(f.status for f in rows.values()) == ["false_positive"] * 3 + ["open"]


def test_marked_findings_stay_marked_and_are_not_duplicated_when_seen_again(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    marked = _many(db, eng, 3)
    assert _bulk(client, db, eng, owner, marked).status_code == 200
    db.add(ScanRun(engagement_id=eng.id, state="running"))  # the next scan
    db.commit()
    for i in range(3):
        _observe(db, eng, f"host{i}.example.test")  # observed again
    rows = _by_id(db, eng)
    assert len(rows) == 3
    assert {f.status for f in rows.values()} == {"false_positive"}


def test_negative_a_finding_that_was_not_named_is_untouched(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    named = _many(db, eng, 2)
    bystander = _observe(db, eng, "bystander.example.test")
    assert _bulk(client, db, eng, owner, named).status_code == 200
    assert _by_id(db, eng)[bystander.id].status == "open"


# ------------------------------------------- REQ-TRIAGE-006: undo as a unit


def test_undo_restores_status_and_note_exactly(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    plain, accepted = _many(db, eng, 2)
    assert _bulk(client, db, eng, owner, [accepted], status="accepted_risk",
                 note="Accepted until the migration").status_code == 200
    bulk = _bulk(client, db, eng, owner, [plain, accepted], status="resolved", note=None).json()
    assert bulk["changed"] == 2

    r = client.post(f"/engagements/{eng.id}/findings/triage/{bulk['bulk_id']}/undo", headers=_auth(db, owner))
    assert r.status_code == 200, r.text
    assert r.json()["restored"] == 2 and r.json()["skipped"] == 0 and r.json()["undo_of"] == bulk["bulk_id"]
    rows = _by_id(db, eng)
    assert rows[plain.id].status == "open" and rows[plain.id].status_note is None
    assert rows[accepted.id].status == "accepted_risk" and rows[accepted.id].status_note == "Accepted until the migration"
    undo_rows = db.scalars(select(AuditLog).where(AuditLog.engagement_id == eng.id,
                                                  AuditLog.action == "finding_triage",
                                                  AuditLog.payload["undo_of"].astext == bulk["bulk_id"])).all()
    assert len(undo_rows) == 2
    assert db.scalars(select(AuditLog).where(AuditLog.action == "finding_triage_bulk_undo")).one()
    assert verify_audit_chain(db, eng.id).ok


def test_negative_a_finding_changed_since_is_not_overwritten_by_undo(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    a, b = _many(db, eng, 2)
    bulk = _bulk(client, db, eng, owner, [a, b]).json()
    # someone decides differently about b afterwards
    r = client.patch(f"/engagements/{eng.id}/findings/{b.id}",
                     json={"status": "accepted_risk", "note": "Decided later, different reason"}, headers=_auth(db, owner))
    assert r.status_code == 200
    out = client.post(f"/engagements/{eng.id}/findings/triage/{bulk['bulk_id']}/undo", headers=_auth(db, owner)).json()
    assert out["restored"] == 1 and out["skipped"] == 1
    rows = _by_id(db, eng)
    assert rows[a.id].status == "open"
    assert rows[b.id].status == "accepted_risk" and rows[b.id].status_note == "Decided later, different reason"


def test_negative_an_undo_can_only_happen_once(client, db):
    owner = _user(db)
    eng = _engagement(db, owner)
    bulk = _bulk(client, db, eng, owner, _many(db, eng, 2)).json()
    url = f"/engagements/{eng.id}/findings/triage/{bulk['bulk_id']}/undo"
    assert client.post(url, headers=_auth(db, owner)).status_code == 200
    assert client.post(url, headers=_auth(db, owner)).status_code == 409


def test_negative_undo_of_an_unknown_or_foreign_bulk_is_404(client, db):
    owner = _user(db)
    eng, other = _engagement(db, owner), _engagement(db, owner)
    foreign_bulk = _bulk(client, db, other, owner, _many(db, other, 2)).json()
    h = _auth(db, owner)
    assert client.post(f"/engagements/{eng.id}/findings/triage/{uuid.uuid4()}/undo", headers=h).status_code == 404
    assert client.post(f"/engagements/{eng.id}/findings/triage/{foreign_bulk['bulk_id']}/undo",
                       headers=h).status_code == 404
    assert {f.status for f in _by_id(db, other).values()} == {"false_positive"}


def test_negative_a_non_owner_cannot_undo(client, db):
    owner, other = _user(db), _user(db)
    eng = _engagement(db, owner)
    bulk = _bulk(client, db, eng, owner, _many(db, eng, 2)).json()
    r = client.post(f"/engagements/{eng.id}/findings/triage/{bulk['bulk_id']}/undo", headers=_auth(db, other))
    assert r.status_code == 403
    assert {f.status for f in _by_id(db, eng).values()} == {"false_positive"}
