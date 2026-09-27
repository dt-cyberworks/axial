"""engagement_source='benchmark' control point (REQ-BENCH-007).

R3 negative test: 'benchmark' must be unreachable through the operator-facing
engagement-creation endpoint (unlike 'lab', which real automation legitimately
creates through this same endpoint - see lab/seed_lab_engagement.py). The
asymmetry is deliberate: 'benchmark' is designed to unlock an additional,
more-privileged capability (default-credential testing) that 'lab' does not,
so it gets the stricter, fail-closed treatment. The benchmark harness's own
seeding path (benchmark/orchestration/lifecycle.py) is not implemented yet -
tests below create a benchmark-sourced engagement directly via the ORM, the
same legitimate test-setup pattern used elsewhere in this test suite, not a
claim that the seeding script exists.
"""

from __future__ import annotations

import datetime as dt

from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app import auth_service
from app.db.base import get_db
from app.main import app
from app.models.engagement import Engagement
from app.models.user import User
from app.passwords import hash_secret


def _create_body(title: str, source: str) -> dict:
    now = dt.datetime.now(dt.timezone.utc)
    return {
        "title": title, "source": source,
        "authorized_from": (now - dt.timedelta(hours=1)).isoformat(),
        "authorized_until": (now + dt.timedelta(days=1)).isoformat(),
    }


def _user(db, *, email=None) -> User:
    user = User(
        email=email or f"bench-{dt.datetime.now(dt.timezone.utc).timestamp()}@example.com",
        display_name="Benchmark Test User", role="operator", status="active",
        must_change_password=False, password_hash=hash_secret("irrelevant-not-used"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _client(engine) -> TestClient:
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)

    def _override_get_db():
        s = SessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _override_get_db
    return TestClient(app)


def test_operator_endpoint_rejects_source_benchmark(engine, db):
    owner = _user(db)
    client = _client(engine)
    try:
        token, _ = auth_service.create_session(db, owner, ip=None, user_agent=None)
        resp = client.post(
            "/engagements",
            headers={"Authorization": f"Bearer {token}"},
            json=_create_body("Sneaky benchmark engagement", "benchmark"),
        )
        assert resp.status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_operator_endpoint_still_accepts_own_domain_unaffected_by_the_new_value(engine, db):
    """Regression guard: adding 'benchmark' to the enum and the rejection
    branch must not change behavior for a real, non-benchmark engagement."""
    owner = _user(db)
    client = _client(engine)
    try:
        token, _ = auth_service.create_session(db, owner, ip=None, user_agent=None)
        resp = client.post(
            "/engagements",
            headers={"Authorization": f"Bearer {token}"},
            json=_create_body("Real customer engagement", "own_domain"),
        )
        assert resp.status_code == 201
        assert resp.json()["source"] == "own_domain"
    finally:
        app.dependency_overrides.clear()


def test_operator_endpoint_still_accepts_source_lab_unaffected(engine, db):
    """The 'benchmark' guard is deliberately narrower than blocking all
    non-operator sources - 'lab' keeps working through this same endpoint
    exactly as lab/seed_lab_engagement.py already relies on."""
    owner = _user(db)
    client = _client(engine)
    try:
        token, _ = auth_service.create_session(db, owner, ip=None, user_agent=None)
        resp = client.post(
            "/engagements",
            headers={"Authorization": f"Bearer {token}"},
            json=_create_body("Lab engagement", "lab"),
        )
        assert resp.status_code == 201
        assert resp.json()["source"] == "lab"
    finally:
        app.dependency_overrides.clear()


def test_benchmark_source_is_a_valid_enum_value_for_direct_orm_creation(db):
    """The benchmark harness's own (not-yet-implemented) seeding path is
    expected to create engagements this way, analogous to how
    lab/seed_lab_engagement.py and uat/reference_scan.py seed their
    engagements - this proves the schema/enum side of REQ-BENCH-007 is in
    place independent of that harness."""
    owner = _user(db)
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        title="Direct benchmark engagement", source="benchmark", status="active",
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
        owner_user_id=owner.id,
    )
    db.add(eng)
    db.commit()
    db.refresh(eng)
    assert eng.source == "benchmark"
