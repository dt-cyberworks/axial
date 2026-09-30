"""Integrationstest-Fixtures gegen eine echte PostgreSQL.

Die Gateway-Logik hängt an DB-Zustand (scope_asset, tool_grant, engagement),
und die Modelle nutzen PG-spezifische Typen (JSONB, ARRAY, ENUM, uuidv7).
Deshalb laufen diese Tests gegen eine echte Postgres statt SQLite.

Konfiguration über TEST_DATABASE_URL. Ist keine DB erreichbar, werden die
Tests übersprungen (skip, kein Fehler) - so bleibt `pytest` ohne Infra grün,
während CI (siehe .github/workflows/ci.yml) eine Postgres bereitstellt.
"""

from __future__ import annotations

import datetime as dt
import os
import pathlib
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

MIGRATIONS = sorted((pathlib.Path(__file__).resolve().parents[2] / "migrations").glob("*.sql"))

_DATA_TABLES = [
    "audit_log", "finding_observation", "agent_step", "approval_request", "asset_review_request",
    "finding", "service", "dns_record", "report", "openwire_callback_token", "scan_check", "scan_surface",
    "discovered_asset", "resolved_host", "bounty_program", "tool_approval_policy",
    "tool_grant", "scope_asset", "scan_run", "rate_reservation", "app_setting", "engagement", "customer",
    "account_audit_log", "user_session", "login_challenge", "user_backup_code", "app_user",
    "cve_lookup_cache", "epss_score_cache", "kev_catalog_cache",
]


def _database_url() -> str | None:
    return os.environ.get("TEST_DATABASE_URL")


@pytest.fixture(scope="session")
def engine():
    url = _database_url()
    if not url:
        pytest.skip("TEST_DATABASE_URL not set - integration tests skipped")
    eng = create_engine(url, future=True)
    try:
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"test database not reachable: {exc}")

    # Frisches Schema, dann Migration anwenden (dedizierte Test-DB vorausgesetzt).
    with eng.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    for migration in MIGRATIONS:
        with eng.begin() as conn:
            conn.execute(text(migration.read_text()))
    return eng


@pytest.fixture
def db(engine) -> Session:
    SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()
        # Datentabellen zwischen Tests leeren (Reihenfolge respektiert FKs via CASCADE).
        with engine.begin() as conn:
            conn.execute(text("TRUNCATE " + ", ".join(_DATA_TABLES) + " CASCADE"))


@pytest.fixture
def test_user(db):
    """A real, minimal app_user row (REQ-IAM-*) for tests that need a caller
    identity (engagement ownership, audit actor, admin endpoints). Password
    is never used/checked in these tests - only .id/.email/.role matter."""
    from app.models.user import User
    from app.passwords import hash_secret

    user = User(
        email=f"test-{uuid.uuid4().hex[:12]}@example.com", display_name="Test User",
        role="operator", status="active", must_change_password=False,
        password_hash=hash_secret("irrelevant-not-used"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def admin_user(db):
    from app.models.user import User
    from app.passwords import hash_secret

    user = User(
        email=f"admin-{uuid.uuid4().hex[:12]}@example.com", display_name="Test Admin",
        role="admin", status="active", must_change_password=False,
        password_hash=hash_secret("irrelevant-not-used"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def lab_engagement(db, test_user):
    """Baut das Lab-Setup aus ASM_Lab_Umgebung.docx Kap. 4 direkt via ORM auf:
    allow (aktiv) für metasploitable2/juice-shop, deny für clean-nginx,
    passiver Grant für recon und aktive Grants für recon/fingerprint/vuln
    (ohne Einzelfreigabe)."""
    from app.models.engagement import Engagement, ScopeAsset, ToolGrant

    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        title="Lab", source="lab", status="active",
        authorized_from=now - dt.timedelta(hours=1),
        authorized_until=now + dt.timedelta(days=1),
        owner_user_id=test_user.id,
    )
    db.add(eng)
    db.flush()

    db.add_all([
        ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain",
                   value="metasploitable2", active_allowed=True, authorization_verified=True),
        ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain",
                   value="juice-shop", active_allowed=True, authorization_verified=True),
        ScopeAsset(engagement_id=eng.id, rule="deny", asset_type="domain",
                   value="clean-nginx", active_allowed=False),
    ])
    db.add(ToolGrant(engagement_id=eng.id, tool_category="recon", mode="passive",
                     requires_manual_approval=False))
    for cat in ("recon", "fingerprint", "vuln"):
        db.add(ToolGrant(engagement_id=eng.id, tool_category=cat, mode="active",
                         requires_manual_approval=False))
    db.commit()
    return eng
