"""REQ-CONCUR-004: audit_log writes attribute the real authenticated user
identity ("user:<email>"), not the generic literal "operator" - with genuinely
distinct people now holding accounts, "who did what" is a real accountability
question this previously undermined."""

from __future__ import annotations

import pathlib

from sqlalchemy import select

from app.api.engagements import add_scope_asset, cancel_scan_run, delete_scope_asset, update_engagement
from app.models.audit import AuditLog
from app.models.engagement import ScopeAsset
from app.models.scan_run import ScanRun
from app.schemas.engagement import EngagementUpdate, ScopeAssetCreate


def _last_audit(db, engagement_id, action):
    return db.scalars(
        select(AuditLog)
        .where(AuditLog.engagement_id == engagement_id, AuditLog.action == action)
        .order_by(AuditLog.ts.desc())
    ).first()


def test_update_engagement_attributes_the_real_user(db, lab_engagement, test_user):
    update_engagement(lab_engagement.id, EngagementUpdate(title="Renamed"), db, user=test_user)
    row = _last_audit(db, lab_engagement.id, "engagement_updated")
    assert row.actor == f"user:{test_user.email}"


def test_add_scope_asset_attributes_the_real_user(db, lab_engagement, test_user):
    add_scope_asset(
        lab_engagement.id,
        ScopeAssetCreate(rule="deny", asset_type="domain", value="another-deny.example"),
        db, user=test_user,
    )
    row = _last_audit(db, lab_engagement.id, "scope_materialization_invalidated")
    assert row.actor == f"user:{test_user.email}"


def test_delete_scope_asset_attributes_the_real_user(db, lab_engagement, test_user):
    asset = db.query(ScopeAsset).filter(
        ScopeAsset.engagement_id == lab_engagement.id, ScopeAsset.rule == "deny",
    ).first()
    delete_scope_asset(lab_engagement.id, asset.id, db, user=test_user)
    row = _last_audit(db, lab_engagement.id, "scope_asset_deleted")
    assert row.actor == f"user:{test_user.email}"


def test_cancel_scan_run_attributes_the_real_user(db, lab_engagement, test_user):
    run = ScanRun(engagement_id=lab_engagement.id, phase="fingerprint", state="running")
    db.add(run)
    db.commit()
    db.refresh(run)
    cancel_scan_run(lab_engagement.id, run.id, db, user=test_user)
    row = _last_audit(db, lab_engagement.id, "scan_run_cancel_requested")
    assert row.actor == f"user:{test_user.email}"


def test_no_generic_operator_actor_literal_remains_in_engagements_module():
    """Structural guard: catches a regression where a future audit write
    forgets the real actor and falls back to the generic literal, rather than
    relying only on spot-checking individual endpoints."""
    source = pathlib.Path(__file__).resolve().parents[2] / "app" / "api" / "engagements.py"
    assert 'actor="operator"' not in source.read_text()
