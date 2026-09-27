"""REQ-ENG-001: engagement deletion is complete, atomic, and auditable."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from fastapi import HTTPException

from app.api.engagements import create_engagement, delete_engagement
from app.models.approval import ApprovalRequest
from app.models.asset import DiscoveredAsset, Service
from app.models.audit import AuditLog
from app.models.dns_record import DnsRecord
from app.models.engagement import Engagement, ScopeAsset
from app.models.finding import Finding, FindingObservation
from app.models.report import Report
from app.models.resolved_host import ResolvedHost
from app.models.scan_run import AgentStep, ScanRun
from app.models.surface_graph import SurfaceEdge, SurfaceNode
from app.models.user import User
from app.passwords import hash_secret
from app.schemas.engagement import EngagementCreate


ENGAGEMENT_STATUSES = (
    "draft",
    "awaiting_signature",
    "active",
    "paused",
    "completed",
    "revoked",
)
TERMINAL_SCAN_STATES = ("done", "failed", "aborted")
ACTIVE_SCAN_STATES = ("running", "waiting_approval")


def _owner(db) -> User:
    user = User(
        email=f"owner-{dt.datetime.now(dt.timezone.utc).timestamp()}@example.com",
        display_name="Test Owner", role="operator", status="active",
        must_change_password=False, password_hash=hash_secret("irrelevant-not-used"),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _create_engagement(db, *, title: str = "Lifecycle test") -> Engagement:
    now = dt.datetime.now(dt.timezone.utc)
    return create_engagement(
        EngagementCreate(
            title=title,
            source="own_domain",
            authorized_from=now,
            authorized_until=now + dt.timedelta(days=1),
        ),
        user=_owner(db),
        db=db,
    )


@pytest.mark.parametrize("engagement_status", ENGAGEMENT_STATUSES)
def test_created_engagement_starts_draft_and_can_be_deleted_in_each_status(
    db, engagement_status
):
    engagement = _create_engagement(db, title=f"Lifecycle {engagement_status}")
    engagement_id = engagement.id

    assert engagement.status == "draft"
    engagement.status = engagement_status
    db.commit()

    response = delete_engagement(engagement_id, db, user=_owner(db))

    assert response.status_code == 204
    assert db.get(Engagement, engagement_id) is None
    deleted = db.query(AuditLog).filter(
        AuditLog.engagement_id == engagement_id,
        AuditLog.action == "engagement_deleted",
    ).one()
    assert deleted.payload["status"] == engagement_status


@pytest.mark.parametrize("engagement_status", ENGAGEMENT_STATUSES)
@pytest.mark.parametrize("scan_state", TERMINAL_SCAN_STATES)
def test_delete_accepts_terminal_runs_in_each_engagement_status(
    db, engagement_status, scan_state
):
    engagement = _create_engagement(db)
    engagement.status = engagement_status
    run = ScanRun(engagement_id=engagement.id, phase="report", state=scan_state)
    db.add(run)
    db.commit()
    engagement_id = engagement.id
    run_id = run.id

    response = delete_engagement(engagement_id, db, user=_owner(db))

    assert response.status_code == 204
    assert db.get(Engagement, engagement_id) is None
    assert db.get(ScanRun, run_id) is None


@pytest.mark.parametrize("engagement_status", ENGAGEMENT_STATUSES)
@pytest.mark.parametrize("scan_state", ACTIVE_SCAN_STATES)
def test_delete_rejects_active_runs_in_each_engagement_status(
    db, engagement_status, scan_state
):
    engagement = _create_engagement(db)
    engagement.status = engagement_status
    run = ScanRun(engagement_id=engagement.id, phase="fingerprint", state=scan_state)
    db.add(run)
    db.commit()
    engagement_id = engagement.id
    run_id = run.id

    with pytest.raises(HTTPException) as exc:
        delete_engagement(engagement_id, db, user=_owner(db))

    assert exc.value.status_code == 409
    assert db.get(Engagement, engagement_id) is not None
    assert db.get(ScanRun, run_id) is not None
    assert db.query(AuditLog).filter(
        AuditLog.engagement_id == engagement_id,
        AuditLog.action == "engagement_deleted",
    ).count() == 0


def test_delete_removes_complete_dependency_graph_and_retains_audit(db, lab_engagement, test_user):
    run = ScanRun(engagement_id=lab_engagement.id, phase="report", state="done")
    asset = DiscoveredAsset(
        engagement_id=lab_engagement.id, asset_type="domain", value="app.example.test",
        in_scope=True, discovered_via="test",
    )
    db.add_all([run, asset])
    db.flush()
    service = Service(asset_id=asset.id, port=443, protocol="https", product="nginx")
    db.add(service)
    db.flush()
    finding = Finding(
        engagement_id=lab_engagement.id, asset_id=asset.id, service_id=service.id,
        category="misconfig", title="Test finding", confidence="validated",
        fingerprint="delete-regression-fingerprint",
    )
    db.add(finding)
    db.flush()
    scope = db.query(ScopeAsset).filter(ScopeAsset.engagement_id == lab_engagement.id).first()
    node_a = SurfaceNode(
        engagement_id=lab_engagement.id, node_type="asset", ref_table="discovered_asset",
        ref_id=str(asset.id), label=asset.value, scannable=True,
    )
    node_b = SurfaceNode(
        engagement_id=lab_engagement.id, node_type="service", ref_table="service",
        ref_id=str(service.id), label="443/https", scannable=False,
    )
    db.add_all([node_a, node_b])
    db.flush()
    db.add_all([
        SurfaceEdge(
            engagement_id=lab_engagement.id, src_node_id=node_a.id, dst_node_id=node_b.id,
            edge_type="exposes",
        ),
        FindingObservation(
            scan_run_id=run.id, engagement_id=lab_engagement.id, finding_id=finding.id,
            fingerprint=finding.fingerprint,
        ),
        AgentStep(
            engagement_id=lab_engagement.id, scan_run_id=run.id, iteration=1,
            request_messages=[{"role": "user", "content": "test"}],
        ),
        DnsRecord(
            engagement_id=lab_engagement.id, asset_id=asset.id, fqdn=asset.value,
            cname_chain=[asset.value], terminal_ips=["192.0.2.10"], dns_status="resolved",
        ),
        ResolvedHost(
            engagement_id=lab_engagement.id, scope_asset_id=scope.id,
            hostname="metasploitable2", ip_address="192.0.2.10",
        ),
        ApprovalRequest(
            engagement_id=lab_engagement.id, tool_call={"tool": "http_request"},
            state="rejected", expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5),
        ),
        # REQ-REPORT-005 (migration 0025): report.scan_run_id is a non-
        # cascading FK to scan_run - live-discovered 2026-08-13 that deleting
        # an engagement with a generated report 500s (ForeignKeyViolation)
        # since this graph never cleared report rows before scan_run.
        Report(
            id=uuid.uuid4(), engagement_id=lab_engagement.id, scan_run_id=run.id, status="done",
            requested_by="user:test@example.test", filename="report.pdf",
            byte_size=1024, sha256="a" * 64, content=b"%PDF-fake",
        ),
    ])
    engagement_id = lab_engagement.id
    db.commit()

    response = delete_engagement(engagement_id, db, user=test_user)

    assert response.status_code == 204
    assert db.get(Engagement, engagement_id) is None
    for model in (
        FindingObservation, AgentStep, Finding, DnsRecord, Service, DiscoveredAsset,
        ApprovalRequest, ResolvedHost, ScanRun, ScopeAsset, SurfaceEdge, SurfaceNode, Report,
    ):
        assert db.query(model).count() == 0, model.__name__
    retained = db.query(AuditLog).filter(
        AuditLog.engagement_id == engagement_id, AuditLog.action == "engagement_deleted"
    ).one()
    assert retained.reason == "operator_delete"
    assert retained.payload["title"] == "Lab"


def test_delete_active_engagement_is_rejected_without_partial_changes(db, lab_engagement, test_user):
    run = ScanRun(engagement_id=lab_engagement.id, phase="fingerprint", state="running")
    db.add(run); db.commit(); db.refresh(run)

    with pytest.raises(HTTPException) as exc:
        delete_engagement(lab_engagement.id, db, user=test_user)

    assert exc.value.status_code == 409
    assert db.get(Engagement, lab_engagement.id) is not None
    assert db.get(ScanRun, run.id) is not None
    assert db.query(AuditLog).filter(AuditLog.action == "engagement_deleted").count() == 0
