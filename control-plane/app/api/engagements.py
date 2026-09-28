import datetime
import fnmatch
import hashlib
import ipaddress
import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app import config_resolver, scan_diff, scan_readiness
from app.config import get_settings
from app.pdf import pdf_escape as _pdf_escape  # noqa: F401  (kept for existing callers/tests)
from app.pdf import simple_pdf as _simple_pdf
from app.pdf import text as _text
from app.pdf import wrap_pdf_lines as _wrap_pdf_lines  # noqa: F401
from app.celery_client import enqueue_scan
from app.db.base import get_db
from app.gateway.audit import append_audit_log
from app.graph.builder import read_graph
from app.tools import registry
from app.models.approval import ApprovalRequest
from app.models.asset import DiscoveredAsset, Service
from app.models.asset_review import AssetReviewRequest
from app.models.dns_record import DnsRecord
from app.models.engagement import BountyProgram, Engagement, ScopeAsset, ToolApprovalPolicy, ToolGrant
from app.models.finding import Finding, FindingObservation
from app.models.report import Report
from app.models.resolved_host import ResolvedHost
from app.models.scan_run import AgentStep, ScanRun
from app.models.surface_graph import SurfaceEdge, SurfaceNode
from app.models.user import User
from app.scan_lifecycle import ScanRunAlreadyActive, reap_stale_runs, start_scan_run
from app.security import require_admin, require_operator, require_user
from app.schemas.asset_review import AssetReviewDecisionIn, AssetReviewOut
from app.schemas.engagement import (
    BountyProgramCreate,
    BountyProgramOut,
    EngagementConfigIn,
    EngagementCreate,
    EngagementOut,
    EngagementOwnerIn,
    EngagementUpdate,
    GatewayOverrideCreate,
    GatewayOverrideOut,
    ScopeAssetCreate,
    ScopeAssetOut,
    ScopeAuthorizationVerificationCreate,
    ToolGrantCreate,
    ToolGrantOut,
)
from app.schemas.internal import ScanRunOut

router = APIRouter(prefix="/engagements", tags=["engagements"])


@router.get("", response_model=list[EngagementOut])
def list_engagements(user: User = Depends(require_user), db: Session = Depends(get_db)):
    # REQ-IAM-007: operators see only their own; admins see everything.
    stmt = select(Engagement).order_by(Engagement.created_at.desc())
    if user.role != "admin":
        stmt = stmt.where(Engagement.owner_user_id == user.id)
    return db.scalars(stmt).all()


@router.post("", response_model=EngagementOut, status_code=201)
def create_engagement(body: EngagementCreate, user: User = Depends(require_user), db: Session = Depends(get_db)):
    """Wizard Schritt 1-2 (Operator-Konsole UI Kap. 2.1): Art + Parteien."""
    # REQ-BENCH-007: source='benchmark' unlocks benchmark-only capabilities
    # (e.g. default-credential testing) and must be reachable ONLY through the
    # benchmark harness's own seeding path, never this operator-facing endpoint.
    if body.source == "benchmark":
        raise HTTPException(403, "source 'benchmark' cannot be set via this endpoint")
    # REQ-IAM-007: owner is always the creating user - never client-supplied.
    eng = Engagement(**body.model_dump(), status="draft", owner_user_id=user.id)
    db.add(eng)
    db.commit()
    db.refresh(eng)
    append_audit_log(
        db, engagement_id=eng.id, actor=f"user:{user.email}", action="engagement_created",
        decision=None, reason=None, payload={
            "title": eng.title, "source": eng.source,
            "tcp_port_range": f"{eng.tcp_port_from}-{eng.tcp_port_to}",
            "udp_discovery_enabled": eng.udp_discovery_enabled,
        },
    )
    return eng


@router.put("/{engagement_id}/owner", response_model=EngagementOut)
def reassign_owner(
    engagement_id: uuid.UUID, body: EngagementOwnerIn,
    user: User = Depends(require_admin), db: Session = Depends(get_db),
):
    """REQ-IAM-007: admin-only reassignment. Ownership itself is already
    enforced router-wide (enforce_engagement_ownership); this additionally
    requires the admin role specifically, since a non-admin owner must never
    be able to reassign their own engagement away or to themselves."""
    eng = _get_engagement_or_404(db, engagement_id)
    new_owner = db.get(User, body.owner_user_id)
    if new_owner is None:
        raise HTTPException(404, "user not found")
    eng.owner_user_id = new_owner.id
    db.commit()
    db.refresh(eng)
    append_audit_log(
        db, engagement_id=eng.id, actor=f"user:{user.email}", action="engagement_owner_reassigned",
        decision=None, reason=None, payload={"new_owner_user_id": str(new_owner.id)},
    )
    return eng


def _get_engagement_or_404(db: Session, engagement_id: uuid.UUID) -> Engagement:
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(404, "engagement not found")
    return eng


def _host_rules_overlap(a: ScopeAsset, b: ScopeAsset) -> bool:
    """REQ-CONCUR-003: conservative same-host overlap check between two
    allow-scope rules belonging to different engagements. This mirrors (but
    does not need to perfectly replicate) the egress-proxy's own host
    matching (`egress-proxy/app/proxy.py::_matches_host`) - it only needs to
    catch the realistic cases (identical/sub domains, identical wildcards,
    overlapping CIDRs/IPs) since the proxy's fail-closed `ambiguous_host`
    resolution remains the actual runtime enforcement boundary, not this
    activation-time check."""
    if a.asset_type in ("ip", "cidr") and b.asset_type in ("ip", "cidr"):
        try:
            return ipaddress.ip_network(a.value, strict=False).overlaps(ipaddress.ip_network(b.value, strict=False))
        except ValueError:
            return False
    if a.asset_type in ("ip", "cidr") or b.asset_type in ("ip", "cidr"):
        return False
    a_val, b_val = a.value.lower().rstrip("."), b.value.lower().rstrip(".")
    if a.asset_type == "domain" and b.asset_type == "domain":
        return a_val == b_val or a_val.endswith("." + b_val) or b_val.endswith("." + a_val)
    if a.asset_type == "wildcard" and b.asset_type == "wildcard":
        return a_val == b_val
    domain_val = a_val if a.asset_type == "domain" else b_val
    wildcard_val = b_val if a.asset_type == "domain" else a_val
    return fnmatch.fnmatch(domain_val, wildcard_val) or fnmatch.fnmatch(wildcard_val, domain_val)


def _check_no_active_scope_overlap(db: Session, eng: Engagement, candidate_assets: list[ScopeAsset]) -> None:
    """REQ-CONCUR-003: refuse to activate (or extend an already-active
    engagement's allow-scope) into overlap with another currently active
    engagement - any owner. Discovered this way, at the source, instead of as
    a confusing `ambiguous_host` scan failure well into a run. Deliberately
    does not name the other engagement or its owner in the error, to avoid
    leaking one user's engagement details to another."""
    own_allow = [a for a in candidate_assets if a.rule == "allow"]
    if not own_allow:
        return
    others = db.scalars(
        select(ScopeAsset)
        .join(Engagement, Engagement.id == ScopeAsset.engagement_id)
        .where(Engagement.status == "active", Engagement.id != eng.id, ScopeAsset.rule == "allow")
    ).all()
    if any(_host_rules_overlap(mine, other) for mine in own_allow for other in others):
        raise HTTPException(
            409,
            "allow-scope overlaps another currently active engagement's allow-scope; "
            "resolve the conflict before activating",
        )


def _authorization_config_payload(eng: Engagement, assets: list[ScopeAsset], grants: list[ToolGrant], policies: list[ToolApprovalPolicy]) -> dict:
    return {
        "engagement_id": str(eng.id),
        "title": eng.title,
        "authorized_from": eng.authorized_from.isoformat() if eng.authorized_from else None,
        "authorized_until": eng.authorized_until.isoformat() if eng.authorized_until else None,
        "emergency_contact": eng.emergency_contact,
        "ai_testing_allowed": bool(eng.ai_testing_allowed),
        "scope_assets": [
            {
                "rule": a.rule,
                "asset_type": a.asset_type,
                "value": a.value,
                "active_allowed": bool(a.active_allowed),
                "authorization_attested": bool(a.authorization_verified),
                "authorization_method": a.authorization_method,
            }
            for a in assets
        ],
        "tool_grants": [
            {"category": g.tool_category, "mode": g.mode, "requires_manual_approval": bool(g.requires_manual_approval)}
            for g in grants
        ],
        "manual_approval_tools": [p.tool_name for p in policies if p.requires_manual_approval],
    }


def _authorization_pdf(eng: Engagement, assets: list[ScopeAsset], grants: list[ToolGrant], policies: list[ToolApprovalPolicy]) -> bytes:
    payload = _authorization_config_payload(eng, assets, grants, policies)
    checksum = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    allow_assets = [a for a in assets if a.rule == "allow"]
    deny_assets = [a for a in assets if a.rule == "deny"]
    manual_tools = sorted(p.tool_name for p in policies if p.requires_manual_approval)

    lines = [
        "Purpose: This document summarizes the authorized external attack surface management engagement configuration for customer review and signature.",
        f"Configuration checksum: {checksum}",
        "",
        "Engagement",
        f"- Title: {eng.title}",
        f"- Engagement ID: {eng.id}",
        f"- Test window: {eng.authorized_from} to {eng.authorized_until}",
        f"- Emergency contact: {_text(eng.emergency_contact)}",
        f"- Vector Agent autonomous proposals: {'enabled' if eng.ai_testing_allowed else 'disabled'}",
        "",
        "Authorized scope",
    ]
    if allow_assets:
        for asset in allow_assets:
            lines.append(
                f"- ALLOW {asset.asset_type}: {asset.value} | "
                f"{'active checks allowed' if asset.active_allowed else 'passive only'} | "
                f"authorization {'attested' if asset.authorization_verified else 'not attested'}"
                f"{f' ({asset.authorization_method})' if asset.authorization_method else ''}"
            )
    else:
        lines.append("- No allow-scope assets configured.")

    lines.append("")
    lines.append("Explicitly denied scope")
    if deny_assets:
        for asset in deny_assets:
            lines.append(f"- DENY {asset.asset_type}: {asset.value}")
    else:
        lines.append("- No explicit deny entries configured.")

    lines.extend(["", "Tool permissions"])
    if grants:
        for grant in sorted(grants, key=lambda g: (g.tool_category, g.mode)):
            lines.append(
                f"- {grant.tool_category} / {grant.mode}: granted; "
                f"category manual approval default {'on' if grant.requires_manual_approval else 'off'}"
            )
    else:
        lines.append("- No tool grants configured.")

    lines.extend(["", "Tools requiring manual approval"])
    if manual_tools:
        for tool in manual_tools:
            lines.append(f"- {tool}")
    else:
        lines.append("- No concrete tools require manual approval.")

    lines.extend([
        "",
        "Guardrails",
        "- Every active tool call is authorized by the Scope Gateway before execution.",
        "- Active checks are limited to allow-scope assets and the configured test window.",
        "- Domain scope includes discovered subdomains unless explicitly denied.",
        "- Default posture is non-destructive, bug-bounty-style validation with bounded tool budgets.",
        "- Manual approval tools stop at the gateway until an operator approves the exact call.",
        "",
        "Customer authorization",
        "By signing, the customer confirms that the scope, test window, emergency contact, and tool guardrails above are authorized for the engagement.",
        "",
        "Customer representative: ________________________________",
        "Date: ____________________",
        "",
        "Provider / operator representative: ______________________",
        "Date: ____________________",
    ])
    return _simple_pdf("ASM Engagement Authorization Summary", lines)


@router.get("/{engagement_id}", response_model=EngagementOut)
def get_engagement(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    return _get_engagement_or_404(db, engagement_id)


@router.get("/{engagement_id}/surface-graph")
def get_surface_graph(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    """Read-only attack-surface graph for the operator console (REQ-GRAPH-004/005).

    Ownership/auth is enforced once at the router level (enforce_engagement_ownership),
    so a caller who does not own this engagement gets the same 404 as elsewhere -
    no cross-engagement disclosure."""
    _get_engagement_or_404(db, engagement_id)
    return read_graph(engagement_id, db)


@router.patch("/{engagement_id}", response_model=EngagementOut)
def update_engagement(
    engagement_id: uuid.UUID, body: EngagementUpdate,
    db: Session = Depends(get_db), user: User = Depends(require_user),
):
    eng = _get_engagement_or_404(db, engagement_id)
    changes = body.model_dump(exclude_unset=True)
    if not changes:
        return eng

    new_from = changes.get("authorized_from", eng.authorized_from)
    new_until = changes.get("authorized_until", eng.authorized_until)
    if new_from and new_until and new_from >= new_until:
        raise HTTPException(409, "authorized_from must be before authorized_until")
    if "source" in changes and changes["source"] != eng.source and eng.status != "draft":
        raise HTTPException(409, "source can only be changed while engagement is draft")
    envelope_fields = {"tcp_port_from", "tcp_port_to", "udp_discovery_enabled"}
    if envelope_fields.intersection(changes) and eng.status != "draft":
        raise HTTPException(409, "scan envelope can only be changed while engagement is draft")
    tcp_port_from = changes.get("tcp_port_from", eng.tcp_port_from)
    tcp_port_to = changes.get("tcp_port_to", eng.tcp_port_to)
    if tcp_port_from > tcp_port_to:
        raise HTTPException(422, "tcp_port_from must be less than or equal to tcp_port_to")

    for key, value in changes.items():
        setattr(eng, key, value)
    append_audit_log(
        db, engagement_id=eng.id, actor=f"user:{user.email}", action="engagement_updated",
        decision="ALLOW", reason="metadata_updated", payload={"fields": sorted(changes.keys())},
    )
    db.commit()
    db.refresh(eng)
    return eng


@router.get("/{engagement_id}/config")
def get_engagement_config(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    """Effektive Kampagnen-Config (Schichten 1-5 aufgeloest): je Tool
    enabled/requires_approval mit Herkunft, plus die effektive Agent-Anweisung
    und ob sie kampagnenspezifisch ueberschrieben ist."""
    eng = _get_engagement_or_404(db, engagement_id)
    tools = [
        {"tool": c.tool, "enabled": c.enabled, "requires_approval": c.requires_approval,
         "enabled_source": c.enabled_source, "approval_source": c.approval_source,
         "category": (registry.get(c.tool).category if registry.get(c.tool) else None),
         "installed": (registry.get(c.tool).installed if registry.get(c.tool) else False)}
        for c in config_resolver.effective_tool_policy(db, engagement_id)
    ]
    return {
        "tools": tools,
        "agent_prompt": config_resolver.effective_agent_prompt(db, engagement_id),
        "agent_prompt_overridden": bool((eng.agent_prompt_override or "").strip()),
        "agent_max_iterations": config_resolver.effective_agent_max_iterations(db, engagement_id),
        "agent_max_iterations_overridden": eng.agent_max_iterations_override is not None,
        "agent_max_tokens": config_resolver.effective_agent_max_tokens(db, engagement_id),
        "agent_max_tokens_overridden": eng.agent_max_tokens_override is not None,
        "approval_timeout_seconds": config_resolver.effective_approval_timeout_seconds(db, engagement_id),
        "approval_timeout_seconds_overridden": eng.approval_timeout_seconds_override is not None,
    }


@router.put("/{engagement_id}/config")
def put_engagement_config(
    engagement_id: uuid.UUID, body: EngagementConfigIn,
    db: Session = Depends(get_db), user: User = Depends(require_user),
):
    """Kampagnen-Overrides setzen (Schicht 4/5). Pro Tool: enabled=None erbt die
    globale Policy, true/false ueberschreibt; requires_approval verschaerft nur.
    agent_prompt_override=None/"" -> Kampagne erbt wieder den globalen Prompt."""
    eng = _get_engagement_or_404(db, engagement_id)

    for entry in body.tools:
        spec = registry.get(entry.tool)
        if spec is None:
            continue  # unbekanntes Tool ignorieren (Registry ist der Boden)
        pol = db.get(ToolApprovalPolicy, {"engagement_id": engagement_id, "tool_name": entry.tool})
        # Kein Override noetig -> vorhandene Zeile ggf. entfernen (erbt global).
        if entry.enabled is None and not entry.requires_approval:
            if pol is not None:
                db.delete(pol)
            continue
        if pol is None:
            pol = ToolApprovalPolicy(engagement_id=engagement_id, tool_name=entry.tool,
                                     requires_manual_approval=entry.requires_approval, enabled=entry.enabled)
            db.add(pol)
        else:
            pol.requires_manual_approval = entry.requires_approval
            pol.enabled = entry.enabled

    if body.agent_prompt_override is not None:
        eng.agent_prompt_override = body.agent_prompt_override.strip() or None

    iterations_changed = "agent_max_iterations_override" in body.model_fields_set
    if iterations_changed:
        eng.agent_max_iterations_override = body.agent_max_iterations_override

    max_tokens_changed = "agent_max_tokens_override" in body.model_fields_set
    if max_tokens_changed:
        eng.agent_max_tokens_override = body.agent_max_tokens_override

    timeout_changed = "approval_timeout_seconds_override" in body.model_fields_set
    if timeout_changed:
        eng.approval_timeout_seconds_override = body.approval_timeout_seconds_override

    append_audit_log(
        db, engagement_id=eng.id, actor=f"user:{user.email}", action="engagement_config_updated",
        decision="ALLOW", reason="campaign_config_updated",
        payload={"tools": [t.tool for t in body.tools], "prompt_changed": body.agent_prompt_override is not None,
                 "max_iterations_changed": iterations_changed, "max_tokens_changed": max_tokens_changed,
                 "approval_timeout_changed": timeout_changed},
    )
    db.commit()
    return get_engagement_config(engagement_id, db)


def _delete_engagement_dependents(db: Session, engagement_id: uuid.UUID) -> None:
    asset_ids = select(DiscoveredAsset.id).where(DiscoveredAsset.engagement_id == engagement_id).scalar_subquery()

    # Run observations and agent steps reference findings/runs directly. Delete
    # the complete graph leaf-first so PostgreSQL never needs an unsafe CASCADE.
    db.execute(delete(FindingObservation).where(FindingObservation.engagement_id == engagement_id))
    # REQ-GRAPH-001..006 (migration 0021) added after this function was first
    # written - edge before node even though node->edge already cascades in
    # the schema (ondelete="CASCADE"), matching this function's own explicit,
    # leaf-first style rather than relying on an implicit DB cascade here too.
    db.execute(delete(SurfaceEdge).where(SurfaceEdge.engagement_id == engagement_id))
    db.execute(delete(SurfaceNode).where(SurfaceNode.engagement_id == engagement_id))
    db.execute(delete(AgentStep).where(AgentStep.engagement_id == engagement_id))
    db.execute(delete(AssetReviewRequest).where(AssetReviewRequest.engagement_id == engagement_id))
    db.execute(delete(Finding).where(Finding.engagement_id == engagement_id))
    db.execute(delete(DnsRecord).where(DnsRecord.engagement_id == engagement_id))
    db.execute(delete(Service).where(Service.asset_id.in_(asset_ids)))
    db.execute(delete(DiscoveredAsset).where(DiscoveredAsset.engagement_id == engagement_id))
    db.execute(delete(ApprovalRequest).where(ApprovalRequest.engagement_id == engagement_id))
    db.execute(delete(ResolvedHost).where(ResolvedHost.engagement_id == engagement_id))
    # REQ-REPORT-005 (migration 0025) added `report.scan_run_id` as a non-
    # cascading FK to scan_run AFTER this function was first written - live-
    # discovered 2026-08-13 deleting an engagement with any generated report
    # 500s (ForeignKeyViolation) since scan_run rows it references were never
    # cleared first. Delete leaf-first like everything else here.
    db.execute(delete(Report).where(Report.engagement_id == engagement_id))
    db.execute(delete(ScanRun).where(ScanRun.engagement_id == engagement_id))
    db.execute(delete(BountyProgram).where(BountyProgram.engagement_id == engagement_id))
    db.execute(delete(ToolApprovalPolicy).where(ToolApprovalPolicy.engagement_id == engagement_id))
    db.execute(delete(ToolGrant).where(ToolGrant.engagement_id == engagement_id))
    db.execute(delete(ScopeAsset).where(ScopeAsset.engagement_id == engagement_id))


@router.delete("/{engagement_id}", status_code=204)
def delete_engagement(
    engagement_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(require_user),
):
    eng = _get_engagement_or_404(db, engagement_id)
    running = db.scalar(
        select(ScanRun).where(
            ScanRun.engagement_id == engagement_id,
            ScanRun.state.in_(["running", "waiting_approval"]),
        ).limit(1)
    )
    if running is not None:
        raise HTTPException(409, "engagement has a running or waiting scan_run")

    audit_payload = {"title": eng.title, "status": eng.status}
    _delete_engagement_dependents(db, engagement_id)
    db.delete(eng)
    # Detect a missed dependent before the audit helper commits. The deletion
    # and its retained append-only audit entry are one database transaction.
    db.flush()
    append_audit_log(
        db, engagement_id=engagement_id, actor=f"user:{user.email}", action="engagement_deleted",
        decision="ALLOW", reason="operator_delete", payload=audit_payload,
    )
    return Response(status_code=204)


@router.get("/{engagement_id}/authorization-pdf")
def download_authorization_pdf(
    engagement_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(require_user),
):
    """Customer-facing authorization summary for signature before activation."""
    eng = _get_engagement_or_404(db, engagement_id)
    assets = db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == engagement_id).order_by(ScopeAsset.rule, ScopeAsset.asset_type, ScopeAsset.value)).all()
    grants = db.scalars(select(ToolGrant).where(ToolGrant.engagement_id == engagement_id).order_by(ToolGrant.tool_category, ToolGrant.mode)).all()
    policies = db.scalars(select(ToolApprovalPolicy).where(ToolApprovalPolicy.engagement_id == engagement_id).order_by(ToolApprovalPolicy.tool_name)).all()
    pdf = _authorization_pdf(eng, assets, grants, policies)
    append_audit_log(
        db,
        engagement_id=engagement_id,
        actor=f"user:{user.email}",
        action="authorization_pdf_generated",
        decision=None,
        reason="customer_signature_document",
        payload={"bytes": len(pdf)},
    )
    safe_id = str(engagement_id)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="asm-authorization-{safe_id}.pdf"'},
    )


@router.post("/{engagement_id}/scope-assets", response_model=ScopeAssetOut, status_code=201)
def add_scope_asset(
    engagement_id: uuid.UUID, body: ScopeAssetCreate,
    db: Session = Depends(get_db), user: User = Depends(require_user),
):
    """Wizard Schritt 3 (UI Kap. 2.1): allow-/deny-Listen, Ownership."""
    eng = _get_engagement_or_404(db, engagement_id)
    if body.port_from is not None and (body.port_from < eng.tcp_port_from or body.port_to > eng.tcp_port_to):
        raise HTTPException(
            422,
            f"port range {body.port_from}-{body.port_to} is not within the engagement's "
            f"authorized ceiling ({eng.tcp_port_from}-{eng.tcp_port_to})",
        )
    # GitHub issue #35: no maximum host-discovery range existed anywhere -
    # here (not the schema) because it needs the configured limit from
    # Settings, mirroring the port-ceiling check just above.
    if body.asset_type == "cidr":
        max_addresses = get_settings().max_host_discovery_addresses
        num_addresses = ipaddress.ip_network(body.value, strict=False).num_addresses
        if num_addresses > max_addresses:
            raise HTTPException(
                422,
                f"CIDR {body.value} is too large ({num_addresses} addresses) - the configured "
                f"maximum is {max_addresses}; split into smaller ranges",
            )
    asset = ScopeAsset(engagement_id=engagement_id, **body.model_dump())
    if eng.status == "active" and asset.rule == "allow" and asset.active_allowed:
        # REQ-CONCUR-003: adding active-mode allow scope to an already-active
        # engagement gets the same overlap check as activation itself.
        _check_no_active_scope_overlap(db, eng, [asset])
    db.add(asset)
    # Scope changes invalidate any previous name->IP materialization. It will be
    # rebuilt from the current allow/deny rules before the next raw/proxy egress.
    db.execute(delete(ResolvedHost).where(ResolvedHost.engagement_id == engagement_id))
    db.commit()
    db.refresh(asset)
    append_audit_log(
        db, engagement_id=engagement_id, actor=f"user:{user.email}", action="scope_materialization_invalidated",
        decision=None, reason="scope_asset_changed", payload={"scope_asset_id": str(asset.id)},
    )
    return asset


@router.get("/{engagement_id}/scope-assets", response_model=list[ScopeAssetOut])
def list_scope_assets(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    return db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == engagement_id)).all()


@router.delete("/{engagement_id}/scope-assets/{asset_id}", status_code=204)
def delete_scope_asset(
    engagement_id: uuid.UUID, asset_id: uuid.UUID,
    db: Session = Depends(get_db), user: User = Depends(require_user),
):
    """REQ-ASSETREVIEW-005: Scope-Regeln (inkl. per Asset-Review automatisch
    angelegter deny-Regeln) bleiben nach der Erstellung sichtbar und entfernbar,
    nicht nur waehrend des Wizards."""
    _get_engagement_or_404(db, engagement_id)
    asset = db.get(ScopeAsset, asset_id)
    if asset is None or asset.engagement_id != engagement_id:
        raise HTTPException(404, "scope asset not found")
    db.delete(asset)
    db.execute(delete(ResolvedHost).where(ResolvedHost.engagement_id == engagement_id))
    db.commit()
    append_audit_log(
        db, engagement_id=engagement_id, actor=f"user:{user.email}", action="scope_asset_deleted",
        decision=None, reason="operator_removed_scope_rule",
        payload={"scope_asset_id": str(asset_id), "rule": asset.rule, "value": asset.value},
    )
    return Response(status_code=204)


@router.post("/{engagement_id}/scope-assets/{asset_id}/verify-authorization", response_model=ScopeAssetOut)
def verify_scope_asset_authorization(
    engagement_id: uuid.UUID,
    asset_id: uuid.UUID,
    body: ScopeAuthorizationVerificationCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    """Explicit operator attestation for active allow-scope assets.

    This does not broaden scope or execute a scan. It records that the operator
    has verified authority for an existing allow asset, which is required before
    own-domain/customer engagements may run active checks against that asset.
    """
    _get_engagement_or_404(db, engagement_id)
    asset = db.get(ScopeAsset, asset_id)
    if asset is None or asset.engagement_id != engagement_id:
        raise HTTPException(404, "scope asset not found")
    if asset.rule != "allow":
        raise HTTPException(409, "only allow-scope assets can be authorization attested")

    asset.authorization_verified = True
    asset.authorization_method = body.method
    db.execute(delete(ResolvedHost).where(ResolvedHost.engagement_id == engagement_id))
    append_audit_log(
        db,
        engagement_id=engagement_id,
        actor=body.verified_by or f"user:{user.email}",
        action="scope_authorization_attested",
        decision="ALLOW",
        reason=body.method,
        payload={"scope_asset_id": str(asset.id), "asset": asset.value, "asset_type": asset.asset_type},
    )
    db.commit()
    db.refresh(asset)
    return asset


def _tools_for_category(category: str) -> set[str]:
    return {name for name, spec in registry.REGISTRY.items() if spec.category == category and spec.default_enabled}


# GitHub issue #16: the wizard writes tool grants but never reads them back -
# fine for a one-time creation flow with no prior state, but a page that
# resumes an existing (possibly already partially-granted) draft needs to
# show what is actually granted today rather than defaulting every checkbox
# to unchecked and risking a confusing re-submit.
@router.get("/{engagement_id}/tool-grants", response_model=list[ToolGrantOut])
def list_tool_grants(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    _get_engagement_or_404(db, engagement_id)
    grants = db.scalars(
        select(ToolGrant).where(ToolGrant.engagement_id == engagement_id)
        .order_by(ToolGrant.tool_category, ToolGrant.mode)
    ).all()
    manual_by_category: dict[str, list[str]] = {}
    if any(g.mode == "active" for g in grants):
        policies = db.scalars(
            select(ToolApprovalPolicy).where(
                ToolApprovalPolicy.engagement_id == engagement_id,
                ToolApprovalPolicy.requires_manual_approval.is_(True),
            )
        ).all()
        manual_tool_names = {p.tool_name for p in policies}
        for name, spec in registry.REGISTRY.items():
            if name in manual_tool_names:
                manual_by_category.setdefault(spec.category, []).append(name)
        for tools in manual_by_category.values():
            tools.sort()
    return [
        ToolGrantOut(
            engagement_id=engagement_id,
            tool_category=g.tool_category,
            mode=g.mode,
            requires_manual_approval=g.requires_manual_approval,
            manual_tools=manual_by_category.get(g.tool_category, []) if g.mode == "active" else [],
        )
        for g in grants
    ]


@router.post("/{engagement_id}/tool-grants", response_model=ToolGrantOut, status_code=201)
def add_tool_grant(engagement_id: uuid.UUID, body: ToolGrantCreate, db: Session = Depends(get_db)):
    """Wizard Schritt 4 (UI Kap. 2.1): category grant + concrete manual tools."""
    _get_engagement_or_404(db, engagement_id)
    manual_tools = sorted(set(body.manual_tools or []))
    category_tools = _tools_for_category(body.tool_category)
    invalid_tools = [tool for tool in manual_tools if tool not in category_tools]
    if invalid_tools:
        raise HTTPException(400, f"manual tools do not belong to category {body.tool_category}: {', '.join(invalid_tools)}")

    grant = ToolGrant(
        engagement_id=engagement_id,
        tool_category=body.tool_category,
        mode=body.mode,
        requires_manual_approval=body.requires_manual_approval,
    )
    db.merge(grant)

    if body.mode == "active":
        if category_tools:
            db.execute(
                delete(ToolApprovalPolicy).where(
                    ToolApprovalPolicy.engagement_id == engagement_id,
                    ToolApprovalPolicy.tool_name.in_(category_tools),
                )
            )
        for tool_name in manual_tools:
            db.merge(ToolApprovalPolicy(
                engagement_id=engagement_id,
                tool_name=tool_name,
                requires_manual_approval=True,
            ))

    db.commit()
    saved = db.get(ToolGrant, {"engagement_id": engagement_id, "tool_category": body.tool_category, "mode": body.mode})
    return ToolGrantOut(
        engagement_id=engagement_id,
        tool_category=saved.tool_category,
        mode=saved.mode,
        requires_manual_approval=saved.requires_manual_approval,
        manual_tools=manual_tools if body.mode == "active" else [],
    )




def _asset_type_for_override_target(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain"


def _ensure_active_scope_override(db: Session, engagement_id: uuid.UUID, target: str) -> str:
    asset = ScopeAsset(
        engagement_id=engagement_id,
        rule="allow",
        asset_type=_asset_type_for_override_target(target),
        value=target,
        active_allowed=True,
        authorization_verified=True,
        authorization_method="manual_gateway_override",
    )
    db.add(asset)
    db.execute(delete(ResolvedHost).where(ResolvedHost.engagement_id == engagement_id))
    return f"added exact active allow-scope for {target}"


def _ensure_active_tool_grant_override(db: Session, engagement_id: uuid.UUID, category: str) -> str:
    grant = ToolGrant(
        engagement_id=engagement_id,
        tool_category=category,
        mode="active",
        requires_manual_approval=False,
    )
    db.merge(grant)
    return f"enabled active {category} tool grant without per-call approval"


@router.post("/{engagement_id}/gateway-overrides", response_model=GatewayOverrideOut, status_code=201)
def apply_gateway_override(
    engagement_id: uuid.UUID, body: GatewayOverrideCreate,
    db: Session = Depends(get_db), user: User = Depends(require_user),
):
    """Apply a manual operator override as a policy change, not a bypass.

    The denied call is not executed here. Instead, the smallest relevant
    engagement policy is changed and audited. Any retry still goes through the
    Scope Gateway, preserving the single enforcement point and the audit trail.
    """
    eng = _get_engagement_or_404(db, engagement_id)
    call = body.tool_call or {}
    reason = body.reason
    target = str(call.get("target") or "").strip()
    category = str(call.get("category") or "").strip()
    mode = str(call.get("mode") or "active")
    applied: list[str] = []

    if reason in {"target_out_of_scope", "active_not_allowed"}:
        if not target:
            raise HTTPException(400, "override requires tool_call.target")
        applied.append(_ensure_active_scope_override(db, engagement_id, target))
        if mode == "active" and category:
            applied.append(_ensure_active_tool_grant_override(db, engagement_id, category))
    elif reason == "no_tool_grant":
        if not category:
            raise HTTPException(400, "override requires tool_call.category")
        applied.append(_ensure_active_tool_grant_override(db, engagement_id, category))
    elif reason == "ai_testing_not_enabled":
        eng.ai_testing_allowed = True
        applied.append("enabled Vector Agent proposals for this engagement")
    else:
        raise HTTPException(409, f"gateway decision '{reason}' is not manually overridable here")

    append_audit_log(
        db,
        engagement_id=engagement_id,
        actor=body.approved_by or f"user:{user.email}",
        action="gateway_override",
        decision="ALLOW",
        reason=f"manual_override:{reason}",
        payload={"tool_call": call, "applied": applied, "comment": body.comment},
    )
    db.commit()
    return GatewayOverrideOut(applied=applied, message="override applied; retry will still pass through gateway")

@router.post("/{engagement_id}/bounty-program", status_code=201, response_model=BountyProgramOut)
def add_bounty_program(engagement_id: uuid.UUID, body: BountyProgramCreate, db: Session = Depends(get_db)):
    """Wizard-Schritt (bedingt, source=bug_bounty): Programm-Policy (Kap. 2.3),
    per GitHub issue #12 nun ueber das Scope/Tools-Wizard-Toggle erreichbar
    statt nur per direktem API-Aufruf. Upsert (nicht nur Create): ein Bediener
    kann eine Tippfehler-Korrektur ohne Loeschen/Neuanlage des gesamten
    Engagements einreichen - matcht das bestehende "delete + re-add"-Muster
    fuer Scope-Assets, hier als replace-in-place statt zweier Client-Calls."""
    eng = _get_engagement_or_404(db, engagement_id)
    if eng.source != "bug_bounty":
        raise HTTPException(400, "A bug-bounty program can only be attached to an engagement of type bug bounty.")
    db.execute(delete(BountyProgram).where(BountyProgram.engagement_id == engagement_id))
    prog = BountyProgram(engagement_id=engagement_id, **body.model_dump())
    db.add(prog)
    db.commit()
    db.refresh(prog)
    return prog


@router.get("/{engagement_id}/bounty-program", response_model=BountyProgramOut | None)
def get_bounty_program(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    """Prefill for the wizard-review step / engagement-edit page. `null` when
    this engagement isn't running under a bug-bounty program, or has opted in
    but hasn't submitted its program policy yet."""
    _get_engagement_or_404(db, engagement_id)
    return db.scalar(select(BountyProgram).where(BountyProgram.engagement_id == engagement_id))


@router.post("/{engagement_id}/activate", response_model=EngagementOut)
def activate_engagement(
    engagement_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(require_user),
):
    """Wizard Schritt 6 / Freigabe-Checkliste (Rules of Engagement Kap. 7).

    Fail-closed: das engagement wechselt nur dann auf 'active', wenn alle
    zutreffenden Voraussetzungen erfuellt sind. Sonst bleibt es passiv-only.
    """
    eng = _get_engagement_or_404(db, engagement_id)

    if eng.source == "customer" and not (eng.scope_signed_by and eng.scope_doc_sha256):
        raise HTTPException(409, "Cannot activate: a customer engagement needs the signed scope document - record who signed it and the document's SHA-256.")

    if eng.source == "bug_bounty":
        prog = db.scalar(select(BountyProgram).where(BountyProgram.engagement_id == eng.id))
        if prog is None:
            raise HTTPException(409, "Cannot activate: a bug-bounty engagement needs its program details (platform and program reference).")

    allow_assets = db.scalars(
        select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id, ScopeAsset.rule == "allow")
    ).all()
    if eng.source in ("own_domain", "customer"):
        if not allow_assets:
            raise HTTPException(409, "Cannot activate: add at least one in-scope target (domain, host, or IP range) first.")
        active_assets = [a for a in allow_assets if a.active_allowed]
        if active_assets and not all(a.authorization_verified for a in active_assets):
            raise HTTPException(409, "Cannot activate: confirm your authorization for every target that allows active testing.")

    # REQ-CONCUR-003: catch scope overlap with another already-active
    # engagement (any owner) at activation time, before it can surface as a
    # confusing ambiguous_host scan failure later.
    _check_no_active_scope_overlap(db, eng, allow_assets)

    now = datetime.datetime.now(datetime.timezone.utc)
    if not (eng.authorized_from and eng.authorized_until and eng.authorized_from < eng.authorized_until):
        raise HTTPException(409, "Cannot activate: the test window is missing or ends before it starts.")

    eng.status = "active"
    db.commit()
    db.refresh(eng)
    append_audit_log(
        db, engagement_id=eng.id, actor=f"user:{user.email}", action="engagement_activated",
        decision="ALLOW", reason="activation_checklist_passed", payload={"at": now.isoformat()},
    )
    return eng


@router.get("/{engagement_id}/scan-readiness")
def get_scan_readiness(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    """Preflight: kann fuer diese Engagement ueberhaupt ein Scan laufen? Spiegelt
    die engagement-weiten Blocking-Bedingungen des Gateways (REQ-RUN-002)."""
    _get_engagement_or_404(db, engagement_id)
    r = scan_readiness.evaluate(db, engagement_id)
    return {"ready": r.ready, "blockers": [{"code": b.code, "message": b.message} for b in r.blockers]}


@router.post("/{engagement_id}/scan", status_code=202)
def start_scan(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    """Enqueued die scan_run-Phasen-Pipeline (Architektur Kap. 4.1) beim worker.
    Prozess-Topologie Abb. 1: Orchestrator -> enqueue -> Celery Worker.

    Preflight (REQ-RUN-002): startet NUR, wenn die engagement-weiten Blocking-
    Bedingungen erfuellt sind - sonst 409 mit Blocker-Liste, statt einen Lauf zu
    starten, der dann jeden Request blockt."""
    _get_engagement_or_404(db, engagement_id)
    # Verwaiste Laeufe zuerst ernten (REQ-RAWLEASE-001), damit ein abgestuerzter/
    # haengender Lauf den Start eines neuen nicht dauerhaft blockiert.
    reap_stale_runs(db, engagement_id)
    r = scan_readiness.evaluate(db, engagement_id)
    if not r.ready:
        raise HTTPException(409, {"error": "engagement_not_scan_ready",
                                  "blockers": [{"code": b.code, "message": b.message} for b in r.blockers]})
    # REQ-AGENT-008: effektives Iterationsbudget (Kampagne -> global ->
    # eingebauter Default) statt eines hartcodierten Werts.
    max_iterations = config_resolver.effective_agent_max_iterations(db, engagement_id)
    # REQ-APPROVAL-005: der Worker-Poll-Deckel muss zur control-plane-seitig
    # durchgesetzten expires_at passen, sonst kann der Worker lokal frueher
    # aufgeben als die Freigabe tatsaechlich glaeufig ist (Desync-Risiko).
    approval_timeout_seconds = config_resolver.effective_approval_timeout_seconds(db, engagement_id)
    # GitHub issue #18: the scan_run row is created HERE, transactionally and
    # race-safe (app.scan_lifecycle.start_scan_run - a partial unique index is
    # the actual invariant), and its ID is handed to the worker rather than
    # having the worker create its own row via a second, independently-racing
    # check-then-insert (create_scan_run below still exists as a legacy/
    # direct-testing entry point, now made equally race-safe).
    try:
        run = start_scan_run(db, engagement_id, budget_tool_calls_max=200)
    except ScanRunAlreadyActive:
        raise HTTPException(409, "engagement already has an active scan_run") from None
    task_id = enqueue_scan(
        str(engagement_id), scan_run_id=str(run.id), budget_max_iterations=max_iterations,
        approval_timeout_seconds=approval_timeout_seconds,
    )
    return {"task_id": task_id}


@router.post("/{engagement_id}/scan-runs/{run_id}/cancel")
def cancel_scan_run(
    engagement_id: uuid.UUID, run_id: uuid.UUID,
    db: Session = Depends(get_db), user: User = Depends(require_user),
):
    """Terminaler, kooperativ durchgesetzter Stopp (REQ-RUN-001).

    Der API-Zustand wird sofort terminal. Worker und Tool-Runner beobachten das
    Flag, beenden laufende Prozesse und duerfen den terminalen Zustand danach
    nicht mehr ueberschreiben.
    """
    run = db.scalar(select(ScanRun).where(ScanRun.id == run_id).with_for_update())
    if run is None or run.engagement_id != engagement_id:
        raise HTTPException(404, "scan_run not found for this engagement")
    if run.state not in {"running", "waiting_approval"}:
        raise HTTPException(409, f"scan_run is '{run.state}', not active - cannot cancel")
    now = datetime.datetime.now(datetime.timezone.utc)
    run.cancel_requested = True
    run.state = "aborted"
    run.state_reason = "cancelled_by_operator"
    run.finished_at = now
    for approval in db.scalars(
        select(ApprovalRequest).where(
            ApprovalRequest.engagement_id == engagement_id,
            ApprovalRequest.state.in_(["requested", "approved", "executing"]),
        )
    ):
        # Approval ownership is stored in the exact immutable tool-call JSON.
        # Never close an unrelated run/operator approval in the same engagement.
        if str((approval.tool_call or {}).get("scan_run_id") or "") != str(run_id):
            continue
        approval.state = "cancelled"
        approval.execution_finished_at = now
        approval.execution_error = "scan_cancelled_by_operator"
    pending_review = db.scalar(
        select(AssetReviewRequest).where(
            AssetReviewRequest.scan_run_id == run_id, AssetReviewRequest.state == "pending",
        )
    )
    if pending_review is not None:
        pending_review.state = "cancelled"
        pending_review.decided_at = now
    append_audit_log(
        db, engagement_id=engagement_id, actor=f"user:{user.email}", action="scan_run_cancel_requested",
        decision="ALLOW", reason="cancelled_by_operator", payload={
            "scan_run_id": str(run_id), "state": "aborted",
        },
    )
    return {
        "scan_run_id": str(run_id),
        "cancel_requested": True,
        "state": "aborted",
        "state_reason": "cancelled_by_operator",
    }


@router.get("/{engagement_id}/asset-reviews", response_model=list[AssetReviewOut])
def list_asset_reviews(engagement_id: uuid.UUID, state: str = "pending", db: Session = Depends(get_db)):
    """REQ-ASSETREVIEW-002: fuer den Run-detail-Popup-Poll (Muster wie
    list_approvals) - i. d. R. 0 oder 1 Treffer je Engagement."""
    return db.scalars(
        select(AssetReviewRequest).where(
            AssetReviewRequest.engagement_id == engagement_id, AssetReviewRequest.state == state,
        )
    ).all()


@router.post("/{engagement_id}/asset-reviews/{review_id}/decide", response_model=AssetReviewOut)
def decide_asset_review(
    engagement_id: uuid.UUID, review_id: uuid.UUID, body: AssetReviewDecisionIn,
    db: Session = Depends(get_db), user: User = Depends(require_user),
):
    """REQ-ASSETREVIEW-003/004: Ausschluesse werden auf die urspruengliche
    Kandidatenliste eingeschraenkt (kann Scope nur verkleinern, nie erweitern),
    erzeugen eine ECHTE, vom Gateway durchgesetzte deny-Regel je ausgeschlossenem
    Wert, und setzen discovered_asset.in_scope entsprechend."""
    review = db.get(AssetReviewRequest, review_id)
    if review is None or review.engagement_id != engagement_id:
        raise HTTPException(404, "asset review not found")
    if review.state != "pending":
        raise HTTPException(409, f"asset review already in state '{review.state}'")
    if review.expires_at < datetime.datetime.now(datetime.timezone.utc):
        review.state = "expired"
        db.commit()
        raise HTTPException(409, "asset review expired")

    candidates = {c["value"]: c for c in review.candidate_assets}
    excluded = [v for v in body.excluded_values if v in candidates]

    for value in excluded:
        candidate = candidates[value]
        asset_type = candidate.get("asset_type") or "domain"
        existing_deny = db.scalar(
            select(ScopeAsset).where(
                ScopeAsset.engagement_id == engagement_id, ScopeAsset.rule == "deny",
                ScopeAsset.asset_type == asset_type, ScopeAsset.value == value,
            )
        )
        if existing_deny is None:
            db.add(ScopeAsset(engagement_id=engagement_id, rule="deny", asset_type=asset_type, value=value))
        discovered = db.scalar(
            select(DiscoveredAsset).where(
                DiscoveredAsset.engagement_id == engagement_id, DiscoveredAsset.value == value,
            )
        )
        if discovered is not None:
            discovered.in_scope = False

    review.state = "submitted"
    review.excluded_values = excluded
    review.decided_at = datetime.datetime.now(datetime.timezone.utc)
    review.decided_by = user.email

    run = db.get(ScanRun, review.scan_run_id)
    if run is not None and run.state == "waiting_approval" and run.state_reason == "asset_review_pending":
        run.state = "running"
        run.state_reason = None
        run.heartbeat_at = datetime.datetime.now(datetime.timezone.utc)

    db.execute(delete(ResolvedHost).where(ResolvedHost.engagement_id == engagement_id))
    db.commit()
    db.refresh(review)
    append_audit_log(
        db, engagement_id=engagement_id, actor=f"user:{user.email}", action="asset_review_decided",
        decision="ALLOW", reason="operator_asset_review",
        payload={"scan_run_id": str(review.scan_run_id), "excluded_values": excluded},
    )
    return review


@router.get("/{engagement_id}/scan-runs/{run_id}/agent-steps")
def list_agent_steps(engagement_id: uuid.UUID, run_id: uuid.UUID, db: Session = Depends(get_db)):
    """Vector-Agent-Transparenz (REQ-RUN-006): pro Iteration der an das Modell
    gesendete Kontext + dessen Antwort. Fuer den GUI-Drilldown."""
    run = db.get(ScanRun, run_id)
    if run is None or run.engagement_id != engagement_id:
        raise HTTPException(404, "scan_run not found for this engagement")
    steps = db.scalars(
        select(AgentStep).where(AgentStep.scan_run_id == run_id).order_by(AgentStep.iteration.asc())
    ).all()
    return [
        {"id": str(s.id), "iteration": s.iteration, "request_messages": s.request_messages,
         "response_text": s.response_text, "response_tool_calls": s.response_tool_calls,
         "stop_reason": s.stop_reason, "created_at": s.created_at.isoformat() if s.created_at else None}
        for s in steps
    ]


@router.get("/{engagement_id}/scan-runs/{run_id}/diff")
def scan_run_diff(engagement_id: uuid.UUID, run_id: uuid.UUID, db: Session = Depends(get_db)):
    """Was hat dieser Lauf gegenueber seinem Vorgaenger veraendert: neu / behoben
    (nicht mehr beobachtet) / bestehend. has_baseline=false = erster Lauf, es
    gibt keinen Vorgaenger zum Vergleich."""
    run = db.get(ScanRun, run_id)
    if run is None or run.engagement_id != engagement_id:
        raise HTTPException(404, "scan_run not found for this engagement")
    return scan_diff.compute_diff(db, run)


@router.get("/{engagement_id}/scan-runs", response_model=list[ScanRunOut])
def list_scan_runs(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    """scan_run-Zustandsmaschine von aussen sichtbar (Architektur Kap. 4.1) -
    z. B. um zu pollen, ob ein ausgeloester Scan (state='done') fertig ist,
    statt aus Findings-Zahlen zu raten."""
    return db.scalars(
        select(ScanRun).where(ScanRun.engagement_id == engagement_id).order_by(ScanRun.started_at.desc())
    ).all()
