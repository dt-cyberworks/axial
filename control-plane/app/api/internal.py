"""Interne Schnittstelle fuer den Worker (Deployment-Architektur Kap. 2:
control-plane ist der einzige DB-Schreiber; worker fuehrt selbst nichts aus).

Nicht oeffentlich exponieren - in Produktion nur aus dem Cluster-internen
Netz erreichbar (kein Ingress), s. Deployment-Architektur Kap. 5.
"""

import datetime
import hashlib
import uuid
from secrets import compare_digest, token_urlsafe

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app import config_resolver, report_service
from app.db.base import get_db
from app.gateway.audit import append_audit_log
from app.gateway.authorize import ToolCall, authorize
from app.gateway.dns_materialization import materialize
from app.gateway.raw_egress_policy import render_for_engagement
from app.gateway.raw_egress_lease import _effective_port_ranges_for_target, issue_raw_egress_lease
from app.graph.builder import materialize_graph, read_graph
from app.settings_store import get_llm_config, get_nvd_config
from app.models.asset import DiscoveredAsset, Service
from app.models.asset_review import AssetReviewRequest
from app.models.cve_cache import CveLookupCache, EpssScoreCache, KevCatalogCache
from app.models.dns_record import DnsRecord
from app.models.approval import ApprovalRequest
from app.models.finding import Finding, FindingObservation
from app.models.engagement import BountyProgram, Engagement, ScopeAsset, ToolGrant
from app.models.openwire_callback import OpenwireCallbackToken
from app.models.scan_run import AgentStep, ScanRun
from app.scan_lifecycle import ScanRunAlreadyActive, reap_all_stale_runs, reap_stale_runs, start_scan_run
from app.scoring.risk_score import compute_risk_score, compute_severity, risk_score_floor_for_severity
from app.schemas.internal import (
    AgentEventIn,
    ApprovalClaimOut,
    ApprovalExecutionResult,
    AgentStepIn,
    AssetReviewCreateIn,
    BenchmarkEngagementCreate,
    CveLookupCacheIn,
    CveLookupCacheOut,
    DecisionOut,
    DiscoveredAssetIn,
    DnsRecordIn,
    EpssCacheBatchIn,
    EpssCacheOut,
    FindingIn,
    HttpProbeResultIn,
    KevCatalogCacheIn,
    KevCatalogCacheOut,
    MaterializeDnsOut,
    NvdConfigOut,
    OpenwireCallbackStatusOut,
    OpenwireCallbackTokenCreate,
    OpenwireCallbackTokenOut,
    ProxyAuditEventIn,
    RawEgressLeaseIn,
    RawEgressLeaseOut,
    RawEgressPolicyOut,
    ScanRunCreate,
    ScanRunOut,
    ScanRunUpdate,
    ServiceIn,
    ToolExecutionEventIn,
    ToolCallIn,
)

def require_internal_token(x_asm_internal_token: str | None = Header(default=None)) -> None:
    token = get_settings().internal_api_token
    if not token or not x_asm_internal_token or not compare_digest(x_asm_internal_token, token):
        raise HTTPException(403, "internal token required")


router = APIRouter(prefix="/internal", tags=["internal"], dependencies=[Depends(require_internal_token)])

_VALID_SEV = {"info", "low", "medium", "high", "critical"}


@router.post("/benchmark/engagements", status_code=201)
def internal_create_benchmark_engagement(body: BenchmarkEngagementCreate, db: Session = Depends(get_db)):
    """REQ-BENCH-007: the benchmark harness's own engagement-creation path.
    source='benchmark' is forced here, server-side - never client-supplied,
    and unreachable via the operator-facing POST /engagements (which
    explicitly 403s on source='benchmark', see api/engagements.py). Creates,
    scopes, grants tools, and activates in one call so there is no
    partially-seeded intermediate state for a caller to leave behind."""
    now = datetime.datetime.now(datetime.timezone.utc)
    eng = Engagement(
        title=body.title, source="benchmark", status="active",
        authorized_from=now - datetime.timedelta(minutes=5),
        authorized_until=now + datetime.timedelta(days=1),
        tcp_port_from=body.tcp_port_from, tcp_port_to=body.tcp_port_to,
        ai_testing_allowed=True,
    )
    db.add(eng)
    db.flush()
    db.add(ScopeAsset(
        engagement_id=eng.id, rule="allow", asset_type="domain", value=body.target_host,
        active_allowed=True, authorization_verified=True, authorization_method="benchmark",
    ))
    for category in body.tool_categories:
        db.add(ToolGrant(engagement_id=eng.id, tool_category=category, mode="active", requires_manual_approval=False))
    db.commit()
    db.refresh(eng)
    append_audit_log(
        db, engagement_id=eng.id, actor="internal:benchmark-harness", action="engagement_created",
        decision=None, reason=None, payload={"title": eng.title, "source": "benchmark", "target_host": body.target_host},
    )
    return {"id": str(eng.id), "source": eng.source, "target_host": body.target_host}


_OPENWIRE_CALLBACK_TTL = datetime.timedelta(minutes=2)


@router.post("/engagements/{engagement_id}/openwire-callback-tokens", status_code=201, response_model=OpenwireCallbackTokenOut)
def internal_create_openwire_callback_token(
    engagement_id: uuid.UUID, body: OpenwireCallbackTokenCreate, db: Session = Depends(get_db),
):
    """REQ-AGENT-027: a fresh, single-use, short-lived token for the OpenWire
    deserialization probe's callback URL. ~256 bits of randomness (the same
    generator/entropy this codebase already uses for session tokens,
    app/sessions.py), bound to exactly this engagement (and scan run, when
    given) and expiring quickly - the probe's own bounded wait window is far
    shorter than this TTL, so a token is never usefully guessable or
    replayable after the call that created it is already done."""
    if db.get(Engagement, engagement_id) is None:
        raise HTTPException(404, "engagement not found")
    if body.scan_run_id is not None:
        run = db.get(ScanRun, body.scan_run_id)
        if run is None or run.engagement_id != engagement_id:
            raise HTTPException(422, "scan run does not belong to engagement")
    now = datetime.datetime.now(datetime.timezone.utc)
    token = token_urlsafe(32)
    expires_at = now + _OPENWIRE_CALLBACK_TTL
    db.add(OpenwireCallbackToken(
        token=token, engagement_id=engagement_id, scan_run_id=body.scan_run_id,
        created_at=now, expires_at=expires_at,
    ))
    db.commit()
    callback_url = f"{get_settings().public_base_url.rstrip('/')}/callback/openwire/{token}"
    return OpenwireCallbackTokenOut(token=token, callback_url=callback_url, expires_at=expires_at)


@router.get("/engagements/{engagement_id}/openwire-callback-tokens/{token}", response_model=OpenwireCallbackStatusOut)
def internal_get_openwire_callback_status(engagement_id: uuid.UUID, token: str, db: Session = Depends(get_db)):
    """Polled by the worker within its bounded wait window - never by the
    probed target itself (that hits the genuinely public /callback/openwire/
    endpoint, app/api/openwire_callback.py, with no auth at all)."""
    row = db.get(OpenwireCallbackToken, token)
    if row is None or row.engagement_id != engagement_id:
        raise HTTPException(404, "token not found")
    triggered_at = row.triggered_at
    if triggered_at is not None and triggered_at.tzinfo is None:
        triggered_at = triggered_at.replace(tzinfo=datetime.timezone.utc)
    return OpenwireCallbackStatusOut(triggered=triggered_at is not None, triggered_at=triggered_at)


@router.get("/engagements/{engagement_id}/scope-assets")
def internal_scope_assets(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    if db.get(Engagement, engagement_id) is None:
        raise HTTPException(404, "engagement not found")
    return [
        {"id": str(a.id), "engagement_id": str(a.engagement_id), "rule": a.rule,
         "asset_type": a.asset_type, "value": a.value, "path_pattern": a.path_pattern,
         "active_allowed": a.active_allowed, "authorization_verified": a.authorization_verified}
        for a in db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == engagement_id))
    ]


@router.post("/engagements/{engagement_id}/report", status_code=202)
def internal_request_report(
    engagement_id: uuid.UUID, scan_run_id: uuid.UUID | None = None, db: Session = Depends(get_db),
):
    """REQ-REPORT-003: the pipeline's report phase generates a real report for
    the run that just finished, instead of minting a throwaway job id.

    Actor is "pipeline", not an operator identity - the worker boundary grants
    no user context.
    """
    if db.get(Engagement, engagement_id) is None:
        raise HTTPException(404, "engagement not found")
    report = report_service.generate_report(
        db, engagement_id, requested_by="pipeline", scan_run_id=scan_run_id,
    )
    return {
        "job_id": str(report.id),
        "report_id": str(report.id),
        "status": report.status,
        "byte_size": report.byte_size,
        "error": report.error,
    }


@router.get("/engagements/{engagement_id}/agent-config")
def internal_agent_config(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    """Effektive Agent-Konfig fuer den Worker: die aufgeloeste Anweisung
    (Kampagne -> global -> eingebauter Default, nie leer) und die fuer diese
    Kampagne aktivierten Tools, plus (REQ-AGENT-012) die Engagement-Parameter,
    damit der Agent sein Ziel-Umfeld kennt (Autorisierungsfenster, Quelle,
    Portfenster, KI-Testing-Opt-in) statt nur die reine Hostliste."""
    eng = db.get(Engagement, engagement_id)
    return {
        "prompt": config_resolver.effective_agent_prompt(db, engagement_id),
        "enabled_tools": config_resolver.enabled_tools(db, engagement_id),
        # REQ-AGENT-026: resolved completion-token cap (campaign -> global ->
        # built-in 8192). Delivered here so the worker reads the same
        # configured value every other agent knob already comes from, instead
        # of a container env var fixed at process start.
        "agent_max_tokens": config_resolver.effective_agent_max_tokens(db, engagement_id),
        "engagement": None if eng is None else {
            "title": eng.title,
            "source": eng.source,
            "authorized_from": eng.authorized_from.isoformat(),
            "authorized_until": eng.authorized_until.isoformat(),
            "tcp_port_from": eng.tcp_port_from,
            "tcp_port_to": eng.tcp_port_to,
            "ai_testing_allowed": eng.ai_testing_allowed,
        },
    }


@router.get("/llm-config")
def internal_llm_config(db: Session = Depends(get_db)):
    """Vollstaendige LLM-Provider-Konfig (inkl. api_key) fuer den Worker/Vector
    Agent. Nur Cluster-intern erreichbar (kein Ingress, s. Modulkopf) - der
    Klartext-Schluessel verlaesst das interne Netz nie. Die oeffentliche GUI
    nutzt /settings/llm (maskiert)."""
    cfg = get_llm_config(db)
    return {"base_url": cfg.base_url, "model": cfg.model, "api_key": cfg.api_key,
            "source": cfg.source, "is_usable": cfg.is_usable}


@router.get("/nvd-config", response_model=NvdConfigOut)
def internal_nvd_config(db: Session = Depends(get_db)):
    """Optional NVD API key fuer den Worker (REQ-CORR-008). Nur Cluster-intern
    erreichbar (kein Ingress); unset ist ein vollwertiger, unterstuetzter
    Zustand - die Korrelation arbeitet dann mit dem oeffentlichen Rate-Limit."""
    cfg = get_nvd_config(db)
    return NvdConfigOut(api_key=cfg.api_key or None, source=cfg.source)


# --- Live NVD/EPSS/KEV correlation cache (REQ-CORR-001..008) ---
#
# Plain read-through key/value storage for the worker's correlate phase
# (worker/app/tasks/correlate.py). Staleness/TTL is a worker-side decision
# (compare fetched_at to a configured TTL) - these endpoints do not interpret
# freshness themselves, matching every other internal endpoint in this API.

@router.get("/cve-lookup-cache", response_model=CveLookupCacheOut)
def internal_get_cve_lookup_cache(product_key: str, db: Session = Depends(get_db)):
    row = db.query(CveLookupCache).filter(CveLookupCache.product_key == product_key).first()
    if row is None:
        raise HTTPException(404, "no cached NVD lookup for this product")
    return CveLookupCacheOut(
        product_key=row.product_key, candidates=row.candidates,
        fetched_at=row.fetched_at, source=row.source,
    )


@router.put("/cve-lookup-cache", response_model=CveLookupCacheOut, status_code=201)
def internal_put_cve_lookup_cache(body: CveLookupCacheIn, db: Session = Depends(get_db)):
    row = db.query(CveLookupCache).filter(CveLookupCache.product_key == body.product_key).first()
    now = datetime.datetime.now(datetime.timezone.utc)
    if row is None:
        row = CveLookupCache(product_key=body.product_key, candidates=body.candidates,
                              fetched_at=now, source=body.source)
        db.add(row)
    else:
        row.candidates = body.candidates
        row.source = body.source
        row.fetched_at = now
    db.commit()
    db.refresh(row)
    return CveLookupCacheOut(
        product_key=row.product_key, candidates=row.candidates,
        fetched_at=row.fetched_at, source=row.source,
    )


@router.get("/epss-cache", response_model=EpssCacheOut)
def internal_get_epss_cache(cve_ids: str, db: Session = Depends(get_db)):
    """cve_ids: comma-separated. Response omits misses (REQ-CORR-002) - the
    worker fetches those live from EPSS and writes them back."""
    ids = [c.strip() for c in cve_ids.split(",") if c.strip()]
    rows = db.query(EpssScoreCache).filter(EpssScoreCache.cve_id.in_(ids)).all()
    return EpssCacheOut(
        scores={r.cve_id: float(r.epss) for r in rows},
        fetched_at={r.cve_id: r.fetched_at for r in rows},
    )


@router.put("/epss-cache", status_code=204)
def internal_put_epss_cache(body: EpssCacheBatchIn, db: Session = Depends(get_db)):
    now = datetime.datetime.now(datetime.timezone.utc)
    for entry in body.entries:
        row = db.get(EpssScoreCache, entry.cve_id)
        if row is None:
            db.add(EpssScoreCache(cve_id=entry.cve_id, epss=entry.epss, fetched_at=now))
        else:
            row.epss = entry.epss
            row.fetched_at = now
    db.commit()


@router.get("/kev-catalog-cache", response_model=KevCatalogCacheOut)
def internal_get_kev_catalog_cache(db: Session = Depends(get_db)):
    row = db.get(KevCatalogCache, 1)
    if row is None:
        return KevCatalogCacheOut(cve_ids=[], catalog_version=None, fetched_at=None)
    return KevCatalogCacheOut(
        cve_ids=row.cve_ids, catalog_version=row.catalog_version, fetched_at=row.fetched_at,
    )


@router.put("/kev-catalog-cache", response_model=KevCatalogCacheOut)
def internal_put_kev_catalog_cache(body: KevCatalogCacheIn, db: Session = Depends(get_db)):
    row = db.get(KevCatalogCache, 1)
    now = datetime.datetime.now(datetime.timezone.utc)
    if row is None:
        row = KevCatalogCache(id=1, cve_ids=body.cve_ids, catalog_version=body.catalog_version, fetched_at=now)
        db.add(row)
    else:
        row.cve_ids = body.cve_ids
        row.catalog_version = body.catalog_version
        row.fetched_at = now
    db.commit()
    db.refresh(row)
    return KevCatalogCacheOut(cve_ids=row.cve_ids, catalog_version=row.catalog_version, fetched_at=row.fetched_at)


@router.post("/engagements/{engagement_id}/gateway/authorize", response_model=DecisionOut)
def internal_authorize(engagement_id: uuid.UUID, body: ToolCallIn, db: Session = Depends(get_db)):
    """Wird vom Vector-Agent-Loop (Architektur Listing 8) fuer JEDEN Vorschlag
    aufgerufen, bevor irgendetwas den tool-runner erreicht."""
    call = ToolCall(engagement_id=engagement_id, **body.model_dump())
    decision = authorize(db, call)
    return DecisionOut(
        allowed=decision.allowed,
        reason=decision.reason,
        is_pending=decision.is_pending,
        approval_request_id=decision.approval_request_id,
        is_throttled=decision.is_throttled,
        retry_after_seconds=decision.retry_after_seconds,
    )


@router.post(
    "/engagements/{engagement_id}/raw-egress-leases",
    response_model=RawEgressLeaseOut,
)
def internal_raw_egress_lease(
    engagement_id: uuid.UUID, body: RawEgressLeaseIn, db: Session = Depends(get_db)
):
    result = issue_raw_egress_lease(
        db,
        engagement_id=engagement_id,
        scan_run_id=body.scan_run_id,
        authorized_target=body.authorized_target,
        resolved_target=body.resolved_target,
        phase=body.phase,
        port_profile=body.port_profile,
        port=body.port,
        tool=body.tool,
    )
    decision = result.decision
    return RawEgressLeaseOut(
        allowed=decision.allowed,
        reason=decision.reason,
        is_pending=decision.is_pending,
        approval_request_id=decision.approval_request_id,
        is_throttled=decision.is_throttled,
        retry_after_seconds=decision.retry_after_seconds,
        lease_token=result.lease_token,
        lease_id=result.lease_id,
        expires_at=result.expires_at,
        port_profile=result.port_profile,
        port_range=result.port_range,
        protocol=result.protocol,
        udp_discovery_enabled=result.udp_discovery_enabled,
        max_rate=result.max_rate,
        port=result.port,
    )


@router.post("/engagements/{engagement_id}/agent-events", status_code=201)
def internal_agent_event(engagement_id: uuid.UUID, body: AgentEventIn, db: Session = Depends(get_db)):
    """Worker-visible Vector Agent telemetry for operator audit/live views.

    This records lifecycle, provider failures, proposals, observations, and
    conclusions without exposing API keys or raw prompt contents.
    """
    append_audit_log(
        db,
        engagement_id=engagement_id,
        actor="agent",
        action="agent_event",
        decision=body.decision,
        reason=body.reason or body.event,
        payload={"event": body.event, **(body.payload or {})},
    )
    return {"ok": True}


@router.post("/engagements/{engagement_id}/tool-executions", status_code=201)
def internal_tool_execution(
    engagement_id: uuid.UUID, body: ToolExecutionEventIn, db: Session = Depends(get_db)
):
    if db.get(Engagement, engagement_id) is None:
        raise HTTPException(404, "engagement not found")
    if body.scan_run_id is not None:
        run = db.get(ScanRun, body.scan_run_id)
        if run is None or run.engagement_id != engagement_id:
            raise HTTPException(422, "scan run does not belong to engagement")
    append_audit_log(
        db, engagement_id=engagement_id, actor="worker", action="tool_execution",
        decision="ALLOW" if body.success else "DENY",
        reason="completed" if body.success else (body.error_reason or "tool_execution_failed"),
        payload={
            "scan_run_id": str(body.scan_run_id) if body.scan_run_id else None,
            "tool": body.tool, "phase": body.phase,
            "authorized_target": body.authorized_target,
            "resolved_target": body.resolved_target, "port_range": body.port_range,
            "success": body.success, "exit_code": body.exit_code,
            "error_reason": body.error_reason, "stderr_summary": body.stderr_summary,
            "discovered_services": body.discovered_services,
            "outcome_summary": {
                str(key)[:64]: value for key, value in list(body.outcome_summary.items())[:20]
            },
            # REQ-AUDIT-003: the exact invocation, so "prove what you ran
            # against my systems" is answerable from the audit log alone.
            # Already redacted worker-side (REQ-AUDIT-004).
            "command": body.command,
            # REQ-AUDIT-006/007: the full target response for http_request,
            # already redacted worker-side. "prove what my systems sent back"
            # is answerable the same way "prove what you ran" already is.
            "response": body.response,
        },
    )
    return {"ok": True}


@router.post("/engagements/{engagement_id}/proxy-audit", status_code=201)
def internal_proxy_audit(engagement_id: uuid.UUID, body: ProxyAuditEventIn, db: Session = Depends(get_db)):
    if body.decision not in {"ALLOW", "DENY"}:
        raise HTTPException(422, "invalid proxy audit decision")
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(404, "engagement not found")
    payload = dict(body.payload or {})
    # Bound untrusted network metadata before it enters durable audit storage.
    payload = {str(k)[:64]: str(v)[:500] for k, v in list(payload.items())[:20]}
    append_audit_log(
        db, engagement_id=engagement_id, actor="egress-proxy", action="network_request",
        decision=body.decision, reason=body.reason[:100], payload=payload,
    )
    return {"ok": True}


@router.get("/engagements/{engagement_id}/raw-egress-policy", response_model=RawEgressPolicyOut)
def raw_egress_policy(engagement_id: uuid.UUID, namespace: str | None = None, db: Session = Depends(get_db)):
    """Render the nmap/raw-scan NetworkPolicy for this engagement.

    HTTP-aware tools continue to use the egress-proxy. nmap cannot be safely
    forced through that HTTP proxy, so production runners need a separate
    L3/L4 allowlist generated from active IP/CIDR scope. Domain/wildcard
    assets are omitted until an audited DNS-resolution step materializes IPs.
    """
    try:
        rendered = render_for_engagement(db, engagement_id, namespace=namespace)
    except ValueError as exc:
        status_code = 404 if str(exc) == "engagement_not_found" else 409
        raise HTTPException(status_code, str(exc)) from exc
    return RawEgressPolicyOut(
        policy=rendered.policy,
        ip_blocks=rendered.ip_blocks,
        omitted_assets=rendered.omitted_assets,
        warnings=rendered.warnings,
    )


@router.post("/engagements/{engagement_id}/materialize-dns", response_model=MaterializeDnsOut)
def materialize_dns(
    engagement_id: uuid.UUID, scan_run_id: uuid.UUID | None = Query(default=None),
    db: Session = Depends(get_db),
):
    """Auditierte DNS-Materialisierung des Namens-Scope zu IPs (raw egress).

    Vor einem nmap-/Raw-Scan-Job gegen namensbasierten Scope: loest die
    freigegebenen Namen (aktive domain-allow-Assets + in-scope discovered) zu
    IPs auf, wendet deny-Vorrang auf IP-Ebene an, haelt das Ergebnis auditiert
    fest (resolved_host + audit_log) und speist es in die raw-egress-policy.
    Nur die control-plane fuehrt das aus (Trust-Anchor)."""
    try:
        result = materialize(db, engagement_id, scan_run_id=scan_run_id)
    except ValueError as exc:
        status_code = 404 if str(exc) == "engagement_not_found" else 409
        raise HTTPException(status_code, str(exc)) from exc
    return MaterializeDnsOut(
        resolved=result.resolved,
        denied_ips=result.denied_ips,
        unresolved=result.unresolved,
        warnings=result.warnings,
    )


@router.post("/engagements/{engagement_id}/scan-runs", response_model=ScanRunOut, status_code=201)
def create_scan_run(engagement_id: uuid.UUID, body: ScanRunCreate, db: Session = Depends(get_db)):
    """scan_run-Zustandsmaschine (Architektur Kap. 4.1): discovery -> ... -> report.

    GitHub issue #18: the primary path (start_scan, control-plane/app/api/
    engagements.py) now creates the scan_run itself before enqueueing and the
    worker no longer calls this endpoint - kept as a legacy/direct-testing
    entry point, now sharing the same race-safe creation helper (a partial
    unique index is the actual invariant, not this endpoint's own check)."""
    reap_stale_runs(db, engagement_id)
    try:
        return start_scan_run(db, engagement_id, budget_tool_calls_max=body.budget_tool_calls_max)
    except ScanRunAlreadyActive:
        raise HTTPException(409, "engagement already has an active scan_run") from None


@router.post("/scan-runs/reap-stale")
def internal_reap_all_stale_runs(db: Session = Depends(get_db)):
    """GitHub issue #29: periodic reconciliation, independent of any inbound
    request touching a specific engagement. Meant to be called by a Celery
    beat schedule (worker/app/tasks/reap.py) so an abandoned run does not
    stay 'running' forever just because nobody happened to start another
    scan on that same engagement."""
    reaped = reap_all_stale_runs(db)
    return {"reaped": reaped}


@router.get("/approvals/{approval_id}")
def internal_get_approval(approval_id: uuid.UUID, db: Session = Depends(get_db)):
    """Der Worker pollt hier den Freigabe-Status eines zustandsaendernden
    http_request (REQ-APPROVAL-003). Laeuft die Freigabe ab, wird sie hier
    lazily auf 'expired' gesetzt."""
    ap = db.get(ApprovalRequest, approval_id)
    if ap is None:
        raise HTTPException(404, "approval not found")
    if ap.state == "requested" and ap.expires_at < datetime.datetime.now(datetime.timezone.utc):
        ap.state = "expired"
        db.commit()
    return {"id": str(ap.id), "state": ap.state, "tool_call": ap.tool_call}


def _tool_call_from_approval(ap: ApprovalRequest) -> ToolCall:
    payload = dict(ap.tool_call or {})
    payload.pop("engagement_id", None)
    if payload.get("scan_run_id"):
        payload["scan_run_id"] = uuid.UUID(str(payload["scan_run_id"]))
    return ToolCall(engagement_id=ap.engagement_id, **payload)


@router.post("/approvals/{approval_id}/claim", response_model=ApprovalClaimOut)
def internal_claim_approval(approval_id: uuid.UUID, db: Session = Depends(get_db)):
    """Atomically claim and reauthorize the exact stored call before dispatch."""
    ap = db.get(ApprovalRequest, approval_id)
    if ap is None:
        raise HTTPException(404, "approval not found")
    call = _tool_call_from_approval(ap)
    decision = authorize(db, call, approved_request_id=approval_id)
    if not decision.allowed and not decision.is_throttled:
        current = db.get(ApprovalRequest, approval_id)
        if current is not None and current.state == "approved":
            current.state = "execution_failed"
            current.execution_finished_at = datetime.datetime.now(datetime.timezone.utc)
            current.execution_error = decision.reason[:500]
            db.commit()
    return ApprovalClaimOut(
        allowed=decision.allowed, reason=decision.reason,
        is_throttled=decision.is_throttled,
        retry_after_seconds=decision.retry_after_seconds,
        tool_call=call.as_jsonable() if decision.allowed else None,
    )


@router.post("/approvals/{approval_id}/complete")
def internal_complete_approval(
    approval_id: uuid.UUID, body: ApprovalExecutionResult, db: Session = Depends(get_db)
):
    """Record the terminal result of a previously claimed execution."""
    ap = db.scalar(select(ApprovalRequest).where(ApprovalRequest.id == approval_id).with_for_update())
    if ap is None:
        raise HTTPException(404, "approval not found")
    if ap.state != "executing":
        raise HTTPException(409, f"approval is '{ap.state}', not 'executing'")
    ap.state = "consumed" if body.success else "execution_failed"
    ap.execution_finished_at = datetime.datetime.now(datetime.timezone.utc)
    ap.execution_error = None if body.success else (body.error or "runner_execution_failed")[:500]
    db.add(ap)
    append_audit_log(
        db, engagement_id=ap.engagement_id, actor="worker", action="approval_execution",
        decision="ALLOW" if body.success else "DENY",
        reason="consumed" if body.success else "execution_failed",
        payload={"approval_id": str(ap.id), "scan_run_id": ap.tool_call.get("scan_run_id")},
    )
    return {"id": str(ap.id), "state": ap.state}


@router.get("/scan-runs/{scan_run_id}/cancel-requested")
def scan_run_cancel_requested(scan_run_id: uuid.UUID, db: Session = Depends(get_db)):
    """Der Worker pollt hier, ob ein Stopp angefordert wurde (REQ-RUN-001)."""
    run = db.get(ScanRun, scan_run_id)
    if run is None:
        raise HTTPException(404, "scan_run not found")
    return {"cancel_requested": bool(run.cancel_requested)}


@router.post("/engagements/{engagement_id}/agent-steps", status_code=201)
def internal_record_agent_step(engagement_id: uuid.UUID, body: AgentStepIn, db: Session = Depends(get_db)):
    """Der Worker haelt pro Vector-Agent-Iteration Prompt + Antwort fest
    (REQ-RUN-006). api_key wird nie mitgesendet."""
    run = db.get(ScanRun, body.scan_run_id)
    if (
        run is None or run.engagement_id != engagement_id
        or run.state not in {"running", "waiting_approval"}
        or run.cancel_requested
    ):
        raise HTTPException(409, "scan_run is not active")
    step = AgentStep(
        engagement_id=engagement_id, scan_run_id=body.scan_run_id, iteration=body.iteration,
        request_messages=body.request_messages, response_text=body.response_text,
        response_tool_calls=body.response_tool_calls, stop_reason=body.stop_reason,
    )
    db.add(step)
    db.commit()
    return {"id": str(step.id)}


@router.patch("/scan-runs/{scan_run_id}", response_model=ScanRunOut)
def update_scan_run(scan_run_id: uuid.UUID, body: ScanRunUpdate, db: Session = Depends(get_db)):
    run = db.scalar(select(ScanRun).where(ScanRun.id == scan_run_id).with_for_update())
    if run is None:
        raise HTTPException(404, "scan_run not found")

    # The operator-owned cancellation transition is terminal and immutable. A
    # stale worker may finish an HTTP request later, but it cannot resurrect or
    # relabel the aborted run. Returning the current row keeps cleanup idempotent.
    if run.cancel_requested and run.state == "aborted":
        return run
    if run.state in {"done", "failed", "aborted"}:
        raise HTTPException(409, f"scan_run is terminal: {run.state}")

    if body.increment_tool_calls:
        run.budget_tool_calls_used += body.increment_tool_calls
        if run.budget_tool_calls_used > run.budget_tool_calls_max:
            run.state = "aborted"  # Budget-Grenze, s. Architektur Kap. 4.2

    if body.phase is not None:
        run.phase = body.phase
    if body.state is not None:
        run.state = body.state
    if body.state_reason is not None:
        run.state_reason = body.state_reason
    if body.state in ("done", "failed", "aborted"):
        run.finished_at = datetime.datetime.now(datetime.timezone.utc)
    # REQ-FIDELITY-006: nur anwenden, wenn im Request-Body tatsaechlich gesetzt -
    # sonst wuerde jeder phase/state-only-Aufruf das aktuelle Tool loeschen.
    if "current_tool" in body.model_fields_set:
        run.current_tool = body.current_tool
        run.current_target = body.current_target
        run.current_started_at = (
            datetime.datetime.now(datetime.timezone.utc) if body.current_tool else None
        )

    # Fortschritt = Lebenszeichen (REQ-RAWLEASE-001): jedes Update haelt den Lauf
    # fuer den Reaper "lebendig".
    run.heartbeat_at = datetime.datetime.now(datetime.timezone.utc)

    db.commit()
    db.refresh(run)
    # Ein reines Live-Activity-Update (current_tool, kein Phasen-/Zustandswechsel)
    # ist hochfrequente, ephemere Telemetrie - kein eigener Audit-Eintrag noetig,
    # das Ergebnis landet bereits ueber tool_execution im Audit-Log.
    if body.phase is not None or body.state is not None:
        append_audit_log(
            db, engagement_id=run.engagement_id, actor="worker", action="scan_run_transition",
            decision=None, reason=None, payload={"scan_run_id": str(run.id), "phase": run.phase, "state": run.state},
        )
    return run


@router.post("/scan-runs/{scan_run_id}/heartbeat")
def heartbeat_scan_run(scan_run_id: uuid.UUID, db: Session = Depends(get_db)):
    """Leichtes Lebenszeichen fuer laufende Laeufe (REQ-RAWLEASE-001), damit lange
    Operationen (z. B. ein mehrminuetiger Nmap) nicht faelschlich als verwaist
    geerntet werden. Terminale Laeufe bleiben unangetastet (idempotent)."""
    run = db.get(ScanRun, scan_run_id)
    if run is None:
        raise HTTPException(404, "scan_run not found")
    if run.state in ("running", "waiting_approval"):
        run.heartbeat_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()
    return {"scan_run_id": str(scan_run_id), "state": run.state}


@router.post("/engagements/{engagement_id}/discovered-assets", status_code=201)
def add_discovered_asset(engagement_id: uuid.UUID, body: DiscoveredAssetIn, db: Session = Depends(get_db)):
    # Idempotent auf (engagement, value): ein zweiter Scan-Lauf soll denselben
    # Namen nicht duplizieren, sondern die vorhandene ID zurueckgeben
    # (Diff-Trend lebt ueber finding.fingerprint, nicht ueber Asset-Dubletten).
    existing = db.scalar(
        select(DiscoveredAsset).where(
            DiscoveredAsset.engagement_id == engagement_id, DiscoveredAsset.value == body.value
        )
    )
    if existing is not None:
        existing.last_seen = datetime.datetime.now(datetime.timezone.utc)
        if body.in_scope:
            existing.in_scope = True
        # REQ-GRAPH-006: backfill the structural subdomain->domain backbone on
        # re-scan for assets created before it was populated. parent_id is
        # structural metadata only - the Scope Gateway never reads it.
        if body.parent_id is not None and existing.parent_id is None:
            existing.parent_id = body.parent_id
        db.commit()
        return {"id": existing.id}
    asset = DiscoveredAsset(
        engagement_id=engagement_id,
        first_seen=datetime.datetime.now(datetime.timezone.utc),
        last_seen=datetime.datetime.now(datetime.timezone.utc),
        **body.model_dump(),
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return {"id": asset.id}


@router.patch("/engagements/{engagement_id}/discovered-assets/{asset_id}/http-probe")
def record_http_probe(
    engagement_id: uuid.UUID, asset_id: uuid.UUID, body: HttpProbeResultIn, db: Session = Depends(get_db)
):
    """The deterministic fingerprint phase's httpx probe result (live or dead),
    regardless of outcome - so the agent phase can tell 'never checked' apart
    from 'already checked, no live HTTP service' and skip re-probing the
    latter (REQ-AGENT-015)."""
    asset = db.get(DiscoveredAsset, asset_id)
    if asset is None or asset.engagement_id != engagement_id:
        raise HTTPException(404, "discovered_asset not found for this engagement")
    asset.http_checked_at = datetime.datetime.now(datetime.timezone.utc)
    asset.http_live = body.live
    db.commit()
    return {"ok": True}


@router.get("/engagements/{engagement_id}/discovered-assets")
def list_discovered_assets(engagement_id: uuid.UUID, in_scope: bool | None = None, db: Session = Depends(get_db)):
    """Bereits bekannte Assets (fuer eine gegen Discovery-Ausfaelle resiliente
    fingerprint-Phase: sie soll den vollen in-scope-Bestand scannen, nicht nur
    die in DIESEM Lauf frisch entdeckten)."""
    stmt = select(DiscoveredAsset).where(DiscoveredAsset.engagement_id == engagement_id)
    if in_scope is not None:
        stmt = stmt.where(DiscoveredAsset.in_scope.is_(in_scope))
    return [{"id": a.id, "value": a.value, "in_scope": a.in_scope} for a in db.scalars(stmt)]


@router.get("/engagements/{engagement_id}/asset-review-required")
def asset_review_required(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    """REQ-ASSETREVIEW-001: opt-in Pause zwischen discovery und fingerprint.
    default false -> kein Verhaltensunterschied fuer bestehende Engagements."""
    eng = db.get(Engagement, engagement_id)
    return {"required": bool(eng and eng.asset_review_enabled)}


@router.get("/engagements/{engagement_id}/scan-envelope")
def get_scan_envelope(engagement_id: uuid.UUID, host: str | None = None, db: Session = Depends(get_db)):
    """REQ-FIDELITY-003: das autorisierte TCP-Portfenster fuer aktive HTTP-
    Tools (httpx/nikto/wafw00f/testssl/nuclei) - die public /engagements/{id}
    Route verlangt Operator-Auth, die der Worker nicht hat.

    REQ-PORTSCOPE-004: with `host`, resolves that target's own effective
    range (per-target ScopeAsset override intersected with the ceiling) via
    the same helper raw_egress_lease.py uses. Not itself an enforcement
    point (egress-proxy/raw_egress_lease still decide independently) - this
    only picks which port a tool's target URL should point at. A host
    matched by several scope-asset rows with genuinely different ranges has
    no single well-defined port to prefer, so it falls back to the ceiling
    unchanged rather than guessing."""
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(404, "engagement not found")
    if host:
        ranges = set(_effective_port_ranges_for_target(db, engagement_id, eng, host))
        if len(ranges) == 1:
            port_from, port_to = ranges.pop()
            return {"tcp_port_from": port_from, "tcp_port_to": port_to}
    return {"tcp_port_from": eng.tcp_port_from, "tcp_port_to": eng.tcp_port_to}


@router.get("/engagements/{engagement_id}/bounty-ident")
def get_bounty_ident(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    """GitHub issue #12: the identification the worker must inject into every
    HTTP-proxied tool's request when this engagement runs under a bug-bounty
    program's rules of engagement. The egress-proxy already does this itself
    for plain HTTP (`_forward_plain_http`) - but for HTTPS (CONNECT tunnels)
    the payload is opaque to the proxy, so the worker must inject it into the
    tool invocation directly, before the request is ever made. Returns nulls
    (not 404) for the common case of a non-bug_bounty engagement, so callers
    don't need special-case error handling on their hot path.

    REQ-RATE-004: also returns `max_rps`, so the worker can tighten a
    multi-request tool's own internal rate flag (nuclei/ffuf) to the
    program's cap - the gateway/proxy per-call rate check alone doesn't see
    inside a single tool invocation."""
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(404, "engagement not found")
    empty = {"ident_header_name": None, "ident_header_value": None, "ua_suffix": None, "max_rps": None}
    if eng.source != "bug_bounty":
        return empty
    prog = db.scalar(select(BountyProgram).where(BountyProgram.engagement_id == engagement_id))
    if prog is None:
        return empty
    return {
        "ident_header_name": prog.ident_header_name,
        "ident_header_value": prog.ident_header_value,
        "ua_suffix": prog.ua_suffix,
        "max_rps": float(prog.max_rps),
    }


@router.post("/engagements/{engagement_id}/scan-runs/{scan_run_id}/asset-review", status_code=201)
def create_asset_review(
    engagement_id: uuid.UUID, scan_run_id: uuid.UUID, body: AssetReviewCreateIn, db: Session = Depends(get_db)
):
    """Legt die Review-Pause an und pausiert den Lauf (REQ-ASSETREVIEW-002).
    Ein Review je scan_run (unique) - ein zweiter Aufruf fuer denselben Lauf
    liefert das bestehende Review zurueck (idempotent gegen Worker-Retries)."""
    existing = db.scalar(select(AssetReviewRequest).where(AssetReviewRequest.scan_run_id == scan_run_id))
    if existing is not None:
        return {"id": existing.id, "state": existing.state, "expires_at": existing.expires_at.isoformat()}

    review = AssetReviewRequest(
        engagement_id=engagement_id, scan_run_id=scan_run_id,
        candidate_assets=body.candidate_assets, state="pending",
        expires_at=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15),
    )
    db.add(review)
    run = db.get(ScanRun, scan_run_id)
    if run is not None and run.state == "running":
        run.state = "waiting_approval"
        run.state_reason = "asset_review_pending"
    db.commit()
    db.refresh(review)
    append_audit_log(
        db, engagement_id=engagement_id, actor="worker", action="asset_review_requested",
        decision=None, reason="asset_review_pending",
        payload={"scan_run_id": str(scan_run_id), "candidate_count": len(body.candidate_assets)},
    )
    return {"id": review.id, "state": review.state, "expires_at": review.expires_at.isoformat()}


@router.get("/asset-reviews/{review_id}")
def internal_get_asset_review(review_id: uuid.UUID, db: Session = Depends(get_db)):
    """Der Worker pollt hier den Review-Status (REQ-ASSETREVIEW-006). Laeuft
    die Review ab, wird sie hier lazily auf 'expired' gesetzt (Muster wie
    internal_get_approval)."""
    review = db.get(AssetReviewRequest, review_id)
    if review is None:
        raise HTTPException(404, "asset review not found")
    if review.state == "pending" and review.expires_at < datetime.datetime.now(datetime.timezone.utc):
        review.state = "expired"
        db.commit()
    return {
        "id": str(review.id), "state": review.state,
        "excluded_values": review.excluded_values,
    }


@router.post("/engagements/{engagement_id}/dns-records", status_code=201)
def upsert_dns_record(engagement_id: uuid.UUID, body: DnsRecordIn, db: Session = Depends(get_db)):
    """DNS-Inventar-Metadaten eines in-scope FQDN (CNAME-Kette, Provider,
    Dangling-Status). Reines Metadatum - das hier gespeicherte CNAME-Ziel wird
    NIE zu einem discovered_asset und NIE nach resolved_host materialisiert
    (REQ-DNS-001). Idempotent auf (engagement, fqdn): jeder Lauf frischt auf."""
    fields = body.model_dump()
    existing = db.scalar(
        select(DnsRecord).where(
            DnsRecord.engagement_id == engagement_id, DnsRecord.fqdn == body.fqdn
        )
    )
    if existing is not None:
        for key, value in fields.items():
            setattr(existing, key, value)
        existing.resolved_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()
        return {"id": existing.id}
    record = DnsRecord(engagement_id=engagement_id, **fields)
    db.add(record)
    db.commit()
    db.refresh(record)
    return {"id": record.id}


@router.get("/engagements/{engagement_id}/agent-context")
def agent_context(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    """Kompakte Evidenz je In-Scope-Host (Services + offene Findings) fuer den
    Vector Agent. Er soll auf dem, was die deterministischen Phasen bereits fanden,
    schliessen - nicht im Blindflug raten. Bewusst knapp gehalten (LLM-Kontext).
    """
    assets = db.scalars(
        select(DiscoveredAsset).where(
            DiscoveredAsset.engagement_id == engagement_id, DiscoveredAsset.in_scope.is_(True)
        )
    ).all()
    hosts = []
    for a in assets:
        services = db.scalars(select(Service).where(Service.asset_id == a.id)).all()
        findings = db.scalars(
            select(Finding).where(Finding.asset_id == a.id, Finding.status == "open")
            .order_by(Finding.risk_score.desc().nulls_last())
        ).all()
        hosts.append({
            "host": a.value,
            "http_checked_at": a.http_checked_at.isoformat() if a.http_checked_at else None,
            "http_live": a.http_live,
            "services": [
                {"port": s.port, "protocol": s.protocol, "product": s.product,
                 "tech": (s.tech_stack or {}).get("tech", []) if s.tech_stack else [],
                 "title": (s.tech_stack or {}).get("title", "") if s.tech_stack else "",
                 "status": (s.tech_stack or {}).get("status") if s.tech_stack else None}
                for s in services
            ],
            "findings": [
                {"title": f.title, "severity": f.severity, "category": f.category,
                 "confidence": f.confidence,
                 "cve_ids": list(f.cve_ids) if f.cve_ids else [],
                 "cvss_base": float(f.cvss_base) if f.cvss_base is not None else None,
                 "is_kev": f.is_kev,
                 "risk_score": float(f.risk_score) if f.risk_score is not None else None,
                 "evidence": f.evidence or {}}
                for f in findings
            ],
        })
    # REQ-GRAPH-003: the relationship-native view alongside the flat per-host
    # evidence. Rendered read-only for the agent - no LLM-authored query.
    return {"hosts": hosts, "graph": read_graph(engagement_id, db)}


@router.post("/engagements/{engagement_id}/materialize-graph")
def internal_materialize_graph(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    """Rebuild the attack-surface graph for one engagement (REQ-GRAPH-001).

    The worker triggers this at scan-phase boundaries; the control-plane is the
    sole DB writer, so the builder runs here, not in the worker. Derived metadata
    only - it writes only surface_node/surface_edge and never widens scope
    (REQ-GRAPH-002)."""
    if db.get(Engagement, engagement_id) is None:
        raise HTTPException(404, "engagement not found")
    return materialize_graph(engagement_id, db)


@router.post("/engagements/{engagement_id}/services", status_code=201)
def add_service(engagement_id: uuid.UUID, body: ServiceIn, db: Session = Depends(get_db)):
    """Von der fingerprint-Phase geschriebenes Service-Ergebnis (Kap. 2.4).
    engagement_id nur zur Pfad-Konsistenz mit den Schwester-Endpunkten -
    die eigentliche Bindung laeuft ueber asset_id -> discovered_asset."""
    asset = db.get(DiscoveredAsset, body.asset_id)
    if asset is None or asset.engagement_id != engagement_id:
        raise HTTPException(404, "discovered_asset not found for this engagement")

    fields = body.model_dump()
    # REQ-FPEFF-006: nmap and httpx both report the same port from different
    # angles (nmap the transport/product, httpx the status/title/tech), and an
    # unconditional insert left one asset with several rows for one port -
    # inflating the report's asset inventory and the surface graph. Upsert on
    # the natural key instead, ENRICHING the existing row: a later tool that
    # knows less about a field must not blank what an earlier one established.
    existing = db.scalar(
        select(Service).where(
            Service.asset_id == body.asset_id,
            Service.port == fields.get("port"),
            Service.protocol == fields.get("protocol"),
        ).limit(1)
    )
    if existing is not None:
        for key, value in fields.items():
            if key in ("asset_id", "port", "protocol"):
                continue
            if value in (None, "", {}, []):
                continue
            setattr(existing, key, value)
        db.commit()
        db.refresh(existing)
        return {"id": existing.id}

    service = Service(**fields)
    db.add(service)
    db.commit()
    db.refresh(service)
    return {"id": service.id}


def _fingerprint(asset_value: str, port: int | None, category: str, title: str, cve_ids: list[str] | None) -> str:
    """Kap. 4.4 Listing 9: stabiler Dedup-Fingerprint ueber Tools & Runs hinweg."""
    norm_title = title.strip().lower()
    raw = f"{asset_value}|{port}|{category}|{norm_title}|{','.join(sorted(cve_ids or []))}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _active_run_id(db: Session, engagement_id: uuid.UUID) -> uuid.UUID | None:
    """Der aktuell laufende scan_run dieses Auftrags - waehrend dessen die
    fingerprint-/agent-Phase Findings schreibt. Ohne laufenden Run (z. B.
    manuelle Injektion) wird keine Beobachtung aufgezeichnet."""
    return db.scalar(
        select(ScanRun.id)
        .where(ScanRun.engagement_id == engagement_id, ScanRun.state == "running")
        .order_by(ScanRun.started_at.desc())
        .limit(1)
    )


def _record_observation(db: Session, engagement_id: uuid.UUID, run_id: uuid.UUID | None,
                        fingerprint: str, finding_id: uuid.UUID) -> None:
    """Haelt fest, dass dieser Fingerprint im laufenden scan_run beobachtet wurde
    (Grundlage des Diffs). Idempotent pro (run, fingerprint)."""
    if run_id is None:
        return
    exists = db.get(FindingObservation, {"scan_run_id": run_id, "fingerprint": fingerprint})
    if exists is not None:
        return
    db.add(FindingObservation(scan_run_id=run_id, engagement_id=engagement_id,
                              fingerprint=fingerprint, finding_id=finding_id))
    db.commit()


@router.post("/engagements/{engagement_id}/rescore")
def rescore_open_findings(engagement_id: uuid.UUID, db: Session = Depends(get_db)):
    """Score-Phase (Architektur Kap. 4.1/5.2): EPSS/KEV aendern sich ueber
    Zeit, auch ohne neuen Scan. Rechnet risk_score/severity aller offenen
    Findings mit den aktuell gespeicherten epss/cvss-Werten neu."""
    findings = db.query(Finding).filter(Finding.engagement_id == engagement_id, Finding.status == "open").all()
    updated = 0
    for f in findings:
        risk_score = compute_risk_score(
            epss=float(f.epss) if f.epss is not None else None,
            cvss_base=float(f.cvss_base) if f.cvss_base is not None else None,
            exposure_factor=1.0,
            business_factor=0.5,
            confidence=f.confidence,
        )
        # REQ-AGENT-010: der Score muss zur (erhaltenen) Severity passen - sonst
        # zeigt z. B. ein per severity_override="critical" bestaetigtes, nicht-
        # CVE-basiertes Finding (kein EPSS/CVSS) denselben generischen Score wie
        # jedes andere.
        if f.severity_override in _VALID_SEV:
            risk_score = max(risk_score, risk_score_floor_for_severity(f.severity_override))
        f.risk_score = risk_score
        # REQ-FIDELITY-004: eine explizit gesetzte Severity (Tool-/Agent-
        # Einschaetzung, z. B. eine kritische PII-Exposure) bleibt erhalten -
        # sonst wuerde JEDE Neuberechnung sie stillschweigend auf den generischen
        # risk_score-basierten Wert zuruecksetzen.
        f.severity = f.severity_override or compute_severity(risk_score=risk_score, is_kev=f.is_kev)
        updated += 1
    db.commit()
    return {"rescored": updated}


def _finding_to_update(db: Session, engagement_id: uuid.UUID, fingerprint: str) -> Finding | None:
    """REQ-TRIAGE-002: which existing finding a new observation belongs to.
    An open one first; otherwise a triaged one (false positive / accepted
    risk), so an operator's decision is not undone by a duplicate; otherwise
    a resolved one, which the caller reopens. Newest first within each."""
    candidates = db.scalars(
        select(Finding)
        .where(Finding.engagement_id == engagement_id, Finding.fingerprint == fingerprint)
        .order_by(Finding.first_seen.desc())
    ).all()
    for statuses in (("open",), ("false_positive", "accepted_risk"), ("resolved",)):
        match = next((f for f in candidates if f.status in statuses), None)
        if match is not None:
            return match
    return None


@router.post("/engagements/{engagement_id}/findings", status_code=201)
def add_finding(engagement_id: uuid.UUID, body: FindingIn, db: Session = Depends(get_db)):
    """Berechnet Fingerprint (Dedup, Kap. 4.4) und Risk-Score/Severity (Kap. 5.2/5.3)
    serverseitig - der Worker liefert nur Rohbefunde."""
    asset = db.get(DiscoveredAsset, body.asset_id) if body.asset_id else None
    port = None
    if body.service_id is not None:
        service = db.get(Service, body.service_id)
        port = service.port if service else None

    fp = _fingerprint(asset.value if asset else "unknown", port, body.category, body.title, body.cve_ids)

    existing = _finding_to_update(db, engagement_id, fp)

    risk_score = compute_risk_score(
        epss=body.epss, cvss_base=body.cvss_base, exposure_factor=body.exposure_factor,
        business_factor=body.business_factor, confidence=body.confidence,
    )
    # Tool-gelieferte Severity hat Vorrang (nuclei/testssl bewerten selbst);
    # sonst aus dem Risk-Score (Kap. 5.3).
    if body.severity_override in _VALID_SEV:
        severity = body.severity_override
        # REQ-AGENT-010: der Score selbst muss zur Severity passen - sonst zeigt
        # ein als "critical" eingestuftes, nicht-CVE-basiertes Finding (kein
        # EPSS/CVSS) denselben Score wie jedes andere (37.5 mit den Default-
        # Faktoren), was der angezeigten Severity widerspricht.
        risk_score = max(risk_score, risk_score_floor_for_severity(severity))
    else:
        severity = compute_severity(risk_score=risk_score, is_kev=body.is_kev)

    run_id = _active_run_id(db, engagement_id)

    if existing:
        # PERSIST (Kap. 4.4): gleicher Fund im neuen Run - Werte auffrischen statt duplizieren.
        # Eine bereits gesetzte severity_override bleibt erhalten, wenn DIESE
        # Beobachtung keine mitbringt - eine spaetere, weniger informierte
        # automatische Beobachtung darf eine Agent-/Tool-Einschaetzung nicht
        # stillschweigend zuruecksetzen (REQ-FIDELITY-004).
        if body.severity_override in _VALID_SEV:
            existing.severity_override = body.severity_override
        # REQ-AGENT-010: der Floor muss auf Basis der EFFEKTIVEN (ggf. aus einer
        # frueheren Beobachtung erhaltenen) Override gelten - sonst faellt der
        # Score bei einer spaeteren, override-losen Beobachtung stillschweigend
        # auf den generischen Wert zurueck, waehrend die Severity erhalten bleibt.
        if existing.severity_override in _VALID_SEV:
            risk_score = max(risk_score, risk_score_floor_for_severity(existing.severity_override))
        existing.risk_score = risk_score
        existing.severity = existing.severity_override or severity
        existing.confidence = body.confidence
        existing.evidence = body.evidence
        existing.is_kev = body.is_kev
        # REQ-TRIAGE-002: a false positive or accepted risk keeps its status
        # when seen again; a "resolved" finding seen again is a regression and
        # reopens, recorded in the audit log like an operator's change.
        reopened = existing.status == "resolved"
        if reopened:
            existing.status = "open"
            existing.status_note = "Seen again by a later scan after it was marked resolved."
            existing.status_changed_at = datetime.datetime.now(datetime.timezone.utc)
            existing.status_changed_by = "scan"
        db.commit()
        if reopened:
            append_audit_log(
                db, engagement_id=engagement_id, actor="scan", action="finding_triage", decision="open",
                reason="reopened: observed again after being marked resolved",
                payload={"finding_id": str(existing.id), "title": existing.title, "from": "resolved", "to": "open",
                         "scan_run_id": str(run_id) if run_id else None},
            )
        _record_observation(db, engagement_id, run_id, fp, existing.id)
        return {"id": existing.id, "diff": "reopened" if reopened else "persist"}

    finding = Finding(
        engagement_id=engagement_id,
        asset_id=body.asset_id,
        service_id=body.service_id,
        category=body.category,
        title=body.title,
        cve_ids=body.cve_ids,
        cvss_base=body.cvss_base,
        epss=body.epss,
        confidence=body.confidence,
        status="open",
        evidence=body.evidence,
        raw_ref=body.raw_ref,
        is_kev=body.is_kev,
        severity_override=body.severity_override if body.severity_override in _VALID_SEV else None,
        severity=severity,
        risk_score=risk_score,
        first_seen=datetime.datetime.now(datetime.timezone.utc),
        fingerprint=fp,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    _record_observation(db, engagement_id, run_id, fp, finding.id)
    return {"id": finding.id, "diff": "new"}
