"""Scope Gateway: der einzige Pfad zur Tool-Ausfuehrung (Architektur Kap. 3).

Deterministisch, kein LLM, zustandslos - entscheidet ausschliesslich anhand
von signiertem DB-Zustand und der Eingabe. Jeder Tool-Call durchlaeuft eine
feste Kette; die erste ablehnende Pruefung beendet die Kette (fail-closed).
Keine Pruefung hier beruht auf dem, was das LLM "sagt".
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import fnmatch
import ipaddress
import uuid
from typing import Literal
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.settings_store import get_scan_policy
from app import config_resolver
from app.gateway import args_safety, rate_reservation
from app.gateway.audit import append_audit_log
from app.tools import registry
from app.models.approval import ApprovalRequest
from app.models.engagement import BountyProgram, Engagement, ScopeAsset, ToolApprovalPolicy, ToolGrant
from app.models.scan_run import ScanRun

settings = get_settings()

# Laufzeit-Kategorie-Whitelist (Architektur Kap. 3.2). NICHT mehr hier
# hartkodiert, sondern aus der Capability-Registry abgeleitet - der einzigen
# Quelle der Wahrheit fuer Tool-Metadaten (app/tools/registry.py). Ein neues
# Tool freizuschalten ist damit EINE Aenderung (Registry) statt vier.
WHITELIST: dict[str, set[str]] = registry.enabled_whitelist()

ToolCategory = Literal["recon", "fingerprint", "vuln", "cred", "exploit"]
ScanMode = Literal["passive", "active"]


@dataclasses.dataclass
class ToolCall:
    engagement_id: uuid.UUID
    tool: str
    category: ToolCategory
    mode: ScanMode
    target: str                        # Domain/IP - wird gegen scope_asset aufgeloest
    path: str | None = None
    args: dict = dataclasses.field(default_factory=dict)
    is_automated: bool = True
    phase: str = "scan"                 # 'agent' fuer Vector-Agent-Vorschlaege (Kap. 4.2)
    # Vom Agenten mitgegeben, wenn ein zustandsaendernder Request Freigabe braucht
    # (REQ-APPROVAL-002): warum + LLM-Risikobewertung. Landen im Approval-Payload.
    rationale: str | None = None
    risk: dict | None = None            # {"level": "low|medium|high", "description": str}
    scan_run_id: uuid.UUID | None = None # exact cancellation/budget owner
    # REQ-CIDRDISC-001: target is a CIDR/network, not a single host - matched
    # against an ip/cidr scope asset by subnet containment, not address
    # membership. Never wire-exposed (ToolCallIn has no such field): only
    # raw_egress_lease.py's in-process host-discovery-sweep call ever sets
    # this, so it is unreachable from the worker's HTTP authorize endpoint or
    # any Vector Agent proposal.
    target_is_range: bool = False

    def as_jsonable(self) -> dict:
        d = dataclasses.asdict(self)
        d["engagement_id"] = str(self.engagement_id)
        if self.scan_run_id is not None:
            d["scan_run_id"] = str(self.scan_run_id)
        return d


@dataclasses.dataclass
class Decision:
    allowed: bool
    reason: str
    is_pending: bool = False
    approval_request_id: uuid.UUID | None = None
    is_throttled: bool = False
    retry_after_seconds: float | None = None


def DENY(reason: str) -> Decision:
    return Decision(allowed=False, reason=reason)


def ALLOW(reason: str) -> Decision:
    return Decision(allowed=True, reason=reason)


def THROTTLE(reason: str, retry_after_seconds: float) -> Decision:
    return Decision(allowed=False, reason=reason, is_throttled=True, retry_after_seconds=retry_after_seconds)


def _matches_asset_value(target: str, asset: ScopeAsset, *, target_is_range: bool = False) -> bool:
    if asset.asset_type == "domain":
        host = target.lower().rstrip(".")
        domain = asset.value.lower().rstrip(".")
        return host == domain or host.endswith("." + domain)
    if asset.asset_type == "wildcard":
        return fnmatch.fnmatch(target.lower(), asset.value.lower())
    if asset.asset_type in ("ip", "cidr"):
        try:
            if target_is_range:
                # REQ-CIDRDISC-001: a host-discovery sweep is authorized as ONE
                # call against a whole range, not one call per candidate host -
                # the target network must be contained in (or equal to) the
                # scope asset's network, mirroring the point-containment check
                # below but at network granularity.
                target_net = ipaddress.ip_network(target, strict=False)
                asset_net = ipaddress.ip_network(asset.value, strict=False)
                return target_net.version == asset_net.version and (
                    target_net == asset_net or target_net.subnet_of(asset_net)
                )
            return ipaddress.ip_address(target) in ipaddress.ip_network(asset.value, strict=False)
        except ValueError:
            return False
    if asset.asset_type == "cloud_account":
        return target == asset.value
    return False


def _matches_path(path: str | None, pattern: str | None) -> bool:
    if pattern is None:
        return True
    if path is None:
        return False
    return fnmatch.fnmatch(path, pattern)


def _matching_rules(
    db: Session, engagement_id: uuid.UUID, target: str, path: str | None, rule: str, *, target_is_range: bool = False,
) -> list[ScopeAsset]:
    stmt = select(ScopeAsset).where(ScopeAsset.engagement_id == engagement_id, ScopeAsset.rule == rule)
    return [
        a for a in db.scalars(stmt)
        if _matches_asset_value(target, a, target_is_range=target_is_range) and _matches_path(path, a.path_pattern)
    ]


def _bounty_program_for(db: Session, engagement_id: uuid.UUID) -> BountyProgram | None:
    return db.scalar(select(BountyProgram).where(BountyProgram.engagement_id == engagement_id))


def _tool_grant_for(db: Session, engagement_id: uuid.UUID, category: str, mode: str) -> ToolGrant | None:
    return db.get(ToolGrant, {"engagement_id": engagement_id, "tool_category": category, "mode": mode})


def _tool_requires_manual_approval(db: Session, engagement_id: uuid.UUID, grant: ToolGrant | None, tool: str) -> bool:
    # Freigabepflicht greift nur im aktiven Modus (grant vorhanden). Sie kann aus
    # dem Kategorie-Grant, der globalen Tool-Policy ODER dem Kampagnen-Override
    # kommen - der Resolver buendelt global+Kampagne.
    if grant is None:
        return False
    if grant.requires_manual_approval:
        return True
    return config_resolver.effective_tool_config(db, engagement_id, tool).requires_approval


def _active_scan_run(db: Session, engagement_id: uuid.UUID) -> ScanRun | None:
    """Legacy budget context for non-pipeline gateway checks. Target-touching
    worker calls use their exact run ID via ``_bound_scan_run`` below."""
    return db.scalar(
        select(ScanRun)
        .where(ScanRun.engagement_id == engagement_id, ScanRun.state == "running")
        .order_by(ScanRun.started_at.desc())
        .limit(1)
    )


def _bound_scan_run(db: Session, call: ToolCall) -> tuple[ScanRun | None, Decision | None]:
    """Lock and validate the exact run for pipeline/agent target operations.

    The row lock serializes an authorize-vs-cancel race. Omitting the run ID is
    a denial for these phases, so a stale worker cannot continue by inheriting a
    newer run's authorization/budget context.
    """
    if call.phase not in {"fingerprint", "agent"}:
        return _active_scan_run(db, call.engagement_id), None
    if call.scan_run_id is None:
        return None, DENY("scan_run_required")
    run = db.scalar(
        select(ScanRun).where(ScanRun.id == call.scan_run_id).with_for_update()
    )
    if run is None or run.engagement_id != call.engagement_id:
        return None, DENY("scan_run_not_found")
    if run.cancel_requested:
        return run, DENY("scan_run_cancelled")
    if run.state != "running":
        return run, DENY("scan_run_not_active")
    return run, None


# GitHub issue #19's window formula now lives with the reservation primitive
# (GitHub issue #40); kept under this name for the window tests.
_effective_rate_window = rate_reservation.effective_rate_window


def _create_approval_request(db: Session, call: ToolCall) -> ApprovalRequest:
    # REQ-APPROVAL-005: configurable timeout (campaign override -> global
    # default -> 900s built-in), replacing the previously-hardcoded 15min
    # literal - so a scan is never stuck waiting on an operator who stepped
    # away for longer than the configured window.
    timeout_seconds = config_resolver.effective_approval_timeout_seconds(db, call.engagement_id)
    approval = ApprovalRequest(
        engagement_id=call.engagement_id,
        tool_call=call.as_jsonable(),
        state="requested",
        expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=timeout_seconds),
    )
    db.add(approval)
    db.commit()
    db.refresh(approval)
    return approval


def _log_and_return(db: Session, call: ToolCall, decision: Decision) -> Decision:
    payload = call.as_jsonable()
    if decision.retry_after_seconds is not None:
        payload["retry_after_seconds"] = decision.retry_after_seconds
    audit_decision = "PENDING" if decision.is_pending else ("THROTTLE" if decision.is_throttled else ("ALLOW" if decision.allowed else "DENY"))
    append_audit_log(
        db,
        engagement_id=call.engagement_id,
        actor="gateway",
        action="tool_call",
        decision=audit_decision,
        reason=decision.reason,
        payload=payload,
    )
    return decision


def _claim_matching_approval(db: Session, call: ToolCall, approval_request_id: uuid.UUID) -> Decision | None:
    """Lock and claim exactly one approved call. None means the claim is valid.

    All ordinary gateway checks run before this helper. The row lock makes
    approved -> executing a single-winner transition across workers.
    """
    approval = db.scalar(
        select(ApprovalRequest)
        .where(ApprovalRequest.id == approval_request_id)
        .with_for_update()
    )
    if approval is None or approval.engagement_id != call.engagement_id:
        return DENY("approval_not_found")
    now = dt.datetime.now(dt.timezone.utc)
    if approval.expires_at < now:
        approval.state = "expired"
        approval.execution_finished_at = now
        return DENY("approval_expired")
    if approval.state != "approved":
        return DENY(f"approval_not_claimable:{approval.state}")
    if approval.tool_call != call.as_jsonable():
        return DENY("approval_call_mismatch")
    approval.state = "executing"
    approval.execution_started_at = now
    approval.execution_error = None
    db.add(approval)
    return None


def _extended_discovery_denial(db: Session, eng: Engagement, call: ToolCall, prog: BountyProgram | None) -> Decision | None:
    """REQ-COVER-003/004/006/007: switch checks and per-URL validation for the
    opt-in discovery capabilities. None means no objection."""
    mode = call.args.get("mode") if isinstance(call.args, dict) else None
    if call.tool == "subfinder" and not eng.subfinder_enabled:
        return DENY("subfinder_not_enabled")
    if call.tool == "katana" and not eng.crawling_enabled:
        return DENY("crawling_not_enabled")
    if call.tool == "nuclei" and mode == "endpoints":
        if not eng.crawling_enabled:
            return DENY("crawling_not_enabled")
        # The crawler found these URLs; the target list is untrusted input, so
        # every URL is checked against scope and deny rules like a target.
        for url in args_safety.endpoint_urls(call.args) or []:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower().rstrip(".")
            path = parts.path or "/"
            if parts.username or parts.password:
                return DENY("endpoint_out_of_scope")
            if _matching_rules(db, eng.id, host, path, "deny"):
                return DENY("endpoint_out_of_scope")
            if not _matching_rules(db, eng.id, host, path, "allow"):
                return DENY("endpoint_out_of_scope")
    if call.tool == "nuclei" and mode == "oob" and not eng.oob_enabled:
        return DENY("oob_not_enabled")
    if call.tool == "screenshot":
        if not eng.screenshots_enabled:
            return DENY("screenshots_not_enabled")
        # A browser cannot be made to carry the program's identification
        # header on every sub-request through a CONNECT tunnel, so it is not
        # used where the program requires identification (REQ-COVER-006).
        if prog is not None and (prog.ident_header_value or prog.ua_suffix):
            return DENY("screenshots_not_permitted_for_bounty")
    return None


def authorize(db: Session, call: ToolCall, *, approved_request_id: uuid.UUID | None = None) -> Decision:
    eng = db.get(Engagement, call.engagement_id)
    if eng is None:
        return DENY("engagement_not_found")

    # 1. Auftragsstatus & Zeitfenster
    if eng.status != "active":
        return _log_and_return(db, call, DENY("engagement_not_active"))
    now = dt.datetime.now(dt.timezone.utc)
    if not (eng.authorized_from <= now <= eng.authorized_until):
        return _log_and_return(db, call, DENY("outside_time_window"))

    # 1b. Autonome KI-Aktionen (Vector Agent) sind opt-in - fuer JEDE source, nicht
    #     nur bug_bounty. phase='agent' markiert einen vom LLM vorgeschlagenen
    #     Call; ohne ai_testing_allowed am Auftrag ist der Vector Agent nicht
    #     scharfgeschaltet (fail-closed). Der bug_bounty-Zusatzcheck weiter
    #     unten (Programm-Policy) bleibt bestehen (beides muss zutreffen).
    if call.phase == "agent" and not eng.ai_testing_allowed:
        return _log_and_return(db, call, DENY("ai_testing_not_enabled"))

    # 1a. Bind every target-touching pipeline/agent action to the exact run.
    # Cancellation and authorization lock the same row, closing their race.
    run, run_error = _bound_scan_run(db, call)
    if run_error is not None:
        return _log_and_return(db, call, run_error)

    # 1c. REQ-CIDRDISC-001: a range-shaped target is a categorically different,
    # higher-blast-radius kind of call (one authorization covers a whole
    # network, not one host) - restricted, defense-in-depth, to exactly the
    # deterministic host-discovery sweep. Not itself the security boundary
    # (target_is_range is unreachable from any wire input to begin with, see
    # ToolCall's docstring), but this codebase's established pattern for a
    # call shape that must never widen to another tool (cf. the hardcoded
    # activemq-openwire-probe state-changing check below).
    if call.target_is_range and not (call.tool == "nmap" and call.category == "fingerprint" and call.mode == "active"):
        return _log_and_return(db, call, DENY("target_is_range_not_permitted_for_tool"))

    # 2. Scope: deny hat IMMER Vorrang vor allow (Wildcard + Pfad beachtet)
    if _matching_rules(db, eng.id, call.target, call.path, "deny", target_is_range=call.target_is_range):
        return _log_and_return(db, call, DENY("explicit_out_of_scope"))
    allow_matches = _matching_rules(db, eng.id, call.target, call.path, "allow", target_is_range=call.target_is_range)
    if not allow_matches:
        return _log_and_return(db, call, DENY("target_out_of_scope"))
    asset = allow_matches[0]

    # 3. Quellen-spezifische Regeln (bug_bounty)
    prog = None
    if eng.source == "bug_bounty":
        prog = _bounty_program_for(db, eng.id)
        if prog is None:
            return _log_and_return(db, call, DENY("bounty_program_missing"))
        if call.is_automated and not prog.automation_allowed:
            return _log_and_return(db, call, DENY("automation_forbidden"))
        if call.phase == "agent" and not prog.ai_testing_allowed:
            return _log_and_return(db, call, DENY("ai_testing_forbidden"))

    # 4. Modus-Pruefung. Passive ist kein Freifahrtschein: nur echte
    #    passive/OSINT-Tools duerfen passive laufen, und auch dafuer muss der
    #    Auftrag einen expliziten passiven Category-Grant haben.
    grant = None
    if call.mode == "passive":
        grant = _tool_grant_for(db, eng.id, call.category, "passive")
        if grant is None:
            return _log_and_return(db, call, DENY("no_tool_grant"))
    elif call.mode == "active":
        if not asset.active_allowed:
            return _log_and_return(db, call, DENY("active_not_allowed"))
        grant = _tool_grant_for(db, eng.id, call.category, "active")
        if grant is None:
            return _log_and_return(db, call, DENY("no_tool_grant"))

    # 5. Tool-Whitelist (Kategorie + konkretes Tool + Argumente) - Quelle: Registry
    if call.tool not in WHITELIST.get(call.category, set()):
        return _log_and_return(db, call, DENY("tool_not_whitelisted"))
    tool_spec = registry.get(call.tool)
    if call.mode == "passive" and (tool_spec is None or tool_spec.execution_class != "passive"):
        return _log_and_return(db, call, DENY("passive_not_supported"))
    # REQ-COVER-007: pipeline-only tools (katana, screenshot, subfinder) are
    # never callable from an agent proposal, whatever the switches say.
    if call.phase == "agent" and tool_spec is not None and not tool_spec.agent_callable:
        return _log_and_return(db, call, DENY("tool_not_agent_callable"))
    if not registry.validate_args(call.tool, call.args):
        return _log_and_return(db, call, DENY("unsafe_arguments"))

    # 5b. Effektive Tool-Policy (global + Kampagne): ist dieses Tool fuer DIESE
    #     Kampagne aktiviert? Der Registry-Boden gilt weiter (nicht installierte
    #     Tools sind ohnehin nie enabled) - Konfiguration kann nur INNERHALB des
    #     Bodens ab-/zuschalten, nie den envelope/Scope aufweichen.
    if not config_resolver.effective_tool_config(db, eng.id, call.tool).enabled:
        return _log_and_return(db, call, DENY("tool_disabled"))

    # 5c. REQ-COVER-007: per-engagement switches for the extended discovery
    #     capabilities. They can only narrow what the steps above allow.
    switch_denial = _extended_discovery_denial(db, eng, call, prog)
    if switch_denial is not None:
        return _log_and_return(db, call, switch_denial)

    # 6. Rate-Limit / Blast-Radius (bei bug_bounty aus Programm-Policy).
    # If auto-throttle is enabled, the gateway returns a wait/retry decision
    # instead of a hard denial. The worker must re-authorize after waiting.
    # GitHub issue #40: reserve the slot now, atomically, instead of counting
    # earlier ALLOW audit rows and hoping no concurrent call does the same. A
    # call that does not go ahead after all (budget, approval) gives the slot
    # back before this transaction commits.
    scan_policy = get_scan_policy(db)
    limit = float(prog.max_rps) if prog else scan_policy.max_rps
    reservation = rate_reservation.reserve(db, eng.id, "gateway", limit)
    if not reservation.allowed:
        if scan_policy.auto_throttle_enabled:
            return _log_and_return(db, call, THROTTLE("rate_limited_wait", reservation.retry_after_seconds))
        return _log_and_return(db, call, DENY("rate_limited"))

    # GitHub issue #32: a dedicated step 7 used to re-deny here whenever a
    # bug_bounty engagement had no configured ident_header_value - but step 3
    # above already denies (bounty_program_missing) whenever prog is None
    # for a bug_bounty engagement, and REQ-AUTH-006's 2026-08-12 amendment
    # made the header itself optional once a program row exists. That made
    # this step's own condition unreachable (prog is guaranteed non-None by
    # the time execution gets here) - removed rather than left as dead code.
    # Header injection, when configured, happens in the egress-proxy/worker
    # (egress-proxy/app/proxy.py, worker/app/tool_runner_client.py).

    # 7. Budget / Blast-Radius pro scan_run. Der harte Deckel gegen einen
    #    entgleisten Vector Agent (Endlosschleife/Kosten) - durchgesetzt HIER, an
    #    der einzigen Entscheidungsstelle, nicht in einem separaten Endpoint,
    #    den niemand ruft. Gezaehlt werden nur tatsaechlich freigegebene Calls
    #    (die dispatcht werden); abgelehnte Vorschlaege verbrauchen kein Budget.
    if run is not None and run.budget_tool_calls_used >= run.budget_tool_calls_max:
        rate_reservation.release(db, reservation)
        return _log_and_return(db, call, DENY("budget_exhausted"))

    # 8. Human-in-the-loop. A resumed approval does not bypass this block: it
    #    must match the exact stored call and atomically claim approved ->
    #    executing after every current gateway check has passed.
    # REQ-AGENT-027: activemq-openwire-probe is unconditionally state-changing
    # - unlike http_request, there is no "read-only method" case for it, it
    # always attempts to trigger a real deserialization RCE code path. Kept
    # in this same hardcoded check (not a configurable ToolGrant.requires_
    # manual_approval) so approval can never be disabled by configuration for
    # this specific tool, matching http_request's own treatment.
    state_changing = (
        (call.tool == "http_request" and args_safety.http_request_is_state_changing(call.args))
        or call.tool == "activemq-openwire-probe"
    )
    requires_approval = state_changing or _tool_requires_manual_approval(db, eng.id, grant, call.tool)
    if state_changing and not (call.risk and str(call.risk.get("description") or "").strip()):
        rate_reservation.release(db, reservation)
        return _log_and_return(db, call, DENY("risk_statement_required"))
    if approved_request_id is not None:
        # A policy change that removes the approval requirement must not turn an
        # already issued approval into an unclaimed reusable dispatch token.
        claim_error = _claim_matching_approval(db, call, approved_request_id)
        if claim_error is not None:
            rate_reservation.release(db, reservation)
            return _log_and_return(db, call, claim_error)
    elif requires_approval:
        # The call only runs once approved; it reserves a slot again then.
        rate_reservation.release(db, reservation)
        approval = _create_approval_request(db, call)
        return _log_and_return(
            db, call, Decision(allowed=False, reason="pending_approval", is_pending=True,
                               approval_request_id=approval.id)
        )

    # Freigabe steht fest -> Budget verbrauchen (der Call wird dispatcht).
    if run is not None:
        run.budget_tool_calls_used += 1
        db.add(run)
        db.flush()
    return _log_and_return(db, call, ALLOW("all_checks_passed"))
