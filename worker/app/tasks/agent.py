"""Phase 4 - Vector Agent, Reason-Act-Observe (Architektur Kap. 4.2, Listing 8).

Kritische Trennung (Spezifikation Kap. 3.4): der Agent schlaegt NUR vor. Jeder
Vorschlag geht durch client.authorize() -> Scope Gateway, NIE direkte
Ausfuehrung durchs Modell. Der Agent waehlt WELCHES Tool auf WELCHES (in-scope)
Ziel - er formuliert keine rohen Flags (geschlossener Args-Round-Trip); die
konservative Invocation liegt fest im tool-runner-Body-Builder.

Drei unabhaengige Sicherungen begrenzen den Agenten:
  1. Scope Gateway (deterministisch): out-of-scope, kein Grant, unsafe args ->
     DENY, unabhaengig davon was das LLM 'sagt' oder wie ein Ziel injiziert wird.
  2. ai_testing_allowed am Auftrag: phase='agent' ist ohne Opt-in gar nicht
     scharf (fail-closed, jede source).
  3. Budget: iteration_budget hier + budget_tool_calls_max im Gateway (harter
     Deckel gegen Endlosschleifen/Kosten). budget_exhausted -> der Agent sieht
     ein DENY und beendet.

Der Provider ist ein OpenAI-KOMPATIBLES Interface (base_url + api_key + model):
OpenAI selbst, Eden AI, ein lokaler Gateway o. Ae. Die Konfig kommt zur
Laufzeit von der control-plane (GET /internal/llm-config), die app_setting
(via GUI gesetzt) ueber die Env-Defaults (LLM_BASE_URL/LLM_API_KEY/LLM_MODEL)
legt. Env dient als Fallback, falls die control-plane nicht erreichbar ist.

Ist kein Provider konfiguriert (oder das openai-SDK fehlt), laeuft die Phase
als No-Op durch, damit die Pipeline auch ohne LLM gruen bleibt (die
deterministischen Phasen haben dann bereits alle Befunde geliefert).
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from app import session_state
from app.cancel_probe import CancelProbe
from app.control_plane_client import client
from app.target_envelope import single_port_from_envelope
from app.tasks import dispatch

logger = logging.getLogger(__name__)

# REQ-AGENT-026: fallback only. The effective value comes from the control
# plane (campaign override -> global setting -> built-in 8192) and is resolved
# per run; this env var is what remains if that lookup fails. The clamp bounds
# are the same on both sides so neither path can produce an out-of-range cap.
AGENT_MIN_MAX_TOKENS, AGENT_MAX_MAX_TOKENS = 1024, 32768
AGENT_MAX_TOKENS = max(
    AGENT_MIN_MAX_TOKENS, min(int(os.environ.get("ASM_AGENT_MAX_TOKENS", "8192")), AGENT_MAX_MAX_TOKENS)
)
AGENT_LENGTH_RETRIES = max(0, min(int(os.environ.get("ASM_AGENT_LENGTH_RETRIES", "2")), 3))
AGENT_RETRY_MAX_TOKENS = max(
    AGENT_MAX_TOKENS, min(int(os.environ.get("ASM_AGENT_RETRY_MAX_TOKENS", "8192")), 65536)
)
# The openai SDK's own default (max_retries=2, ~3 total attempts spanning
# under 2s of backoff) is too impatient for a brief upstream provider blip -
# found live: 3 quick attempts each hit a transient 502 from the LLM gateway,
# and the agent phase gave up and ended early (no report, no new findings)
# even though the identical provider had already answered 6 prior calls
# successfully in the same run and would very likely have recovered within a
# few more seconds. This does not change the fail-closed design (a
# genuinely-unavailable provider still ends the phase cleanly, see the
# except block below) - it only raises the bar for "genuinely unavailable".
AGENT_LLM_MAX_RETRIES = max(0, min(int(os.environ.get("ASM_AGENT_LLM_MAX_RETRIES", "5")), 10))

# Die fertigen Scanner (run_check). http_request hat sein eigenes Werkzeug mit
# Methode/Pfad/Header und ist hier bewusst NICHT enthalten.
ALLOWED_TOOLS = sorted(t for t in dispatch.TOOL_CATEGORY if t not in {"http_request", "nmap"})

# REQ-AGENT-021. Only `direct_technical_proof` maps to confidence="validated";
# the other two (and anything unrecognised) map to "inferred" and forfeit the
# agent's self-assigned severity. Kept as a module constant so the tool schema
# and the handler's fail-closed check cannot drift apart.
_EVIDENCE_BASES = frozenset({"direct_technical_proof", "tool_signal", "contextual_inference"})

# REQ-BENCH-011: MITRE's own uppercase convention. Normalizing to uppercase
# here - not just validating the shape - keeps every downstream consumer
# (correlation lookups, benchmark ground-truth matching) on one consistent
# case, rather than each one needing to case-fold independently.
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _audit_agent_event(engagement_id: str, event: str, *, decision: str | None = None, reason: str | None = None, **payload) -> None:
    try:
        client.agent_event(uuid.UUID(engagement_id), event=event, decision=decision, reason=reason, payload=payload)
    except Exception as exc:  # noqa: BLE001 - telemetry must never break a scan
        logger.warning("agent telemetry failed for %s: %s", event, exc)


def _normalize_chat_base_url(base_url: str) -> tuple[str, str | None]:
    normalized = base_url.strip().rstrip("/")
    if normalized.endswith("/chat/completions"):
        return normalized[: -len("/chat/completions")], "removed_chat_completions_suffix"
    if normalized.endswith("/responses"):
        return normalized[: -len("/responses")], "removed_responses_suffix"
    return normalized, None


def _safe_error(exc: Exception) -> str:
    text = str(exc)
    return text[:500]


def _safe_url(value: str) -> str:
    if not value:
        return value
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "<invalid-url>"
    netloc = parsed.hostname or ""
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def _resolve_provider() -> tuple[str, str, str]:
    """(base_url, api_key, model) - control-plane (DB ueber Env) mit Env-Fallback."""
    try:
        cfg = client.get_llm_config()
        if cfg.get("is_usable"):
            return cfg["base_url"], cfg["api_key"], cfg["model"]
        logger.info("agent phase: LLM provider not fully configured (source=%s)", cfg.get("source"))
    except Exception as exc:  # noqa: BLE001 - Fallback auf lokale Env
        logger.warning("agent: LLM config not loadable from the control plane (%s) - using the environment fallback", exc)
    return (
        os.environ.get("LLM_BASE_URL", ""),
        os.environ.get("LLM_API_KEY", ""),
        os.environ.get("LLM_MODEL", ""),
    )

# Nur ein Notfall-Fallback, falls die control-plane nicht erreichbar ist
# (client.get_agent_config() wirft) - der echte, ausfuehrliche Default-Prompt
# lebt in control-plane/app/default_prompts.py (REQ-AGENT-011/012), einsehbar
# und editierbar ueber die Settings-GUI. In diesem Fall ist ohnehin auch
# authorize()/dispatch() betroffen (beide brauchen die control-plane), daher
# reicht ein knapper, sicherer Fallback statt einer zweiten, driftenden Kopie.
_SYSTEM_PROMPT = """\
You are a security testing agent for an Attack Surface Management platform,
operating within an authorized engagement. Propose one check at a time via
run_check/http_request/content_discovery; an independent Scope Gateway
authorizes every action. Scope is absolute (only the given in-scope hosts),
minimize impact, and when you report_finding you MUST set evidence_basis
honestly: direct_technical_proof only when an observation in this run
demonstrated the weakness itself, otherwise tool_signal or
contextual_inference. A labelled inference is useful; an inference dressed up
as proof is not. Never report a non-finding (unreachable service, no live
HTTP). The full campaign instructions could not be loaded from the control
plane, so work conservatively and call finish once you have covered the
in-scope hosts."""

# OpenAI-kompatibles function-calling-Format (tools[].function). Funktioniert
# gegen OpenAI, Eden AI und jeden kompatiblen Gateway.
_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_check",
            "description": (
                "Requests ONE security check against an in-scope host. The proposal "
                "goes through the Scope Gateway; the result (or DENIED/REJECTED) "
                "comes back as an observation. Most tools here run "
                "autonomously. activemq-openwire-probe is the one exception: it sends a "
                "crafted packet that deliberately triggers OpenWire deserialization RCE "
                "(CVE-2023-46604) and requires the target to fetch a URL we host - it is "
                "NOT autonomous. You MUST also provide risk_level and risk (an honest "
                "assessment - state plainly that this attempts to trigger the target's "
                "deserialization code path) or the request is refused."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "tool": {"type": "string", "enum": ALLOWED_TOOLS},
                    "target": {"type": "string", "description": "Hostname from the in-scope list"},
                    "rationale": {"type": "string", "description": "Short reason why this check, now"},
                    "risk_level": {
                        "type": "string", "enum": ["low", "medium", "high"],
                        "description": "Required for activemq-openwire-probe; ignored by autonomous tools.",
                    },
                    "risk": {
                        "type": "string",
                        "description": "Required for activemq-openwire-probe: honest description of what this does and what could go wrong.",
                    },
                },
                "required": ["tool", "target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": (
                "Send ONE crafted HTTP request (curl) to an in-scope host and get the FULL response "
                "back. Your primary manual tool: enumerate auth headers, probe endpoints, test "
                "access-control/authorization bypasses, judge exposed data. "
                "READ methods (GET/HEAD/OPTIONS) run AUTONOMOUSLY. "
                "STATE-CHANGING methods (POST/PUT/DELETE/PATCH) or any request with a body are NOT "
                "autonomous: they require operator approval. When you propose one, you MUST also "
                "provide risk_level and risk (an honest assessment of what the request does and what "
                "could go wrong) — without it the request is refused. Use writes only when they "
                "materially prove a finding (e.g. submit a login form to confirm an open redirect); "
                "prefer the least invasive proof. Scope is always enforced by the gateway."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Hostname from the in-scope list"},
                    "method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE", "PATCH"]},
                    "path": {"type": "string", "description": "Request path incl. query, e.g. /api/users?id=1"},
                    "headers": {
                        "type": "object",
                        "description": "Optional request headers to set (e.g. an auth/bypass header you want to try).",
                        "additionalProperties": {"type": "string"},
                    },
                    "body": {"type": "string", "description": "Optional request body (for write methods, e.g. form or JSON payload)"},
                    "rationale": {"type": "string", "description": "What you expect to learn and why it matters"},
                    "risk_level": {"type": "string", "enum": ["low", "medium", "high"], "description": "Required for state-changing requests"},
                    "risk": {"type": "string", "description": "Required for state-changing requests: what it does and what could go wrong"},
                    "identity": {
                        "type": "string",
                        "enum": ["primary", "secondary"],
                        "description": (
                            "Which session to send. 'primary' (default) is your normal session. "
                            "'secondary' is a second test identity (from register_test_identity, or "
                            "operator-supplied second-identity credentials if configured) - use it to "
                            "test whether identity B can access identity A's objects (BOLA/IDOR)."
                        ),
                    },
                },
                "required": ["target", "method", "path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "register_test_identity",
            "description": (
                "Self-register a SECOND, SYNTHETIC test account on an in-scope host that visibly "
                "offers open signup, so you can prove BOLA/IDOR by comparing what this identity can "
                "access versus your primary identity - not just guessing at an ID change. Only use "
                "this when the target actually exposes a public registration endpoint you found; "
                "never invent one. The payload MUST be synthetic: a randomly-suffixed username/email, "
                "never anything resembling a real person or your primary identity's own credentials. "
                "This is a state-changing request like any write: it requires operator approval and an "
                "honest risk statement. On success the resulting session is captured as your "
                "'secondary' identity - pass identity: \"secondary\" on later http_request calls to act "
                "as it."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Hostname from the in-scope list"},
                    "method": {"type": "string", "enum": ["POST", "PUT"]},
                    "path": {"type": "string", "description": "Registration endpoint path, e.g. /api/v1/users"},
                    "headers": {
                        "type": "object",
                        "description": "Optional request headers to set.",
                        "additionalProperties": {"type": "string"},
                    },
                    "body": {"type": "string", "description": "Registration payload (form or JSON) with SYNTHETIC values only"},
                    "rationale": {"type": "string", "description": "What you expect to learn and why it matters"},
                    "risk_level": {"type": "string", "enum": ["low", "medium", "high"]},
                    "risk": {"type": "string", "description": "What it does and what could go wrong"},
                },
                "required": ["target", "path", "body", "rationale"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_finding",
            "description": (
                "Record a finding you concluded from the evidence (e.g. an unauthenticated PII "
                "exposure you confirmed via http_request). State honestly, via evidence_basis, "
                "what your conclusion actually rests on - a labelled inference is useful and "
                "welcome; an inference presented as proof is not. Do not invent findings, and do "
                "not report non-findings (a service being unreachable, or no live HTTP on a port, "
                "is not a finding)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "In-scope host the finding is on"},
                    "title": {"type": "string", "description": "Concise finding title"},
                    "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                    "category": {"type": "string", "enum": ["cve", "misconfig", "exposure", "logic"]},
                    "rationale": {"type": "string", "description": "The evidence and impact, briefly"},
                    # REQ-AGENT-021: the model MUST be able to say "this is inference".
                    # Without this it could only ever assert certainty, and every
                    # agent finding was persisted as confidence="validated".
                    "evidence_basis": {
                        "type": "string",
                        "enum": ["direct_technical_proof", "tool_signal", "contextual_inference"],
                        "description": (
                            "What this conclusion actually rests on. "
                            "direct_technical_proof: an observation in THIS run demonstrates the "
                            "weakness itself (e.g. you requested the endpoint unauthenticated and "
                            "the response body contained the protected data; your payload was "
                            "reflected unescaped). "
                            "tool_signal: a tool asserted it (nuclei template match, testssl check) "
                            "and you are relaying that. "
                            "contextual_inference: reasoned from a version banner, product name, "
                            "naming, or context WITHOUT an observation that demonstrates it. "
                            "If you did not see it happen in an observation, it is not "
                            "direct_technical_proof."
                        ),
                    },
                    "cve_id": {
                        "type": "string",
                        "description": (
                            "Optional: the exact CVE ID (e.g. CVE-2022-22965) this finding demonstrates, "
                            "if you actually demonstrated the CVE itself - not a version banner you "
                            "recognized. Only honored when evidence_basis is direct_technical_proof; "
                            "supplying it otherwise has no effect, so never guess one in to look more certain."
                        ),
                    },
                },
                "required": ["target", "title", "severity", "category", "evidence_basis"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "content_discovery",
            "description": (
                "Curated content/endpoint discovery on an in-scope host via ffuf. YOU choose the "
                "wordlist that fits the target context (from the fingerprint evidence) and optionally "
                "add a few reasoned, target-specific candidates; ffuf does the volume, rate-limited "
                "and non-destructive, through the scope-enforcing proxy. Use it to find hidden "
                "endpoints, admin panels, backups, config/exposed files, or to enumerate an ID range. "
                "The path must contain the literal placeholder FUZZ (e.g. /FUZZ, /api/FUZZ, /users/FUZZ). "
                "The pipeline already ran a quickhits baseline (see 'Pipeline checks already run'); the call "
                "is capped at about four minutes, so a large wordlist only reaches its first few thousand "
                "entries - prefer a deeper path, reasoned extra_candidates or a small list."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Hostname from the in-scope list"},
                    "wordlist": {
                        "type": "string",
                        "enum": ["common", "raft-medium-dirs", "raft-medium-files", "quickhits", "directory-list-medium"],
                        "description": "Curated SecLists wordlist that best fits the target",
                    },
                    "path": {"type": "string", "description": "Path containing FUZZ, e.g. /FUZZ or /api/FUZZ"},
                    "extensions": {
                        "type": "array", "items": {"type": "string"},
                        "description": "Optional extensions to append, e.g. [php, bak, json]",
                    },
                    "extra_candidates": {
                        "type": "array", "items": {"type": "string"},
                        "description": "Optional small list of your own reasoned candidates (used instead of the wordlist)",
                    },
                    "rationale": {"type": "string"},
                },
                "required": ["target", "path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": "End the investigation when no useful check is left.",
            "parameters": {
                "type": "object",
                "properties": {"summary": {"type": "string"}},
                "required": ["summary"],
            },
        },
    },
]


@dataclass
class SimpleContext:
    """Beobachtungs-/Ablehnungs-Protokoll des Laufs (auch fuer Tests nutzbar)."""

    exhausted: bool = False
    iterations: int = 0
    observations: list[dict] = field(default_factory=list)
    denied: list[dict] = field(default_factory=list)
    reported: list[dict] = field(default_factory=list)
    conclusion: str | None = None
    incomplete_reason: str | None = None
    scan_run_id: str | None = None      # fuer waiting_approval + Cancel-Checks in Handlern
    # REQ-FIDELITY-007: einmal pro Lauf aufgeloestes Engagement-Portfenster, damit
    # jeder Agent-Tool-Vorschlag denselben Port trifft wie die Fingerprint-Phase
    # (REQ-FIDELITY-003) statt stumpf auf 443 zu landen und geblockt zu werden.
    single_port: int | None = None
    # REQ-FIDELITY-009: host(lower) -> der von der Fingerprint-Phase per httpx
    # BESTAETIGTE Scheme ("http"/"https"). Ohne ihn zielt jedes agent-getriebene
    # Tool blind auf https:// und liefert gegen einen reinen HTTP-Dienst still
    # gar nichts. Leer => unveraendertes https-Default.
    protocol_by_host: dict[str, str] = field(default_factory=dict)
    # REQ-AGENT-022/023: host(lower) -> identity("primary"/"secondary") ->
    # {cookie name: value}, observed from Set-Cookie during THIS run and
    # replayed only to the same host AND the same identity. Lives and dies
    # with this context object - never persisted, never shared across runs or
    # engagements. See app/session_state.py for the full rationale. The
    # "secondary" slot exists so BOLA/IDOR can be PROVEN by comparing what a
    # second, independent identity can access - not just guessed at.
    cookies_by_host: dict[str, dict[str, dict[str, str]]] = field(default_factory=dict)
    # REQ-APPROVAL-005: der Worker-Poll-Deckel in _await_approval MUSS zur
    # control-plane-seitig durchgesetzten expires_at passen (sonst koennte der
    # Worker lokal aufgeben, waehrend die Freigabe dort noch glaeufig ist).
    approval_timeout_seconds: int = 900

    def observe(self, proposal: dict, result: str) -> None:
        self.observations.append({"proposal": proposal, "result": result})

    def record_denied(self, proposal: dict, reason: str) -> None:
        self.denied.append({"proposal": proposal, "reason": reason})


def _load_scope(engagement_id: str, scan_run_id: str | None = None) -> tuple[dict[str, str], dict[str, str]]:
    """(target_lower -> asset_id, target_lower -> materialisierte IP)."""
    asset_by_host: dict[str, str] = {}
    try:
        for a in client.list_discovered_assets(uuid.UUID(engagement_id), in_scope=True):
            asset_by_host[a["value"].lower()] = str(a["id"])
    except Exception as exc:  # noqa: BLE001
        logger.warning("agent: in-scope assets not loadable: %s", exc)

    ip_by_host: dict[str, str] = {}
    try:
        for r in client.materialize_dns(uuid.UUID(engagement_id), scan_run_id=scan_run_id).get("resolved", []):
            ip_by_host.setdefault(r["hostname"].lower(), r["ip_address"])
    except Exception as exc:  # noqa: BLE001
        logger.warning("agent: DNS materialization failed: %s", exc)
    return asset_by_host, ip_by_host


def _authorize_throttled(engagement_id: str, payload: dict, proposal: dict, context: SimpleContext) -> dict:
    """Ruft das Scope Gateway und behandelt Auto-Throttle (warten & erneut
    anfragen) transparent. Gibt die finale Entscheidung zurueck. Throttle ist
    KEIN Bypass - ausgefuehrt wird erst nach einem echten ALLOW."""
    decision: dict = {}
    for _ in range(8):
        decision = client.authorize(uuid.UUID(engagement_id), payload)
        if decision.get("allowed") or not decision.get("is_throttled"):
            break
        delay = min(max(float(decision.get("retry_after_seconds") or 1.0), 0.1), 5.0)
        _audit_agent_event(engagement_id, "proposal_throttled", scan_run_id=context.scan_run_id, decision="THROTTLE",
                           reason="rate_limited_wait", proposal=proposal, retry_after_seconds=delay)
        time.sleep(delay)
    return decision


def _handle_run_check(
    engagement_id: str, tool_input: dict, asset_by_host: dict[str, str], ip_by_host: dict[str, str],
    context: SimpleContext,
) -> str:
    """Autorisiert einen Agent-Vorschlag und fuehrt ihn bei Freigabe aus.
    Liefert die Beobachtung als Text zurueck (fuer das LLM)."""
    tool = str(tool_input.get("tool", "")).strip()
    target = str(tool_input.get("target", "")).strip()
    proposal = {"tool": tool, "target": target}

    # Leerer/kaputter Vorschlag (REQ-TOOL-005): sauber ueberspringen, kein
    # verwirrendes Scope-Reject, keine Wiederholung provozieren.
    if not tool or not target:
        _audit_agent_event(engagement_id, "proposal_skipped", scan_run_id=context.scan_run_id, decision=None, reason="empty_proposal", proposal=proposal)
        return "SKIPPED: empty tool or target. Pick an enabled tool and an in-scope host from the lists above."
    if tool not in dispatch.TOOL_CATEGORY:
        context.record_denied(proposal, "unknown_tool")
        _audit_agent_event(engagement_id, "proposal_rejected", scan_run_id=context.scan_run_id, decision="DENY", reason="unknown_tool", proposal=proposal)
        return (f"REJECTED: {tool!r} is not runnable in this campaign. Only propose tools from the "
                f"ENABLED list. Do not propose this tool again.")
    if tool == "nmap":
        context.record_denied(proposal, "deterministic_full_scan_only")
        _audit_agent_event(engagement_id, "proposal_skipped", scan_run_id=context.scan_run_id, decision=None,
                           reason="deterministic_full_scan_only", proposal=proposal)
        return "UNAVAILABLE: Nmap TCP/UDP discovery is engagement-configured and pipeline-owned; the agent cannot repeat or widen it."
    host = target.lower()
    asset_id = asset_by_host.get(host)
    if asset_id is None:
        context.record_denied(proposal, "not_in_scope_list")
        _audit_agent_event(engagement_id, "proposal_rejected", scan_run_id=context.scan_run_id, decision="DENY", reason="not_in_scope_list", proposal=proposal)
        return f"REJECTED: {target!r} is not in the in-scope list. Choose a listed target."

    decision_payload = {
        "tool": tool, "category": dispatch.TOOL_CATEGORY[tool], "mode": "active",
        "target": target, "args": {}, "is_automated": True, "phase": "agent",
        "scan_run_id": context.scan_run_id,
        "rationale": str(tool_input.get("rationale", "")),
    }
    # REQ-AGENT-027: some run_check tools (activemq-openwire-probe) are
    # mandatorily state-changing (authorize.py) and therefore require a risk
    # statement, exactly like http_request's own POST/PUT - the model must
    # supply one or the gateway denies with risk_statement_required. Tools
    # that are NOT state-changing (redis-probe, activemq-banner) never reach
    # that check, so passing this through unconditionally is harmless for them.
    risk_description = str(tool_input.get("risk", "") or "").strip()
    if risk_description:
        decision_payload["risk"] = {"level": str(tool_input.get("risk_level", "") or "medium"), "description": risk_description}
    decision = _authorize_throttled(engagement_id, decision_payload, proposal, context)
    if decision.get("is_pending"):
        # REQ-APPROVAL-006: this used to record "pending_approval" and move on
        # without ever waiting - the ApprovalRequest row existed, the operator
        # saw a popup, but nothing ever consumed an "approved" decision, so
        # approving or rejecting had the identical effect (the tool never
        # ran). Now waits exactly like _handle_http_request/
        # _handle_register_test_identity, generalized to the actual tool.
        return _await_approval(engagement_id, decision.get("approval_request_id"), asset_id, target,
                               {}, ip_by_host.get(host), proposal, context, tool=tool)
    if not decision.get("allowed"):
        reason = decision.get("reason", "denied")
        context.record_denied(proposal, reason)
        _audit_agent_event(engagement_id, "proposal_denied", scan_run_id=context.scan_run_id, decision="DENY", reason=reason, proposal=proposal)
        return f"DENIED by the Scope Gateway: {reason}."

    _audit_agent_event(engagement_id, "proposal_allowed", scan_run_id=context.scan_run_id, decision="ALLOW", reason="gateway_allowed", proposal=proposal)
    obs = dispatch.dispatch(engagement_id, asset_id, tool, target, ip_by_host.get(host), scan_run_id=context.scan_run_id, single_port=context.single_port,
                            confirmed_protocol=context.protocol_by_host.get(host.lower()))
    context.observe(proposal, obs.as_text())
    _audit_agent_event(engagement_id, "observation", scan_run_id=context.scan_run_id, decision="ALLOW", reason="tool_observed", proposal=proposal, observation=obs.as_text(), services=obs.services, findings=obs.findings)
    return obs.as_text()


def _handle_http_request(
    engagement_id: str, tool_input: dict, asset_by_host: dict[str, str], ip_by_host: dict[str, str],
    context: SimpleContext,
) -> str:
    """Agent-geformter roher HTTP-Lesezugriff. Der Agent waehlt Methode/Pfad/
    Header (z. B. Auth-Header enumerieren); das Gateway prueft Scope UND den
    nicht-destruktiven envelope (nur safe methods). Bei Freigabe kommt die VOLLE
    Antwort zurueck - die Grundlage fuer die Klassifikation durch das LLM."""
    target = str(tool_input.get("target", "")).strip()
    method = str(tool_input.get("method", "GET")).upper()
    path = str(tool_input.get("path", "/") or "/")
    headers = tool_input.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    body = tool_input.get("body")
    # REQ-AGENT-023: which session-slot to read from / write back into. Fails
    # closed to "primary" - today's well-tested behaviour - on anything else,
    # never a hard reject; a malformed identity value is not itself unsafe.
    identity_raw = str(tool_input.get("identity", "primary")).strip().lower()
    identity = identity_raw if identity_raw in ("primary", "secondary") else "primary"
    proposal = {"tool": "http_request", "target": target, "method": method, "path": path, "identity": identity}

    host = target.lower()
    asset_id = asset_by_host.get(host)
    if asset_id is None:
        context.record_denied(proposal, "not_in_scope_list")
        _audit_agent_event(engagement_id, "proposal_rejected", scan_run_id=context.scan_run_id, decision="DENY", reason="not_in_scope_list", proposal=proposal)
        return f"REJECTED: {target!r} is not in the in-scope list. Choose a listed target."

    # REQ-AGENT-022/023: attach this run's session for THIS host AND THIS
    # identity, if one was established. Deliberately merged BEFORE authorize()
    # below, so the Scope Gateway sees and validates the exact request that
    # will be sent (header count/size/injection checks included) - this adds
    # convenience, never a path around the gateway. A "secondary" cookie is
    # never read when identity="primary", and vice versa.
    headers = session_state.apply_to_headers(headers, context.cookies_by_host.get(host, {}).get(identity, {}))

    args = {"method": method, "path": path, "headers": headers}
    if body:
        args["body"] = str(body)
    state_changing = method in _WRITE_METHODS or bool(body)
    payload = {
        "tool": "http_request", "category": "vuln", "mode": "active",
        "target": target, "args": args, "is_automated": True, "phase": "agent",
        "scan_run_id": context.scan_run_id,
    }
    # Zustandsaendernder Request: LLM-Risikobewertung mitgeben (REQ-APPROVAL-002).
    if state_changing:
        payload["rationale"] = str(tool_input.get("rationale", ""))
        payload["risk"] = {"level": str(tool_input.get("risk_level", "") or "medium"),
                           "description": str(tool_input.get("risk", "") or "")}

    decision = _authorize_throttled(engagement_id, payload, proposal, context)

    if decision.get("is_pending"):
        # REQ-APPROVAL-003: der Agent WARTET live auf die Operator-Entscheidung.
        return _await_approval(engagement_id, decision.get("approval_request_id"), asset_id, target,
                               args, ip_by_host.get(host), proposal, context, identity=identity)
    if not decision.get("allowed"):
        reason = decision.get("reason", "denied")
        context.record_denied(proposal, reason)
        _audit_agent_event(engagement_id, "proposal_denied", scan_run_id=context.scan_run_id, decision="DENY", reason=reason, proposal=proposal)
        if reason == "risk_statement_required":
            return "DENIED: state-changing requests need a risk assessment. Re-propose with risk_level and risk."
        return f"DENIED by the Scope Gateway: {reason}."

    _audit_agent_event(engagement_id, "proposal_allowed", scan_run_id=context.scan_run_id, decision="ALLOW", reason="gateway_allowed", proposal=proposal)
    obs = dispatch.dispatch(engagement_id, asset_id, "http_request", target, ip_by_host.get(host), args=args, scan_run_id=context.scan_run_id, single_port=context.single_port,
                            confirmed_protocol=context.protocol_by_host.get(host.lower()))
    _capture_session(context, host, obs.as_text(), engagement_id, identity=identity)
    context.observe(proposal, obs.as_text())
    # REQ-AUDIT-006/007: no separate truncation here - obs.as_text() is
    # already redacted AND bounded upstream by dispatch._run() (the runner's
    # own 16 KB response cap), so a second, smaller cut would only throw away
    # evidence the operator explicitly asked to see in full.
    _audit_agent_event(engagement_id, "observation", scan_run_id=context.scan_run_id, decision="ALLOW", reason="tool_observed", proposal=proposal, observation=obs.as_text())
    return obs.as_text()


def _handle_register_test_identity(
    engagement_id: str, tool_input: dict, asset_by_host: dict[str, str], ip_by_host: dict[str, str],
    context: SimpleContext,
) -> str:
    """REQ-AGENT-023: self-register a second, SYNTHETIC identity so BOLA/IDOR
    can be PROVEN by comparing what identity A vs identity B can access,
    instead of only guessed at from an ID change. Dispatches exactly like a
    state-changing http_request (same gateway authorization, same mandatory
    operator approval, REQ-APPROVAL-002 - registration is a POST/PUT like any
    other write). The only additions are the worker-side synthetic-payload
    guard below, run BEFORE the request is even proposed to the gateway, and
    capturing the resulting session into the "secondary" jar instead of
    "primary"."""
    target = str(tool_input.get("target", "")).strip()
    method = str(tool_input.get("method", "POST")).upper()
    path = str(tool_input.get("path", "") or "")
    headers = tool_input.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    body = str(tool_input.get("body", "") or "")
    proposal = {"tool": "register_test_identity", "target": target, "method": method, "path": path}

    if method not in ("POST", "PUT"):
        context.record_denied(proposal, "invalid_registration_method")
        return "REJECTED: registration must be POST or PUT."
    if not path or not body:
        context.record_denied(proposal, "empty_registration_payload")
        return "REJECTED: a registration request needs a path and a body."
    if not session_state.looks_synthetic_registration_body(body):
        context.record_denied(proposal, "registration_payload_not_synthetic")
        _audit_agent_event(engagement_id, "proposal_rejected", scan_run_id=context.scan_run_id, decision="DENY",
                           reason="registration_payload_not_synthetic", proposal=proposal)
        return ("REJECTED: this payload looks like it uses a real-world email domain. Register with an "
                "obviously synthetic identity (a randomly-suffixed username/email), never anything "
                "resembling a real person.")

    host = target.lower()
    asset_id = asset_by_host.get(host)
    if asset_id is None:
        context.record_denied(proposal, "not_in_scope_list")
        _audit_agent_event(engagement_id, "proposal_rejected", scan_run_id=context.scan_run_id, decision="DENY", reason="not_in_scope_list", proposal=proposal)
        return f"REJECTED: {target!r} is not in the in-scope list. Choose a listed target."

    args = {"method": method, "path": path, "headers": headers, "body": body}
    payload = {
        "tool": "http_request", "category": "vuln", "mode": "active",
        "target": target, "args": args, "is_automated": True, "phase": "agent",
        "scan_run_id": context.scan_run_id,
        "rationale": str(tool_input.get("rationale", "")),
        "risk": {"level": str(tool_input.get("risk_level", "") or "medium"),
                 "description": str(tool_input.get("risk", "") or
                                    "self-registers a synthetic second test account for BOLA/IDOR differential testing")},
    }
    decision = _authorize_throttled(engagement_id, payload, proposal, context)

    if decision.get("is_pending"):
        return _await_approval(engagement_id, decision.get("approval_request_id"), asset_id, target,
                               args, ip_by_host.get(host), proposal, context, identity="secondary")
    if not decision.get("allowed"):
        reason = decision.get("reason", "denied")
        context.record_denied(proposal, reason)
        _audit_agent_event(engagement_id, "proposal_denied", scan_run_id=context.scan_run_id, decision="DENY", reason=reason, proposal=proposal)
        if reason == "risk_statement_required":
            return "DENIED: registration needs a risk assessment. Re-propose with risk_level and risk."
        return f"DENIED by the Scope Gateway: {reason}."

    _audit_agent_event(engagement_id, "proposal_allowed", scan_run_id=context.scan_run_id, decision="ALLOW", reason="gateway_allowed", proposal=proposal)
    obs = dispatch.dispatch(engagement_id, asset_id, "http_request", target, ip_by_host.get(host), args=args, scan_run_id=context.scan_run_id, single_port=context.single_port,
                            confirmed_protocol=context.protocol_by_host.get(host.lower()))
    _capture_session(context, host, obs.as_text(), engagement_id, identity="secondary")
    context.observe(proposal, obs.as_text())
    # REQ-AUDIT-006/007: see the identical note in _handle_http_request.
    _audit_agent_event(engagement_id, "observation", scan_run_id=context.scan_run_id, decision="ALLOW", reason="tool_observed", proposal=proposal, observation=obs.as_text())
    return obs.as_text()


def _capture_session(context: SimpleContext, host: str, response_text: str, engagement_id: str,
                     identity: str = "primary") -> None:
    """REQ-AGENT-022/023: harvest Set-Cookie from a response into the
    run-scoped jar for THAT host AND THAT identity only.

    Keyed strictly by the host the request went to - never by the cookie's own
    Domain attribute, which is the one input that could widen replay beyond the
    issuing host (see session_state.extract_cookies) - and by the identity slot
    that made the request, so a secondary identity's session can never bleed
    into the primary one or vice versa."""
    fresh = session_state.extract_cookies(response_text)
    if not fresh:
        return
    host_jars = context.cookies_by_host.setdefault(host, {})
    previous = host_jars.get(identity, {})
    host_jars[identity] = session_state.merge_cookies(previous, fresh)
    # Audit the fact and the cookie NAMES, never the values - a session id is
    # exactly as sensitive as the credential that produced it.
    _audit_agent_event(
        engagement_id, "session_established", scan_run_id=context.scan_run_id,
        decision="ALLOW", reason="set_cookie_observed",
        proposal={"tool": "http_request", "target": host, "identity": identity},
        cookie_names=sorted(fresh), cookie_count=len(host_jars[identity]),
    )


_WRITE_METHODS = {"POST", "PUT", "DELETE", "PATCH"}
# Poll-Intervall fuer die Live-Freigabe. Die Wartegrenze selbst ist NICHT mehr
# hier hartcodiert (REQ-APPROVAL-005) - sie kommt als context.approval_timeout_seconds,
# aufgeloest von der control-plane aus derselben Konfiguration, die auch
# ApprovalRequest.expires_at bestimmt, damit beide nie auseinanderlaufen koennen.
_APPROVAL_POLL_SECONDS = 3


def _await_approval(engagement_id, approval_id, asset_id, target, args, ip, proposal, context,
                    identity: str = "primary", tool: str = "http_request") -> str:
    """Wartet live auf die Operator-Freigabe eines zustandsaendernden Requests
    (REQ-APPROVAL-003): scan_run -> waiting_approval, pollt den Status, fuehrt bei
    Freigabe aus (und konsumiert die Freigabe), ueberspringt bei Ablehnung/Ablauf.
    Ein Cancel des Laufs bricht das Warten ab."""
    if not approval_id:
        context.record_denied(proposal, "pending_no_id")
        return "PENDING: approval could not be created; skipped."
    _audit_agent_event(engagement_id, "proposal_pending_approval", scan_run_id=context.scan_run_id, decision="PENDING",
                       reason="awaiting_operator_approval", proposal=proposal, approval_id=str(approval_id))
    run_id = context.scan_run_id
    if run_id:
        try:
            client.update_scan_run(uuid.UUID(run_id), state="waiting_approval")
        except Exception as exc:  # noqa: BLE001
            logger.warning("could not set the waiting_approval state: %s", exc)

    waited = 0
    decision_state = "expired"
    cancel_probe = CancelProbe.for_run(run_id) if run_id else None
    while waited < context.approval_timeout_seconds:
        if cancel_probe is not None and cancel_probe.is_cancelled():  # issue #49: fail closed when unreadable
            decision_state = "cancelled"
            break
        st = client.get_approval(str(approval_id)).get("state")
        if st in ("approved", "rejected", "expired", "consumed"):
            decision_state = st
            break
        time.sleep(_APPROVAL_POLL_SECONDS)
        waited += _APPROVAL_POLL_SECONDS

    # Lauf zurueck auf 'running' (der Pipeline-Task setzt danach die Phasen weiter).
    if run_id:
        try:
            client.update_scan_run(uuid.UUID(run_id), state="running")
        except Exception:  # noqa: BLE001
            pass

    if decision_state == "approved":
        # Claim performs current gateway checks and atomically changes approved
        # -> executing. Only the exact stored call returned by the control plane
        # is dispatched; captured/in-memory arguments are not trusted.
        claim = client.claim_approval(str(approval_id))
        if not claim.get("allowed"):
            reason = claim.get("reason", "approval_claim_denied")
            context.record_denied(proposal, reason)
            _audit_agent_event(engagement_id, "approval_claim_denied", scan_run_id=context.scan_run_id, decision="DENY", reason=reason, proposal=proposal)
            return f"NOT EXECUTED: approval reauthorization failed ({reason})."
        exact = claim.get("tool_call") or {}
        exact_target = str(exact.get("target") or "")
        # REQ-APPROVAL-006: the actually-approved tool, not an assumption -
        # the stored, re-reviewed call is the one source of truth for WHAT
        # runs, same principle as exact_args below already applied to HOW.
        exact_tool = str(exact.get("tool") or tool)
        # REQ-AGENT-022: deliberately NOT re-injecting the session jar here. The
        # cookie was merged before authorize(), so the stored call the operator
        # actually reviewed and approved already carries it. Adding it now would
        # send something other than what was approved, breaking this block's own
        # "captured/in-memory arguments are not trusted" invariant.
        exact_args = exact.get("args") or {}
        exact_asset_id = asset_id if exact_target.lower() == target.lower() else None
        if exact_asset_id is None:
            client.complete_approval(str(approval_id), success=False, error="approved_target_not_loaded")
            return "NOT EXECUTED: approved target is not available in the loaded scope."
        _audit_agent_event(engagement_id, "approval_claimed", scan_run_id=context.scan_run_id, decision="ALLOW", reason="reauthorized", proposal=proposal)
        try:
            obs = dispatch.dispatch(engagement_id, exact_asset_id, exact_tool, exact_target, ip, args=exact_args, scan_run_id=context.scan_run_id, single_port=context.single_port,
                                    confirmed_protocol=context.protocol_by_host.get(exact_target.lower()))
        except Exception as exc:  # noqa: BLE001
            client.complete_approval(str(approval_id), success=False, error=str(exc)[:500])
            _audit_agent_event(engagement_id, "approval_execution_failed", scan_run_id=context.scan_run_id, decision="DENY", reason="runner_execution_failed", proposal=proposal)
            return "ERROR: approved request execution failed."
        client.complete_approval(str(approval_id), success=True)
        # REQ-AGENT-022/023: the approval path is where a LOGIN or a
        # registration actually happens - both are POSTs, and every
        # state-changing request routes through here. Without this capture
        # the jar would miss the one response that matters most. `identity`
        # tags it into the right slot - "secondary" for register_test_identity
        # and any http_request explicitly proposed with identity="secondary".
        _capture_session(context, exact_target.lower(), obs.as_text(), engagement_id, identity=identity)
        context.observe(proposal, obs.as_text())
        # REQ-AUDIT-006/007: see the identical note in _handle_http_request.
        _audit_agent_event(engagement_id, "observation", scan_run_id=context.scan_run_id, decision="ALLOW", reason="tool_observed_after_approval",
                           proposal=proposal, observation=obs.as_text())
        return obs.as_text()

    context.record_denied(proposal, decision_state)
    _audit_agent_event(engagement_id, "approval_not_granted", scan_run_id=context.scan_run_id, decision="DENY", reason=decision_state, proposal=proposal)
    if decision_state == "expired":
        # REQ-APPROVAL-005: an unanswered approval auto-rejects once the
        # configured timeout elapses - phrased explicitly as a rejection
        # (not just "expired") so the agent - and anyone reading this step in
        # the Vector Agent tab - understands it exactly like an explicit
        # operator rejection, not a system error.
        return (
            f"NOT EXECUTED: auto-rejected - no operator response within the configured "
            f"{context.approval_timeout_seconds}s timeout. Continue without it."
        )
    return f"NOT EXECUTED: the operator {decision_state} this state-changing request. Continue without it."


def _handle_ffuf(
    engagement_id: str, tool_input: dict, asset_by_host: dict[str, str], ip_by_host: dict[str, str],
    context: SimpleContext,
) -> str:
    """Kuratierte Content-Discovery. Der Agent waehlt Wortliste/Pfad/Kandidaten;
    das Gateway prueft Scope + den ffuf-envelope (Wortlisten-Allowlist, FUZZ-
    Pfad). Die Trefferliste kommt als Beobachtung zurueck."""
    target = str(tool_input.get("target", "")).strip()
    path = str(tool_input.get("path", "/FUZZ") or "/FUZZ")
    wordlist = str(tool_input.get("wordlist", "common"))
    extensions = tool_input.get("extensions") or []
    extra_candidates = tool_input.get("extra_candidates") or []
    if not isinstance(extensions, list):
        extensions = []
    if not isinstance(extra_candidates, list):
        extra_candidates = []
    proposal = {"tool": "ffuf", "target": target, "path": path, "wordlist": wordlist}

    host = target.lower()
    asset_id = asset_by_host.get(host)
    if asset_id is None:
        context.record_denied(proposal, "not_in_scope_list")
        _audit_agent_event(engagement_id, "proposal_rejected", scan_run_id=context.scan_run_id, decision="DENY", reason="not_in_scope_list", proposal=proposal)
        return f"REJECTED: {target!r} is not in the in-scope list. Choose a listed target."

    args = {"wordlist": wordlist, "path": path, "extensions": extensions, "extra_candidates": extra_candidates}
    payload = {
        "tool": "ffuf", "category": "vuln", "mode": "active",
        "target": target, "args": args, "is_automated": True, "phase": "agent",
        "scan_run_id": context.scan_run_id,
    }
    decision = _authorize_throttled(engagement_id, payload, proposal, context)
    if decision.get("is_pending"):
        context.record_denied(proposal, "pending_approval")
        _audit_agent_event(engagement_id, "proposal_pending_approval", scan_run_id=context.scan_run_id, decision="PENDING", reason="pending_approval", proposal=proposal)
        return "PENDING: needs manual approval - skipped here."
    if not decision.get("allowed"):
        reason = decision.get("reason", "denied")
        context.record_denied(proposal, reason)
        _audit_agent_event(engagement_id, "proposal_denied", scan_run_id=context.scan_run_id, decision="DENY", reason=reason, proposal=proposal)
        return f"DENIED by the Scope Gateway: {reason}."

    _audit_agent_event(engagement_id, "proposal_allowed", scan_run_id=context.scan_run_id, decision="ALLOW", reason="gateway_allowed", proposal=proposal)
    obs = dispatch.dispatch(engagement_id, asset_id, "ffuf", target, ip_by_host.get(host), args=args, scan_run_id=context.scan_run_id, single_port=context.single_port,
                            confirmed_protocol=context.protocol_by_host.get(host.lower()))
    context.observe(proposal, obs.as_text())
    _audit_agent_event(engagement_id, "observation", scan_run_id=context.scan_run_id, decision="ALLOW", reason="tool_observed", proposal=proposal, observation=obs.as_text()[:2000])
    return obs.as_text()


def _handle_report_finding(engagement_id: str, tool_input: dict, asset_by_host: dict[str, str],
                           context: SimpleContext) -> str:
    """Der Agent haelt ein selbst begruendetes Ergebnis als Finding fest. Das
    beruehrt kein Ziel (reines Schreiben in die control-plane) - daher keine
    Gateway-Freigabe noetig, aber auditiert. So gehen die Schluesse des Agenten
    (z. B. 'unauth. PII-Exposure bestaetigt') nicht verloren."""
    target = str(tool_input.get("target", "")).strip()
    title = str(tool_input.get("title", "")).strip()
    severity = str(tool_input.get("severity", "info")).lower()
    category = str(tool_input.get("category", "exposure")).lower()
    rationale = str(tool_input.get("rationale", ""))
    # REQ-AGENT-021: fail closed. Anything not explicitly and recognizably
    # claimed as direct proof is treated as inference - a missing, unknown,
    # empty or non-string value must never buy `validated`. Same defensive
    # normalisation style as severity/category just below.
    raw_basis = tool_input.get("evidence_basis")
    evidence_basis = raw_basis.lower().strip() if isinstance(raw_basis, str) else ""
    if evidence_basis not in _EVIDENCE_BASES:
        evidence_basis = "contextual_inference"
    # REQ-BENCH-011: same fail-closed shape as severity_override just below -
    # a well-formed CVE ID is only ever attached when actually demonstrated,
    # never on an inference the platform's own version-banner correlation
    # already covers (see the tool description: guessing one in to look more
    # certain has no effect, it is silently dropped here).
    raw_cve = tool_input.get("cve_id")
    cve_id = raw_cve.strip().upper() if isinstance(raw_cve, str) else ""
    if not _CVE_ID_RE.match(cve_id):
        cve_id = ""

    asset_id = asset_by_host.get(target.lower())
    if asset_id is None:
        return f"REJECTED: {target!r} is not in the in-scope list."
    if not title:
        return "REJECTED: 'title' is missing."
    if severity not in {"info", "low", "medium", "high", "critical"}:
        severity = "info"
    if category not in {"cve", "misconfig", "exposure", "logic"}:
        category = "exposure"

    # REQ-AGENT-021: only a demonstrated weakness earns confidence="validated"
    # (which feeds compute_risk_score's W_VALID term) AND the right to assert
    # its own severity (severity_override bypasses compute_severity entirely
    # and floors risk_score up to match - REQ-AGENT-010). For everything else
    # the platform scores the finding instead of the agent grading itself.
    proven = evidence_basis == "direct_technical_proof"
    try:
        client.add_finding(
            engagement_id, asset_id=asset_id, category=category, title=title,
            confidence="validated" if proven else "inferred",
            severity_override=severity if proven else None,
            cve_ids=[cve_id] if (proven and cve_id) else None,
            evidence={
                "tool": "vector_agent", "reported_by": "vector_agent",
                "rationale": rationale, "evidence_basis": evidence_basis,
                # Preserve what the agent *claimed* even when we don't honour
                # it as the severity - useful for triage and for spotting a
                # model that systematically over-rates its own inferences.
                "agent_assessed_severity": severity,
            },
            exposure_factor=1.0, business_factor=0.5,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("report_finding failed: %s", exc)
        return f"ERROR: the finding could not be saved ({exc})."

    context.reported.append({"target": target, "title": title, "severity": severity, "category": category,
                             "evidence_basis": evidence_basis})
    _audit_agent_event(engagement_id, "finding_reported", scan_run_id=context.scan_run_id, decision="ALLOW", reason="agent_reported",
                       proposal={"tool": "report_finding", "target": target}, title=title, severity=severity,
                       evidence_basis=evidence_basis)
    if proven:
        return f"Finding recorded as PROVEN: [{severity}/{category}] {title}"
    # Tell the agent plainly that its severity claim was not taken at face
    # value, so it can escalate by actually demonstrating the weakness rather
    # than by re-reporting the same claim more forcefully.
    return (
        f"Finding recorded as INFERRED ({evidence_basis}), severity computed by the platform "
        f"rather than your '{severity}' assessment: [{category}] {title}. To have it recorded as "
        f"proven, demonstrate it in an observation and report again with "
        f"evidence_basis=direct_technical_proof."
    )


def _safe_agent_context(engagement_id: str) -> dict:
    """Holt den Agent-Kontext (Hosts + Graph) einmal pro Lauf, fault-isoliert.
    Ein Fehler darf den Agenten nie abreissen - Fallback auf leere Struktur."""
    try:
        return client.get_agent_context(uuid.UUID(engagement_id))
    except Exception as exc:  # noqa: BLE001
        logger.warning("agent: evidence context not loadable (%s) - host list only", exc)
        return {"hosts": [], "graph": {"nodes": [], "edges": []}}


def _protocols_from_context(ctx: dict) -> dict[str, str]:
    """host(lower) -> "http"/"https", aus den bereits erhobenen Services
    (REQ-FIDELITY-009). Nimmt pro Host das erste eindeutige http/https-Signal.

    Bewusst konservativ: taucht fuer denselben Host BEIDES auf (was vorkommen
    kann, solange alte, vor dem Fix geschriebene Service-Zeilen in der DB
    liegen), gewinnt "https" - das ist das historische Default und damit die
    sichere, nicht-regressive Wahl gegenueber einem Raten."""
    out: dict[str, str] = {}
    for entry in ctx.get("hosts") or []:
        host = str(entry.get("host") or "").lower()
        if not host:
            continue
        seen = {
            str(svc.get("protocol") or "").lower()
            for svc in (entry.get("services") or [])
            if str(svc.get("protocol") or "").lower() in ("http", "https")
        }
        if seen == {"http"}:
            out[host] = "http"
        elif "https" in seen:
            out[host] = "https"
    return out


def _render_pipeline_checks(checks: list[dict]) -> list[str]:
    """REQ-PIPE-018: what the scan pipeline already ran on this host, per port, so
    the agent builds on it and does not repeat it. Compact: nuclei's many checks
    collapse into one count per outcome; a redirect-only alias says where its
    coverage lives."""
    by_port: dict[int, list[dict]] = {}
    for c in checks:
        by_port.setdefault(int(c.get("port") or 0), []).append(c)
    if not by_port:
        return []
    lines = [
        "  Pipeline checks already run in this scan (do not repeat a completed check with the same "
        "tool and wordlist; a check marked partial was cut short by its time limit):"
    ]
    for port in sorted(by_port):
        items = by_port[port]
        skipped = [c for c in items if c.get("state") == "skipped"]
        alias = next((str(c.get("reason")) for c in skipped if str(c.get("reason", "")).startswith("web_alias_of:")), None)
        if alias:
            lines.append(f"    port {port}: only a redirect to {alias.split(':', 1)[1]}; its checks run there")
            continue
        parts: list[str] = []
        nuclei: dict[str, int] = {}
        for c in items:
            state = str(c.get("state"))
            if state == "skipped":
                continue
            if c.get("tool") == "nuclei":
                nuclei[state] = nuclei.get(state, 0) + 1
                continue
            label = str(c.get("check_id"))
            if c.get("wordlist"):
                label += f"[{c['wordlist']}]"
            parts.append(f"{label}={state}")
        for state, n in sorted(nuclei.items()):
            parts.append(f"nuclei x{n}={state}")
        if parts:
            lines.append(f"    port {port}: " + ", ".join(parts))
    return lines if len(lines) > 1 else []


def _render_evidence(engagement_id: str, asset_by_host: dict[str, str], ctx: dict | None = None) -> str:
    """Baut den Evidenz-Block aus den bereits erhobenen Services/Findings. Faellt
    auf die reine Hostliste zurueck, wenn der Kontext nicht ladbar ist."""
    if ctx is None:
        ctx = _safe_agent_context(engagement_id)

    by_host = {h["host"].lower(): h for h in ctx.get("hosts", [])}
    lines: list[str] = []
    for host in sorted(asset_by_host):
        h = by_host.get(host, {})
        services = h.get("services", [])
        findings = h.get("findings", [])
        lines.append(f"### {host}")
        if services:
            for s in services:
                tech = ", ".join(s.get("tech") or []) or "-"
                lines.append(
                    f"  Service: Port {s.get('port')}/{s.get('protocol') or '?'} "
                    f"{s.get('product') or '?'} | status {s.get('status')} | tech: {tech}"
                )
        elif h.get("http_checked_at") and h.get("http_live") is False:
            # REQ-AGENT-015: distinguish "never checked" from "already checked,
            # confirmed no live HTTP service" - found live: without this, the
            # agent re-ran httpx against the same dead subdomains in every one
            # of 3 consecutive scan runs, wasting iteration budget that could
            # have gone toward deeper coverage of the one live host.
            lines.append(
                f"  Service: NONE - httpx already confirmed no live HTTP service "
                f"(checked {h['http_checked_at']}). Do not re-run httpx on this host "
                f"unless you have a specific new reason (e.g. a different port)."
            )
        else:
            lines.append("  Service: (none recorded yet)")
        lines.extend(_render_pipeline_checks(h.get("checks") or []))
        if findings:
            for f in findings:
                extra = []
                if f.get("cve_ids"):
                    extra.append(", ".join(f["cve_ids"]))
                if f.get("cvss_base") is not None:
                    extra.append(f"CVSS {f['cvss_base']}")
                if f.get("is_kev"):
                    extra.append("KEV")
                if f.get("risk_score") is not None:
                    extra.append(f"risk {f['risk_score']}")
                tail = f" [{'; '.join(extra)}]" if extra else ""
                lines.append(
                    f"  Finding [{f.get('severity') or '?'}/{f.get('category')}]: "
                    f"{f.get('title')} ({f.get('confidence')}){tail}"
                )
        else:
            lines.append("  Findings: (none open)")
    return "\n".join(lines) or "(no evidence recorded)"


def _render_relationships(graph: dict | None) -> str:
    """REQ-GRAPH-003: rendert die cross-host-Beziehungen aus dem
    Attack-Surface-Graphen (shared infra, Technologie-Fan-out, Technologie->CVE)
    als knappen, NUR-LESE Textblock. Kein LLM-generiertes Query - der Agent
    bekommt eine fertig gerenderte Struktur. Leerer Graph -> leerer Block."""
    if not graph:
        return ""
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    edges = graph.get("edges", [])
    lines: list[str] = []

    # Shared infrastructure: an IP hosting >=2 names links those names.
    shared: dict[str, list[str]] = {}
    for e in edges:
        if e.get("edge_type") == "SHARES_INFRA":
            ip = nodes.get(e["src"], {}).get("label", "?")
            host = nodes.get(e["dst"], {}).get("label")
            if host:
                shared.setdefault(ip, []).append(host)
    for ip, hosts in sorted(shared.items()):
        if len(hosts) >= 2:
            lines.append(
                f"- Shared infra: {ip} is shared by {', '.join(sorted(set(hosts)))} "
                f"— a finding on one likely applies to the others."
            )

    # Technology fan-out: a technology running on >=2 services.
    tech_services: dict[str, set[str]] = {}
    for e in edges:
        if e.get("edge_type") == "RUNS_TECHNOLOGY":
            tech = nodes.get(e["dst"], {}).get("label", "?")
            svc = nodes.get(e["src"], {}).get("label")
            if svc:
                tech_services.setdefault(tech, set()).add(svc)
    for tech, svcs in sorted(tech_services.items()):
        if len(svcs) >= 2:
            lines.append(
                f"- Technology fan-out: {tech} runs on {len(svcs)} services "
                f"({', '.join(sorted(svcs))}) — one weakness there is systemic."
            )

    # Technology -> CVE links.
    tech_cves: dict[str, set[str]] = {}
    for e in edges:
        if e.get("edge_type") == "HAS_CVE":
            src = nodes.get(e["src"], {})
            if src.get("node_type") == "technology":
                tech_cves.setdefault(src.get("label", "?"), set()).add(
                    nodes.get(e["dst"], {}).get("label", "?")
                )
    for tech, cves in sorted(tech_cves.items()):
        lines.append(f"- {tech} is linked to {', '.join(sorted(cves))}.")

    if not lines:
        return ""
    return (
        "ATTACK-SURFACE RELATIONSHIPS (derived graph — context only, it does NOT "
        "change what is in scope; only the IN-SCOPE HOSTS above are valid targets):\n"
        + "\n".join(lines)
        + "\n\n"
    )


def _engagement_params_block(engagement_params: dict | None) -> str:
    """REQ-AGENT-012: konkrete Engagement-Parameter fuer DIESEN Lauf - der
    System-Prompt beschreibt nur, DASS diese Werte kommen; hier stehen die
    tatsaechlichen (pro Lauf verschiedenen, daher nicht Teil des statischen
    Prompts)."""
    if not engagement_params:
        return ""
    port_from = engagement_params.get("tcp_port_from")
    port_to = engagement_params.get("tcp_port_to")
    if port_from is not None and port_to is not None and port_from == port_to and port_from not in (80, 443):
        port_line = f"Authorized port: {port_from} ONLY (already applied automatically to every check you propose)."
    else:
        port_line = "Authorized ports: standard (no single-port restriction for this campaign)."
    return (
        "ENGAGEMENT PARAMETERS for this run:\n"
        f"- Title: {engagement_params.get('title', '?')}\n"
        f"- Type: {engagement_params.get('source', '?')}\n"
        f"- Authorized window: {engagement_params.get('authorized_from', '?')} to "
        f"{engagement_params.get('authorized_until', '?')}\n"
        f"- {port_line}\n"
        f"- AI-driven active testing opt-in: {engagement_params.get('ai_testing_allowed', '?')}\n\n"
    )


def _initial_context(
    engagement_id: str, asset_by_host: dict[str, str], enabled_tools: list[str] | None = None,
    engagement_params: dict | None = None,
) -> str:
    hosts = ", ".join(sorted(asset_by_host)) or "(none)"
    ctx = _safe_agent_context(engagement_id)
    evidence = _render_evidence(engagement_id, asset_by_host, ctx)
    relationships = _render_relationships(ctx.get("graph"))
    tools_line = ""
    if enabled_tools:
        tools_line = (
            "ENABLED TOOLS for this campaign — this list is AUTHORITATIVE. Propose ONLY "
            "these; any tool named in the toolkit description but absent here is DISABLED "
            "for this campaign, and proposing it just wastes a step (it will be denied). "
            f"Enabled: {', '.join(sorted(enabled_tools))}\n\n"
        )
    return (
        f"{_engagement_params_block(engagement_params)}"
        "IN-SCOPE HOSTS (these — and ONLY these — are valid targets):\n"
        f"{hosts}\n\n"
        f"{tools_line}"
        "The automated (non-agentic) ASM scan has already run its deterministic "
        "phases (httpx/nmap/nikto/wafw00f/testssl/nuclei). Below is the evidence "
        "it collected per host. This is your starting intelligence — reason from "
        "it, do not re-derive it blindly:\n\n"
        f"{evidence}\n\n"
        f"{relationships}"
        "Now work the surface: propose the few highest-value checks that fill a "
        "coverage gap or validate/deepen a promising lead, each with a concrete "
        "rationale. Call finish with a prioritized summary once the marginal "
        "value of further checks drops."
    )


def run(engagement_id: str, budget_max_iterations: int, scan_run_id: str | None = None,
        findings_and_services: dict | None = None, approval_timeout_seconds: int = 900) -> SimpleContext:
    context = SimpleContext(scan_run_id=scan_run_id, approval_timeout_seconds=approval_timeout_seconds)
    # REQ-FIDELITY-007: einmal pro Lauf aufloesen, damit jeder Agent-Tool-Vorschlag
    # denselben Port trifft wie die deterministische Fingerprint-Phase (REQ-FIDELITY-003).
    try:
        context.single_port = single_port_from_envelope(client.get_scan_envelope(uuid.UUID(engagement_id)))
    except Exception:  # noqa: BLE001 - best effort, faellt auf implizites 443 zurueck
        context.single_port = None
    # REQ-FIDELITY-009: dasselbe einmal pro Lauf fuer das Schema. Die
    # Fingerprint-Phase hat pro Host/Port bereits per httpx bestaetigt, ob dort
    # http oder https laeuft; ohne diese Uebergabe zielt jeder agent-getriebene
    # Tool-Aufruf blind auf https:// (gegen einen reinen HTTP-Dienst: still
    # keine Treffer). Best effort - leer => unveraendertes https-Default.
    try:
        context.protocol_by_host = _protocols_from_context(_safe_agent_context(engagement_id))
    except Exception:  # noqa: BLE001
        context.protocol_by_host = {}
    _audit_agent_event(engagement_id, "started", scan_run_id=scan_run_id, decision=None, reason="agent_phase_started", budget_max_iterations=budget_max_iterations)

    try:
        from openai import OpenAI
    except ImportError:
        logger.info("agent phase: openai SDK not available - no-op")
        _audit_agent_event(engagement_id, "skipped", scan_run_id=scan_run_id, decision="DENY", reason="openai_sdk_missing")
        return context

    base_url, api_key, model = _resolve_provider()
    if not (base_url and api_key and model):
        logger.info("agent phase: no LLM provider configured - no-op (the deterministic phases have delivered)")
        _audit_agent_event(engagement_id, "skipped", scan_run_id=scan_run_id, decision="DENY", reason="llm_provider_missing", base_url_set=bool(base_url), api_key_set=bool(api_key), model_set=bool(model))
        return context

    normalized_base_url, normalization = _normalize_chat_base_url(base_url)
    _audit_agent_event(engagement_id, "provider_configured", scan_run_id=scan_run_id, decision="ALLOW", reason="llm_provider_usable",
        base_url=_safe_url(normalized_base_url), original_base_url=_safe_url(base_url), normalization=normalization, model=model,
    )

    asset_by_host, ip_by_host = _load_scope(engagement_id, scan_run_id)
    if not asset_by_host:
        logger.info("agent phase: no in-scope assets - no-op")
        _audit_agent_event(engagement_id, "skipped", scan_run_id=scan_run_id, decision="DENY", reason="no_in_scope_assets")
        return context

    # Effektive Config (Schichtenmodell im control-plane-Resolver): die
    # aufgeloeste Agent-Anweisung + die fuer DIESE Kampagne aktivierten Tools.
    # Leerer Prompt -> eingebauter Default. Faellt bei Ausfall sauber zurueck.
    system_prompt = _SYSTEM_PROMPT
    enabled_tools: list[str] = []
    engagement_params: dict | None = None
    # REQ-AGENT-026: env-var default only until the control plane answers.
    max_tokens = AGENT_MAX_TOKENS
    try:
        cfg = client.get_agent_config(uuid.UUID(engagement_id))
        if (cfg.get("prompt") or "").strip():
            system_prompt = cfg["prompt"].strip()
        enabled_tools = list(cfg.get("enabled_tools") or [])
        # Full TCP Nmap is deterministic pipeline work. The Vector Agent
        # receives its results but cannot repeat the broad scan.
        enabled_tools = [tool for tool in enabled_tools if tool != "nmap"]
        engagement_params = cfg.get("engagement")
        # Re-clamp rather than trust the delivered number: the worker's own
        # bounds are the last word on what it will ask a provider for.
        if cfg.get("agent_max_tokens") is not None:
            max_tokens = max(AGENT_MIN_MAX_TOKENS, min(int(cfg["agent_max_tokens"]), AGENT_MAX_MAX_TOKENS))
    except Exception as exc:  # noqa: BLE001
        logger.warning("agent: effective config not loadable (%s) - using the built-in prompt", exc)
    # The length-retry ceiling must never sit below the configured cap, or a
    # raised max_tokens would be silently clamped back down on every retry.
    # Found live: with the module-level AGENT_RETRY_MAX_TOKENS defaulting to
    # the SAME value as AGENT_MAX_TOKENS (8192 each out of the box), the old
    # `max(max_tokens, AGENT_RETRY_MAX_TOKENS)` resolved to 8192 for a run at
    # the default cap, so `token_budget = min(max_tokens * 2, retry_max_tokens)`
    # on retry was ALSO 8192 - zero extra headroom, defeating the entire
    # point of retrying. Two engagements (Confluence, Jenkins) hit their
    # length limit on iteration 1, retried, hit the identical 8192 ceiling
    # again, and gave up with zero tool calls ever made.
    #
    # Fixed once already by doubling THIS run's own resolved max_tokens
    # rather than the static module default - live-reverified afterward:
    # Confluence recovered cleanly (hit the limit again at iteration 20,
    # retried into the doubled budget, and continued for 24+ more
    # iterations), but Jenkins still failed - even the doubled 16384-token
    # budget was not enough for this model's response on that context. A
    # flat `max_tokens * 2` ceiling does not scale with AGENT_LENGTH_RETRIES:
    # a THIRD attempt would ask for `max_tokens * 4` per the exponential
    # formula below, but was still being clamped back down to the SAME
    # doubled ceiling as the second attempt - raising the retry count alone
    # could never reach further. The ceiling must scale to cover the actual
    # maximum a full retry sequence can ask for.
    retry_max_tokens = min(
        max(max_tokens * (2 ** AGENT_LENGTH_RETRIES), AGENT_RETRY_MAX_TOKENS), AGENT_MAX_MAX_TOKENS
    )

    llm = OpenAI(base_url=normalized_base_url, api_key=api_key, max_retries=AGENT_LLM_MAX_RETRIES)
    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": _initial_context(engagement_id, asset_by_host, enabled_tools, engagement_params)},
    ]

    cancel_probe = CancelProbe.for_run(scan_run_id) if scan_run_id else None
    while context.iterations < budget_max_iterations and not context.exhausted:
        # Kooperativer Stopp (REQ-RUN-001): vor jedem (teuren) LLM-Aufruf pruefen.
        # An unreadable answer is never "not cancelled" (GitHub issue #49).
        if cancel_probe is not None and cancel_probe.is_cancelled():
            logger.info("agent phase: stopped by the operator")
            _audit_agent_event(engagement_id, "cancelled", scan_run_id=scan_run_id, decision="DENY", reason="cancelled_by_operator")
            break

        iteration = context.iterations + 1
        request_snapshot = [dict(m) for m in messages]  # was an das Modell geht (ohne Secrets)
        resp = None
        request_failed = False
        for completion_attempt in range(AGENT_LENGTH_RETRIES + 1):
            token_budget = min(max_tokens * (2 ** completion_attempt), retry_max_tokens)
            try:
                _audit_agent_event(engagement_id, "llm_request", scan_run_id=scan_run_id, decision=None, reason="requesting_next_action",
                    iteration=iteration, model=model, completion_attempt=completion_attempt + 1,
                    max_tokens=token_budget,
                )
                resp = llm.chat.completions.create(
                    model=model, max_tokens=token_budget, messages=messages,
                    tools=_TOOLS, tool_choice="auto",
                )
            except Exception as exc:  # noqa: BLE001 - LLM-Ausfall beendet die Phase sauber
                logger.warning("agent phase: LLM call failed: %s", exc)
                _audit_agent_event(engagement_id, "llm_call_failed", scan_run_id=scan_run_id, decision="DENY", reason="llm_call_failed",
                    error=_safe_error(exc), base_url=_safe_url(normalized_base_url),
                    original_base_url=_safe_url(base_url), model=model, normalization=normalization,
                )
                if scan_run_id:
                    client.record_agent_step(
                        uuid.UUID(engagement_id), scan_run_id=scan_run_id, iteration=iteration,
                        request_messages=request_snapshot, response_text=None,
                        response_tool_calls=None, stop_reason="error",
                    )
                request_failed = True
                break

            finish_reason = getattr(resp.choices[0], "finish_reason", None) or "stop"
            if finish_reason != "length":
                break
            _audit_agent_event(engagement_id, "llm_incomplete", scan_run_id=scan_run_id, decision="DENY", reason="finish_reason_length",
                iteration=iteration, completion_attempt=completion_attempt + 1, max_tokens=token_budget,
                will_retry=completion_attempt < AGENT_LENGTH_RETRIES,
            )

        if request_failed or resp is None:
            break

        msg = resp.choices[0].message
        tool_calls = msg.tool_calls or []
        finish_reason = getattr(resp.choices[0], "finish_reason", None) or ("tool_calls" if tool_calls else "stop")
        # Vector-Agent-Transparenz (REQ-RUN-006): Prompt + Antwort dieser Iteration
        # festhalten fuer den GUI-Drilldown.
        if scan_run_id:
            client.record_agent_step(
                uuid.UUID(engagement_id), scan_run_id=scan_run_id, iteration=iteration,
                request_messages=request_snapshot, response_text=msg.content or "",
                response_tool_calls=[
                    {"name": tc.function.name, "arguments": tc.function.arguments} for tc in tool_calls
                ],
                stop_reason=finish_reason,
            )
        if finish_reason == "length":
            # Even syntactically present tool calls may be a truncated subset.
            # Never dispatch an incomplete provider response.
            context.incomplete_reason = "finish_reason_length"
            _audit_agent_event(engagement_id, "incomplete", scan_run_id=scan_run_id, decision="DENY", reason="finish_reason_length",
                retries_exhausted=True,
            )
            break
        if not tool_calls:
            content = (msg.content or "").strip()
            if not content:
                context.incomplete_reason = "empty_response"
                _audit_agent_event(engagement_id, "incomplete", scan_run_id=scan_run_id, decision="DENY", reason="empty_response")
                break
            # Text without an action is a conclusion only for a complete response.
            context.conclusion = content
            _audit_agent_event(engagement_id, "conclusion", scan_run_id=scan_run_id, decision="ALLOW", reason="llm_finished_without_tool", conclusion=content)
            break

        # Assistant-Turn (mit tool_calls) unveraendert zurueck in den Verlauf.
        messages.append({
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in tool_calls
            ],
        })

        for tc in tool_calls:
            if context.iterations >= budget_max_iterations:
                context.exhausted = True
                break
            context.iterations += 1
            name = tc.function.name
            try:
                arguments = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                arguments = {}

            if name == "finish":
                context.exhausted = True
                context.conclusion = str(arguments.get("summary", ""))
                _audit_agent_event(engagement_id, "finish_requested", scan_run_id=scan_run_id, decision="ALLOW", reason="llm_finish", summary=context.conclusion)
                observation = "ok, finished."
            elif name == "run_check":
                _audit_agent_event(engagement_id, "proposal", scan_run_id=scan_run_id, decision=None, reason="llm_proposed_tool", proposal=arguments)
                observation = _handle_run_check(engagement_id, arguments, asset_by_host, ip_by_host, context)
            elif name == "http_request":
                _audit_agent_event(engagement_id, "proposal", scan_run_id=scan_run_id, decision=None, reason="llm_proposed_http_request", proposal=arguments)
                observation = _handle_http_request(engagement_id, arguments, asset_by_host, ip_by_host, context)
            elif name == "register_test_identity":
                _audit_agent_event(engagement_id, "proposal", scan_run_id=scan_run_id, decision=None, reason="llm_proposed_register_test_identity", proposal=arguments)
                observation = _handle_register_test_identity(engagement_id, arguments, asset_by_host, ip_by_host, context)
            elif name == "content_discovery":
                _audit_agent_event(engagement_id, "proposal", scan_run_id=scan_run_id, decision=None, reason="llm_proposed_content_discovery", proposal=arguments)
                observation = _handle_ffuf(engagement_id, arguments, asset_by_host, ip_by_host, context)
            elif name == "report_finding":
                observation = _handle_report_finding(engagement_id, arguments, asset_by_host, context)
            elif name in ALLOWED_TOOLS:
                # REQ-AGENT-009: das Modell hat gelegentlich eine Funktion
                # NAMENS des Tools aufgerufen (z. B. "nuclei(...)") statt
                # run_check({"tool": "nuclei", ...}). Statt eine Iteration fuer
                # einen reinen Formfehler zu verbrennen, wird das identisch wie
                # ein echter run_check-Vorschlag behandelt - der Funktionsname
                # ist dabei massgeblich fuer "tool" (ueberschreibt ein evtl.
                # widerspruechliches "tool"-Argument). Auditiert mit eigenem
                # Grund, damit Modell-Zuverlaessigkeit sichtbar bleibt.
                tool_input = {**arguments, "tool": name}
                _audit_agent_event(engagement_id, "proposal", scan_run_id=scan_run_id, decision=None,
                                    reason="llm_proposed_tool_as_function_name", proposal=tool_input)
                observation = _handle_run_check(engagement_id, tool_input, asset_by_host, ip_by_host, context)
            else:
                observation = f"REJECTED: unknown tool {name!r}."

            messages.append({"role": "tool", "tool_call_id": tc.id, "content": observation})

    logger.info(
        "agent phase finished: %d iterations, %d observations, %d denied%s",
        context.iterations, len(context.observations), len(context.denied),
        f", conclusion: {context.conclusion}" if context.conclusion else "",
    )
    _audit_agent_event(engagement_id, "finished", scan_run_id=scan_run_id, decision="ALLOW", reason="agent_phase_finished",
        iterations=context.iterations, observations=len(context.observations), denied=len(context.denied), conclusion=context.conclusion, exhausted=context.exhausted,
    )
    return context
