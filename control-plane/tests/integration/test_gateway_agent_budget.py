"""Gateway-Haertung fuer den Vector Agent: ai_testing-Gate + Budget-Deckel.

Beide Sicherungen wurden ergaenzt, BEVOR der autonome Agent scharfgeschaltet
wird - sie beantworten 'darf autonome KI hier ueberhaupt handeln' (ai_testing)
und 'wie oft' (Budget), unabhaengig davon, was das LLM vorschlaegt.
"""

from __future__ import annotations

import datetime as dt

from app.gateway.authorize import ToolCall, authorize
from app.models.scan_run import ScanRun


def _agent_call(
    engagement_id, target="metasploitable2", tool="httpx", category="fingerprint",
    scan_run_id=None,
):
    return ToolCall(
        engagement_id=engagement_id, tool=tool, category=category,
        mode="active", target=target, args={}, is_automated=True, phase="agent",
        scan_run_id=scan_run_id,
    )


# --- ai_testing-Gate ------------------------------------------------------

def test_agent_phase_blocked_without_ai_testing_optin(db, lab_engagement):
    """phase='agent' ohne ai_testing_allowed am Auftrag -> fail-closed, jede
    source (hier lab). Der wichtigste Schutz vor versehentlich scharfem Agent."""
    assert lab_engagement.ai_testing_allowed is False
    decision = authorize(db, _agent_call(lab_engagement.id))
    assert not decision.allowed
    assert decision.reason == "ai_testing_not_enabled"


def test_agent_phase_allowed_with_optin(db, lab_engagement):
    lab_engagement.ai_testing_allowed = True
    db.commit()
    run = _running_scan_run(db, lab_engagement.id, budget_max=10)
    decision = authorize(db, _agent_call(lab_engagement.id, scan_run_id=run.id))
    assert decision.allowed, decision.reason


def test_non_agent_phase_unaffected_by_gate(db, lab_engagement):
    """Deterministische Phasen (phase!='agent') sind vom Gate unberuehrt -
    ai_testing_allowed=False darf den normalen Pipeline-Scan nicht blockieren."""
    run = _running_scan_run(db, lab_engagement.id, budget_max=10)
    call = ToolCall(
        engagement_id=lab_engagement.id, tool="nuclei", category="vuln",
        mode="active", target="metasploitable2", args={}, phase="fingerprint",
        scan_run_id=run.id,
    )
    decision = authorize(db, call)
    assert decision.allowed, decision.reason


# --- Budget-Deckel --------------------------------------------------------

def _running_scan_run(db, engagement_id, budget_max):
    run = ScanRun(
        engagement_id=engagement_id, phase="agent", state="running",
        budget_tool_calls_max=budget_max, budget_tool_calls_used=0,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def test_budget_increments_only_on_allow(db, lab_engagement):
    run = _running_scan_run(db, lab_engagement.id, budget_max=10)
    # 3 freigegebene Calls -> used == 3
    for _ in range(3):
        d = authorize(db, ToolCall(
            engagement_id=lab_engagement.id, tool="httpx", category="fingerprint",
            mode="active", target="metasploitable2", args={},
        ))
        assert d.allowed
    db.refresh(run)
    assert run.budget_tool_calls_used == 3

    # Ein abgelehnter Call (out-of-scope) darf KEIN Budget verbrauchen.
    d = authorize(db, ToolCall(
        engagement_id=lab_engagement.id, tool="httpx", category="fingerprint",
        mode="active", target="clean-nginx", args={},
    ))
    assert not d.allowed
    db.refresh(run)
    assert run.budget_tool_calls_used == 3


def test_budget_exhausted_blocks_further_calls(db, lab_engagement):
    run = _running_scan_run(db, lab_engagement.id, budget_max=2)
    reasons = []
    for _ in range(4):
        d = authorize(db, ToolCall(
            engagement_id=lab_engagement.id, tool="httpx", category="fingerprint",
            mode="active", target="metasploitable2", args={},
        ))
        reasons.append((d.allowed, d.reason))
    # Erste zwei ALLOW, danach budget_exhausted (harter Deckel).
    assert reasons[0][0] and reasons[1][0]
    assert reasons[2] == (False, "budget_exhausted")
    assert reasons[3] == (False, "budget_exhausted")
    db.refresh(run)
    assert run.budget_tool_calls_used == 2


def test_no_scan_run_means_no_budget_enforcement(db, lab_engagement):
    """Ohne laufenden scan_run (isolierter Gateway-Aufruf) gilt kein Budget -
    der Check wird sauber uebersprungen, statt zu blockieren."""
    d = authorize(db, ToolCall(
        engagement_id=lab_engagement.id, tool="httpx", category="fingerprint",
        mode="active", target="metasploitable2", args={},
    ))
    assert d.allowed, d.reason


# --- http_request-Primitiv: Gateway erzwingt den nicht-destruktiven envelope ---

def test_http_request_safe_read_is_allowed(db, lab_engagement):
    """Roher HTTP-Lesezugriff mit beliebigen Headern -> erlaubt (in scope,
    vuln-Grant, safe method). Das ist der autonome Pentest-Mehrwert."""
    call = ToolCall(
        engagement_id=lab_engagement.id, tool="http_request", category="vuln",
        mode="active", target="metasploitable2",
        args={"method": "GET", "path": "/api/users", "headers": {"X-Internal": "true"}},
    )
    decision = authorize(db, call)
    assert decision.allowed, decision.reason


def test_http_request_write_without_risk_is_denied(db, lab_engagement):
    """REQ-APPROVAL-002: zustandsaendernder Request OHNE LLM-Risikobewertung ->
    fail-closed (risk_statement_required), keine Freigabe."""
    call = ToolCall(
        engagement_id=lab_engagement.id, tool="http_request", category="vuln",
        mode="active", target="metasploitable2",
        args={"method": "POST", "path": "/api/users"},
    )
    decision = authorize(db, call)
    assert not decision.allowed and decision.reason == "risk_statement_required"


def test_http_request_write_with_risk_becomes_pending(db, lab_engagement):
    """REQ-APPROVAL-001: zustandsaendernder Request in-scope + gueltig + mit Risiko
    -> pending_approval (Freigabe erzeugt), NICHT autonom, NICHT hart-denied."""
    from app.models.approval import ApprovalRequest
    call = ToolCall(
        engagement_id=lab_engagement.id, tool="http_request", category="vuln",
        mode="active", target="metasploitable2",
        args={"method": "POST", "path": "/login", "body": "next=https://evil.com"},
        rationale="Confirm the open redirect by submitting the login form.",
        risk={"level": "medium", "description": "Submits a login form; may create a session but changes no stored data."},
    )
    decision = authorize(db, call)
    assert not decision.allowed and decision.is_pending
    assert decision.approval_request_id is not None
    ap = db.get(ApprovalRequest, decision.approval_request_id)
    assert ap.state == "requested"
    assert ap.tool_call["risk"]["description"]  # Risiko im Payload fuer das Popup
    assert ap.tool_call["args"]["body"] == "next=https://evil.com"


def test_http_request_out_of_scope_still_denied(db, lab_engagement):
    """Scope schlaegt alles: selbst ein safe read auf das deny-Ziel wird
    strukturell geblockt."""
    call = ToolCall(
        engagement_id=lab_engagement.id, tool="http_request", category="vuln",
        mode="active", target="clean-nginx", args={"method": "GET", "path": "/"},
    )
    decision = authorize(db, call)
    assert not decision.allowed
    assert decision.reason == "explicit_out_of_scope"
