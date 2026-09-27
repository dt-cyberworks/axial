"""REQ-AGENT-027: activemq-openwire-probe is unconditionally state-changing,
exactly like http_request's own POST/PUT - mandatory per-call approval that
cannot be disabled by ToolGrant configuration, and a required risk statement.
R4: positive AND negative tests (CLAUDE.md)."""

from __future__ import annotations

from app.gateway.authorize import ToolCall, authorize


def _probe_call(eng, with_risk=True, target="metasploitable2"):
    return ToolCall(
        engagement_id=eng.id, tool="activemq-openwire-probe", category="vuln", mode="active",
        target=target, args={},
        rationale="confirm CVE-2023-46604",
        risk={"level": "high", "description": "attempts to trigger OpenWire deserialization RCE"} if with_risk else None,
    )


def test_a_probe_with_a_risk_statement_creates_a_pending_approval_not_an_autonomous_run(db, lab_engagement):
    d = authorize(db, _probe_call(lab_engagement))
    assert not d.allowed
    assert d.is_pending
    assert d.approval_request_id is not None


def test_negative_a_probe_without_a_risk_statement_is_denied_not_pending(db, lab_engagement):
    """Unlike a passive tool, this must never silently run - and must never
    even reach the pending-approval state without an honest risk assessment,
    exactly like http_request's own POST/PUT."""
    d = authorize(db, _probe_call(lab_engagement, with_risk=False))
    assert not d.allowed
    assert not d.is_pending
    assert d.reason == "risk_statement_required"


def test_negative_an_out_of_scope_target_is_hard_denied_not_pending(db, lab_engagement):
    """A deny/out-of-scope target must never become a pending approval a
    careless operator could accidentally click through - it is blocked
    before the approval mechanism is even reached."""
    d = authorize(db, _probe_call(lab_engagement, target="not-in-scope.example"))
    assert not d.allowed
    assert not d.is_pending


def test_negative_a_grants_own_requires_manual_approval_false_does_not_bypass_the_mandatory_gate(db, lab_engagement):
    """THE load-bearing negative test: this tool's approval requirement
    comes from the HARDCODED state_changing check, not from ToolGrant.
    requires_manual_approval - so an operator (or a bug) setting that grant
    field to False must NOT be able to make this tool run autonomously."""
    from app.models.engagement import ToolGrant

    grant = db.query(ToolGrant).filter(
        ToolGrant.engagement_id == lab_engagement.id, ToolGrant.tool_category == "vuln", ToolGrant.mode == "active",
    ).one()
    grant.requires_manual_approval = False
    db.commit()

    d = authorize(db, _probe_call(lab_engagement))

    assert not d.allowed
    assert d.is_pending, "approval must still be required even with the grant's own flag set to False"
