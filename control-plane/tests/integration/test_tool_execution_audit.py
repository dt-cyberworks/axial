from sqlalchemy import select

from app.api.internal import internal_tool_execution
from app.models.audit import AuditLog
from app.schemas.internal import ToolExecutionEventIn


def test_tool_execution_outcome_is_hash_chained_and_bounded(db, lab_engagement):
    body = ToolExecutionEventIn(
        tool="nmap",
        phase="fingerprint",
        authorized_target="metasploitable2",
        resolved_target="192.0.2.10",
        port_range="default-top-1000",
        success=False,
        exit_code=0,
        error_reason="zero_targets_scanned",
        stderr_summary="No targets were specified",
        discovered_services=0,
        outcome_summary={"protocol": "udp", "states": {"open|filtered": 9}},
    )

    result = internal_tool_execution(lab_engagement.id, body, db)

    assert result == {"ok": True}
    row = db.scalar(
        select(AuditLog).where(
            AuditLog.engagement_id == lab_engagement.id,
            AuditLog.action == "tool_execution",
        )
    )
    assert row.decision == "DENY"
    assert row.reason == "zero_targets_scanned"
    assert row.payload["authorized_target"] == "metasploitable2"
    assert row.payload["resolved_target"] == "192.0.2.10"
    assert row.payload["discovered_services"] == 0
    assert row.payload["outcome_summary"] == {"protocol": "udp", "states": {"open|filtered": 9}}
    assert row.row_hash


def test_tool_execution_records_the_exact_invocation(db, lab_engagement):
    """TC-AUDIT-003: the invocation reaches the durable audit payload, so
    'prove exactly what you ran against my systems' is answerable from the
    audit log alone."""
    command = "ffuf -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt:FUZZ -u https://target/FUZZ -mc 200"
    body = ToolExecutionEventIn(
        tool="ffuf", phase="fingerprint", authorized_target="target",
        success=True, exit_code=0, command=command,
    )

    internal_tool_execution(lab_engagement.id, body, db)

    row = db.scalar(
        select(AuditLog).where(
            AuditLog.engagement_id == lab_engagement.id,
            AuditLog.action == "tool_execution",
        ).order_by(AuditLog.ts.desc())
    )
    assert row.payload["command"] == command


def test_tool_execution_without_an_invocation_records_none(db, lab_engagement):
    """A tool whose invocation could not be rendered records None - never a
    fabricated or partial command (REQ-AUDIT-003)."""
    body = ToolExecutionEventIn(
        tool="nikto", phase="fingerprint", authorized_target="target",
        success=True, exit_code=0,
    )

    internal_tool_execution(lab_engagement.id, body, db)

    row = db.scalar(
        select(AuditLog).where(
            AuditLog.engagement_id == lab_engagement.id,
            AuditLog.action == "tool_execution",
        ).order_by(AuditLog.ts.desc())
    )
    assert row.payload["command"] is None


def test_tool_execution_records_the_full_http_request_response(db, lab_engagement):
    """TC-AUDIT-006: the worker-redacted response reaches the durable audit
    payload alongside the request, so 'prove what my systems sent back' is
    answerable the same way 'prove what you ran' already is."""
    response = "HTTP/1.1 200 OK\nSet-Cookie: <redacted>\nContent-Type: text/html\n\n<html>ok</html>"
    body = ToolExecutionEventIn(
        tool="http_request", phase="agent", authorized_target="target",
        success=True, exit_code=0, response=response,
    )

    internal_tool_execution(lab_engagement.id, body, db)

    row = db.scalar(
        select(AuditLog).where(
            AuditLog.engagement_id == lab_engagement.id,
            AuditLog.action == "tool_execution",
        ).order_by(AuditLog.ts.desc())
    )
    assert row.payload["response"] == response


def test_tool_execution_without_a_response_records_none(db, lab_engagement):
    """Every non-http_request tool, and a failed http_request call, leaves
    response absent rather than an empty string or a fabricated one."""
    body = ToolExecutionEventIn(
        tool="nmap", phase="fingerprint", authorized_target="target",
        success=True, exit_code=0,
    )

    internal_tool_execution(lab_engagement.id, body, db)

    row = db.scalar(
        select(AuditLog).where(
            AuditLog.engagement_id == lab_engagement.id,
            AuditLog.action == "tool_execution",
        ).order_by(AuditLog.ts.desc())
    )
    assert row.payload["response"] is None


def test_oversized_invocation_is_rejected_before_durable_storage(db, lab_engagement):
    """The control-plane never trusts a client-supplied length for something it
    writes into the append-only, hash-chained audit table."""
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ToolExecutionEventIn(
            tool="ffuf", phase="fingerprint", authorized_target="target",
            success=True, exit_code=0, command="x" * 4001,
        )
