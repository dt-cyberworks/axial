"""REQ-AGENT-025 / TC-AGENT-025: dispatch.py's redis-probe/activemq-banner
handlers - output parsing, finding/service persistence, and the honest
"skip, don't fabricate" behaviour when no materialized IP exists yet.
"""

from __future__ import annotations

from app import raw_tcp_probe
from app.tasks import dispatch


def _outcome(stdout: str, *, success: bool = True, port: int = 6379, error_reason: str | None = None):
    result = {"success": success, "stdout": stdout, "stderr": "", "error_reason": error_reason}
    return raw_tcp_probe.RawProbeOutcome(result=result, port=port)


# --- _parse_raw_probe --------------------------------------------------------

def test_parse_raw_probe_extracts_status_and_payload():
    result = {"stdout": "asm_probe_status=ok\nasm_probe_bytes_read=7\n+PONG\n"}
    status, text = dispatch._parse_raw_probe(result)
    assert status == "ok"
    assert text == "+PONG"


def test_parse_raw_probe_handles_connect_failure_with_no_payload():
    result = {"stdout": "asm_probe_status=connect_failed:ConnectionRefusedError"}
    status, text = dispatch._parse_raw_probe(result)
    assert status == "connect_failed:ConnectionRefusedError"
    assert text == ""


def test_parse_raw_probe_handles_missing_result():
    status, text = dispatch._parse_raw_probe(None)
    assert status == "connect_failed:unknown"
    assert text == ""


# --- redis-probe -------------------------------------------------------------

def test_redis_probe_skips_without_a_materialized_ip():
    obs = dispatch._dispatch_redis_probe("eid", "asset-1", "redis.example", None, "run-1")
    assert "keine materialisierte IP" in obs.summary


def test_redis_probe_reports_unauthenticated_pong_as_a_high_severity_finding(monkeypatch):
    monkeypatch.setattr(raw_tcp_probe, "execute_probe",
                        lambda *a, **k: _outcome("asm_probe_status=ok\nasm_probe_bytes_read=7\n+PONG\n"))
    findings = []
    monkeypatch.setattr(dispatch.client, "add_finding", lambda *a, **k: findings.append(k) or {"id": "f1"})
    monkeypatch.setattr(dispatch.client, "add_service", lambda *a, **k: {"id": "svc-1"})

    obs = dispatch._dispatch_redis_probe("eid", "asset-1", "redis.example", "192.0.2.10", "run-1")

    assert obs.findings == 1
    assert findings[0]["severity_override"] == "high"
    assert findings[0]["confidence"] == "validated"
    assert "Unauthenticated" in findings[0]["title"]


def test_redis_probe_does_not_report_a_finding_when_auth_is_required(monkeypatch):
    monkeypatch.setattr(raw_tcp_probe, "execute_probe",
                        lambda *a, **k: _outcome("asm_probe_status=ok\nasm_probe_bytes_read=30\n-NOAUTH Authentication required.\n"))
    findings = []
    monkeypatch.setattr(dispatch.client, "add_finding", lambda *a, **k: findings.append(k) or {"id": "f1"})
    monkeypatch.setattr(dispatch.client, "add_service", lambda *a, **k: {"id": "svc-1"})

    obs = dispatch._dispatch_redis_probe("eid", "asset-1", "redis.example", "192.0.2.10", "run-1")

    assert obs.findings == 0
    assert findings == []  # correctly protected - not a finding


def test_redis_probe_reports_nothing_executed_when_lease_denied(monkeypatch):
    monkeypatch.setattr(raw_tcp_probe, "execute_probe",
                        lambda *a, **k: _outcome("", success=False, error_reason="port_not_in_configured_range"))
    finding_calls = []
    monkeypatch.setattr(dispatch.client, "add_finding", lambda *a, **k: finding_calls.append(1))

    obs = dispatch._dispatch_redis_probe("eid", "asset-1", "redis.example", "192.0.2.10", "run-1")

    assert finding_calls == []
    assert "port_not_in_configured_range" in obs.summary


def test_redis_probe_no_response_is_not_a_finding(monkeypatch):
    monkeypatch.setattr(raw_tcp_probe, "execute_probe",
                        lambda *a, **k: _outcome("asm_probe_status=connect_failed:ConnectionRefusedError"))
    finding_calls = []
    monkeypatch.setattr(dispatch.client, "add_finding", lambda *a, **k: finding_calls.append(1))

    obs = dispatch._dispatch_redis_probe("eid", "asset-1", "redis.example", "192.0.2.10", "run-1")

    assert finding_calls == []
    assert obs.findings == 0


# --- activemq-banner ----------------------------------------------------------

def test_activemq_banner_skips_without_a_materialized_ip():
    obs = dispatch._dispatch_activemq_banner("eid", "asset-1", "mq.example", None, "run-1")
    assert "keine materialisierte IP" in obs.summary


def test_activemq_banner_reports_a_finding_on_any_readable_greeting(monkeypatch):
    monkeypatch.setattr(
        raw_tcp_probe, "execute_probe",
        lambda *a, **k: _outcome("asm_probe_status=ok\nasm_probe_bytes_read=40\nActiveMQ-OpenWire-5.18.2", port=61616),
    )
    findings = []
    monkeypatch.setattr(dispatch.client, "add_finding", lambda *a, **k: findings.append(k) or {"id": "f1"})
    monkeypatch.setattr(dispatch.client, "add_service", lambda *a, **k: {"id": "svc-1"})

    obs = dispatch._dispatch_activemq_banner("eid", "asset-1", "mq.example", "192.0.2.10", "run-1")

    assert obs.findings == 1
    assert findings[0]["severity_override"] == "medium"
    assert findings[0]["confidence"] == "validated"
    assert "ActiveMQ-OpenWire-5.18.2" in findings[0]["evidence"]["banner"]


def test_activemq_banner_no_greeting_is_not_a_finding(monkeypatch):
    monkeypatch.setattr(raw_tcp_probe, "execute_probe",
                        lambda *a, **k: _outcome("asm_probe_status=connect_failed:TimeoutError"))
    finding_calls = []
    monkeypatch.setattr(dispatch.client, "add_finding", lambda *a, **k: finding_calls.append(1))

    obs = dispatch._dispatch_activemq_banner("eid", "asset-1", "mq.example", "192.0.2.10", "run-1")

    assert finding_calls == []
    assert obs.findings == 0
