"""TC-AGENT-027: dispatch.py's activemq-openwire-probe handler - the
confidence-tiering discipline (callback observed = validated finding;
sent-but-unobserved = explicitly NOT a finding) is the load-bearing behavior
here, mirroring REQ-AGENT-025's "absence is not a finding" pattern.
"""

from __future__ import annotations

from app import openwire_payload, raw_tcp_probe
from app.tasks import dispatch


def _outcome(stdout: str, *, success: bool = True, port: int = 61616, error_reason: str | None = None):
    result = {"success": success, "stdout": stdout, "stderr": "", "error_reason": error_reason}
    return raw_tcp_probe.RawProbeOutcome(result=result, port=port)


def _fake_clock(monkeypatch, *, step: float = 1.0):
    """A controllable fake monotonic clock so the probe's bounded-wait loop
    advances deterministically, in zero real time, instead of busy-spinning
    against the real clock for up to _OPENWIRE_CALLBACK_WAIT_SECONDS."""
    state = {"now": 0.0}

    def fake_monotonic():
        state["now"] += step
        return state["now"]

    monkeypatch.setattr(dispatch.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(dispatch.time, "sleep", lambda *_: None)


def _patch_common(monkeypatch, *, triggered_sequence, execute_result=None):
    monkeypatch.setattr(
        dispatch.client, "create_openwire_callback_token",
        lambda *a, **k: {"token": "tok-123", "callback_url": "https://scan.example/callback/openwire/tok-123", "expires_at": "2026-01-01T00:00:00Z"},
    )
    monkeypatch.setattr(
        raw_tcp_probe, "execute_probe",
        lambda *a, **k: execute_result or _outcome("asm_probe_status=ok\nasm_probe_bytes_read=0\n"),
    )
    calls = iter(triggered_sequence)
    monkeypatch.setattr(dispatch.client, "get_openwire_callback_status", lambda *a, **k: next(calls))
    _fake_clock(monkeypatch)


def test_skips_without_a_materialized_ip():
    obs = dispatch._dispatch_activemq_openwire_probe("019fc77d-ced9-72c6-be50-2335883f0a63", "asset-1", "mq.example", None, "run-1")
    assert "keine materialisierte IP" in obs.summary


def test_a_callback_within_the_wait_window_is_reported_as_a_validated_critical_finding(monkeypatch):
    _patch_common(monkeypatch, triggered_sequence=[{"triggered": True, "triggered_at": "2026-01-01T00:00:05Z"}])
    findings = []
    monkeypatch.setattr(dispatch.client, "add_finding", lambda *a, **k: findings.append(k) or {"id": "f1"})
    monkeypatch.setattr(dispatch.client, "add_service", lambda *a, **k: {"id": "svc-1"})

    obs = dispatch._dispatch_activemq_openwire_probe("019fc77d-ced9-72c6-be50-2335883f0a63", "asset-1", "mq.example", "192.0.2.10", "run-1")

    assert obs.findings == 1
    assert len(findings) == 1
    assert findings[0]["confidence"] == "validated"
    assert findings[0]["severity_override"] == "critical"
    assert findings[0]["cve_ids"] == ["CVE-2023-46604"]
    assert findings[0]["is_kev"] is True
    assert findings[0]["evidence"]["evidence_basis"] == "direct_technical_proof"
    assert "BESTAETIGT" in obs.summary


def test_negative_no_callback_within_the_wait_window_is_not_a_finding(monkeypatch):
    """THE load-bearing negative test: a sent-but-unconfirmed probe must
    never be reported as a finding - patched, egress-filtered, and simply
    slow are all indistinguishable from here, and reporting any of them as
    a critical RCE finding would be exactly the fabricated-evidence failure
    mode REQ-DISCO's work elsewhere this session exists to prevent."""
    _patch_common(monkeypatch, triggered_sequence=[{"triggered": False, "triggered_at": None}] * 20)
    finding_calls = []
    monkeypatch.setattr(dispatch.client, "add_finding", lambda *a, **k: finding_calls.append(1))
    monkeypatch.setattr(dispatch.client, "add_service", lambda *a, **k: {"id": "svc-1"})

    obs = dispatch._dispatch_activemq_openwire_probe("019fc77d-ced9-72c6-be50-2335883f0a63", "asset-1", "mq.example", "192.0.2.10", "run-1")

    assert finding_calls == []
    assert obs.findings == 0
    assert "kein Befund" in obs.summary


def test_a_connect_failure_is_not_a_finding_and_never_polls_for_a_callback(monkeypatch):
    monkeypatch.setattr(
        dispatch.client, "create_openwire_callback_token",
        lambda *a, **k: {"token": "tok-123", "callback_url": "https://scan.example/callback/openwire/tok-123", "expires_at": "2026-01-01T00:00:00Z"},
    )
    monkeypatch.setattr(
        raw_tcp_probe, "execute_probe",
        lambda *a, **k: _outcome("", success=False, error_reason="port_not_in_configured_range"),
    )
    poll_calls = []
    monkeypatch.setattr(dispatch.client, "get_openwire_callback_status", lambda *a, **k: poll_calls.append(1))
    finding_calls = []
    monkeypatch.setattr(dispatch.client, "add_finding", lambda *a, **k: finding_calls.append(1))

    obs = dispatch._dispatch_activemq_openwire_probe("019fc77d-ced9-72c6-be50-2335883f0a63", "asset-1", "mq.example", "192.0.2.10", "run-1")

    assert finding_calls == []
    assert poll_calls == []  # never wasted a poll on a probe that never sent
    assert "port_not_in_configured_range" in obs.summary


def test_the_packet_sent_is_built_from_a_fresh_callback_url_each_call(monkeypatch):
    """Wiring guard: the send bytes must come from openwire_payload, built
    from THIS call's own fresh token - never a stale or hardcoded packet."""
    captured_extra_args = {}

    def fake_execute_probe(*a, **k):
        captured_extra_args.update(k.get("extra_args") or {})
        return _outcome("asm_probe_status=ok\nasm_probe_bytes_read=0\n")

    monkeypatch.setattr(
        dispatch.client, "create_openwire_callback_token",
        lambda *a, **k: {"token": "tok-abc", "callback_url": "https://scan.example/callback/openwire/tok-abc", "expires_at": "2026-01-01T00:00:00Z"},
    )
    monkeypatch.setattr(raw_tcp_probe, "execute_probe", fake_execute_probe)
    monkeypatch.setattr(dispatch.client, "get_openwire_callback_status", lambda *a, **k: {"triggered": False, "triggered_at": None})
    _fake_clock(monkeypatch)

    dispatch._dispatch_activemq_openwire_probe("019fc77d-ced9-72c6-be50-2335883f0a63", "asset-1", "mq.example", "192.0.2.10", "run-1")

    expected = openwire_payload.build_probe_packet("https://scan.example/callback/openwire/tok-abc")
    assert captured_extra_args.get("_send_bytes") == expected


def test_a_status_check_hiccup_stops_polling_without_crashing_the_scan(monkeypatch):
    monkeypatch.setattr(
        dispatch.client, "create_openwire_callback_token",
        lambda *a, **k: {"token": "tok-123", "callback_url": "https://scan.example/callback/openwire/tok-123", "expires_at": "2026-01-01T00:00:00Z"},
    )
    monkeypatch.setattr(raw_tcp_probe, "execute_probe", lambda *a, **k: _outcome("asm_probe_status=ok\nasm_probe_bytes_read=0\n"))

    def _raise(*a, **k):
        raise RuntimeError("control-plane unreachable")

    monkeypatch.setattr(dispatch.client, "get_openwire_callback_status", _raise)
    monkeypatch.setattr(dispatch.time, "sleep", lambda *_: None)
    finding_calls = []
    monkeypatch.setattr(dispatch.client, "add_finding", lambda *a, **k: finding_calls.append(1))

    obs = dispatch._dispatch_activemq_openwire_probe("019fc77d-ced9-72c6-be50-2335883f0a63", "asset-1", "mq.example", "192.0.2.10", "run-1")

    assert finding_calls == []  # a telemetry hiccup must never fabricate a finding
    assert obs.findings == 0
