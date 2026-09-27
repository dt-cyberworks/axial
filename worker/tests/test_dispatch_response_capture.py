"""TC-AUDIT-006/007: dispatch.py threads the full, redacted http_request
response into tool_execution.record() and reuses that same redacted text for
the LLM-facing Observation - one redaction site, no drift between what the
model sees and what durable audit storage records.
"""

from __future__ import annotations

from app.tasks import dispatch


def _stub_record(calls):
    def record(*args, **kwargs):
        calls.append(kwargs)
    return record


def test_a_successful_http_request_threads_the_redacted_response_into_tool_execution(monkeypatch):
    calls = []
    monkeypatch.setattr(dispatch.tool_execution, "record", _stub_record(calls))
    raw = "HTTP/1.1 200 OK\nSet-Cookie: PHPSESSID=deadbeefcafe1234\n\n<html>ok</html>"
    monkeypatch.setattr(
        dispatch.tool_runner, "run",
        lambda tool, target, args, scan_run_id=None, engagement_id=None: {"success": True, "exit_code": 0, "stdout": raw, "stderr": ""},
    )

    obs = dispatch.dispatch(
        "eid", "asset-1", "http_request", "target.example",
        args={"method": "GET", "path": "/"}, single_port=443,
    )

    assert len(calls) == 1
    response = calls[0]["response"]
    assert response is not None
    assert "deadbeefcafe1234" not in response
    assert "<html>ok</html>" in response
    # The SAME redacted text is what the LLM-facing Observation carries - no
    # second, independently-truncated copy that could drift out of sync.
    assert "deadbeefcafe1234" not in obs.as_text()
    assert "<html>ok</html>" in obs.as_text()


def test_a_non_http_request_tool_never_gets_a_response_field(monkeypatch):
    calls = []
    monkeypatch.setattr(dispatch.tool_execution, "record", _stub_record(calls))
    monkeypatch.setattr(
        dispatch.tool_runner, "run",
        lambda tool, target, args, scan_run_id=None, engagement_id=None: {"success": True, "exit_code": 0, "stdout": "some raw nikto output", "stderr": ""},
    )
    monkeypatch.setattr(dispatch, "parse_nikto_missing_headers", lambda stdout: [])
    monkeypatch.setattr(dispatch.client, "add_service", lambda *a, **k: {"id": "svc-1"})

    dispatch.dispatch("eid", "asset-1", "nikto", "target.example", single_port=443)

    assert len(calls) == 1
    assert calls[0]["response"] is None


def test_a_failed_http_request_never_records_a_partial_response(monkeypatch):
    calls = []
    monkeypatch.setattr(dispatch.tool_execution, "record", _stub_record(calls))
    monkeypatch.setattr(
        dispatch.tool_runner, "run",
        lambda tool, target, args, scan_run_id=None, engagement_id=None: {
            "success": False, "exit_code": -1, "stdout": "", "stderr": "timeout", "error_reason": "runner_timeout",
        },
    )

    dispatch.dispatch("eid", "asset-1", "http_request", "target.example",
                       args={"method": "GET", "path": "/"}, single_port=443)

    assert len(calls) == 1
    assert calls[0]["response"] is None


def test_negative_a_login_response_cookie_never_reaches_the_observation_or_the_record(monkeypatch):
    """Realistic shape of the live bug found on int 2026-08-10."""
    calls = []
    monkeypatch.setattr(dispatch.tool_execution, "record", _stub_record(calls))
    session = "9c9ecb61c44cb62b7d9d83bd30ceb70c"
    raw = f"HTTP/1.1 302 Found\nSet-Cookie: ocqycf4p1g88={session}; Path=/; HttpOnly\nLocation: /dashboard\n\n"
    monkeypatch.setattr(
        dispatch.tool_runner, "run",
        lambda tool, target, args, scan_run_id=None, engagement_id=None: {"success": True, "exit_code": 0, "stdout": raw, "stderr": ""},
    )

    obs = dispatch.dispatch("eid", "asset-1", "http_request", "target.example",
                             args={"method": "POST", "path": "/login", "body": "user=x&password=y"}, single_port=443)

    assert session not in calls[0]["response"]
    assert session not in obs.as_text()
