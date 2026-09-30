"""TC-AUDIT-003: the exact invocation is captured for both dispatch paths.

The worker has two of them and they behave differently, so both need cover:
  - `_COMMANDS` tools build a literal shell command and POST it to the
    runner's generic /api/command;
  - `_ENDPOINTS` tools POST a structured body to a per-tool HexStrike route,
    which builds the CLI server-side - there is no literal command to capture,
    so the body IS the invocation spec.
"""

from __future__ import annotations

from app import tool_execution
from app import tool_runner_client as trc

# Everything is referenced through `trc.` at CALL time, never bound at import
# time: test_runner_auth_header.py calls importlib.reload(trc), which rebinds
# the module's ToolRunnerClient class and its `tool_runner` singleton. A
# module-level `from ... import tool_runner` here would keep the pre-reload
# instance while monkeypatch patched the post-reload class, so the patch would
# silently not apply and the call would take the raw_egress_unavailable early
# return instead (found exactly that way - passed alone, failed in the suite).


def _fake_response(payload: dict):
    class R:
        def raise_for_status(self):
            return None

        def json(self):
            return payload

    return R()


# --- literal-command path ---------------------------------------------------

def test_command_path_captures_the_real_invocation(monkeypatch):
    captured = {}

    def fake_post(path, payload, scan_run_id):
        captured["path"], captured["payload"] = path, payload
        return _fake_response({"stdout": "ok", "return_code": 0, "success": True})

    monkeypatch.setattr(trc.ToolRunnerClient, "_post_cancellable", lambda self, p, pl, s, b=None: fake_post(p, pl, s))

    result = trc.tool_runner.run("ffuf", "https://target.example.com", {"wordlist": "quickhits"})

    assert captured["path"] == "/api/command"
    assert result["command"], "no invocation captured"
    assert "ffuf" in result["command"]
    # the wordlist actually used is exactly the kind of detail this exists for
    assert "quickhits" in result["command"]


def test_captured_command_matches_what_was_actually_sent(monkeypatch):
    """Guards the drift risk: the logged invocation must be the same builder's
    output as the executed one, not a separate rendering."""
    captured = {}

    def fake_post(self, path, payload, scan_run_id, budget_s=None):
        captured["payload"] = payload
        return _fake_response({"stdout": "", "return_code": 0, "success": True})

    monkeypatch.setattr(trc.ToolRunnerClient, "_post_cancellable", fake_post)

    result = trc.tool_runner.run("httpx", "https://target.example.com", {})

    # No secrets in these args, so the logged and executed commands are equal.
    assert result["command"] == captured["payload"]["command"]


# --- HexStrike structured-body path ----------------------------------------

def test_endpoint_path_captures_the_structured_body(monkeypatch):
    """nmap has no literal command here - HexStrike builds the CLI from this
    body, so the body is what must be recorded (not an empty command)."""
    monkeypatch.setattr(trc.ToolRunnerClient, "raw_network_available", staticmethod(lambda: True))
    monkeypatch.setattr(
        trc.ToolRunnerClient, "_post_cancellable",
        lambda self, p, pl, s, b=None: _fake_response({"stdout": "", "return_code": 0, "success": True}),
    )

    args = {"stage": "discovery", "flags": ["-sS"], "ports": "1-65535", "max_rate": 500}
    result = trc.tool_runner.run("nmap", "target.example.com", args)

    assert result["command"], "structured-body invocation was not captured"
    assert "/api/tools/nmap" in result["command"]
    assert "target.example.com" in result["command"]
    # the scan profile actually used is the detail an operator needs to see
    assert "1-65535" in result["command"]
    assert "500" in result["command"]


# --- bounding + best-effort contract ---------------------------------------

def test_invocation_is_truncated_before_storage():
    huge = {"method": "GET", "path": "/" + ("a" * 9000), "headers": {}}
    rendered = trc._audit_invocation(trc._http_request_command, "target.example.com", huge)
    assert len(rendered) <= trc.AUDIT_COMMAND_MAX_CHARS


def test_capture_failure_yields_none_and_never_raises():
    """REQ-AUDIT-003: telemetry must never change a tool's outcome."""
    def exploding_builder(target, args):
        raise RuntimeError("builder blew up")

    assert trc._audit_invocation(exploding_builder, "target.example.com", {}) is None


def test_record_forwards_the_command_to_the_control_plane(monkeypatch):
    sent = {}
    monkeypatch.setattr(tool_execution.client, "record_tool_execution",
                        lambda eid, **fields: sent.update(fields))

    tool_execution.record(
        "11111111-1111-1111-1111-111111111111",
        scan_run_id=None, tool="ffuf", phase="fingerprint",
        authorized_target="target.example.com", resolved_target=None, port_range="443",
        result={"success": True, "exit_code": 0, "command": "ffuf -w list -u https://x/FUZZ"},
    )

    assert sent["command"] == "ffuf -w list -u https://x/FUZZ"


def test_record_tolerates_a_result_without_a_command(monkeypatch):
    """A tool whose invocation could not be rendered records None, not a
    fabricated command - and recording still succeeds."""
    sent = {}
    monkeypatch.setattr(tool_execution.client, "record_tool_execution",
                        lambda eid, **fields: sent.update(fields))

    tool_execution.record(
        "11111111-1111-1111-1111-111111111111",
        scan_run_id=None, tool="nikto", phase="fingerprint",
        authorized_target="target.example.com", resolved_target=None, port_range="443",
        result={"success": True, "exit_code": 0},
    )

    assert sent["command"] is None
