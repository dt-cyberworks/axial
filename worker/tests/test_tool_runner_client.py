"""TC-FIDELITY-001: a single failed cancellation-status poll must not kill an
otherwise-healthy, long-running tool call. Only sustained, consecutive
unavailability fails closed. A genuine cancel is still honored immediately."""

from __future__ import annotations

import time
from types import SimpleNamespace

from app import tool_runner_client as trc

_RUN_ID = "22222222-2222-2222-2222-222222222222"


def _runner(monkeypatch, delay: float, response):
    runner = trc.ToolRunnerClient()
    monkeypatch.setattr(
        runner._client, "post",
        lambda path, json=None, headers=None: (time.sleep(delay), response)[1],
    )
    monkeypatch.setattr(trc, "CANCEL_POLL_SECONDS", 0.05)
    monkeypatch.setattr(trc, "CANCEL_STATUS_FAILURE_TOLERANCE", 3)
    monkeypatch.setattr(runner, "_terminate_scan_run", lambda *a, **k: None)
    return runner


def test_single_transient_failure_does_not_kill_the_tool(monkeypatch):
    # The dispatch thread's response arrives well after a few polls happen.
    response = SimpleNamespace(status_code=200)
    runner = _runner(monkeypatch, delay=0.3, response=response)

    calls = {"n": 0}

    def flaky(scan_run_id):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient control-plane blip")
        return False  # not cancelled

    monkeypatch.setattr(trc, "_cancel_requested", flaky)

    out = runner._post_cancellable("/api/tools/nikto", {}, _RUN_ID)

    assert out is response  # real tool result, NOT a cancelled result
    assert calls["n"] >= 2  # the failing poll plus at least one recovering poll


def test_sustained_consecutive_failures_still_fail_closed(monkeypatch):
    response = SimpleNamespace(status_code=200)
    runner = _runner(monkeypatch, delay=5.0, response=response)  # never arrives in time

    def always_fails(scan_run_id):
        raise RuntimeError("control-plane down")

    monkeypatch.setattr(trc, "_cancel_requested", always_fails)

    out = runner._post_cancellable("/api/tools/nikto", {}, _RUN_ID)

    assert out["success"] is False
    assert out["error_reason"] == "cancellation_status_unavailable"


def test_genuine_cancel_is_still_honored_immediately(monkeypatch):
    response = SimpleNamespace(status_code=200)
    runner = _runner(monkeypatch, delay=5.0, response=response)
    monkeypatch.setattr(trc, "_cancel_requested", lambda scan_run_id: True)

    out = runner._post_cancellable("/api/tools/nikto", {}, _RUN_ID)

    assert out["success"] is False
    assert out["error_reason"] == "cancelled_by_operator"


# --- _httpx_command: fixed 2026-08-03 (a second, independent https://
# fallback here silently defeated target_envelope.httpx_target's whole
# point), then REQ-FIDELITY-010 (2026-08-04) changed what httpx_target itself
# now sends - always an explicit http://, never schemeless. This function's
# own contract (never mutate whatever scheme the caller built) is unchanged
# and still worth locking down independently of what its current caller
# happens to send. ---

def test_httpx_command_does_not_force_a_scheme_onto_a_schemeless_target(monkeypatch):
    """No current caller sends this shape (httpx_target always includes a
    scheme now), but _httpx_command's own contract - never second-guess the
    caller - must hold regardless."""
    monkeypatch.setattr(trc, "EGRESS_PROXY_URL", "")
    cmd = trc._httpx_command("dvwa.bench.internal:18080", {})
    assert "-u dvwa.bench.internal:18080 " in cmd
    assert "https://" not in cmd


def test_httpx_command_preserves_an_explicit_scheme(monkeypatch):
    monkeypatch.setattr(trc, "EGRESS_PROXY_URL", "")
    cmd = trc._httpx_command("https://host.example.com:8443", {})
    assert "-u https://host.example.com:8443 " in cmd


def test_httpx_command_preserves_explicit_http_scheme_too(monkeypatch):
    monkeypatch.setattr(trc, "EGRESS_PROXY_URL", "")
    cmd = trc._httpx_command("http://host.example.com:8080", {})
    assert "-u http://host.example.com:8080 " in cmd


# --- REQ-AGENT-025: curated raw-protocol probe command builders ------------

def test_redis_probe_command_sends_ping_and_nothing_else():
    cmd = trc._redis_probe_command("192.0.2.10", {"port": 6379})
    assert "python3 -c" in cmd
    # shlex.quote() re-escapes the inner repr()'s own quotes, so check content
    # survived rather than matching the exact (now-mangled) quote characters.
    assert "sendall" in cmd and "PING" in cmd and r"\r\n" in cmd
    assert "192.0.2.10" in cmd
    assert "6379" in cmd


def test_activemq_banner_command_sends_no_payload():
    """Purely passive - the generated script must contain no sendall() call
    at all, not merely an empty one, since OpenWire self-announces."""
    cmd = trc._activemq_banner_command("192.0.2.10", {"port": 61616})
    assert "sendall" not in cmd
    assert "192.0.2.10" in cmd
    assert "61616" in cmd


def test_raw_tcp_probe_command_is_bounded_by_an_outer_timeout():
    cmd = trc._redis_probe_command("192.0.2.10", {"port": 6379})
    assert cmd.startswith("timeout 8 python3 -c")


def test_raw_tcp_probe_command_requires_a_valid_port():
    import pytest

    with pytest.raises(ValueError, match="port"):
        trc._redis_probe_command("192.0.2.10", {})
    with pytest.raises(ValueError, match="port"):
        trc._redis_probe_command("192.0.2.10", {"port": 70000})
    with pytest.raises(ValueError, match="port"):
        trc._redis_probe_command("192.0.2.10", {"port": 0})


def test_raw_tcp_probe_command_rejects_an_unsafe_target():
    import pytest

    with pytest.raises(ValueError, match="unsicheres Ziel"):
        trc._redis_probe_command("192.0.2.10; rm -rf /", {"port": 6379})


def test_raw_tcp_probe_host_reaches_the_generated_script():
    """_safe_target's regex (^[A-Za-z0-9][A-Za-z0-9.:/_-]{0,253}$) already
    excludes every character that could break out of a Python string literal
    (no quotes, no backslash) - this confirms a realistic hostname survives
    through repr() and shlex.quote() intact, end to end."""
    cmd = trc._redis_probe_command("host-with-dash.bench.internal", {"port": 6379})
    assert "host-with-dash.bench.internal" in cmd


# --- Live execution against a real local socket -----------------------------
# The generated command is a hand-built multi-line Python source string - a
# syntax/indentation slip does not raise anywhere upstream (shlex.quote and
# ValueError checks only validate the WRAPPING, never the generated code
# itself). Found live 2026-08-04: an earlier version indented s.sendall(...)
# to match the preceding except-block, silently making it dead code (never
# ran on a successful connect) - and separately, mixing print() with
# sys.stdout.buffer.write() reordered output under a piped stdout, breaking
# dispatch.py's parser. Neither was caught by string-content assertions
# alone; both were only caught by actually running the script.

def _run_probe_command(cmd: str) -> str:
    import subprocess

    result = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    return result.stdout


def _local_server(reply: bytes | None = None, *, expect_recv: bool = False):
    """Starts a one-shot TCP server on an ephemeral port; returns (port, thread).
    If expect_recv, waits to receive data before replying (proves the probe
    actually sent something, not just that it connected)."""
    import socket
    import threading

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    received = {}

    def serve():
        conn, _ = srv.accept()
        if expect_recv:
            received["data"] = conn.recv(100)
        if reply:
            conn.sendall(reply)
        import time
        time.sleep(0.3)
        conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    import time
    time.sleep(0.2)
    return port, thread, received


def test_redis_probe_actually_sends_ping_and_captures_the_reply():
    port, thread, received = _local_server(b"+PONG\r\n", expect_recv=True)
    cmd = trc._redis_probe_command("127.0.0.1", {"port": port})

    stdout = _run_probe_command(cmd)

    thread.join(timeout=2)
    assert received.get("data") == b"PING\r\n", "the PING was never actually sent - regression of the indentation bug"
    assert "asm_probe_status=ok" in stdout
    assert "asm_probe_bytes_read=7" in stdout
    assert stdout.endswith("+PONG\n")


def test_activemq_banner_actually_reads_a_passive_greeting():
    port, thread, _ = _local_server(b"OpenWire-Greeting-v5.18.2\x00\x01\x02binary")
    cmd = trc._activemq_banner_command("127.0.0.1", {"port": port})

    stdout = _run_probe_command(cmd)

    assert "asm_probe_status=ok" in stdout
    assert "OpenWire-Greeting-v5.18.2" in stdout
    # binary junk (\x00\x01\x02) must not appear - only the printable extract
    assert "\x00" not in stdout


def test_raw_tcp_probe_reports_connect_refused_cleanly():
    import socket

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.close()  # bound-then-closed port: nothing listening, connection refused

    cmd = trc._redis_probe_command("127.0.0.1", {"port": port})
    stdout = _run_probe_command(cmd)

    assert stdout.startswith("asm_probe_status=connect_failed:")
    assert "asm_probe_bytes_read" not in stdout
