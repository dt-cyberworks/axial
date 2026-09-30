"""REQ-PIPE-012: the throughput measurement is repeatable and safe to run.

The parts that run inside containers are checked against a fake proxy on
localhost, so the script's own logic (request counting, status accounting,
percentiles, argument bounds) is verified without Docker."""

from __future__ import annotations

import json
import socketserver
import subprocess
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import measure_egress_throughput as m  # noqa: E402


class _FakeProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _serve(deny_hosts=()):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                data += chunk
            first = data.split(b"\r\n", 1)[0].decode()
            if any(h in first for h in deny_hosts):
                self.request.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                return
            if first.startswith("CONNECT"):
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                self.request.recv(4096)
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    server = _FakeProxy(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _loadgen(port, mode, requests, concurrency, engagement=""):
    args = ["127.0.0.1", str(port), "t.test", "80", mode, str(requests), str(concurrency)] + ([engagement] if engagement else [])
    out = subprocess.run([sys.executable, "-c", m.LOADGEN, *args], capture_output=True, text=True, timeout=60, check=True).stdout
    return json.loads(out.strip().splitlines()[-1])


@pytest.mark.parametrize("mode", ["connect", "http"])
@pytest.mark.parametrize("concurrency", [1, 4])
def test_req_pipe_012_the_load_generator_counts_every_request_and_reports_the_rate(mode, concurrency):
    server = _serve()
    try:
        row = _loadgen(server.server_address[1], mode, 40, concurrency)
    finally:
        server.shutdown()
    assert row["requests"] == 40 and row["concurrency"] == concurrency
    assert row["statuses"] == {"200": 40}
    assert row["rps"] > 0 and 0 < row["p50_ms"] <= row["p95_ms"] <= row["max_ms"]


def test_req_pipe_012_a_denied_request_is_counted_as_its_status_not_as_success():
    server = _serve(deny_hosts=("t.test",))
    try:
        row = _loadgen(server.server_address[1], "connect", 10, 2, engagement="11111111-1111-1111-1111-111111111111")
    finally:
        server.shutdown()
    assert row["statuses"] == {"403": 10}


def test_negative_req_pipe_012_an_unreachable_proxy_is_an_error_count_never_a_crash():
    row = _loadgen(9, "connect", 5, 1)
    assert sum(row["statuses"].values()) == 5 and "200" not in row["statuses"]


def test_req_pipe_012_the_in_container_scripts_compile():
    compile(m.LOADGEN, "loadgen", "exec")
    compile(m.STAGES, "stages", "exec")
    assert "submit_audit" in m.STAGES and "getaddrinfo" in m.STAGES, "the stages it names are the ones measured"


@pytest.mark.parametrize("argv", [["--requests", "0"], ["--requests", "5000"], ["--concurrency", "64"], ["--concurrency", ""]])
def test_negative_req_pipe_012_the_run_size_is_bounded(argv, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["measure", *argv])
    monkeypatch.setattr(m, "start_target", lambda: pytest.fail("must not start anything for an invalid size"))
    with pytest.raises(SystemExit):
        m.main()


def test_req_pipe_012_the_measurement_never_touches_a_real_target():
    """The target is a throwaway container on the egress network with a synthetic name."""
    assert m.TARGET_HOST.endswith(".test") and m.TARGET_HOST != "cloud.example.com"
    text = (ROOT / "scripts" / "measure_egress_throughput.py").read_text()
    assert "nginx:alpine" in text and "--rm" in text
    assert "delete_engagement(engagement)" in text, "the synthetic engagement is removed even if a step fails"
