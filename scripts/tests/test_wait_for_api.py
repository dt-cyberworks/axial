"""REQ-INSTALL-001: `make up` waits until the API answers.

Found on 2026-10-01 by typing the published guide's commands one after another on a clean
machine: `make up` returned as soon as the containers were STARTED, and the guide's next step
(`curl --fail http://localhost:8000/health`) failed with "Connection reset by peer". The install
smoke test had a wait loop that hid it. These tests run the real script against a real local
HTTP server that only starts answering after a delay."""

from __future__ import annotations

import http.server
import os
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "wait_for_api.sh"
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _Health(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, *_):  # quiet
        pass


def _serve_after(port: int, delay: float) -> threading.Thread:
    def run():
        time.sleep(delay)
        server = http.server.HTTPServer(("127.0.0.1", port), _Health)
        server.timeout = 0.5
        deadline = time.time() + 30
        while time.time() < deadline:
            server.handle_request()
        server.server_close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def _run(url: str, seconds: int) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(SCRIPT), url], capture_output=True, text=True, timeout=60,
                          env={**os.environ, "WAIT_SECONDS": str(seconds)})


def test_it_waits_for_an_api_that_starts_late_and_then_returns_success():
    port = _free_port()
    _serve_after(port, delay=3)                      # nothing listens for the first 3 seconds
    started = time.time()
    result = _run(f"http://127.0.0.1:{port}/health", seconds=30)
    assert result.returncode == 0, result.stderr
    assert time.time() - started >= 2.5, "it must really have waited for the late start"
    assert "up" in result.stdout


def test_negative_it_gives_up_with_a_pointer_when_the_api_never_answers():
    result = _run(f"http://127.0.0.1:{_free_port()}/health", seconds=4)
    assert result.returncode == 1
    assert "did not answer within 4s" in result.stderr and "docker compose logs control-plane" in result.stderr


def test_negative_a_server_that_answers_with_an_error_status_is_not_ready():
    class _Broken(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(503)
            self.end_headers()

        def log_message(self, *_):
            pass

    port = _free_port()
    server = http.server.HTTPServer(("127.0.0.1", port), _Broken)
    threading.Thread(target=lambda: [server.handle_request() for _ in range(10)], daemon=True).start()
    result = _run(f"http://127.0.0.1:{port}/health", seconds=4)
    server.server_close()
    assert result.returncode == 1


def test_make_up_runs_the_wait_after_starting_the_stack():
    recipe = MAKEFILE.split("\nup: env", 1)[1].split("\n\n", 1)[0]
    assert "docker compose up -d --build" in recipe
    assert "scripts/wait_for_api.sh" in recipe
    assert recipe.index("docker compose up -d --build") < recipe.index("scripts/wait_for_api.sh")


def test_the_script_is_executable_and_valid_shell():
    assert SCRIPT.stat().st_mode & 0o111
    assert subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True).returncode == 0


def test_the_smoke_test_checks_health_immediately_after_make_up_without_waiting():
    """A wait loop in the smoke test is what hid the race; the guide's reader does not wait."""
    smoke = (ROOT / "scripts" / "install_smoke.sh").read_text()
    block = smoke.split("start and verify the backend (make up)", 1)[1].split("the first administrator", 1)[0]
    assert "run make up" in block and "wait_for" not in block, "no wait loop between `make up` and the first health check"
    assert "curl --fail --silent --show-error" in block and "right after make up" in block
