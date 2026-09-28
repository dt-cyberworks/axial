"""REQ-HTTP-003: one agent http_request - one gateway decision, and for a
state-changing request one human approval - is exactly one HTTP request.

curl expands `[a-b]` ranges and `{x,y}` lists in a URL into one request per
combination unless --globoff is given, and the http_request validator
deliberately allows those characters (PHP array parameters like `a[]=1` are
legitimate test input). The behavioral test runs the real built command
against a local server and counts what arrives.
"""
from __future__ import annotations

import shlex
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app import tool_runner_client

GLOB_PATHS = ["/item/[1-5]", "/{a,b,c}", "/x?ids[]=1&ids[]=2"]


@pytest.mark.parametrize("path", GLOB_PATHS)
def test_http_request_command_disables_url_globbing(monkeypatch, path):
    monkeypatch.setattr(tool_runner_client, "EGRESS_PROXY_URL", "")
    cmd = tool_runner_client._http_request_command("https://target.example", {"method": "GET", "path": path})
    argv = shlex.split(cmd.split(" | head ")[0])
    assert argv[:2] == ["curl", "--globoff"]
    assert argv[-1] == "https://target.example" + path


class _CountingHandler(BaseHTTPRequestHandler):
    paths: list[str] = []

    def _record(self):
        type(self).paths.append(self.path)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = do_POST = do_DELETE = _record

    def log_message(self, *args):  # keep test output quiet
        pass


@pytest.mark.skipif(shutil.which("curl") is None, reason="needs a real curl binary")
@pytest.mark.parametrize("method", ["GET", "POST", "DELETE"])
@pytest.mark.parametrize("path", ["/item/[1-5]", "/{a,b,c}"])
def test_negative_a_globbing_path_sends_exactly_one_request(monkeypatch, method, path):
    monkeypatch.setattr(tool_runner_client, "EGRESS_PROXY_URL", "")
    _CountingHandler.paths = []
    server = HTTPServer(("127.0.0.1", 0), _CountingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        cmd = tool_runner_client._http_request_command(
            f"http://127.0.0.1:{server.server_port}",
            {"method": method, "path": path, "body": "x=1" if method == "POST" else None},
        )
        subprocess.run(["bash", "-c", cmd], check=False, capture_output=True, timeout=30)
    finally:
        server.shutdown()
        thread.join(timeout=5)
    assert _CountingHandler.paths == [path], _CountingHandler.paths
