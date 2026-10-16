"""Minimal tool runner for the lab test loop.

For this live test it deliberately replaces the full HexStrike/Kali
integration (runner.Dockerfile) with a slim HTTP server offering exactly the
two tools the lab test loop needs: nmap (service scan) and a simple HTTP
security-header check.

Only gateway-approved calls reach this server at all (see
worker/app/tasks/fingerprint.py: client.authorize() first, then dispatch).
The server still validates its input on its own (defense in depth, no trust in
the caller) - the same stance as the egress proxy.
"""

from __future__ import annotations

import json
import re
import subprocess
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TARGET_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,253}$")
ALLOWED_NMAP_FLAGS = {"-sV", "-sS"}


def _run_nmap(target: str, args: dict) -> dict:
    if not TARGET_RE.match(target):
        return {"error": "invalid target", "stdout": ""}
    flags = [f for f in args.get("flags", ["-sV"]) if f in ALLOWED_NMAP_FLAGS] or ["-sV"]
    # --version-light haelt die Sondierung pro Port kurz; volle -sV ueber
    # 1000 Standardports kann sonst pro Ziel deutlich ueber 30s dauern.
    cmd = ["nmap", *flags, "--version-light", "-oG", "-", "--host-timeout", "90s", target]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=100)
        return {"stdout": proc.stdout, "stderr": proc.stderr, "exit_code": proc.returncode}
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "stdout": ""}


def _run_http_headers(target: str, args: dict) -> dict:
    if not TARGET_RE.match(target):
        return {"error": "invalid target", "headers": {}}
    port = int(args.get("port", 80))
    url = f"http://{target}:{port}/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "asm-lab-runner/0.1"})
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - Ziel serverseitig validiert
            headers = dict(resp.getheaders())
            status = resp.status
        return {"headers": headers, "status": status}
    except Exception as exc:  # noqa: BLE001 - Fehler sollen als Ergebnis zurueckkommen, nicht crashen
        return {"error": str(exc), "headers": {}}


TOOLS = {"nmap": _run_nmap, "http-headers": _run_http_headers}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # weniger Rauschen im Container-Log
        print("lab-runner:", fmt % args)

    def do_POST(self):
        if self.path != "/run":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return

        tool = body.get("tool")
        target = body.get("target", "")
        args = body.get("args", {})
        handler = TOOLS.get(tool)

        if handler is None:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": f"unknown tool '{tool}'"}).encode())
            return

        result = handler(target, args)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8888), Handler)
    print("lab-runner listening on :8888")
    server.serve_forever()
