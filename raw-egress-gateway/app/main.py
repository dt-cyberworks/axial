"""Minimal internal HTTP API for the raw-egress gateway."""

from __future__ import annotations

import json
import os
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.gateway import (
    LeaseBusy, LeaseError, NftPolicyManager, PolicyError, QueueFull, RawEgressGateway,
)
from app.raw_egress_auth import RAW_EGRESS_TOKEN_HEADER, enforce_production_token, is_authorized

HOST = os.environ.get("RAW_EGRESS_GATEWAY_HOST", "0.0.0.0")
PORT = int(os.environ.get("RAW_EGRESS_GATEWAY_PORT", "8765"))
SECRET = os.environ.get("RAW_EGRESS_SIGNING_SECRET", "raw-egress-change-me-in-dev")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development").lower()
if ENVIRONMENT == "production" and SECRET in {"", "raw-egress-change-me-in-dev"}:
    raise RuntimeError("insecure production configuration: raw_egress_signing_secret")

# GitHub issue #22: a SEPARATE secret from SECRET above (which signs lease
# payloads) - this one authenticates the CALLER, same shared-secret pattern
# as tool-runner/runner_auth.py.
API_TOKEN = os.environ.get("RAW_EGRESS_API_TOKEN", "raw-egress-api-change-me-in-dev")
enforce_production_token(ENVIRONMENT, API_TOKEN)

PROXY_HOST = os.environ.get("EGRESS_PROXY_HOST", "egress-proxy")
PROXY_PORT = int(os.environ.get("EGRESS_PROXY_PORT", "3128"))
try:
    PROXY_ADDRESSES = sorted({
        item[4][0] for item in socket.getaddrinfo(PROXY_HOST, PROXY_PORT, proto=socket.IPPROTO_TCP)
    })
except OSError as exc:
    raise RuntimeError("egress proxy cannot be resolved before deny-all policy installation") from exc
if not PROXY_ADDRESSES:
    raise RuntimeError("egress proxy has no address")

# REQ-COVER-004: optional self-hosted interaction server. Unset -> no extra
# rule at all (the deny-all policy is exactly as before).
OOB_HOST = os.environ.get("OOB_SERVER_HOST", "").strip()
OOB_PORT = int(os.environ.get("OOB_SERVER_PORT", "8080"))
OOB_ADDRESSES: list[str] = []
if OOB_HOST:
    try:
        OOB_ADDRESSES = sorted({
            item[4][0] for item in socket.getaddrinfo(OOB_HOST, OOB_PORT, socket.AF_INET, socket.SOCK_STREAM)
        })
    except OSError:
        # The interaction server is optional: if it is not up, run without it.
        print("raw-egress-gateway: oob server not resolvable; oob disabled", flush=True)

# REQ-CONCUR-002: bounded 1-8, defaulting to 2, so multiple users' raw-network
# (nmap) scans don't hard-serialize behind a single global slot.
MAX_CONCURRENT_LEASES = max(1, min(8, int(os.environ.get("RAW_EGRESS_MAX_CONCURRENT_LEASES", "2"))))

gateway = RawEgressGateway(
    SECRET,
    NftPolicyManager(
        proxy_addresses=PROXY_ADDRESSES, proxy_port=PROXY_PORT, num_slots=MAX_CONCURRENT_LEASES,
        oob_addresses=OOB_ADDRESSES, oob_port=OOB_PORT,
    ),
    max_concurrent_leases=MAX_CONCURRENT_LEASES,
)

class Handler(BaseHTTPRequestHandler):
    server_version = "ASMRawEgress/2"
    # GitHub issue #22: a client that opens a connection and sends a partial
    # body/headers previously held a ThreadingHTTPServer worker thread
    # indefinitely - socketserver.StreamRequestHandler applies this as a
    # socket-level timeout in setup(), and handle_timeout() (below) closes
    # the connection without holding the slot/thread any longer.
    timeout = float(os.environ.get("RAW_EGRESS_REQUEST_TIMEOUT_SECONDS", "10"))

    def handle_timeout(self) -> None:
        self.close_connection = True

    def log_message(self, format, *args):  # noqa: A003
        print(f"raw-egress-gateway: {format % args}", flush=True)

    def _authorized(self) -> bool:
        return is_authorized(self.path, self.headers.get(RAW_EGRESS_TOKEN_HEADER), API_TOKEN)

    def _json(self, status: int, body: dict) -> None:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise LeaseError("request_length_invalid") from exc
        if not 1 <= length <= 32768:
            raise LeaseError("request_length_invalid")
        try:
            body = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LeaseError("request_json_invalid") from exc
        if not isinstance(body, dict):
            raise LeaseError("request_json_invalid")
        return body

    @staticmethod
    def _string(body: dict, name: str) -> str:
        value = body.get(name)
        if not isinstance(value, str) or not value:
            raise LeaseError(f"{name}_missing")
        return value

    def do_GET(self):  # noqa: N802
        if self.path != "/health":
            self._json(404, {"error": "not_found"})
            return
        self._json(200, gateway.status())

    def do_POST(self):  # noqa: N802
        # GitHub issue #22: checked BEFORE _body() (which reads and parses
        # the request) - an unauthenticated caller is rejected without this
        # gateway spending any work on its payload, on every POST path
        # including the reservation endpoints that previously had no check
        # at all (unlike the lease endpoints below them, which were already
        # implicitly protected by requiring a control-plane-signed
        # lease_token - this is a uniform, earlier check on top of that).
        if not self._authorized():
            self._json(401, {"error": "unauthorized"})
            return
        try:
            body = self._body()
            if self.path == "/v1/reservations/acquire":
                result = gateway.reserve(self._string(body, "scan_run_id"))
                self._json(200, {**result, "policy_enforced": True})
                return
            if self.path == "/v1/reservations/release":
                gateway.release(
                    self._string(body, "scan_run_id"), self._string(body, "reservation_token")
                )
                self._json(200, {"status": "released", "policy_enforced": True})
                return
            token = self._string(body, "lease_token")
            reservation = self._string(body, "reservation_token")
            if self.path == "/v1/leases/activate":
                lease = gateway.activate(token, reservation)
                self._json(200, {
                    "status": "active", "policy_enforced": True, "lease_id": lease.lease_id,
                    "expires_at": lease.expires_at, "max_rate": lease.max_rate,
                    "port_profile": lease.port_profile, "protocol": lease.protocol,
                })
                return
            if self.path == "/v1/leases/heartbeat":
                lease = gateway.heartbeat(token, reservation)
                self._json(200, {
                    "status": "active", "policy_enforced": True,
                    "heartbeat_deadline": lease.heartbeat_deadline,
                })
                return
            if self.path == "/v1/leases/deactivate":
                gateway.deactivate(token, reservation)
                self._json(200, {"status": "inactive", "policy_enforced": True})
                return
            self._json(404, {"error": "not_found"})
        except LeaseBusy as exc:
            self._json(409, {"error": str(exc)})
        except QueueFull as exc:
            self._json(429, {"error": str(exc)})
        except LeaseError as exc:
            self._json(403, {"error": str(exc)})
        except PolicyError as exc:
            self._json(503, {"error": "policy_installation_failed", "detail": str(exc)[:500]})

def run() -> None:
    gateway.initialize()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"raw-egress-gateway listening on {HOST}:{PORT} (deny-all baseline)", flush=True)
    server.serve_forever()

if __name__ == "__main__":
    run()
