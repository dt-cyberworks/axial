"""REQ-EGRESS-004 / REQ-EGRESS-005: the reply to an allowed CONNECT.

Found on int (2026-10-02): the proxy answered `CONNECT` with a bare status line and a blank line.
nuclei's raw HTTP client (used by every `unsafe: true` template) waits for a header line, sends nothing
through the tunnel for 60 s and gives up, so those checks never reached a target and the shard they
sit in took 545 s instead of 14 s. One header line makes the client send its first bytes at once.
"""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://x:x@localhost:5432/x")

from app import proxy  # noqa: E402

ENGAGEMENT_ID = "019649b8-0000-7000-8000-000000000001"
PROXY_SOURCE = Path(proxy.__file__).read_text(encoding="utf-8")


class _Writer:
    def __init__(self):
        self.data = b""
        self.closed = False

    def write(self, data):
        self.data += data

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    def get_extra_info(self, _name):
        return None


class _LineReader:
    def __init__(self, lines: list[bytes]):
        self._lines = list(lines)

    async def readline(self):
        return self._lines.pop(0) if self._lines else b""


class _Remote:
    async def readexactly(self, _n):
        return b""


def _run_connect(monkeypatch, *, allowed=True, reason="allow", target="host.example.com:443"):
    """Drive one CONNECT through the real _handle_client; returns (writer, upstream connections, relays)."""
    connected, relayed = [], []

    async def fake_evaluate(eid, host, path, port):
        return allowed, reason

    async def fake_submit(_writer, _eid, decision, why, payload):
        return True

    async def fake_open_connection(host, port):
        connected.append((host, port))
        return _Remote(), _Writer()

    async def fake_relay(*_args, **_kwargs):
        relayed.append(True)

    monkeypatch.setattr(proxy, "evaluate", fake_evaluate)
    monkeypatch.setattr(proxy, "vet_target_host", lambda host, port: host)
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: {"id": eid, "source": "own_domain"})
    monkeypatch.setattr(proxy, "_submit_audit_or_deny", fake_submit)
    monkeypatch.setattr(proxy, "_relay", fake_relay)
    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    proxy._concurrency_in_flight.clear()
    reader = _LineReader([f"CONNECT {target} HTTP/1.1\r\n".encode(),
                          f"X-ASM-Engagement-Id: {ENGAGEMENT_ID}\r\n".encode(), b"\r\n"])
    writer = _Writer()
    asyncio.run(proxy._handle_client(reader, writer))
    return writer, connected, relayed


def _reply_parts(data: bytes) -> tuple[str, list[str], bytes]:
    """Split a proxy reply into (status line, header lines, whatever follows the blank line)."""
    head, sep, rest = data.partition(b"\r\n\r\n")
    assert sep, "the reply never ends with a blank line"
    lines = head.decode("latin-1").split("\r\n")
    return lines[0], lines[1:], rest


def _client_that_needs_a_header_line(data: bytes) -> bool:
    """nuclei's raw client, as measured: it only starts sending once it has read a status line AND at
    least one header line before the blank line. A reply without one leaves it waiting for 60 s."""
    status, headers, _rest = _reply_parts(data)
    return status.startswith("HTTP/1.1 200") and any(re.match(r"^[A-Za-z-]+:\s*\S", h) for h in headers)


# --- REQ-EGRESS-004 ------------------------------------------------------------

def test_req_egress_004_an_allowed_connect_gets_a_status_line_and_a_header_line(monkeypatch):
    writer, connected, relayed = _run_connect(monkeypatch)
    status, headers, rest = _reply_parts(writer.data)
    assert status == "HTTP/1.1 200 Connection Established"
    assert len(headers) >= 1
    assert rest == b""  # nothing but the handshake: the tunnel bytes are the client's and the target's
    assert connected == [("host.example.com", 443)]
    assert relayed == [True]


def test_req_egress_004_a_client_that_waits_for_a_header_line_is_not_left_waiting(monkeypatch):
    writer, _connected, _relayed = _run_connect(monkeypatch)
    assert _client_that_needs_a_header_line(writer.data)


def test_req_egress_004_the_old_bare_reply_is_what_such_a_client_rejects():
    """Keeps the model honest: the reply this requirement replaces fails the same check."""
    assert not _client_that_needs_a_header_line(b"HTTP/1.1 200 Connection Established\r\n\r\n")


def test_req_egress_004_the_handshake_is_defined_once_and_never_inline_without_a_header():
    occurrences = [line for line in PROXY_SOURCE.splitlines() if "Connection Established" in line]
    assert len(occurrences) == 1, occurrences
    assert "Proxy-Agent:" in occurrences[0] or "Proxy-Agent:" in PROXY_SOURCE
    assert proxy.CONNECT_ESTABLISHED.endswith(b"\r\n\r\n")
    assert proxy.CONNECT_ESTABLISHED.count(b"\r\n\r\n") == 1


# --- REQ-EGRESS-005 ------------------------------------------------------------

def test_req_egress_005_the_header_is_a_fixed_value_that_names_nothing_of_the_engagement(monkeypatch):
    writer, _connected, _relayed = _run_connect(monkeypatch, target="customer-secret.example.org:8443")
    _status, headers, _rest = _reply_parts(writer.data)
    assert headers == ["Proxy-Agent: asm-egress-proxy"]
    text = writer.data.decode("latin-1")
    for private in (ENGAGEMENT_ID, "customer-secret", "example.org", "8443"):
        assert private not in text


def test_req_egress_005_the_reply_is_identical_for_every_target(monkeypatch):
    first, _c1, _r1 = _run_connect(monkeypatch, target="a.example.com:443")
    second, _c2, _r2 = _run_connect(monkeypatch, target="b.example.org:8443")
    assert first.data == second.data == proxy.CONNECT_ESTABLISHED


def test_req_egress_004_on_a_real_socket_the_client_gets_the_header_and_traffic_flows_both_ways(monkeypatch):
    """The wire, not a fake writer: a real listener running the proxy's own client handler, a real
    upstream that echoes, and a client that reads the handshake byte by byte the way a strict parser
    does. The tunnel must deliver the client's first bytes and the upstream's answer unchanged."""

    async def allow(eid, host, path, port):
        return True, "allow"

    async def audited(_writer, _eid, decision, why, payload):
        return True

    monkeypatch.setattr(proxy, "evaluate", allow)
    monkeypatch.setattr(proxy, "vet_target_host", lambda host, port: host)
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: {"id": eid, "source": "own_domain"})
    monkeypatch.setattr(proxy, "_submit_audit_or_deny", audited)
    proxy._concurrency_in_flight.clear()

    async def scenario():
        async def echo(reader, writer):
            data = await reader.read(1024)
            writer.write(b"upstream:" + data)
            await writer.drain()
            writer.close()

        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        listener = await asyncio.start_server(proxy.handle_client, "127.0.0.1", 0)
        up_port = upstream.sockets[0].getsockname()[1]
        proxy_port = listener.sockets[0].getsockname()[1]
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            writer.write(f"CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\nX-ASM-Engagement-Id: {ENGAGEMENT_ID}\r\n\r\n".encode())
            await writer.drain()
            handshake = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
            writer.write(b"first-bytes")  # what nuclei's raw client sends the moment it has the header
            await writer.drain()
            answer = await asyncio.wait_for(reader.read(1024), timeout=5)
            writer.close()
            return handshake, answer
        finally:
            listener.close()
            upstream.close()

    handshake, answer = asyncio.run(scenario())
    assert handshake == proxy.CONNECT_ESTABLISHED
    assert _client_that_needs_a_header_line(handshake)
    assert answer == b"upstream:first-bytes"


@pytest.mark.parametrize("reason", ["no_scope_match", "scope_deny", "concurrency_limit_exceeded", "blocked_loopback"])
def test_negative_req_egress_005_a_denied_connect_gets_no_established_reply_and_opens_no_tunnel(monkeypatch, reason):
    writer, connected, relayed = _run_connect(monkeypatch, allowed=False, reason=reason)
    assert b"Connection Established" not in writer.data
    assert b"Proxy-Agent" not in writer.data
    assert connected == []
    assert relayed == []
    assert writer.data.startswith(b"HTTP/1.1 403")


def test_negative_req_egress_005_a_failed_audit_write_gets_no_established_reply(monkeypatch):
    connected = []

    async def fake_evaluate(eid, host, path, port):
        return True, "allow"

    async def failing_submit(writer, _eid, decision, reason, payload):
        await proxy._deny(writer, 503, "audit_unavailable")
        return False

    async def fake_open_connection(host, port):
        connected.append((host, port))
        return _Remote(), _Writer()

    monkeypatch.setattr(proxy, "evaluate", fake_evaluate)
    monkeypatch.setattr(proxy, "vet_target_host", lambda host, port: host)
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: {"id": eid, "source": "own_domain"})
    monkeypatch.setattr(proxy, "_submit_audit_or_deny", failing_submit)
    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    proxy._concurrency_in_flight.clear()
    reader = _LineReader([b"CONNECT host.example.com:443 HTTP/1.1\r\n",
                          f"X-ASM-Engagement-Id: {ENGAGEMENT_ID}\r\n".encode(), b"\r\n"])
    writer = _Writer()
    asyncio.run(proxy._handle_client(reader, writer))
    assert b"Connection Established" not in writer.data
    assert connected == []
