"""GitHub issues #40 (max_rps reserved atomically before forwarding; #19's
fractional-rate window now lives in the control plane's reservation), #30
(BountyProgram.max_concurrency enforcement), #28 (event-loop-blocking DB
calls, header read deadlines/size limits, CONNECT-relay idle/max duration)."""

from __future__ import annotations

import asyncio
import datetime as dt
import os

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://x:x@localhost:5432/x")

from app import proxy  # noqa: E402


def _eng(source="bug_bounty"):
    now = dt.datetime.now(dt.timezone.utc)
    return {
        "id": "E1", "status": "active", "source": source,
        "authorized_from": now - dt.timedelta(days=1), "authorized_until": now + dt.timedelta(days=1),
        "tcp_port_from": 1, "tcp_port_to": 65535,
    }


def _prog(max_rps=2.0, max_concurrency=2):
    return {
        "max_rps": max_rps, "max_concurrency": max_concurrency,
        "ident_header_name": "X-Bug-Bounty", "ident_header_value": "researcher", "ua_suffix": None,
    }


@pytest.fixture(autouse=True)
def _in_scope_host(monkeypatch):
    monkeypatch.setattr(proxy, "matching_scope_assets",
                         lambda eid, host, path, rule: (
                             [{"asset_type": "domain", "value": "example.com", "path_pattern": None}]
                             if rule == "allow" else []
                         ))
    monkeypatch.setattr(proxy, "is_materialized_ip", lambda eid, ip: False)
    proxy._concurrency_in_flight.clear()


# --- GitHub issue #40: reserve a rate slot before forwarding ------------------

def test_evaluate_no_longer_decides_the_rate(monkeypatch):
    """The read-then-decide count is gone from evaluate(); the slot is reserved
    atomically after every other check (see the forwarding tests below)."""
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng())
    monkeypatch.setattr(proxy, "bounty_program_for", lambda eid: _prog(max_rps=0.2, max_concurrency=99))
    assert not hasattr(proxy, "recent_allowed_count")
    assert asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 443)) == (True, "allow")


def _plain_http(monkeypatch, *, reserve, source="bug_bounty"):
    audited, connected = [], []

    async def fake_evaluate(eid, host, path, port):
        return True, "allow"

    async def fake_submit(_writer, _eid, decision, reason, payload):
        audited.append((decision, reason))
        return True

    async def fake_open_connection(host, port):
        connected.append((host, port))
        return _Reader(), _Writer()

    async def fake_relay(*_a, **_k):
        return None

    monkeypatch.setattr(proxy, "evaluate", fake_evaluate)
    monkeypatch.setattr(proxy, "vet_target_host", lambda host, port: host)
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng(source=source))
    monkeypatch.setattr(proxy, "bounty_program_for", lambda eid: _prog(max_rps=1, max_concurrency=5))
    monkeypatch.setattr(proxy, "reserve_rate_slot", reserve)
    monkeypatch.setattr(proxy, "_submit_audit_or_deny", fake_submit)
    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    monkeypatch.setattr(proxy, "_relay", fake_relay)
    writer = _Writer()
    asyncio.run(proxy._forward_plain_http(
        _Reader(), writer, "GET", "http://host.example.com/", {"host": "host.example.com"}, "E1"))
    return audited, connected, writer


def test_negative_no_reserved_slot_means_no_forwarding(monkeypatch):
    audited, connected, writer = _plain_http(
        monkeypatch, reserve=lambda eid: {"allowed": False, "reason": "rate_limited", "retry_after_seconds": 1.0})
    assert audited == [("DENY", "rate_limited")]
    assert connected == []
    assert b"HTTP/1.1 403" in writer.data
    assert "E1" not in proxy._concurrency_in_flight  # the concurrency slot was given back


def test_negative_an_unreachable_control_plane_fails_closed(monkeypatch):
    def down(eid):
        raise OSError("control plane down")

    audited, connected, _writer = _plain_http(monkeypatch, reserve=down)
    assert audited == [("DENY", "rate_reservation_unavailable")]
    assert connected == []


def test_a_reserved_slot_forwards(monkeypatch):
    calls = []
    audited, connected, _writer = _plain_http(
        monkeypatch, reserve=lambda eid: calls.append(eid) or {"allowed": True, "reason": "allow"})
    assert calls == ["E1"]
    assert audited == [("ALLOW", "allow")]
    assert connected == [("host.example.com", 80)]


def test_non_bug_bounty_requests_never_ask_for_a_slot(monkeypatch):
    calls = []
    audited, connected, _writer = _plain_http(
        monkeypatch, source="own_domain", reserve=lambda eid: calls.append(eid) or {"allowed": False})
    assert calls == []
    assert audited == [("ALLOW", "allow")]
    assert connected


def test_negative_connect_without_a_reserved_slot_opens_no_tunnel(monkeypatch):
    audited, connected = [], []

    async def fake_evaluate(eid, host, path, port):
        return True, "allow"

    async def fake_submit(_writer, _eid, decision, reason, payload):
        audited.append((decision, reason))
        return True

    async def fake_open_connection(host, port):
        connected.append((host, port))
        return _Reader(), _Writer()

    monkeypatch.setattr(proxy, "evaluate", fake_evaluate)
    monkeypatch.setattr(proxy, "vet_target_host", lambda host, port: host)
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng())
    monkeypatch.setattr(proxy, "bounty_program_for", lambda eid: _prog(max_rps=1, max_concurrency=5))
    monkeypatch.setattr(proxy, "reserve_rate_slot", lambda eid: {"allowed": False, "reason": "rate_limited"})
    monkeypatch.setattr(proxy, "_submit_audit_or_deny", fake_submit)
    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    engagement_id = "019649b8-0000-7000-8000-000000000001"
    reader = _LineReader([b"CONNECT host.example.com:443 HTTP/1.1\r\n",
                          f"X-ASM-Engagement-Id: {engagement_id}\r\n".encode(), b"\r\n"])
    writer = _Writer()
    asyncio.run(proxy._handle_client(reader, writer))
    assert audited == [("DENY", "rate_limited")]
    assert connected == []
    assert engagement_id not in proxy._concurrency_in_flight


# --- GitHub issue #30: max_concurrency enforcement --------------------------

def test_acquire_and_release_slot_roundtrip():
    assert proxy._try_acquire_concurrency_slot("E1", 2) is True
    assert proxy._concurrency_in_flight["E1"] == 1
    assert proxy._try_acquire_concurrency_slot("E1", 2) is True
    assert proxy._concurrency_in_flight["E1"] == 2
    assert proxy._try_acquire_concurrency_slot("E1", 2) is False  # at capacity
    proxy._release_concurrency_slot("E1")
    assert proxy._concurrency_in_flight["E1"] == 1
    proxy._release_concurrency_slot("E1")
    assert "E1" not in proxy._concurrency_in_flight  # cleaned up, not left at 0


def test_release_without_a_prior_acquire_is_a_safe_noop():
    proxy._release_concurrency_slot("never-acquired")  # must not raise
    assert "never-acquired" not in proxy._concurrency_in_flight


def test_evaluate_denies_when_at_the_configured_concurrency_limit(monkeypatch):
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng())
    monkeypatch.setattr(proxy, "bounty_program_for", lambda eid: _prog(max_rps=99, max_concurrency=1))
    proxy._concurrency_in_flight["E1"] = 1  # already at the configured max

    allowed, reason = asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 443))
    assert (allowed, reason) == (False, "concurrency_limit_exceeded")


def test_evaluate_allows_below_the_concurrency_limit(monkeypatch):
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng())
    monkeypatch.setattr(proxy, "bounty_program_for", lambda eid: _prog(max_rps=99, max_concurrency=2))
    proxy._concurrency_in_flight["E1"] = 1

    allowed, reason = asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 443))
    assert (allowed, reason) == (True, "allow")


def test_non_bug_bounty_engagements_are_never_concurrency_limited(monkeypatch):
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng(source="managed"))
    allowed, reason = asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 443))
    assert (allowed, reason) == (True, "allow")


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


class _Reader:
    async def readexactly(self, _n):
        return b""


def test_forward_plain_http_releases_the_concurrency_slot_even_on_relay_failure(monkeypatch):
    """The slot must be released in `finally` regardless of how the request
    ends - proven here by making the relay itself raise."""
    async def fake_evaluate(eid, host, path, port):
        return True, "allow"

    async def fake_submit_audit_or_deny(_writer, _eid, decision, reason, payload):
        return True

    async def fake_open_connection(_host, _port):
        return _Reader(), _Writer()

    async def failing_relay(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(proxy, "evaluate", fake_evaluate)
    monkeypatch.setattr(proxy, "vet_target_host", lambda host, port: host)
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng())
    monkeypatch.setattr(proxy, "bounty_program_for", lambda eid: _prog(max_rps=99, max_concurrency=1))
    monkeypatch.setattr(proxy, "_submit_audit_or_deny", fake_submit_audit_or_deny)
    monkeypatch.setattr(proxy, "reserve_rate_slot", lambda eid: {"allowed": True, "reason": "allow"})
    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    monkeypatch.setattr(proxy, "_relay", failing_relay)

    with pytest.raises(RuntimeError):
        asyncio.run(proxy._forward_plain_http(
            _Reader(), _Writer(), "GET", "http://host.example.com/", {"host": "host.example.com"}, "E1",
        ))

    assert "E1" not in proxy._concurrency_in_flight


# --- GitHub issue #28: header-read deadlines and size limits ----------------

class _SlowReader:
    """Never delivers a line - simulates a client dribbling bytes forever."""
    async def readline(self):
        await asyncio.sleep(3600)
        return b""


class _LineReader:
    def __init__(self, lines: list[bytes]):
        self._lines = list(lines)

    async def readline(self):
        return self._lines.pop(0) if self._lines else b""


def test_header_read_times_out_instead_of_hanging_forever(monkeypatch):
    monkeypatch.setattr(proxy, "HEADER_READ_TIMEOUT_SECONDS", 0.05)
    with pytest.raises(proxy.RequestTooSlowError):
        asyncio.run(proxy._read_request_line_and_headers(_SlowReader()))


def test_oversized_header_line_is_rejected():
    lines = [b"GET / HTTP/1.1\r\n", b"X-Big: " + b"a" * (proxy.MAX_HEADER_LINE_BYTES + 1) + b"\r\n"]
    with pytest.raises(proxy.RequestTooLargeError):
        asyncio.run(proxy._read_request_line_and_headers(_LineReader(lines)))


def test_too_many_headers_is_rejected():
    lines = [b"GET / HTTP/1.1\r\n"] + [f"X-{i}: v\r\n".encode() for i in range(proxy.MAX_HEADER_COUNT + 1)] + [b"\r\n"]
    with pytest.raises(proxy.RequestTooLargeError):
        asyncio.run(proxy._read_request_line_and_headers(_LineReader(lines)))


def test_a_normal_small_request_parses_fine_within_the_deadline():
    lines = [b"GET / HTTP/1.1\r\n", b"Host: example.com\r\n", b"\r\n"]
    request_line, headers = asyncio.run(proxy._read_request_line_and_headers(_LineReader(lines)))
    assert request_line == "GET / HTTP/1.1"
    assert headers["host"] == "example.com"


def test_handle_client_returns_408_when_headers_never_finish(monkeypatch):
    monkeypatch.setattr(proxy, "HEADER_READ_TIMEOUT_SECONDS", 0.05)
    writer = _Writer()
    asyncio.run(proxy._handle_client(_SlowReader(), writer))
    assert b"HTTP/1.1 408" in writer.data
    assert b"header_read_timeout" in writer.data


# --- GitHub issue #28: CONNECT-relay idle timeout ---------------------------

class _NeverReader:
    async def read(self, _n):
        await asyncio.sleep(3600)
        return b""


class _RelayWriter:
    def __init__(self):
        self.data = b""
        self.closed = False
    def write(self, data):
        self.data += data
    async def drain(self):
        return None
    def close(self):
        self.closed = True


def test_relay_closes_an_idle_connect_tunnel_instead_of_holding_it_forever(monkeypatch):
    monkeypatch.setattr(proxy, "RELAY_IDLE_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(proxy, "RELAY_MAX_DURATION_SECONDS", 10)
    a_writer, b_writer = _RelayWriter(), _RelayWriter()

    asyncio.run(proxy._relay(_NeverReader(), a_writer, _NeverReader(), b_writer))

    assert a_writer.closed and b_writer.closed
