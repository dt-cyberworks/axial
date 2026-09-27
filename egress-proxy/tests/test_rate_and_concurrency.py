"""GitHub issues #19 (fractional max_rps + widened-window flooring), #30
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


# --- REQ-CIDRDISC n/a - GitHub issue #19: fractional max_rps -----------------

@pytest.mark.parametrize("max_rps,expected_window", [
    (0.2, 5), (0.5, 2), (1.0, 1.0), (1.5, 1.0), (2.5, 1.0),
])
def test_effective_rate_window_widens_only_below_one(max_rps, expected_window):
    assert proxy._effective_rate_window(max_rps) == expected_window


def test_negative_sub_one_max_rps_is_not_over_permissive(monkeypatch):
    """The old code compared a raw count against a FIXED 1-second window
    regardless of max_rps, so max_rps=0.5 permitted 1 req/s (2x over) and
    max_rps=0.2 permitted 1 req/s (5x over). One ALLOW must now be enough to
    deny the next call for the full widened window, not just 1 second."""
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng())
    monkeypatch.setattr(proxy, "bounty_program_for", lambda eid: _prog(max_rps=0.2, max_concurrency=99))

    calls = {"window_seconds": None}

    def fake_recent(eid, window_seconds=1.0):
        calls["window_seconds"] = window_seconds
        return 1  # one call already recorded

    monkeypatch.setattr(proxy, "recent_allowed_count", fake_recent)

    allowed, reason = asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 443))

    assert (allowed, reason) == (False, "rate_limited")
    assert calls["window_seconds"] == 5  # ceil(1/0.2)


def test_zero_recent_calls_is_allowed_even_at_a_fractional_rate(monkeypatch):
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng())
    monkeypatch.setattr(proxy, "bounty_program_for", lambda eid: _prog(max_rps=0.2, max_concurrency=99))
    monkeypatch.setattr(proxy, "recent_allowed_count", lambda eid, window_seconds=1.0: 0)

    allowed, reason = asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 443))
    assert (allowed, reason) == (True, "allow")


def test_rates_at_or_above_one_are_unaffected(monkeypatch):
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng())
    monkeypatch.setattr(proxy, "bounty_program_for", lambda eid: _prog(max_rps=2.5, max_concurrency=99))
    monkeypatch.setattr(proxy, "recent_allowed_count", lambda eid, window_seconds=1.0: 2)

    allowed, reason = asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 443))
    # threshold = int(2.5) = 2, count=2 >= 2 -> denied, same as pre-fix behavior
    assert (allowed, reason) == (False, "rate_limited")


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
    monkeypatch.setattr(proxy, "recent_allowed_count", lambda eid, window_seconds=1.0: 0)
    proxy._concurrency_in_flight["E1"] = 1  # already at the configured max

    allowed, reason = asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 443))
    assert (allowed, reason) == (False, "concurrency_limit_exceeded")


def test_evaluate_allows_below_the_concurrency_limit(monkeypatch):
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng())
    monkeypatch.setattr(proxy, "bounty_program_for", lambda eid: _prog(max_rps=99, max_concurrency=2))
    monkeypatch.setattr(proxy, "recent_allowed_count", lambda eid, window_seconds=1.0: 0)
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
