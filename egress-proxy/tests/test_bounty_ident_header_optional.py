"""GitHub issue #32: bounty_program_for() returns a truthy dict whenever a
bounty_program ROW exists, even when ident_header_value is unset
(REQ-AUTH-006's 2026-08-12 amendment made the header itself optional) - the
old `if prog:` guard in _forward_plain_http therefore unconditionally set a
header whose value was the Python string "None", sent verbatim over plain
HTTP to the real target. This proves the fix: no header line at all when
unset, the real header when configured, unchanged."""

from __future__ import annotations

import asyncio
import datetime as dt

from app import proxy


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


def _eng():
    now = dt.datetime.now(dt.timezone.utc)
    return {
        "id": "E1", "status": "active", "source": "bug_bounty",
        "authorized_from": now - dt.timedelta(days=1), "authorized_until": now + dt.timedelta(days=1),
        "tcp_port_from": 1, "tcp_port_to": 65535,
    }


async def _run_forward(monkeypatch, *, ident_header_value):
    remote_writer = _Writer()

    async def fake_evaluate(eid, host, path, port):
        return True, "allow"

    async def fake_open_connection(_host, _port):
        return _Reader(), remote_writer

    async def fake_relay(*_args, **_kwargs):
        return None

    async def fake_submit_audit_or_deny(_writer, _eid, decision, reason, payload):
        return True

    monkeypatch.setattr(proxy, "evaluate", fake_evaluate)
    monkeypatch.setattr(proxy, "vet_target_host", lambda host, port: host)
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng())
    monkeypatch.setattr(proxy, "bounty_program_for", lambda eid: {
        "max_rps": 2.0, "max_concurrency": 99,
        "ident_header_name": "X-Bug-Bounty", "ident_header_value": ident_header_value, "ua_suffix": None,
    })
    monkeypatch.setattr(proxy, "_submit_audit_or_deny", fake_submit_audit_or_deny)
    monkeypatch.setattr(proxy, "reserve_rate_slot", lambda eid: {"allowed": True, "reason": "allow"})  # GitHub issue #40
    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    monkeypatch.setattr(proxy, "_relay", fake_relay)
    proxy._concurrency_in_flight.clear()

    await proxy._forward_plain_http(
        _Reader(), _Writer(), "GET", "http://target.example.test/",
        {"host": "target.example.test"}, "E1",
    )
    return remote_writer.data.decode("latin-1")


def test_no_header_line_at_all_when_the_program_has_no_configured_header(monkeypatch):
    sent = asyncio.run(_run_forward(monkeypatch, ident_header_value=None))
    assert "x-bug-bounty" not in sent.lower()
    assert "None" not in sent.split("\r\n\r\n", 1)[0]


def test_the_configured_header_is_still_sent_unchanged(monkeypatch):
    sent = asyncio.run(_run_forward(monkeypatch, ident_header_value="researcher-handle"))
    assert "x-bug-bounty: researcher-handle" in sent.lower()
