"""REQ-EGRESS-006/007/009 (GitHub #81): the proxy judges a request by the engagement its signed run token names.

Seen on int (2026-10-20): a monitoring engagement for three names and an assessment scoped to their two IPs shared a
host, the proxy could not tell whose request it was, and answered `409 ambiguous_host` to both. These tests drive the
real `_handle_client` with the real token verifier; only the database, the audit transport and the network are faked."""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import logging
import os
import sys
import time
from pathlib import Path

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://x:x@localhost:5432/x")

from app import proxy, run_token  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("cp_egress_identity", ROOT / "control-plane/app/gateway/egress_identity.py")
minter = importlib.util.module_from_spec(_spec)
sys.modules["cp_egress_identity"] = minter
_spec.loader.exec_module(minter)

ENG_A = "019649b8-0000-7000-8000-00000000000a"
ENG_B = "019649b8-0000-7000-8000-00000000000b"
RUN_A = "019649b8-0000-7000-8000-0000000000a1"
RUN_B = "019649b8-0000-7000-8000-0000000000b1"
SECRET = run_token.SECRET


def _token(engagement=ENG_A, run=RUN_A, *, secret=SECRET, ttl=600, now=None):
    return minter.mint(secret, engagement, run, ttl, now=time.time() if now is None else now)


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def _auth(token: str, user: str = "asm") -> str:
    return _basic(user, token)


def _basic_raw(decoded: str) -> str:
    return "Basic " + base64.b64encode(decoded.encode()).decode()


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
    def __init__(self, lines):
        self._lines = list(lines)

    async def readline(self):
        return self._lines.pop(0) if self._lines else b""

    async def readexactly(self, _n):
        return b""


class _Upstream:
    def __init__(self):
        self.written = b""

    def write(self, data):
        self.written += data

    async def drain(self):
        return None

    def close(self):
        pass


class Drive:
    def __init__(self, monkeypatch, *, live=True, live_error=None, bound=None, require=False, evaluate=None):
        self.evaluated, self.audits, self.connected, self.live_checks = [], [], [], []
        self.upstream = _Upstream()
        self.guess_calls = 0

        async def fake_evaluate(eid, host, path, port):
            self.evaluated.append((eid, host, port))
            return (True, "allow") if evaluate is None else evaluate(eid, host, path, port)

        async def fake_submit(_writer, eid, decision, why, payload):
            self.audits.append((eid, decision, why, payload))
            return True

        async def fake_connection(host, port):
            self.connected.append((host, port))
            return _LineReader([]), self.upstream

        async def fake_relay(*_a, **_k):
            return None

        async def fake_guess(host):
            self.guess_calls += 1
            return None, "ambiguous_host"

        def fake_live(run, eng):
            self.live_checks.append((run, eng))
            if live_error:
                raise live_error
            return live

        monkeypatch.setattr(proxy, "evaluate", fake_evaluate)
        monkeypatch.setattr(proxy, "vet_target_host", lambda host, port: host)
        monkeypatch.setattr(proxy, "load_engagement", lambda eid: {"id": eid, "source": "own_domain"})
        monkeypatch.setattr(proxy, "_submit_audit_or_deny", fake_submit)
        monkeypatch.setattr(proxy, "_relay", fake_relay)
        monkeypatch.setattr(proxy, "resolve_engagement_for_host", fake_guess)
        monkeypatch.setattr(proxy, "scan_run_live", fake_live)
        monkeypatch.setattr(proxy, "DEFAULT_ENGAGEMENT_ID", bound)
        monkeypatch.setattr(proxy, "REQUIRE_TOKEN", require)
        monkeypatch.setattr(asyncio, "open_connection", fake_connection)
        proxy._concurrency_in_flight.clear()

    def connect(self, headers, target="host.example.com:443"):
        reader = _LineReader([f"CONNECT {target} HTTP/1.1\r\n".encode(), *[f"{h}\r\n".encode() for h in headers], b"\r\n"])
        writer = _Writer()
        asyncio.run(proxy._handle_client(reader, writer))
        return writer

    def get(self, headers, url="http://host.example.com/path?q=1"):
        reader = _LineReader([f"GET {url} HTTP/1.1\r\n".encode(), "Host: host.example.com\r\n".encode(),
                              *[f"{h}\r\n".encode() for h in headers], b"\r\n"])
        writer = _Writer()
        asyncio.run(proxy._handle_client(reader, writer))
        return writer


def _status(writer) -> str:
    return writer.data.split(b"\r\n", 1)[0].decode("latin-1")


# --- a valid token selects the engagement -------------------------------------------------------------------------

def test_a_valid_token_names_the_engagement_whatever_else_matches_the_destination(monkeypatch):
    drive = Drive(monkeypatch)
    writer = drive.connect([f"Proxy-Authorization: {_auth(_token())}"])
    assert _status(writer) == "HTTP/1.1 200 Connection Established"
    assert drive.evaluated == [(ENG_A, "host.example.com", 443)]
    assert drive.guess_calls == 0, "the destination is never used to guess when an identity is proven"
    assert drive.live_checks == [(RUN_A, ENG_A)]


def test_two_engagements_that_share_a_host_are_each_judged_by_their_own_token(monkeypatch):
    """The incident: both are refused today. With tokens both run, each by its own engagement."""
    drive = Drive(monkeypatch)
    for engagement, run in ((ENG_A, RUN_A), (ENG_B, RUN_B)):
        writer = drive.connect([f"Proxy-Authorization: {_auth(_token(engagement, run))}"])
        assert _status(writer) == "HTTP/1.1 200 Connection Established"
    assert [e[0] for e in drive.evaluated] == [ENG_A, ENG_B]
    assert drive.guess_calls == 0


def test_one_engagements_deny_does_not_affect_the_other(monkeypatch):
    def evaluate(eid, host, path, port):
        return (False, "out_of_scope_deny") if eid == ENG_A else (True, "allow")

    drive = Drive(monkeypatch, evaluate=evaluate)
    refused = drive.connect([f"Proxy-Authorization: {_auth(_token(ENG_A, RUN_A))}"])
    allowed = drive.connect([f"Proxy-Authorization: {_auth(_token(ENG_B, RUN_B))}"])
    assert _status(refused).startswith("HTTP/1.1 403") and _status(allowed) == "HTTP/1.1 200 Connection Established"


def test_every_audited_request_of_a_token_connection_carries_the_run(monkeypatch):
    drive = Drive(monkeypatch)
    drive.connect([f"Proxy-Authorization: {_auth(_token())}"])
    drive.get([f"Proxy-Authorization: {_auth(_token())}"])
    assert len(drive.audits) == 2
    for eid, decision, reason, payload in drive.audits:
        assert eid == ENG_A and payload["scan_run_id"] == RUN_A


def test_a_request_without_a_token_does_not_carry_a_run_in_its_audit(monkeypatch):
    drive = Drive(monkeypatch)
    drive.connect([f"X-ASM-Engagement-Id: {ENG_A}"])
    assert drive.audits and "scan_run_id" not in drive.audits[0][3]


# --- a credential that is present but not valid is never rescued ----------------------------------------------------

WRONG_KEY = "-".join(["not", "the", "proxy", "key"])


def _bad_credentials():
    return {
        "forged (another key)": _auth(_token(secret=WRONG_KEY)),
        "expired": _auth(_token(now=time.time() - 3600, ttl=600)),
        "garbage password": _auth("not-a-token"),
        "empty password": _basic("asm", ""),
        "wrong user": _auth(_token(), user="root"),
        "no user separator": "Basic " + base64.b64encode(_token().encode()).decode(),
        "bearer scheme": f"Bearer {_token()}",
        "right payload, wrong scheme": "Bearer " + base64.b64encode(f"asm:{_token()}".encode()).decode(),
        "not base64": "Basic ***not-base64***",
        "no credentials after scheme": "Basic",
        "token for the wrong purpose": _auth("v2." + _token().split(".", 1)[1]),
        # nuclei's raw client puts the scheme in front (see below); no other prefix is accepted
        "ftp prefix": _basic_raw(f"ftp://asm:{_token()}"),
        "scheme with another user": _basic_raw(f"http://root:{_token()}"),
        "bare slashes": _basic_raw(f"//asm:{_token()}"),
        "scheme without slashes": _basic_raw(f"http:asm:{_token()}"),
        "upper-case scheme": _basic_raw(f"HTTP://asm:{_token()}"),
        "doubled scheme": _basic_raw(f"http://http://asm:{_token()}"),
    }


@pytest.mark.parametrize("case", list(_bad_credentials()))
def test_negative_an_invalid_credential_is_refused_and_never_falls_back_to_a_header_or_a_guess(monkeypatch, case):
    drive = Drive(monkeypatch)
    writer = drive.connect([f"Proxy-Authorization: {_bad_credentials()[case]}", f"X-ASM-Engagement-Id: {ENG_B}"])
    assert _status(writer).startswith("HTTP/1.1 407") and writer.data.endswith(b"invalid_run_token")
    assert drive.evaluated == [] and drive.guess_calls == 0 and drive.connected == [] and drive.live_checks == []
    assert drive.audits == [], "no engagement is trusted, so nothing is audited under one"


@pytest.mark.parametrize("scheme", ["http://", "https://"])
def test_the_credential_form_of_nucleis_raw_client_is_accepted_and_verified_like_any_other(monkeypatch, scheme):
    """Measured against the real nuclei: every `unsafe: true` template goes through a raw HTTP client that sends
    `Basic base64("<scheme>://asm:<token>")`. On int 238 requests of one scan were refused as malformed until this."""
    drive = Drive(monkeypatch)
    writer = drive.connect([f"Proxy-Authorization: {_basic_raw(scheme + 'asm:' + _token())}"])
    assert _status(writer) == "HTTP/1.1 200 Connection Established"
    assert [e[0] for e in drive.evaluated] == [ENG_A] and drive.live_checks == [(RUN_A, ENG_A)]


def test_negative_the_raw_client_form_is_still_verified_a_forged_token_in_it_is_refused(monkeypatch):
    drive = Drive(monkeypatch)
    writer = drive.connect([f"Proxy-Authorization: {_basic_raw('http://asm:' + _token(secret=WRONG_KEY))}"])
    assert _status(writer).startswith("HTTP/1.1 407") and drive.evaluated == []


def test_negative_a_header_cannot_choose_the_engagement_of_a_token(monkeypatch):
    drive = Drive(monkeypatch)
    drive.connect([f"Proxy-Authorization: {_auth(_token(ENG_A, RUN_A))}", f"X-ASM-Engagement-Id: {ENG_B}"])
    assert [e[0] for e in drive.evaluated] == [ENG_A]


def test_negative_a_token_of_one_engagement_is_judged_against_that_engagements_scope(monkeypatch):
    import datetime as dt

    allow = {ENG_A: "a.example", ENG_B: "b.example"}
    window = dict(authorized_from=dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc),
                  authorized_until=dt.datetime(2999, 1, 1, tzinfo=dt.timezone.utc))
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: {"status": "active", "source": "own_domain",
                                                               "tcp_port_from": 1, "tcp_port_to": 65535, **window})
    monkeypatch.setattr(proxy, "matching_scope_assets", lambda eid, host, path, rule: (
        [{"asset_type": "domain", "value": allow[eid], "path_pattern": None, "port_from": None, "port_to": None}]
        if rule == "allow" else []))
    calls = []

    async def fake_submit(_w, eid, decision, why, payload):
        calls.append((eid, decision, why))
        return True

    async def conn(host, port):
        return _LineReader([]), _Upstream()

    async def relay(*_a, **_k):
        return None

    monkeypatch.setattr(proxy, "vet_target_host", lambda host, port: host)
    monkeypatch.setattr(proxy, "_submit_audit_or_deny", fake_submit)
    monkeypatch.setattr(proxy, "_relay", relay)
    monkeypatch.setattr(proxy, "scan_run_live", lambda run, eng: True)
    monkeypatch.setattr(proxy, "DEFAULT_ENGAGEMENT_ID", None)
    monkeypatch.setattr(proxy, "REQUIRE_TOKEN", False)
    monkeypatch.setattr(asyncio, "open_connection", conn)
    proxy._concurrency_in_flight.clear()

    def connect(token, target):
        reader = _LineReader([f"CONNECT {target} HTTP/1.1\r\n".encode(),
                              f"Proxy-Authorization: {_auth(token)}\r\n".encode(), b"\r\n"])
        writer = _Writer()
        asyncio.run(proxy._handle_client(reader, writer))
        return _status(writer)

    assert connect(_token(ENG_A, RUN_A), "a.example:443") == "HTTP/1.1 200 Connection Established"
    assert connect(_token(ENG_A, RUN_A), "b.example:443").startswith("HTTP/1.1 403")        # only B allows it
    assert connect(_token(ENG_B, RUN_B), "b.example:443") == "HTTP/1.1 200 Connection Established"
    assert connect(_token(ENG_B, RUN_B), "a.example:443").startswith("HTTP/1.1 403")
    assert (ENG_A, "DENY", "not_in_scope") in calls and (ENG_B, "DENY", "not_in_scope") in calls


# --- the run must still be live --------------------------------------------------------------------------------------

def test_negative_a_token_of_a_run_that_ended_or_was_stopped_stops_working_and_is_audited(monkeypatch):
    drive = Drive(monkeypatch, live=False)
    writer = drive.connect([f"Proxy-Authorization: {_auth(_token())}"])
    assert _status(writer).startswith("HTTP/1.1 403") and writer.data.endswith(b"run_not_active")
    assert drive.audits == [(ENG_A, "DENY", "run_not_active", {"method": "CONNECT", "host": "host.example.com", "scan_run_id": RUN_A})]
    assert drive.evaluated == [] and drive.connected == []


def test_negative_when_the_run_cannot_be_checked_nothing_is_forwarded(monkeypatch):
    drive = Drive(monkeypatch, live_error=RuntimeError("database down"))
    writer = drive.connect([f"Proxy-Authorization: {_auth(_token())}"])
    assert _status(writer).startswith("HTTP/1.1 503") and writer.data.endswith(b"run_check_unavailable")
    assert drive.evaluated == [] and drive.connected == []


# --- the migration mode and the required mode ----------------------------------------------------------------------

def test_without_credentials_the_migration_mode_keeps_the_header_and_counts_the_request(monkeypatch, caplog):
    drive = Drive(monkeypatch)
    with caplog.at_level(logging.INFO, logger=proxy.logger.name):
        writer = drive.connect([f"X-ASM-Engagement-Id: {ENG_B}"])
    assert _status(writer) == "HTTP/1.1 200 Connection Established"
    assert [e[0] for e in drive.evaluated] == [ENG_B]
    assert any(r.getMessage().startswith("TOKENLESS CONNECT host.example.com") for r in caplog.records)


def test_without_credentials_or_header_the_migration_mode_still_guesses_and_fails_closed(monkeypatch):
    drive = Drive(monkeypatch)
    writer = drive.connect([])
    assert _status(writer).startswith("HTTP/1.1 409") and drive.guess_calls == 1 and drive.evaluated == []


def test_negative_when_a_token_is_required_a_request_without_one_is_refused_and_counted(monkeypatch, caplog):
    drive = Drive(monkeypatch, require=True)
    with caplog.at_level(logging.INFO, logger=proxy.logger.name):
        writer = drive.connect([])
    assert _status(writer).startswith("HTTP/1.1 407") and writer.data.endswith(b"run_token_required")
    assert drive.evaluated == [] and drive.guess_calls == 0 and drive.connected == []
    assert any("TOKENLESS CONNECT host.example.com" in r.getMessage() and "refused" in r.getMessage() for r in caplog.records)


def test_negative_when_a_token_is_required_the_header_is_no_identity(monkeypatch):
    drive = Drive(monkeypatch, require=True)
    writer = drive.connect([f"X-ASM-Engagement-Id: {ENG_A}"])
    assert _status(writer).startswith("HTTP/1.1 407") and drive.evaluated == [] and drive.connected == []


def test_when_a_token_is_required_a_valid_one_is_accepted(monkeypatch):
    drive = Drive(monkeypatch, require=True)
    writer = drive.connect([f"Proxy-Authorization: {_auth(_token())}"])
    assert _status(writer) == "HTTP/1.1 200 Connection Established" and [e[0] for e in drive.evaluated] == [ENG_A]


def test_a_proxy_bound_to_one_engagement_ignores_credentials_and_keeps_its_engagement(monkeypatch):
    drive = Drive(monkeypatch, bound=ENG_B)
    writer = drive.connect([f"Proxy-Authorization: {_basic('asm', 'not-even-a-token')}"])
    assert _status(writer) == "HTTP/1.1 200 Connection Established"
    assert [e[0] for e in drive.evaluated] == [ENG_B] and drive.live_checks == []


# --- credentials never reach a target -----------------------------------------------------------------------------

def test_negative_plain_http_never_forwards_the_credentials_or_the_engagement_header(monkeypatch):
    drive = Drive(monkeypatch)
    drive.get([f"Proxy-Authorization: {_auth(_token())}", f"X-ASM-Engagement-Id: {ENG_B}", "Proxy-Connection: keep-alive",
               "User-Agent: probe"])
    sent = drive.upstream.written.decode("latin-1").lower()
    assert sent.startswith("get /path?q=1 http/1.1")
    assert "proxy-authorization" not in sent and "x-asm-engagement-id" not in sent and "proxy-connection" not in sent
    assert "user-agent: probe" in sent and "host: host.example.com" in sent
    assert _token().split(".")[0] not in sent


def test_negative_the_token_is_not_in_the_proxys_own_reply_or_logs(monkeypatch, caplog):
    drive = Drive(monkeypatch, live=False)
    token = _token()
    with caplog.at_level(logging.DEBUG):
        writer = drive.connect([f"Proxy-Authorization: {_auth(token)}"])
    assert token not in writer.data.decode("latin-1")
    assert all(token not in r.getMessage() for r in caplog.records)
    bad = Drive(monkeypatch)
    with caplog.at_level(logging.DEBUG):
        writer = bad.connect([f"Proxy-Authorization: {_auth(_token(secret='other'))}"])
    assert all("other" not in r.getMessage() for r in caplog.records)
