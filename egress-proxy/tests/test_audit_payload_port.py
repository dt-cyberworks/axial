"""Found live 2026-08-09: an operator inspecting the egress-proxy's audit
trail for a plain-HTTP ALLOW decision could not see which port the Scope
Gateway actually enforced against - the payload carried only host/path/
method. Port enforcement itself was never wrong (`evaluate()` is the sole
network enforcement point and always checked it - proven by the CONNECT
path's payload, which already included port), but the audit record could not
prove that on its own, undermining the audit trail's purpose as an
independent, inspectable record of what the gateway actually decided."""

from __future__ import annotations

import asyncio

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


def test_negative_plain_http_allow_payload_must_record_the_enforced_port(monkeypatch):
    """The old payload {"method", "host", "path"} would satisfy every
    assertion below except the last - proving this test would have failed
    against the pre-fix code."""
    captured = {}

    async def fake_submit_audit_or_deny(_writer, _eid, decision, reason, payload):
        captured["decision"] = decision
        captured["reason"] = reason
        captured["payload"] = payload
        return True

    async def fake_open_connection(_host, _port):
        return _Reader(), _Writer()

    async def fake_relay(*_args, **_kwargs):
        return None

    async def fake_evaluate(eid, host, path, port):
        return True, "allow"

    monkeypatch.setattr(proxy, "evaluate", fake_evaluate)
    monkeypatch.setattr(proxy, "vet_target_host", lambda host, port: host)
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: {"source": "managed"})
    monkeypatch.setattr(proxy, "_submit_audit_or_deny", fake_submit_audit_or_deny)
    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    monkeypatch.setattr(proxy, "_relay", fake_relay)

    asyncio.run(
        proxy._forward_plain_http(
            _Reader(),
            _Writer(),
            "GET",
            "http://www.pentest-ground.com:4280/deploy",
            {"host": "www.pentest-ground.com:4280"},
            "019fe768-acdf-77d8-bb63-3ce9e9cb4c23",
        )
    )

    assert captured["decision"] == "ALLOW"
    assert captured["payload"]["host"] == "www.pentest-ground.com"
    assert captured["payload"]["path"] == "/deploy"
    assert captured["payload"]["port"] == 4280


# --- REQ-DISCO-002: a denial must be distinguishable from a target response --

def test_every_self_generated_denial_carries_the_marker_header():
    """Found live: a scanned name was NXDOMAIN, this proxy answered every
    request `403 Blocked` + `dns_resolution_failed`, and httpx/ffuf/nikto/
    nuclei all read that as the TARGET responding - producing a phantom
    service and 1800 fabricated "discovered paths" for a host that does not
    exist. Every response the proxy synthesises must say so."""
    for code, reason in (
        (403, "dns_resolution_failed"),
        (403, "out_of_scope_deny"),
        (403, "out_of_scope_port"),
        (403, "not_in_scope"),
        (403, "blocked_loopback_address"),
        (503, "audit_unavailable"),
        (503, "proxy_capacity_exhausted"),
        (400, "bad_request"),
        (407, "no_engagement_for_host"),
        (502, "connect_failed: [Errno -2] Name or service not known"),
    ):
        writer = _Writer()
        asyncio.run(proxy._deny(writer, code, reason))
        text = writer.data.decode("latin-1")
        assert f"{proxy.DENIAL_MARKER_HEADER}:" in text, f"{reason} has no denial marker"
        assert reason.split(":")[0] in text


def test_the_marker_value_stays_a_single_well_formed_header_line():
    """`reason` can carry an exception string (connect_failed: <OSError>), so
    the value must not be able to open a second header line or run unbounded.

    CRLF is collapsed to spaces rather than stripped: the injected text
    survives as harmless content INSIDE the marker value, which is the point -
    it never becomes a header of its own."""
    writer = _Writer()
    asyncio.run(proxy._deny(writer, 502, "connect_failed: bad\r\nX-Injected: yes\n" + "A" * 500))
    head = writer.data.decode("latin-1").split("\r\n\r\n", 1)[0]
    lines = head.split("\r\n")

    marker_lines = [l for l in lines if l.startswith(proxy.DENIAL_MARKER_HEADER)]
    assert len(marker_lines) == 1
    # The injected text did NOT become its own header line...
    assert not any(l.startswith("X-Injected") for l in lines)
    # ...it is contained within the marker value, which stays bounded.
    assert len(marker_lines[0]) < 260


def test_negative_a_relayed_target_response_never_gains_the_marker(monkeypatch):
    """A genuine 403 from a real in-scope target must still be recorded
    normally - the fix must not suppress findings on servers that
    legitimately answer 403. The proxy only marks what it generates itself,
    and a target cannot forge it."""
    import inspect
    # The marker is emitted from _deny only - the one function that
    # SYNTHESISES a response. The relay path copies target bytes verbatim and
    # never adds it, so a target cannot forge it to suppress its own findings.
    assert "DENIAL_MARKER_HEADER" in inspect.getsource(proxy._deny)
    assert "DENIAL_MARKER_HEADER" not in inspect.getsource(proxy._relay)
    assert "DENIAL_MARKER_HEADER" not in inspect.getsource(proxy._forward_plain_http)
