"""TC-FIDELITY-005: the egress-proxy is the independent network-layer scope
enforcement point (Deployment-Architektur Kap. 6.2) - it must deny an
otherwise in-scope host on a port outside the engagement's tcp_port_from/to
window, not just rely on tool commands being built correctly."""

from __future__ import annotations

import datetime as dt
import os

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://x:x@localhost:5432/x")

import asyncio

from app import proxy  # noqa: E402


def _eng(port_from=1, port_to=65535, status="active", source="managed"):
    now = dt.datetime.now(dt.timezone.utc)
    return {
        "id": "E1",
        "status": status,
        "source": source,
        "authorized_from": now - dt.timedelta(days=1),
        "authorized_until": now + dt.timedelta(days=1),
        "tcp_port_from": port_from,
        "tcp_port_to": port_to,
    }


@pytest.fixture(autouse=True)
def _in_scope_host(monkeypatch):
    # Host-Scope ist fuer diese Tests immer erlaubt - isoliert die Port-Pruefung.
    monkeypatch.setattr(proxy, "matching_scope_assets",
                         lambda eid, host, path, rule: (
                             [{"asset_type": "domain", "value": "example.com", "path_pattern": None}]
                             if rule == "allow" else []
                         ))
    monkeypatch.setattr(proxy, "is_materialized_ip", lambda eid, ip: False)


def test_port_outside_configured_window_is_denied(monkeypatch):
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng(port_from=4280, port_to=4280))
    allowed, reason = asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 443))
    assert (allowed, reason) == (False, "out_of_scope_port")


def test_port_inside_configured_window_is_allowed(monkeypatch):
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng(port_from=4280, port_to=4280))
    allowed, reason = asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 4280))
    assert (allowed, reason) == (True, "allow")


def test_default_full_range_allows_any_port(monkeypatch):
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng(port_from=1, port_to=65535))
    allowed, reason = asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 443))
    assert (allowed, reason) == (True, "allow")


def test_port_at_window_boundaries_is_allowed(monkeypatch):
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng(port_from=8000, port_to=8100))
    assert asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 8000)) == (True, "allow")
    assert asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 8100)) == (True, "allow")


def test_port_just_outside_window_boundaries_is_denied(monkeypatch):
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng(port_from=8000, port_to=8100))
    assert asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 7999)) == (False, "out_of_scope_port")
    assert asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 8101)) == (False, "out_of_scope_port")


def test_deny_still_wins_over_port_scope(monkeypatch):
    # Ein per Name geblockter Host darf NICHT ueber einen zufaellig passenden
    # Port "gerettet" werden - deny hat weiterhin unbedingten Vorrang.
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng(port_from=1, port_to=65535))
    monkeypatch.setattr(proxy, "matching_scope_assets",
                         lambda eid, host, path, rule: (
                             [{"asset_type": "domain", "value": "example.com", "path_pattern": None}]
                             if rule == "deny" else []
                         ))
    allowed, reason = asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 443))
    assert (allowed, reason) == (False, "out_of_scope_deny")


def test_out_of_scope_host_is_denied_before_port_is_even_considered(monkeypatch):
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng(port_from=1, port_to=65535))
    monkeypatch.setattr(proxy, "matching_scope_assets", lambda eid, host, path, rule: [])
    allowed, reason = asyncio.run(proxy.evaluate("E1", "not-in-scope.example.org", "/", 4280))
    assert (allowed, reason) == (False, "not_in_scope")


# REQ-PORTSCOPE-002: per-target port ranges (ScopeAsset.port_from/to),
# intersected with the engagement's tcp_port_from/to ceiling.

def test_target_with_no_port_override_still_gets_the_full_ceiling(monkeypatch):
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng(port_from=1, port_to=65535))
    monkeypatch.setattr(proxy, "matching_scope_assets",
                         lambda eid, host, path, rule: (
                             [{"asset_type": "domain", "value": "example.com", "path_pattern": None,
                               "port_from": None, "port_to": None}]
                             if rule == "allow" else []
                         ))
    assert asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 22)) == (True, "allow")


def test_negative_target_specific_range_narrower_than_ceiling_blocks_a_port_the_ceiling_would_allow(monkeypatch):
    """The core negative test: a wide engagement ceiling (1-65535) must NOT
    rescue a port outside one specific target's own narrower authorization -
    exactly the scenario a per-target range exists to express (e.g. a public
    web domain scoped to 443 only, even though the engagement overall allows
    a much wider range for other targets)."""
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng(port_from=1, port_to=65535))
    monkeypatch.setattr(proxy, "matching_scope_assets",
                         lambda eid, host, path, rule: (
                             [{"asset_type": "domain", "value": "example.com", "path_pattern": None,
                               "port_from": 443, "port_to": 443}]
                             if rule == "allow" else []
                         ))
    assert asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 443)) == (True, "allow")
    assert asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 22)) == (False, "out_of_scope_port")


def test_negative_narrowing_the_ceiling_after_the_fact_immediately_narrows_a_target_too(monkeypatch):
    """Proves the range is re-intersected fresh on every call, not trusted
    from the stored asset row alone: a target's own range (1-8100) is wider
    than a ceiling that gets narrowed later (to 8000-8100) - the effective
    range must shrink to the intersection immediately, no asset-row edit
    required."""
    monkeypatch.setattr(proxy, "matching_scope_assets",
                         lambda eid, host, path, rule: (
                             [{"asset_type": "domain", "value": "example.com", "path_pattern": None,
                               "port_from": 1, "port_to": 8100}]
                             if rule == "allow" else []
                         ))

    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng(port_from=1, port_to=65535))
    assert asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 22)) == (True, "allow")

    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng(port_from=8000, port_to=8100))
    assert asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 22)) == (False, "out_of_scope_port")
    assert asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 8050)) == (True, "allow")


def test_port_allowed_if_it_falls_within_any_matched_allow_assets_range(monkeypatch):
    """Two allow-scope rows both match the same host (e.g. an exact domain
    and a covering wildcard) with different port ranges - mirrors the
    existing 'any allow match legitimizes the host' semantics for names."""
    monkeypatch.setattr(proxy, "load_engagement", lambda eid: _eng(port_from=1, port_to=65535))
    monkeypatch.setattr(proxy, "matching_scope_assets",
                         lambda eid, host, path, rule: (
                             [
                                 {"asset_type": "domain", "value": "host.example.com", "path_pattern": None,
                                  "port_from": 443, "port_to": 443},
                                 {"asset_type": "wildcard", "value": "*.example.com", "path_pattern": None,
                                  "port_from": 8080, "port_to": 8080},
                             ]
                             if rule == "allow" else []
                         ))
    assert asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 443)) == (True, "allow")
    assert asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 8080)) == (True, "allow")
    assert asyncio.run(proxy.evaluate("E1", "host.example.com", "/", 22)) == (False, "out_of_scope_port")
