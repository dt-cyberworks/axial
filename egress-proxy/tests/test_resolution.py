"""Host-basierte Engagement-Aufloesung des Egress-Proxy (REQ-EGRESS-001).

Reine Logik: candidate_engagements() wird gemockt; getestet wird, dass der Proxy
die richtige Engagement aus dem Ziel-Host waehlt, deny beruecksichtigt und bei
Mehrdeutigkeit/keinem Treffer fail-closed geht (None)."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://x:x@localhost:5432/x")

import asyncio

from app import proxy  # noqa: E402


def _eng(eid, allow, deny=None):
    return {"engagement_id": eid,
            "allow": [{"asset_type": "domain", "value": v, "path_pattern": None} for v in allow],
            "deny": [{"asset_type": "domain", "value": v, "path_pattern": None} for v in (deny or [])]}


@pytest.fixture(autouse=True)
def _no_materialized_ips(monkeypatch):
    # Standard: keine materialisierten IPs (Tests, die es brauchen, ueberschreiben).
    monkeypatch.setattr(proxy, "active_engagements_for_materialized_ip", lambda ip: [])


def test_single_match_resolves(monkeypatch):
    monkeypatch.setattr(proxy, "candidate_engagements", lambda: [_eng("E1", ["example.org"])])
    assert asyncio.run(proxy.resolve_engagement_for_host("cloud.example.org")) == ("E1", "host")


def test_no_match_fails_closed(monkeypatch):
    monkeypatch.setattr(proxy, "candidate_engagements", lambda: [_eng("E1", ["example.com"])])
    assert asyncio.run(proxy.resolve_engagement_for_host("cloud.example.org")) == (None, "no_engagement_for_host")


def test_deny_suppresses_candidate(monkeypatch):
    # E1 hat den Host im allow, aber auch im deny -> nicht auswaehlbar -> keiner uebrig.
    monkeypatch.setattr(proxy, "candidate_engagements",
                        lambda: [_eng("E1", ["example.org"], deny=["cloud.example.org"])])
    assert asyncio.run(proxy.resolve_engagement_for_host("cloud.example.org")) == (None, "no_engagement_for_host")


def test_ambiguous_fails_closed(monkeypatch):
    monkeypatch.setattr(proxy, "candidate_engagements",
                        lambda: [_eng("E1", ["example.org"]), _eng("E2", ["example.org"])])
    assert asyncio.run(proxy.resolve_engagement_for_host("cloud.example.org")) == (None, "ambiguous_host")


def test_exact_domain_match(monkeypatch):
    monkeypatch.setattr(proxy, "candidate_engagements", lambda: [_eng("E1", ["example.org"])])
    assert asyncio.run(proxy.resolve_engagement_for_host("example.org")) == ("E1", "host")


def test_materialized_ip_resolves(monkeypatch):
    # Tool verbindet per IP (testssl --ip). Kein Domain-Match, aber die IP ist
    # fuer E1 auditiert materialisiert -> aufgeloest.
    monkeypatch.setattr(proxy, "candidate_engagements", lambda: [_eng("E1", ["example.org"])])
    monkeypatch.setattr(proxy, "active_engagements_for_materialized_ip",
                        lambda ip: ["E1"] if ip == "93.254.65.195" else [])
    assert asyncio.run(proxy.resolve_engagement_for_host("93.254.65.195")) == ("E1", "host")


def test_unmaterialized_ip_fails_closed(monkeypatch):
    monkeypatch.setattr(proxy, "candidate_engagements", lambda: [_eng("E1", ["example.org"])])
    assert asyncio.run(proxy.resolve_engagement_for_host("93.254.65.195")) == (None, "no_engagement_for_host")
