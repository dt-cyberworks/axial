"""Integrationstest der auditierten DNS-Materialisierung (raw egress fuer nmap).

DNS wird gemockt (socket.getaddrinfo), damit der Test deterministisch ist -
verifiziert wird die Logik: Namenssammlung, deny-Vorrang auf IP-Ebene,
resolved_host-Persistenz, Audit-Eintrag und Einspeisung in die raw-egress-policy.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest

from tests.integration.owners import make_owner
from app.gateway import dns_materialization
from app.gateway.dns_materialization import materialize, materialized_ips
from app.gateway.raw_egress_policy import render_for_engagement


def _fake_getaddrinfo(mapping: dict[str, list[str]]):
    def _inner(host, *args, **kwargs):
        ips = mapping.get(host)
        if not ips:
            import socket
            raise socket.gaierror("name not found")
        return [(None, None, None, "", (ip, 0)) for ip in ips]
    return _inner


def _active_domain_engagement(db):
    from app.models.engagement import Engagement, ScopeAsset, ToolGrant

    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        owner_user_id=make_owner(db).id,
        title="dns-mat", source="own_domain", status="active",
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
    )
    db.add(eng)
    db.flush()
    db.add(
        ScopeAsset(engagement_id=eng.id, rule="allow", asset_type="domain",
                   value="example.org", active_allowed=True, authorization_verified=True)
    )
    db.add(ToolGrant(engagement_id=eng.id, tool_category="fingerprint", mode="active",
                     requires_manual_approval=False))
    db.commit()
    return eng


def test_materialize_resolves_names_and_feeds_policy(db, monkeypatch):
    from app.models.asset import DiscoveredAsset

    eng = _active_domain_engagement(db)
    # Eine in-scope entdeckte Subdomain (durch die domain autorisiert).
    db.add(DiscoveredAsset(engagement_id=eng.id, asset_type="domain",
                           value="cloud.example.org", in_scope=True, discovered_via="crt.sh"))
    db.commit()

    monkeypatch.setattr(dns_materialization.socket, "getaddrinfo", _fake_getaddrinfo({
        "example.org": ["93.254.65.195"],
        "cloud.example.org": ["93.254.65.196"],
    }))

    result = materialize(db, eng.id)
    resolved_ips = sorted(r["ip_address"] for r in result.resolved)
    assert resolved_ips == ["93.254.65.195", "93.254.65.196"]

    # In die raw-egress-policy eingespeist -> beide als /32-Block.
    rendered = render_for_engagement(db, eng.id)
    cidrs = sorted(b["cidr"] for b in rendered.ip_blocks)
    assert cidrs == ["93.254.65.195/32", "93.254.65.196/32"]


def test_materialize_applies_deny_precedence_on_resolved_ip(db, monkeypatch):
    from app.models.engagement import ScopeAsset

    eng = _active_domain_engagement(db)
    # deny genau die IP, auf die der Name aufloest.
    db.add(ScopeAsset(engagement_id=eng.id, rule="deny", asset_type="ip", value="93.254.65.195"))
    db.commit()

    monkeypatch.setattr(dns_materialization.socket, "getaddrinfo", _fake_getaddrinfo({
        "example.org": ["93.254.65.195"],
    }))

    result = materialize(db, eng.id)
    assert result.resolved == []
    assert result.denied_ips[0]["ip_address"] == "93.254.65.195"
    assert result.denied_ips[0]["reason"] == "deny_ip_precedence"
    # Nichts materialisiert -> Policy bleibt fail-closed (kein egress).
    assert materialized_ips(db, eng.id) == []


def test_materialize_records_audit_entry(db, monkeypatch):
    from app.models.audit import AuditLog

    eng = _active_domain_engagement(db)
    monkeypatch.setattr(dns_materialization.socket, "getaddrinfo", _fake_getaddrinfo({
        "example.org": ["93.254.65.195"],
    }))
    materialize(db, eng.id)

    entry = db.query(AuditLog).filter(
        AuditLog.engagement_id == eng.id, AuditLog.action == "dns_materialization"
    ).one()
    assert entry.payload["resolved"][0]["ip_address"] == "93.254.65.195"


def test_materialize_requires_active_engagement(db):
    from app.models.engagement import Engagement

    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(owner_user_id=make_owner(db).id, title="draft", source="own_domain", status="draft",
                     authorized_from=now, authorized_until=now + dt.timedelta(days=1))
    db.add(eng)
    db.commit()
    with pytest.raises(ValueError, match="engagement_not_active"):
        materialize(db, eng.id)