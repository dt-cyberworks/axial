"""TC-ASSETREVIEW-007: discovery.run()'s in-scope computation respects deny
precedence (deny beats allow), mirroring the Scope Gateway's own invariant.
Previously discovery only ever consulted allow rules."""

from __future__ import annotations

from app.tasks import discovery


class RecordingClient:
    def __init__(self, scope_assets, known=None):
        self._scope_assets = scope_assets
        self._known = known or []
        self.discovered_assets = []

    def list_scope_assets(self, engagement_id):
        return self._scope_assets

    def list_discovered_assets(self, engagement_id, in_scope=None):
        return self._known

    def add_discovered_asset(self, engagement_id, **fields):
        self.discovered_assets.append(fields)
        return {"id": f"asset-{len(self.discovered_assets)}"}


def _run(monkeypatch, scope_assets):
    rec = RecordingClient(scope_assets)
    monkeypatch.setattr(discovery, "client", rec)
    monkeypatch.setattr(discovery, "_enrich_dns", lambda *a, **k: None)
    # Hermetic: no real OSINT calls. Patch the aggregator so no source hits the network.
    monkeypatch.setattr(discovery, "_passive_subdomains", lambda domain: set())
    return rec


def test_deny_domain_overrides_matching_allow(monkeypatch):
    rec = _run(monkeypatch, [
        {"rule": "allow", "asset_type": "domain", "value": "example.com"},
        {"rule": "deny", "asset_type": "domain", "value": "orphan.example.com"},
    ])
    # Vorbestand liefert BEIDE Namen als bereits bekannt, damit ohne crt.sh
    # trotzdem beide klassifiziert werden.
    rec._known = [
        {"value": "example.com", "in_scope": True},
        {"value": "orphan.example.com", "in_scope": True},
    ]

    discovery.run("11111111-1111-1111-1111-111111111111")

    by_value = {a["value"]: a["in_scope"] for a in rec.discovered_assets}
    assert by_value["orphan.example.com"] is False  # deny gewinnt, trotz allow-Match
    assert by_value["example.com"] is True           # unbeeinflusst


def test_deny_wildcard_overrides_matching_allow(monkeypatch):
    rec = _run(monkeypatch, [
        {"rule": "allow", "asset_type": "domain", "value": "example.com"},
        {"rule": "deny", "asset_type": "wildcard", "value": "*.internal.example.com"},
    ])
    rec._known = [
        {"value": "example.com", "in_scope": True},
        {"value": "db.internal.example.com", "in_scope": True},
    ]

    discovery.run("11111111-1111-1111-1111-111111111111")

    by_value = {a["value"]: a["in_scope"] for a in rec.discovered_assets}
    assert by_value["db.internal.example.com"] is False
    assert by_value["example.com"] is True


def test_no_deny_rule_leaves_allow_matching_unaffected(monkeypatch):
    rec = _run(monkeypatch, [
        {"rule": "allow", "asset_type": "domain", "value": "example.com"},
    ])
    rec._known = [{"value": "app.example.com", "in_scope": True}]

    discovery.run("11111111-1111-1111-1111-111111111111")

    by_value = {a["value"]: a["in_scope"] for a in rec.discovered_assets}
    assert by_value["app.example.com"] is True


def test_allow_domain_scope_matching_is_case_insensitive(monkeypatch):
    """Found live in production: an allow scope value entered with uppercase
    letters ("Pentest-Ground.com") left every already-lowercased discovered
    name computed out of scope (in_scope=False), even the apex domain itself,
    because real_domains preserved the original case while every discovered
    value is lowercased. The tool-based scan still ran and recorded findings
    normally, but the agent phase's "no in-scope assets" check saw zero
    matches and no-opped - DNS names are case-insensitive, so this must
    match regardless of how the operator capitalized the scope value."""
    rec = _run(monkeypatch, [
        {"rule": "allow", "asset_type": "domain", "value": "Pentest-Ground.com"},
    ])
    rec._known = [
        {"value": "pentest-ground.com", "in_scope": True},
        {"value": "www.pentest-ground.com", "in_scope": True},
    ]

    discovery.run("11111111-1111-1111-1111-111111111111")

    by_value = {a["value"]: a["in_scope"] for a in rec.discovered_assets}
    assert by_value["pentest-ground.com"] is True
    assert by_value["www.pentest-ground.com"] is True
