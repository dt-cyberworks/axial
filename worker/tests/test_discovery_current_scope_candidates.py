"""REQ-ASSETREVIEW-009 / GitHub issue #33: only current, active-eligible
candidates leave discovery.

discovery.run() hands its result straight to the asset-review gate and the
fingerprint phase (worker/app/tasks/pipeline.py), and the agent phase reads
the stored in_scope flag. These tests pin down that stale, denied,
out-of-scope, passive-only, and suffix-lookalike values never become
candidates, and that the stored flag follows the current scope.
"""

from __future__ import annotations

import httpx

from app.raw_nmap import HostDiscoveryOutcome
from app.tasks import discovery

ENGAGEMENT_ID = "11111111-1111-1111-1111-111111111111"
SCAN_RUN_ID = "22222222-2222-2222-2222-222222222222"


class RecordingClient:
    def __init__(self, scope_assets, known=None):
        self._scope_assets = scope_assets
        self._known = known or []
        self.discovered_assets = []

    def get_discovery_options(self, engagement_id):
        return {"subfinder": False, "crawling": False, "oob": False, "screenshots": False}

    def list_scope_assets(self, engagement_id):
        return self._scope_assets

    def list_discovered_assets(self, engagement_id, in_scope=None):
        return [k for k in self._known if in_scope is None or k.get("in_scope") == in_scope]

    def add_discovered_asset(self, engagement_id, **fields):
        self.discovered_assets.append(fields)
        return {"id": f"asset-{len(self.discovered_assets)}"}

    def acquire_raw_egress_lease(self, engagement_id, **fields):
        return {"allowed": True, "lease_token": "tok", "max_rate": 100}

    def is_cancel_requested(self, scan_run_id):
        return False

    def record_tool_execution(self, engagement_id, **fields):
        return {"id": "exec-1"}


def _setup(monkeypatch, scope_assets, *, known=None, passive=None, live_hosts=None):
    rec = RecordingClient(scope_assets, known)
    monkeypatch.setattr(discovery, "client", rec)
    monkeypatch.setattr(discovery.tool_execution, "client", rec)
    monkeypatch.setattr(discovery, "_enrich_dns", lambda *a, **k: None)
    monkeypatch.setattr(discovery, "_passive_subdomains", lambda domain: set(passive or ()))
    monkeypatch.setattr(discovery.raw_egress_gateway, "acquire_reservation", lambda *a, **k: {"reservation_token": "s"})
    monkeypatch.setattr(discovery.raw_egress_gateway, "release_reservation", lambda *a, **k: None)
    monkeypatch.setattr(
        discovery, "execute_host_discovery_sweep",
        lambda cidr, token, **k: HostDiscoveryOutcome(
            result={"success": True, "exit_code": 0, "stdout": "", "stderr": "", "error_reason": None},
            live_hosts=live_hosts or []),
    )
    return rec


def _values(out):
    return {r["value"] for r in out}


def _stored(rec, value):
    return [a["in_scope"] for a in rec.discovered_assets if a["value"] == value]


# --- ip / cidr ------------------------------------------------------------------

def test_a_known_swept_ip_now_covered_by_a_deny_rule_is_not_a_candidate_and_is_demoted(monkeypatch):
    rec = _setup(monkeypatch, [
        {"rule": "allow", "asset_type": "cidr", "value": "203.0.113.0/28", "active_allowed": True},
        {"rule": "deny", "asset_type": "ip", "value": "203.0.113.9", "active_allowed": False},
    ], known=[{"id": "old-1", "value": "203.0.113.9", "in_scope": True, "discovered_via": "cidr-sweep"}])
    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)
    assert "203.0.113.9" not in _values(out)
    assert _stored(rec, "203.0.113.9") == [False]


def test_a_known_ip_no_longer_covered_by_any_allow_rule_is_not_a_candidate_and_is_demoted(monkeypatch):
    rec = _setup(monkeypatch, [
        {"rule": "allow", "asset_type": "cidr", "value": "198.51.100.0/28", "active_allowed": True},
    ], known=[{"id": "old-1", "value": "203.0.113.9", "in_scope": True, "discovered_via": "cidr-sweep"}])
    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)
    assert "203.0.113.9" not in _values(out)
    assert _stored(rec, "203.0.113.9") == [False]


def test_a_known_ip_still_covered_stays_a_candidate_without_rewriting_it(monkeypatch):
    rec = _setup(monkeypatch, [
        {"rule": "allow", "asset_type": "cidr", "value": "203.0.113.0/28", "active_allowed": True},
    ], known=[{"id": "old-1", "value": "203.0.113.9", "in_scope": True}])
    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)
    assert {"value": "203.0.113.9", "asset_id": "old-1", "asset_type": "ip"} in out
    assert _stored(rec, "203.0.113.9") == []


def test_negative_a_passive_only_ip_asset_is_never_a_candidate(monkeypatch):
    rec = _setup(monkeypatch, [
        {"rule": "allow", "asset_type": "ip", "value": "203.0.113.5", "active_allowed": False},
    ])
    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)
    assert "203.0.113.5" not in _values(out)
    assert _stored(rec, "203.0.113.5") == []  # like a passive-only cidr: never registered as a target


def test_negative_a_directly_allowed_but_denied_ip_is_recorded_out_of_scope_and_not_a_candidate(monkeypatch):
    rec = _setup(monkeypatch, [
        {"rule": "allow", "asset_type": "ip", "value": "203.0.113.5", "active_allowed": True},
        {"rule": "deny", "asset_type": "cidr", "value": "203.0.113.0/29", "active_allowed": False},
    ])
    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)
    assert "203.0.113.5" not in _values(out)
    assert _stored(rec, "203.0.113.5") == [False]


# --- domains --------------------------------------------------------------------

def test_a_known_name_that_fell_out_of_scope_is_demoted_and_not_a_candidate(monkeypatch):
    rec = _setup(monkeypatch, [
        {"rule": "allow", "asset_type": "domain", "value": "example.com", "active_allowed": True},
    ], known=[{"id": "k1", "value": "shop.other.org", "in_scope": True}])
    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)
    assert "shop.other.org" not in _values(out)
    assert _stored(rec, "shop.other.org") == [False]
    assert "example.com" in _values(out)


def test_a_denied_name_is_recorded_out_of_scope_and_not_a_candidate(monkeypatch):
    rec = _setup(monkeypatch, [
        {"rule": "allow", "asset_type": "domain", "value": "example.com", "active_allowed": True},
        {"rule": "deny", "asset_type": "domain", "value": "legacy.example.com", "active_allowed": False},
    ], passive={"legacy.example.com", "app.example.com"})
    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)
    assert _values(out) == {"example.com", "app.example.com"}
    assert _stored(rec, "legacy.example.com") == [False]


def test_a_passive_only_domain_is_inventory_not_a_candidate(monkeypatch):
    rec = _setup(monkeypatch, [
        {"rule": "allow", "asset_type": "domain", "value": "example.com", "active_allowed": False},
    ], passive={"app.example.com"})
    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)
    assert out == []
    assert _stored(rec, "app.example.com") == [True]  # in scope (passive DNS etc.), just not an active target


def test_a_wildcard_rule_covers_subdomains_but_not_the_bare_root_like_the_gateway(monkeypatch):
    rec = _setup(monkeypatch, [
        {"rule": "allow", "asset_type": "wildcard", "value": "*.example.com", "active_allowed": True},
    ], known=[{"id": "k1", "value": "example.com", "in_scope": True}], passive={"app.example.com"})
    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)
    assert _values(out) == {"app.example.com"}
    assert _stored(rec, "example.com") == [False]


def test_mixed_active_and_passive_rules_the_active_one_makes_the_name_a_candidate(monkeypatch):
    _setup(monkeypatch, [
        {"rule": "allow", "asset_type": "domain", "value": "example.com", "active_allowed": False},
        {"rule": "allow", "asset_type": "wildcard", "value": "*.api.example.com", "active_allowed": True},
    ], passive={"v1.api.example.com", "www.example.com"})
    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)
    assert _values(out) == {"v1.api.example.com"}


# --- passive sources: label boundary ---------------------------------------------

class _Resp:
    def __init__(self, *, json_data=None, text=""):
        self._json, self.text = json_data, text

    def raise_for_status(self):
        return None

    def json(self):
        return self._json


def test_negative_lookalike_names_from_passive_sources_are_dropped(monkeypatch):
    def fake_get(url, **kwargs):
        if "crt.sh" in url:
            return _Resp(json_data=[{"name_value": "badexample.com\nwww.example.com\n*.api.example.com"}])
        if "certspotter" in url:
            return _Resp(json_data=[{"dns_names": ["notexample.com", "mail.example.com", "example.com"]}])
        return _Resp(text="evilexample.com,1.2.3.4\nvpn.example.com,1.2.3.5\n")

    monkeypatch.setattr(discovery.httpx, "get", fake_get)
    found = discovery._passive_subdomains("example.com")
    assert found == {"www.example.com", "api.example.com", "mail.example.com", "example.com", "vpn.example.com"}


def test_negative_lookalike_passive_results_never_become_candidates(monkeypatch):
    rec = _setup(monkeypatch, [
        {"rule": "allow", "asset_type": "domain", "value": "example.com", "active_allowed": True},
    ])
    # Even if a lookalike reached the pool, the gateway-identical matching keeps it out.
    monkeypatch.setattr(discovery, "_passive_subdomains", lambda domain: {"badexample.com", "a.example.com"})
    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)
    assert _values(out) == {"example.com", "a.example.com"}
    assert _stored(rec, "badexample.com") == [False]


def test_passive_source_failures_stay_isolated(monkeypatch):
    def failing_get(url, **kwargs):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(discovery.httpx, "get", failing_get)
    monkeypatch.setattr(discovery.time, "sleep", lambda s: None)
    assert discovery._passive_subdomains("example.com") == set()
