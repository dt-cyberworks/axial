"""REQ-CIDRDISC-001/002/003: discovery.py's active ip/cidr host-discovery
path - a single `ip` scope asset registers directly (like a domain's
scope-direct entry), a `cidr` asset needs an authorized liveness sweep first,
and both flow into the same candidate list the fingerprint phase and the
asset-review gate already consume, carrying their real asset_type."""

from __future__ import annotations

from app.raw_nmap import HostDiscoveryOutcome
from app.tasks import discovery


class RecordingClient:
    def __init__(self, scope_assets, known=None, lease=None):
        self._scope_assets = scope_assets
        self._known = known or []
        self._lease = lease or {"allowed": True, "lease_token": "tok", "max_rate": 100}
        self.discovered_assets = []
        self.tool_executions = []
        self.leases_requested = []

    def get_discovery_options(self, engagement_id):
        return {"subfinder": False, "crawling": False, "oob": False, "screenshots": False}

    def list_scope_assets(self, engagement_id):
        return self._scope_assets

    def list_discovered_assets(self, engagement_id, in_scope=None):
        return self._known

    def add_discovered_asset(self, engagement_id, **fields):
        self.discovered_assets.append(fields)
        return {"id": f"asset-{len(self.discovered_assets)}"}

    def acquire_raw_egress_lease(self, engagement_id, **fields):
        self.leases_requested.append(fields)
        return self._lease

    def is_cancel_requested(self, scan_run_id):
        return False

    def record_tool_execution(self, engagement_id, **fields):
        self.tool_executions.append(fields)
        return {"id": "exec-1"}


def _setup(monkeypatch, scope_assets, *, known=None, lease=None, live_hosts=None, sweep_error=None):
    rec = RecordingClient(scope_assets, known=known, lease=lease)
    monkeypatch.setattr(discovery, "client", rec)
    # tool_execution.record() uses its OWN module-level `client` binding
    # (from app.control_plane_client import client), a separate reference
    # from discovery.client - both must point at the same recording double.
    monkeypatch.setattr(discovery.tool_execution, "client", rec)
    monkeypatch.setattr(discovery, "_enrich_dns", lambda *a, **k: None)
    monkeypatch.setattr(discovery, "_passive_subdomains", lambda domain: set())
    monkeypatch.setattr(discovery.raw_egress_gateway, "acquire_reservation", lambda *a, **k: {"reservation_token": "slot"})
    monkeypatch.setattr(discovery.raw_egress_gateway, "release_reservation", lambda *a, **k: None)

    def fake_sweep(cidr, lease_token, *, reservation_token, max_rate, scan_run_id=None):
        if sweep_error is not None:
            raise sweep_error
        result = {"success": True, "exit_code": 0, "stdout": "", "stderr": "", "error_reason": None}
        return HostDiscoveryOutcome(result=result, live_hosts=live_hosts or [])

    monkeypatch.setattr(discovery, "execute_host_discovery_sweep", fake_sweep)
    return rec


ENGAGEMENT_ID = "11111111-1111-1111-1111-111111111111"
SCAN_RUN_ID = "22222222-2222-2222-2222-222222222222"


def test_single_ip_scope_asset_registers_directly_without_a_sweep(monkeypatch):
    rec = _setup(monkeypatch, [
        {"rule": "allow", "asset_type": "ip", "value": "203.0.113.5", "active_allowed": True},
    ])

    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)

    assert {"value": "203.0.113.5", "asset_id": "asset-1", "asset_type": "ip"} in out
    assert rec.leases_requested == []  # a single ip is a concrete target already - no sweep needed
    added = [a for a in rec.discovered_assets if a["value"] == "203.0.113.5"]
    assert added == [{"asset_type": "ip", "value": "203.0.113.5", "discovered_via": "scope-direct", "in_scope": True}]


def test_cidr_sweep_registers_live_hosts_and_they_carry_asset_type_ip(monkeypatch):
    rec = _setup(
        monkeypatch,
        [{"rule": "allow", "asset_type": "cidr", "value": "203.0.113.0/28", "active_allowed": True}],
        live_hosts=["203.0.113.1", "203.0.113.3"],
    )

    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)

    ip_out = {r["value"]: r["asset_type"] for r in out if r["asset_type"] == "ip"}
    assert ip_out == {"203.0.113.1": "ip", "203.0.113.3": "ip"}
    assert rec.leases_requested == [{
        "scan_run_id": SCAN_RUN_ID, "authorized_target": "203.0.113.0/28",
        "resolved_target": "203.0.113.0/28", "phase": "fingerprint", "port_profile": "host_discovery",
    }]
    via = {a["value"]: a["discovered_via"] for a in rec.discovered_assets}
    assert via["203.0.113.1"] == "cidr-sweep"
    assert via["203.0.113.3"] == "cidr-sweep"


def test_cidr_sweep_respects_ip_deny_precedence(monkeypatch):
    """REQ-CIDRDISC-001: an explicit deny rule covering part of the range
    still wins for a live host discovered inside it, even though the sweep
    ITSELF was authorized for the whole range."""
    rec = _setup(
        monkeypatch,
        [
            {"rule": "allow", "asset_type": "cidr", "value": "203.0.113.0/28", "active_allowed": True},
            {"rule": "deny", "asset_type": "ip", "value": "203.0.113.3", "active_allowed": False},
        ],
        live_hosts=["203.0.113.1", "203.0.113.3"],
    )

    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)

    values = {r["value"] for r in out}
    assert "203.0.113.1" in values
    assert "203.0.113.3" not in values


def test_cidr_asset_without_active_allowed_is_never_swept(monkeypatch):
    rec = _setup(
        monkeypatch,
        [{"rule": "allow", "asset_type": "cidr", "value": "203.0.113.0/28", "active_allowed": False}],
        live_hosts=["203.0.113.1"],
    )

    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)

    assert rec.leases_requested == []
    assert not any(r["asset_type"] == "ip" for r in out)


def test_no_scan_run_id_skips_the_sweep_but_still_registers_direct_ip_assets(monkeypatch):
    """A sweep is an active, run-bound operation - without a scan_run_id
    there is nothing to bind it to, so it is skipped entirely rather than
    attempted unbound. A directly-scoped single ip asset needs no such
    binding and still registers."""
    rec = _setup(
        monkeypatch,
        [
            {"rule": "allow", "asset_type": "ip", "value": "203.0.113.5", "active_allowed": True},
            {"rule": "allow", "asset_type": "cidr", "value": "203.0.113.0/28", "active_allowed": True},
        ],
        live_hosts=["203.0.113.1"],
    )

    out = discovery.run(ENGAGEMENT_ID, scan_run_id=None)

    assert rec.leases_requested == []
    values = {r["value"] for r in out}
    assert "203.0.113.5" in values
    assert "203.0.113.1" not in values


def test_lease_denial_is_recorded_and_yields_no_hosts(monkeypatch):
    rec = _setup(
        monkeypatch,
        [{"rule": "allow", "asset_type": "cidr", "value": "203.0.113.0/28", "active_allowed": True}],
        lease={"allowed": False, "reason": "raw_nmap_not_permitted_for_bug_bounty"},
    )

    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)

    assert not any(r["asset_type"] == "ip" for r in out)
    assert rec.tool_executions[-1]["error_reason"] == "raw_nmap_not_permitted_for_bug_bounty"
    assert rec.tool_executions[-1]["success"] is False


def test_sweep_dispatch_failure_is_best_effort_and_does_not_crash_discovery(monkeypatch):
    rec = _setup(
        monkeypatch,
        [{"rule": "allow", "asset_type": "cidr", "value": "203.0.113.0/28", "active_allowed": True}],
        sweep_error=RuntimeError("tool-runner unreachable"),
    )

    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)  # must not raise

    assert not any(r["asset_type"] == "ip" for r in out)
    assert rec.tool_executions[-1]["success"] is False


def test_known_ip_resilience_survives_an_empty_run(monkeypatch):
    """Mirrors the domain path's own "known in-scope assets" resilience
    (step 3) - a previously live-discovered host stays a target even when
    this run's sweep finds nothing new (or is skipped)."""
    rec = _setup(
        monkeypatch,
        [{"rule": "allow", "asset_type": "cidr", "value": "203.0.113.0/28", "active_allowed": True}],
        known=[{"id": "existing-1", "value": "203.0.113.9", "in_scope": True}],
        live_hosts=[],
    )

    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)

    assert {"value": "203.0.113.9", "asset_id": "existing-1", "asset_type": "ip"} in out
    # already known - must not be re-added via add_discovered_asset
    assert not any(a["value"] == "203.0.113.9" for a in rec.discovered_assets)


# --- GitHub issue #34: a deny exception inside an allowed CIDR must not ---
# permanently block sweeping the rest of the range on later runs.

def test_a_deny_exception_inside_the_cidr_no_longer_blocks_the_whole_sweep(monkeypatch):
    """Before the fix, a single denied host inside the range made the WHOLE
    sweep request denied (control-plane's _network_is_allowed_by_current_policy
    rejects any overlap with a deny exception) - no new host anywhere in the
    range was ever discoverable again. The fix sweeps the deny-avoiding
    sub-ranges instead, so a live host elsewhere in the range is still found."""
    rec = _setup(
        monkeypatch,
        [
            {"rule": "allow", "asset_type": "cidr", "value": "203.0.113.0/28", "active_allowed": True},
            {"rule": "deny", "asset_type": "ip", "value": "203.0.113.5", "active_allowed": False},
        ],
        live_hosts=["203.0.113.1"],
    )

    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)

    # Multiple lease requests now - one per deny-avoiding sub-range - none
    # of them for the original, still-overlapping-the-deny full CIDR.
    requested = [r["authorized_target"] for r in rec.leases_requested]
    assert "203.0.113.0/28" not in requested
    assert len(requested) > 1
    values = {r["value"] for r in out}
    assert "203.0.113.1" in values


def test_the_denied_address_itself_is_never_the_target_of_any_sub_range_lease(monkeypatch):
    """Negative: none of the decomposed sub-range lease requests may cover
    the denied address - this is what actually keeps the raw-egress-gateway
    from ever granting firewall access to it (Policy.apply enforces exactly
    a lease's own resolved_target)."""
    import ipaddress as ip_module

    rec = _setup(
        monkeypatch,
        [
            {"rule": "allow", "asset_type": "cidr", "value": "203.0.113.0/28", "active_allowed": True},
            {"rule": "deny", "asset_type": "ip", "value": "203.0.113.5", "active_allowed": False},
        ],
        live_hosts=[],
    )

    discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)

    denied = ip_module.ip_address("203.0.113.5")
    for req in rec.leases_requested:
        net = ip_module.ip_network(req["authorized_target"], strict=False)
        assert denied not in net, f"sub-range lease {net} still covers the denied address"


def test_no_overlapping_deny_still_sweeps_the_single_original_cidr_in_one_request(monkeypatch):
    """Regression guard: the common case (no deny inside the range) must not
    start issuing multiple lease requests where one used to suffice."""
    rec = _setup(
        monkeypatch,
        [
            {"rule": "allow", "asset_type": "cidr", "value": "203.0.113.0/28", "active_allowed": True},
            {"rule": "deny", "asset_type": "ip", "value": "198.51.100.5", "active_allowed": False},  # unrelated network
        ],
        live_hosts=["203.0.113.1"],
    )

    discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)

    assert rec.leases_requested == [{
        "scan_run_id": SCAN_RUN_ID, "authorized_target": "203.0.113.0/28",
        "resolved_target": "203.0.113.0/28", "phase": "fingerprint", "port_profile": "host_discovery",
    }]


def test_a_deny_exactly_matching_the_whole_cidr_sweeps_nothing(monkeypatch):
    rec = _setup(
        monkeypatch,
        [
            {"rule": "allow", "asset_type": "cidr", "value": "203.0.113.0/28", "active_allowed": True},
            {"rule": "deny", "asset_type": "cidr", "value": "203.0.113.0/28", "active_allowed": False},
        ],
        live_hosts=["203.0.113.1"],
    )

    discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)

    assert rec.leases_requested == []


def test_domain_results_still_carry_asset_type_domain(monkeypatch):
    rec = _setup(monkeypatch, [
        {"rule": "allow", "asset_type": "domain", "value": "example.com", "active_allowed": True},
    ], known=[{"id": "d1", "value": "example.com", "in_scope": True}])

    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)

    domain_rows = [r for r in out if r["value"] == "example.com"]
    assert domain_rows and domain_rows[0]["asset_type"] == "domain"
