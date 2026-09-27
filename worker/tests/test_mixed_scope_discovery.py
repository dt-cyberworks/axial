"""GitHub issue #38: no single test previously exercised one engagement with
a domain, a direct ip, AND a cidr together through discovery.run() - exactly
the combination whose cross-mechanism interactions (issue #34's fix among
them) isolated single-type tests elsewhere cannot catch. Reuses
test_discovery_ip_cidr.py's RecordingClient/_setup harness rather than
duplicating it."""

from __future__ import annotations

import ipaddress

from app.raw_nmap import HostDiscoveryOutcome
from app.tasks import discovery
from tests.test_discovery_ip_cidr import ENGAGEMENT_ID, SCAN_RUN_ID, RecordingClient, _setup


def test_mixed_domain_ip_cidr_scope_produces_every_candidate_type_together(monkeypatch):
    rec = _setup(
        monkeypatch,
        [
            {"rule": "allow", "asset_type": "domain", "value": "example.com"},
            {"rule": "allow", "asset_type": "ip", "value": "198.51.100.9", "active_allowed": True},
            {"rule": "allow", "asset_type": "cidr", "value": "203.0.113.0/28", "active_allowed": True},
            # A false-positive host deselected during a prior asset review -
            # exactly the workflow issue #34 fixed: this must not block the
            # rest of the CIDR from being (re)swept.
            {"rule": "deny", "asset_type": "ip", "value": "203.0.113.5", "active_allowed": False},
        ],
    )
    monkeypatch.setattr(
        discovery, "_passive_subdomains",
        lambda domain: {"api.example.com"} if domain == "example.com" else set(),
    )

    def fake_sweep(cidr, lease_token, *, reservation_token, max_rate, scan_run_id=None):
        result = {"success": True, "exit_code": 0, "stdout": "", "stderr": "", "error_reason": None}
        net = ipaddress.ip_network(cidr)
        live = [str(ip) for ip in ("203.0.113.1", "203.0.113.9") if ipaddress.ip_address(ip) in net]
        return HostDiscoveryOutcome(result=result, live_hosts=live)

    monkeypatch.setattr(discovery, "execute_host_discovery_sweep", fake_sweep)

    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)

    by_type: dict[str, set[str]] = {}
    for r in out:
        by_type.setdefault(r["asset_type"], set()).add(r["value"])

    # Domain apex + a mocked passive-source subdomain both present.
    assert {"example.com", "api.example.com"} <= by_type.get("domain", set())
    # The direct ip asset registers without any sweep.
    assert "198.51.100.9" in by_type.get("ip", set())
    # Both live hosts elsewhere in the CIDR are found DESPITE the deny
    # sitting inside the same range (issue #34, now proven in a genuinely
    # mixed-scope engagement, not an ip/cidr-only one).
    assert {"203.0.113.1", "203.0.113.9"} <= by_type.get("ip", set())
    # The denied address itself never appears as a candidate of any type.
    assert "203.0.113.5" not in by_type.get("ip", set())
    assert all("203.0.113.5" not in v for v in by_type.get("domain", set()))

    # None of the sub-range sweep requests covered the denied address either
    # (the actual enforcement-layer guarantee, not just the final result).
    denied = ipaddress.ip_address("203.0.113.5")
    for req in rec.leases_requested:
        net = ipaddress.ip_network(req["authorized_target"], strict=False)
        assert denied not in net


def test_mixed_scope_second_run_still_finds_a_new_host_after_the_deny_exists(monkeypatch):
    """The exact scenario from issue #34's own reproduction: a deny created
    from a first run's asset review must not prevent a LATER run from
    finding a newly-live host elsewhere in the same range - proven here
    alongside an unrelated domain and direct ip target, not in isolation."""
    rec = _setup(
        monkeypatch,
        [
            {"rule": "allow", "asset_type": "domain", "value": "example.com"},
            {"rule": "allow", "asset_type": "ip", "value": "198.51.100.9", "active_allowed": True},
            {"rule": "allow", "asset_type": "cidr", "value": "203.0.113.0/28", "active_allowed": True},
            {"rule": "deny", "asset_type": "ip", "value": "203.0.113.5", "active_allowed": False},
        ],
        live_hosts=["203.0.113.12"],  # a host that only became live on THIS run
    )

    out = discovery.run(ENGAGEMENT_ID, scan_run_id=SCAN_RUN_ID)

    values = {r["value"] for r in out}
    assert "203.0.113.12" in values
    assert "example.com" in values
    assert "198.51.100.9" in values
    assert rec.leases_requested  # at least one sub-range lease was actually requested
