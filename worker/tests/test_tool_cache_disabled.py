"""REQ-CONCUR-001: HexStrike's execute_command() caches by hash(command_string)
alone, defaults to caching ON, with NO engagement/scan_run scoping and a 1h
TTL. Every one of our tool-body builders that hits a dedicated HexStrike
endpoint (nmap/nuclei/nikto/subfinder/amass) must explicitly disable it, or a
re-scan (or an unrelated engagement hitting an identical target+flags
combination) can silently receive another run's stale result. wafw00f moved
off this dedicated-endpoint path (GitHub issue #12 - see tool_runner_client's
_wafw00f_command docstring) onto the generic /api/command path instead, where
ToolRunnerClient.run() itself unconditionally sets use_cache: False for
every command-string tool - no per-tool test needed there."""

from __future__ import annotations

from app import tool_runner_client as trc


def test_nmap_body_disables_cache():
    body = trc._nmap_body("192.0.2.10", {"stage": "discovery", "flags": ["-sS"], "ports": "1-65535", "max_rate": 300})
    assert body["use_cache"] is False


def test_nuclei_body_disables_cache():
    assert trc._nuclei_body("host.example.com", {})["use_cache"] is False


def test_nikto_body_disables_cache():
    assert trc._nikto_body("host.example.com", {})["use_cache"] is False


def test_subfinder_body_disables_cache():
    assert trc._subfinder_body("host.example.com", {})["use_cache"] is False


def test_amass_body_disables_cache():
    assert trc._amass_body("host.example.com", {})["use_cache"] is False


def test_every_dedicated_endpoint_tool_disables_cache():
    """Structural guard: catches a future tool added to _ENDPOINTS without
    remembering this - fails loudly instead of silently reintroducing stale
    cross-run/cross-engagement cache hits."""
    for tool, (endpoint, body_fn) in trc._ENDPOINTS.items():
        body = body_fn("host.example.com", {"stage": "discovery", "flags": ["-sS"], "ports": "1-1024", "max_rate": 100})
        assert body.get("use_cache") is False, f"{tool} ({endpoint}) does not disable HexStrike's result cache"
