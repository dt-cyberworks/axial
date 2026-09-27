"""Lease-bound TCP, targeted UDP, and host-discovery Nmap execution."""

from __future__ import annotations

import dataclasses
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TypeVar

from app.nmap_parse import (
    nmap_xml_target_count, parse_nmap_xml, parse_nmap_xml_live_hosts, parse_nmap_xml_port_states,
)
from app.raw_egress_client import raw_egress_gateway
from app.tool_runner_client import tool_runner

SERVICE_BATCH_SIZE = 128
MAX_VERSION_PORTS = 1024
TARGETED_UDP_PORT_RANGE = "53,123,161,443,500,1900,4500,5060,5353"

@dataclass(frozen=True)
class RawNmapOutcome:
    result: dict
    services: list[dict]
    port_range: str = "1-65535"
    protocol: str = "tcp"
    state_counts: dict[str, int] = field(default_factory=dict)

@dataclass(frozen=True)
class HostDiscoveryOutcome:
    """REQ-CIDRDISC-002/003: result of one liveness-only sweep - hosts, not
    services. Same result/lease lifecycle shape as RawNmapOutcome (both flow
    through the same generic `_with_active_lease`), deliberately kept as its
    own type rather than shoehorned into RawNmapOutcome's services list."""
    result: dict
    live_hosts: list[str]

_T = TypeVar("_T")

def _failed(reason: str, detail: str = "") -> dict:
    return {
        "success": False, "exit_code": -1, "stdout": "",
        "stderr": (detail or reason)[:1000], "error_reason": reason,
    }

def _merge_services(discovered: list[dict], fingerprinted: list[dict]) -> list[dict]:
    by_key = {(item["protocol"], item["port"]): item for item in discovered}
    for item in fingerprinted:
        by_key[(item["protocol"], item["port"])] = item
    return [by_key[key] for key in sorted(by_key, key=lambda value: (value[0], value[1]))]

def _with_active_lease(
    lease_token: str, reservation_token: str, operation: Callable[[], _T],
    make_failed: Callable[[dict], _T], scan_run_id: str | None = None,
) -> _T:
    """Generic over the outcome type (RawNmapOutcome or HostDiscoveryOutcome) -
    both are frozen dataclasses whose only field this function itself needs to
    rewrite is `result`, so `dataclasses.replace` keeps every other field
    (services/live_hosts, port_range, ...) untouched regardless of shape."""
    activated = False
    stop_heartbeat = threading.Event()
    heartbeat_failures: list[str] = []
    heartbeat_thread: threading.Thread | None = None
    outcome: _T | None = None
    try:
        raw_egress_gateway.activate(lease_token, reservation_token)
        activated = True

        def heartbeat() -> None:
            while not stop_heartbeat.wait(3.0):
                try:
                    raw_egress_gateway.heartbeat(lease_token, reservation_token)
                except Exception as exc:  # noqa: BLE001
                    heartbeat_failures.append(str(exc))
                    return
                # Zusaetzlich den scan_run am Leben halten (REQ-RAWLEASE-001), damit
                # ein mehrminuetiger Nmap nicht faelschlich als verwaist geerntet
                # wird. Best effort - ein Fehler hier bricht die Lease nicht ab.
                if scan_run_id is not None:
                    from app.control_plane_client import client
                    client.heartbeat_scan_run(scan_run_id)

        heartbeat_thread = threading.Thread(target=heartbeat, name="raw-egress-heartbeat", daemon=True)
        heartbeat_thread.start()
        outcome = operation()
        if heartbeat_failures:
            result = dict(outcome.result)
            result.update(success=False, error_reason="raw_egress_heartbeat_failed")
            result["stderr"] = (
                f"{result.get('stderr') or ''}\nraw_egress_heartbeat_failed:{heartbeat_failures[0]}"
            ).strip()[:1000]
            outcome = dataclasses.replace(outcome, result=result)
    except Exception as exc:  # noqa: BLE001
        outcome = make_failed(_failed("raw_egress_activation_or_dispatch_failed", str(exc)))
    finally:
        stop_heartbeat.set()
        if heartbeat_thread is not None:
            heartbeat_thread.join(timeout=1.0)
        if activated:
            try:
                raw_egress_gateway.deactivate(lease_token, reservation_token)
            except Exception as exc:  # noqa: BLE001
                previous = outcome if outcome is not None else make_failed(_failed("raw_scan_incomplete"))
                result = dict(previous.result)
                result.update(success=False, error_reason="raw_egress_revoke_failed")
                result["stderr"] = (
                    f"{result.get('stderr') or ''}\nraw_egress_revoke_failed:{exc}"
                ).strip()[:1000]
                outcome = dataclasses.replace(previous, result=result)
    return outcome if outcome is not None else make_failed(_failed("raw_scan_incomplete"))

def execute_configured_tcp_scan(
    ip: str, lease_token: str, *, reservation_token: str, max_rate: int,
    port_range: str = "1-65535", scan_run_id: str | None = None,
) -> RawNmapOutcome:
    """Discover exactly the configured TCP range, then fingerprint open ports."""
    def operation() -> RawNmapOutcome:
        discovery = tool_runner.run(
            "nmap", ip, {
                "stage": "discovery", "flags": ["-sS"],
                "ports": port_range, "max_rate": max_rate,
            }, scan_run_id=scan_run_id,
        )
        if not discovery.get("success"):
            return RawNmapOutcome(result=discovery, services=[], port_range=port_range)
        try:
            if nmap_xml_target_count(discovery.get("stdout", "")) == 0:
                raise ValueError("zero_targets_scanned")
            discovered = parse_nmap_xml(discovery.get("stdout", ""))
        except ValueError as exc:
            return RawNmapOutcome(result=_failed(str(exc)), services=[], port_range=port_range)
        open_ports = sorted({item["port"] for item in discovered if item.get("protocol") == "tcp"})
        fingerprinted: list[dict] = []
        warnings: list[str] = []
        for offset in range(0, min(len(open_ports), MAX_VERSION_PORTS), SERVICE_BATCH_SIZE):
            batch = open_ports[offset: offset + SERVICE_BATCH_SIZE]
            service_result = tool_runner.run(
                "nmap", ip, {
                    "stage": "service", "flags": ["-sV"],
                    "ports": ",".join(str(port) for port in batch), "max_rate": max_rate,
                }, scan_run_id=scan_run_id,
            )
            if not service_result.get("success"):
                warnings.append(service_result.get("error_reason") or "service_detection_failed")
                continue
            try:
                fingerprinted.extend(parse_nmap_xml(service_result.get("stdout", "")))
            except ValueError as exc:
                warnings.append(str(exc))
        if len(open_ports) > MAX_VERSION_PORTS:
            warnings.append(f"version_detection_capped:{MAX_VERSION_PORTS}/{len(open_ports)}")
        services = _merge_services(discovered, fingerprinted)
        result = dict(discovery)
        result["stderr"] = "\n".join(
            part for part in [str(discovery.get("stderr") or ""), *warnings] if part
        )[:1000]
        result["warning_reason"] = ",".join(warnings)[:500] or None
        result["outcome_summary"] = {"protocol": "tcp", "open": len(services)}
        return RawNmapOutcome(result=result, services=services, port_range=port_range)
    return _with_active_lease(
        lease_token, reservation_token, operation,
        make_failed=lambda r: RawNmapOutcome(result=r, services=[]), scan_run_id=scan_run_id,
    )

def execute_targeted_udp_scan(
    ip: str, lease_token: str, *, reservation_token: str, max_rate: int,
    port_range: str = TARGETED_UDP_PORT_RANGE, scan_run_id: str | None = None,
) -> RawNmapOutcome:
    """Probe only the fixed UDP profile and fingerprint only confirmed-open ports."""
    if port_range != TARGETED_UDP_PORT_RANGE:
        return RawNmapOutcome(
            result=_failed("udp_port_profile_invalid"), services=[],
            port_range=port_range, protocol="udp",
        )

    def operation() -> RawNmapOutcome:
        discovery = tool_runner.run(
            "nmap", ip, {
                "stage": "udp_discovery", "flags": ["-sU"],
                "ports": port_range, "max_rate": max_rate,
            }, scan_run_id=scan_run_id,
        )
        if not discovery.get("success"):
            return RawNmapOutcome(result=discovery, services=[], port_range=port_range, protocol="udp")
        try:
            if nmap_xml_target_count(discovery.get("stdout", "")) == 0:
                raise ValueError("zero_targets_scanned")
            rows = [row for row in parse_nmap_xml_port_states(discovery.get("stdout", "")) if row["protocol"] == "udp"]
        except ValueError as exc:
            return RawNmapOutcome(result=_failed(str(exc)), services=[], port_range=port_range, protocol="udp")
        state_counts: dict[str, int] = {}
        for row in rows:
            state_counts[row["state"]] = state_counts.get(row["state"], 0) + 1
        confirmed = [{key: value for key, value in row.items() if key != "state"} for row in rows if row["state"] == "open"]
        open_ports = sorted({row["port"] for row in rows if row["state"] == "open"})
        fingerprinted: list[dict] = []
        warnings: list[str] = []
        for offset in range(0, len(open_ports), SERVICE_BATCH_SIZE):
            batch = open_ports[offset: offset + SERVICE_BATCH_SIZE]
            service_result = tool_runner.run(
                "nmap", ip, {
                    "stage": "udp_service", "flags": ["-sU", "-sV"],
                    "ports": ",".join(str(port) for port in batch), "max_rate": max_rate,
                }, scan_run_id=scan_run_id,
            )
            if not service_result.get("success"):
                warnings.append(service_result.get("error_reason") or "udp_service_detection_failed")
                continue
            try:
                fingerprinted.extend(parse_nmap_xml(service_result.get("stdout", "")))
            except ValueError as exc:
                warnings.append(str(exc))
        services = _merge_services(confirmed, fingerprinted)
        summary = {"protocol": "udp", "states": state_counts, "confirmed_open": len(services)}
        state_text = "udp_states:" + ",".join(f"{key}={state_counts[key]}" for key in sorted(state_counts))
        ambiguous_only = not services and bool(state_counts.get("open|filtered") or state_counts.get("filtered"))
        if not rows:
            warnings.append("udp_no_port_states")
        elif ambiguous_only:
            warnings.append("udp_results_ambiguous")
        elif state_counts.get("open|filtered"):
            warnings.append("udp_partial_ambiguity")
        result = dict(discovery)
        result["stderr"] = "\n".join(
            part for part in [str(discovery.get("stderr") or ""), state_text, *warnings] if part
        )[:1000]
        result["warning_reason"] = ",".join(warnings)[:500] or None
        if not rows or ambiguous_only:
            result["success"] = False
            result["error_reason"] = "udp_no_port_states" if not rows else "udp_results_ambiguous"
        result["outcome_summary"] = summary
        return RawNmapOutcome(
            result=result, services=services, port_range=port_range,
            protocol="udp", state_counts=state_counts,
        )
    return _with_active_lease(
        lease_token, reservation_token, operation,
        make_failed=lambda r: RawNmapOutcome(result=r, services=[]), scan_run_id=scan_run_id,
    )


def execute_host_discovery_sweep(
    cidr: str, lease_token: str, *, reservation_token: str, max_rate: int, scan_run_id: str | None = None,
) -> HostDiscoveryOutcome:
    """REQ-CIDRDISC-001/002: one liveness-only `-sn` sweep of a whole ip/cidr
    scope asset. No follow-up service/version pass here at all - a live host
    becomes a discovered_asset (discovery.py) and re-enters the normal
    fingerprint pipeline, which authorizes and scans it exactly like any other
    discovered target."""
    def operation() -> HostDiscoveryOutcome:
        discovery = tool_runner.run(
            "nmap", cidr, {"stage": "host_discovery", "flags": ["-sn"], "max_rate": max_rate},
            scan_run_id=scan_run_id,
        )
        if not discovery.get("success"):
            return HostDiscoveryOutcome(result=discovery, live_hosts=[])
        try:
            if nmap_xml_target_count(discovery.get("stdout", "")) == 0:
                raise ValueError("zero_targets_scanned")
            live_hosts = parse_nmap_xml_live_hosts(discovery.get("stdout", ""))
        except ValueError as exc:
            return HostDiscoveryOutcome(result=_failed(str(exc)), live_hosts=[])
        result = dict(discovery)
        result["outcome_summary"] = {"live_hosts": len(live_hosts)}
        return HostDiscoveryOutcome(result=result, live_hosts=live_hosts)
    return _with_active_lease(
        lease_token, reservation_token, operation,
        make_failed=lambda r: HostDiscoveryOutcome(result=r, live_hosts=[]), scan_run_id=scan_run_id,
    )


# Compatibility name for older callers; semantics are the persisted configured range.
execute_full_tcp_scan = execute_configured_tcp_scan
