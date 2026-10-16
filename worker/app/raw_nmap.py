"""Lease-bound TCP, targeted UDP, and host-discovery Nmap execution."""

from __future__ import annotations

import dataclasses
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import TypeVar

from app.nmap_parse import (
    nmap_xml_state_counts, nmap_xml_target_count, parse_nmap_xml, parse_nmap_xml_live_hosts,
    parse_nmap_xml_port_states,
)
from app.raw_egress_client import raw_egress_gateway
from app.tool_runner_client import tool_runner

SERVICE_BATCH_SIZE = 128
MAX_VERSION_PORTS = 1024
# GitHub issue #60: a port that earlier runs found open and this scan did not is probed once
# more, slowly, before the scan is accepted. Bounded, and never faster than this many packets
# per second (a handful of ports needs no more).
MAX_REPROBE_PORTS = 64
REPROBE_MAX_RATE = 100
# Reasons a scan that ran to the end is still not a clean port scan (outcome `partial`).
PROBES_DROPPED = "probes_dropped"
PORTS_NO_LONGER_OPEN = "ports_no_longer_open"
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

def count_dropped_probes(stderr: str | None) -> int:
    """GitHub issue #60: probes the local firewall refused to send. nmap logs each as
    `sendto in send_ip_packet_sd: sendto(...) => Operation not permitted` and carries on as if it
    had been sent; the host then looks silent. nmap stops printing after a few messages, so this
    is a lower bound: zero means none were reported, any number above zero means the scan has
    holes."""
    return sum(1 for line in str(stderr or "").splitlines() if "Operation not permitted" in line)

def _ports_in_range(ports: Iterable[int], port_range: str) -> list[int]:
    """The given ports that lie inside an nmap `-p` style range ("1-65535" or "22,80-90")."""
    spans: list[tuple[int, int]] = []
    for part in str(port_range).split(","):
        first, _, last = part.strip().partition("-")
        if first.isdigit() and (not last or last.isdigit()):
            spans.append((int(first), int(last or first)))
    return sorted({port for port in ports if any(lo <= port <= hi for lo, hi in spans)})

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
    expected_ports: Iterable[int] = (),
) -> RawNmapOutcome:
    """Discover exactly the configured TCP range, then fingerprint open ports.

    `expected_ports` are ports earlier runs found open on this address. One that this scan did not
    find is probed again, slowly, in the same lease (GitHub issue #60); if it is still absent, or if
    the local firewall dropped probes, the scan is reported `partial` rather than clean.
    """
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
        try:
            state_counts = nmap_xml_state_counts(discovery.get("stdout", ""))
        except ValueError:  # the document parsed above, so this is only defensive
            state_counts = {}
        dropped = count_dropped_probes(discovery.get("stderr"))
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
            dropped += count_dropped_probes(service_result.get("stderr"))
            if not service_result.get("success"):
                warnings.append(service_result.get("error_reason") or "service_detection_failed")
                continue
            try:
                fingerprinted.extend(parse_nmap_xml(service_result.get("stdout", "")))
            except ValueError as exc:
                warnings.append(str(exc))
        if len(open_ports) > MAX_VERSION_PORTS:
            warnings.append(f"version_detection_capped:{MAX_VERSION_PORTS}/{len(open_ports)}")

        # Ports that earlier runs found open and this scan did not: ask again, slowly.
        missing = [
            port for port in _ports_in_range(expected_ports, port_range) if port not in set(open_ports)
        ][:MAX_REPROBE_PORTS]
        reprobed: dict[str, str] = {}
        reconfirmed: list[int] = []
        if missing:
            reprobe = tool_runner.run(
                "nmap", ip, {
                    "stage": "service", "flags": ["-sV"],
                    "ports": ",".join(str(port) for port in missing),
                    "max_rate": min(max_rate, REPROBE_MAX_RATE),
                }, scan_run_id=scan_run_id,
            )
            if reprobe.get("success"):
                try:
                    rows = [r for r in parse_nmap_xml_port_states(reprobe.get("stdout", "")) if r["protocol"] == "tcp"]
                    reprobed = {str(row["port"]): row["state"] for row in rows}
                    reprobe_dropped = count_dropped_probes(reprobe.get("stderr"))
                    dropped += reprobe_dropped
                    found = [
                        {key: value for key, value in row.items() if key != "state"}
                        for row in rows if row["state"] == "open"
                    ]
                    fingerprinted.extend(found)
                    reconfirmed = sorted(item["port"] for item in found)
                except ValueError as exc:
                    warnings.append(str(exc))
            else:
                warnings.append(reprobe.get("error_reason") or "reprobe_failed")
        still_missing = [port for port in missing if port not in reconfirmed]

        services = _merge_services(discovered, fingerprinted)
        partial: list[str] = []
        if dropped:
            partial.append(PROBES_DROPPED)
            warnings.append(f"{PROBES_DROPPED}:{dropped}")
        if still_missing:
            partial.append(PORTS_NO_LONGER_OPEN)
            warnings.append(f"{PORTS_NO_LONGER_OPEN}:{','.join(str(port) for port in still_missing)}")
        if reconfirmed:
            warnings.append(f"ports_reconfirmed:{','.join(str(port) for port in reconfirmed)}")
        state_text = "tcp_states:" + ",".join(f"{key}={state_counts[key]}" for key in sorted(state_counts))
        result = dict(discovery)
        result["stderr"] = "\n".join(
            part for part in [state_text if state_counts else "", *warnings, str(discovery.get("stderr") or "")] if part
        )[:1000]
        result["warning_reason"] = ",".join(warnings)[:500] or None
        summary: dict = {"protocol": "tcp", "open": len(services), "states": state_counts, "dropped_probes": dropped}
        if missing:
            summary.update(expected_missing=missing, reprobed=reprobed, reconfirmed=reconfirmed)
        if partial:
            summary["partial_reasons"] = partial
            result["outcome"] = "partial"
        result["outcome_summary"] = summary
        return RawNmapOutcome(result=result, services=services, port_range=port_range, state_counts=state_counts)
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
