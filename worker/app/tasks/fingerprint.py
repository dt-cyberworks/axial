"""Phase 2 - Fingerprinting (Spezifikation Kap. 3.2).

Sendet nach Gateway-Freigabe echte Tool-Calls an den tool-runner (die echte
HexStrike-API, s. worker/app/tool_runner_client.py), schreibt Service-/
Finding-Ergebnisse ueber die interne control-plane-API. Fehlende Security-
Header (misconfig, Kap. 5.1) werden aus den Response-Headern abgeleitet, die
der httpx-Aufruf ohnehin aufzeichnet (REQ-PIPE-013; nikto laeuft im
automatischen Scan nicht mehr).

Hinweis: der worker selbst haengt NICHT im Lab-/Ziel-Netz (nur ctrl+egress)
und kann Ziele nicht direkt erreichen - jeder aktive Call muss durch den
tool-runner laufen, der als einziger Netzwerksicht auf die Ziele hat.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import logging
import time
import uuid
from urllib.parse import urlsplit

from app.cancel_probe import CancelProbe
from app.control_plane_client import client
from app.discovery_parse import nuclei_candidate_urls, parse_katana_jsonl
from app.ffuf_parse import is_catch_all, parse_ffuf_json
from app.httpx_parse import parse_httpx_json
from app.known_vulns import lookup as lookup_known_vuln
from app.lab_hosts import is_lab_host
from app.nmap_parse import parse_nmap_grepable
from app.nuclei_parse import parse_nuclei_jsonl, parse_nuclei_tech
from app.planner import IndexInfo, Options, SurfaceInput, plan_surface, resolve_products
from app.scan_executor import CheckRun, Handler
from app.raw_egress_client import raw_egress_gateway
from app.raw_nmap import RawNmapOutcome, execute_configured_tcp_scan, execute_targeted_udp_scan
from app.security_headers import missing_security_headers
from app.surfaces import classify_open_port, redirect_alias_port
from app.tech_profile import MAX_PROFILE_ENTRIES, build_profile
from app.target_envelope import httpx_target, protocol_from_httpx_url, single_port_from_envelope, target_url
from app.testssl_parse import parse_testssl_json, testssl_scan_problem
from app.tool_runner_client import FFUF_WORDLISTS, NUCLEI_OOB_PARTS, OOB_SERVER_URL, nuclei_select_budget_s, tool_runner
from app import scan_executor, tool_execution
from app.wafw00f_parse import parse_wafw00f

logger = logging.getLogger(__name__)


# REQ-FIDELITY-003: Logik lebt in app.target_envelope (mit dispatch.py geteilt,
# s. REQ-FIDELITY-007) - hier als Modul-lokale Namen weitergereicht, damit
# bestehende Aufrufe/Tests in dieser Datei unveraendert bleiben.
_single_port_from_envelope = single_port_from_envelope
_target_url = target_url


@dataclasses.dataclass
class _PortScanResult:
    """What one executed port scan produced, for reuse by other hostnames."""
    services: list[dict]
    scanned_by: str
    succeeded: bool


@dataclasses.dataclass
class _RunContext:
    """Per-run memo for work that is provably identical across hostnames.

    Created fresh in run() and deliberately NOT module-level state: a Celery
    worker process is long-lived and serves many runs, so run-scoped caches
    must not outlive their run - the same leak tool_execution's coverage
    accumulator has to guard against (see pipeline.py's clear_coverage).
    """

    # REQ-FPEFF-002: (resolved ip, port_from, port_to) -> that scan's outcome.
    # The port range is part of the key because per-target port scoping
    # (REQ-PORTSCOPE-001) lets two hostnames on one IP carry different
    # authorized ranges - a narrower earlier scan must never satisfy a wider
    # later one.
    port_scans: dict[tuple[str, int | None, int | None], _PortScanResult] = dataclasses.field(default_factory=dict)
    # REQ-FPEFF-004: web-surface fingerprint -> the hostname already deep-scanned.
    web_surfaces: dict[tuple, str] = dataclasses.field(default_factory=dict)
    # REQ-COVER-003/004/006: the engagement's optional-capability switches,
    # fetched once per run (None until first use).
    options: dict | None = None
    # REQ-PIPE-001: host -> web ports httpx confirmed live in this run and that
    # are not themselves aliases; a redirect-only port is an alias of one of them.
    live_web_ports: dict[str, set[int]] = dataclasses.field(default_factory=dict)

    def discovery_options(self, engagement_id: str) -> dict:
        if self.options is None:
            self.options = client.get_discovery_options(uuid.UUID(engagement_id))
        return self.options


def _port_scan_key(ip: str, envelope: dict) -> tuple[str, int | None, int | None]:
    return (ip, envelope.get("tcp_port_from"), envelope.get("tcp_port_to"))


def _reused_result(scanned_by: str) -> dict:
    """REQ-FPEFF-002: reuse is recorded, never silent - the audit trail must
    show why this host ran no scan of its own and which one covered it."""
    return {
        "success": True,
        "exit_code": 0,
        "stdout": "",
        "stderr": f"reused_port_scan_from:{scanned_by}",
        "error_reason": None,
        "outcome_summary": {"reused_from": scanned_by},
    }


def _web_surface_key(ip: str | None, port: int | None, probe: dict) -> tuple | None:
    """REQ-FPEFF-004: identity of a web surface, not of a hostname.

    Returns None when any component is unknown, which makes the surface
    un-deduplicable and therefore always scanned - the fail-toward-coverage
    direction. Virtual hosting means the same IP:port legitimately serves
    different content per Host header, so the response fingerprint (not the
    address) is what decides whether two names are the same surface.
    """
    if ip is None:
        return None
    status = probe.get("status_code")
    if status is None:
        return None
    return (
        ip,
        port or 443,
        status,
        str(probe.get("webserver") or ""),
        str(probe.get("title") or ""),
        probe.get("content_length"),
    )


def _add_finding(*args, **kwargs):
    """Store a finding and count it for the check that produced it."""
    result = client.add_finding(*args, **kwargs)
    tool_execution.note_finding()
    return result


def _propose(
    engagement_id: str, tool: str, category: str, target: str, args: dict,
    scan_run_id: str | None, phase: str = "fingerprint",
) -> dict | None:
    payload = {
        "tool": tool, "category": category, "mode": "active", "target": target, "args": args,
        "is_automated": True, "phase": phase, "scan_run_id": scan_run_id,
    }
    cancel_probe = CancelProbe.for_run(scan_run_id) if scan_run_id else None
    for attempt in range(8):
        if cancel_probe is not None and cancel_probe.is_cancelled():  # issue #49: raises when unreadable
            return None
        decision = client.authorize(uuid.UUID(engagement_id), payload)
        if decision["allowed"]:
            return decision
        if decision.get("is_throttled") and decision.get("retry_after_seconds") is not None:
            delay = min(max(float(decision["retry_after_seconds"]), 0.1), 5.0)
            logger.info("%s on %s throttled: waiting %.2fs before asking the gateway again", tool, target, delay)
            time.sleep(delay)
            continue
        logger.info("%s on %s denied: %s", tool, target, decision["reason"])
        tool_execution.note_denied(tool, decision["reason"])
        return None
    logger.info("%s on %s skipped after repeated throttling", tool, target)
    tool_execution.note_denied(tool, "throttled")
    return None


def _persist_services(
    engagement_id: str, asset_id: str, target: str, services: list[dict],
) -> list[dict]:
    """Attach discovered services to THIS asset.

    Called for a host that executed its own scan and for one reusing another
    host's result (REQ-FPEFF-002) - every hostname resolving to a scanned IP
    keeps a complete service inventory, so nothing is lost by being second.
    """
    written = []
    for svc in services:
        svc_resp = client.add_service(
            engagement_id, asset_id=asset_id, port=svc["port"], protocol=svc["protocol"],
            transport=svc["protocol"], product=svc["product"], version=svc.get("version"),
        )
        service_id = svc_resp["id"]
        written.append({**svc, "service_id": service_id, "asset_id": asset_id, "target": target})
        # REQ-CORR-001/006: the static known_vulns table stays the CVE source
        # for lab engagements only (deterministic, no internet dependency for
        # make lab-test). Real (non-lab) targets are correlated against live
        # NVD/EPSS/KEV in the correlate phase instead - see correlate.py.
        if is_lab_host(target):
            vuln = lookup_known_vuln(svc.get("product_name") or svc["product"], svc.get("version"))
            if vuln:
                client.add_finding(
                    engagement_id, asset_id=asset_id, service_id=service_id, category="cve",
                    title=vuln.title, cve_ids=vuln.cve_ids, cvss_base=vuln.cvss_base, epss=vuln.epss,
                    is_kev=vuln.is_kev, confidence="inferred",
                    evidence={"tool": "nmap", "nmap_product": svc["product"], "port": svc["port"], "protocol": svc["protocol"]},
                    exposure_factor=1.0, business_factor=0.5,
                )
    return written


def _execute_port_scan(
    engagement_id: str, asset_id: str, target: str, ip: str | None, scan_run_id: str | None
) -> tuple[list[dict], bool]:
    """Run persisted TCP and optional bounded UDP profiles under one FIFO slot.

    Returns (services attached to this asset, whether any profile succeeded).
    The success flag drives REQ-FPEFF-003: only a scan that actually ran may
    be treated as evidence about which ports are closed.
    """
    if not tool_runner.raw_network_available():
        tool_execution.record(
            engagement_id, scan_run_id=scan_run_id, tool="nmap", phase="fingerprint",
            authorized_target=target, resolved_target=ip, port_range="configured_tcp",
            result=tool_execution.failed_result("raw_egress_unavailable"), discovered_services=0,
        )
        return [], False
    if ip is None or scan_run_id is None:
        reason = "materialized_ip_missing" if ip is None else "scan_run_missing"
        tool_execution.record(
            engagement_id, scan_run_id=scan_run_id, tool="nmap", phase="fingerprint",
            authorized_target=target, resolved_target=ip, port_range="configured_tcp",
            result=tool_execution.failed_result(reason), discovered_services=0,
        )
        return [], False

    reservation_token: str | None = None
    executions: list[RawNmapOutcome] = []
    try:
        reservation = raw_egress_gateway.acquire_reservation(
            scan_run_id,
            cancel_requested=lambda: client.is_cancel_requested(uuid.UUID(scan_run_id)),
        )
        reservation_token = str(reservation["reservation_token"])

        def acquire(profile: str) -> dict:
            lease: dict = {}
            for _ in range(8):
                lease = client.acquire_raw_egress_lease(
                    uuid.UUID(engagement_id), scan_run_id=scan_run_id,
                    authorized_target=target, resolved_target=ip, phase="fingerprint",
                    port_profile=profile,
                )
                if lease.get("allowed") or not lease.get("is_throttled"):
                    break
                time.sleep(min(max(float(lease.get("retry_after_seconds") or 1.0), 0.1), 5.0))
            return lease

        tcp_lease = acquire("configured_tcp")
        if not tcp_lease.get("allowed") or not tcp_lease.get("lease_token"):
            reason = str(tcp_lease.get("reason") or "raw_egress_lease_denied")
            executions.append(RawNmapOutcome(
                result=tool_execution.failed_result(reason), services=[],
                port_range=str(tcp_lease.get("port_range") or "configured_tcp"),
            ))
        else:
            executions.append(execute_configured_tcp_scan(
                ip, str(tcp_lease["lease_token"]), reservation_token=reservation_token,
                max_rate=int(tcp_lease.get("max_rate") or 300),
                port_range=str(tcp_lease.get("port_range") or "1-65535"),
                scan_run_id=scan_run_id,
            ))
            if tcp_lease.get("udp_discovery_enabled"):
                udp_lease = acquire("targeted_udp")
                if not udp_lease.get("allowed") or not udp_lease.get("lease_token"):
                    reason = str(udp_lease.get("reason") or "udp_raw_egress_lease_denied")
                    executions.append(RawNmapOutcome(
                        result=tool_execution.failed_result(reason), services=[],
                        port_range=str(udp_lease.get("port_range") or "targeted_udp"),
                        protocol="udp",
                    ))
                else:
                    executions.append(execute_targeted_udp_scan(
                        ip, str(udp_lease["lease_token"]), reservation_token=reservation_token,
                        max_rate=int(udp_lease.get("max_rate") or 100),
                        port_range=str(udp_lease.get("port_range")), scan_run_id=scan_run_id,
                    ))
    except Exception as exc:  # noqa: BLE001
        executions.append(RawNmapOutcome(
            result=tool_execution.failed_result("raw_egress_queue_or_dispatch_failed", exc),
            services=[], port_range="configured_tcp",
        ))
    finally:
        if reservation_token is not None:
            try:
                raw_egress_gateway.release_reservation(scan_run_id, reservation_token)
            except Exception as exc:  # noqa: BLE001
                if not executions:
                    executions.append(RawNmapOutcome(
                        result=tool_execution.failed_result("raw_egress_reservation_release_failed", exc),
                        services=[], port_range="configured_tcp",
                    ))
                else:
                    failed: list[RawNmapOutcome] = []
                    for outcome in executions:
                        result = dict(outcome.result)
                        result.update(success=False, error_reason="raw_egress_reservation_release_failed")
                        result["stderr"] = (
                            f"{result.get('stderr') or ''}\nraw_egress_reservation_release_failed:{exc}"
                        ).strip()[:1000]
                        failed.append(RawNmapOutcome(
                            result=result, services=outcome.services, port_range=outcome.port_range,
                            protocol=outcome.protocol, state_counts=outcome.state_counts,
                        ))
                    executions = failed

    services: list[dict] = []
    for outcome in executions:
        tool_execution.record(
            engagement_id, scan_run_id=scan_run_id, tool="nmap", phase="fingerprint",
            authorized_target=target, resolved_target=ip, port_range=outcome.port_range,
            result=outcome.result, discovered_services=len(outcome.services),
        )
        if not outcome.result.get("success"):
            logger.warning(
                "nmap %s for %s not fully successful: %s",
                outcome.protocol, target, outcome.result.get("error_reason"),
            )
        services.extend(outcome.services)

    return _persist_services(engagement_id, asset_id, target, services), any(
        outcome.result.get("success") for outcome in executions
    )


def _nmap_scan(
    ctx: _RunContext, engagement_id: str, asset_id: str, target: str, ip: str | None,
    scan_run_id: str | None, envelope: dict,
) -> tuple[list[dict], bool]:
    """REQ-FPEFF-002: execute a port scan at most once per distinct network
    target per run; later hostnames on the same IP reuse that result.

    nmap operates on the resolved IP - the hostname used to reach it does not
    change which ports are open - so scanning one IP once per name multiplies
    the pipeline's most expensive and most serialized operation (raw egress is
    a single global FIFO lease, REQ-CONCUR-002) for no new information.
    """
    if ip is None:
        return _execute_port_scan(engagement_id, asset_id, target, ip, scan_run_id)

    key = _port_scan_key(ip, envelope)
    cached = ctx.port_scans.get(key)
    if cached is not None:
        logger.info(
            "nmap for %s skipped: %s was already scanned in this run (by %s)",
            target, ip, cached.scanned_by,
        )
        tool_execution.record(
            engagement_id, scan_run_id=scan_run_id, tool="nmap", phase="fingerprint",
            authorized_target=target, resolved_target=ip,
            port_range=f"{key[1]}-{key[2]}" if key[1] is not None else "configured_tcp",
            result=_reused_result(cached.scanned_by),
            discovered_services=len(cached.services),
        )
        # The services still attach to THIS asset - reuse saves the scan, not
        # the inventory.
        return _persist_services(engagement_id, asset_id, target, cached.services), cached.succeeded

    services, succeeded = _execute_port_scan(engagement_id, asset_id, target, ip, scan_run_id)
    # Only a SUCCESSFUL scan is evidence worth reusing. Caching a failure would
    # be wrong twice over: the reuse record would claim a success that never
    # happened (masking REQ-SCAN-014's coverage-degraded signal, which treats
    # nmap as load-bearing), and it would deny the next host on this IP a
    # retry that may well succeed - a stale-materialization denial in
    # particular clears the moment the next host re-materializes.
    if succeeded:
        ctx.port_scans[key] = _PortScanResult(services=services, scanned_by=target, succeeded=True)
    return services, succeeded


def _header_findings(engagement_id: str, asset_id: str, target: str, live: dict, single_port: int | None = None,
                     confirmed_protocol: str | None = None) -> None:
    """REQ-PIPE-013: missing security headers from the response headers httpx
    already recorded for this surface - no request to the target. Replaces the
    nikto run, which spent its whole 40 s budget (always truncated) to report
    the same thing.

    confirmed_protocol (REQ-FIDELITY-009): HSTS is only judged over https."""
    port = single_port or 443
    missing = missing_security_headers(
        live.get("headers") or {}, scheme=confirmed_protocol or "https", status_code=live.get("status_code"),
    )
    if not missing:  # None: a response that cannot be judged (redirect, no headers); []: nothing missing
        return
    _add_finding(
        engagement_id, asset_id=asset_id, service_id=live.get("service_id"), category="misconfig",
        title=f"Missing security headers: {', '.join(missing)}", confidence="validated",
        evidence={"missing_headers": missing, "port": port, "tool": "httpx"},
        exposure_factor=1.0, business_factor=0.4,
    )


def _waf_detect(engagement_id: str, asset_id: str, target: str, scan_run_id: str | None, single_port: int | None = None,
                confirmed_protocol: str | None = None) -> None:
    """WAF-Fingerprinting via wafw00f ueber den Egress-Proxy (fingerprint-Tool,
    Allowlist Kap. 2.2). Ein erkannter WAF ist Recon-Kontext fuer den Operator
    (was schuetzt das Asset?) - bei Erkennung ein Info-Finding, sonst nichts.

    confirmed_protocol: REQ-FIDELITY-009, same reason as the header check - wafw00f
    takes a URL and does not probe the other scheme."""
    url = _target_url(target, single_port, confirmed_protocol)
    if _propose(engagement_id, "wafw00f", "fingerprint", target, {}, scan_run_id) is None:
        return
    try:
        result = tool_runner.run("wafw00f", url, {}, scan_run_id=scan_run_id, engagement_id=engagement_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("wafw00f failed for %s: %s", target, exc)
        result = tool_execution.failed_result("runner_dispatch_failed", exc)
    waf = parse_wafw00f(result.get("stdout", "")) if result.get("success") else None
    tool_execution.record(
        engagement_id, scan_run_id=scan_run_id, tool="wafw00f", phase="fingerprint",
        authorized_target=target, resolved_target=None, port_range=str(single_port or 443), result=result,
    )
    if not result.get("success"):
        return
    if waf:
        _add_finding(
            engagement_id, asset_id=asset_id, category="exposure",
            title=f"WAF detected: {waf}", confidence="validated",
            evidence={"waf": waf, "tool": "wafw00f", "target": url},
            exposure_factor=0.2, business_factor=0.2,  # rein informativ -> info
        )


def _http_probe(engagement_id: str, asset_id: str, target: str, scan_run_id: str | None, single_port: int | None = None) -> dict | None:
    """httpx: Liveness + Tech-Stack + Server + Status (fingerprint). Legt bei
    lebendem HTTP-Dienst einen service-Eintrag mit tech_stack an und liefert
    dessen Daten zurueck (z. B. um teure Folge-Tools nur auf Live-Hosts zu
    fahren)."""
    if _propose(engagement_id, "httpx", "fingerprint", target, {}, scan_run_id) is None:
        return None
    # REQ-FIDELITY-003/010: explicit http://, which httpx self-corrects to
    # https when needed - see target_envelope.httpx_target's docstring for why
    # a bare/schemeless target (tried first) is wrong: it silently never
    # probes https at all on a non-standard port.
    url = httpx_target(target, single_port)
    try:
        result = tool_runner.run("httpx", url, {}, scan_run_id=scan_run_id, engagement_id=engagement_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("httpx failed for %s: %s", target, exc)
        result = tool_execution.failed_result("runner_dispatch_failed", exc)
    rows = parse_httpx_json(result.get("stdout", "")) if result.get("success") else []
    tool_execution.record(
        engagement_id, scan_run_id=scan_run_id, tool="httpx", phase="fingerprint",
        authorized_target=target, resolved_target=None, port_range=str(single_port or 443), result=result,
        discovered_services=len(rows),
    )
    if not rows:
        # REQ-AGENT-015: record the check even on a dead result - otherwise the
        # agent phase can't tell "never checked" apart from "already checked,
        # no live HTTP service" and re-probes the same dead hosts every run.
        client.record_http_probe(engagement_id, asset_id, live=False)
        return None
    r = rows[0]
    # REQ-FIDELITY-003, fixed 2026-08-03: record the scheme httpx actually
    # used (from its own reported url), not a hardcoded "https" - accurate
    # regardless of which scheme the target turned out to serve.
    svc = client.add_service(
        engagement_id, asset_id=asset_id, port=r.get("port") or single_port or 443,
        protocol=protocol_from_httpx_url(r.get("url", "")),
        product=r.get("webserver") or "http",
        tech_stack={"tech": r.get("tech", []), "title": r.get("title", ""), "status": r.get("status_code")},
    )
    client.record_http_probe(engagement_id, asset_id, live=True)
    return {**r, "service_id": svc["id"], "asset_id": asset_id, "target": target}


def _tls_scan(
    engagement_id: str, asset_id: str, target: str, ip: str | None, scan_run_id: str | None,
    single_port: int | None = None, confirmed_protocol: str | None = None,
) -> None:
    """testssl.sh: TLS-/Zertifikats-Hygiene (fingerprint, ueber Egress-Proxy via
    --proxy). Nur nennenswerte Befunde (severity >= low) werden als Findings
    uebernommen; testssls eigene Severity gilt (severity_override). Braucht die
    materialisierte IP (--ip), weil testssl DNS lokal aufloest.

    confirmed_protocol: was httpx (this same fingerprint pass, seconds
    earlier) actually observed on this port - fixed 2026-08-03. Found live:
    testssl ran unconditionally regardless of that result, so a confirmed
    plain-HTTP service on a non-standard port got "TLS 1.2 not offered" /
    "TLS 1.3 not offered" findings - true, but meaningless noise (there is no
    TLS layer at all to be missing versions from, the same way "this HTTP
    server doesn't support telnet" would be). Skipping testssl when httpx
    already confirmed http (not https) avoids that noise and the wasted
    tool-runtime, for ANY target, not just this benchmark's."""
    port_range = str(single_port or 443)
    if confirmed_protocol == "http":
        logger.info("testssl for %s skipped: httpx already confirmed plain HTTP (no TLS)", target)
        tool_execution.record(
            engagement_id, scan_run_id=scan_run_id, tool="testssl", phase="fingerprint",
            authorized_target=target, resolved_target=ip, port_range=port_range,
            result=tool_execution.failed_result("not_a_tls_service"),
        )
        return
    if ip is None:
        logger.info("testssl for %s skipped: no materialized IP", target)
        tool_execution.record(
            engagement_id, scan_run_id=scan_run_id, tool="testssl", phase="fingerprint",
            authorized_target=target, resolved_target=None, port_range=port_range,
            result=tool_execution.failed_result("materialized_ip_missing"),
        )
        return
    # ip ist ein Routing-Detail (materialisiert), kein sicherheitsrelevantes
    # Tool-Argument -> nicht ans Gateway (dessen args-Haertung wuerde es sonst
    # als unbekanntes Argument fail-closed ablehnen).
    if _propose(engagement_id, "testssl", "fingerprint", target, {}, scan_run_id) is None:
        return
    url = _target_url(target, single_port)
    try:
        result = tool_runner.run("testssl", url, {"ip": ip}, scan_run_id=scan_run_id, engagement_id=engagement_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("testssl failed for %s: %s", target, exc)
        result = tool_execution.failed_result("runner_dispatch_failed", exc)
    issues = parse_testssl_json(result.get("stdout", "")) if tool_execution.usable_output(result) else []
    tool_execution.record(
        engagement_id, scan_run_id=scan_run_id, tool="testssl", phase="fingerprint",
        authorized_target=target, resolved_target=ip, port_range=port_range, result=result,
    )
    if not tool_execution.usable_output(result):
        return
    for f in issues:
        _add_finding(
            engagement_id, asset_id=asset_id, category="misconfig",
            title=f["title"], confidence="validated", severity_override=f["severity"],
            evidence={"check": f["id"], "tool": "testssl"},
            exposure_factor=1.0, business_factor=0.4,
        )


def _tls_service_scan(
    engagement_id: str, asset_id: str, target: str, ip: str | None, scan_run_id: str | None,
    port: int, starttls: str | None, service_name: str | None = None,
) -> None:
    """REQ-PIPE-009: TLS hygiene of a non-web TLS service (mail, LDAP, ...):
    directly for an implicit-TLS port, with --starttls where the protocol upgrades
    to TLS. Every finding names the service and the port, so the same weakness on
    two ports of one host stays two findings."""
    port_range = str(port)
    if ip is None:
        tool_execution.record(
            engagement_id, scan_run_id=scan_run_id, tool="testssl", phase="fingerprint",
            authorized_target=target, resolved_target=None, port_range=port_range,
            result=tool_execution.failed_result("materialized_ip_missing"),
        )
        return
    gateway_args = {"starttls": starttls} if starttls else {}
    if _propose(engagement_id, "testssl", "fingerprint", target, gateway_args, scan_run_id) is None:
        return
    try:
        result = tool_runner.run("testssl", f"{target}:{port}", {"ip": ip, **gateway_args},
                                 scan_run_id=scan_run_id, engagement_id=engagement_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("testssl failed for %s:%s: %s", target, port, exc)
        result = tool_execution.failed_result("runner_dispatch_failed", exc)
    problem = testssl_scan_problem(result.get("stdout", "")) if tool_execution.usable_output(result) else None
    if problem is not None:
        # testssl could not test the service: never a clean result.
        result = tool_execution.failed_result(problem[0]) | {"stderr": problem[1], "command": result.get("command")}
    issues = parse_testssl_json(result.get("stdout", "")) if tool_execution.usable_output(result) else []
    tool_execution.record(
        engagement_id, scan_run_id=scan_run_id, tool="testssl", phase="fingerprint",
        authorized_target=target, resolved_target=ip, port_range=port_range, result=result,
    )
    label = service_name or starttls or "tls"
    for f in issues:
        _add_finding(
            engagement_id, asset_id=asset_id, category="misconfig",
            title=f"{f['title']} ({label} on port {port})"[:240], confidence="validated", severity_override=f["severity"],
            evidence={"check": f["id"], "tool": "testssl", "port": port, "service": label, "starttls": starttls},
            exposure_factor=1.0, business_factor=0.4,
        )


def _nuclei_pass(engagement_id: str, asset_id: str, target: str, url: str, args: dict,
                 scan_run_id: str | None, single_port: int | None, budget_s: int | None = None) -> None:
    """Ein einzelner nuclei-Aufruf (Haupt- ODER Headless-Pass, per args["mode"]).
    Beide gehen durch dasselbe Scope Gateway (Tool 'nuclei', Kategorie 'vuln')
    und HexStrikes /api/tools/nuclei; jeder Pass bleibt fuer sich unter dem
    harten 300s-Executor-Limit (s. _nuclei_body)."""
    if _propose(engagement_id, "nuclei", "vuln", target, args, scan_run_id) is None:
        return
    try:
        extra = {} if budget_s is None else {"budget_s": budget_s}
        result = tool_runner.run("nuclei", url, args, scan_run_id=scan_run_id, engagement_id=engagement_id, **extra)
    except Exception as exc:  # noqa: BLE001
        logger.warning("nuclei failed for %s (mode=%s): %s", target, args.get("mode", "select"), exc)
        result = tool_execution.failed_result("runner_dispatch_failed", exc)
    # Matches printed before a timeout or a nonzero exit are real template hits;
    # the pass is still recorded as failed (coverage degraded), never as clean.
    salvage = tool_execution.usable_output(result) or result.get("error_reason") == "nonzero_exit"
    hits = parse_nuclei_jsonl(result.get("stdout", "")) if salvage else []
    tool_execution.record(
        engagement_id, scan_run_id=scan_run_id, tool="nuclei", phase="fingerprint",
        authorized_target=target, resolved_target=None, port_range=str(single_port or 443), result=result,
    )
    for f in hits:
        _add_finding(
            engagement_id, asset_id=asset_id, category=f["category"],
            title=f["title"], confidence="validated", severity_override=f["severity"],
            cve_ids=f["cve_ids"], cvss_base=f["cvss_base"],
            evidence={"template_id": f["template_id"], "matched_at": f["matched_at"], "tool": "nuclei"},
            exposure_factor=1.0, business_factor=0.5,
        )


# REQ-SCANQUAL-005: smallest of the 5 allowed SecLists keys - curated for
# exactly this always-on-every-scan use, unlike common/raft-medium-*/
# directory-list-medium, which are 10-100x larger and better suited to a
# deliberate, agent-chosen deep dive on a specific lead.
_CONTENT_DISCOVERY_WORDLIST = "quickhits"


def _content_discovery(engagement_id: str, asset_id: str, target: str, scan_run_id: str | None,
                       single_port: int | None = None, confirmed_protocol: str | None = None,
                       wordlist: str = _CONTENT_DISCOVERY_WORDLIST) -> None:
    """ffuf: curated content discovery (fingerprint baseline, REQ-SCANQUAL-005).

    Previously ffuf only ran if the agent decided to call it mid-loop - the
    one web tool in the registry NOT part of the deterministic baseline,
    unlike httpx/wafw00f/testssl/nuclei above. Judging whether a hit
    matters stays the agent's job (ffuf_parse.py's own docstring), so hits
    are reported as a single inferred-confidence Finding, not asserted as a
    confirmed issue the way the header check is."""
    url = _target_url(target, single_port, confirmed_protocol)
    port = single_port or 443
    args = {"wordlist": wordlist}
    if _propose(engagement_id, "ffuf", "vuln", target, args, scan_run_id) is None:
        return
    try:
        result = tool_runner.run("ffuf", url, args, scan_run_id=scan_run_id, engagement_id=engagement_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("ffuf content discovery failed for %s: %s", target, exc)
        result = tool_execution.failed_result("runner_dispatch_failed", exc)
    hits = parse_ffuf_json(result.get("stdout", "")) if tool_execution.usable_output(result) else []
    # REQ-DISCO-001: one response repeated is one observation, not N findings.
    # Recorded as a distinct outcome rather than dropped silently, so the
    # operator can see that discovery ran and why it produced nothing.
    if is_catch_all(hits):
        logger.info(
            "ffuf for %s discarded: %d hits, practically all with the same "
            "response - catch-all, no content discovery", target, len(hits),
        )
        result = dict(result)
        result.update(
            success=False,
            error_reason="content_discovery_catch_all",
            stderr=f"catch_all_response: {len(hits)} hits collapse onto one (status,length)",
        )
        tool_execution.record(
            engagement_id, scan_run_id=scan_run_id, tool="ffuf", phase="fingerprint",
            authorized_target=target, resolved_target=None, port_range=str(port), result=result,
        )
        return
    tool_execution.record(
        engagement_id, scan_run_id=scan_run_id, tool="ffuf", phase="fingerprint",
        authorized_target=target, resolved_target=None, port_range=str(port), result=result,
    )
    if not hits:
        return
    _add_finding(
        engagement_id, asset_id=asset_id, category="exposure",
        title=f"Content discovery: {len(hits)} path(s) found via ffuf ({wordlist})",
        confidence="inferred",
        evidence={"hits": hits, "wordlist": wordlist, "tool": "ffuf", "port": port},
        exposure_factor=1.0, business_factor=0.4,
    )


def _crawl(engagement_id: str, asset_id: str, target: str, scan_run_id: str | None,
           single_port: int | None, confirmed_protocol: str | None) -> list[str]:
    """REQ-COVER-003 (R4, switch `crawling_enabled`): bounded katana crawl of
    this one origin. Stores the endpoints (the control plane drops anything out
    of scope) and returns the parameterized same-host URLs for the DAST pass."""
    url = _target_url(target, single_port, confirmed_protocol)
    port = single_port or 443
    if _propose(engagement_id, "katana", "fingerprint", target, {}, scan_run_id) is None:
        return []
    try:
        result = tool_runner.run("katana", url, {}, scan_run_id=scan_run_id, engagement_id=engagement_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("katana failed for %s: %s", target, exc)
        result = tool_execution.failed_result("runner_dispatch_failed", exc)
    endpoints = parse_katana_jsonl(result.get("stdout", "")) if tool_execution.usable_output(result) else []
    tool_execution.record(
        engagement_id, scan_run_id=scan_run_id, tool="katana", phase="fingerprint",
        authorized_target=target, resolved_target=None, port_range=str(port), result=result,
    )
    if not endpoints:
        return []
    payload = [
        {"url": e["url"], "method": e["method"], "source": e["source"], "param_names": e["param_names"]}
        for e in endpoints
    ]
    try:
        for i in range(0, len(payload), 500):
            client.add_discovered_endpoints(uuid.UUID(engagement_id), scan_run_id, payload[i:i + 500])
    except Exception as exc:  # noqa: BLE001 - a store failure must not fail the scan
        logger.warning("storing crawled endpoints for %s failed: %s", target, exc)
    host = target.lower()
    return nuclei_candidate_urls([e for e in endpoints if (urlsplit(e["url"]).hostname or "").lower() == host])


def _nuclei_endpoints_pass(engagement_id: str, asset_id: str, target: str, scan_run_id: str | None,
                           single_port: int | None, confirmed_protocol: str | None, urls: list[str]) -> None:
    if not urls:
        return
    url = _target_url(target, single_port, confirmed_protocol)
    _nuclei_pass(engagement_id, asset_id, target, url, {"mode": "endpoints", "urls": urls}, scan_run_id, single_port)


def _screenshot(engagement_id: str, asset_id: str, target: str, scan_run_id: str | None,
                single_port: int | None, confirmed_protocol: str | None) -> None:
    """REQ-COVER-006 (R4, switch `screenshots_enabled`): one PNG of the live
    origin through the egress proxy, stored by the control plane."""
    url = _target_url(target, single_port, confirmed_protocol)
    port = single_port or 443
    if _propose(engagement_id, "screenshot", "fingerprint", target, {}, scan_run_id) is None:
        return
    try:
        result = tool_runner.run("screenshot", url, {}, scan_run_id=scan_run_id, engagement_id=engagement_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("screenshot failed for %s: %s", target, exc)
        result = tool_execution.failed_result("runner_dispatch_failed", exc)
    png_b64 = (result.get("stdout") or "").strip() if result.get("success") else ""
    if result.get("success") and not png_b64:
        result = dict(result)
        result.update(success=False, error_reason="screenshot_empty", stderr="no screenshot was produced")
    tool_execution.record(
        engagement_id, scan_run_id=scan_run_id, tool="screenshot", phase="fingerprint",
        authorized_target=target, resolved_target=None, port_range=str(port), result=result,
    )
    if not png_b64:
        return
    try:
        client.add_web_screenshot(uuid.UUID(engagement_id), scan_run_id, url, png_b64)
    except Exception as exc:  # noqa: BLE001
        logger.warning("storing screenshot for %s failed: %s", target, exc)


# REQ-SCANQUAL-003: nmap-identified web services worth enumerating on non-443 ports.
_WEB_PRODUCT_HINTS = ("http", "nginx", "apache", "caddy", "iis", "tomcat", "jetty", "lighttpd", "openresty")
_WEB_PORT_CAP = 4


def _web_candidate_ports(nmap_services: list[dict], scan_succeeded: bool = False) -> list[int]:
    """Ports to web-enumerate when the engagement window is broad.

    REQ-FPEFF-003: when a port scan actually ran, its open-port set is
    evidence - a port it proved closed is not probed, including 443. When no
    scan result exists (denied, unavailable, degraded), 443 is still probed:
    absence of evidence is not evidence of absence, and that run is already
    flagged degraded by REQ-SCAN-014. Capped to keep runtime bounded; the
    egress proxy still enforces that each port is inside the authorized window.
    """
    open_ports: set[int] = set()
    extra: set[int] = set()
    for svc in nmap_services:
        try:
            port = int(svc["port"])
        except (KeyError, TypeError, ValueError):
            continue
        # TCP only: a UDP service on 443 says nothing about an HTTPS listener.
        if str(svc.get("protocol") or "tcp").lower() not in ("tcp", "http", "https", "ssl"):
            continue
        open_ports.add(port)
        product = str(svc.get("product") or "").lower()
        if any(hint in product for hint in _WEB_PRODUCT_HINTS) and port != 443:
            extra.add(port)

    # 443 is kept unless a successful scan positively established it is closed.
    base = [443] if (not scan_succeeded or 443 in open_ports) else []
    return base + sorted(extra)[: max(0, _WEB_PORT_CAP - len(base))]


def _record_missing_ip(engagement_id: str, host: str, scan_run_id: str | None, single_port: int | None) -> None:
    """REQ-DISCO-004: DNS materialization already established whether this name
    resolves at all. nmap honours that (materialized_ip_missing); the web tools
    did not, so an NXDOMAIN host was probed by httpx/ffuf/nuclei and produced
    ~33,000 proxy-denied requests plus fabricated findings.

    This is audit hygiene and efficiency, NOT a security boundary: the egress
    proxy remains the enforcement point and refuses these connections
    regardless. It must never be relied on as the reason a connection does not
    happen."""
    logger.info("%s: no materialized IP - skipping web tools", host)
    for tool in ("httpx", "wafw00f", "testssl", "ffuf", "nuclei"):
        tool_execution.record(
            engagement_id, scan_run_id=scan_run_id, tool=tool, phase="fingerprint",
            authorized_target=host, resolved_target=None, port_range=str(single_port or 443),
            result=tool_execution.failed_result("materialized_ip_missing"),
        )


_SECRET_HEADERS = frozenset({"set-cookie", "cookie", "authorization", "proxy-authorization", "www-authenticate"})


def _surface_fingerprint(live: dict, protocol: str | None) -> dict:
    """What later checks need to know about a live web surface (REQ-PIPE-001)."""
    keep = ("url", "status_code", "title", "webserver", "content_length")
    fingerprint = {k: live.get(k) for k in keep if live.get(k) is not None}
    # Session-bearing headers are never stored (the control plane drops them too).
    headers = {}
    for name, value in (live.get("headers") or {}).items():
        key = str(name).strip().lower().replace("_", "-")
        if key not in _SECRET_HEADERS:
            headers[key] = value
    fingerprint.update(
        protocol=protocol, tech=list(live.get("tech") or []), headers=headers, service_id=live.get("service_id"),
    )
    return fingerprint


def _nmap_product_for(nmap_services: list[dict], port: int) -> list[tuple[str, str | None]]:
    out = []
    for svc in nmap_services:
        if svc.get("port") == port and str(svc.get("protocol") or "tcp").lower() in ("tcp", "http", "https", "ssl"):
            name = svc.get("product_name") or svc.get("product")
            if name and str(name).lower() not in ("unknown", "tcpwrapped"):
                out.append((str(name), svc.get("version")))
    return out


def _probe_web_surface(
    ctx: _RunContext, engagement_id: str, aid: str, host: str, ip: str | None, scan_run_id: str | None,
    single_port: int | None, nmap_services: list[dict],
) -> tuple[dict | None, dict | None]:
    """Stage S4 for one candidate web port (REQ-PIPE-001/002): httpx confirms a
    live HTTP(S) service (skip dead ports), and the port becomes a surface with
    its class and technology profile.

    Returns (probe result to hand on as a service, surface row for the plan), or
    (None, None) when the port is not a live web service. single_port is the
    exact port to hit (None => 443).
    """
    if ip is None:
        _record_missing_ip(engagement_id, host, scan_run_id, single_port)
        return None, None
    live = _http_probe(engagement_id, aid, host, scan_run_id, single_port)
    if live is None:
        logger.info("%s:%s not confirmed as a live HTTP service - skipping web tools", host, single_port or 443)
        return None, None
    port = single_port or 443
    # REQ-FIDELITY-009: httpx has just reported the scheme it actually reached
    # this host/port with. Every tool needs an EXPLICIT scheme (none of them
    # auto-probe), so hand them the confirmed one instead of the blanket
    # https:// default - against a plain-HTTP service the forced https:// made
    # nuclei/nikto silently return nothing at all.
    protocol = protocol_from_httpx_url(live.get("url", ""))
    profile = build_profile(
        httpx_tech=live.get("tech") or [], webserver=live.get("webserver"),
        nmap_products=_nmap_product_for(nmap_services, port),
    )
    surface = {
        "host": host, "ip": ip, "port": port, "scheme": protocol, "service_class": "web", "asset_id": aid,
        "profile": profile, "fingerprint": _surface_fingerprint(live, protocol),
    }

    # REQ-PIPE-001: a port that only redirects to another surface of this same
    # host, live in this run, is an alias of it. It keeps its httpx result and
    # gets no deep checks; the target surface gets them once.
    live_ports = ctx.live_web_ports.setdefault(host.lower(), set())
    alias_port = redirect_alias_port(live.get("status_code"), live.get("location"), host, port, live_ports)
    if alias_port is not None:
        logger.info("%s:%s only redirects to %s:%s - alias, skipping deep checks", host, port, host, alias_port)
        surface.update(service_class="web_alias", alias_of=f"{host}:{alias_port}")
        return live, surface
    live_ports.add(port)

    # REQ-FPEFF-004: the expensive tools run once per distinct web SURFACE.
    # Virtual hosting means one IP:port serves different content per Host
    # header, so this is keyed on httpx's response fingerprint, never on the
    # address alone. An unknown fingerprint is never deduplicated.
    key = _web_surface_key(ip, single_port, live)
    if key is not None and key in ctx.web_surfaces:
        covered_by = ctx.web_surfaces[key]
        logger.info("%s:%s serves the same web surface as %s - skipping the deep checks", host, port, covered_by)
        surface["fingerprint"]["duplicate_of"] = covered_by
    elif key is not None:
        ctx.web_surfaces[key] = host
    return live, surface


def _non_web_surfaces(
    aid: str, host: str, ip: str | None, nmap_services: list[dict], taken_ports: set[int],
) -> list[dict]:
    """One surface per open TCP port that is not a live web service (REQ-PIPE-001)."""
    rows: list[dict] = []
    seen: set[int] = set()
    for svc in nmap_services:
        try:
            port = int(svc["port"])
        except (KeyError, TypeError, ValueError):
            continue
        if port in taken_ports or port in seen or str(svc.get("protocol") or "tcp").lower() != "tcp":
            continue
        seen.add(port)
        service_class, starttls = classify_open_port(port, svc.get("service_name"), svc.get("product"))
        fingerprint = {"service_name": svc.get("service_name"), "product": svc.get("product"), "version": svc.get("version")}
        if starttls:
            fingerprint["starttls"] = starttls
        rows.append({
            "host": host, "ip": ip, "port": port, "scheme": None, "service_class": service_class, "asset_id": aid,
            "profile": build_profile(nmap_products=_nmap_product_for(nmap_services, port)),
            "fingerprint": {k: v for k, v in fingerprint.items() if v},
        })
    return rows


def _materialize(engagement_id: str, scan_run_id: str | None) -> dict[str, str]:
    """Audited control-plane DNS materialization -> {hostname: ip}.

    The worker never resolves DNS itself for this purpose: the snapshot the
    raw-egress lease validates against is control-plane-owned (trust anchor),
    and a worker-side resolution would not be the thing being checked.
    """
    ip_by_host: dict[str, str] = {}
    for r in client.materialize_dns(uuid.UUID(engagement_id), scan_run_id=scan_run_id).get("resolved", []):
        ip_by_host.setdefault(r["hostname"].lower(), r["ip_address"])
    return ip_by_host


def _index_info() -> IndexInfo:
    """Template counts of the runner image's index, for sizing the nuclei calls.
    When the runner cannot answer, the plan uses the last measured counts and
    each call re-resolves its own count when it runs."""
    try:
        summary = tool_runner.nuclei_index_summary()
        return IndexInfo(generic=int(summary["generic"]), total=int(summary["total"]), known=True)
    except Exception as exc:  # noqa: BLE001
        logger.warning("nuclei template index summary unavailable: %s", exc)
        return IndexInfo()


def _discover_surfaces(engagement_id: str, discovered: list[dict], scan_run_id: str | None) -> tuple[list[dict], list[dict]]:
    """Stages S3 and S4 for every approved asset: port scan (once per IP), then
    classify each open port as a surface. Returns (services, surface rows)."""
    # DNS-Materialisierung (auditiert): liefert Namen->IP fuer Tools, die DNS
    # lokal aufloesen (testssl) und speist zugleich die Egress-Proxy-IP-
    # Freigabe (resolved_host).
    ip_by_host: dict[str, str] = {}
    try:
        ip_by_host = _materialize(engagement_id, scan_run_id)
    except Exception as exc:  # noqa: BLE001 - Materialisierung ist best effort
        logger.warning("DNS materialization failed: %s", exc)

    ctx = _RunContext()
    all_services: list[dict] = []
    surfaces: list[dict] = []
    for asset in discovered:
        aid, host = asset["asset_id"], asset["value"]
        # REQ-FIDELITY-003/REQ-PORTSCOPE-004: bei einem einzelnen, autorisierten
        # Nicht-Standard-Port (z. B. 4280) zielen die Web-Tools auf DIESEN Port
        # statt implizit auf 443 - sonst wird der autorisierte Dienst nie
        # getestet. Per-Host aufgeloest (nicht einmal vorab fuer das ganze
        # Engagement), da verschiedene Ziele im selben Auftrag unterschiedliche
        # Portbereiche haben koennen.
        envelope = client.get_scan_envelope(uuid.UUID(engagement_id), host=host)
        single_port = _single_port_from_envelope(envelope)
        ip = ip_by_host.get(host.lower())
        if ip is None:
            try:
                ip = str(ipaddress.ip_address(host))
            except ValueError:
                pass

        # REQ-FPEFF-001: the raw-egress lease re-checks this host's DNS
        # materialization age at ITS dispatch time against a 15-minute window
        # (an anti-rebinding control that must stay). One snapshot taken before
        # the whole loop went stale for every host after roughly the second, so
        # refresh it here - but only when this host will actually execute a
        # scan, since a cache hit (REQ-FPEFF-002) needs no fresh snapshot.
        if ip is not None and _port_scan_key(ip, envelope) not in ctx.port_scans:
            try:
                refreshed = _materialize(engagement_id, scan_run_id)
                ip_by_host.update(refreshed)
                ip = refreshed.get(host.lower(), ip)
            except Exception as exc:  # noqa: BLE001
                # Do not scan against a snapshot known to be stale: the lease
                # would deny it anyway, and proceeding would be scanning an IP
                # the control plane has not just re-confirmed.
                logger.warning("DNS re-materialization for %s failed: %s", host, exc)
                tool_execution.record(
                    engagement_id, scan_run_id=scan_run_id, tool="nmap", phase="fingerprint",
                    authorized_target=host, resolved_target=ip, port_range="configured_tcp",
                    result=tool_execution.failed_result("dns_rematerialization_failed", exc),
                    discovered_services=0,
                )
                ip = None

        # nmap first so its discovered web ports can steer the web tools.
        nmap_services, scan_succeeded = _nmap_scan(
            ctx, engagement_id, aid, host, ip, scan_run_id, envelope,
        )
        all_services.extend(nmap_services)

        # REQ-SCANQUAL-003 / REQ-FIDELITY-003: a configured single non-default
        # port pins every web tool to exactly that port (unchanged). Otherwise
        # web-enumerate the ports the scan actually found open (REQ-FPEFF-003),
        # falling back to 443 when there is no scan evidence at all.
        if single_port is not None:
            web_ports = [single_port]
        else:
            web_ports = _web_candidate_ports(nmap_services, scan_succeeded=scan_succeeded)

        web_taken: set[int] = set()
        for port in web_ports:
            # None => https default (443); an explicit port => https://host:port.
            probe_port = None if port == 443 else port
            live, surface = _probe_web_surface(ctx, engagement_id, aid, host, ip, scan_run_id, probe_port, nmap_services)
            if live is not None and surface is not None:
                all_services.append({**live, "service_id": live.get("service_id"), "asset_id": aid, "target": host})
                surfaces.append(surface)
                web_taken.add(port)
        surfaces.extend(_non_web_surfaces(aid, host, ip, nmap_services, web_taken))
    return all_services, surfaces


def _plan_payload(surfaces: list[dict], options: Options, index: IndexInfo) -> list[dict]:
    """The API shape of a plan: each surface row with its planned/skipped checks."""
    payload = []
    for row in surfaces:
        fingerprint = row.get("fingerprint") or {}
        surface_input = SurfaceInput(
            host=row["host"], port=row["port"], service_class=row["service_class"], scheme=row.get("scheme"),
            profile=tuple(row.get("profile") or ()), alias_of=row.get("alias_of"),
            duplicate_of=fingerprint.get("duplicate_of"), starttls=fingerprint.get("starttls"),
        )
        checks = plan_surface(surface_input, options, index)
        payload.append({**row, "checks": [
            {"check_id": c.check_id, "tool": c.tool, "state": c.state, "reason": c.reason, "args": c.args,
             "depends_on": c.depends_on, "budget_s": c.budget_s}
            for c in checks
        ]})
    return payload


# --- Check handlers: one function per planned check (REQ-PIPE-003) ---------------------

def _live_from_surface(r: CheckRun) -> dict:
    fp = r.fingerprint
    return {"status_code": fp.get("status_code"), "headers": fp.get("headers") or {}, "service_id": fp.get("service_id")}


def _h_header_findings(r: CheckRun) -> None:
    _header_findings(r.engagement_id, r.asset_id, r.host, _live_from_surface(r), r.single_port, confirmed_protocol=r.protocol)


def _h_waf(r: CheckRun) -> None:
    _waf_detect(r.engagement_id, r.asset_id, r.host, r.scan_run_id, r.single_port, confirmed_protocol=r.protocol)


def _h_testssl(r: CheckRun) -> None:
    if r.surface.get("service_class") == "tls_service":
        fp = r.fingerprint
        _tls_service_scan(r.engagement_id, r.asset_id, r.host, r.surface.get("ip"), r.scan_run_id, r.port,
                          (r.check.get("args") or {}).get("starttls") or fp.get("starttls"), fp.get("service_name"))
        return
    _tls_scan(r.engagement_id, r.asset_id, r.host, r.surface.get("ip"), r.scan_run_id, r.single_port,
              confirmed_protocol=r.protocol)


def _h_ffuf(r: CheckRun) -> None:
    """The quickhits check and the thorough profile's deep sweep (REQ-PIPE-017)
    share this handler; the wordlist comes from the check's own stored args and
    only a key the runner knows is used."""
    wordlist = (r.check.get("args") or {}).get("wordlist")
    known = isinstance(wordlist, str) and wordlist in FFUF_WORDLISTS
    kwargs = {"wordlist": wordlist} if known and wordlist != _CONTENT_DISCOVERY_WORDLIST else {}
    _content_discovery(r.engagement_id, r.asset_id, r.host, r.scan_run_id, r.single_port,
                       confirmed_protocol=r.protocol, **kwargs)


def _h_screenshot(r: CheckRun) -> None:
    _screenshot(r.engagement_id, r.asset_id, r.host, r.scan_run_id, r.single_port, r.protocol)


def _h_katana(r: CheckRun) -> None:
    urls = _crawl(r.engagement_id, r.asset_id, r.host, r.scan_run_id, r.single_port, r.protocol)
    r.outcome_summary["candidate_urls"] = urls[:50]
    r.outcome_summary["candidate_url_count"] = len(urls)


def _h_nuclei_endpoints(r: CheckRun) -> None:
    urls = list(((r.dependencies.get("katana") or {}).get("outcome_summary") or {}).get("candidate_urls") or [])
    if not urls:
        r.skip("no_endpoints")
        return
    r.args = {**(r.check.get("args") or {}), "urls": urls}
    _nuclei_endpoints_pass(r.engagement_id, r.asset_id, r.host, r.scan_run_id, r.single_port, r.protocol, urls)


def _h_nuclei_fixed(r: CheckRun) -> None:
    mode = (r.check.get("args") or {}).get("mode")
    url = _target_url(r.host, r.single_port, r.protocol)
    _nuclei_pass(r.engagement_id, r.asset_id, r.host, url, {"mode": mode}, r.scan_run_id, r.single_port)


def _h_nuclei_oob(r: CheckRun) -> None:
    args = r.check.get("args") or {}
    url = _target_url(r.host, r.single_port, r.protocol)
    _nuclei_pass(r.engagement_id, r.asset_id, r.host, url, {"mode": "oob", "part": args.get("part")},
                 r.scan_run_id, r.single_port)


def _h_nuclei_tech(r: CheckRun) -> None:
    """REQ-PIPE-002: nuclei's technology-detection templates enrich the surface's
    profile, so the product-bound templates that follow match what is really there."""
    url = _target_url(r.host, r.single_port, r.protocol)
    args = {"mode": "tech"}
    if _propose(r.engagement_id, "nuclei", "vuln", r.host, args, r.scan_run_id) is None:
        return
    try:
        result = tool_runner.run("nuclei", url, args, scan_run_id=r.scan_run_id, engagement_id=r.engagement_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("nuclei technology detection failed for %s: %s", r.host, exc)
        result = tool_execution.failed_result("runner_dispatch_failed", exc)
    names = parse_nuclei_tech(result.get("stdout", "")) if tool_execution.usable_output(result) else []
    tool_execution.record(
        r.engagement_id, scan_run_id=r.scan_run_id, tool="nuclei", phase="fingerprint",
        authorized_target=r.host, resolved_target=None, port_range=str(r.port), result=result,
    )
    if not names:
        return
    merged = build_profile(extra=names, nmap_products=[], httpx_tech=[])
    known = list(r.surface.get("profile") or [])
    profile = list(dict.fromkeys([*known, *merged]))[:MAX_PROFILE_ENTRIES]
    client.update_scan_surface(r.scan_run_id, r.surface["id"], profile=profile)
    r.surface["profile"] = profile
    r.outcome_summary["detected"] = names[:20]


def _h_nuclei_select(r: CheckRun) -> None:
    """One selection of the template index (REQ-PIPE-004): resolve what it holds
    now (a product selection follows the surface's profile as the technology
    check left it), size the call's budget from the template count, run it."""
    args = dict(r.check.get("args") or {})
    if args.pop("from_profile", False):
        keys, reason = resolve_products(r.surface.get("profile") or [])
        args["products"] = keys
        r.reason = reason
    selection = {k: v for k, v in args.items() if k in ("mode", "group", "shard", "products")}
    r.args = {**selection, **({"from_profile": True} if (r.check.get("args") or {}).get("from_profile") else {})}
    try:
        count = tool_runner.nuclei_selection_count(selection)
    except Exception as exc:  # noqa: BLE001
        logger.warning("nuclei selection could not be resolved for %s: %s", r.host, exc)
        tool_execution.record(
            r.engagement_id, scan_run_id=r.scan_run_id, tool="nuclei", phase="fingerprint",
            authorized_target=r.host, resolved_target=None, port_range=str(r.port),
            result=tool_execution.failed_result("selection_unavailable", exc),
        )
        return
    r.outcome_summary["templates"] = count
    if count == 0:
        r.skip("no_matching_templates")
        return
    r.budget_s = nuclei_select_budget_s(count)
    url = _target_url(r.host, r.single_port, r.protocol)
    _nuclei_pass(r.engagement_id, r.asset_id, r.host, url, selection, r.scan_run_id, r.single_port, budget_s=r.budget_s)


def resolve_handler(check: dict) -> Handler | None:
    """The handler for one check row, chosen from its tool and mode only."""
    tool, check_id = check.get("tool"), check.get("check_id")
    mode = (check.get("args") or {}).get("mode")
    if check_id == "header_findings":
        return _h_header_findings
    simple = {"wafw00f": _h_waf, "testssl": _h_testssl, "ffuf": _h_ffuf, "screenshot": _h_screenshot, "katana": _h_katana}
    if tool in simple:
        return simple[tool]
    if tool == "nuclei":
        return {
            "select": _h_nuclei_select, "tech": _h_nuclei_tech, "headless": _h_nuclei_fixed,
            "takeover": _h_nuclei_fixed, "endpoints": _h_nuclei_endpoints, "oob": _h_nuclei_oob,
        }.get(mode)
    return None


def run(
    engagement_id: str, discovered: list[dict], scan_run_id: str | None = None,
    resume_services: list[dict] | None = None,
) -> list[dict]:
    """discovered: Ergebnis von discovery.run() - [{"value": ..., "asset_id": ...}].

    Stages S3-S6 of the scan pipeline: discover and classify the surfaces, plan
    the checks, execute them. A resumed run (resume_services holds what the first
    attempt found) reads its stored plan and continues with the checks that were
    not finished (REQ-PIPE-008)."""
    settings = client.get_scan_settings(uuid.UUID(engagement_id))
    plan_exists = False
    if scan_run_id is not None and resume_services is not None:
        try:
            plan_exists = bool(client.get_scan_plan(scan_run_id).get("surfaces"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("stored scan plan could not be read, discovering again: %s", exc)
    if plan_exists:
        logger.info("scan_run %s resumed: continuing the stored plan", scan_run_id)
        services = list(resume_services or [])
    else:
        services, surfaces = _discover_surfaces(engagement_id, discovered, scan_run_id)
        if scan_run_id is None:
            return services
        options_raw = _RunContext().discovery_options(engagement_id)
        options = Options(
            crawling=bool(options_raw.get("crawling")), screenshots=bool(options_raw.get("screenshots")),
            oob=bool(options_raw.get("oob")), oob_available=bool(OOB_SERVER_URL),
            scan_profile=settings["scan_profile"], disabled_tools=frozenset(settings.get("disabled_tools") or ()),
        )
        client.store_scan_plan(scan_run_id, _plan_payload(surfaces, options, _index_info()))
        client.update_scan_run(scan_run_id, checkpoint={"fp_services": json.loads(json.dumps(services, default=str))})
    if scan_run_id is None:
        return services
    scan_executor.execute_plan(
        client=client, scan_run_id=scan_run_id, engagement_id=engagement_id, resolve_handler=resolve_handler,
        max_parallel=settings["max_parallel_checks"],
        is_cancelled=lambda: client.is_cancel_requested(scan_run_id),
    )
    return services
