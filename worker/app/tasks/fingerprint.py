"""Phase 2 - Fingerprinting (Spezifikation Kap. 3.2).

Sendet nach Gateway-Freigabe echte Tool-Calls an den tool-runner (die echte
HexStrike-API, s. worker/app/tool_runner_client.py), schreibt Service-/
Finding-Ergebnisse ueber die interne control-plane-API. Fuer erkannte HTTP-
Dienste zusaetzlich ein nikto-Scan (misconfig/fehlende Security-Header,
Kap. 5.1).

Hinweis zum Header-Check: der worker selbst haengt NICHT im Lab-/Ziel-Netz
(nur ctrl+egress) und kann Ziele nicht direkt erreichen - jeder aktive Call
muss durch den tool-runner laufen, der als einziger Netzwerksicht auf die
Ziele hat. HexStrikes httpx-Endpunkt exponiert keine rohen Response-Header
ueber seine begrenzten Parameter; nikto (ebenfalls Tool-Allowlist Kap. 2.3)
meldet fehlende Security-Header verlaesslich in seiner Klartextausgabe und
wird stattdessen genutzt (s. nikto_parse.py).
"""

from __future__ import annotations

import dataclasses
import ipaddress
import logging
import time
import uuid

from app.control_plane_client import client
from app.ffuf_parse import is_catch_all, parse_ffuf_json
from app.httpx_parse import parse_httpx_json
from app.known_vulns import lookup as lookup_known_vuln
from app.lab_hosts import is_lab_host
from app.nikto_parse import parse_nikto_missing_headers
from app.nmap_parse import parse_nmap_grepable
from app.nuclei_parse import parse_nuclei_jsonl
from app.raw_egress_client import raw_egress_gateway
from app.raw_nmap import RawNmapOutcome, execute_configured_tcp_scan, execute_targeted_udp_scan
from app.target_envelope import httpx_target, protocol_from_httpx_url, single_port_from_envelope, target_url
from app.testssl_parse import parse_testssl_json
from app.tool_runner_client import tool_runner
from app import tool_execution
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


def _propose(
    engagement_id: str, tool: str, category: str, target: str, args: dict,
    scan_run_id: str | None, phase: str = "fingerprint",
) -> dict | None:
    payload = {
        "tool": tool, "category": category, "mode": "active", "target": target, "args": args,
        "is_automated": True, "phase": phase, "scan_run_id": scan_run_id,
    }
    for attempt in range(8):
        if scan_run_id and client.is_cancel_requested(uuid.UUID(scan_run_id)):
            return None
        decision = client.authorize(uuid.UUID(engagement_id), payload)
        if decision["allowed"]:
            return decision
        if decision.get("is_throttled") and decision.get("retry_after_seconds") is not None:
            delay = min(max(float(decision["retry_after_seconds"]), 0.1), 5.0)
            logger.info("%s auf %s gedrosselt: warte %.2fs vor erneutem Gateway-Check", tool, target, delay)
            time.sleep(delay)
            continue
        logger.info("%s auf %s abgelehnt: %s", tool, target, decision["reason"])
        return None
    logger.info("%s auf %s nach wiederholter Drosselung uebersprungen", tool, target)
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
                "nmap %s fuer %s nicht vollstaendig erfolgreich: %s",
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
            "nmap fuer %s uebersprungen: %s wurde in diesem Lauf bereits gescannt (durch %s)",
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


def _web_enum(engagement_id: str, asset_id: str, target: str, scan_run_id: str | None, single_port: int | None = None,
              confirmed_protocol: str | None = None) -> None:
    """Web-Enumeration via nikto ueber den Egress-Proxy (HTTP(S) ist die primaere
    externe ASM-Angriffsflaeche - laeuft unabhaengig von nmap). nikto ist ein
    vuln-Tool (Allowlist Kap. 2.3) und braucht daher einen vuln-Grant.

    confirmed_protocol (REQ-FIDELITY-009): the scheme httpx actually reached
    this host/port with. nikto needs an explicit scheme (it does not probe the
    other one), so a plain-HTTP service scanned as https:// yields nothing."""
    url = _target_url(target, single_port, confirmed_protocol)
    port = single_port or 443
    if _propose(engagement_id, "nikto", "vuln", target, {}, scan_run_id) is None:
        return
    # REQ-SCANQUAL-002: non-intrusive tuning categories relevant to ASM -
    # interesting files (1), misconfiguration (2), information disclosure (3),
    # software identification (b). Deliberately EXCLUDES injection (4), DoS (6),
    # remote file retrieval (5,7), command execution (8), SQLi (9), file upload
    # (0), auth bypass (a), remote source inclusion (c) to stay non-destructive.
    # Missing-security-header findings surface from nikto's baseline analysis
    # regardless of tuning (verified), and are still parsed below.
    try:
        result = tool_runner.run("nikto", url, {"additional_args": "-Tuning 123b -maxtime 40s"}, scan_run_id=scan_run_id, engagement_id=engagement_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("nikto-Enumeration fehlgeschlagen fuer %s: %s", target, exc)
        result = tool_execution.failed_result("runner_dispatch_failed", exc)
    stdout = result.get("stdout", "") if result.get("success") else ""
    missing = parse_nikto_missing_headers(stdout)
    tool_execution.record(
        engagement_id, scan_run_id=scan_run_id, tool="nikto", phase="fingerprint",
        authorized_target=target, resolved_target=None, port_range=str(port), result=result,
        discovered_services=1 if result.get("success") else 0,
    )
    if not result.get("success"):
        return
    # REQ-FIDELITY-009: record the protocol httpx CONFIRMED, never a hardcoded
    # "https". add_service has no upsert (control-plane/app/api/internal.py) -
    # every call inserts - so a wrong literal here does not merely mislabel, it
    # permanently adds a second, contradictory service row for a port that was
    # already correctly identified. Measured before this fix:
    # pentest-ground.com:4280 (a REAL engagement) carried https/http,
    # https/nginx and tcp/nginx rows simultaneously, all of which are rendered
    # into the agent's evidence block.
    svc_resp = client.add_service(engagement_id, asset_id=asset_id, port=port,
                                  protocol=confirmed_protocol or "https", product="http")
    service_id = svc_resp["id"]
    if missing:
        client.add_finding(
            engagement_id, asset_id=asset_id, service_id=service_id, category="misconfig",
            title=f"Fehlende Security-Header: {', '.join(missing)}", confidence="validated",
            evidence={"missing_headers": missing, "port": port, "tool": "nikto"},
            exposure_factor=1.0, business_factor=0.4,
        )


def _waf_detect(engagement_id: str, asset_id: str, target: str, scan_run_id: str | None, single_port: int | None = None,
                confirmed_protocol: str | None = None) -> None:
    """WAF-Fingerprinting via wafw00f ueber den Egress-Proxy (fingerprint-Tool,
    Allowlist Kap. 2.2). Ein erkannter WAF ist Recon-Kontext fuer den Operator
    (was schuetzt das Asset?) - bei Erkennung ein Info-Finding, sonst nichts.

    confirmed_protocol: REQ-FIDELITY-009, same reason as _web_enum - wafw00f
    takes a URL and does not probe the other scheme."""
    url = _target_url(target, single_port, confirmed_protocol)
    if _propose(engagement_id, "wafw00f", "fingerprint", target, {}, scan_run_id) is None:
        return
    try:
        result = tool_runner.run("wafw00f", url, {}, scan_run_id=scan_run_id, engagement_id=engagement_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("wafw00f fehlgeschlagen fuer %s: %s", target, exc)
        result = tool_execution.failed_result("runner_dispatch_failed", exc)
    waf = parse_wafw00f(result.get("stdout", "")) if result.get("success") else None
    tool_execution.record(
        engagement_id, scan_run_id=scan_run_id, tool="wafw00f", phase="fingerprint",
        authorized_target=target, resolved_target=None, port_range=str(single_port or 443), result=result,
    )
    if not result.get("success"):
        return
    if waf:
        client.add_finding(
            engagement_id, asset_id=asset_id, category="exposure",
            title=f"WAF erkannt: {waf}", confidence="validated",
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
        logger.warning("httpx fehlgeschlagen fuer %s: %s", target, exc)
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
        logger.info("testssl fuer %s uebersprungen: httpx hat bereits reines HTTP (kein TLS) bestaetigt", target)
        tool_execution.record(
            engagement_id, scan_run_id=scan_run_id, tool="testssl", phase="fingerprint",
            authorized_target=target, resolved_target=ip, port_range=port_range,
            result=tool_execution.failed_result("not_a_tls_service"),
        )
        return
    if ip is None:
        logger.info("testssl fuer %s uebersprungen: keine materialisierte IP", target)
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
        logger.warning("testssl fehlgeschlagen fuer %s: %s", target, exc)
        result = tool_execution.failed_result("runner_dispatch_failed", exc)
    issues = parse_testssl_json(result.get("stdout", "")) if result.get("success") else []
    tool_execution.record(
        engagement_id, scan_run_id=scan_run_id, tool="testssl", phase="fingerprint",
        authorized_target=target, resolved_target=ip, port_range=port_range, result=result,
    )
    if not result.get("success"):
        return
    for f in issues:
        client.add_finding(
            engagement_id, asset_id=asset_id, category="misconfig",
            title=f["title"], confidence="validated", severity_override=f["severity"],
            evidence={"check": f["id"], "tool": "testssl"},
            exposure_factor=1.0, business_factor=0.4,
        )


def _nuclei_pass(engagement_id: str, asset_id: str, target: str, url: str, args: dict,
                 scan_run_id: str | None, single_port: int | None) -> None:
    """Ein einzelner nuclei-Aufruf (Haupt- ODER Headless-Pass, per args["mode"]).
    Beide gehen durch dasselbe Scope Gateway (Tool 'nuclei', Kategorie 'vuln')
    und HexStrikes /api/tools/nuclei; jeder Pass bleibt fuer sich unter dem
    harten 300s-Executor-Limit (s. _nuclei_body)."""
    if _propose(engagement_id, "nuclei", "vuln", target, args, scan_run_id) is None:
        return
    try:
        result = tool_runner.run("nuclei", url, args, scan_run_id=scan_run_id, engagement_id=engagement_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("nuclei fehlgeschlagen fuer %s (mode=%s): %s", target, args.get("mode", "main"), exc)
        result = tool_execution.failed_result("runner_dispatch_failed", exc)
    hits = parse_nuclei_jsonl(result.get("stdout", "")) if result.get("success") else []
    tool_execution.record(
        engagement_id, scan_run_id=scan_run_id, tool="nuclei", phase="fingerprint",
        authorized_target=target, resolved_target=None, port_range=str(single_port or 443), result=result,
    )
    if not result.get("success"):
        return
    for f in hits:
        client.add_finding(
            engagement_id, asset_id=asset_id, category=f["category"],
            title=f["title"], confidence="validated", severity_override=f["severity"],
            cve_ids=f["cve_ids"], cvss_base=f["cvss_base"],
            evidence={"template_id": f["template_id"], "matched_at": f["matched_at"], "tool": "nuclei"},
            exposure_factor=1.0, business_factor=0.5,
        )


def _nuclei_scan(engagement_id: str, asset_id: str, target: str, scan_run_id: str | None, single_port: int | None = None,
                 confirmed_protocol: str | None = None) -> None:
    """nuclei: Template-basierte Schwachstellen-/Exposure-Erkennung (vuln,
    ueber Egress-Proxy). Konservativ (nicht-intrusive Templates, s.
    tool_runner_client). nuclei liefert eigene Severity + ggf. CVE/CVSS.

    REQ-AGENT-018: zwei getrennte Passes, weil HexStrike jeden Aufruf hart bei
    300s killt und der Headless-Modus zusammen mit dem vollen Tag-Satz diese
    Grenze gegen ein echtes, proxied Ziel sprengt (live festgestellt). Der
    Haupt-Pass (schnell, non-headless) und der Mini-Headless-Pass (nur domxss,
    1 Template) bleiben jeder fuer sich unter 300s. phase bleibt 'fingerprint'
    (deterministischer Pipeline-Call, KEIN Vector-Agent-Vorschlag).

    confirmed_protocol (REQ-FIDELITY-009): verified live 2026-08-03 - nuclei
    against a plain-HTTP service found 2 real template matches with http://,
    and 0 with https:// (silently: "Scan completed. No results found."). A
    schemeless target is not a fix either - nuclei's embedded httpx reported
    "Found 0 URL from httpx" and also scored 0."""
    url = _target_url(target, single_port, confirmed_protocol)
    _nuclei_pass(engagement_id, asset_id, target, url, {}, scan_run_id, single_port)
    _nuclei_pass(engagement_id, asset_id, target, url, {"mode": "headless"}, scan_run_id, single_port)


# REQ-SCANQUAL-005: smallest of the 5 allowed SecLists keys - curated for
# exactly this always-on-every-scan use, unlike common/raft-medium-*/
# directory-list-medium, which are 10-100x larger and better suited to a
# deliberate, agent-chosen deep dive on a specific lead.
_CONTENT_DISCOVERY_WORDLIST = "quickhits"


def _content_discovery(engagement_id: str, asset_id: str, target: str, scan_run_id: str | None,
                       single_port: int | None = None, confirmed_protocol: str | None = None) -> None:
    """ffuf: curated content discovery (fingerprint baseline, REQ-SCANQUAL-005).

    Previously ffuf only ran if the agent decided to call it mid-loop - the
    one web tool in the registry NOT part of the deterministic baseline,
    unlike httpx/nikto/wafw00f/testssl/nuclei above. Judging whether a hit
    matters stays the agent's job (ffuf_parse.py's own docstring), so hits
    are reported as a single inferred-confidence Finding, not asserted as a
    confirmed issue the way nikto's header check is."""
    url = _target_url(target, single_port, confirmed_protocol)
    port = single_port or 443
    args = {"wordlist": _CONTENT_DISCOVERY_WORDLIST}
    if _propose(engagement_id, "ffuf", "vuln", target, args, scan_run_id) is None:
        return
    try:
        result = tool_runner.run("ffuf", url, args, scan_run_id=scan_run_id, engagement_id=engagement_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("ffuf-Content-Discovery fehlgeschlagen fuer %s: %s", target, exc)
        result = tool_execution.failed_result("runner_dispatch_failed", exc)
    hits = parse_ffuf_json(result.get("stdout", "")) if result.get("success") else []
    # REQ-DISCO-001: one response repeated is one observation, not N findings.
    # Recorded as a distinct outcome rather than dropped silently, so the
    # operator can see that discovery ran and why it produced nothing.
    if is_catch_all(hits):
        logger.info(
            "ffuf fuer %s verworfen: %d Treffer, praktisch alle mit derselben "
            "Antwort - Catch-all, keine Content-Discovery", target, len(hits),
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
    client.add_finding(
        engagement_id, asset_id=asset_id, category="exposure",
        title=f"Content discovery: {len(hits)} path(s) found via ffuf ({_CONTENT_DISCOVERY_WORDLIST})",
        confidence="inferred",
        evidence={"hits": hits, "wordlist": _CONTENT_DISCOVERY_WORDLIST, "tool": "ffuf", "port": port},
        exposure_factor=1.0, business_factor=0.4,
    )


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


def _record_deep_skip(engagement_id: str, target: str, ip: str | None, scan_run_id: str | None,
                      port: int | None, covered_by: str) -> None:
    """REQ-FPEFF-004: a skipped deep tool is recorded against the host that
    skipped it, naming the host whose scan covered the same surface. The audit
    trail must show why a tool did not run - a silent skip is indistinguishable
    from a missed target."""
    for tool in ("nikto", "ffuf", "nuclei"):
        tool_execution.record(
            engagement_id, scan_run_id=scan_run_id, tool=tool, phase="fingerprint",
            authorized_target=target, resolved_target=ip, port_range=str(port or 443),
            result={
                "success": True, "exit_code": 0, "stdout": "",
                "stderr": f"duplicate_vhost_of:{covered_by}",
                "error_reason": None,
                "outcome_summary": {"duplicate_vhost_of": covered_by},
            },
        )


def _web_suite(ctx: _RunContext, engagement_id: str, aid: str, host: str, ip: str | None,
               scan_run_id: str | None, single_port: int | None) -> list[dict]:
    """httpx liveness first (skip dead ports), then the web tools on a live host.
    single_port is the exact port to hit (None => 443).

    REQ-FPEFF-005 order: cheapest and most informative first, so an aborted or
    timed-out run still yields the cheap signal, and the ~5-minute nuclei pass
    runs last. Every pre-existing gate is preserved.
    """
    services: list[dict] = []
    # REQ-DISCO-004: DNS materialization already established whether this name
    # resolves at all. nmap honours that (materialized_ip_missing); the web
    # tools did not, so an NXDOMAIN host was probed by httpx/nikto/ffuf/nuclei
    # and produced ~33,000 proxy-denied requests plus fabricated findings.
    # `ip` is None only when the control plane could not materialize an
    # address AND the host is not itself a literal IP (see run()).
    #
    # This is audit hygiene and efficiency, NOT a security boundary: the
    # egress proxy remains the enforcement point and refuses these
    # connections regardless. It must never be relied on as the reason a
    # connection does not happen.
    if ip is None:
        logger.info("%s: keine materialisierte IP - ueberspringe Web-Tools", host)
        for tool in ("httpx", "nikto", "wafw00f", "testssl", "ffuf", "nuclei"):
            tool_execution.record(
                engagement_id, scan_run_id=scan_run_id, tool=tool, phase="fingerprint",
                authorized_target=host, resolved_target=None,
                port_range=str(single_port or 443),
                result=tool_execution.failed_result("materialized_ip_missing"),
            )
        return services
    live = _http_probe(engagement_id, aid, host, scan_run_id, single_port)
    if live is None:
        logger.info("%s:%s nicht als lebender HTTP-Dienst bestaetigt - ueberspringe Web-Tools", host, single_port or 443)
        return services
    services.append(live)
    # REQ-FIDELITY-009: httpx has just reported the scheme it actually reached
    # this host/port with. Every tool below needs an EXPLICIT scheme (none of
    # them auto-probe), so hand them the confirmed one instead of the blanket
    # https:// default - against a plain-HTTP service the forced https:// made
    # nuclei/nikto silently return nothing at all.
    confirmed_protocol = protocol_from_httpx_url(live.get("url", ""))

    # Cheap and always per-name: a WAF verdict is context for reading every
    # later result, and costs ~1s.
    _waf_detect(engagement_id, aid, host, scan_run_id, single_port, confirmed_protocol=confirmed_protocol)
    # Per-name by definition: the certificate presented for one hostname says
    # nothing about another, so this is never deduplicated. Still skips a port
    # httpx just confirmed is not TLS at all.
    _tls_scan(engagement_id, aid, host, ip, scan_run_id, single_port, confirmed_protocol=confirmed_protocol)

    # REQ-FPEFF-004: the expensive tools run once per distinct web SURFACE.
    # Virtual hosting means one IP:port serves different content per Host
    # header, so this is keyed on httpx's response fingerprint, never on the
    # address alone. An unknown fingerprint is never deduplicated.
    surface = _web_surface_key(ip, single_port, live)
    if surface is not None and surface in ctx.web_surfaces:
        covered_by = ctx.web_surfaces[surface]
        logger.info(
            "%s:%s liefert dieselbe Web-Oberflaeche wie %s - ueberspringe nikto/ffuf/nuclei",
            host, single_port or 443, covered_by,
        )
        _record_deep_skip(engagement_id, host, ip, scan_run_id, single_port, covered_by)
        return services
    if surface is not None:
        ctx.web_surfaces[surface] = host

    _web_enum(engagement_id, aid, host, scan_run_id, single_port, confirmed_protocol=confirmed_protocol)
    _content_discovery(engagement_id, aid, host, scan_run_id, single_port, confirmed_protocol=confirmed_protocol)
    # Most expensive by far (~4m37s observed) - last, so everything cheaper has
    # already been recorded if the run is cut short.
    _nuclei_scan(engagement_id, aid, host, scan_run_id, single_port, confirmed_protocol=confirmed_protocol)
    return services


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


def run(engagement_id: str, discovered: list[dict], scan_run_id: str | None = None) -> list[dict]:
    """discovered: Ergebnis von discovery.run() - [{"value": ..., "asset_id": ...}]."""
    # DNS-Materialisierung (auditiert): liefert Namen->IP fuer Tools, die DNS
    # lokal aufloesen (testssl) und speist zugleich die Egress-Proxy-IP-
    # Freigabe (resolved_host).
    ip_by_host: dict[str, str] = {}
    try:
        ip_by_host = _materialize(engagement_id, scan_run_id)
    except Exception as exc:  # noqa: BLE001 - Materialisierung ist best effort
        logger.warning("DNS-Materialisierung fehlgeschlagen: %s", exc)

    ctx = _RunContext()
    all_services: list[dict] = []
    for asset in discovered:
        aid, host = asset["asset_id"], asset["value"]
        # REQ-FIDELITY-003/REQ-PORTSCOPE-004: bei einem einzelnen, autorisierten
        # Nicht-Standard-Port (z. B. 4280) zielen httpx/nikto/wafw00f/testssl/
        # nuclei auf DIESEN Port statt implizit auf 443 - sonst wird der
        # autorisierte Dienst nie getestet. Per-Host aufgeloest (nicht einmal
        # vorab fuer das ganze Engagement), da verschiedene Ziele im selben
        # Auftrag unterschiedliche Portbereiche haben koennen.
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
                logger.warning("DNS-Neumaterialisierung fuer %s fehlgeschlagen: %s", host, exc)
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

        for port in web_ports:
            # None => https default (443); an explicit port => https://host:port.
            probe_port = None if port == 443 else port
            all_services.extend(_web_suite(ctx, engagement_id, aid, host, ip, scan_run_id, probe_port))
    return all_services
