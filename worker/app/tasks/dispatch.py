"""Gemeinsame Tool-Ausfuehrung: freigegebener Call -> tool-runner -> Parser ->
Findings/Services -> kompakte Text-Beobachtung.

Genutzt vom Vector Agent (agent.py), damit ein LLM-Vorschlag exakt denselben,
gehaerteten Ausfuehrungspfad nimmt wie die deterministischen Phasen: die
konservative Invocation lebt in tool_runner_client (Body-Builder), die Parser
sind dieselben. Der Agent waehlt nur WELCHES Tool auf WELCHES (in-scope) Ziel -
er reicht KEINE Freiform-Flags durch (geschlossener Args-Round-Trip). Die
zurueckgegebene Beobachtung ist bewusst knapp (fuer das LLM-Kontextbudget) und
enthaelt nur, was der Agent zum Weiterschliessen braucht.

Wichtig: dispatch() setzt voraus, dass der Call bereits vom Scope Gateway
freigegeben wurde (client.authorize -> allowed). Es ist KEINE zweite
Autorisierung - nur Ausfuehrung + Persistenz.
"""

from __future__ import annotations

import logging
import time
import uuid as _uuid

from app import command_redaction
from app.control_plane_client import client
from app.ffuf_parse import is_catch_all, parse_ffuf_json
from app.httpx_parse import parse_httpx_json
from app.known_vulns import lookup as lookup_known_vuln
from app.nikto_parse import parse_nikto_missing_headers
from app.nmap_parse import parse_nmap_grepable
from app.nuclei_parse import parse_nuclei_jsonl
from app.target_envelope import httpx_target, protocol_from_httpx_url, target_url
from app.testssl_parse import parse_testssl_json
from app.planner import resolve_products
from app.tool_runner_client import (
    CHECK_BUDGET_S,
    FFUF_WORDLIST_ENTRIES,
    ffuf_entries_tried_at_most,
    nuclei_select_budget_s,
    tool_runner,
)
from app import tool_execution
from app.wafw00f_parse import parse_wafw00f

logger = logging.getLogger(__name__)

# REQ-PIPE-018: an agent-dispatched ffuf call keeps the fixed interactive cap
# whatever wordlist it names; a wordlist-sized budget is only the plan's.
AGENT_FFUF_BUDGET_S = CHECK_BUDGET_S["ffuf"]

# Tool -> Scope-Gateway-Kategorie (muss zur Registry passen). Der Agent nutzt
# genau diese Menge; alles andere ist fuer ihn nicht erreichbar.
TOOL_CATEGORY = {
    "httpx": "fingerprint",
    "nmap": "fingerprint",
    "wafw00f": "fingerprint",
    "testssl": "fingerprint",
    "nikto": "vuln",
    "nuclei": "vuln",
    # Agent-gesteuerter roher HTTP-Lesezugriff (Fundament autonomes Pentesting).
    "http_request": "vuln",
    # Kuratierte Content-Discovery (ffuf + SecLists).
    "ffuf": "vuln",
    # REQ-AGENT-025: curated, non-agent-composed raw-protocol probes.
    "redis-probe": "fingerprint",
    "activemq-banner": "fingerprint",
    # REQ-AGENT-027: curated, non-agent-composed, but ACTIVE (sends a real
    # deserialization-triggering packet) - "vuln" like http_request/nikto/
    # nuclei, not "fingerprint" like the passive probes above.
    "activemq-openwire-probe": "vuln",
}


class Observation:
    """Ergebnis eines Dispatch-Laufs, knapp fuer das LLM aufbereitet."""

    def __init__(self, tool: str, target: str, summary: str, services: int = 0, findings: int = 0):
        self.tool = tool
        self.target = target
        self.summary = summary
        self.services = services
        self.findings = findings

    def as_text(self) -> str:
        return f"[{self.tool} {self.target}] {self.summary}"


class _EgressBlocked(Exception):
    """Der Egress-Proxy hat die Anfrage geblockt - das Ziel wurde NIE erreicht.
    Muss als Fehler-Beobachtung durchgereicht werden, nicht als 'keine Treffer'
    (REQ-EGRESS-002)."""

    def __init__(self, reason: str):
        self.reason = reason


# Distinktive Denial-Gruende UNSERES Egress-Proxys (unwahrscheinlich in einer
# echten Ziel-Antwort - deshalb sicher zu matchen). Ein 407 vom ZIEL selbst
# (nach erfolgreichem CONNECT) enthaelt diese Tokens nicht und bleibt eine
# normale Beobachtung (wichtig fuer http_request).
_PROXY_BLOCK_TOKENS = (
    "missing_engagement_id_header", "no_engagement_for_host", "ambiguous_host",
    "out_of_scope_deny", "not_in_scope", "engagement_not_active", "outside_window",
    "bounty_program_missing", "invalid_engagement_id", "engagement_not_active",
    "audit_unavailable", "proxy_capacity_exhausted",
    # REQ-FIDELITY-007: der Egress-Proxy erzwingt seit REQ-FIDELITY-005 auch das
    # Engagement-Portfenster - ohne diesen Token wuerde ein Agent-Vorschlag, der
    # (noch) den falschen Port trifft, als stille "keine Treffer"-Beobachtung statt
    # als klarer Infrastruktur-Block erscheinen und blind wiederholt werden.
    "out_of_scope_port",
)
_PROXY_CURL_ERRORS = (
    "received http code 407 from proxy", "received http code 409 from proxy",
    "received http code 403 from proxy", "connect tunnel failed", "connect_failed",
)


def _egress_block_reason(result: dict | None) -> str | None:
    if not result:
        return None
    blob = ((result.get("stdout") or "") + " " + (result.get("stderr") or "")).lower()
    for t in _PROXY_BLOCK_TOKENS:
        if t in blob:
            return t
    for t in _PROXY_CURL_ERRORS:
        if t in blob:
            return t
    return None


def _run(
    engagement_id: str, tool: str, target: str, args: dict, scan_run_id: str | None = None,
    *, ip: str | None = None, port_range: str | None = None, budget_s: int | None = None,
) -> dict:
    """REQ-SCAN-014: every agent-dispatched call is recorded through the same
    tool_execution.record() telemetry the deterministic fingerprint phase
    already uses (success or failure) - so a tool-runner outage during the
    agent phase feeds the same coverage-degraded signal instead of silently
    reading as 'no findings'. Found live 2026-08-09: an unreachable
    tool-runner made httpx/testssl/nuclei/nikto agent calls return an empty
    Observation indistinguishable from a genuinely clean target, and the
    agent's own summary reported the target clean having never actually
    tested it - the exact failure mode REQ-SCAN-014 exists to catch, just not
    wired into this dispatch path."""
    try:
        extra = {} if budget_s is None else {"budget_s": budget_s}
        result = tool_runner.run(tool, target, args, scan_run_id=scan_run_id, engagement_id=engagement_id, **extra)
    except Exception as exc:  # noqa: BLE001 - Runner-Ausfall darf den Agent nicht abreissen
        logger.warning("dispatch %s on %s failed: %s", tool, target, exc)
        result = tool_execution.failed_result("runner_dispatch_failed", exc)
        tool_execution.record(
            engagement_id, scan_run_id=scan_run_id, tool=tool, phase="agent",
            authorized_target=target, resolved_target=ip, port_range=port_range,
            result=result, discovered_services=0,
        )
        return result
    # REQ-AUDIT-006/007: http_request's stdout IS the raw target response
    # (status + headers + body) - the one dispatched call whose full response
    # is itself the evidence an operator needs to see, not a summary. Redacted
    # here, once, with the SAME structured-value-drop rule already proven for
    # the request side (REQ-AUDIT-004), and reused for every downstream
    # consumer (the LLM's own context, the audit record below, and the
    # agent's observation event) so none of them can drift into an
    # unredacted copy the way agent.py's observation event did before this.
    response = None
    if tool == "http_request" and result.get("success"):
        response = command_redaction.redact_http_response(result.get("stdout", ""))
        result["response"] = response
    tool_execution.record(
        engagement_id, scan_run_id=scan_run_id, tool=tool, phase="agent",
        authorized_target=target, resolved_target=ip, port_range=port_range,
        result=result, discovered_services=0, response=response,
    )
    reason = _egress_block_reason(result)
    if reason:
        raise _EgressBlocked(reason)
    return result


def _dispatch_httpx(
    engagement_id: str, asset_id: str, target: str, ip: str | None, scan_run_id: str | None,
    single_port: int | None = None,
    confirmed_protocol: str | None = None,
) -> Observation:
    # REQ-FIDELITY-003/007/010: explicit http://, which httpx self-corrects to
    # https when needed (see target_envelope.httpx_target's docstring for why
    # this is NOT schemeless - that was tried first and found live to silently
    # skip the https probe entirely on a non-standard port).
    url = httpx_target(target, single_port)
    result = _run(engagement_id, "httpx", url, {}, scan_run_id, ip=ip, port_range=str(single_port or 443))
    rows = parse_httpx_json(result.get("stdout", "")) if result.get("success") else []
    if not rows:
        # REQ-AGENT-015: same tracking as the deterministic fingerprint phase -
        # so a NEXT run (or the same run's later iterations) knows this host
        # was already checked, not just that no data exists for it yet.
        client.record_http_probe(engagement_id, asset_id, live=False)
        return Observation("httpx", target, "no live HTTP service / no response")
    r = rows[0]
    client.add_service(
        engagement_id, asset_id=asset_id, port=r.get("port") or single_port or 443,
        protocol=protocol_from_httpx_url(r.get("url", "")),
        product=r.get("webserver") or "http",
        tech_stack={"tech": r.get("tech", []), "title": r.get("title", ""), "status": r.get("status_code")},
    )
    client.record_http_probe(engagement_id, asset_id, live=True)
    tech = ", ".join(r.get("tech", []) or []) or "no technology detected"
    return Observation(
        "httpx", target,
        f"live, status={r.get('status_code')}, server={r.get('webserver') or '?'}, tech=[{tech}]",
        services=1,
    )


def _dispatch_nmap(
    engagement_id: str, asset_id: str, target: str, ip: str | None, scan_run_id: str | None,
    single_port: int | None = None,
    confirmed_protocol: str | None = None,
) -> Observation:
    # Full TCP Nmap requires a control-plane-signed lease and is deliberately
    # owned by fingerprint._nmap_scan. Generic/agent dispatch cannot create or
    # reuse raw-network permission.
    result = tool_execution.failed_result("deterministic_full_scan_only")
    tool_execution.record(
        engagement_id, scan_run_id=scan_run_id, tool="nmap", phase="agent",
        authorized_target=target, resolved_target=ip, port_range="1-65535",
        result=result, discovered_services=0,
    )
    return Observation(
        "nmap", target,
        "SCAN NOT EXECUTED (deterministic_full_scan_only): use the fingerprint-phase result",
    )

def _dispatch_nikto(
    engagement_id: str, asset_id: str, target: str, ip: str | None, scan_run_id: str | None,
    single_port: int | None = None,
    confirmed_protocol: str | None = None,
) -> Observation:
    url = target_url(target, single_port, confirmed_protocol)
    port = single_port or 443
    result = _run(engagement_id, "nikto", url, {"additional_args": "-Tuning b -maxtime 40s"}, scan_run_id,
                  ip=ip, port_range=str(port))
    stdout = result.get("stdout", "") if result.get("success") else ""
    # REQ-FIDELITY-009: never assert a hardcoded "https" here. add_service has
    # no upsert - each call INSERTS - so a wrong literal permanently adds a
    # second, contradictory service row for a port httpx already identified
    # correctly, and every such row is rendered into the agent's own evidence
    # context (agent.py::_render_evidence).
    svc_resp = client.add_service(engagement_id, asset_id=asset_id, port=port,
                                  protocol=confirmed_protocol or "https", product="http")
    missing = parse_nikto_missing_headers(stdout)
    if missing:
        client.add_finding(
            engagement_id, asset_id=asset_id, service_id=svc_resp["id"], category="misconfig",
            title=f"Missing security headers: {', '.join(missing)}", confidence="validated",
            evidence={"missing_headers": missing, "port": port, "tool": "nikto"},
            exposure_factor=1.0, business_factor=0.4,
        )
        return Observation("nikto", target, f"missing headers: {', '.join(missing)}", findings=1)
    return Observation("nikto", target, "no missing security headers reported")


def _dispatch_wafw00f(
    engagement_id: str, asset_id: str, target: str, ip: str | None, scan_run_id: str | None,
    single_port: int | None = None,
    confirmed_protocol: str | None = None,
) -> Observation:
    url = target_url(target, single_port, confirmed_protocol)
    result = _run(engagement_id, "wafw00f", url, {}, scan_run_id, ip=ip, port_range=str(single_port or 443))
    waf = parse_wafw00f(result.get("stdout", "")) if result.get("success") else None
    if waf:
        client.add_finding(
            engagement_id, asset_id=asset_id, category="exposure",
            title=f"WAF detected: {waf}", confidence="validated",
            evidence={"waf": waf, "tool": "wafw00f", "target": url},
            exposure_factor=0.2, business_factor=0.2,
        )
        return Observation("wafw00f", target, f"WAF: {waf}", findings=1)
    return Observation("wafw00f", target, "no WAF detected")


def _dispatch_testssl(
    engagement_id: str, asset_id: str, target: str, ip: str | None, scan_run_id: str | None,
    single_port: int | None = None,
    confirmed_protocol: str | None = None,
) -> Observation:
    # REQ-FIDELITY-009: the deterministic fingerprint path already refuses to
    # run testssl against a port httpx confirmed is plain HTTP
    # (fingerprint.py::_tls_scan, "not_a_tls_service"); the agent's own ad-hoc
    # call had no such gate and produced technically-true but meaningless
    # "TLS 1.2/1.3 not offered" findings on non-TLS ports - which then also
    # polluted the benchmark's negative controls.
    if str(confirmed_protocol or "").lower() == "http":
        return Observation("testssl", target,
                           "skipped: httpx confirmed plain HTTP (no TLS) on this port")
    if ip is None:
        return Observation("testssl", target, "skipped: no materialized IP")
    url = target_url(target, single_port, confirmed_protocol)
    result = _run(engagement_id, "testssl", url, {"ip": ip}, scan_run_id, ip=ip, port_range=str(single_port or 443))
    issues = parse_testssl_json(result.get("stdout", "")) if result.get("success") else []
    for f in issues:
        client.add_finding(
            engagement_id, asset_id=asset_id, category="misconfig",
            title=f["title"], confidence="validated", severity_override=f["severity"],
            evidence={"check": f["id"], "tool": "testssl"},
            exposure_factor=1.0, business_factor=0.4,
        )
    if issues:
        top = ", ".join(f"{f['severity']}:{f['title']}" for f in issues[:4])
        return Observation("testssl", target, f"TLS findings ({len(issues)}): {top}", findings=len(issues))
    return Observation("testssl", target, "no notable TLS findings")


def _surface_profile(scan_run_id: str | None, target: str, port: int) -> list[str]:
    """The technology profile the scan recorded for this host:port, or [] when
    the run has no such surface (or the plan cannot be read)."""
    if not scan_run_id:
        return []
    try:
        for surface in client.get_scan_plan(scan_run_id).get("surfaces", []):
            if str(surface.get("host", "")).lower() == target.lower() and int(surface.get("port", 0)) == port:
                return list(surface.get("profile") or [])
    except Exception as exc:  # noqa: BLE001
        logger.warning("scan plan unavailable for the agent's nuclei call: %s", exc)
    return []


def _dispatch_nuclei(
    engagement_id: str, asset_id: str, target: str, ip: str | None, scan_run_id: str | None,
    single_port: int | None = None,
    confirmed_protocol: str | None = None,
) -> Observation:
    """The agent's nuclei call (REQ-PIPE-004): the templates bound to the products
    the scan identified on this host. The generic templates already ran in this
    run's fingerprint phase, so they are not repeated; a host with nothing
    identified gets the fixed common-product list instead. Hits printed by a call
    that ran into its budget are still real."""
    url = target_url(target, single_port, confirmed_protocol)
    keys, reason = resolve_products(_surface_profile(scan_run_id, target, single_port or 443))
    selection = {"mode": "select", "group": "products", "products": keys}
    try:
        count = tool_runner.nuclei_selection_count(selection)
    except Exception as exc:  # noqa: BLE001
        logger.warning("nuclei selection unavailable for %s: %s", target, exc)
        result = tool_execution.failed_result("selection_unavailable", exc)
        tool_execution.record(
            engagement_id, scan_run_id=scan_run_id, tool="nuclei", phase="agent",
            authorized_target=target, resolved_target=ip, port_range=str(single_port or 443), result=result,
        )
        return Observation("nuclei", target, "template selection unavailable (tool runner)")
    if count == 0:
        return Observation("nuclei", target, f"no product-bound templates apply ({reason})")
    result = _run(engagement_id, "nuclei", url, selection, scan_run_id, ip=ip, port_range=str(single_port or 443),
                  budget_s=nuclei_select_budget_s(count))
    hits = parse_nuclei_jsonl(result.get("stdout", "")) if tool_execution.usable_output(result) or result.get("error_reason") == "nonzero_exit" else []
    for f in hits:
        client.add_finding(
            engagement_id, asset_id=asset_id, category=f["category"],
            title=f["title"], confidence="validated", severity_override=f["severity"],
            cve_ids=f["cve_ids"], cvss_base=f["cvss_base"],
            evidence={"template_id": f["template_id"], "matched_at": f["matched_at"], "tool": "nuclei"},
            exposure_factor=1.0, business_factor=0.5,
        )
    if hits:
        top = ", ".join(f"{f['severity']}:{f['title']}" for f in hits[:4])
        return Observation("nuclei", target, f"vulnerabilities/exposures ({len(hits)}): {top}", findings=len(hits))
    return Observation("nuclei", target, f"no template matches ({count} product-bound templates, {reason})")


def _dispatch_http_request(
    engagement_id: str, asset_id: str, target: str, ip: str | None, args: dict, scan_run_id: str | None,
    single_port: int | None = None,
    confirmed_protocol: str | None = None,
) -> Observation:
    """Fuehrt den agent-geformten HTTP-Lesezugriff aus und gibt die VOLLE Antwort
    (Status + Header + Body-Anfang) als Beobachtung zurueck - anders als die
    Scanner, die nur Zusammenfassungen liefern. Genau diese Rohantwort ist es,
    aus der das LLM Auth-Bypass/PII-Exposure klassifiziert. Findings entstehen
    NICHT hier automatisch, sondern durch das Urteil des Agenten (report_finding)."""
    method = str((args or {}).get("method", "GET")).upper()
    path = str((args or {}).get("path", "/"))
    url = target_url(target, single_port, confirmed_protocol)
    result = _run(engagement_id, "http_request", url, args or {}, scan_run_id, ip=ip, port_range=str(single_port or 443))
    # Bereits redigiert in _run() (REQ-AUDIT-007) - dieselbe Beobachtung geht
    # unveraendert an das LLM UND in den Audit-Trail, keine zweite Kopie.
    body = result.get("response") or ""
    if not body.strip():
        return Observation("http_request", target, f"{method} {path} -> no response / error")
    # Die Rohantwort ist die Beobachtung (bereits auf 16 KB gedeckelt im Runner).
    return Observation("http_request", target, f"{method} {path} ->\n{body}")


def _dispatch_ffuf(
    engagement_id: str, asset_id: str, target: str, ip: str | None, args: dict, scan_run_id: str | None,
    single_port: int | None = None,
    confirmed_protocol: str | None = None,
) -> Observation:
    """Kuratierte Content-Discovery. Gibt die Treffer (Pfad/Status/Groesse) als
    Beobachtung zurueck - die Bewertung, ob ein Treffer ein Befund ist (z. B.
    exponiertes /admin, /.git/config), macht der Agent per report_finding."""
    url = target_url(target, single_port, confirmed_protocol)
    # The agent's call keeps its interactive time cap whatever list it picks
    # (REQ-PIPE-018); a whole-list sweep is the thorough plan's check
    # (REQ-PIPE-017), which gets a budget sized to its list.
    result = _run(engagement_id, "ffuf", url, args or {}, scan_run_id, ip=ip, port_range=str(single_port or 443),
                  budget_s=AGENT_FFUF_BUDGET_S)
    # A run stopped by its time limit still holds real hits; only a failed one
    # has nothing to parse (REQ-PIPE-006/018).
    partial = result.get("error_reason") == tool_execution.BUDGET_REACHED
    hits = parse_ffuf_json(result.get("stdout", "")) if tool_execution.usable_output(result) else []
    # REQ-DISCO-001: the agent must not be told a catch-all responder is a
    # discovery either - it would reason from, and report findings on, paths
    # that do not exist. Same guard as the deterministic fingerprint path.
    if is_catch_all(hits):
        return Observation(
            "ffuf", target,
            f"content-discovery: {len(hits)} hits discarded - all with the same "
            f"response (catch-all/wildcard, e.g. an SPA fallback or a block page). "
            f"No real content discovery; treat this target as 'no hits'.",
        )
    note = _ffuf_partial_note(args or {}, result) if partial else ""
    if not hits:
        return Observation("ffuf", target, f"content-discovery: no hits{note}")
    top = "; ".join(f"{h.get('status')} /{h.get('word')} ({h.get('length')}B)" for h in hits[:25])
    more = f" (+{len(hits) - 25} more)" if len(hits) > 25 else ""
    return Observation("ffuf", target, f"content-discovery: {len(hits)} hits: {top}{more}{note}")


def _ffuf_partial_note(args: dict, result: dict) -> str:
    """What the agent must know about a sweep its time limit cut short: it is
    not a complete pass, and how little of a large list it may have tried."""
    wordlist = str(args.get("wordlist") or "common")
    entries = FFUF_WORDLIST_ENTRIES.get(wordlist)
    note = " [PARTIAL: stopped at its time limit"
    duration = result.get("duration_s")
    if entries and not args.get("extra_candidates") and isinstance(duration, (int, float)):
        tried = min(entries, ffuf_entries_tried_at_most(duration))
        note += (f"; at most the first {tried:,} of {entries:,} entries of '{wordlist}' were tried "
                 f"(about {round(100 * tried / entries)}%) - this is NOT a complete pass, and the "
                 f"thorough scan profile's deep sweep is the one that covers the whole list")
    return note + "]"


def _parse_raw_probe(result: dict | None) -> tuple[str, str]:
    """(status, printable_text) from a raw_tcp_probe result's stdout - see
    tool_runner_client._raw_tcp_probe_command for the exact status lines it
    always emits (never raises past them, even on a refused/timed-out
    connection - "no response" is itself a valid, distinct outcome here)."""
    stdout = (result or {}).get("stdout", "") or ""
    status = "connect_failed:unknown"
    for line in stdout.splitlines():
        if line.startswith("asm_probe_status="):
            status = line[len("asm_probe_status="):]
            break
    idx = stdout.find("\n", stdout.find("asm_probe_bytes_read="))
    text = stdout[idx + 1:] if idx >= 0 else ""
    return status, text.strip()


def _dispatch_redis_probe(
    engagement_id: str, asset_id: str, target: str, ip: str | None, scan_run_id: str | None,
    single_port: int | None = None,
    confirmed_protocol: str | None = None,
) -> Observation:
    """REQ-AGENT-025: read-only Redis PING - proves reachability and whether
    authentication is enforced, never more. A `+PONG` reply means Redis
    answered a command BEFORE any AUTH - a real, reportable exposure, not an
    inference. An auth-required error means the opposite: correctly
    protected, not a finding."""
    if ip is None:
        return Observation("redis-probe", target, "skipped: no materialized IP")
    from app.raw_tcp_probe import execute_probe

    outcome = execute_probe(engagement_id, scan_run_id, "redis-probe", target, ip, single_port=single_port)
    result, port = outcome.result, outcome.port
    if not result.get("success"):
        reason = result.get("error_reason") or "unknown"
        return Observation("redis-probe", target, f"not run ({reason})")
    status, text = _parse_raw_probe(result)
    if status != "ok":
        return Observation("redis-probe", target, f"no Redis reachable on port {port} ({status})")
    client.add_service(engagement_id, asset_id=asset_id, port=port, protocol="tcp", product="redis")
    if text.strip() == "+PONG":
        client.add_finding(
            engagement_id, asset_id=asset_id, category="exposure",
            title=f"Unauthenticated Redis instance reachable on port {port}",
            confidence="validated", severity_override="high",
            evidence={"tool": "redis-probe", "port": port, "response": text},
            exposure_factor=1.0, business_factor=0.5,
        )
        return Observation("redis-probe", target, f"Port {port}: PING answered WITHOUT authentication (+PONG)", findings=1)
    return Observation("redis-probe", target, f"Port {port}: Redis reachable, authentication required ({text[:80]!r})")


def _dispatch_activemq_banner(
    engagement_id: str, asset_id: str, target: str, ip: str | None, scan_run_id: str | None,
    single_port: int | None = None,
    confirmed_protocol: str | None = None,
) -> Observation:
    """REQ-AGENT-025: purely passive - sends nothing, reads whatever the
    OpenWire broker self-announces (a WireFormatInfo packet, version embedded
    as readable ASCII) on connect. Any readable greeting confirms an
    unauthenticated, network-reachable message broker - a real, reportable
    exposure on its own, independent of any specific CVE."""
    if ip is None:
        return Observation("activemq-banner", target, "skipped: no materialized IP")
    from app.raw_tcp_probe import execute_probe

    outcome = execute_probe(engagement_id, scan_run_id, "activemq-banner", target, ip, single_port=single_port)
    result, port = outcome.result, outcome.port
    if not result.get("success"):
        reason = result.get("error_reason") or "unknown"
        return Observation("activemq-banner", target, f"not run ({reason})")
    status, text = _parse_raw_probe(result)
    if status != "ok" or not text:
        return Observation("activemq-banner", target, f"no OpenWire broker reachable on port {port} ({status})")
    client.add_service(engagement_id, asset_id=asset_id, port=port, protocol="tcp", product="activemq")
    client.add_finding(
        engagement_id, asset_id=asset_id, category="exposure",
        title=f"Unauthenticated ActiveMQ OpenWire broker reachable on port {port}",
        confidence="validated", severity_override="medium",
        evidence={"tool": "activemq-banner", "port": port, "banner": text[:500]},
        exposure_factor=1.0, business_factor=0.5,
    )
    return Observation("activemq-banner", target, f"Port {port}: OpenWire greeting read: {text[:120]!r}", findings=1)


_OPENWIRE_CALLBACK_WAIT_SECONDS = 8.0
_OPENWIRE_CALLBACK_POLL_INTERVAL = 1.0


def _dispatch_activemq_openwire_probe(
    engagement_id: str, asset_id: str, target: str, ip: str | None, scan_run_id: str | None,
    single_port: int | None = None,
    confirmed_protocol: str | None = None,
) -> Observation:
    """REQ-AGENT-027: sends a curated, non-agent-composed OpenWire
    deserialization-RCE probe (worker/app/openwire_payload.py) pointed at a
    fresh, single-use callback token, then waits a bounded window to see
    whether the target itself fetched it - the only available proof for this
    vulnerability class (no in-band response to read, unlike e.g. Struts2's
    OGNL-in-header trick; see the requirement doc for why). Mandatory
    per-call operator approval happens BEFORE this function ever runs
    (control-plane/app/gateway/authorize.py's state_changing check), not
    here - this function only executes an already-approved call."""
    if ip is None:
        return Observation("activemq-openwire-probe", target, "skipped: no materialized IP")

    from app import openwire_payload
    from app.raw_tcp_probe import execute_probe

    token_info = client.create_openwire_callback_token(_uuid.UUID(engagement_id), scan_run_id=scan_run_id)
    callback_url = token_info["callback_url"]
    token = token_info["token"]
    packet = openwire_payload.build_probe_packet(callback_url)

    outcome = execute_probe(
        engagement_id, scan_run_id, "activemq-openwire-probe", target, ip, single_port=single_port,
        extra_args={"_send_bytes": packet},
    )
    result, port = outcome.result, outcome.port
    if not result.get("success"):
        reason = result.get("error_reason") or "unknown"
        return Observation("activemq-openwire-probe", target, f"not run ({reason})")
    status, _text = _parse_raw_probe(result)
    if status not in ("ok", "recv_failed"):
        # A connect failure means the packet was never even sent - genuinely
        # not a finding, mirroring REQ-AGENT-025's "absence is not a finding"
        # discipline. recv_failed/timeout on the READ is expected and fine:
        # the proof is the callback, not this connection's own response.
        return Observation("activemq-openwire-probe", target, f"connection to port {port} failed ({status})")

    triggered = False
    deadline = time.monotonic() + _OPENWIRE_CALLBACK_WAIT_SECONDS
    while time.monotonic() < deadline:
        try:
            status_resp = client.get_openwire_callback_status(_uuid.UUID(engagement_id), token)
        except Exception:  # noqa: BLE001 - a status-check hiccup must not crash the scan
            break
        if status_resp.get("triggered"):
            triggered = True
            break
        time.sleep(_OPENWIRE_CALLBACK_POLL_INTERVAL)

    if not triggered:
        # Explicitly NOT a finding: patched, egress-filtered, or simply
        # slower than the wait window are all indistinguishable from "not
        # vulnerable" from here - reporting this as a finding would be
        # exactly the fabricated-evidence failure mode this session's other
        # REQ-DISCO work exists to prevent.
        return Observation(
            "activemq-openwire-probe", target,
            f"Port {port}: packet sent, no callback observed within {_OPENWIRE_CALLBACK_WAIT_SECONDS:.0f}s - "
            "no finding (possible: patched, egress-filtered, or slower than the wait window)",
        )

    client.add_service(engagement_id, asset_id=asset_id, port=port, protocol="tcp", product="activemq")
    client.add_finding(
        engagement_id, asset_id=asset_id, category="rce",
        title="Apache ActiveMQ OpenWire Deserialization RCE (CVE-2023-46604) - confirmed via callback",
        cve_ids=["CVE-2023-46604"], cvss_base=9.8, is_kev=True,
        confidence="validated", severity_override="critical",
        evidence={
            "tool": "activemq-openwire-probe", "port": port,
            "proof": "target fetched a single-use callback URL embedded in the OpenWire packet, "
                     "confirming FileSystemXmlApplicationContext was instantiated with attacker-controlled data",
            "evidence_basis": "direct_technical_proof",
        },
        exposure_factor=1.0, business_factor=1.0,
    )
    return Observation(
        "activemq-openwire-probe", target,
        f"Port {port}: OpenWire deserialization CONFIRMED - the target fetched the callback URL (CVE-2023-46604)",
        findings=1,
    )


_DISPATCH = {
    "httpx": _dispatch_httpx,
    "nmap": _dispatch_nmap,
    "nikto": _dispatch_nikto,
    "wafw00f": _dispatch_wafw00f,
    "testssl": _dispatch_testssl,
    "nuclei": _dispatch_nuclei,
    "redis-probe": _dispatch_redis_probe,
    "activemq-banner": _dispatch_activemq_banner,
    "activemq-openwire-probe": _dispatch_activemq_openwire_probe,
}


def dispatch(engagement_id: str, asset_id: str, tool: str, target: str, ip: str | None = None,
             args: dict | None = None, scan_run_id: str | None = None,
             single_port: int | None = None, confirmed_protocol: str | None = None) -> Observation:
    """Fuehrt ein bereits gateway-freigegebenes Tool aus, persistiert Ergebnisse
    und liefert eine knappe Beobachtung. Unbekanntes Tool -> Fehlerbeobachtung
    (der Agent-Toolset ist ohnehin auf den erlaubten Werkzeugsatz beschraenkt).
    args wird von den agent-gesteuerten Primitiven genutzt (http_request:
    Methode/Pfad/Header; ffuf: Wortliste/Pfad/Kandidaten); die Scanner bauen
    ihre Invocation selbst (geschlossener Args-Round-Trip).

    single_port (REQ-FIDELITY-007): das engagement-konfigurierte TCP-Portfenster,
    wenn es auf einen einzelnen Nicht-Standard-Port eingeschraenkt ist - sonst
    wuerde jeder Agent-Vorschlag stumpf auf den impliziten 443 zielen und am
    (korrekt arbeitenden) Egress-Proxy-Portcheck (REQ-FIDELITY-005) abprallen,
    obwohl der Host in-scope ist.

    confirmed_protocol (REQ-FIDELITY-009): der von der Fingerprint-Phase per
    httpx TATSAECHLICH bestaetigte Scheme fuer diesen Host/Port. Ohne ihn
    zielt jedes dieser Tools blind auf https:// - gegen einen reinen
    HTTP-Dienst liefert das still gar nichts (live gemessen: nuclei 2 Treffer
    mit http://, 0 mit https://). None => unveraendertes https-Default."""
    try:
        if tool == "http_request":
            return _dispatch_http_request(engagement_id, asset_id, target, ip, args or {}, scan_run_id, single_port,
                                          confirmed_protocol)
        if tool == "ffuf":
            return _dispatch_ffuf(engagement_id, asset_id, target, ip, args or {}, scan_run_id, single_port,
                                  confirmed_protocol)
        fn = _DISPATCH.get(tool)
        if fn is None:
            return Observation(tool, target, "no dispatch mapping (tool not available to the agent)")
        return fn(engagement_id, asset_id, target, ip, scan_run_id, single_port, confirmed_protocol)
    except _EgressBlocked as blocked:
        # REQ-EGRESS-002: ehrlich als Block melden, nicht als 'keine Treffer'. So
        # schliesst der Agent nicht faelschlich 'sauber/WAF' und wiederholt es nicht.
        return Observation(
            tool, target,
            f"EGRESS BLOCKED ({blocked.reason}): the request never reached the target — "
            f"this is an infrastructure block, NOT a clean result. Do not treat it as evidence "
            f"and do not retry the same call.",
        )
