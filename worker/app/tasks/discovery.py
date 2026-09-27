"""Phase 1 - Discovery (Spezifikation Kap. 3.1 / Architektur Kap. 4.1).

Ausschliesslich passiv: Certificate-Transparency-Logs. Rechtlich unkritisch,
da oeffentliche Quelle - erfordert keine Gateway-Freigabe (kein aktiver
Tool-Call gegen ein Kundensystem). Aktive Discovery-Schritte muessten wie
jeder andere aktive Call durch client.authorize() laufen.

Lab-Sonderfall: interne Docker-Hostnamen (z. B. 'metasploitable2') haben
keinen Certificate-Transparency-Eintrag - crt.sh liefert dafuer nichts.
Ein Scope-Wert ohne Punkt kann kein echter DNS-Name sein, daher wird er
direkt als discovered_asset registriert statt ueber crt.sh gesucht
(ASM_Lab_Umgebung.docx Kap. 4: "das Lab ist kein Sonderfall, sondern ein
regulaeres engagement" - dieselbe Pipeline, nur eine andere Aufloesungsquelle).
"""

import fnmatch
import ipaddress
import logging
import time
import uuid

import httpx

from app import dns_intel, tool_execution
from app.control_plane_client import client
from app.lab_hosts import is_lab_host
from app.raw_egress_client import raw_egress_gateway
from app.raw_nmap import execute_host_discovery_sweep

logger = logging.getLogger(__name__)

CRT_SH_URL = "https://crt.sh/"


CRT_SH_ATTEMPTS = 3
# REQ-SCANQUAL-001: additional free, key-less passive OSINT sources. Passive =
# they query third-party data aggregators, never the target, so they belong on
# the worker's OSINT egress path (like crt.sh) and keep the "worker runs no
# offensive tool binaries" boundary intact. Source choice verified live:
# certspotter (CT issuances, JSON) and hackertarget (CSV) both answer without an
# API key; each is rate-limited, so both are strictly best-effort.
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"
PASSIVE_SOURCE_TIMEOUT = 20.0


def _denied(value: str, deny_named: list[dict]) -> bool:
    """Deny-Vorrang (REQ-ASSETREVIEW-007): ein Name, der zu einer expliziten
    deny-domain/-wildcard-Regel passt, ist NIE in-scope, selbst wenn er
    zusaetzlich eine allow-Regel trifft. Spiegelt authorize.py's
    _matches_asset_value (dort fuer aktive Calls, hier fuer die Discovery-
    Klassifikation - dieselbe Semantik, getrennte Prozesse)."""
    for a in deny_named:
        if a["asset_type"] == "domain":
            d = a["value"].lower().lstrip("*.").rstrip(".")
            if value == d or value.endswith("." + d):
                return True
        elif a["asset_type"] == "wildcard":
            if fnmatch.fnmatch(value, a["value"].lower()):
                return True
    return False


def _closest_parent_value(value: str, present: dict[str, str]) -> str | None:
    """REQ-GRAPH-006: the closest ancestor name already registered as a
    discovered_asset, or None. Walks progressively shorter suffixes (dropping the
    leftmost label) and returns the first that exists - e.g. for
    `api.v2.example.com` it prefers `v2.example.com` over `example.com` when both
    were discovered. Never returns the bare TLD."""
    parts = value.split(".")
    for i in range(1, len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate in present:
            return candidate
    return None


def _query_crtsh(domain: str) -> set[str]:
    # crt.sh ist notorisch unzuverlaessig (intermittierende 404/502, langsame
    # Antworten). Ein einzelner Fehlschlag darf die Discovery nicht leer
    # ausgehen lassen - daher mehrere Versuche mit kurzem Backoff.
    rows = None
    for attempt in range(1, CRT_SH_ATTEMPTS + 1):
        try:
            resp = httpx.get(CRT_SH_URL, params={"q": f"%.{domain}", "output": "json"}, timeout=60.0)
            resp.raise_for_status()
            rows = resp.json()
            break
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("crt.sh Versuch %d/%d fuer %s fehlgeschlagen: %s",
                           attempt, CRT_SH_ATTEMPTS, domain, exc)
            if attempt < CRT_SH_ATTEMPTS:
                time.sleep(3 * attempt)
    if rows is None:
        return set()

    subdomains = set()
    for row in rows:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith(domain):
                subdomains.add(name)
    return subdomains


def _scope_name(raw: str, domain: str) -> str | None:
    name = str(raw).strip().lstrip("*.").lower().rstrip(".")
    return name if name and name.endswith(domain) else None


def _query_certspotter(domain: str) -> set[str]:
    """Cert Spotter CT issuances - free, no API key, JSON. Best effort."""
    try:
        resp = httpx.get(CERTSPOTTER_URL.format(domain=domain),
                         timeout=PASSIVE_SOURCE_TIMEOUT, follow_redirects=True)
        resp.raise_for_status()
        records = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("certspotter fuer %s fehlgeschlagen: %s", domain, exc)
        return set()
    out: set[str] = set()
    for rec in records if isinstance(records, list) else []:
        for dns_name in (rec.get("dns_names") or []) if isinstance(rec, dict) else []:
            name = _scope_name(dns_name, domain)
            if name:
                out.add(name)
    return out


def _query_hackertarget(domain: str) -> set[str]:
    """HackerTarget hostsearch - free, no API key, CSV 'host,ip' lines. Best effort.
    Rate-limit/error responses are plain text without a comma-host and yield nothing."""
    try:
        resp = httpx.get(HACKERTARGET_URL.format(domain=domain),
                         timeout=PASSIVE_SOURCE_TIMEOUT, follow_redirects=True)
        resp.raise_for_status()
        body = resp.text
    except httpx.HTTPError as exc:
        logger.warning("hackertarget fuer %s fehlgeschlagen: %s", domain, exc)
        return set()
    if "API count exceeded" in body or "error" in body.lower():
        return set()
    out: set[str] = set()
    for line in body.splitlines():
        host = line.split(",", 1)[0]
        name = _scope_name(host, domain)
        if name:
            out.add(name)
    return out


# All passive sources. Each is independently fault-isolated so one failing
# source (crt.sh is notoriously flaky) never fails discovery or drops the others.
_PASSIVE_SOURCES = (_query_crtsh, _query_certspotter, _query_hackertarget)


def _passive_subdomains(domain: str) -> set[str]:
    """Aggregate subdomains for a root from every passive OSINT source
    (REQ-SCANQUAL-001), best-effort and de-duplicated."""
    found: set[str] = set()
    for source in _PASSIVE_SOURCES:
        try:
            found |= source(domain)
        except Exception as exc:  # noqa: BLE001 - a source must never break discovery
            logger.warning("passive source %s fuer %s fehlgeschlagen: %s", getattr(source, "__name__", source), domain, exc)
    return found


def _denied_ip(value: str, deny_ip_cidr: list[dict]) -> bool:
    """REQ-CIDRDISC-001 (mirrors authorize.py's ip/cidr deny-precedence, same
    semantics as `_denied` above but for address containment): an explicit
    deny rule covering part of a swept range still wins for any live host
    discovered inside it, even though sweep AUTHORIZATION only blocks a deny
    that covers the whole requested range (REQ-CIDRDISC-005's own reasoning -
    per-host filtering handles the partial-overlap case)."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return True
    for a in deny_ip_cidr:
        try:
            if addr in ipaddress.ip_network(a["value"], strict=False):
                return True
        except ValueError:
            continue
    return False


def _sweepable_sub_ranges(cidr_value: str, deny_ip_cidr: list[dict]) -> list[str]:
    """GitHub issue #34: a deny exception (e.g. from asset review deselecting
    one false-positive host) covering only PART of an allowed CIDR must not
    block sweeping the rest of the range on every later run - the previous
    behavior, since a sweep lease was only ever authorized for the exact
    original CIDR, and _network_is_allowed_by_current_policy (control-plane)
    correctly rejects ANY overlap with a deny exception for that request.

    Decomposes into the maximal sub-networks of `cidr_value` that avoid every
    current deny exception entirely, so each can be leased/swept on its own.
    This is not merely an authorization-check change: the raw-egress-gateway
    applies its nftables allowlist to EXACTLY a lease's own resolved_target
    (raw-egress-gateway/app/gateway.py's Policy.apply) - sweeping the reduced
    sub-networks means the denied address's space is never granted firewall
    access in the first place, not filtered client-side after the fact.

    No overlapping exception -> a single-element list containing the
    original CIDR unchanged (the common case costs nothing extra)."""
    try:
        network = ipaddress.ip_network(cidr_value, strict=False)
    except ValueError:
        return []
    exceptions = []
    for d in deny_ip_cidr:
        try:
            exceptions.append(ipaddress.ip_network(d["value"], strict=False))
        except ValueError:
            continue

    fragments = [network]
    for exc in exceptions:
        if exc.version != network.version:
            continue
        next_fragments = []
        for frag in fragments:
            if not frag.overlaps(exc):
                next_fragments.append(frag)
            elif frag.subnet_of(exc) or frag == exc:
                pass  # the whole fragment is denied - drop it
            elif exc.subnet_of(frag):
                next_fragments.extend(frag.address_exclude(exc))
            # else: an overlap that is neither containment direction can't
            # happen for two well-formed networks - fail closed by dropping
            # the fragment rather than risk sweeping into denied space.
        fragments = next_fragments

    return [str(f) for f in fragments]


def _sweep_cidr(engagement_id: str, scan_run_id: str, cidr: str) -> list[str]:
    """REQ-CIDRDISC-001/002: one authorized, audited liveness-only sweep of a
    whole `cidr` scope asset. Best effort like every other network step in
    this module - a lease denial or dispatch failure yields no hosts (visibly
    recorded) rather than aborting discovery."""
    lease = client.acquire_raw_egress_lease(
        uuid.UUID(engagement_id), scan_run_id=scan_run_id,
        authorized_target=cidr, resolved_target=cidr, phase="fingerprint",
        port_profile="host_discovery",
    )
    if not lease.get("allowed") or not lease.get("lease_token"):
        tool_execution.record(
            engagement_id, scan_run_id=scan_run_id, tool="nmap", phase="discovery",
            authorized_target=cidr, resolved_target=cidr, port_range="host_discovery",
            result=tool_execution.failed_result(str(lease.get("reason") or "raw_egress_lease_denied")),
        )
        return []

    reservation_token: str | None = None
    try:
        reservation = raw_egress_gateway.acquire_reservation(
            scan_run_id, cancel_requested=lambda: client.is_cancel_requested(uuid.UUID(scan_run_id)),
        )
        reservation_token = str(reservation["reservation_token"])
        outcome = execute_host_discovery_sweep(
            cidr, str(lease["lease_token"]), reservation_token=reservation_token,
            max_rate=int(lease.get("max_rate") or 100), scan_run_id=scan_run_id,
        )
    except Exception as exc:  # noqa: BLE001
        tool_execution.record(
            engagement_id, scan_run_id=scan_run_id, tool="nmap", phase="discovery",
            authorized_target=cidr, resolved_target=cidr, port_range="host_discovery",
            result=tool_execution.failed_result("raw_egress_queue_or_dispatch_failed", exc),
        )
        return []
    finally:
        if reservation_token is not None:
            try:
                raw_egress_gateway.release_reservation(scan_run_id, reservation_token)
            except Exception:  # noqa: BLE001 - best effort, mirrors fingerprint.py
                pass

    tool_execution.record(
        engagement_id, scan_run_id=scan_run_id, tool="nmap", phase="discovery",
        authorized_target=cidr, resolved_target=cidr, port_range="host_discovery",
        result=outcome.result, discovered_services=len(outcome.live_hosts),
    )
    return outcome.live_hosts


def _active_ip_discovery(engagement_id: str, scope_assets: list[dict], scan_run_id: str | None) -> list[dict]:
    """REQ-CIDRDISC-001/003: `ip`/`cidr` scope assets get zero automated
    targets otherwise - a single `ip` asset is already a concrete target (no
    sweep needed, registered directly like a domain's "scope-direct" entry); a
    `cidr` asset needs a liveness sweep first to find out which addresses
    inside it are even worth registering at all."""
    allow_ip = [a for a in scope_assets if a["rule"] == "allow" and a["asset_type"] == "ip"]
    allow_cidr = [
        a for a in scope_assets
        if a["rule"] == "allow" and a["asset_type"] == "cidr" and a.get("active_allowed")
    ]
    deny_ip_cidr = [a for a in scope_assets if a["rule"] == "deny" and a["asset_type"] in ("ip", "cidr")]

    results: list[dict] = []
    seen: set[str] = set()
    for a in allow_ip:
        value = a["value"]
        resp = client.add_discovered_asset(
            engagement_id, asset_type="ip", value=value,
            discovered_via="scope-direct", in_scope=not _denied_ip(value, deny_ip_cidr),
        )
        results.append({"value": value, "asset_id": resp["id"], "asset_type": "ip"})
        seen.add(value)

    # REQ-CIDRDISC-003: resilience against a single empty/failed sweep, same
    # rationale as the domain path's own "known in-scope assets" step (3) -
    # a previously live-discovered host stays a target even if this run's
    # raw-egress lease is transiently unavailable.
    try:
        for a in client.list_discovered_assets(engagement_id, in_scope=True):
            value = a["value"]
            if value in seen:
                continue
            try:
                ipaddress.ip_address(value)
            except ValueError:
                continue
            results.append({"value": value, "asset_id": a["id"], "asset_type": "ip"})
            seen.add(value)
    except Exception as exc:  # noqa: BLE001 - Vorbestand ist optional
        logger.warning("Vorbestand in-scope-IP-Assets nicht abrufbar: %s", exc)

    if scan_run_id is None:
        return results  # REQ-CIDRDISC-001: a sweep is an active, run-bound operation
    for a in allow_cidr:
        # GitHub issue #34: sweep each deny-avoiding sub-range separately,
        # rather than the whole scope asset's CIDR in one request - a single
        # denied host inside it must not block rediscovery of the rest.
        for sub_cidr in _sweepable_sub_ranges(a["value"], deny_ip_cidr):
            for live_ip in _sweep_cidr(engagement_id, scan_run_id, sub_cidr):
                if live_ip in seen or _denied_ip(live_ip, deny_ip_cidr):
                    continue
                resp = client.add_discovered_asset(
                    engagement_id, asset_type="ip", value=live_ip,
                    discovered_via="cidr-sweep", in_scope=True,
                )
                results.append({"value": live_ip, "asset_id": resp["id"], "asset_type": "ip"})
                seen.add(live_ip)
    return results


def run(engagement_id: str, scan_run_id: str | None = None) -> list[dict]:
    """Enumeriert Assets fuer alle Root-Werte im Scope (allow-Regeln) und
    schreibt sie als discovered_asset (Architektur Kap. 2.4). Liefert
    [{"value": ..., "asset_id": ..., "asset_type": ...}] fuer die
    nachfolgende fingerprint-Phase."""
    scope_assets = client.list_scope_assets(engagement_id)
    allow_named = [
        a for a in scope_assets
        if a["rule"] == "allow" and a["asset_type"] in ("domain", "wildcard")
    ]
    deny_named = [
        a for a in scope_assets
        if a["rule"] == "deny" and a["asset_type"] in ("domain", "wildcard")
    ]
    # .lower(): DNS names are case-insensitive, and every other value in this
    # function (targets keys, deny-matching, crt.sh/passive-source results) is
    # already lowercased - an un-lowercased root here silently broke both the
    # in_scope check below and passive-source subdomain matching (name.endswith
    # comparisons) for any scope value entered with uppercase letters. Found
    # live: a scope value "Pentest-ground.com" made in_scope compute false for
    # the already-lowercased discovered "pentest-ground.com", so the agent
    # phase saw zero in-scope assets and no-opped even though the tool-based
    # scan itself ran and recorded findings normally.
    root_values = {a["value"].lstrip("*.").lower() for a in allow_named}
    lab_hosts = {v for v in root_values if is_lab_host(v)}
    real_domains = root_values - lab_hosts

    # targets: value -> discovered_via. Reihenfolge der Quellen sichert
    # Robustheit gegen den Ausfall EINER Quelle (crt.sh ist notorisch flaky):
    targets: dict[str, str] = {}

    # 1. Lab-Hosts (Docker-Namen ohne Punkt) - direkt.
    for host in lab_hosts:
        targets[host] = "lab-direct"

    # 2. KONKRETE domain-allow-Assets immer aufnehmen (z. B. example.org) -
    #    unabhaengig von crt.sh. Ohne das wuerde bei crt.sh-Ausfall nicht mal
    #    das freigegebene Apex-Ziel gescannt.
    for a in allow_named:
        if a["asset_type"] == "domain":
            targets.setdefault(a["value"].lower(), "scope-direct")

    # 3. Bereits bekannte in-scope-Assets aus frueheren Laeufen (persistiert) -
    #    macht die fingerprint-Phase resilient gegen einen einzelnen leeren
    #    Discovery-Lauf.
    try:
        for a in client.list_discovered_assets(engagement_id, in_scope=True):
            value = a["value"].lower()
            # REQ-CIDRDISC-003: an ip-typed value is handled by
            # _active_ip_discovery below (its own known-asset resilience,
            # its own ip/cidr deny-precedence) - never by the domain path,
            # which would mislabel it asset_type="domain" on re-add.
            try:
                ipaddress.ip_address(value)
                continue
            except ValueError:
                pass
            targets.setdefault(value, "known")
    except Exception as exc:  # noqa: BLE001 - Vorbestand ist optional
        logger.warning("Vorbestand in-scope-Assets nicht abrufbar: %s", exc)

    # 4. Passive OSINT als Bonus-Quellen (crt.sh + OTX + Anubis, REQ-SCANQUAL-001,
    #    je best effort und fault-isoliert).
    for domain in real_domains:
        for value in _passive_subdomains(domain):
            targets.setdefault(value, "passive-osint")

    results: list[dict] = []
    # REQ-GRAPH-006: create shorter names before longer ones (by label count) so
    # a subdomain's parent domain already has a discovered_asset id when we wire
    # its parent_id backbone. This is structural metadata only - it changes no
    # authorization outcome (the Scope Gateway never reads parent_id).
    asset_id_by_value: dict[str, str] = {}
    for value in sorted(targets, key=lambda v: (v.count("."), v)):
        in_scope = (
            value in lab_hosts or any(
                value == d or value.endswith("." + d) for d in real_domains
            )
        ) and not _denied(value, deny_named)
        parent_value = _closest_parent_value(value, asset_id_by_value)
        resp = client.add_discovered_asset(
            engagement_id, asset_type="domain", value=value,
            discovered_via=targets[value], in_scope=in_scope,
            parent_id=asset_id_by_value.get(parent_value) if parent_value else None,
        )
        asset_id_by_value[value] = resp["id"]
        results.append({"value": value, "asset_id": resp["id"], "in_scope": in_scope, "asset_type": "domain"})

    _enrich_dns(engagement_id, results)

    # REQ-CIDRDISC-001/003: ip/cidr scope assets are a separate, active-call-
    # bound path (a sweep needs an authorized, run-bound raw-egress lease -
    # nothing above this line makes any active call at all). Merged into the
    # same returned candidate list the fingerprint phase and the asset-review
    # gate already consume.
    results.extend(_active_ip_discovery(engagement_id, scope_assets, scan_run_id))

    return [{"value": r["value"], "asset_id": r["asset_id"], "asset_type": r.get("asset_type", "domain")} for r in results]


def _enrich_dns(engagement_id: str, assets: list[dict], resolver=None) -> None:
    """Passive DNS-Anreicherung (REQ-DNS-001..003): CNAME-Kette + Provider je
    in-scope FQDN als Metadatum speichern und Dangling-DNS als inferred
    Takeover-Finding melden.

    WICHTIG (Scope-Invariante): das CNAME-Ziel wird NUR als Metadatum
    gespeichert - es wird hier bewusst NIE per add_discovered_asset angelegt und
    nie in den aktiven Scan aufgenommen. Nur der urspruengliche FQDN bleibt das
    Asset. Lab-Hosts ohne Punkt haben keinen oeffentlichen DNS-Eintrag und werden
    uebersprungen."""
    if resolver is None:
        resolver = dns_intel.SystemResolver()

    for asset in assets:
        value = asset["value"]
        if not asset.get("in_scope") or "." not in value:
            continue
        try:
            intel = dns_intel.resolve_chain(value, resolver)
        except Exception as exc:  # noqa: BLE001 - DNS darf Discovery nie abbrechen
            logger.warning("DNS-Anreicherung fuer %s fehlgeschlagen: %s", value, exc)
            continue

        try:
            client.add_dns_record(engagement_id, **intel.as_record(asset_id=asset["asset_id"]))
        except Exception as exc:  # noqa: BLE001
            logger.warning("dns_record fuer %s nicht speicherbar: %s", value, exc)

        if intel.takeover_suspected:
            try:
                client.add_finding(engagement_id, **dns_intel.takeover_finding(intel, asset["asset_id"]))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Takeover-Finding fuer %s nicht speicherbar: %s", value, exc)
