"""HTTP-Client zum tool-runner (Architektur Kap. 4.3: MCP Tool-Runner).

Wichtig: der worker fuehrt selbst keine Tools aus ('Tools? nein', Deployment-
Architektur Kap. 2) - er schickt nach Gateway-Freigabe lediglich einen HTTP-
Request an den ephemeren tool-runner-Container, der die eigentliche
Kommandoausfuehrung uebernimmt (eigener Prozess, eigene Capabilities/NET_RAW).

Spricht die ECHTE HexStrike-API (tool-runner/runner.Dockerfile, Endpunkte aus
dem Quellcode erschlossen - HexStrike dokumentiert seine REST-Contracts nicht
separat). Jeder Tool-Name wird auf seinen konkreten HexStrike-Endpunkt und
dessen Parameter-Namen abgebildet; das Rueckgabeformat wird auf
{"stdout", "stderr", "exit_code", "success"} normalisiert, damit Aufrufer
(z. B. nmap_parse.py) unveraendert bleiben.

Bewusste Sicherheits-Entscheidung: scan_type/additional_args werden HIER
hart auf sichere Werte gesetzt (z. B. nmap "-sV", nie HexStrikes Default
"-sCV" mit NSE-Skripten) - der Worker vertraut nicht darauf, dass HexStrikes
eigene Defaults mit unserer args_are_safe()-Policy (Kap. 3.2) uebereinstimmen.
"""

from __future__ import annotations

import json
import logging
import os
from queue import Empty, Queue
import shlex
import threading
import time
import uuid

import httpx

from app import command_redaction

logger = logging.getLogger(__name__)

TOOL_RUNNER_URL = os.environ.get("TOOL_RUNNER_URL", "http://tool-runner-lab:8888")
# REQ-HARDEN-001: shared secret proving this request comes from the worker
# (the only component authorized to drive the execution boundary), not from a
# compromised peer on the runner/egress network. Sent on every runner request;
# the runner enforces it fail-closed (tool-runner/runner_auth.py).
RUNNER_API_TOKEN = os.environ.get("RUNNER_API_TOKEN", "")

# Egress-Proxy fuer HTTP-basierte Tools (nikto/nuclei/httpx). Diese muessen
# den Proxy EXPLIZIT nutzen - HTTP_PROXY-Env-Vars respektieren sie nicht.
# Adresse aus Sicht des tool-runner (nicht des worker); im Lab-Netz nicht
# gesetzt (dort erreichen die Tools die Ziele direkt, kein Proxy noetig).
EGRESS_PROXY_URL = os.environ.get("EGRESS_PROXY_URL", "")
# Raw sockets cannot traverse the HTTP proxy. This flag may be enabled only
# when the deployment has installed the current per-engagement raw-egress
# allowlist (Kubernetes NetworkPolicy). Compose sets it explicitly to disabled.
RAW_NETWORK_MODE = os.environ.get("ASM_RAW_NETWORK_MODE", "disabled").lower()
CANCEL_POLL_SECONDS = max(0.1, min(float(os.environ.get("ASM_CANCEL_POLL_SECONDS", "1")), 5.0))
CANCEL_TERMINATE_GRACE_SECONDS = max(1.0, min(
    float(os.environ.get("ASM_CANCEL_TERMINATE_GRACE_SECONDS", "8")), 30.0
))
# REQ-FIDELITY-001: a single failed cancellation-status poll (control-plane
# restart, network blip) must not kill an otherwise-healthy, long-running tool.
# Only sustained, consecutive unavailability fails closed.
CANCEL_STATUS_FAILURE_TOLERANCE = max(1, min(
    int(os.environ.get("ASM_CANCEL_STATUS_FAILURE_TOLERANCE", "3")), 20
))


import re

_NMAP_SERVICE_PORTS_RE = re.compile(r"^[0-9]{1,5}(?:,[0-9]{1,5}){0,127}$")
_NMAP_DISCOVERY_PORTS_RE = re.compile(r"^[1-9][0-9]{0,4}(?:-[1-9][0-9]{0,4})?$")
_TARGETED_UDP_PORTS = {53, 123, 161, 443, 500, 1900, 4500, 5060, 5353}
_TARGETED_UDP_PORT_RANGE = "53,123,161,443,500,1900,4500,5060,5353"

# GitHub issue #12: the egress-proxy already injects a bug-bounty program's
# mandatory identification header (and UA suffix) for plain HTTP
# (egress-proxy/app/proxy.py::_forward_plain_http) - but for HTTPS (CONNECT
# tunnels) the payload is opaque to the proxy, so every HTTP-proxied tool
# must carry it itself. Deliberately excludes the raw_network tools (nmap,
# redis-probe, activemq-*) - those don't speak HTTP at all, so there is no
# header/UA to identify with.
_HTTP_PROXIED_TOOLS = {"httpx", "nikto", "wafw00f", "testssl", "nuclei", "http_request", "ffuf"}

# Looked up once per engagement per worker process, not once per tool call -
# a bounty program's policy doesn't change mid-run, and every fingerprint-
# phase host/tool combination would otherwise repeat an identical internal
# API round-trip. A stale/missing entry just means the next lookup tries
# again (no TTL needed: the cache only ever holds a value once a lookup has
# actually succeeded).
_bounty_ident_cache: dict[str, dict] = {}


def _bounty_ident_for(engagement_id: str) -> dict | None:
    """None when this engagement isn't (or isn't yet configured as) a
    bug_bounty engagement - callers then inject nothing and apply no rate
    cap, identical to today's behavior. Never raises: a lookup failure must
    not abort a scan.

    REQ-AUTH-006 (amended 2026-08-12): the identification header is now
    optional (not every program requires one), so "no header configured" no
    longer implies "no policy at all" - a program can still set max_rps
    without a header. Gate on whether ANY of the policy's fields are
    present, not specifically the header, so a header-less-but-rate-capped
    policy still reaches _bounty_rate_cap's REQ-RATE-004 tightening. The
    header-building helpers (_bounty_h_flags and friends) already no-op
    correctly on a missing name/value independent of this.

    Local import avoids a module cycle during worker startup (same reasoning
    as _cancel_requested/_set_current_activity above)."""
    from app.control_plane_client import client as control_plane_client

    cached = _bounty_ident_cache.get(engagement_id)
    if cached is None:
        try:
            ident = control_plane_client.get_bounty_ident(uuid.UUID(engagement_id))
        except Exception:  # noqa: BLE001 - see get_bounty_ident's own docstring
            return None
        if not any(ident.get(k) for k in ("ident_header_value", "max_rps", "ua_suffix")):
            return None
        _bounty_ident_cache[engagement_id] = ident
        cached = ident
    return cached


# tool-Name -> (HexStrike-Endpunkt, Funktion die (target, args) -> Request-Body baut)
def _nmap_body(target: str, args: dict) -> dict:
    stage = str(args.get("stage", ""))
    ports = str(args.get("ports", ""))
    try:
        max_rate = int(args.get("max_rate"))
    except (TypeError, ValueError) as exc:
        raise ValueError("tool_runner_client: ungueltige nmap max_rate") from exc
    if not 1 <= max_rate <= 1000:
        raise ValueError("tool_runner_client: nmap max_rate ausserhalb des sicheren Bereichs")

    if stage == "discovery":
        if args.get("flags") != ["-sS"] or not _NMAP_DISCOVERY_PORTS_RE.fullmatch(ports):
            raise ValueError("tool_runner_client: ungueltiges nmap discovery profile")
        bounds = [int(value) for value in ports.split("-", 1)]
        if not 1 <= bounds[0] <= bounds[-1] <= 65535:
            raise ValueError("tool_runner_client: ungueltige nmap discovery ports")
        scan_type = "-sS"
        # --host-timeout grosszuegig (war 280s): ein Full-Range-Scan (1-65535)
        # eines ueberwiegend gefilterten Hosts braucht selbst bei 1000 pps ~200s;
        # bei 280s riss der Host-Timeout mittendrin ab -> nmap verwarf den Host und
        # meldete 0 offene Ports. 600s liegt sicher unter der Lease-TTL (900s).
        extra = f"--privileged -T3 -Pn -n --max-rate {max_rate} --max-retries 2 --host-timeout 600s -oX -"
    elif stage == "udp_discovery":
        if args.get("flags") != ["-sU"] or ports != _TARGETED_UDP_PORT_RANGE or max_rate > 100:
            raise ValueError("tool_runner_client: ungueltiges nmap UDP discovery profile")
        scan_type = "-sU"
        extra = f"--privileged -T3 -Pn -n --max-rate {max_rate} --max-retries 1 --host-timeout 180s -oX -"
    elif stage == "host_discovery":
        # REQ-CIDRDISC-002: liveness-only sweep of a whole CIDR/IP scope
        # asset - no port scan, no -Pn (that would SKIP host discovery,
        # defeating the point). -PS80,443 forces TCP-SYN-only discovery
        # probes (no ICMP, no ARP - ARP does not apply to routed internet
        # targets anyway) so the probe traffic matches exactly what the
        # raw-egress nftables policy allows for this lease (tcp dport 80,443
        # to the leased CIDR block, nothing else).
        if args.get("flags") != ["-sn"] or ports:
            raise ValueError("tool_runner_client: ungueltiges nmap host_discovery profile")
        scan_type = "-sn"
        extra = f"--privileged -T3 -n -PS80,443 --max-rate {max_rate} --max-retries 1 --host-timeout 30s -oX -"
    elif stage in {"service", "udp_service"}:
        expected_flags = ["-sV"] if stage == "service" else ["-sU", "-sV"]
        if args.get("flags") != expected_flags or not _NMAP_SERVICE_PORTS_RE.fullmatch(ports):
            raise ValueError("tool_runner_client: ungueltiges nmap service profile")
        parsed_ports = [int(value) for value in ports.split(",")]
        if any(not 1 <= value <= 65535 for value in parsed_ports) or parsed_ports != sorted(set(parsed_ports)):
            raise ValueError("tool_runner_client: ungueltige nmap service ports")
        if stage == "udp_service" and (not set(parsed_ports) <= _TARGETED_UDP_PORTS or max_rate > 100):
            raise ValueError("tool_runner_client: ungueltige nmap UDP service ports")
        scan_type = "-sV" if stage == "service" else "-sU -sV"
        retry_bound = 2 if stage == "service" else 1
        extra = f"--version-light -T3 -Pn -n --max-rate {max_rate} --max-retries {retry_bound} --host-timeout 180s -oX -"
    else:
        raise ValueError("tool_runner_client: nmap stage fehlt")

    return {
        "target": _safe_target(target),
        "scan_type": scan_type,
        "ports": ports,
        "additional_args": extra,
        "use_recovery": False,
        # REQ-CONCUR-001: HexStrike caches execute_command() results for 1h,
        # keyed ONLY by the raw command string hash - no engagement scoping at
        # all. Without this, a re-scan (or a different engagement hitting the
        # same target+flags) can silently receive another run's stale result
        # instead of actually re-executing.
        "use_cache": False,
    }



# Ziel muss ein einfacher Hostname/URL sein - schuetzt die generischen
# /api/command-Aufrufe (httpx/testssl) vor Shell-Injection. Das Ziel kommt aus
# gateway-freigegebenen discovered_asset-Werten, aber Defense-in-Depth.
_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:/_-]{0,253}$")
_PROXY_RE = re.compile(r"^https?://[A-Za-z0-9][A-Za-z0-9._-]*(?::[0-9]{1,5})?/?$")


def _safe_target(target: str) -> str:
    if not _TARGET_RE.match(target):
        raise ValueError(f"tool_runner_client: unsicheres Ziel fuer Command: {target!r}")
    return target


def _proxy_url() -> str:
    if not EGRESS_PROXY_URL:
        return ""
    if not _PROXY_RE.match(EGRESS_PROXY_URL):
        raise ValueError(f"tool_runner_client: unsichere Egress-Proxy-URL: {EGRESS_PROXY_URL!r}")
    return EGRESS_PROXY_URL.rstrip("/")


def _proxy_hostport() -> str:
    """egress-proxy:3128 aus der http://...-URL (testssl --proxy will host:port)."""
    return _proxy_url().split("://", 1)[-1]


def _bounty_h_flags(args: dict) -> str:
    """GitHub issue #12: `-H "Name: Value"` flags for the tools whose CLI
    supports that exact curl-style syntax (httpx, nuclei, ffuf) - the
    mandatory identification header, plus the User-Agent override when a
    suffix is configured. Empty string when this call isn't for a
    bug_bounty engagement (the common case - run() only ever sets these
    three keys together, see ToolRunnerClient.run's docstring)."""
    name, value = args.get("_bounty_ident_header_name"), args.get("_bounty_ident_header_value")
    if not name or not value:
        return ""
    flags = f'-H {shlex.quote(f"{name}: {value}")} '
    ua_suffix = args.get("_bounty_ua_suffix")
    if ua_suffix:
        flags += f'-H {shlex.quote(f"User-Agent: {ua_suffix}")} '
    return flags


def _bounty_rate_cap(args: dict, default: int) -> int:
    """REQ-RATE-004: nuclei/ffuf each fire many requests per gateway-
    authorized call at their own hardcoded internal pace - the gateway's and
    egress-proxy's per-call rate check (BountyProgram.max_rps) never sees
    inside a single invocation, and for HTTPS the proxy only re-checks once
    per CONNECT, not per request within a reused connection. This tightens
    the tool's own rate flag to the program's cap when it's stricter than our
    default; a missing/looser cap (non-bug_bounty engagement, or a program
    whose allowed rate exceeds our own default) leaves the default unchanged
    - this only ever tightens, never loosens."""
    max_rps = args.get("_bounty_max_rps")
    if not max_rps:
        return default
    return max(1, min(default, int(max_rps)))


# REQ-FPEFF-007: nuclei templates that re-derive - less accurately - what a
# purpose-built tool in the SAME per-host suite has already established.
# Excluded by template id, deliberately not by tag: both carry broad tags
# (`tech`/`misc`/`discovery`, `misconfig`/`headers`/`generic`/`vuln`) whose
# removal would drop large unrelated parts of the set. Verified to remove
# exactly these two and nothing else (5974 -> 5972 selected).
#
# Each entry must name the tool that owns the signal instead - this list is
# for redundancy only, never a general-purpose way to quieten nuclei.
REDUNDANT_NUCLEI_TEMPLATE_IDS = (
    # wafw00f runs per host in the same suite and is the purpose-built WAF
    # detector. waf-detect declares no matchers-condition (so its 96 matchers
    # are OR'd) and one of them, `nginxgeneric`, is the bare regex
    # `(?i)nginx` against the whole response - every stock nginx Server
    # header matches. Live: all 5 nginx hosts on 93.254.158.41 reported a
    # WAF that wafw00f correctly found absent; neither Caddy host matched.
    "waf-detect",
    # nikto already reports missing security headers for the same host, at
    # `low` rather than `info` AND naming the specific headers - and in ~24s
    # against nuclei's ~5min. The two carried different fingerprints, so the
    # finding dedup never collapsed them: two rows per host for one fact.
    "http-missing-security-headers",
)


def _nuclei_body(target: str, args: dict) -> dict:
    # Gebackene Templates (Build-Zeit, /opt/nuclei-templates), kein Runtime-
    # Fetch (-disable-update-check), JSONL auf stdout, Proxy erzwungen, und
    # bewusst konservativ: nicht-intrusive Templates, kein dos/fuzz, Rate-Limit.
    #
    # REQ-AGENT-018 (korrigiert nach Live-Messung): nuclei laeuft in ZWEI
    # getrennten Aufrufen, weil HexStrikes Command-Executor jeden Aufruf hart
    # bei 300s killt (hexstrike_server.py COMMAND_TIMEOUT=300, NICHT pro Call
    # ueberschreibbar). Der -headless-Modus gegen ein echtes, proxied Ziel
    # sprengt zusammen mit dem vollen Tag-Satz diese 300s (live: nonzero_exit,
    # nur partielle Findings) - waehrend der non-headless-Lauf zuvor 5/5 sauber
    # unter 300s durchlief. Loesung: Haupt-Pass (non-headless, voller Tag-Satz)
    # und ein separater Mini-Headless-Pass (nur domxss, 1 Template, ~5-30s) -
    # jeder fuer sich sicher unter 300s. mode wird ueber args gewaehlt; der
    # deterministische fingerprint-Lauf (fingerprint.py) ruft beide, ein
    # Agent-Vorschlag ('args' ohne mode) bekommt den schnellen Haupt-Pass.
    proxy_url = _proxy_url()
    proxy = f"-p {proxy_url} " if proxy_url else ""
    rate_limit = _bounty_rate_cap(args, 50)
    common = (
        "-t /opt/nuclei-templates -disable-update-check -j -silent -no-color "
        f"-eid {','.join(REDUNDANT_NUCLEI_TEMPLATE_IDS)} "
        # REQ-FPEFF-008: tool-runner has no internet egress by design (isolated
        # image, all traffic through the egress proxy) - so of the ~680 baked
        # templates that need an Interactsh out-of-band callback to confirm a
        # finding, EVERY one fails, deterministically, every run. Without this
        # flag that failure takes 60-90s per template (nuclei retries
        # registration against 6 public interactsh.* servers before giving
        # up); measured live: CVE-2023-46604's template alone. -no-interactsh
        # makes the same, correct "no results" outcome cost ~2ms instead -
        # confirmed live it does not affect a template's own non-OOB
        # requests/matchers (CVE-2019-17558, a mixed template, still ran its
        # full non-OOB HTTP chain and reached a normal conclusion).
        "-no-interactsh "
        # GitHub issue #12: mandatory identification for a bug-bounty
        # engagement - nuclei's -H sets the header on every request the
        # template set makes, no separate random-agent handling needed
        # (unlike httpx, nuclei doesn't randomize its User-Agent by default).
        f"{_bounty_h_flags(args)}"
    )

    if args.get("mode") == "headless":
        # Mini-Pass: NUR das eine generische DOM-XSS-Template
        # (headless/window-name-domxss.yaml). DOM-XSS-Templates tragen nie das
        # 'dast'-Tag, nur 'headless'/'xss'/'domxss'; 'domxss' trifft praezise
        # dieses eine generische Template (die zweite domxss-Fundstelle ist
        # bereits CVE-getaggt und im Haupt-Pass abgedeckt). Bewusst NICHT das
        # breite 'headless'-Tag (zieht u. a. ein DVWA-spezifisches Template mit)
        # oder 'xss' (1411, ueberwiegend produktspezifisch).
        # -system-chrome: das im Image installierte Chromium (kein Runtime-
        # Download - isoliertes Image ohne Internet). --no-sandbox: Chromes
        # eigene Sandbox braucht Capabilities, die der Container bewusst nicht
        # hat (cap_drop: ALL) - Isolation kommt vom Container selbst (non-root,
        # read-only rootfs, cap_drop ALL, Netz nur ueber Egress-Proxy).
        # -hbs/-headc 2: die kleine IONOS-Box vertraegt keine 10 parallelen
        # Chrome-Prozesse. Ein Template -> Laufzeit ~5-30s, klar unter 300s.
        extra = (
            common +
            "-tags domxss -severity info,low,medium,high,critical "
            f"-rate-limit {rate_limit} -timeout 8 -retries 1 {proxy}"
            " -headless -system-chrome -ho \"--no-sandbox\" -hbs 2 -headc 2 -page-timeout 20"
        ).strip()
    else:
        # Haupt-Pass: schnelle, non-headless HTTP-Templates. 'dast' = gebackene
        # generische Verwundbarkeits-Templates (xss, sqli inkl. blind/time-
        # based, redirect, lfi, rfi, cmdi, ssrf, ssti, xxe, crlf - je
        # max-request:1, kein 'fuzz'-Tag, daher nicht von -etags ausgeschlossen;
        # REQ-AGENT-016). csp-bypass ausgeschlossen: braucht -headless UND
        # ~192 Vendor-spezifische Templates - fuer eine generische ASM-Baseline
        # unverhaeltnismaessig teuer (gemessen: ~530s allein fuer die 24
        # Templates im headless/-Verzeichnis gegen ein Ziel).
        extra = (
            common +
            "-tags cve,misconfig,exposure,exposures,default-login,waf,dast "
            "-severity info,low,medium,high,critical -etags intrusive,dos,fuzz,csp-bypass "
            f"-rate-limit {rate_limit} -timeout 8 -retries 1 {proxy}"
        ).strip()

    # REQ-CONCUR-001: see _nmap_body - HexStrike's own result cache is not
    # engagement-scoped, must be disabled per call.
    return {"target": target, "tags": "", "additional_args": extra, "use_recovery": False, "use_cache": False}


def _nikto_body(target: str, args: dict) -> dict:
    extra = args.get("additional_args", "")
    # nikto respektiert HTTP_PROXY-Env NICHT - Proxy muss per -useproxy an das
    # Tool. So laeuft aller nikto-Traffic durch den Egress-Proxy (Scope-Recheck
    # + Rate-Limit auf Netzwerkebene), statt am Enforcement vorbei.
    if EGRESS_PROXY_URL:
        extra = f"-useproxy {_proxy_url()} {extra}".strip()
    # GitHub issue #12: mandatory identification for a bug-bounty engagement.
    # -Add-header is repeatable (one flag per header pair, verified against
    # the real nikto binary); -useragent forces the UA nikto would otherwise
    # pull from its own database.
    ident_name, ident_value = args.get("_bounty_ident_header_name"), args.get("_bounty_ident_header_value")
    if ident_name and ident_value:
        extra = f'{extra} -Add-header "{ident_name}: {ident_value}"'.strip()
    ua_suffix = args.get("_bounty_ua_suffix")
    if ua_suffix:
        extra = f'{extra} -useragent "{ua_suffix}"'.strip()
    # REQ-CONCUR-001: see _nmap_body.
    return {"target": target, "additional_args": extra, "use_cache": False}


def _subfinder_body(target: str, args: dict) -> dict:
    # REQ-CONCUR-001: see _nmap_body.
    return {"domain": target, "silent": True, "use_cache": False}


def _amass_body(target: str, args: dict) -> dict:
    # REQ-CONCUR-001: see _nmap_body.
    return {"domain": target, "mode": "enum", "use_cache": False}


# wafw00f's own realistic default headers (wafw00f/lib/evillib.py's
# def_headers, transcribed from the installed image 2026-08-11). Only needed
# to REBUILD when a bug-bounty ident header must be injected (see
# _wafw00f_command below) - if wafw00f ever changes these, the live symptom
# would be wafw00f-tagged findings quietly getting less accurate for
# bug_bounty engagements specifically, not a hard failure.
_WAFW00F_DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,"
              "application/signed-exchange;v=b3",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Accept-Language": "en-US,en;q=0.5",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "cross-site",
    "Priority": "u=0, i",
    "DNT": "1",
}


def _wafw00f_command(target: str, args: dict) -> str:
    """GitHub issue #12: migrated off HexStrike's dedicated /api/tools/wafw00f
    endpoint (dict body) to a worker-constructed command, because wafw00f's
    ONLY header-injection mechanism (`-H <file>`) takes a FILE and, per its
    own docs, OVERWRITES (not merges with) its realistic default header set -
    writing a file with just the ident header would make every wafw00f
    request look like a bare, obviously-automated single-header probe
    (verified against wafw00f's own source: a truthy `head` argument REPLACES
    `self.headers` outright, `wafw00f/lib/evillib.py`). Only the compound
    "write file; run; cleanup" shape this needs is available on the generic
    /api/command endpoint (same reason httpx/testssl are worker-constructed
    already, see the module comment above _httpx_command)."""
    url = _safe_target(target)
    proxy = f"-p {_proxy_url()} " if EGRESS_PROXY_URL else ""
    ident_name, ident_value = args.get("_bounty_ident_header_name"), args.get("_bounty_ident_header_value")
    if not (ident_name and ident_value):
        return f"wafw00f {url} {proxy}".strip()

    headers = dict(_WAFW00F_DEFAULT_HEADERS)
    ua_suffix = args.get("_bounty_ua_suffix")
    if ua_suffix:
        headers["User-Agent"] = ua_suffix
    headers[ident_name] = ident_value  # last, so it can never be shadowed by a same-named default

    header_file = f"/tmp/wafw00f-headers-{uuid.uuid4().hex}.txt"
    lines = [f"{k}: {v}" for k, v in headers.items()]
    write_file = "printf '%s\\n' " + " ".join(shlex.quote(line) for line in lines) + f" > {header_file}; "
    return f"{write_file}wafw00f {url} {proxy}-H {header_file}; rm -f {header_file}"


_ENDPOINTS = {
    "nmap": ("/api/tools/nmap", _nmap_body),
    "nuclei": ("/api/tools/nuclei", _nuclei_body),
    "nikto": ("/api/tools/nikto", _nikto_body),
    "subfinder": ("/api/tools/subfinder", _subfinder_body),
    "amass": ("/api/tools/amass", _amass_body),
}


# --- Tools ueber den generischen /api/command-Endpoint --------------------
# httpx: HexStrikes dedizierter Endpoint ist fuer Einzel-Hosts kaputt
#        (`httpx -l {target}` behandelt den Namen als Dateiliste). testssl:
# hat gar keinen dedizierten Endpoint. Beide werden daher als vollstaendig
# vom Worker konstruierte, gateway-freigegebene Kommandos ausgefuehrt.

def _httpx_command(target: str, args: dict) -> str:
    # REQ-FIDELITY-010: do not re-force or strip whatever scheme
    # target_envelope.httpx_target built (always an explicit http://, which
    # httpx itself self-corrects to https when needed) - this function must
    # not second-guess that choice.
    url = _safe_target(target)
    proxy_url = _proxy_url()
    proxy = f"-proxy {proxy_url} " if proxy_url else ""
    # GitHub issue #12: httpx randomizes its own User-Agent by default
    # (-random-agent defaults to true) - actively working against a
    # bug-bounty program's mandatory identification, so it must be disabled
    # whenever we're setting an explicit one. Verified live: without this,
    # the -H "User-Agent: ..." below gets silently overridden.
    bounty = _bounty_h_flags(args)
    random_agent_off = "-random-agent=false " if args.get("_bounty_ua_suffix") else ""
    # REQ-DISCO-003: -irh includes the response headers in the JSON, which is
    # what lets the parser tell OUR OWN egress-proxy denial apart from a real
    # target response. Without it a `403 Blocked` from the proxy is
    # indistinguishable from a target's 403, and gets recorded as a live
    # service (observed live against an NXDOMAIN host).
    return (
        f"httpx -u {url} -json -silent -disable-update-check "
        f"-tech-detect -status-code -title -web-server -include-response-header "
        f"-timeout 10 -no-color {proxy}{bounty}{random_agent_off}"
    ).strip()


def _testssl_command(target: str, args: dict) -> str:
    url = _safe_target(target if "://" in target else f"https://{target}")
    proxy = f"--proxy {_proxy_hostport()} " if EGRESS_PROXY_URL else ""
    # testssl loest DNS LOKAL auf (anders als nikto/nuclei) - der isolierte
    # Runner hat aber kein DNS. Daher die materialisierte IP per --ip; der
    # Egress-Proxy laesst diese IP zu, weil sie aus einem in-scope-Namen
    # auditiert materialisiert wurde (resolved_host).
    ip = args.get("ip")
    ip_arg = f"--ip {_safe_target(ip)} " if ip else ""
    # Fokussiert (Protokolle + Server-/Zertifikatsdefaults) statt Vollscan;
    # nur nennenswerte Befunde. Eindeutige jsonfile (testssl ueberschreibt nicht),
    # dann per cat an stdout - saubere JSON ohne Banner-Verunreinigung.
    out = f"/tmp/testssl-{uuid.uuid4().hex}.json"
    # GitHub issue #12: testssl still makes a handful of real HTTP requests
    # (HSTS/security-header/server-banner checks) even though its main job is
    # the TLS handshake itself - --reqheader and --user-agent are its own
    # supported flags for exactly this (confirmed in testssl.sh source: both
    # feed the same GET request testssl builds for those checks).
    ident_name, ident_value = args.get("_bounty_ident_header_name"), args.get("_bounty_ident_header_value")
    bounty = f'--reqheader {shlex.quote(f"{ident_name}: {ident_value}")} ' if ident_name and ident_value else ""
    ua_suffix = args.get("_bounty_ua_suffix")
    if ua_suffix:
        bounty += f"--user-agent {shlex.quote(ua_suffix)} "
    # REQ-SCANQUAL-004: also run testssl's non-destructive vulnerability section
    # (--vulnerable: Heartbleed, ROBOT, CCS, BEAST, ...) on top of protocol and
    # server-default hygiene. These are diagnostic probes (crafted handshakes,
    # read responses), no exploitation - consistent with the platform posture.
    return (
        f"testssl --quiet --protocols --server-defaults --vulnerable --severity LOW {ip_arg}{proxy}{bounty}"
        f"--jsonfile {out} {url} >/dev/null 2>&1; cat {out}; rm -f {out}"
    )


def _http_request_command(target: str, args: dict) -> str:
    """Agent-gesteuerter roher HTTP-Lesezugriff via curl DURCH den Egress-Proxy
    (Scope-Enforcement + Rate-Limit auf Netzwerkebene). Der Agent formt
    Methode/Pfad/Header; die volle Antwort (Status + Header + Body-Anfang)
    geht zur Klassifikation zurueck. Args sind bereits gateway-geprueft
    (nicht-destruktiver envelope), hier zusaetzlich hart shlex-gequotet gegen
    Shell-Injektion (Defense-in-Depth).

    GitHub issue #12: a bug-bounty program's mandatory ident header/UA suffix
    is injected HERE, not by the egress-proxy - for HTTPS (the common case)
    the request payload is opaque to the proxy (CONNECT tunnel), so this is
    the only point that can see and set it before the request is made."""
    method = str(args.get("method", "GET")).upper()
    path = str(args.get("path", "/") or "/")
    if not path.startswith("/"):
        path = "/" + path
    # Callers always pass a full URL whose scheme already reflects the
    # fingerprint-confirmed protocol (REQ-FIDELITY-009, target_envelope.
    # target_url), so this https fallback applies to a bare host only. It is
    # NOT the place to decide the scheme - if a target reaches here without
    # one, fix the caller to pass the confirmed protocol.
    base = target if "://" in target else f"https://{target}"
    url = base + path

    # REQ-HTTP-003: --globoff, or curl expands [] and {} in the URL into many
    # requests - one gateway decision (or one human approval of a
    # state-changing request) must never become more than one request.
    parts = ["curl", "--globoff", "-sS", "-i", "-X", method, "--max-time", "20"]
    proxy_url = _proxy_url()
    if proxy_url:
        parts += ["-x", proxy_url]
    out_headers = dict(args.get("headers") or {})
    # GitHub issue #12: for HTTPS this is the ONLY place a bug-bounty
    # program's mandatory identification can be injected (the egress-proxy
    # only sees inside plain-HTTP requests, never a CONNECT tunnel's
    # payload). Set AFTER copying the agent's own headers and matched
    # case-insensitively, so this always wins over - never merges with, never
    # gets silently dropped by - whatever the agent itself proposed, even if
    # it happened to reuse the same header name.
    ident_name, ident_value = args.get("_bounty_ident_header_name"), args.get("_bounty_ident_header_value")
    if ident_name and ident_value:
        out_headers = {k: v for k, v in out_headers.items() if k.lower() != ident_name.lower()}
        out_headers[ident_name] = ident_value
    ua_suffix = args.get("_bounty_ua_suffix")
    if ua_suffix:
        out_headers = {k: v for k, v in out_headers.items() if k.lower() != "user-agent"}
        out_headers["User-Agent"] = ua_suffix
    for name, value in out_headers.items():
        parts += ["-H", f"{name}: {value}"]
    # Request-Body (nur bei schreibenden, freigegebenen Aufrufen - REQ-HTTP-002).
    # --data-raw: curl interpretiert @/% nicht, sendet den Body 1:1.
    body = args.get("body")
    if body:
        parts += ["--data-raw", str(body)]
    parts.append(url)

    cmd = " ".join(shlex.quote(p) for p in parts)
    # Antwort deckeln (16 KB): Status + Header + Body-Anfang reichen zur
    # Klassifikation und schuetzen das LLM-Kontextbudget.
    return f"{cmd} | head -c 16384"


# SecLists-Wortlisten, waehlbar per Schluessel (nie roher Pfad vom Agenten).
# Schluesselmenge MUSS mit _FFUF_WORDLISTS in control-plane args_safety
# uebereinstimmen. Pfade liegen im Runner-Image (apt-Paket seclists).
FFUF_WORDLISTS = {
    "common": "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "raft-medium-dirs": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "raft-medium-files": "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt",
    "quickhits": "/usr/share/seclists/Discovery/Web-Content/quickhits.txt",
    "directory-list-medium": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
}


def _ffuf_command(target: str, args: dict) -> str:
    """Kuratierte Content-Discovery via ffuf DURCH den Egress-Proxy. Der Agent
    waehlt die Wortliste (Schluessel) und/oder liefert wenige eigene Kandidaten;
    ffuf feuert die Serie rate-limitiert. Scope wird pro Request am Proxy
    erzwungen. Args sind gateway-geprueft, hier zusaetzlich shlex-gequotet."""
    path = str(args.get("path", "/FUZZ") or "/FUZZ")
    if not path.startswith("/"):
        path = "/" + path
    # Callers always pass a full URL whose scheme already reflects the
    # fingerprint-confirmed protocol (REQ-FIDELITY-009, target_envelope.
    # target_url), so this https fallback applies to a bare host only. It is
    # NOT the place to decide the scheme - if a target reaches here without
    # one, fix the caller to pass the confirmed protocol.
    base = target if "://" in target else f"https://{target}"
    url = base + path

    out = f"/tmp/ffuf-{uuid.uuid4().hex}.json"
    prefix = ""
    cleanup_extra = ""
    cands = args.get("extra_candidates") or []
    if cands:
        # Vom Agenten begruendete Kandidaten -> temporaere Wortliste.
        wl = f"/tmp/ffufwl-{uuid.uuid4().hex}.txt"
        prefix = "printf '%s\\n' " + " ".join(shlex.quote(str(c)) for c in cands) + f" > {wl}; "
        wordlist_path = wl
        cleanup_extra = f"; rm -f {wl}"
    else:
        wordlist_path = FFUF_WORDLISTS.get(str(args.get("wordlist", "common")), FFUF_WORDLISTS["common"])

    parts = [
        "ffuf", "-w", f"{wordlist_path}:FUZZ", "-u", url,
        "-mc", "200,204,301,302,307,401,403,405,500",
        # REQ-DISCO-001: match on status code ALONE makes every wordlist entry
        # a "hit" against any catch-all responder. Measured live: an SPA whose
        # server does `try_files {path} /index.html` returned the same 396-byte
        # shell 1677 times, and our own egress proxy's 21-byte denial 1800
        # times - all reported as discovered paths. -ac is ffuf's own remedy:
        # it probes known-nonexistent paths first, learns the catch-all
        # signature, and filters responses matching it. The parser applies an
        # independent uniformity check as well (see ffuf_parse), because -ac
        # calibrates per run and cannot be assumed to catch every shape.
        "-ac",
        # REQ-RATE-004: -rate is ffuf's own internal pacing across its worker
        # threads - tightened to a bug-bounty program's configured max_rps
        # when stricter than our default, since the gateway/proxy per-call
        # rate check never sees inside this one authorized invocation.
        "-rate", str(_bounty_rate_cap(args, 20)), "-t", "10", "-maxtime", "90", "-s", "-of", "json", "-o", out,
    ]
    exts = args.get("extensions") or []
    if exts:
        parts += ["-e", ",".join((e if e.startswith(".") else "." + e) for e in exts)]
    proxy_url = _proxy_url()
    if proxy_url:
        parts += ["-x", proxy_url]
    # GitHub issue #12: mandatory identification for a bug-bounty engagement -
    # ffuf fires many requests per call, so this matters as much here as
    # anywhere (arguably more: a large content-discovery burst is exactly the
    # kind of traffic a program operator most wants attributable).
    ident_name, ident_value = args.get("_bounty_ident_header_name"), args.get("_bounty_ident_header_value")
    if ident_name and ident_value:
        parts += ["-H", f"{ident_name}: {ident_value}"]
    ua_suffix = args.get("_bounty_ua_suffix")
    if ua_suffix:
        parts += ["-H", f"User-Agent: {ua_suffix}"]

    cmd = " ".join(shlex.quote(p) for p in parts)
    return f"{prefix}{cmd} >/dev/null 2>&1; cat {out}; rm -f {out}{cleanup_extra}"


# --- Curated raw-protocol probes (REQ-AGENT-025) ---------------------------
# Non-HTTP services (Redis, ActiveMQ OpenWire) the HTTP-only tools above
# cannot touch at all. Each entry is the FULL, fixed, non-destructive I/O:
# what bytes to send (or none - purely passive), never anything an agent or
# caller can influence. A third protocol later is a registry entry here, not
# new plumbing. Bounded by construction: 3s connect timeout, 3s read
# timeout, 4096-byte read cap, an outer `timeout 8` as defense-in-depth
# against any edge case the socket-level timeouts don't cover (e.g. DNS
# resolution hangs before connect() even starts its own timeout clock).
_RAW_TCP_PROTOCOLS: dict[str, bytes | None] = {
    "redis-probe": b"PING\r\n",
    "activemq-banner": None,  # OpenWire self-announces a WireFormatInfo greeting on connect
    # REQ-AGENT-027: no static entry - the bytes are per-call (they embed a
    # single-use callback URL) and never agent-supplied; see _send_bytes
    # handling below. Listed here only so the "known tool" check passes.
    "activemq-openwire-probe": None,
}


def _raw_tcp_probe_command(target: str, args: dict) -> str:
    host = _safe_target(target)
    try:
        port = int(args["port"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("tool_runner_client: raw tcp probe port fehlt/ungueltig") from exc
    if not 1 <= port <= 65535:
        raise ValueError("tool_runner_client: raw tcp probe port ausserhalb des gueltigen Bereichs")
    tool = str(args.get("_tool") or "")
    if tool not in _RAW_TCP_PROTOCOLS:
        raise ValueError(f"tool_runner_client: unbekannte raw-tcp-Probe {tool!r}")
    if tool == "activemq-openwire-probe":
        # Built server-side by dispatch.py from a fresh callback token
        # (worker/app/openwire_payload.py) - never a static registry value,
        # since it must embed a per-call, single-use URL. Never agent-
        # supplied: the agent selects the TOOL, never these bytes
        # (args_safety._raw_tcp_probe_args_safe rejects any other argument).
        send_bytes = args.get("_send_bytes")
        if not isinstance(send_bytes, (bytes, bytearray)) or not send_bytes:
            raise ValueError("tool_runner_client: activemq-openwire-probe braucht _send_bytes")
        send_bytes = bytes(send_bytes)
    else:
        send_bytes = _RAW_TCP_PROTOCOLS[tool]

    # Column 0, NOT indented: this statement must sit at the SAME (top)
    # indentation level as the `try:`/`s.close()` lines around it. Found live
    # by actually running the generated script against a real socket
    # (2026-08-04): an earlier version indented this to match the preceding
    # `except:` block, which silently made it DEAD CODE - Python parsed it as
    # part of that except suite (after its own sys.exit(0)), so it only ever
    # ran on the connect-failure path and never actually sent anything on a
    # successful connection. A syntax mistake this specific does not raise
    # anywhere upstream; only exercising the real script caught it.
    send_line = f"s.sendall({send_bytes!r})\n" if send_bytes else ""
    # ALL output goes through sys.stdout.buffer.write() - never mixed with
    # print(). Found live (2026-08-04): print() (text-mode, block-buffered
    # under a piped stdout) and a separate sys.stdout.buffer.write() call
    # (binary-mode, unbuffered) do NOT interleave in call order once
    # captured through a pipe - the status lines arrived AFTER the payload
    # bytes instead of before, silently breaking dispatch.py's parser, which
    # assumes the status/byte-count header precedes the payload. A single
    # write() of one pre-assembled bytes blob has no such ordering hazard.
    py = (
        "import socket, sys\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "s.settimeout(3)\n"
        "try:\n"
        f"    s.connect(({host!r}, {port}))\n"
        "except Exception as e:\n"
        "    sys.stdout.buffer.write(b'asm_probe_status=connect_failed:' + type(e).__name__.encode())\n"
        "    sys.exit(0)\n"
        f"{send_line}"
        "try:\n"
        "    data = s.recv(4096)\n"
        "except socket.timeout:\n"
        "    data = b''\n"
        "except Exception as e:\n"
        "    sys.stdout.buffer.write(b'asm_probe_status=recv_failed:' + type(e).__name__.encode())\n"
        "    s.close()\n"
        "    sys.exit(0)\n"
        "s.close()\n"
        "printable = bytes(b for b in data if 32 <= b < 127 or b in (9, 10, 13))\n"
        "header = ('asm_probe_status=ok\\nasm_probe_bytes_read=' + str(len(data)) + '\\n').encode()\n"
        "sys.stdout.buffer.write(header + printable[:2000])\n"
    )
    return f"timeout 8 python3 -c {shlex.quote(py)}"


def _redis_probe_command(target: str, args: dict) -> str:
    return _raw_tcp_probe_command(target, {**args, "_tool": "redis-probe"})


def _activemq_banner_command(target: str, args: dict) -> str:
    return _raw_tcp_probe_command(target, {**args, "_tool": "activemq-banner"})


def _activemq_openwire_probe_command(target: str, args: dict) -> str:
    return _raw_tcp_probe_command(target, {**args, "_tool": "activemq-openwire-probe"})


_COMMANDS = {
    "httpx": _httpx_command,
    "testssl": _testssl_command,
    "http_request": _http_request_command,
    "ffuf": _ffuf_command,
    "wafw00f": _wafw00f_command,
    "redis-probe": _redis_probe_command,
    "activemq-banner": _activemq_banner_command,
    "activemq-openwire-probe": _activemq_openwire_probe_command,
}


def _cancel_requested(scan_run_id: str) -> bool:
    # Local import avoids a module cycle during worker startup. The control
    # plane remains the authoritative cancellation source.
    from app.control_plane_client import client

    return client.is_cancel_requested(uuid.UUID(scan_run_id))


def _set_current_activity(scan_run_id: str, tool: str, target: str) -> None:
    """REQ-FIDELITY-006: best effort - a telemetry failure must never affect
    tool execution. Local import avoids a module cycle during worker startup
    (same reasoning as _cancel_requested)."""
    from app.control_plane_client import client

    try:
        client.update_scan_run(uuid.UUID(scan_run_id), current_tool=tool, current_target=target)
    except Exception:  # noqa: BLE001
        pass


def _clear_current_activity(scan_run_id: str) -> None:
    from app.control_plane_client import client

    try:
        client.update_scan_run(uuid.UUID(scan_run_id), current_tool=None, current_target=None)
    except Exception:  # noqa: BLE001
        pass


def _cancelled_result(reason: str = "cancelled_by_operator") -> dict:
    return {
        "stdout": "",
        "stderr": reason,
        "exit_code": -1,
        "success": False,
        "error_reason": reason,
    }


# REQ-AUDIT-003: bound before durable, hash-chained storage. Generous enough
# for a real ffuf/nuclei invocation, small enough that a pathological argument
# set cannot bloat the audit table.
AUDIT_COMMAND_MAX_CHARS = 4000


def _audit_invocation(builder, target: str, args: dict, *, endpoint: str | None = None) -> str | None:
    """Render the invocation for the audit trail (REQ-AUDIT-003/004).

    Calls the SAME builder used for execution, but with redacted args - so the
    logged invocation cannot drift from the executed one (no second,
    hand-maintained rendering to keep in sync), while secrets never reach
    storage. Best-effort by contract: capturing the invocation must never
    change the tool's outcome, so any failure here yields None rather than
    propagating.
    """
    try:
        rendered = builder(target, command_redaction.redact_args(args))
        if not isinstance(rendered, str):
            # HexStrike-endpoint builders return a dict body; render it
            # deterministically and prefix the endpoint that received it.
            rendered = f"POST {endpoint} {json.dumps(rendered, sort_keys=True, default=str)}"
        return rendered[:AUDIT_COMMAND_MAX_CHARS]
    except Exception:  # noqa: BLE001 - telemetry must never break execution
        logger.warning("could not render audit invocation for %s", target, exc_info=True)
        return None


class ToolRunnerClient:
    @staticmethod
    def raw_network_available() -> bool:
        if RAW_NETWORK_MODE == "scope-restricted":
            return True  # Kubernetes NetworkPolicy mode.
        if RAW_NETWORK_MODE != "lease-gateway":
            return False
        from app.raw_egress_client import raw_egress_gateway
        return raw_egress_gateway.available()

    def __init__(self, base_url: str = TOOL_RUNNER_URL, timeout: float = 320.0):
        # 320s: nuclei/testssl laufen mit vielen Templates/Checks durch den
        # Proxy laenger als 120s; deckt sich mit max_runtime_seconds=300 in der
        # Registry + HexStrikes COMMAND_TIMEOUT (300s).
        # REQ-HARDEN-001: attach the runner shared secret as a default header so
        # EVERY request (tool dispatch and process termination alike) is
        # authenticated by the execution boundary.
        default_headers = {"X-ASM-Runner-Token": RUNNER_API_TOKEN} if RUNNER_API_TOKEN else None
        self._client = httpx.Client(base_url=base_url, timeout=timeout, headers=default_headers)

    def _terminate_scan_run(self, scan_run_id: str, result_queue: Queue) -> None:
        """Ask the isolated runner to kill only processes tagged with this run.

        Registration races are handled by retrying for a short bounded window:
        cancellation can arrive after the HTTP request but just before Popen.
        """
        deadline = time.monotonic() + CANCEL_TERMINATE_GRACE_SECONDS
        endpoint = f"/api/processes/terminate-scan-run/{scan_run_id}"
        while time.monotonic() < deadline:
            try:
                response = self._client.post(endpoint)
                response.raise_for_status()
                if int(response.json().get("terminated_count") or 0) > 0:
                    return
            except Exception:  # noqa: BLE001 - retry registration/control races
                pass
            try:
                result_queue.get_nowait()
                return
            except Empty:
                time.sleep(0.1)

    def _post_cancellable(self, path: str, payload: dict, scan_run_id: str | None):
        headers = {"X-ASM-Scan-Run-ID": scan_run_id} if scan_run_id else None
        if scan_run_id is None:
            return self._client.post(path, json=payload, headers=headers)

        result_queue: Queue = Queue(maxsize=1)

        def dispatch() -> None:
            try:
                result_queue.put(("response", self._client.post(path, json=payload, headers=headers)))
            except BaseException as exc:  # noqa: BLE001 - transferred to caller thread
                result_queue.put(("error", exc))

        threading.Thread(target=dispatch, name=f"tool-{scan_run_id}", daemon=True).start()
        consecutive_status_failures = 0
        while True:
            try:
                kind, value = result_queue.get(timeout=CANCEL_POLL_SECONDS)
            except Empty:
                try:
                    cancelled = _cancel_requested(scan_run_id)
                except Exception:  # noqa: BLE001
                    consecutive_status_failures += 1
                    if consecutive_status_failures >= CANCEL_STATUS_FAILURE_TOLERANCE:
                        # Sustained unavailability, not a single blip -> fail
                        # closed (REQ-FIDELITY-001).
                        self._terminate_scan_run(scan_run_id, result_queue)
                        return _cancelled_result("cancellation_status_unavailable")
                    continue
                consecutive_status_failures = 0
                if cancelled:
                    self._terminate_scan_run(scan_run_id, result_queue)
                    return _cancelled_result()
                continue
            if kind == "error":
                raise value
            return value

    def run(
        self, tool: str, target: str, args: dict | None = None, *,
        scan_run_id: str | None = None, engagement_id: str | None = None,
    ) -> dict:
        """Execute one gateway-authorized tool with bounded in-flight cancel.

        A run-tagged request is polled against authoritative control-plane state.
        On stop (or unknown stop state), the matching HexStrike process group is
        terminated; unrelated runs in the shared runner are never targeted.

        `engagement_id`, when given, is used ONLY to look up whether this is a
        bug-bounty engagement needing self-identification injected into HTTP-
        proxied tool calls (GitHub issue #12) - never passed to the tool-runner
        itself. Injected into a COPY of `args`, never the caller's own dict, and
        never something an agent proposal could itself set: these keys are added
        here, strictly after the Scope Gateway already authorized the caller's
        original args.
        """
        args = args or {}
        if engagement_id and tool in _HTTP_PROXIED_TOOLS:
            ident = _bounty_ident_for(engagement_id)
            if ident:
                args = {
                    **args,
                    "_bounty_ident_header_name": ident["ident_header_name"],
                    "_bounty_ident_header_value": ident["ident_header_value"],
                    "_bounty_ua_suffix": ident.get("ua_suffix"),
                    "_bounty_max_rps": ident.get("max_rps"),
                }
        if tool in ("nmap", "redis-probe", "activemq-banner", "activemq-openwire-probe") and not self.raw_network_available():
            return {
                "stdout": "", "stderr": "raw network egress is not enabled for this deployment",
                "exit_code": -1, "success": False, "error_reason": "raw_egress_unavailable",
            }
        if tool in _COMMANDS:
            command = _COMMANDS[tool](target, args)
            endpoint = "/api/command"
            payload = {"command": command, "use_cache": False}
            audit_command = _audit_invocation(_COMMANDS[tool], target, args)
        else:
            endpoint, body_fn = _ENDPOINTS.get(tool, (None, None))
            if endpoint is None:
                raise ValueError(f"tool_runner_client: kein HexStrike-Endpunkt-Mapping fuer '{tool}'")
            payload = body_fn(target, args)
            # No literal command exists for these - HexStrike builds the CLI
            # server-side from this body, so the body IS the invocation spec
            # (REQ-AUDIT-003).
            audit_command = _audit_invocation(body_fn, target, args, endpoint=endpoint)
        if scan_run_id:
            _set_current_activity(scan_run_id, tool, target)
        try:
            resp = self._post_cancellable(endpoint, payload, scan_run_id)
            if isinstance(resp, dict):
                # Cancelled mid-flight: the invocation still ran, so it is still
                # what the operator needs to see (REQ-AUDIT-003).
                return {**resp, "command": audit_command}
            resp.raise_for_status()
            raw = resp.json()
            if "error" in raw and "stdout" not in raw:
                return {
                    "stdout": "", "stderr": str(raw["error"]), "exit_code": -1,
                    "success": False, "error_reason": "runner_error",
                    "command": audit_command,
                }
            result = {
                "stdout": raw.get("stdout", ""),
                "stderr": raw.get("stderr", ""),
                "exit_code": raw.get("return_code", -1 if not raw.get("success") else 0),
                "success": bool(raw.get("success", False)),
                "error_reason": None,
                "command": audit_command,
            }
            if result["exit_code"] not in (0, None):
                result["success"] = False
                result["error_reason"] = "nonzero_exit"
            evidence = f"{result['stdout']}\n{result['stderr']}".lower()
            proxy_failures = (
                "audit_unavailable", "proxy_capacity_exhausted", "missing_engagement_id_header",
                "no_engagement_for_host", "ambiguous_host", "out_of_scope_deny",
                # REQ-FIDELITY-007: Port-Scope-Ablehnung des Egress-Proxy (REQ-FIDELITY-005).
                "out_of_scope_port",
                "received http code 503 from proxy", "received http code 407 from proxy",
                "received http code 409 from proxy", "received http code 403 from proxy",
            )
            if any(token in evidence for token in proxy_failures):
                # Multi-Request-Tools (nuclei/nikto/ffuf) sehen bei Proxy-Rate-Limiting
                # einzelne 407, liefern aber trotzdem gueltige Ergebnisse. Nur als
                # Egress-Block werten, wenn das Tool KEIN verwertbares Ergebnis lieferte
                # (nonzero exit ODER leerer stdout). Sonst ist es Rate-Limiting einzelner
                # Requests, kein Block des gesamten Scans - ein erfolgreicher Lauf mit
                # Funden darf nicht als "egress blocked" verworfen werden (REQ-EGRESS-002:
                # ein Block ist ein Fehler, ein erfolgreicher Teil-Scan ist keiner).
                produced_result = result["exit_code"] in (0, None) and bool(result["stdout"].strip())
                if not produced_result:
                    result["success"] = False
                    result["error_reason"] = "egress_proxy_blocked"
            if tool == "nmap":
                if "failed to resolve" in evidence:
                    result["success"] = False
                    result["error_reason"] = "dns_resolution_failed"
                elif "no targets were specified" in evidence or "0 ip addresses" in evidence:
                    result["success"] = False
                    result["error_reason"] = "zero_targets_scanned"
            if not result["success"] and not result["error_reason"]:
                result["error_reason"] = "runner_reported_failure"
            return result
        finally:
            if scan_run_id:
                _clear_current_activity(scan_run_id)


tool_runner = ToolRunnerClient()
