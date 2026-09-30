"""Capability-Registry: die EINZIGE Quelle der Wahrheit fuer Tools.

Bisher waren die Guardrails ueber vier Stellen verstreut (Build-Allowlist im
runner.Dockerfile, WHITELIST in authorize.py, Validatoren in args_safety.py,
tool_grant-Zeilen). Diese Registry buendelt die Tool-Metadaten an EINER Stelle
und treibt daraus ab:

  - die Laufzeit-Whitelist des Scope Gateways (enabled_whitelist)
  - die Argument-Haertung (validate_args, delegiert an args_safety)
  - die maschinenlesbare Capability-Matrix (capability_matrix) fuer Worker,
    UI und Docs

Der "Capability-Funnel" aus docs/kali-tools-capability-analysis-handoff.md
wird hier als Daten explizit: ein Tool ist erst dann voll einsatzfaehig, wenn
es installiert UND freigegeben UND (bei aktiven Tools) im Worker gemappt UND
in einer Scan-Phase dispatcht UND geparst ist. Die booleschen Felder machen
jede Stufe sichtbar - kein "installiert == nutzbar"-Trugschluss.

Sicherheitshinweis: Diese Registry ist ein Katalog + Ableitungsschicht. Die
verbindliche Entscheidung faellt weiterhin deterministisch im Scope Gateway
(authorize.py), das die hier abgeleitete Whitelist konsumiert.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from app.gateway import args_safety

# Ausfuehrungsklasse bestimmt den Egress-Enforcement-Pfad:
#   raw_network : direkte TCP/Raw-Verbindung -> signierter Compose-Lease mit
#                 nftables oder K8s-NetworkPolicy aus materialisierten IPs
#   http_proxy  : HTTP(S)-Tool -> muss den Egress-Proxy explizit nutzen (proxy_flag)
#   passive     : rein passiv/OSINT ueber externe APIs/DNS (kein Ziel-Egress
#                 im Scan-Sinn, z. B. subfinder/amass/crt.sh)
EXECUTION_CLASSES = {"raw_network", "http_proxy", "passive"}
CATEGORIES = {"recon", "fingerprint", "vuln", "cred", "exploit"}


@dataclass(frozen=True)
class ToolSpec:
    name: str
    category: str                       # recon|fingerprint|vuln|cred|exploit
    execution_class: str                # raw_network|http_proxy|passive
    installed: bool                     # im runner.Dockerfile-Build-Allowlist
    default_enabled: bool               # Teil der Laufzeit-Whitelist
    hexstrike_endpoint: str | None = None   # /api/tools/... (None = kein HexStrike-Tool)
    worker_mapped: bool = False         # in worker/app/tool_runner_client.py gemappt
    dispatched: bool = False            # wird heute von einer Scan-Phase aufgerufen
    proxy_flag: str | None = None       # expliziter Proxy-Parameter (http_proxy-Tools)
    proxy_verified: bool = False        # proxy_flag praktisch bestaetigt?
    parser: str | None = None           # Modul/Funktion, das Output -> Findings/Services macht
    max_runtime_seconds: int = 120
    arg_validator: Callable[[dict], bool] | None = None
    # False = only the deterministic pipeline may call this tool; the gateway
    # denies it for phase "agent" and the Vector Agent is never offered it
    # (REQ-COVER-007).
    agent_callable: bool = True
    notes: str = ""


# --- Der Katalog ----------------------------------------------------------
# Ehrliche Ist-Werte (Stand: docs/kali-tools-capability-analysis-handoff.md).
# worker_mapped/dispatched/parser bilden die REALITAET ab, nicht den Wunsch -
# so bleibt die Registry auch als Fortschrittskarte ehrlich.

_SPECS: list[ToolSpec] = [
    # --- recon (passiv/OSINT) ---
    # REQ-COVER-001: runs in the WORKER image (user-approved exception to "the
    # worker runs no tool binaries": it only talks to third-party sources over
    # the OSINT egress). Never via the runner, hence no worker_mapped and no
    # hexstrike endpoint; discovery asks the gateway (recon/passive) before
    # every run. Not offered to the agent.
    ToolSpec("subfinder", "recon", "passive", installed=True, default_enabled=True,
             hexstrike_endpoint=None, worker_mapped=False, dispatched=False,
             parser="subfinder", agent_callable=False,
             arg_validator=args_safety._subfinder_args_safe,
             notes="passive subdomain sources, run in the worker image by discovery (REQ-COVER-001); "
                   "per-engagement switch subfinder_enabled"),
    ToolSpec("amass", "recon", "passive", installed=True, default_enabled=False,
             hexstrike_endpoint="/api/tools/amass", worker_mapped=True, dispatched=False,
             parser=None, notes="mapped, not yet orchestrated into any phase"),
    ToolSpec("dnsx", "recon", "passive", installed=False, default_enabled=False,
             notes="whitelisted, but NOT in the image (the Dockerfile installs dnsutils, not projectdiscovery/dnsx)"),
    ToolSpec("tlsx", "recon", "passive", installed=False, default_enabled=False,
             notes="whitelisted, but NOT in the image"),

    # --- fingerprint ---
    ToolSpec("nmap", "fingerprint", "raw_network", installed=True, default_enabled=True,
             hexstrike_endpoint="/api/tools/nmap", worker_mapped=True, dispatched=True,
             proxy_flag=None, parser="nmap_xml", max_runtime_seconds=300,
             arg_validator=args_safety._nmap_args_safe,
             notes="configured TCP and opt-in targeted UDP via signed Compose lease/nftables or generated K8s NetworkPolicy"),
    ToolSpec("httpx", "fingerprint", "http_proxy", installed=True, default_enabled=True,
             hexstrike_endpoint="/api/command", worker_mapped=True, dispatched=True,
             proxy_flag="-proxy", proxy_verified=True, parser="httpx",
             arg_validator=args_safety._httpx_args_safe,
             notes="via /api/command (HexStrike's /api/tools/httpx uses -l = file list, broken "
                   "for single hosts); symlink httpx-toolkit->httpx in the image; liveness + tech"),
    # REQ-COVER-003: pipeline-only crawler (fingerprint baseline), through the
    # egress proxy under the rate policy; depth/pages/time are worker constants.
    ToolSpec("katana", "fingerprint", "http_proxy", installed=True, default_enabled=True,
             hexstrike_endpoint="/api/command", worker_mapped=True, dispatched=True,
             proxy_flag="-proxy", proxy_verified=False, parser="katana", max_runtime_seconds=120,
             arg_validator=args_safety._no_args, agent_callable=False,
             notes="crawler, one host per call, no headless mode; per-engagement switch crawling_enabled "
                   "(REQ-COVER-003/007)"),
    # REQ-COVER-006: one page load per live web service through the egress proxy.
    ToolSpec("screenshot", "fingerprint", "http_proxy", installed=True, default_enabled=True,
             hexstrike_endpoint="/api/command", worker_mapped=True, dispatched=True,
             proxy_flag="--proxy-server", proxy_verified=False, parser="screenshot", max_runtime_seconds=60,
             arg_validator=args_safety._no_args, agent_callable=False,
             notes="headless Chromium screenshot via the egress proxy; per-engagement switch "
                   "screenshots_enabled; denied for bug-bounty engagements (REQ-COVER-006/007)"),
    ToolSpec("whatweb", "fingerprint", "http_proxy", installed=True, default_enabled=False,
             hexstrike_endpoint=None, worker_mapped=False, dispatched=False,
             proxy_flag="--proxy", proxy_verified=False, parser=None,
             notes="installed + whitelisted, but neither mapped in the client nor dispatched"),
    ToolSpec("wafw00f", "fingerprint", "http_proxy", installed=True, default_enabled=True,
             hexstrike_endpoint="/api/tools/wafw00f", worker_mapped=True, dispatched=True,
             proxy_flag="-p", proxy_verified=True, parser="wafw00f",
             notes="proven end to end (egress proxy + WAF info finding)"),
    ToolSpec("sslscan", "fingerprint", "raw_network", installed=True, default_enabled=False,
             hexstrike_endpoint=None, worker_mapped=False, dispatched=False,
             parser=None, notes="direct TLS connection; raw egress like nmap, cannot go through the HTTP proxy"),
    ToolSpec("testssl", "fingerprint", "http_proxy", installed=True, default_enabled=True,
             hexstrike_endpoint="/api/command", worker_mapped=True, dispatched=True,
             proxy_flag="--proxy", proxy_verified=True, parser="testssl", max_runtime_seconds=600,
             arg_validator=args_safety._testssl_args_safe,
             notes="testssl.sh from Git in the image; --proxy (HTTP CONNECT) -> runs through the "
                   "egress proxy like nikto; TLS/certificate hygiene, --fast --severity LOW. REQ-PIPE-009: "
                   "also runs on non-web TLS services (mail, LDAP, ...), with --starttls where the "
                   "protocol upgrades to TLS; the STARTTLS protocol is a fixed set."),
    # REQ-AGENT-025: curated, non-agent-composed raw-protocol probes for
    # services the HTTP-only toolkit above cannot touch at all - found live
    # 2026-08-04, Vulhub Redis/ActiveMQ scored zero findings for exactly this
    # structural reason. Both dispatch via /api/command (a worker-built
    # python3 one-liner, same pattern as httpx/testssl/http_request/ffuf
    # below - no new tool-runner image/route needed) but, unlike those, go
    # through the SAME signed raw-egress lease/nftables path as nmap
    # (execution_class="raw_network") rather than the HTTP egress-proxy - a
    # raw TCP connect cannot traverse an HTTP proxy. Zero agent-composed
    # bytes ever: the exact bytes sent (or none) are a fixed, server-side
    # registry entry per protocol (worker/app/raw_tcp_probe.py), keyed by
    # tool name, not by any agent-supplied argument.
    ToolSpec("redis-probe", "fingerprint", "raw_network", installed=True, default_enabled=True,
             hexstrike_endpoint="/api/command", worker_mapped=True, dispatched=True,
             parser="raw_tcp_probe", max_runtime_seconds=15,
             arg_validator=args_safety._raw_tcp_probe_args_safe,
             notes="read-only Redis PING (RESP), single-port raw-egress lease (port_profile=raw_tcp_probe); "
                   "confirms reachability + whether auth is enforced, never more"),
    ToolSpec("activemq-banner", "fingerprint", "raw_network", installed=True, default_enabled=True,
             hexstrike_endpoint="/api/command", worker_mapped=True, dispatched=True,
             parser="raw_tcp_probe", max_runtime_seconds=15,
             arg_validator=args_safety._raw_tcp_probe_args_safe,
             notes="purely passive - sends nothing, reads the OpenWire broker's own self-announced "
                   "WireFormatInfo greeting; single-port raw-egress lease (port_profile=raw_tcp_probe)"),

    # --- vuln ---
    # REQ-AGENT-027: unlike the two passive raw-network probes above, this
    # ACTIVELY sends a curated OpenWire deserialization-RCE probe - "vuln"
    # category, not "fingerprint". default_enabled=True matches http_request
    # below: the safety gate is the MANDATORY per-call operator approval
    # (authorize.py's hardcoded state_changing check), not this flag - being
    # enabled only means the agent may PROPOSE it, every actual invocation
    # still requires a fresh human decision.
    ToolSpec("activemq-openwire-probe", "vuln", "raw_network", installed=True, default_enabled=True,
             hexstrike_endpoint="/api/command", worker_mapped=True, dispatched=True,
             parser="raw_tcp_probe", max_runtime_seconds=30,
             arg_validator=args_safety._raw_tcp_probe_args_safe,
             notes="curated, non-agent-composed OpenWire deserialization probe (CVE-2023-46604 class); "
                   "single-port raw-egress lease (port_profile=raw_tcp_probe); proof requires the target "
                   "to fetch a single-use callback URL we host, polled within a bounded wait"),
    ToolSpec("nuclei", "vuln", "http_proxy", installed=True, default_enabled=True,
             hexstrike_endpoint="/api/tools/nuclei", worker_mapped=True, dispatched=True,
             proxy_flag="-proxy", proxy_verified=True, parser="nuclei", max_runtime_seconds=300,
             arg_validator=args_safety._nuclei_args_safe,
             notes="templates baked in at build time (/opt/nuclei-templates, -disable-update-check); "
                   "-proxy through the egress proxy; conservative (non-intrusive, -etags dos/intrusive/fuzz/"
                   "csp-bypass, rate limit). REQ-AGENT-018: runs in TWO passes (main non-headless + "
                   "mini headless for domxss only), because HexStrike's command executor hard-kills EVERY "
                   "call at 300s (not overridable per call) - a combined headless + full run exceeded "
                   "that live. Each pass stays under 300s on its own; see worker _nuclei_body."),
    ToolSpec("nikto", "vuln", "http_proxy", installed=True, default_enabled=True,
             hexstrike_endpoint="/api/tools/nikto", worker_mapped=True, dispatched=True,
             proxy_flag="-useproxy", proxy_verified=True, parser="nikto_missing_headers",
             max_runtime_seconds=60,
             notes="REQ-PIPE-013: retired from the automatic scan pipeline - it always stopped at its 40 s "
                   "budget (truncated) and its useful checks overlap nuclei's generic templates; missing "
                   "security headers now come from the response headers httpx records. Still available on "
                   "demand to the agent. Proven end to end (egress proxy + findings)."),
    # Agent-gesteuertes rohes HTTP-Lesen (beliebige Header/Pfad, safe methods)
    # durch den Egress-Proxy - Fundament fuer autonomes Pentesting: der Vector
    # Agent formt gezielte Requests (z. B. Auth-Header enumerieren) und bekommt
    # die VOLLE Antwort zur Klassifikation (Auth-Bypass, PII-Exposure) zurueck.
    # Scope wird im Gateway erzwungen; der nicht-destruktive envelope
    # (nur GET/HEAD/OPTIONS) in args_safety._http_request_args_safe.
    ToolSpec("http_request", "vuln", "http_proxy", installed=True, default_enabled=True,
             hexstrike_endpoint="/api/command", worker_mapped=True, dispatched=True,
             proxy_flag="-x", proxy_verified=False, parser="http_response",
             max_runtime_seconds=30, arg_validator=args_safety._http_request_args_safe,
             notes="raw HTTP read access via curl (generic /api/command) through the egress proxy; full response to the LLM"),
    # Content-Discovery/Enumeration (Burp-Intruder-Aequivalent, das ins Modell
    # passt): ffuf leistet die Fleissarbeit, der Vector Agent KURATIERT
    # (kontextpassende SecLists-Wortliste + wenige eigene Kandidaten). Feuert
    # viele Requests unter EINER Gateway-Freigabe - Scope wird pro Request am
    # Egress-Proxy erzwungen, Rate ueber die Scan-Policy (genau wie nikto/nuclei).
    ToolSpec("ffuf", "vuln", "http_proxy", installed=True, default_enabled=True,
             hexstrike_endpoint="/api/command", worker_mapped=True, dispatched=True,
             proxy_flag="-x", proxy_verified=False, parser="ffuf", max_runtime_seconds=120,
             arg_validator=args_safety._ffuf_args_safe,
             notes="curated content discovery via ffuf + SecLists through the egress proxy; "
                   "wordlist only by allowlist key, non-destructive, rate-limited"),

    # --- cred (nur mit Freigabe + Einzelbestaetigung) ---
    ToolSpec("default-cred-check", "cred", "http_proxy", installed=True, default_enabled=False,
             hexstrike_endpoint=None, worker_mapped=False, dispatched=False,
             parser=None, arg_validator=args_safety._default_cred_check_args_safe,
             notes="only vendor-documented default logins, at most 3 attempts; not wired yet"),

    # --- exploit (bewusst leer im Startangebot) ---
]

REGISTRY: dict[str, ToolSpec] = {s.name: s for s in _SPECS}


# --- Ableitungen ----------------------------------------------------------

def get(name: str) -> ToolSpec | None:
    return REGISTRY.get(name)


def agent_dispatchable() -> set[str]:
    """Tools, die der Worker fuer Agent-Vorschlaege tatsaechlich ausfuehren kann
    (dispatched=True). Die EINE Quelle dafuer, was dem Vector Agent als
    verfuegbar gemeldet werden darf (REQ-TOOL-004) - haelt die dispatch-Realitaet
    des Workers und das Agent-Angebot synchron."""
    return {name for name, spec in REGISTRY.items() if spec.dispatched and spec.agent_callable}


def enabled_whitelist() -> dict[str, set[str]]:
    """Laufzeit-Whitelist des Scope Gateways, abgeleitet aus der Registry.

    Ein Tool ist erlaubt, wenn default_enabled=True. Jede Kategorie ist immer
    vertreten (auch leer), damit das Gateway 'category not in WHITELIST' nie
    faelschlich als 'erlaubt' interpretiert."""
    wl: dict[str, set[str]] = {c: set() for c in CATEGORIES}
    for spec in REGISTRY.values():
        if spec.default_enabled:
            wl[spec.category].add(spec.name)
    return wl


def validate_args(tool: str, args: dict) -> bool:
    """Argument-Haertung ueber die Registry. Tools ohne eigenen Validator sind
    konservativ nur mit leeren Argumenten zulaessig (fail-closed)."""
    spec = REGISTRY.get(tool)
    if spec is None or spec.arg_validator is None:
        return not args
    return spec.arg_validator(args)


def enabled_but_not_installed() -> list[str]:
    """Konsistenz-Warnung: freigegeben, aber nicht im Runner-Image - das
    Gateway wuerde den Call erlauben, der Runner kann ihn nicht ausfuehren."""
    return sorted(s.name for s in REGISTRY.values() if s.default_enabled and not s.installed)


def capability_matrix() -> list[dict]:
    """Maschinenlesbarer Capability-Funnel (fuer Worker/UI/Docs)."""
    rows = []
    for spec in sorted(REGISTRY.values(), key=lambda s: (s.category, s.name)):
        rows.append({
            "name": spec.name,
            "category": spec.category,
            "execution_class": spec.execution_class,
            "installed": spec.installed,
            "enabled": spec.default_enabled,
            "worker_mapped": spec.worker_mapped,
            "dispatched": spec.dispatched,
            "has_parser": spec.parser is not None,
            "proxy_flag": spec.proxy_flag,
            "proxy_verified": spec.proxy_verified,
            "max_runtime_seconds": spec.max_runtime_seconds,
            "notes": spec.notes,
        })
    return rows
