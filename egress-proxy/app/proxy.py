"""Egress-Proxy: Netzwerk-Scope-Enforcement (Deployment-Architektur Kap. 6).

Jeder ausgehende Scan-Request (vom tool-runner-Pod) laeuft ueber diesen
Proxy. Er ist der einzige Weg nach draussen (NetworkPolicy, Deployment Kap.
5.2) und prueft scope_asset ein zweites Mal, unabhaengig vom Scope Gateway
in der control-plane.

Engagement-Zuordnung - zwei Modi:
  (a) Per-Engagement-Proxy (ASM_ENGAGEMENT_ID gesetzt): der Proxy laeuft
      scoped auf GENAU einen Auftrag. Entspricht dem ephemeren Modell der
      K8s-Jobs (Deployment Kap. 5.1: ein Runner + Proxy pro engagement) und
      ermoeglicht rohe HTTP-Tools (nikto, nuclei, httpx), die den Proxy
      ueber -useproxy nutzen, ohne einen Custom-Header senden zu koennen.
  (b) Multiplex-Proxy (kein ASM_ENGAGEMENT_ID): der Client (MCP-Runner) muss
      pro Request 'X-ASM-Engagement-Id: <uuid>' senden. Ohne beides ->
      407 (fail-closed).

Bei TLS-Tunneln (CONNECT) ist der Payload fuer den Proxy opak; die Pflicht-
Ident-Header-Injektion fuer source='bug_bounty' (Kap. 3.5, Listing 6b) erfolgt
daher auf Anwendungsebene im MCP-Runner, nicht hier. Fuer Klartext-HTTP
injiziert dieser Proxy den Header selbst (s. _forward_plain_http).
"""

from __future__ import annotations

import asyncio
import datetime as dt
import fnmatch
import ipaddress
import logging
import math
import os
import time
import uuid
from urllib.parse import urlsplit

from app.audit_client import submit_audit
from app.ssrf_guard import BlockedAddressError, vet_target_host
from app.db import (
    active_engagements_for_materialized_ip,
    bounty_program_for,
    candidate_engagements,
    is_materialized_ip,
    load_engagement,
    matching_scope_assets,
    recent_allowed_count,
)

logger = logging.getLogger(__name__)

PROXY_PORT = int(os.environ.get("EGRESS_PROXY_PORT", "3128"))
RELAY_CHUNK = 65536
MAX_CONCURRENT_CLIENTS = max(1, min(int(os.environ.get("EGRESS_MAX_CONCURRENT_CLIENTS", "64")), 512))
_CLIENT_SLOTS = asyncio.Semaphore(MAX_CONCURRENT_CLIENTS)

# GitHub issue #30: BountyProgram.max_concurrency enforcement. A plain dict
# keyed by engagement_id, not asyncio.Semaphore(max_concurrency) - a
# program's max_concurrency isn't known (it requires a DB read) until a
# request for that engagement first arrives, and asyncio.Semaphore's limit
# is fixed at construction. Safe without an explicit lock: every mutation
# below is a single synchronous dict read-then-write with no `await` inside
# it, and asyncio only switches tasks at an await point - the same
# reasoning _CLIENT_SLOTS' own Semaphore relies on internally.
_concurrency_in_flight: dict[str, int] = {}


def _try_acquire_concurrency_slot(engagement_id: str, max_concurrency: int) -> bool:
    current = _concurrency_in_flight.get(engagement_id, 0)
    if current >= max_concurrency:
        return False
    _concurrency_in_flight[engagement_id] = current + 1
    return True


def _release_concurrency_slot(engagement_id: str) -> None:
    current = _concurrency_in_flight.get(engagement_id, 0)
    if current <= 1:
        _concurrency_in_flight.pop(engagement_id, None)
    else:
        _concurrency_in_flight[engagement_id] = current - 1

# Per-Engagement-Modus (a): wenn gesetzt, ist dieser Proxy fest an einen
# Auftrag gebunden und braucht keinen X-ASM-Engagement-Id-Header pro Request.
DEFAULT_ENGAGEMENT_ID = os.environ.get("ASM_ENGAGEMENT_ID") or None


def _matches_host(host: str, asset: dict) -> bool:
    if asset["asset_type"] == "domain":
        h = host.lower().rstrip(".")
        domain = asset["value"].lower().rstrip(".")
        return h == domain or h.endswith("." + domain)
    if asset["asset_type"] == "wildcard":
        return fnmatch.fnmatch(host.lower(), asset["value"].lower())
    if asset["asset_type"] in ("ip", "cidr"):
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(asset["value"], strict=False)
        except ValueError:
            return False
    return False


def _effective_rate_window(max_rps: float) -> float:
    """GitHub issue #19: mirrors control-plane/app/gateway/authorize.py's own
    copy (deliberately duplicated, not imported - same defense-in-depth
    reasoning as _matches_host's own cross-reference comment). A fixed
    1-second window cannot express "less than 1 request per second" - widen
    the lookback window to ceil(1/max_rps) seconds when max_rps < 1, so
    "allowed" means "zero allowed calls in the last N seconds", the only way
    an integer count can express a sub-1 rate."""
    return 1.0 if max_rps >= 1 else math.ceil(1.0 / max_rps)


def _effective_port_range(asset: dict, eng: dict) -> tuple[int, int]:
    """REQ-PORTSCOPE-002: an asset with no port override inherits the
    ceiling in full; one that has an override is intersected with the
    ceiling (never used raw) so a ceiling narrowed after the fact still
    applies without touching the asset row."""
    ceiling_from, ceiling_to = eng["tcp_port_from"], eng["tcp_port_to"]
    if asset.get("port_from") is None:
        return ceiling_from, ceiling_to
    return max(ceiling_from, asset["port_from"]), min(ceiling_to, asset["port_to"])


async def resolve_engagement_for_host(host: str) -> tuple[str | None, str]:
    """Host-basierte Engagement-Aufloesung (REQ-EGRESS-001), wenn weder
    ASM_ENGAGEMENT_ID noch der Header vorliegt: die EINE aktive Engagement, deren
    allow-Scope den Host matcht und deren deny-Scope ihn NICHT matcht. Mehrdeutig
    (>1) oder keine -> None (fail-closed). Reine Auswahl - evaluate() erzwingt
    danach weiterhin die volle Kette.

    GitHub issue #28: candidate_engagements()/active_engagements_for_materialized_ip()
    are blocking SQLAlchemy calls - run off the event loop (asyncio.to_thread)
    so one slow query does not stall every other in-flight connection on this
    proxy, not just its own.
    """
    matches: set[str] = set()
    for eng in await asyncio.to_thread(candidate_engagements):
        if any(_matches_host(host, a) for a in eng["deny"]):
            continue
        if any(_matches_host(host, a) for a in eng["allow"]):
            matches.add(eng["engagement_id"])

    # Verbindet ein Tool per IP (z. B. testssl --ip mit der materialisierten IP),
    # matcht kein Domain-scope_asset. Dann ueber die auditierte Materialisierung
    # (resolved_host) aufloesen - deny-Vorrang erzwingt evaluate() danach ohnehin.
    try:
        ipaddress.ip_address(host)
        matches.update(await asyncio.to_thread(active_engagements_for_materialized_ip, host))
    except ValueError:
        pass

    if len(matches) == 1:
        return next(iter(matches)), "host"
    if len(matches) > 1:
        return None, "ambiguous_host"
    return None, "no_engagement_for_host"


async def evaluate(engagement_id: str, host: str, path: str, port: int) -> tuple[bool, str]:
    """Spiegelt Listing 5 (on_request) der Deployment-Architektur Kap. 6.2.

    REQ-FIDELITY-005: das Engagement-TCP-Portfenster (tcp_port_from/to) war bis
    hierher nur eine Bauanleitung fuer Tool-Kommandos (nmap -p, Ziel-URLs) -
    diese Funktion ist der einzige unabhaengige Netzwerk-Enforcement-Punkt
    (Kap. 6.2), also muss sie den Port selbst durchsetzen, nicht nur den Host.

    GitHub issue #28: every DB call below runs via asyncio.to_thread - the
    underlying engine (app/db.py) is a plain synchronous SQLAlchemy engine,
    and calling it directly from this coroutine would block the WHOLE event
    loop (every other in-flight connection on this proxy, not just this
    request) for the duration of the query. This was previously ordinary
    Postgres latency waiting to become head-of-line blocking, not something
    that needed an attacker at all.
    """
    eng = await asyncio.to_thread(load_engagement, engagement_id)
    if eng is None:
        return False, "engagement_not_found"
    if eng["status"] != "active":
        return False, "engagement_not_active"

    now = dt.datetime.now(dt.timezone.utc)
    if not (eng["authorized_from"] <= now <= eng["authorized_until"]):
        return False, "outside_window"

    # deny hat IMMER Vorrang (out-of-scope-Schutz)
    deny_assets = await asyncio.to_thread(matching_scope_assets, engagement_id, host, path, "deny")
    if any(_matches_host(host, a) for a in deny_assets):
        return False, "out_of_scope_deny"

    allow_assets = await asyncio.to_thread(matching_scope_assets, engagement_id, host, path, "allow")
    matched_allow_assets = [a for a in allow_assets if _matches_host(host, a)]
    allowed_by_name = bool(matched_allow_assets)
    if not allowed_by_name:
        # Verbindet ein Tool direkt per IP (DNS lokal aufgeloest, z. B.
        # testssl --ip), ist die IP nur legitim, wenn sie aus einem in-scope-
        # Namen auditiert MATERIALISIERT wurde (resolved_host). deny-Vorrang
        # gilt bereits oben (auch fuer IP/CIDR-deny-Regeln).
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False
        if not (is_ip and await asyncio.to_thread(is_materialized_ip, engagement_id, host)):
            return False, "not_in_scope"

    # REQ-PORTSCOPE-002: each matched allow-asset's own range (if it has one)
    # is intersected with the engagement ceiling fresh here, never trusted
    # from the DB row alone - a ceiling narrowed after the asset was created
    # still applies immediately. Port is allowed if it falls in ANY matched
    # asset's effective range, mirroring "any allow match legitimizes the
    # host" above. The materialized-IP fallback (no specific matched asset)
    # keeps today's behavior: the ceiling alone.
    if matched_allow_assets:
        port_allowed = any(
            _effective_port_range(a, eng)[0] <= port <= _effective_port_range(a, eng)[1]
            for a in matched_allow_assets
        )
    else:
        port_allowed = eng["tcp_port_from"] <= port <= eng["tcp_port_to"]
    if not port_allowed:
        return False, "out_of_scope_port"

    if eng["source"] == "bug_bounty":
        prog = await asyncio.to_thread(bounty_program_for, engagement_id)
        if prog is None:
            return False, "bounty_program_missing"
        max_rps = float(prog["max_rps"])
        # GitHub issue #19: threshold and window both derived the same way as
        # the gateway's own copy - max(1, int(max_rps)) alone was the bug
        # (compared against a FIXED 1-second window regardless of max_rps, so
        # any max_rps < 1 still permitted 1 req/s: 2x-5x over the configured
        # limit for the fractional values a program can actually configure).
        window_seconds = _effective_rate_window(max_rps)
        threshold = max(1, int(max_rps))
        recent = await asyncio.to_thread(recent_allowed_count, engagement_id, window_seconds)
        if recent >= threshold:
            return False, "rate_limited"
        # GitHub issue #30: max_concurrency was configured, stored, and even
        # SELECTed here - but never enforced anywhere. In-memory, per-proxy-
        # instance counter (consistent with MAX_CONCURRENT_CLIENTS/
        # _CLIENT_SLOTS below); the caller acquires the actual slot for the
        # duration of the forwarded request/CONNECT tunnel (this check alone
        # is a read, not a reservation - see _try_acquire_concurrency_slot).
        max_concurrency = int(prog["max_concurrency"])
        if _concurrency_in_flight.get(engagement_id, 0) >= max_concurrency:
            return False, "concurrency_limit_exceeded"

    return True, "allow"


class RequestTooSlowError(Exception):
    pass


class RequestTooLargeError(Exception):
    pass


# GitHub issue #28: a client that opens a connection and dribbles a header
# byte per minute previously held its slot (one of MAX_CONCURRENT_CLIENTS)
# forever - no protocol-level deadline or size limit existed anywhere in
# this read path.
HEADER_READ_TIMEOUT_SECONDS = float(os.environ.get("EGRESS_HEADER_READ_TIMEOUT_SECONDS", "10"))
MAX_HEADER_COUNT = 100
MAX_HEADER_LINE_BYTES = 8192
MAX_TOTAL_HEADER_BYTES = 65536


async def _read_request_line_and_headers(reader: asyncio.StreamReader) -> tuple[str, dict[str, str]]:
    async def _read() -> tuple[str, dict[str, str]]:
        request_line = (await reader.readline()).decode("latin-1").strip()
        headers: dict[str, str] = {}
        total_bytes = len(request_line)
        while True:
            raw_line = await reader.readline()
            total_bytes += len(raw_line)
            if len(raw_line) > MAX_HEADER_LINE_BYTES or total_bytes > MAX_TOTAL_HEADER_BYTES:
                raise RequestTooLargeError("header_too_large")
            line = raw_line.decode("latin-1")
            if line in ("\r\n", "\n", ""):
                break
            if len(headers) >= MAX_HEADER_COUNT:
                raise RequestTooLargeError("too_many_headers")
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return request_line, headers

    try:
        return await asyncio.wait_for(_read(), timeout=HEADER_READ_TIMEOUT_SECONDS)
    except asyncio.TimeoutError as exc:
        raise RequestTooSlowError("header_read_timeout") from exc


async def _submit_audit_or_deny(
    writer: asyncio.StreamWriter, engagement_id: str, decision: str, reason: str, payload: dict
) -> bool:
    try:
        await asyncio.to_thread(submit_audit, engagement_id, decision, reason, payload)
        return True
    except Exception as exc:  # noqa: BLE001 - audit is a fail-closed legal control
        logger.error("audit submission failed for engagement %s: %s", engagement_id, exc)
        await _deny(writer, 503, "audit_unavailable")
        return False


# REQ-DISCO-002: marks a response this proxy generated ITSELF, so a tool
# downstream can tell the platform's own refusal apart from the target's
# answer. Found live: a scanned name was NXDOMAIN, this proxy answered every
# request with `403 Blocked` + `dns_resolution_failed`, and httpx/ffuf/nikto/
# nuclei all read that as the target responding - producing a phantom service
# and 1800 fabricated "discovered paths" for a host that does not exist.
#
# Set on responses this proxy synthesises and NEVER copied from an upstream
# response, so a target cannot forge it to suppress its own findings.
DENIAL_MARKER_HEADER = "X-ASM-Egress-Denied"


async def _deny(writer: asyncio.StreamWriter, code: int, reason: str) -> None:
    body = reason.encode()
    # Bound the header value: `reason` can carry an exception string
    # (connect_failed: ...), and a header must stay a single well-formed line.
    marker = str(reason).replace("\r", " ").replace("\n", " ")[:200]
    writer.write(
        f"HTTP/1.1 {code} Blocked\r\n"
        f"{DENIAL_MARKER_HEADER}: {marker}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
        + body
    )
    await writer.drain()


# GitHub issue #28: an established CONNECT tunnel with no traffic was never
# reaped - both bound only by the fixed MAX_CONCURRENT_CLIENTS slot pool,
# each slot holdable indefinitely.
RELAY_IDLE_TIMEOUT_SECONDS = float(os.environ.get("EGRESS_RELAY_IDLE_TIMEOUT_SECONDS", "300"))
RELAY_MAX_DURATION_SECONDS = float(os.environ.get("EGRESS_RELAY_MAX_DURATION_SECONDS", "1800"))


async def _relay(a_reader, a_writer, b_reader, b_writer) -> None:
    deadline = time.monotonic() + RELAY_MAX_DURATION_SECONDS

    async def pump(src, dst):
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    chunk = await asyncio.wait_for(
                        src.read(RELAY_CHUNK), timeout=min(RELAY_IDLE_TIMEOUT_SECONDS, remaining),
                    )
                except asyncio.TimeoutError:
                    break
                if not chunk:
                    break
                dst.write(chunk)
                await dst.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            dst.close()

    await asyncio.gather(pump(a_reader, b_writer), pump(b_reader, a_writer))


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    # Immediate fail-closed load shedding bounds open audit/target sockets. A
    # scanner receives explicit backpressure and may retry within its own
    # configured rate limits; traffic is never forwarded without capacity.
    if _CLIENT_SLOTS.locked():
        await _deny(writer, 503, "proxy_capacity_exhausted")
        writer.close()
        return
    async with _CLIENT_SLOTS:
        await _handle_client(reader, writer)


async def _handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    try:
        try:
            request_line, headers = await _read_request_line_and_headers(reader)
        except RequestTooSlowError:
            await _deny(writer, 408, "header_read_timeout")
            return
        except RequestTooLargeError as exc:
            await _deny(writer, 431, str(exc))
            return
        if not request_line:
            return
        parts = request_line.split(" ")
        if len(parts) < 2:
            await _deny(writer, 400, "bad_request")
            return
        method, target = parts[0], parts[1]

        # Ziel-Host frueh bestimmen - fuer die Host-basierte Engagement-Aufloesung.
        if method == "CONNECT":
            req_host = target.partition(":")[0]
        else:
            parsed = urlsplit(target if "://" in target else f"http://{headers.get('host', '')}{target}")
            req_host = parsed.hostname or headers.get("host", "").split(":")[0]

        # Engagement-Aufloesung (REQ-EGRESS-001), Reihenfolge:
        #   1. ASM_ENGAGEMENT_ID (per-Engagement-Proxy)  2. X-ASM-Engagement-Id-Header
        #   3. Host-basiert: die eine aktive Engagement, deren allow-Scope den Host matcht.
        engagement_id = DEFAULT_ENGAGEMENT_ID or headers.get("x-asm-engagement-id")
        if engagement_id:
            try:
                uuid.UUID(engagement_id)
            except ValueError:
                await _deny(writer, 400, "invalid_engagement_id")
                return
        else:
            engagement_id, why = await resolve_engagement_for_host(req_host)
            if engagement_id is None:
                # Kein Audit-Eintrag (kein gueltiges engagement_id fuer den FK); nur Log.
                logger.info("DENY %s %s from %s: %s", method, req_host, peer, why)
                await _deny(writer, 407 if why == "no_engagement_for_host" else 409, why)
                return

        if method == "CONNECT":
            host, _, port_str = target.partition(":")
            port = int(port_str or "443")
            allowed, reason = await evaluate(engagement_id, host, "/", port)
            # REQ-HARDEN-002: even an in-scope host must not resolve to a
            # never-legitimate address (loopback, link-local/cloud-metadata).
            # Fold the block into the single scope decision so it is audited as
            # one honest DENY, and pin the vetted IP to close the resolve-then-
            # connect DNS-rebinding window.
            connect_ip = host
            if allowed:
                try:
                    connect_ip = await asyncio.to_thread(vet_target_host, host, port)
                except BlockedAddressError as exc:
                    allowed, reason = False, exc.reason
            # GitHub issue #30: reserve the concurrency slot as part of the
            # same audited decision - a program's max_concurrency is checked
            # (read-only) inside evaluate() above, but the actual reservation
            # happens here so it can be released deterministically (finally,
            # below) once the tunnel closes, whatever the reason. Release is
            # always safe to call even when nothing was acquired (no-op).
            if allowed:
                eng_for_slot = await asyncio.to_thread(load_engagement, engagement_id)
                if eng_for_slot and eng_for_slot["source"] == "bug_bounty":
                    prog_for_slot = await asyncio.to_thread(bounty_program_for, engagement_id)
                    if prog_for_slot is not None and not _try_acquire_concurrency_slot(
                        engagement_id, int(prog_for_slot["max_concurrency"]),
                    ):
                        allowed, reason = False, "concurrency_limit_exceeded"
            try:
                if not await _submit_audit_or_deny(
                    writer, engagement_id, "ALLOW" if allowed else "DENY", reason,
                    {"method": method, "host": host, "port": port},
                ):
                    return
                if not allowed:
                    logger.info("DENY CONNECT %s (%s) from %s: %s", host, port, peer, reason)
                    await _deny(writer, 403, reason)
                    return
                try:
                    remote_reader, remote_writer = await asyncio.open_connection(connect_ip, port)
                except OSError as exc:
                    await _deny(writer, 502, f"connect_failed: {exc}")
                    return
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                await _relay(reader, writer, remote_reader, remote_writer)
            finally:
                _release_concurrency_slot(engagement_id)
        else:
            await _forward_plain_http(reader, writer, method, target, headers, engagement_id)
    finally:
        writer.close()


async def _forward_plain_http(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    method: str,
    target: str,
    headers: dict[str, str],
    engagement_id: str,
) -> None:
    """Klartext-HTTP-Weiterleitung mit Ident-Header-Injektion (Deployment Kap. 6.1/6.2).

    MVP-Grenzen: kein chunked Transfer-Encoding, keine Keep-Alive-Wiederverwendung.
    Fuer TLS-Ziele nutzen Clients CONNECT (s. handle_client) - dort ist der
    Payload fuer den Proxy opak, Header-Injektion erfolgt im MCP-Runner.
    """
    parsed = urlsplit(target if "://" in target else f"http://{headers.get('host', '')}{target}")
    host = parsed.hostname or headers.get("host", "").split(":")[0]
    port = parsed.port or 80
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    allowed, reason = await evaluate(engagement_id, host, path, port)
    # REQ-HARDEN-002: block never-legitimate resolved addresses (loopback,
    # link-local/cloud-metadata) even when scope allows, and pin the vetted IP.
    connect_host = host
    if allowed:
        try:
            connect_host = await asyncio.to_thread(vet_target_host, host, port)
        except BlockedAddressError as exc:
            allowed, reason = False, exc.reason

    prog = None
    if allowed:
        eng = await asyncio.to_thread(load_engagement, engagement_id)
        prog = await asyncio.to_thread(bounty_program_for, engagement_id) if eng and eng["source"] == "bug_bounty" else None
        # GitHub issue #30: reserve the concurrency slot as part of the same
        # audited decision - released deterministically in `finally` below,
        # whatever happens next (connect failure, relay error, client abort).
        if prog is not None and not _try_acquire_concurrency_slot(engagement_id, int(prog["max_concurrency"])):
            allowed, reason = False, "concurrency_limit_exceeded"

    try:
        if not await _submit_audit_or_deny(
            writer, engagement_id, "ALLOW" if allowed else "DENY", reason,
            {"method": method, "host": host, "path": path, "port": port},
        ):
            return
        if not allowed:
            logger.info("DENY %s http://%s%s: %s", method, host, path, reason)
            await _deny(writer, 403, reason)
            return

        out_headers = {k: v for k, v in headers.items() if k not in ("x-asm-engagement-id", "proxy-connection")}
        out_headers["host"] = host
        out_headers["connection"] = "close"
        # GitHub issue #32: `prog` is a truthy dict whenever a bounty_program
        # ROW exists, even when its ident_header_value is unset (REQ-AUTH-006's
        # 2026-08-12 amendment made the header itself optional) - `if prog:`
        # alone unconditionally set a header to the Python string "None" for
        # such a program, sent verbatim over plain HTTP to the real target.
        # Mirrors the worker's own injection guard (tool_runner_client.py's
        # `if ident_name and ident_value:`).
        if prog and prog.get("ident_header_value"):
            out_headers[prog["ident_header_name"].lower()] = prog["ident_header_value"]  # ⚖ Pflicht bei bug_bounty, falls konfiguriert
            if prog.get("ua_suffix") and "user-agent" in out_headers:
                out_headers["user-agent"] = f"{out_headers['user-agent']} {prog['ua_suffix']}"

        try:
            # Connect to the vetted, pinned IP (REQ-HARDEN-002); Host header still
            # carries the name for correct virtual-host routing.
            remote_reader, remote_writer = await asyncio.open_connection(connect_host, port)
        except OSError as exc:
            await _deny(writer, 502, f"connect_failed: {exc}")
            return

        header_block = "".join(f"{k}: {v}\r\n" for k, v in out_headers.items())
        remote_writer.write(f"{method} {path} HTTP/1.1\r\n{header_block}\r\n".encode("latin-1"))

        body_len = int(headers.get("content-length", "0") or 0)
        if body_len:
            remote_writer.write(await reader.readexactly(body_len))
        await remote_writer.drain()

        await _relay(reader, writer, remote_reader, remote_writer)
    finally:
        _release_concurrency_slot(engagement_id)


async def serve() -> None:
    server = await asyncio.start_server(handle_client, host="0.0.0.0", port=PROXY_PORT)
    logger.info("egress-proxy listening on :%d", PROXY_PORT)
    async with server:
        await server.serve_forever()
