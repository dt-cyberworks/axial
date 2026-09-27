"""Short-lived, signed raw-egress leases for Compose Nmap execution.

The worker cannot grant network permission. It asks the control plane for a
lease, and this module reuses the Scope Gateway for the exact Nmap call before
signing a bounded capability. The raw-egress gateway can verify the capability
without DB or control-plane network access.
"""

from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

import fnmatch

from app.config import get_settings
from app.gateway.audit import append_audit_log
from app.gateway.authorize import Decision, ToolCall, authorize
from app.gateway.raw_egress_policy import render_for_engagement
from app.models.engagement import BountyProgram, Engagement, ScopeAsset
from app.models.resolved_host import ResolvedHost
from app.models.scan_run import ScanRun

# REQ-CIDRDISC-002: fixed TCP-SYN discovery-probe ports for the host-discovery
# sweep (-PS80,443) - never operator/agent-chosen. Kept in sync with
# tool_runner_client._nmap_body's host_discovery stage and the raw-egress-
# gateway's own lease-payload validation (verify_lease).
HOST_DISCOVERY_PORTS = (80, 443)


# Deliberately fixed, small UDP envelope (REQ-SCAN-011). A worker or LLM may
# select the profile, never arbitrary ports.
TARGETED_UDP_PORTS = (53, 123, 161, 443, 500, 1900, 4500, 5060, 5353)


@dataclasses.dataclass(frozen=True)
class RawLeaseResult:
    decision: Decision
    lease_token: str | None = None
    lease_id: uuid.UUID | None = None
    expires_at: dt.datetime | None = None
    port_profile: str | None = None
    port_range: str | None = None
    protocol: str | None = None
    udp_discovery_enabled: bool = False
    max_rate: int | None = None
    port: int | None = None


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _canonical_payload(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sign_lease(payload: dict, secret: str) -> str:
    """Return body.signature; both parts are URL-safe and padding-free."""
    body = _b64url(_canonical_payload(payload))
    signature = hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64url(signature)}"


def _audit_denial(
    db: Session,
    engagement_id: uuid.UUID,
    *,
    reason: str,
    scan_run_id: uuid.UUID,
    target: str,
    resolved_target: str,
) -> RawLeaseResult:
    append_audit_log(
        db,
        engagement_id=engagement_id,
        actor="control-plane",
        action="raw_egress_lease",
        decision="DENY",
        reason=reason,
        payload={
            "scan_run_id": str(scan_run_id),
            "authorized_target": target,
            "resolved_target": resolved_target,
        },
    )
    return RawLeaseResult(decision=Decision(allowed=False, reason=reason))


def _ip_is_allowed_by_current_policy(db: Session, engagement_id: uuid.UUID, address: str) -> bool:
    ip = ipaddress.ip_address(address)
    rendered = render_for_engagement(db, engagement_id)
    for block in rendered.ip_blocks:
        network = ipaddress.ip_network(block["cidr"], strict=False)
        if ip.version != network.version or ip not in network:
            continue
        denied = any(
            ip.version == ipaddress.ip_network(item, strict=False).version
            and ip in ipaddress.ip_network(item, strict=False)
            for item in block.get("except", [])
        )
        if not denied:
            return True
    return False


def _network_is_allowed_by_current_policy(db: Session, engagement_id: uuid.UUID, network: "ipaddress.IPv4Network | ipaddress.IPv6Network") -> bool:
    """REQ-CIDRDISC-001: the host-discovery-sweep counterpart of
    `_ip_is_allowed_by_current_policy` above - checked at network granularity
    (subnet containment) rather than point containment, and rejects any
    overlap with a deny exception rather than only an exact match, since a
    sweep touches every address in the range, not one resolved point."""
    rendered = render_for_engagement(db, engagement_id)
    for block in rendered.ip_blocks:
        allow_net = ipaddress.ip_network(block["cidr"], strict=False)
        if network.version != allow_net.version or not (network == allow_net or network.subnet_of(allow_net)):
            continue
        overlaps_exception = any(
            network.version == ipaddress.ip_network(item, strict=False).version
            and network.overlaps(ipaddress.ip_network(item, strict=False))
            for item in block.get("except", [])
        )
        if not overlaps_exception:
            return True
    return False


def _matches_target(target: str, asset: ScopeAsset) -> bool:
    """REQ-PORTSCOPE-003: same domain/wildcard/ip/cidr matching semantics as
    egress-proxy's _matches_host (egress-proxy/app/proxy.py) - a deliberately
    separate implementation, mirroring this codebase's existing
    defense-in-depth duplication between the two independent enforcement
    services rather than a shared import between them."""
    t = target.lower().rstrip(".")
    if asset.asset_type == "domain":
        domain = asset.value.lower().rstrip(".")
        return t == domain or t.endswith("." + domain)
    if asset.asset_type == "wildcard":
        return fnmatch.fnmatch(t, asset.value.lower())
    if asset.asset_type in ("ip", "cidr"):
        try:
            return ipaddress.ip_address(t) in ipaddress.ip_network(asset.value, strict=False)
        except ValueError:
            return False
    return False


def _effective_port_ranges_for_target(
    db: Session, engagement_id: uuid.UUID, eng: Engagement, target: str,
) -> list[tuple[int, int]]:
    """REQ-PORTSCOPE-003: one effective (from, to) tuple per allow-scope
    asset that matches `target`, each intersected with the engagement
    ceiling fresh here (never trusted from the stored row alone - a ceiling
    narrowed after the asset was created still applies immediately). No
    matched asset at all (e.g. a target reached via context rather than a
    specific scope asset) falls back to the ceiling alone, unchanged from
    this module's pre-REQ-PORTSCOPE-003 behavior."""
    assets = db.scalars(
        select(ScopeAsset).where(ScopeAsset.engagement_id == engagement_id, ScopeAsset.rule == "allow")
    ).all()
    matched = [a for a in assets if _matches_target(target, a)]
    ceiling = (int(eng.tcp_port_from), int(eng.tcp_port_to))
    if not matched:
        return [ceiling]
    ranges = []
    for a in matched:
        if a.port_from is None:
            ranges.append(ceiling)
        else:
            ranges.append((max(ceiling[0], a.port_from), min(ceiling[1], a.port_to)))
    return ranges


def _effective_raw_max_rate(base_rate: int, bounty_program: BountyProgram | None) -> int:
    """GitHub issue #37: raw_max_packets_per_second is a DISTINCT unit from
    max_rps (an HTTP request-rate concept) - conflating the two (using
    max_rps to tighten a RAW nmap rate) was itself part of the gap this
    issue reports. Prefers the program's own explicit raw-rate cap when
    configured; falls back to max_rps - the pre-existing behavior - only for
    backward compatibility with a program that never set the new field."""
    if bounty_program is None:
        return base_rate
    if bounty_program.raw_max_packets_per_second is not None:
        return max(1, min(base_rate, int(bounty_program.raw_max_packets_per_second)))
    return max(1, min(base_rate, int(bounty_program.max_rps)))


def _issue_host_discovery_lease(
    db: Session, settings, eng: Engagement, *,
    engagement_id: uuid.UUID, scan_run_id: uuid.UUID, authorized_target: str, resolved_target: str,
    phase: str, tool: str, bounty_program: BountyProgram | None,
) -> RawLeaseResult:
    """REQ-CIDRDISC-001/002: authorize ONE liveness-only `nmap -sn` sweep
    against a whole ip/cidr scope asset. Unlike every other profile there is
    no single resolved host to prove via DNS materialization - the ip/cidr
    scope asset itself is already the ground truth, so `authorized_target`
    and `resolved_target` are required to be the same literal network (the
    worker sends both identically; a mismatch is refused rather than trusted)."""
    try:
        network = ipaddress.ip_network(resolved_target, strict=False)
        authorized_network = ipaddress.ip_network(authorized_target, strict=False)
    except ValueError:
        return _audit_denial(
            db, engagement_id, reason="resolved_target_invalid", scan_run_id=scan_run_id,
            target=authorized_target, resolved_target=resolved_target,
        )
    if authorized_network != network:
        return _audit_denial(
            db, engagement_id, reason="materialized_target_mismatch", scan_run_id=scan_run_id,
            target=authorized_target, resolved_target=resolved_target,
        )
    if not _network_is_allowed_by_current_policy(db, engagement_id, network):
        return _audit_denial(
            db, engagement_id, reason="resolved_target_not_in_current_raw_policy",
            scan_run_id=scan_run_id, target=authorized_target, resolved_target=str(network),
        )

    protocol = "tcp"
    ports = [[p, p] for p in HOST_DISCOVERY_PORTS]
    port_range = ",".join(str(p) for p in HOST_DISCOVERY_PORTS)
    # REQ-CIDRDISC-005: for a bug_bounty engagement the program's own rate
    # cap is not optional tightening here - it is the specific basis the
    # exemption to the raw-nmap block was granted on.
    max_rate = _effective_raw_max_rate(max(1, min(settings.nmap_max_rate, 1000)), bounty_program)
    args = {"flags": ["-sn"], "max_rate": max_rate, "port_profile": "host_discovery"}

    call = ToolCall(
        engagement_id=engagement_id, tool=tool, category="fingerprint", mode="active",
        target=authorized_target, args=args, is_automated=True, phase=phase,
        scan_run_id=scan_run_id, target_is_range=True,
    )
    decision = authorize(db, call)
    if not decision.allowed:
        return RawLeaseResult(
            decision=decision, port_profile="host_discovery", port_range=port_range,
            max_rate=max_rate, port=None,
        )

    now = dt.datetime.now(dt.timezone.utc)
    lease_ttl = max(60, min(settings.raw_egress_lease_ttl_seconds, 1800))
    expires_at = now + dt.timedelta(seconds=lease_ttl)
    lease_id = uuid.uuid4()
    payload = {
        "version": 1,
        "lease_id": str(lease_id),
        "engagement_id": str(engagement_id),
        "scan_run_id": str(scan_run_id),
        "authorized_target": authorized_target.lower().rstrip("."),
        "resolved_target": str(network),
        "protocol": protocol,
        "ports": ports,
        "port_profile": "host_discovery",
        "max_rate": max_rate,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "nonce": uuid.uuid4().hex,
    }
    token = sign_lease(payload, settings.raw_egress_signing_secret)
    append_audit_log(
        db, engagement_id=engagement_id, actor="control-plane", action="raw_egress_lease",
        decision="ALLOW", reason="lease_issued",
        payload={key: value for key, value in payload.items() if key != "nonce"},
    )
    return RawLeaseResult(
        decision=decision, lease_token=token, lease_id=lease_id, expires_at=expires_at,
        port_profile="host_discovery", port_range=port_range, protocol=protocol,
        udp_discovery_enabled=bool(eng.udp_discovery_enabled), max_rate=max_rate, port=None,
    )


def issue_raw_egress_lease(
    db: Session,
    *,
    engagement_id: uuid.UUID,
    scan_run_id: uuid.UUID,
    authorized_target: str,
    resolved_target: str,
    phase: str,
    port_profile: str,
    port: int | None = None,
    tool: str = "nmap",
) -> RawLeaseResult:
    """Authorize and sign one persisted, bounded Nmap TCP/UDP or raw-protocol-
    probe lease. `port` is only used (and required) for "raw_tcp_probe" -
    REQ-AGENT-025's curated, non-destructive redis-probe/activemq-banner
    checks, which need exactly one specific port, resolved by the worker,
    not the engagement's own configured range the way nmap's profiles use it
    directly. Re-validated here against that range regardless - never trusted
    from the caller alone."""
    settings = get_settings()
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        return RawLeaseResult(decision=Decision(allowed=False, reason="engagement_not_found"))

    run = db.get(ScanRun, scan_run_id)
    if (
        run is None or run.engagement_id != engagement_id
        or run.state != "running" or run.cancel_requested
    ):
        return _audit_denial(
            db, engagement_id, reason="scan_run_not_active", scan_run_id=scan_run_id,
            target=authorized_target, resolved_target=resolved_target,
        )
    if port_profile not in {"full_tcp", "configured_tcp", "targeted_udp", "raw_tcp_probe", "host_discovery"}:
        return _audit_denial(
            db, engagement_id, reason="raw_port_profile_unknown", scan_run_id=scan_run_id,
            target=authorized_target, resolved_target=resolved_target,
        )
    if eng.source == "bug_bounty":
        # REQ-CIDRDISC-005 (GitHub issue #37 extends this): the raw-nmap
        # block's ONE narrow exception used to be a fixed single profile -
        # host_discovery, gated only on automation_allowed. tcp_syn_scan_
        # profile makes that an explicit, opt-in tier instead of a fixed
        # ceiling: 'none' (default) preserves the original behavior exactly;
        # 'common' additionally permits configured_tcp (the engagement's own
        # already-configured scope-asset port ranges); 'full' additionally
        # permits full_tcp, gated on a recorded authorization reason (never
        # on automation_allowed/max_rps alone - an HTTP-rate statement is not
        # itself permission for a full port scan). targeted_udp/raw_tcp_probe
        # remain unconditionally denied for bug_bounty regardless of profile -
        # a deliberately unaddressed follow-on, not an oversight.
        prog = db.scalar(select(BountyProgram).where(BountyProgram.engagement_id == engagement_id))
        if prog is None or not prog.automation_allowed:
            return _audit_denial(
                db, engagement_id, reason="raw_nmap_not_permitted_for_bug_bounty",
                scan_run_id=scan_run_id, target=authorized_target, resolved_target=resolved_target,
            )
        allowed_profiles = {"host_discovery"}
        if prog.tcp_syn_scan_profile in ("common", "full"):
            allowed_profiles.add("configured_tcp")
        if prog.tcp_syn_scan_profile == "full":
            if not (prog.network_scan_authorization_evidence or "").strip():
                return _audit_denial(
                    db, engagement_id, reason="full_tcp_requires_authorization_evidence",
                    scan_run_id=scan_run_id, target=authorized_target, resolved_target=resolved_target,
                )
            allowed_profiles.add("full_tcp")
        if port_profile not in allowed_profiles:
            return _audit_denial(
                db, engagement_id, reason="raw_nmap_not_permitted_for_bug_bounty",
                scan_run_id=scan_run_id, target=authorized_target, resolved_target=resolved_target,
            )
    else:
        prog = None
    if port_profile == "host_discovery":
        # REQ-CIDRDISC-002: fixed TCP-SYN discovery ports, checked against the
        # engagement's own configured ceiling like every other raw nmap
        # profile - never against a per-target scope-asset range, since a
        # sweep is not scanning a specific named target's configured window.
        ceiling = (int(eng.tcp_port_from), int(eng.tcp_port_to))
        if not all(ceiling[0] <= p <= ceiling[1] for p in HOST_DISCOVERY_PORTS):
            return _audit_denial(
                db, engagement_id, reason="host_discovery_ports_out_of_range", scan_run_id=scan_run_id,
                target=authorized_target, resolved_target=resolved_target,
            )
        return _issue_host_discovery_lease(
            db, settings, eng, engagement_id=engagement_id, scan_run_id=scan_run_id,
            authorized_target=authorized_target, resolved_target=resolved_target,
            phase=phase, tool=tool, bounty_program=prog,
        )

    # REQ-PORTSCOPE-003: resolved once, re-derived fresh every call (never
    # cached/trusted from a prior lease) - one effective (from, to) per
    # allow-scope asset matching `authorized_target`, each already
    # intersected with the current engagement ceiling.
    target_ranges = _effective_port_ranges_for_target(db, engagement_id, eng, authorized_target)

    if port_profile == "full_tcp" and (1, 65535) not in target_ranges:
        return _audit_denial(
            db, engagement_id, reason="full_tcp_not_configured", scan_run_id=scan_run_id,
            target=authorized_target, resolved_target=resolved_target,
        )
    if port_profile == "targeted_udp" and not eng.udp_discovery_enabled:
        return _audit_denial(
            db, engagement_id, reason="udp_discovery_not_enabled", scan_run_id=scan_run_id,
            target=authorized_target, resolved_target=resolved_target,
        )
    if port_profile == "raw_tcp_probe":
        if port is None or not 1 <= port <= 65535:
            return _audit_denial(
                db, engagement_id, reason="raw_tcp_probe_port_invalid", scan_run_id=scan_run_id,
                target=authorized_target, resolved_target=resolved_target,
            )
        if not any(lo <= port <= hi for lo, hi in target_ranges):
            return _audit_denial(
                db, engagement_id, reason="port_not_in_configured_range", scan_run_id=scan_run_id,
                target=authorized_target, resolved_target=resolved_target,
            )

    try:
        resolved_ip = ipaddress.ip_address(resolved_target)
    except ValueError:
        return _audit_denial(
            db, engagement_id, reason="resolved_target_invalid", scan_run_id=scan_run_id,
            target=authorized_target, resolved_target=resolved_target,
        )

    # Direct IP scope needs no DNS snapshot. Named scope must match a fresh,
    # control-plane-owned materialization exactly.
    target_is_same_ip = False
    try:
        target_is_same_ip = ipaddress.ip_address(authorized_target) == resolved_ip
    except ValueError:
        pass
    if not target_is_same_ip:
        row = db.scalar(
            select(ResolvedHost)
            .where(
                ResolvedHost.engagement_id == engagement_id,
                func.lower(ResolvedHost.hostname) == authorized_target.lower().rstrip("."),
                ResolvedHost.ip_address == str(resolved_ip),
            )
            .order_by(ResolvedHost.resolved_at.desc())
            .limit(1)
        )
        if row is None:
            return _audit_denial(
                db, engagement_id, reason="materialized_target_mismatch", scan_run_id=scan_run_id,
                target=authorized_target, resolved_target=str(resolved_ip),
            )
        resolved_at = row.resolved_at
        if resolved_at.tzinfo is None:
            resolved_at = resolved_at.replace(tzinfo=dt.timezone.utc)
        age = (dt.datetime.now(dt.timezone.utc) - resolved_at).total_seconds()
        if age > max(60, min(settings.raw_egress_materialization_max_age_seconds, 3600)):
            return _audit_denial(
                db, engagement_id, reason="materialized_target_stale", scan_run_id=scan_run_id,
                target=authorized_target, resolved_target=str(resolved_ip),
            )

    if not _ip_is_allowed_by_current_policy(db, engagement_id, str(resolved_ip)):
        return _audit_denial(
            db, engagement_id, reason="resolved_target_not_in_current_raw_policy",
            scan_run_id=scan_run_id, target=authorized_target, resolved_target=str(resolved_ip),
        )

    if port_profile == "targeted_udp":
        protocol = "udp"
        ports = [[udp_port, udp_port] for udp_port in TARGETED_UDP_PORTS]
        port_range = ",".join(str(udp_port) for udp_port in TARGETED_UDP_PORTS)
        max_rate = max(1, min(settings.nmap_max_rate, 100))
        args = {"flags": ["-sU", "-p"], "ports": port_range, "max_rate": max_rate, "port_profile": port_profile}
    elif port_profile == "raw_tcp_probe":
        # REQ-AGENT-025: a single, worker-resolved port - already validated
        # against the engagement's configured range above. No nmap-shaped
        # flags/max_rate at all; the real tool (redis-probe/activemq-banner)
        # takes no structured args, matching every other curated run_check
        # tool's empty-args envelope (args_safety's default: no entry -> only
        # empty args are safe).
        protocol = "tcp"
        ports = [[port, port]]
        port_range = str(port)
        # max_rate has no meaning for a single connect/read (not a packet-rate
        # scan) but the signed lease payload schema requires a valid int
        # (raw-egress-gateway's verify_lease) - a nominal, unused placeholder.
        max_rate = 1
        args = {}
    else:
        protocol = "tcp"
        # full_tcp already required exactly (1, 65535) to be present above -
        # scan that single full segment, not a mix with any other matched
        # asset's narrower range. configured_tcp scans every matched target
        # range (REQ-PORTSCOPE-003) as its own nmap port-list segment -
        # already supported by this payload shape (see targeted_udp above,
        # which has always been a multi-segment list).
        segments = [(1, 65535)] if port_profile == "full_tcp" else sorted(set(target_ranges))
        ports = [[lo, hi] for lo, hi in segments]
        port_range = ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in segments)
        # GitHub issue #37: configured_tcp/full_tcp were previously
        # unreachable for a bug_bounty engagement at all, so this had no
        # bounty-specific tightening - now that tcp_syn_scan_profile can
        # unlock them, the same distinct-raw-rate reasoning as the
        # host_discovery path applies.
        max_rate = _effective_raw_max_rate(max(1, min(settings.nmap_max_rate, 1000)), prog)
        args = {"flags": ["-sS", "-p"], "ports": port_range, "max_rate": max_rate, "port_profile": port_profile}

    call = ToolCall(
        engagement_id=engagement_id,
        tool=tool,
        category="fingerprint",
        mode="active",
        target=authorized_target,
        args=args,
        is_automated=True,
        phase=phase,
        scan_run_id=scan_run_id,
    )
    decision = authorize(db, call)
    if not decision.allowed:
        return RawLeaseResult(
            decision=decision, port_profile=port_profile,
            port_range=port_range, max_rate=max_rate, port=port,
        )

    now = dt.datetime.now(dt.timezone.utc)
    lease_ttl = max(60, min(settings.raw_egress_lease_ttl_seconds, 1800))
    expires_at = now + dt.timedelta(seconds=lease_ttl)
    lease_id = uuid.uuid4()
    payload = {
        "version": 1,
        "lease_id": str(lease_id),
        "engagement_id": str(engagement_id),
        "scan_run_id": str(scan_run_id),
        "authorized_target": authorized_target.lower().rstrip("."),
        "resolved_target": str(resolved_ip),
        "protocol": protocol,
        "ports": ports,
        "port_profile": port_profile,
        "max_rate": max_rate,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "nonce": uuid.uuid4().hex,
    }
    token = sign_lease(payload, settings.raw_egress_signing_secret)
    append_audit_log(
        db,
        engagement_id=engagement_id,
        actor="control-plane",
        action="raw_egress_lease",
        decision="ALLOW",
        reason="lease_issued",
        payload={key: value for key, value in payload.items() if key != "nonce"},
    )
    return RawLeaseResult(
        decision=decision,
        lease_token=token,
        lease_id=lease_id,
        expires_at=expires_at,
        port_profile=port_profile,
        port_range=port_range,
        protocol=protocol,
        udp_discovery_enabled=bool(eng.udp_discovery_enabled),
        max_rate=max_rate,
        port=port,
    )
