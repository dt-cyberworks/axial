"""FIFO scheduling, lease verification, and nftables enforcement for raw Nmap.

REQ-CONCUR-002: supports up to `max_concurrent_leases` independently active
leases (default 1, unchanged behavior). Each lease gets its own dedicated
nftables sets ("slot") so one lease's port range can never combine with
another lease's target address - see NftPolicyManager. Scheduling state
(_active, _reservations) is keyed by scan_run_id (a dict), generalizing the
original single-value model rather than replacing its semantics: a granted
reservation still represents one held concurrency slot (whether or not it
has activated yet), matching the original invariant that an active lease
always has a corresponding reservation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import secrets
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Callable

TABLE = "asm_raw"
MAX_TOKEN_BYTES = 32_768
MAX_LEASE_SECONDS = 1_800
EXPIRY_GRACE_SECONDS = 60
MAX_QUEUE_LENGTH = 128
RESERVATION_IDLE_SECONDS = 120
ACTIVE_HEARTBEAT_SECONDS = 12
TARGETED_UDP_PORTS = (53, 123, 161, 443, 500, 1900, 4500, 5060, 5353)

class LeaseError(ValueError):
    pass

class LeaseBusy(RuntimeError):
    pass

class QueueFull(RuntimeError):
    pass

class PolicyError(RuntimeError):
    pass

def _decode_part(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:  # noqa: BLE001
        raise LeaseError("lease_encoding_invalid") from exc

def verify_lease(token: str, secret: str, *, now: int | None = None, allow_expired: bool = False) -> dict:
    if not token or len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
        raise LeaseError("lease_missing_or_oversized")
    try:
        body, supplied_signature = token.split(".", 1)
    except ValueError as exc:
        raise LeaseError("lease_format_invalid") from exc
    expected = hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
    if not hmac.compare_digest(_decode_part(supplied_signature), expected):
        raise LeaseError("lease_signature_invalid")
    try:
        payload = json.loads(_decode_part(body))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LeaseError("lease_payload_invalid") from exc
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise LeaseError("lease_version_invalid")
    for field in ("lease_id", "engagement_id", "scan_run_id"):
        try:
            uuid.UUID(str(payload.get(field)))
        except (ValueError, TypeError) as exc:
            raise LeaseError(f"{field}_invalid") from exc
    if not isinstance(payload.get("nonce"), str) or len(payload["nonce"]) < 16:
        raise LeaseError("lease_nonce_invalid")
    protocol = payload.get("protocol")
    profile = payload.get("port_profile")
    if protocol == "tcp":
        if profile not in {"full_tcp", "configured_tcp", "raw_tcp_probe", "host_discovery"}:
            raise LeaseError("lease_port_profile_invalid")
    elif protocol == "udp":
        if profile != "targeted_udp":
            raise LeaseError("lease_port_profile_invalid")
    else:
        raise LeaseError("lease_protocol_invalid")
    try:
        # REQ-CIDRDISC-001: a host-discovery lease's target is a whole
        # network, not one resolved host - every other profile keeps the
        # single-address requirement unchanged.
        if profile == "host_discovery":
            address = ipaddress.ip_network(str(payload["resolved_target"]), strict=False)
        else:
            address = ipaddress.ip_address(str(payload["resolved_target"]))
    except (ValueError, KeyError) as exc:
        raise LeaseError("lease_target_invalid") from exc
    payload["resolved_target"] = str(address)
    target = payload.get("authorized_target")
    if not isinstance(target, str) or not 1 <= len(target) <= 255:
        raise LeaseError("lease_authorized_target_invalid")
    ports = payload.get("ports")
    if not isinstance(ports, list) or not 1 <= len(ports) <= 32:
        raise LeaseError("lease_ports_invalid")
    normalized_ports: list[tuple[int, int]] = []
    for item in ports:
        if not isinstance(item, list) or len(item) != 2:
            raise LeaseError("lease_ports_invalid")
        try:
            first, last = int(item[0]), int(item[1])
        except (TypeError, ValueError) as exc:
            raise LeaseError("lease_ports_invalid") from exc
        if not 1 <= first <= last <= 65535:
            raise LeaseError("lease_ports_invalid")
        normalized_ports.append((first, last))
    if protocol == "tcp" and profile != "host_discovery" and len(normalized_ports) != 1:
        raise LeaseError("lease_ports_invalid")
    if profile == "full_tcp" and normalized_ports != [(1, 65535)]:
        raise LeaseError("lease_ports_invalid")
    # REQ-AGENT-025: unlike configured_tcp (a caller-chosen RANGE is the
    # point), a curated raw-protocol probe must never widen into anything
    # resembling a port scan - exactly one single port, first == last.
    if profile == "raw_tcp_probe" and (len(normalized_ports) != 1 or normalized_ports[0][0] != normalized_ports[0][1]):
        raise LeaseError("lease_ports_invalid")
    # REQ-CIDRDISC-002: fixed TCP-SYN discovery-probe ports (80, 443) - kept in
    # sync with raw_egress_lease.HOST_DISCOVERY_PORTS and tool_runner_client's
    # host_discovery stage. Never operator/agent-chosen.
    if profile == "host_discovery" and normalized_ports != [(80, 80), (443, 443)]:
        raise LeaseError("lease_ports_invalid")
    if protocol == "udp" and normalized_ports != [(port, port) for port in TARGETED_UDP_PORTS]:
        raise LeaseError("lease_ports_invalid")
    payload["ports"] = normalized_ports
    try:
        issued_at = int(payload["iat"])
        expires_at = int(payload["exp"])
        max_rate = int(payload["max_rate"])
    except (KeyError, TypeError, ValueError) as exc:
        raise LeaseError("lease_bounds_invalid") from exc
    current = int(time.time()) if now is None else now
    if issued_at > current + 30 or expires_at <= issued_at:
        raise LeaseError("lease_time_invalid")
    if expires_at - issued_at > MAX_LEASE_SECONDS:
        raise LeaseError("lease_ttl_excessive")
    if expires_at <= current and not (allow_expired and expires_at + EXPIRY_GRACE_SECONDS > current):
        raise LeaseError("lease_expired")
    if not 1 <= max_rate <= (100 if protocol == "udp" else 1000):
        raise LeaseError("lease_rate_invalid")
    return payload

def _subprocess_nft(script: str, check: bool = True) -> None:
    proc = subprocess.run(["nft", "-f", "-"], input=script, text=True, capture_output=True, check=False)
    if check and proc.returncode != 0:
        raise PolicyError((proc.stderr or "nft_failed")[:1000])

class NftPolicyManager:
    """Own a deny-all output table in the runner's shared network namespace.

    REQ-CONCUR-002: `num_slots` independent (address, port-range) pairs, each
    with its OWN dedicated sets, ANDed only with each other - never a single
    shared set whose members could combine across concurrently active
    leases. Slot N's rule only ever matches slot N's own sets.
    """
    def __init__(
        self, runner: Callable[[str, bool], None] = _subprocess_nft, *, proxy_addresses=None, proxy_port=3128,
        num_slots: int = 1, oob_addresses=None, oob_port: int = 8080,
    ):
        self._run = runner
        self._proxy_addresses = [str(ipaddress.ip_address(value)) for value in (proxy_addresses or [])]
        self._proxy_port = int(proxy_port)
        if not 1 <= self._proxy_port <= 65535:
            raise ValueError("proxy_port_invalid")
        # REQ-COVER-004: the self-hosted interaction server's own address(es),
        # reachable on ONE tcp port only, and only when configured. Never a
        # target address; the address set is fixed at start-up like the proxy.
        self._oob_addresses = [
            str(ipaddress.ip_address(value)) for value in (oob_addresses or [])
            if ipaddress.ip_address(value).version == 4
        ]
        self._oob_port = int(oob_port)
        if self._oob_addresses and not 1 <= self._oob_port <= 65535:
            raise ValueError("oob_port_invalid")
        self.num_slots = int(num_slots)
        if self.num_slots < 1:
            raise ValueError("num_slots_invalid")

    def _validate_slot(self, slot: int) -> None:
        if not 0 <= slot < self.num_slots:
            raise PolicyError("slot_index_invalid")

    def initialize(self) -> None:
        self._run(f"delete table inet {TABLE}\n", False)
        proxy_v4 = [value for value in self._proxy_addresses if ipaddress.ip_address(value).version == 4]
        proxy_v6 = [value for value in self._proxy_addresses if ipaddress.ip_address(value).version == 6]
        elements = []
        if proxy_v4:
            elements.append(f"add element inet {TABLE} proxy_v4 {{ {', '.join(proxy_v4)} }}")
        if proxy_v6:
            elements.append(f"add element inet {TABLE} proxy_v6 {{ {', '.join(proxy_v6)} }}")
        # REQ-CIDRDISC-001: `interval` lets a host-discovery lease install a
        # whole CIDR block as one element; every other (single-host) lease
        # still adds an exact /32-/128, functionally identical to a plain
        # address element (interval sets accept a bare host as a one-address
        # interval) - unchanged behavior for every pre-existing caller.
        if self._oob_addresses:
            elements.append(f"add element inet {TABLE} oob_v4 {{ {', '.join(self._oob_addresses)} }}")
        oob_set = f"    set oob_v4 {{ type ipv4_addr; }}\n" if self._oob_addresses else ""
        oob_rule = (
            f"        ip daddr @oob_v4 tcp dport {self._oob_port} accept\n" if self._oob_addresses else ""
        )
        slot_sets = "\n".join(
            f"    set allowed_v4_{i} {{ type ipv4_addr; flags interval, timeout; timeout 30m; }}\n"
            f"    set allowed_v6_{i} {{ type ipv6_addr; flags interval, timeout; timeout 30m; }}\n"
            f"    set allowed_tcp_ports_{i} {{ type inet_service; flags interval; }}\n"
            f"    set allowed_udp_ports_{i} {{ type inet_service; flags interval; }}"
            for i in range(self.num_slots)
        )
        # GitHub issue #37: each slot gets its own dedicated, initially-empty
        # chain (jumped to unconditionally from `output`) instead of a fixed
        # accept rule - apply() below rebuilds it per-lease with an inline
        # `limit rate` clause carrying THAT lease's own configured packet
        # rate. This is the actual enforcement-layer hard limiter the
        # acceptance criteria ask for: a real kernel-level token bucket
        # (nftables' own `limit rate`), independent of whatever the nmap
        # process invoked inside the runner actually does with its own
        # --max-rate flag (which stays in place too, as defense in depth -
        # see worker/app/tool_runner_client.py). Verified against a real nft
        # binary (nft -c, and a real apply+list roundtrip) that this
        # flush-chain-and-rebuild pattern is the correct way to change a
        # slot's rate live: nftables refuses to delete/redefine a NAMED limit
        # object while a rule still references it ("Resource busy") - an
        # inline limit tied to the rule itself, recreated via flush+add, has
        # no such restriction.
        slot_chains = "\n".join(f"    chain slot_{i} {{\n    }}" for i in range(self.num_slots))
        slot_jumps = "\n".join(f"        jump slot_{i}" for i in range(self.num_slots))
        self._run(f"""
table inet {TABLE} {{
{slot_sets}
    set proxy_v4 {{ type ipv4_addr; }}
    set proxy_v6 {{ type ipv6_addr; }}
{oob_set}{slot_chains}
    chain output {{
        type filter hook output priority 0; policy drop;
        oifname "lo" accept
        ct state established,related accept
        ip daddr @proxy_v4 tcp dport {self._proxy_port} accept
        ip6 daddr @proxy_v6 tcp dport {self._proxy_port} accept
{oob_rule}{slot_jumps}
    }}
}}
{chr(10).join(elements)}
""".strip() + "\n", True)

    def apply(
        self, slot: int, address: str, ports: list[tuple[int, int]], ttl_seconds: int,
        protocol: str = "tcp", max_rate: int = 1000,
    ) -> None:
        self._validate_slot(slot)
        if protocol not in {"tcp", "udp"}:
            raise PolicyError("policy_protocol_invalid")
        # Same bound issue_raw_egress_lease/verify_lease already enforce on
        # the signed lease payload - re-checked here since this is the
        # actual enforcement point, not assumed from the caller.
        if not 1 <= max_rate <= 1000:
            raise PolicyError("policy_rate_invalid")
        # REQ-CIDRDISC-001: `address` may be a single host or (host-discovery
        # leases only) a whole CIDR block - ip_network(..., strict=False)
        # renders either as an explicit prefix (a bare host becomes /32 or
        # /128), which an `interval`-flagged set matches identically to the
        # previous bare-address element for every single-host caller.
        network = ipaddress.ip_network(address, strict=False)
        address_set = f"allowed_v4_{slot}" if network.version == 4 else f"allowed_v6_{slot}"
        port_set = f"allowed_{protocol}_ports_{slot}"
        daddr_kw = "ip daddr" if network.version == 4 else "ip6 daddr"
        port_elements = ", ".join(str(first) if first == last else f"{first}-{last}" for first, last in ports)
        self._run(
            f"flush set inet {TABLE} allowed_v4_{slot}\n"
            f"flush set inet {TABLE} allowed_v6_{slot}\n"
            f"flush set inet {TABLE} allowed_tcp_ports_{slot}\n"
            f"flush set inet {TABLE} allowed_udp_ports_{slot}\n"
            f"add element inet {TABLE} {address_set} {{ {network} timeout {ttl_seconds}s }}\n"
            f"add element inet {TABLE} {port_set} {{ {port_elements} }}\n"
            f"flush chain inet {TABLE} slot_{slot}\n"
            f"add rule inet {TABLE} slot_{slot} {daddr_kw} @{address_set} {protocol} dport @{port_set} "
            f"limit rate {int(max_rate)}/second accept\n",
            True)

    def clear(self, slot: int) -> None:
        self._validate_slot(slot)
        self._run(
            f"flush set inet {TABLE} allowed_v4_{slot}\n"
            f"flush set inet {TABLE} allowed_v6_{slot}\n"
            f"flush set inet {TABLE} allowed_tcp_ports_{slot}\n"
            f"flush set inet {TABLE} allowed_udp_ports_{slot}\n"
            f"flush chain inet {TABLE} slot_{slot}\n", True)

@dataclass
class Reservation:
    scan_run_id: str
    token: str
    created_at: float
    last_seen: float

@dataclass
class ActiveLease:
    lease_id: str
    engagement_id: str
    scan_run_id: str
    expires_at: int
    heartbeat_deadline: float
    authorized_target: str
    resolved_target: str
    max_rate: int
    port_profile: str
    protocol: str
    ports: list[tuple[int, int]]
    slot: int

class RawEgressGateway:
    """Up to `max_concurrent_leases` active leases plus a bounded FIFO of run
    reservations (REQ-CONCUR-002). A granted reservation represents one held
    concurrency slot whether or not it has activated yet - the original
    invariant (an active lease always has a matching reservation) is
    preserved, just keyed by scan_run_id instead of a single value."""
    def __init__(
        self, secret: str, policy: NftPolicyManager, *, clock: Callable[[], float] = time.time,
        max_concurrent_leases: int = 1,
    ):
        self._secret = secret
        self._policy = policy
        self._clock = clock
        self._lock = threading.Lock()
        self._max_concurrent = max(1, int(max_concurrent_leases))
        self._free_slots: list[int] = list(range(self._max_concurrent))
        self._active: dict[str, ActiveLease] = {}
        self._reservations: dict[str, Reservation] = {}
        self._queue: list[Reservation] = []
        self._expiry_timers: dict[str, threading.Timer] = {}

    def initialize(self) -> None:
        self._policy.initialize()

    def _promote_locked(self) -> None:
        while len(self._reservations) < self._max_concurrent and self._queue:
            item = self._queue.pop(0)
            self._reservations[item.scan_run_id] = item

    def _prune_locked(self, now: float) -> None:
        self._queue = [item for item in self._queue if now - item.last_seen <= RESERVATION_IDLE_SECONDS]
        stale = [
            run_id for run_id, item in self._reservations.items()
            if run_id not in self._active and now - item.last_seen > RESERVATION_IDLE_SECONDS
        ]
        for run_id in stale:
            del self._reservations[run_id]
        self._promote_locked()

    @staticmethod
    def _run_id(value: str) -> str:
        try:
            return str(uuid.UUID(str(value)))
        except (TypeError, ValueError) as exc:
            raise LeaseError("scan_run_id_invalid") from exc

    def reserve(self, scan_run_id: str) -> dict:
        owner = self._run_id(scan_run_id)
        now = float(self._clock())
        with self._lock:
            self._prune_locked(now)
            if owner in self._reservations:
                self._reservations[owner].last_seen = now
                return {"status": "granted", "reservation_token": self._reservations[owner].token, "position": 0}
            for position, item in enumerate(self._queue, 1):
                if item.scan_run_id == owner:
                    item.last_seen = now
                    return {"status": "queued", "reservation_token": item.token, "position": position}
            if len(self._queue) >= MAX_QUEUE_LENGTH:
                raise QueueFull("raw_egress_queue_full")
            item = Reservation(owner, secrets.token_urlsafe(32), now, now)
            if len(self._reservations) < self._max_concurrent:
                self._reservations[owner] = item
                return {"status": "granted", "reservation_token": item.token, "position": 0}
            self._queue.append(item)
            return {"status": "queued", "reservation_token": item.token, "position": len(self._queue)}

    def release(self, scan_run_id: str, reservation_token: str) -> None:
        owner = self._run_id(scan_run_id)
        with self._lock:
            item = self._reservations.get(owner)
            if item is not None:
                if not hmac.compare_digest(item.token, reservation_token):
                    raise LeaseError("reservation_token_invalid")
                if owner in self._active:
                    raise LeaseBusy("raw_egress_lease_active")
                del self._reservations[owner]
                self._promote_locked()
                return
            for index, queued in enumerate(self._queue):
                if queued.scan_run_id == owner:
                    if not hmac.compare_digest(queued.token, reservation_token):
                        raise LeaseError("reservation_token_invalid")
                    self._queue.pop(index)
                    return

    def _schedule_expiry_locked(self, scan_run_id: str) -> None:
        lease = self._active.get(scan_run_id)
        if lease is None:
            return
        existing = self._expiry_timers.pop(scan_run_id, None)
        if existing is not None:
            existing.cancel()
        deadline = min(float(lease.expires_at), lease.heartbeat_deadline)
        delay = max(0.05, deadline - float(self._clock()) + 0.05)
        timer = threading.Timer(delay, self._expire, args=(lease.lease_id,))
        timer.daemon = True
        timer.start()
        self._expiry_timers[scan_run_id] = timer

    def _release_slot_locked(self, scan_run_id: str) -> None:
        """Reclaim one active lease's slot: clear its OWN nft sets (never
        another lease's), return its slot to the free pool, and pop its
        reservation so a queued waiter can be promoted."""
        lease = self._active.pop(scan_run_id, None)
        if lease is None:
            return
        try:
            self._policy.clear(lease.slot)
        finally:
            self._free_slots.append(lease.slot)
            timer = self._expiry_timers.pop(scan_run_id, None)
            if timer is not None:
                timer.cancel()
            self._reservations.pop(scan_run_id, None)
            self._promote_locked()

    def _expire(self, lease_id: str) -> None:
        with self._lock:
            run_id = next((rid for rid, lease in self._active.items() if lease.lease_id == lease_id), None)
            if run_id is None:
                return
            lease = self._active[run_id]
            now = float(self._clock())
            deadline = min(float(lease.expires_at), lease.heartbeat_deadline)
            if now < deadline:
                self._schedule_expiry_locked(run_id)
                return
            self._release_slot_locked(run_id)

    def _reconcile_locked(self, now: float) -> None:
        """Reclaim any lease whose holder is dead (heartbeat lapsed) so it
        cannot block a new run (REQ-RAWLEASE-003). The watchdog timer
        normally does this per-lease; this makes every request self-healing
        even if a timer has not yet fired, across ALL active leases."""
        dead = [run_id for run_id, lease in self._active.items() if now >= lease.heartbeat_deadline]
        for run_id in dead:
            self._release_slot_locked(run_id)

    def _check_reservation_locked(self, scan_run_id: str, reservation_token: str, now: float) -> None:
        item = self._reservations.get(scan_run_id)
        if item is None or not hmac.compare_digest(item.token, reservation_token):
            raise LeaseError("reservation_not_granted")
        # REQ-RAWLEASE-004: activity under the reservation (activate/heartbeat)
        # keeps it alive across a multi-stage scan spanning RESERVATION_IDLE_SECONDS.
        item.last_seen = now

    def activate(self, token: str, reservation_token: str) -> ActiveLease:
        now = int(self._clock())
        payload = verify_lease(token, self._secret, now=now)
        lease_id = str(payload["lease_id"])
        scan_run_id = str(payload["scan_run_id"])
        with self._lock:
            self._prune_locked(float(now))
            self._reconcile_locked(float(now))
            self._check_reservation_locked(scan_run_id, reservation_token, float(now))
            existing = self._active.get(scan_run_id)
            if existing is not None and now < existing.heartbeat_deadline:
                if existing.lease_id == lease_id:
                    return existing
                raise LeaseBusy("raw_egress_lease_busy")
            if not self._free_slots:
                # Should not happen given the reservation<->slot invariant above;
                # fail closed rather than silently exceed capacity.
                raise LeaseBusy("raw_egress_lease_busy")
            slot = self._free_slots.pop(0)
            ttl = max(1, payload["exp"] - now)
            kernel_ttl = min(ttl, ACTIVE_HEARTBEAT_SECONDS)
            self._policy.apply(
                slot, payload["resolved_target"], payload["ports"], kernel_ttl,
                payload["protocol"], int(payload["max_rate"]),
            )
            lease = ActiveLease(
                lease_id=lease_id, engagement_id=str(payload["engagement_id"]), scan_run_id=scan_run_id,
                expires_at=int(payload["exp"]), heartbeat_deadline=min(float(payload["exp"]), float(now) + ACTIVE_HEARTBEAT_SECONDS),
                authorized_target=str(payload["authorized_target"]), resolved_target=str(payload["resolved_target"]),
                max_rate=int(payload["max_rate"]), port_profile=str(payload["port_profile"]), protocol=str(payload["protocol"]),
                ports=list(payload["ports"]), slot=slot,
            )
            self._active[scan_run_id] = lease
            self._schedule_expiry_locked(scan_run_id)
            return lease

    def heartbeat(self, token: str, reservation_token: str) -> ActiveLease:
        payload = verify_lease(token, self._secret, now=int(self._clock()))
        scan_run_id = str(payload["scan_run_id"])
        with self._lock:
            now = float(self._clock())
            self._check_reservation_locked(scan_run_id, reservation_token, now)
            lease = self._active.get(scan_run_id)
            if lease is None or lease.lease_id != str(payload["lease_id"]):
                raise LeaseError("lease_not_active")
            remaining = max(1, min(int(lease.expires_at - now), ACTIVE_HEARTBEAT_SECONDS))
            # Refresh the kernel target timeout too. If the gateway process dies,
            # target egress therefore expires with the heartbeat, not the longer
            # signed capability TTL.
            self._policy.apply(lease.slot, lease.resolved_target, lease.ports, remaining, lease.protocol, lease.max_rate)
            lease.heartbeat_deadline = min(float(lease.expires_at), now + ACTIVE_HEARTBEAT_SECONDS)
            self._schedule_expiry_locked(scan_run_id)
            return lease

    def deactivate(self, token: str, reservation_token: str) -> None:
        """Best-effort, idempotent release (REQ-RAWLEASE-002). Only the holder of
        the CURRENT lease (proven by the signed token's lease_id) clears its OWN
        slot. If no matching lease is active, this is a no-op - it never errors
        and never clears a foreign lease's slot."""
        payload = verify_lease(token, self._secret, now=int(self._clock()), allow_expired=True)
        lease_id = str(payload["lease_id"])
        with self._lock:
            run_id = next((rid for rid, lease in self._active.items() if lease.lease_id == lease_id), None)
            if run_id is None:
                return
            lease = self._active.pop(run_id)
            self._policy.clear(lease.slot)
            self._free_slots.append(lease.slot)
            timer = self._expiry_timers.pop(run_id, None)
            if timer is not None:
                timer.cancel()

    def status(self) -> dict:
        now = float(self._clock())
        with self._lock:
            self._prune_locked(now)
            # Health darf keinen toten Lease als aktiv zeigen (REQ-RAWLEASE-003).
            self._reconcile_locked(now)
            active_leases = [
                {
                    "lease_id": lease.lease_id, "engagement_id": lease.engagement_id,
                    "scan_run_id": lease.scan_run_id, "expires_at": lease.expires_at,
                    "heartbeat_deadline": lease.heartbeat_deadline, "port_profile": lease.port_profile,
                    "protocol": lease.protocol, "slot": lease.slot,
                }
                for lease in self._active.values()
            ]
            return {
                "status": "ok", "policy_enforced": True,
                "max_concurrent_leases": self._max_concurrent,
                "active_leases": active_leases,
                "active_lease_count": len(active_leases),
                "free_slots": len(self._free_slots),
                "reserved_slots": len(self._reservations),
                "queue_length": len(self._queue),
            }
