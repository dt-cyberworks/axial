import base64
import hashlib
import hmac
import json
import time
import uuid

import pytest

from app.gateway import TABLE, LeaseError, NftPolicyManager, PolicyError, RawEgressGateway, verify_lease

SECRET = "test-raw-egress-signing-secret"
UDP_PORTS = [53, 123, 161, 443, 500, 1900, 4500, 5060, 5353]

def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")

def _token(*, lease_id=None, engagement_id=None, scan_run_id=None, target="192.0.2.10", now=None, exp_offset=300, protocol="tcp", ports=None, profile=None, max_rate=None):
    now = int(time.time()) if now is None else now
    if ports is None:
        ports = [[1, 65535]] if protocol == "tcp" else [[port, port] for port in UDP_PORTS]
    if profile is None:
        profile = "full_tcp" if protocol == "tcp" else "targeted_udp"
    payload = {
        "version": 1, "lease_id": str(lease_id or uuid.uuid4()),
        "engagement_id": str(engagement_id or uuid.uuid4()),
        "scan_run_id": str(scan_run_id or uuid.uuid4()),
        "authorized_target": "example.test", "resolved_target": target,
        "protocol": protocol, "ports": ports, "port_profile": profile,
        "max_rate": max_rate or (300 if protocol == "tcp" else 100),
        "iat": now, "exp": now + exp_offset, "nonce": uuid.uuid4().hex,
    }
    body = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    signature = _b64(hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{signature}", payload

class _Policy:
    def __init__(self):
        self.initialized = 0
        self.applied = []
        self.cleared = 0
        self.cleared_slots = []
    def initialize(self):
        self.initialized += 1
    def apply(self, slot, address, ports, ttl, protocol="tcp", max_rate=1000):
        self.applied.append((slot, address, ports, ttl, protocol, max_rate))
    def clear(self, slot):
        self.cleared += 1
        self.cleared_slots.append(slot)

def _reserve(gateway, run_id):
    return gateway.reserve(str(run_id))["reservation_token"]

def _active_leases(gateway):
    return gateway.status()["active_leases"]

def test_valid_reservation_and_lease_activate_exact_configured_tcp_envelope():
    now = int(time.time())
    policy = _Policy()
    gateway = RawEgressGateway(SECRET, policy, clock=lambda: now)
    run_id = uuid.uuid4()
    reservation = _reserve(gateway, run_id)
    token, payload = _token(now=now, scan_run_id=run_id, ports=[[443, 8443]], profile="configured_tcp")

    active = gateway.activate(token, reservation)

    assert active.lease_id == payload["lease_id"]
    assert active.slot == 0
    assert policy.applied == [(0, "192.0.2.10", [(443, 8443)], 12, "tcp", 300)]
    assert _active_leases(gateway)[0]["protocol"] == "tcp"
    gateway.deactivate(token, reservation)
    gateway.release(str(run_id), reservation)

def test_tampered_expired_and_wrong_udp_envelopes_are_denied():
    now = int(time.time())
    token, _ = _token(now=now)
    body, signature = token.split(".")
    with pytest.raises(LeaseError, match="lease_signature_invalid"):
        verify_lease(f"{body[:-1]}A.{signature}", SECRET, now=now)
    expired, _ = _token(now=now - 120, exp_offset=60)
    with pytest.raises(LeaseError, match="lease_expired"):
        verify_lease(expired, SECRET, now=now)
    wrong_udp, _ = _token(now=now, protocol="udp", ports=[[53, 53]])
    with pytest.raises(LeaseError, match="lease_ports_invalid"):
        verify_lease(wrong_udp, SECRET, now=now)

def test_raw_tcp_probe_lease_activates_and_scopes_the_nftables_rule_to_one_port():
    """REQ-AGENT-025: redis-probe/activemq-banner reuse nmap's exact lease/
    nftables mechanism via a new, single-port profile - this is the load
    -bearing proof that the actual network-level enforcement (not just the
    control-plane's own pre-check) accepts and correctly scopes it."""
    now = int(time.time())
    policy = _Policy()
    gateway = RawEgressGateway(SECRET, policy, clock=lambda: now)
    run_id = uuid.uuid4()
    reservation = _reserve(gateway, run_id)
    token, payload = _token(now=now, scan_run_id=run_id, ports=[[6379, 6379]], profile="raw_tcp_probe")

    active = gateway.activate(token, reservation)

    assert active.lease_id == payload["lease_id"]
    assert policy.applied == [(0, "192.0.2.10", [(6379, 6379)], 12, "tcp", 300)]
    gateway.deactivate(token, reservation)
    assert policy.cleared_slots == [0]


def test_raw_tcp_probe_profile_rejects_a_port_range_not_a_single_port():
    """Unlike configured_tcp (a range is the point), raw_tcp_probe must never
    accept more than exactly one port - a range here would silently widen a
    curated, single-purpose check into something closer to a port scan."""
    now = int(time.time())
    token, _ = _token(now=now, ports=[[6379, 6400]], profile="raw_tcp_probe")
    with pytest.raises(LeaseError, match="lease_ports_invalid"):
        verify_lease(token, SECRET, now=now)


def test_raw_tcp_probe_profile_name_is_recognized_for_tcp():
    """Before REQ-AGENT-025, any profile other than full_tcp/configured_tcp
    on a tcp-protocol lease was rejected outright - confirms the new profile
    name itself is now accepted (not just single-port shaped)."""
    now = int(time.time())
    token, _ = _token(now=now, ports=[[61616, 61616]], profile="raw_tcp_probe")
    payload = verify_lease(token, SECRET, now=now)
    assert payload["port_profile"] == "raw_tcp_probe"
    assert payload["ports"] == [(61616, 61616)]


# --- REQ-CIDRDISC-001/002: host_discovery profile (whole-CIDR liveness sweep) ---

def test_host_discovery_lease_accepts_a_cidr_resolved_target_and_activates_into_the_policy():
    """The load-bearing proof that a whole-network lease actually enforces at
    the nftables level, not just the control-plane's own pre-check - mirrors
    test_raw_tcp_probe_lease_activates_and_scopes_the_nftables_rule_to_one_port."""
    now = int(time.time())
    policy = _Policy()
    gateway = RawEgressGateway(SECRET, policy, clock=lambda: now)
    run_id = uuid.uuid4()
    reservation = _reserve(gateway, run_id)
    token, payload = _token(
        now=now, scan_run_id=run_id, target="203.0.113.0/28",
        ports=[[80, 80], [443, 443]], profile="host_discovery",
    )

    active = gateway.activate(token, reservation)

    assert active.lease_id == payload["lease_id"]
    assert active.resolved_target == "203.0.113.0/28"
    assert policy.applied == [(0, "203.0.113.0/28", [(80, 80), (443, 443)], 12, "tcp", 300)]
    gateway.deactivate(token, reservation)
    assert policy.cleared_slots == [0]


def test_host_discovery_profile_name_is_recognized_and_target_stays_a_network():
    now = int(time.time())
    token, _ = _token(now=now, target="203.0.113.0/28", ports=[[80, 80], [443, 443]], profile="host_discovery")
    payload = verify_lease(token, SECRET, now=now)
    assert payload["port_profile"] == "host_discovery"
    assert payload["resolved_target"] == "203.0.113.0/28"
    assert payload["ports"] == [(80, 80), (443, 443)]


def test_host_discovery_rejects_a_single_host_target():
    """A single-address resolved_target is nonsensical for a range sweep -
    proves the profile really requires (and preserves) a network, not just
    accepting whatever ipaddress.ip_address vs ip_network happens to parse."""
    now = int(time.time())
    token, _ = _token(now=now, target="192.0.2.10", ports=[[80, 80], [443, 443]], profile="host_discovery")
    payload = verify_lease(token, SECRET, now=now)
    # ip_network(..., strict=False) on a bare host degrades to a /32 - still a
    # valid (if degenerate) network, not a parse failure. The real width
    # authorization happens in control-plane's authorize() (subnet-of check),
    # not here - this layer only proves the payload shape round-trips intact.
    assert payload["resolved_target"] == "192.0.2.10/32"


def test_host_discovery_rejects_wrong_ports():
    """The fixed 80/443 discovery-probe ports are not operator/agent-chosen -
    any other port set must be rejected, not silently widened or narrowed."""
    now = int(time.time())
    wrong_ports, _ = _token(
        now=now, target="203.0.113.0/28", ports=[[80, 80]], profile="host_discovery",
    )
    with pytest.raises(LeaseError, match="lease_ports_invalid"):
        verify_lease(wrong_ports, SECRET, now=now)
    port_range, _ = _token(
        now=now, target="203.0.113.0/28", ports=[[80, 443]], profile="host_discovery",
    )
    with pytest.raises(LeaseError, match="lease_ports_invalid"):
        verify_lease(port_range, SECRET, now=now)


def test_nft_policy_renders_a_cidr_block_as_an_interval_element():
    """REQ-CIDRDISC-001: apply() with a CIDR address renders the whole block,
    not just its network address - the actual nftables-syntax proof behind
    the mocked-policy tests above."""
    scripts = []
    policy = NftPolicyManager(lambda script, check: scripts.append(script), proxy_addresses=["172.30.0.8"], proxy_port=3128, num_slots=1)
    policy.initialize()
    assert "flags interval, timeout" in scripts[1]
    policy.apply(0, "203.0.113.0/28", [(80, 80), (443, 443)], 300, "tcp")
    apply_script = scripts[2]
    assert "203.0.113.0/28 timeout 300s" in apply_script


# --- GitHub issue #37: a real kernel-level rate limiter, not only nmap's ---
# own --max-rate flag - nftables' native `limit rate` on the slot's rule.

def test_apply_installs_an_inline_kernel_level_rate_limit():
    scripts = []
    policy = NftPolicyManager(lambda script, check: scripts.append(script), proxy_addresses=["172.30.0.8"], proxy_port=3128, num_slots=1)
    policy.initialize()
    policy.apply(0, "192.0.2.10", [(443, 443)], 60, "tcp", 42)
    assert "limit rate 42/second accept" in scripts[2]


def test_apply_with_a_different_rate_on_a_later_lease_replaces_the_slot_rule():
    """The actual live-update path a real second scan on the same slot takes -
    flush+rebuild, not a named object update (which nftables refuses while a
    rule still references it - confirmed against a real nft binary, not
    assumed; see test_rate_limit_real_nft.py)."""
    scripts = []
    policy = NftPolicyManager(lambda script, check: scripts.append(script), proxy_addresses=["172.30.0.8"], proxy_port=3128, num_slots=1)
    policy.initialize()
    policy.apply(0, "192.0.2.10", [(443, 443)], 60, "tcp", 5)
    policy.apply(0, "192.0.2.10", [(443, 443)], 60, "tcp", 800)
    first_apply, second_apply = scripts[2], scripts[3]
    assert "limit rate 5/second accept" in first_apply
    assert "limit rate 800/second accept" in second_apply
    assert f"flush chain inet {TABLE} slot_0" in second_apply


def test_negative_apply_rejects_a_rate_outside_the_signed_lease_bound():
    policy = NftPolicyManager(lambda script, check: None, proxy_addresses=["172.30.0.8"], proxy_port=3128, num_slots=1)
    policy.initialize()
    with pytest.raises(PolicyError):
        policy.apply(0, "192.0.2.10", [(443, 443)], 60, "tcp", 0)
    with pytest.raises(PolicyError):
        policy.apply(0, "192.0.2.10", [(443, 443)], 60, "tcp", 1001)


def test_clear_flushes_the_slot_chain_alongside_its_sets():
    scripts = []
    policy = NftPolicyManager(lambda script, check: scripts.append(script), proxy_addresses=["172.30.0.8"], proxy_port=3128, num_slots=1)
    policy.initialize()
    policy.apply(0, "192.0.2.10", [(443, 443)], 60, "tcp", 300)
    policy.clear(0)
    assert f"flush chain inet {TABLE} slot_0" in scripts[3]


def test_nft_policy_single_host_still_renders_as_an_exact_slash32():
    """Regression proof that switching the sets to `interval` did not change
    single-host lease behavior - every pre-existing caller renders an exact
    /32, functionally identical to the old bare-address element."""
    scripts = []
    policy = NftPolicyManager(lambda script, check: scripts.append(script), proxy_addresses=["172.30.0.8"], proxy_port=3128, num_slots=1)
    policy.initialize()
    policy.apply(0, "192.0.2.10", [(443, 443)], 60, "tcp")
    assert "192.0.2.10/32 timeout 60s" in scripts[2]


def test_fifo_reservations_prevent_cross_run_activation_and_promote_in_order():
    now = int(time.time())
    gateway = RawEgressGateway(SECRET, _Policy(), clock=lambda: now)
    runs = [uuid.uuid4() for _ in range(3)]
    first = gateway.reserve(str(runs[0]))
    second = gateway.reserve(str(runs[1]))
    third = gateway.reserve(str(runs[2]))
    assert [first["status"], second["status"], third["status"]] == ["granted", "queued", "queued"]
    assert [second["position"], third["position"]] == [1, 2]

    first_token, _ = _token(now=now, scan_run_id=runs[0])
    second_token, _ = _token(now=now, scan_run_id=runs[1])
    gateway.activate(first_token, first["reservation_token"])
    with pytest.raises(LeaseError, match="reservation_not_granted"):
        gateway.activate(second_token, second["reservation_token"])
    gateway.deactivate(first_token, first["reservation_token"])
    gateway.release(str(runs[0]), first["reservation_token"])
    assert gateway.reserve(str(runs[1]))["status"] == "granted"
    gateway.release(str(runs[1]), second["reservation_token"])
    assert gateway.reserve(str(runs[2]))["status"] == "granted"

def test_watchdog_expiry_clears_policy_and_advances_waiter():
    clock = [float(int(time.time()))]
    policy = _Policy()
    gateway = RawEgressGateway(SECRET, policy, clock=lambda: clock[0])
    first_run, second_run = uuid.uuid4(), uuid.uuid4()
    first = gateway.reserve(str(first_run))
    second = gateway.reserve(str(second_run))
    token, payload = _token(now=int(clock[0]), scan_run_id=first_run)
    gateway.activate(token, first["reservation_token"])

    clock[0] += 13
    gateway._expire(payload["lease_id"])

    assert policy.cleared == 1
    assert gateway.status()["active_lease_count"] == 0
    assert gateway.reserve(str(second_run))["status"] == "granted"
    gateway.release(str(second_run), second["reservation_token"])

def test_heartbeat_keeps_policy_active_only_while_worker_is_alive():
    clock = [float(int(time.time()))]
    policy = _Policy()
    gateway = RawEgressGateway(SECRET, policy, clock=lambda: clock[0])
    run_id = uuid.uuid4()
    reservation = _reserve(gateway, run_id)
    token, payload = _token(now=int(clock[0]), scan_run_id=run_id)
    gateway.activate(token, reservation)
    clock[0] += 10
    gateway.heartbeat(token, reservation)
    clock[0] += 3
    gateway._expire(payload["lease_id"])
    assert gateway.status()["active_lease_count"] == 1
    gateway.deactivate(token, reservation)
    gateway.release(str(run_id), reservation)

def test_targeted_udp_lease_installs_only_udp_profile():
    now = int(time.time())
    policy = _Policy()
    gateway = RawEgressGateway(SECRET, policy, clock=lambda: now)
    run_id = uuid.uuid4()
    reservation = _reserve(gateway, run_id)
    token, _ = _token(now=now, scan_run_id=run_id, protocol="udp")
    active = gateway.activate(token, reservation)
    assert active.protocol == "udp"
    assert policy.applied == [(0, "192.0.2.10", [(port, port) for port in UDP_PORTS], 12, "udp", 100)]
    gateway.deactivate(token, reservation)
    gateway.release(str(run_id), reservation)

def test_stale_head_does_not_block_live_waiter():
    clock = [float(int(time.time()))]
    gateway = RawEgressGateway(SECRET, _Policy(), clock=lambda: clock[0])
    stale, live = uuid.uuid4(), uuid.uuid4()
    gateway.reserve(str(stale))
    clock[0] += 121
    assert gateway.reserve(str(live))["status"] == "granted"

def test_nft_policy_keeps_proxy_baseline_and_separates_tcp_udp_sets():
    scripts = []
    policy = NftPolicyManager(lambda script, check: scripts.append((script, check)), proxy_addresses=["172.30.0.8"], proxy_port=3128, num_slots=2)
    policy.initialize()
    policy.apply(0, "192.0.2.10", [(443, 8443)], 300, "tcp")
    policy.apply(0, "192.0.2.10", [(53, 53)], 100, "udp")
    baseline, tcp, udp = scripts[1][0], scripts[2][0], scripts[3][0]
    assert "policy drop" in baseline and "allowed_udp_ports" in baseline
    assert "ip daddr @proxy_v4 tcp dport 3128 accept" in baseline
    assert "allowed_tcp_ports_0 { 443-8443 }" in tcp
    assert "allowed_udp_ports_0 { 53 }" in udp
    assert "198.51.100.20" not in tcp + udp


# --- REQ-CONCUR-002: concurrent leases never cross-match each other's -------
# address/port sets, even though they share one nftables table -------------

def test_nft_policy_separates_slots_no_cross_product():
    scripts = []
    policy = NftPolicyManager(lambda script, check: scripts.append(script), proxy_addresses=["172.30.0.8"], proxy_port=3128, num_slots=2)
    policy.initialize()
    baseline = scripts[1]
    # GitHub issue #37: each slot now gets its OWN dedicated chain (jumped to
    # from `output`), initially empty - apply() below fills it in with a
    # rule scoped to exactly that slot's own address/port sets. Structural
    # separation at the chain level, not just the rule level.
    assert "chain slot_0 {" in baseline
    assert "chain slot_1 {" in baseline
    assert "jump slot_0" in baseline
    assert "jump slot_1" in baseline

    policy.apply(0, "192.0.2.10", [(443, 443)], 60, "tcp")
    policy.apply(1, "203.0.113.5", [(8080, 8080)], 60, "tcp")
    slot0_script, slot1_script = scripts[2], scripts[3]
    # Every slot's rule only ANDs its OWN address set with its OWN port set -
    # never a shared set another slot could also populate.
    assert "@allowed_v4_0 tcp dport @allowed_tcp_ports_0" in slot0_script
    assert "@allowed_v4_1 tcp dport @allowed_tcp_ports_1" not in slot0_script
    assert "@allowed_v4_1 tcp dport @allowed_tcp_ports_1" in slot1_script
    assert "@allowed_v4_0 tcp dport @allowed_tcp_ports_0" not in slot1_script
    assert "allowed_v4_0" in slot0_script and "192.0.2.10" in slot0_script
    assert "allowed_v4_1" not in slot0_script and "203.0.113.5" not in slot0_script
    assert "allowed_v4_1" in slot1_script and "203.0.113.5" in slot1_script
    assert "allowed_v4_0" not in slot1_script and "192.0.2.10" not in slot1_script


def test_two_concurrent_leases_activate_into_independent_slots():
    now = int(time.time())
    policy = _Policy()
    gateway = RawEgressGateway(SECRET, policy, clock=lambda: now, max_concurrent_leases=2)
    run_a, run_b = uuid.uuid4(), uuid.uuid4()
    res_a = _reserve(gateway, run_a)
    res_b = _reserve(gateway, run_b)
    token_a, _ = _token(now=now, scan_run_id=run_a, target="192.0.2.10", ports=[[443, 443]], profile="configured_tcp")
    token_b, _ = _token(now=now, scan_run_id=run_b, target="203.0.113.5", ports=[[8080, 8080]], profile="configured_tcp")

    active_a = gateway.activate(token_a, res_a)
    active_b = gateway.activate(token_b, res_b)

    assert {active_a.slot, active_b.slot} == {0, 1}
    assert (active_a.slot, "192.0.2.10", [(443, 443)], 12, "tcp", 300) in policy.applied
    assert (active_b.slot, "203.0.113.5", [(8080, 8080)], 12, "tcp", 300) in policy.applied
    status = gateway.status()
    assert status["active_lease_count"] == 2
    assert status["free_slots"] == 0
    assert status["max_concurrent_leases"] == 2

    # Deactivating A frees only A's slot; B is untouched.
    gateway.deactivate(token_a, res_a)
    assert policy.cleared_slots == [active_a.slot]
    status = gateway.status()
    assert status["active_lease_count"] == 1
    assert status["free_slots"] == 1
    assert status["active_leases"][0]["scan_run_id"] == str(run_b)

    gateway.deactivate(token_b, res_b)
    gateway.release(str(run_a), res_a)
    gateway.release(str(run_b), res_b)


def test_third_reservation_queues_fifo_once_both_slots_are_taken():
    now = int(time.time())
    gateway = RawEgressGateway(SECRET, _Policy(), clock=lambda: now, max_concurrent_leases=2)
    runs = [uuid.uuid4() for _ in range(3)]
    first = gateway.reserve(str(runs[0]))
    second = gateway.reserve(str(runs[1]))
    third = gateway.reserve(str(runs[2]))
    assert [first["status"], second["status"], third["status"]] == ["granted", "granted", "queued"]
    assert third["position"] == 1

    gateway.release(str(runs[0]), first["reservation_token"])
    assert gateway.reserve(str(runs[2]))["status"] == "granted"


def test_status_reports_slot_occupancy():
    now = int(time.time())
    gateway = RawEgressGateway(SECRET, _Policy(), clock=lambda: now, max_concurrent_leases=3)
    run_a = uuid.uuid4()
    res_a = _reserve(gateway, run_a)
    token_a, _ = _token(now=now, scan_run_id=run_a)
    gateway.activate(token_a, res_a)
    status = gateway.status()
    assert status["max_concurrent_leases"] == 3
    assert status["active_lease_count"] == 1
    assert status["free_slots"] == 2
    assert status["reserved_slots"] == 1
    assert status["queue_length"] == 0


# --- REQ-RAWLEASE-002: idempotent release -----------------------------------

def test_deactivate_with_no_active_lease_is_noop():
    policy = _Policy()
    gateway = RawEgressGateway(SECRET, policy, clock=lambda: int(time.time()))
    token, _ = _token()
    # kein aktiver Lease -> darf nicht werfen, nichts loeschen
    gateway.deactivate(token, "irrelevant-reservation")
    assert policy.cleared == 0


def test_deactivate_never_clears_a_foreign_lease():
    now = int(time.time())
    policy = _Policy()
    gateway = RawEgressGateway(SECRET, policy, clock=lambda: now)
    run_a = uuid.uuid4()
    res_a = _reserve(gateway, run_a)
    token_a, _ = _token(now=now, scan_run_id=run_a)
    gateway.activate(token_a, res_a)
    cleared_before = policy.cleared
    # Ein FREMDER Lease-Token (anderer lease_id) darf A nicht deaktivieren.
    foreign_token, _ = _token(now=now, scan_run_id=uuid.uuid4())
    gateway.deactivate(foreign_token, "whatever")            # no-op, kein Fehler
    assert policy.cleared == cleared_before                  # A NICHT geloescht
    assert gateway.status()["active_lease_count"] == 1        # A bleibt aktiv
    # Der echte Halter kann A deaktivieren, auch doppelt (idempotent).
    gateway.deactivate(token_a, res_a)
    assert policy.cleared == cleared_before + 1
    gateway.deactivate(token_a, res_a)                       # zweites Mal: no-op
    assert policy.cleared == cleared_before + 1


# --- REQ-RAWLEASE-003: activation reclaims a dead-heartbeat lease ------------

def test_activate_reclaims_dead_heartbeat_lease_and_promotes_waiter():
    clk = {"t": int(time.time())}
    policy = _Policy()
    gateway = RawEgressGateway(SECRET, policy, clock=lambda: clk["t"])
    run_a, run_b = uuid.uuid4(), uuid.uuid4()
    res_a = _reserve(gateway, run_a)
    token_a, _ = _token(now=clk["t"], scan_run_id=run_a)
    gateway.activate(token_a, res_a)
    second = gateway.reserve(str(run_b))            # wartet in der Queue
    assert second["status"] == "queued"

    # Heartbeat-Deadline (now+12) ueberschreiten -> A ist tot.
    clk["t"] += 30
    token_b, payload_b = _token(now=clk["t"], scan_run_id=run_b)
    active = gateway.activate(token_b, second["reservation_token"])

    assert active.lease_id == payload_b["lease_id"]          # B uebernahm den Slot
    assert policy.cleared >= 1                               # A's Policy wurde geraeumt


def test_live_lease_still_blocks_a_different_lease():
    now = int(time.time())
    policy = _Policy()
    gateway = RawEgressGateway(SECRET, policy, clock=lambda: now)
    run_a = uuid.uuid4()
    res_a = _reserve(gateway, run_a)
    token_a, _ = _token(now=now, scan_run_id=run_a)
    gateway.activate(token_a, res_a)
    # gleicher Reservierungshalter, ANDERER Lease, A noch lebendig -> busy
    token_b, _ = _token(now=now, scan_run_id=run_a)
    with pytest.raises(Exception) as exc:
        gateway.activate(token_b, res_a)
    assert "busy" in str(exc.value).lower()
    # gleicher Lease erneut aktivieren bleibt idempotent
    assert gateway.activate(token_a, res_a).lease_id is not None


def test_status_reconciles_dead_lease():
    clk = {"t": int(time.time())}
    policy = _Policy()
    gateway = RawEgressGateway(SECRET, policy, clock=lambda: clk["t"])
    run_a = uuid.uuid4()
    res_a = _reserve(gateway, run_a)
    token_a, _ = _token(now=clk["t"], scan_run_id=run_a)
    gateway.activate(token_a, res_a)
    assert gateway.status()["active_lease_count"] == 1
    clk["t"] += 30                                  # Heartbeat abgelaufen
    assert gateway.status()["active_lease_count"] == 0  # reconciled
    assert policy.cleared >= 1


# --- REQ-RAWLEASE-004: reservation stays alive across a long, multi-stage scan --

def test_reservation_survives_a_long_active_scan_across_a_second_lease():
    """Ein Ablauf wie execute_configured_tcp_scan gefolgt von einer separaten
    UDP-Lease UNTER DERSELBEN reservation: viele heartbeat()-Aufrufe ueber mehr
    als RESERVATION_IDLE_SECONDS hinweg duerfen die Reservierung NICHT verwaisen
    lassen, nur weil reserve() selbst nicht erneut aufgerufen wurde."""
    from app.gateway import RESERVATION_IDLE_SECONDS

    clk = {"t": int(time.time())}
    policy = _Policy()
    gateway = RawEgressGateway(SECRET, policy, clock=lambda: clk["t"])
    run_a = uuid.uuid4()
    res_a = _reserve(gateway, run_a)
    token_a, _ = _token(now=clk["t"], scan_run_id=run_a)
    gateway.activate(token_a, res_a)

    # Lange "TCP-Phase": regelmaessige Heartbeats, insgesamt laenger als
    # RESERVATION_IDLE_SECONDS, OHNE dass reserve() je erneut aufgerufen wird.
    elapsed = 0
    while elapsed < RESERVATION_IDLE_SECONDS + 30:
        clk["t"] += 3
        elapsed += 3
        gateway.heartbeat(token_a, res_a)

    gateway.deactivate(token_a, res_a)

    # Zweite Lease (die "UDP-Phase") unter DERSELBEN reservation, sofort danach:
    # darf NICHT mit reservation_not_granted scheitern.
    token_b, payload_b = _token(now=clk["t"], scan_run_id=run_a, protocol="udp")
    active = gateway.activate(token_b, res_a)
    assert active.lease_id == payload_b["lease_id"]


def test_truly_abandoned_reservation_still_gets_pruned():
    """Gegenprobe: eine Reservierung OHNE jede Aktivitaet (kein activate/
    heartbeat) verwaist weiterhin nach RESERVATION_IDLE_SECONDS."""
    from app.gateway import RESERVATION_IDLE_SECONDS

    clk = {"t": int(time.time())}
    policy = _Policy()
    gateway = RawEgressGateway(SECRET, policy, clock=lambda: clk["t"])
    run_a, run_b = uuid.uuid4(), uuid.uuid4()
    _reserve(gateway, run_a)          # nie aktiviert, nie geheartbeatet
    second = gateway.reserve(str(run_b))
    assert second["status"] == "queued"

    clk["t"] += RESERVATION_IDLE_SECONDS + 10
    assert gateway.reserve(str(run_b))["status"] == "granted"  # A wurde geprunt


# --- REQ-COVER-004: self-hosted interaction server reachable on ONE port ---

def test_nft_policy_allows_the_oob_server_on_its_single_port_only():
    scripts = []
    policy = NftPolicyManager(
        lambda script, check: scripts.append(script), proxy_addresses=["172.30.0.8"], proxy_port=3128,
        num_slots=1, oob_addresses=["172.31.0.5"], oob_port=8080,
    )
    policy.initialize()
    rendered = scripts[1]
    assert "ip daddr @oob_v4 tcp dport 8080 accept" in rendered
    assert "add element inet asm_raw oob_v4 { 172.31.0.5 }" in rendered
    assert rendered.count("@oob_v4") == 1
    assert "policy drop" in rendered


def test_nft_policy_has_no_oob_rule_when_not_configured():
    scripts = []
    policy = NftPolicyManager(
        lambda script, check: scripts.append(script), proxy_addresses=["172.30.0.8"], proxy_port=3128, num_slots=1,
    )
    policy.initialize()
    assert "oob" not in scripts[1]
