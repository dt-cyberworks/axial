"""REQ-RAWLEASE-005 / REQ-RAWLEASE-006: the deny-all policy follows the proxy (and interaction server) to a new address,
changes nothing else, and says on /health whether the runner can reach the proxy."""

from __future__ import annotations

import json
import socket

import pytest

from app.endpoints import EndpointWatcher, probe_tcp, resolve, vet
from app.gateway import NftPolicyManager, PolicyError, RawEgressGateway

PROXY = "egress-proxy"


def _policy(scripts, *, oob_addresses=None, oob_enabled=False, proxy=("172.30.0.8",), fail=False):
    def run(script, check):
        if fail and "flush set" in script:
            raise PolicyError("nft_failed")
        scripts.append(script)

    return NftPolicyManager(
        run, proxy_addresses=list(proxy), proxy_port=3128, num_slots=2,
        oob_addresses=oob_addresses, oob_port=8080, oob_enabled=oob_enabled,
    )


# --- the policy: what a refresh may touch ---

def test_a_moved_proxy_replaces_only_the_proxy_set():
    scripts = []
    policy = _policy(scripts)
    policy.initialize()
    assert policy.refresh_endpoints(proxy_addresses=["172.30.0.9"]) is True
    refresh = scripts[-1]
    assert refresh == (
        "flush set inet asm_raw proxy_v4\n"
        "add element inet asm_raw proxy_v4 { 172.30.0.9 }\n"
    )


def test_a_refresh_never_touches_the_slot_sets_the_chains_or_the_verdicts():
    """Negative: whatever the addresses, the script is only flush + add element on the two endpoint sets."""
    scripts = []
    policy = _policy(scripts, oob_addresses=["172.31.0.5"])
    policy.initialize()
    policy.refresh_endpoints(proxy_addresses=["172.30.0.9", "fd00::9"], oob_addresses=["172.31.0.6"])
    for line in scripts[-1].strip().splitlines():
        assert line.startswith(("flush set inet asm_raw ", "add element inet asm_raw "))
        assert line.split()[4] in {"proxy_v4", "proxy_v6", "oob_v4"}
    for forbidden in ("allowed_", "slot_", "delete", "policy", "accept", "drop", "chain", "table inet asm_raw {"):
        assert forbidden not in scripts[-1]


def test_an_unchanged_address_runs_nothing():
    scripts = []
    policy = _policy(scripts)
    policy.initialize()
    count = len(scripts)
    assert policy.refresh_endpoints(proxy_addresses=["172.30.0.8"]) is False
    assert len(scripts) == count


def test_none_leaves_an_endpoint_alone():
    scripts = []
    policy = _policy(scripts, oob_addresses=["172.31.0.5"])
    policy.initialize()
    count = len(scripts)
    assert policy.refresh_endpoints(proxy_addresses=None, oob_addresses=None) is False
    assert len(scripts) == count


def test_an_empty_proxy_list_is_refused_and_the_old_address_stays():
    scripts = []
    policy = _policy(scripts)
    policy.initialize()
    count = len(scripts)
    with pytest.raises(PolicyError, match="proxy_addresses_empty"):
        policy.refresh_endpoints(proxy_addresses=[])
    assert len(scripts) == count
    assert policy.refresh_endpoints(proxy_addresses=["172.30.0.8"]) is False  # still the original


def test_a_failed_nft_run_does_not_record_the_new_address():
    """If the kernel did not take the change, the recorded state must not claim it did."""
    scripts = []
    policy = _policy(scripts, fail=True)
    policy.initialize()
    with pytest.raises(PolicyError):
        policy.refresh_endpoints(proxy_addresses=["172.30.0.9"])
    policy2_scripts = []
    # same manager, kernel healthy again: the same refresh must be attempted again, not skipped as "unchanged"
    policy._run = lambda script, check: policy2_scripts.append(script)
    assert policy.refresh_endpoints(proxy_addresses=["172.30.0.9"]) is True
    assert "add element inet asm_raw proxy_v4 { 172.30.0.9 }" in policy2_scripts[0]


def test_an_address_family_switch_flushes_the_old_family_and_fills_the_new_one():
    scripts = []
    policy = _policy(scripts)
    policy.initialize()
    policy.refresh_endpoints(proxy_addresses=["fd00::9"])
    assert scripts[-1] == (
        "flush set inet asm_raw proxy_v4\n"
        "flush set inet asm_raw proxy_v6\n"
        "add element inet asm_raw proxy_v6 { fd00::9 }\n"
    )


def test_garbage_addresses_are_rejected_before_any_nft_run():
    scripts = []
    policy = _policy(scripts)
    policy.initialize()
    count = len(scripts)
    with pytest.raises(ValueError):
        policy.refresh_endpoints(proxy_addresses=["172.30.0.9; flush ruleset"])
    assert len(scripts) == count


# --- the interaction server ---

def test_an_interaction_server_that_was_down_at_start_can_be_added_later():
    scripts = []
    policy = _policy(scripts, oob_enabled=True)  # configured, but its name did not resolve at start-up
    policy.initialize()
    start = scripts[-1]
    assert "set oob_v4" in start and "ip daddr @oob_v4 tcp dport 8080 accept" in start
    assert "add element inet asm_raw oob_v4" not in start  # nothing allowed yet
    assert policy.refresh_endpoints(oob_addresses=["172.31.0.5"]) is True
    assert scripts[-1] == "flush set inet asm_raw oob_v4\nadd element inet asm_raw oob_v4 { 172.31.0.5 }\n"


def test_a_policy_without_an_interaction_server_never_gains_one():
    """Negative: oob not configured -> an address handed to refresh is ignored, there is no set to put it in."""
    scripts = []
    policy = _policy(scripts)
    policy.initialize()
    count = len(scripts)
    assert policy.refresh_endpoints(oob_addresses=["172.31.0.5"]) is False
    assert len(scripts) == count
    assert "oob" not in scripts[-1]


def test_interaction_server_addresses_stay_ipv4_only():
    scripts = []
    policy = _policy(scripts, oob_enabled=True)
    policy.initialize()
    policy.refresh_endpoints(oob_addresses=["fd00::5", "172.31.0.5"])
    assert "fd00::5" not in scripts[-1] and "172.31.0.5" in scripts[-1]


def test_the_gateway_wrapper_serializes_with_the_lease_operations():
    scripts = []
    gateway = RawEgressGateway("s", _policy(scripts))
    gateway.initialize()
    assert gateway.refresh_endpoints(proxy_addresses=["172.30.0.9"]) is True
    assert not gateway._lock.locked()


# --- what counts as a usable service address ---

@pytest.mark.parametrize("bad", [
    "0.0.0.0", "127.0.0.1", "::1", "169.254.169.254", "fe80::1", "224.0.0.1", "ff02::1", "240.0.0.1", "not-an-ip", "",
])
def test_vet_drops_addresses_that_cannot_be_a_service_on_a_bridge(bad):
    assert vet([bad]) == []


def test_vet_keeps_private_addresses_sorted_and_unique():
    assert vet(["172.20.0.4", "172.20.0.4", "10.0.0.2", "fe80::1%eth0", "fd00::2"]) == ["10.0.0.2", "172.20.0.4", "fd00::2"]


def test_resolve_returns_nothing_for_a_name_that_does_not_resolve():
    assert resolve("no-such-name.invalid", 3128) == []


def test_resolve_vets_what_the_lookup_returns(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 3128)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("172.20.0.4", 3128)),
    ])
    assert resolve(PROXY, 3128) == ["172.20.0.4"]


def test_probe_tcp_sees_an_open_and_a_closed_port():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        assert probe_tcp(["127.0.0.1"], port) is True
        assert probe_tcp(["10.255.255.1", "127.0.0.1"], port) is True  # any address that accepts is enough
    finally:
        server.close()
    assert probe_tcp(["127.0.0.1"], port) is False
    assert probe_tcp([], port) is False


# --- the watcher ---

class FakeGateway:
    def __init__(self, error=None, installed=("172.20.0.4",)):
        self.calls = []
        self.error = error
        self.installed = list(installed)

    def proxy_addresses(self):
        return list(self.installed)

    def refresh_endpoints(self, proxy_addresses=None, oob_addresses=None):
        self.calls.append((proxy_addresses, oob_addresses))
        if self.error:
            raise self.error
        if proxy_addresses is not None:
            self.installed = list(proxy_addresses)
        return proxy_addresses is not None or oob_addresses is not None


def _watcher(gateway, answers, *, reachable=True, oob_host="", log=None, clock=lambda: 1000.0, probed=None, **extra):
    def resolver(host, port, family):
        value = answers.get(host, [])
        if isinstance(value, Exception):
            raise value
        return value

    def prober(addresses, port):
        if probed is not None:
            probed.append(list(addresses))
        return reachable() if callable(reachable) else reachable

    return EndpointWatcher(
        gateway, proxy_host=PROXY, proxy_port=3128, oob_host=oob_host, oob_port=8080,
        resolver=resolver, prober=prober, clock=clock, log=(log.append if log is not None else lambda message: None),
        **extra,
    )


def test_a_moved_proxy_is_handed_to_the_gateway_and_reported():
    gateway, log = FakeGateway(installed=["172.20.0.2"]), []
    watcher = _watcher(gateway, {PROXY: ["172.20.0.4"]}, log=log)
    watcher.check()
    assert gateway.calls == [(["172.20.0.4"], None)]
    status = watcher.status()["proxy"]
    assert status["resolved"] is True and status["reachable"] is True and status["changed_at"] == 1000.0
    assert any("address changed" in line for line in log)


def test_a_name_that_does_not_resolve_keeps_the_last_known_address():
    """Negative: an empty lookup must never be passed on as "the proxy has no address"."""
    gateway = FakeGateway()
    watcher = _watcher(gateway, {PROXY: []}, reachable=False)
    watcher.check()
    assert gateway.calls == [(None, None)]
    status = watcher.status()["proxy"]
    assert status["resolved"] is False and status["reachable"] is False


def test_a_policy_error_is_reported_and_does_not_stop_the_watcher():
    gateway = FakeGateway(error=PolicyError("nft_failed"))
    watcher = _watcher(gateway, {PROXY: ["172.20.0.4"]})
    watcher.check()
    watcher.check()
    assert watcher.status()["proxy"]["refresh_error"] == "nft_failed"
    assert len(gateway.calls) == 2


def test_an_unexpected_error_inside_a_pass_never_escapes():
    watcher = _watcher(FakeGateway(error=KeyError("boom")), {PROXY: ["172.20.0.4"]})
    watcher.check()
    assert watcher.status()["proxy"]["refresh_error"] == "unexpected:KeyError"


def test_a_resolver_that_raises_is_an_empty_answer_not_a_dead_watcher():
    gateway = FakeGateway()
    watcher = _watcher(gateway, {PROXY: RuntimeError("boom")})
    watcher.check()
    assert gateway.calls == [(None, None)]
    assert watcher.status()["proxy"]["resolved"] is False


def test_losing_and_regaining_the_proxy_is_logged_once_per_change():
    state = {"up": True}
    log = []
    watcher = _watcher(FakeGateway(), {PROXY: ["172.20.0.4"]}, reachable=lambda: state["up"], log=log)
    watcher.check()
    state["up"] = False
    watcher.check()
    watcher.check()
    state["up"] = True
    watcher.check()
    notes = [line for line in log if "reach the egress proxy" in line]
    assert [("can NOT" in line) for line in notes] == [True, False]


def test_the_probe_goes_to_the_addresses_the_policy_allows_not_to_the_name():
    probed = []
    watcher = _watcher(FakeGateway(installed=["172.20.0.4"]), {PROXY: ["172.20.0.4"]}, probed=probed)
    watcher.check()
    assert probed == [["172.20.0.4"]]


def test_a_policy_that_lags_behind_a_moved_proxy_reads_as_unreachable_even_if_the_old_address_answers():
    """Negative: the runner resolves the NAME and connects to the answer; an old address that still accepts
    connections (a squatter, a slow shutdown) must not make a policy that does not allow the new one look healthy."""
    probed = []
    gateway = FakeGateway(error=PolicyError("nft_failed"), installed=["172.20.0.2"])
    watcher = _watcher(gateway, {PROXY: ["172.20.0.5"]}, reachable=True, probed=probed)
    watcher.check()
    assert watcher.status()["proxy"]["reachable"] is False
    assert probed == []  # nothing to connect to: the new address is not allowed, the old one is not what the name says


def test_while_the_name_does_not_resolve_the_last_known_address_is_still_probed():
    """A stopped proxy: the lookup fails, the policy keeps the old address, and a direct connect to it fails fast."""
    probed = []
    answers = {PROXY: ["172.20.0.4"]}
    watcher = _watcher(FakeGateway(installed=["172.20.0.4"]), answers, reachable=False, probed=probed)
    watcher.check()
    answers[PROXY] = []
    watcher.check()
    assert probed == [["172.20.0.4"], ["172.20.0.4"]]
    assert watcher.status()["proxy"]["reachable"] is False


def test_a_slow_lookup_does_not_delay_the_reachability_check():
    """The measured case: a vanished name takes 5 s to fail. The check must still answer within the probe time."""
    import threading
    import time as _time

    release = threading.Event()
    watcher = _watcher(
        FakeGateway(), {}, reachable=False, lookup_timeout=0.05,
    )
    watcher._resolver = lambda host, port, family: (release.wait(5), [])[1]
    started = _time.monotonic()
    watcher.check_resolution()              # abandons the stuck lookup after its timeout
    watcher.check_reachability()
    assert _time.monotonic() - started < 1.0
    assert watcher.status()["proxy"]["reachable"] is False
    release.set()


def test_stuck_lookups_cannot_pile_up_without_bound():
    import threading

    from app import endpoints

    release = threading.Event()
    calls = []

    def stuck(host, port, family):
        calls.append(1)
        release.wait(5)
        return []

    watcher = _watcher(FakeGateway(), {}, lookup_timeout=0.01)
    watcher._resolver = stuck
    for _ in range(endpoints.MAX_LOOKUPS_IN_FLIGHT + 5):
        watcher.check_resolution()
    assert len(calls) <= endpoints.MAX_LOOKUPS_IN_FLIGHT
    release.set()


def test_the_interaction_server_is_followed_only_when_configured():
    gateway = FakeGateway()
    _watcher(gateway, {PROXY: ["172.20.0.4"], "oob.invalid": ["172.31.0.5"]}).check()
    assert gateway.calls == [(["172.20.0.4"], None)]  # not configured -> never looked up, never passed on

    gateway = FakeGateway()
    watcher = _watcher(gateway, {PROXY: ["172.20.0.4"], "oob.invalid": ["172.31.0.5"]}, oob_host="oob.invalid")
    watcher.check()
    assert gateway.calls == [(["172.20.0.4"], None), (None, ["172.31.0.5"])]
    assert watcher.status()["oob"] == {"configured": True, "resolved": True}


def test_an_interaction_server_name_that_stops_resolving_keeps_the_last_known_address():
    gateway = FakeGateway()
    watcher = _watcher(gateway, {PROXY: ["172.20.0.4"], "oob.invalid": []}, oob_host="oob.invalid")
    watcher.check()
    assert gateway.calls == [(["172.20.0.4"], None), (None, None)]
    assert watcher.status()["oob"] == {"configured": True, "resolved": False}


def test_the_status_carries_no_addresses():
    """/health is open to every peer on the runner network: booleans and times only."""
    watcher = _watcher(FakeGateway(), {PROXY: ["172.20.0.4"], "oob.invalid": ["172.31.0.5"]}, oob_host="oob.invalid")
    watcher.check()
    text = json.dumps(watcher.status())
    assert "172.20.0.4" not in text and "172.31.0.5" not in text


def test_the_background_loops_keep_checking_until_stopped():
    import threading

    seen = threading.Event()
    calls = []

    class Counting(FakeGateway):
        def refresh_endpoints(self, proxy_addresses=None, oob_addresses=None):
            calls.append(1)
            if len(calls) >= 2:
                seen.set()
            return False

    watcher = _watcher(Counting(), {PROXY: ["172.20.0.4"]})
    watcher._interval = 0.01
    threads = watcher.start()
    assert seen.wait(5)
    assert {t.name for t in threads} == {"endpoint-resolution", "endpoint-reachability"}  # no oob configured here
    watcher.stop()
    for thread in threads:
        thread.join(5)
        assert not thread.is_alive()


def test_the_reachability_loop_looks_again_sooner_while_the_proxy_is_unreachable():
    from app import endpoints

    class Clock:
        def __init__(self):
            self.waits, self.rounds = [], 0

        def is_set(self):
            return self.rounds >= 2

        def wait(self, seconds):
            self.waits.append(seconds)
            self.rounds += 1

    for reachable, expected in ((True, 30.0), (False, endpoints.RECOVERY_INTERVAL_S)):
        watcher = _watcher(FakeGateway(), {PROXY: ["172.20.0.4"]}, reachable=reachable)
        watcher._interval = 30.0
        watcher._stop = Clock()
        watcher._reachability_loop()
        assert watcher._stop.waits == [expected, expected]


def test_a_name_that_never_resolves_for_the_interaction_server_does_not_slow_the_proxy_loop():
    """Int has no interaction server, so its name never resolves and every lookup runs into its timeout."""
    import threading
    import time as _time

    release = threading.Event()
    gateway = FakeGateway(installed=["172.20.0.2"])

    def resolver(host, port, family):
        if host == "oob.invalid":
            release.wait(5)
            return []
        return ["172.20.0.4"]

    watcher = EndpointWatcher(
        gateway, proxy_host=PROXY, proxy_port=3128, oob_host="oob.invalid", oob_port=8080, resolver=resolver,
        prober=lambda addresses, port: True, log=lambda message: None, lookup_timeout=0.5,
    )
    started = _time.monotonic()
    watcher.check_resolution()
    assert _time.monotonic() - started < 0.4          # the proxy pass never waited for the other name
    assert gateway.calls == [(["172.20.0.4"], None)]
    watcher.check_oob()
    assert watcher.status()["oob"]["resolved"] is False
    release.set()


def test_the_interaction_server_loop_only_exists_when_one_is_configured():
    with_oob = _watcher(FakeGateway(), {PROXY: ["172.20.0.4"]}, oob_host="oob.invalid")
    threads = with_oob.start()
    with_oob.stop()
    assert {t.name for t in threads} == {"endpoint-resolution", "endpoint-reachability", "endpoint-oob"}
