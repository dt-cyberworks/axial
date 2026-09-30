"""REQ-FPEFF-001..005: the fingerprint phase must stop doing work it can prove
is redundant - without ever doing less than it should.

Every requirement here makes the scanner run FEWER tools, so the negative
tests (proving it still runs them when it must) are the load-bearing ones.
Modelled on the real int run 019feaae-768d-7489-858a-0503c127b676, where 7
hostnames resolved to 2 IPs and half the runtime produced nothing.
"""

from __future__ import annotations

import pytest

from app.tasks import fingerprint

EID = "11111111-1111-1111-1111-111111111111"
RUN = "22222222-2222-2222-2222-222222222222"
BROAD = {"tcp_port_from": 1, "tcp_port_to": 65535}


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Nothing in this module may reach a tool runner or the control plane."""
    monkeypatch.setattr(fingerprint.client, "add_service", lambda *a, **k: {"id": "svc-1"})
    monkeypatch.setattr(fingerprint.client, "add_finding", lambda *a, **k: {"id": "f-1"})
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: None)
    monkeypatch.setattr(fingerprint, "lookup_known_vuln", lambda *a: None)
    monkeypatch.setattr(fingerprint.scan_executor, "execute_plan", lambda **k: None)


def _asset(name: str, idx: int) -> dict:
    return {"asset_id": f"asset-{idx}", "value": name}


# --- REQ-FPEFF-002: one port scan per distinct network target ---------------

def _dedup_harness(monkeypatch, hosts, ip_map, envelopes=None, record=None):
    monkeypatch.setattr(
        fingerprint.client, "materialize_dns",
        lambda eid, scan_run_id=None: {"resolved": [{"hostname": h, "ip_address": ip} for h, ip in ip_map.items()]},
    )
    monkeypatch.setattr(
        fingerprint.client, "get_scan_envelope",
        lambda eid, host=None: (envelopes or {}).get(host, BROAD),
    )
    scanned: list[str] = []

    def fake_execute(engagement_id, asset_id, target, ip, scan_run_id):
        scanned.append(target)
        return ([{"port": 443, "product": "nginx", "protocol": "tcp"}], True)

    monkeypatch.setattr(fingerprint, "_execute_port_scan", fake_execute)
    monkeypatch.setattr(fingerprint, "_probe_web_surface", lambda *a, **k: (None, None))
    if record is not None:
        monkeypatch.setattr(fingerprint.tool_execution, "record",
                            lambda *a, **k: record.append(k))
    fingerprint.run(EID, [_asset(h, i) for i, h in enumerate(hosts)], scan_run_id=RUN)
    return scanned


def test_five_hostnames_on_one_ip_produce_exactly_one_port_scan(monkeypatch):
    hosts = ["a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"]
    scanned = _dedup_harness(monkeypatch, hosts, {h: "93.254.158.41" for h in hosts})
    assert scanned == ["a.example.com"]


def test_every_reusing_host_still_gets_the_services_attached(monkeypatch):
    """Reuse saves the scan, never the inventory.

    The first host persists inside _execute_port_scan (mocked out here, and
    covered against the real implementation by test_scan_integrity); what this
    asserts is that the hosts served FROM the cache - the ones at risk of
    silently losing their service inventory - still get every service
    attached to their own asset.
    """
    hosts = ["a.example.com", "b.example.com", "c.example.com"]
    attached: list[tuple[str, str, int]] = []
    monkeypatch.setattr(
        fingerprint, "_persist_services",
        lambda eid, aid, target, services: attached.append((target, aid, len(services))) or [],
    )
    _dedup_harness(monkeypatch, hosts, {h: "1.2.3.4" for h in hosts})

    assert attached == [("b.example.com", "asset-1", 1), ("c.example.com", "asset-2", 1)]


def test_reuse_is_recorded_and_names_the_host_that_scanned(monkeypatch):
    hosts = ["a.example.com", "b.example.com"]
    recorded: list[dict] = []
    _dedup_harness(monkeypatch, hosts, {h: "1.2.3.4" for h in hosts}, record=recorded)
    reuse = [r for r in recorded if "reused_from" in (r.get("result", {}).get("outcome_summary") or {})]
    assert len(reuse) == 1
    assert reuse[0]["authorized_target"] == "b.example.com"
    assert reuse[0]["result"]["outcome_summary"]["reused_from"] == "a.example.com"


def test_negative_same_ip_different_port_ranges_are_scanned_separately(monkeypatch):
    """REQ-PORTSCOPE-001 lets two names on one IP carry different authorized
    ranges - a narrower earlier scan must never satisfy a wider later one."""
    hosts = ["narrow.example.com", "wide.example.com"]
    scanned = _dedup_harness(
        monkeypatch, hosts, {h: "1.2.3.4" for h in hosts},
        envelopes={
            "narrow.example.com": {"tcp_port_from": 443, "tcp_port_to": 443},
            "wide.example.com": BROAD,
        },
    )
    assert scanned == hosts


def test_negative_different_ips_are_scanned_separately(monkeypatch):
    hosts = ["a.example.com", "b.example.com"]
    scanned = _dedup_harness(monkeypatch, hosts, {"a.example.com": "1.2.3.4", "b.example.com": "5.6.7.8"})
    assert scanned == hosts


def test_negative_the_cache_does_not_survive_across_runs(monkeypatch):
    """Ports change over time; a later run must re-scan."""
    hosts = ["a.example.com"]
    first = _dedup_harness(monkeypatch, hosts, {"a.example.com": "1.2.3.4"})
    second = _dedup_harness(monkeypatch, hosts, {"a.example.com": "1.2.3.4"})
    assert first == ["a.example.com"] and second == ["a.example.com"]


# --- REQ-FPEFF-001: per-host DNS freshness ---------------------------------

def test_dns_is_rematerialized_per_host_not_once_per_run(monkeypatch):
    hosts = ["a.example.com", "b.example.com", "c.example.com"]
    calls: list[int] = []

    def fake_materialize(eid, scan_run_id=None):
        calls.append(1)
        return {"resolved": [{"hostname": h, "ip_address": f"10.0.0.{i}"} for i, h in enumerate(hosts, start=1)]}

    monkeypatch.setattr(fingerprint.client, "materialize_dns", fake_materialize)
    monkeypatch.setattr(fingerprint.client, "get_scan_envelope", lambda eid, host=None: BROAD)
    monkeypatch.setattr(fingerprint, "_execute_port_scan", lambda *a, **k: ([], True))
    monkeypatch.setattr(fingerprint, "_probe_web_surface", lambda *a, **k: (None, None))

    fingerprint.run(EID, [_asset(h, i) for i, h in enumerate(hosts)], scan_run_id=RUN)

    # One upfront + one immediately before each host's own scan. The whole
    # defect was that a single upfront snapshot aged past the lease's window.
    assert len(calls) == 1 + len(hosts)


def test_no_rematerialization_when_the_scan_is_served_from_cache(monkeypatch):
    """A cache hit executes no scan, so it needs no fresh snapshot."""
    hosts = ["a.example.com", "b.example.com", "c.example.com"]
    calls: list[int] = []

    def fake_materialize(eid, scan_run_id=None):
        calls.append(1)
        return {"resolved": [{"hostname": h, "ip_address": "1.2.3.4"} for h in hosts]}

    monkeypatch.setattr(fingerprint.client, "materialize_dns", fake_materialize)
    monkeypatch.setattr(fingerprint.client, "get_scan_envelope", lambda eid, host=None: BROAD)
    monkeypatch.setattr(fingerprint, "_execute_port_scan", lambda *a, **k: ([], True))
    monkeypatch.setattr(fingerprint, "_probe_web_surface", lambda *a, **k: (None, None))

    fingerprint.run(EID, [_asset(h, i) for i, h in enumerate(hosts)], scan_run_id=RUN)

    # Upfront + exactly one refresh (for the single host that really scanned).
    assert len(calls) == 2


def test_negative_a_failed_rematerialization_does_not_scan_a_stale_ip(monkeypatch):
    state = {"n": 0}

    def flaky(eid, scan_run_id=None):
        state["n"] += 1
        if state["n"] == 1:
            return {"resolved": [{"hostname": "a.example.com", "ip_address": "1.2.3.4"}]}
        raise RuntimeError("control plane unreachable")

    monkeypatch.setattr(fingerprint.client, "materialize_dns", flaky)
    monkeypatch.setattr(fingerprint.client, "get_scan_envelope", lambda eid, host=None: BROAD)
    seen_ip: list = []
    monkeypatch.setattr(
        fingerprint, "_execute_port_scan",
        lambda eid, aid, target, ip, run: seen_ip.append(ip) or ([], False),
    )
    monkeypatch.setattr(fingerprint, "_probe_web_surface", lambda *a, **k: (None, None))
    recorded: list[dict] = []
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: recorded.append(k))

    fingerprint.run(EID, [_asset("a.example.com", 0)], scan_run_id=RUN)

    # The stale IP is NOT handed to the scanner...
    assert seen_ip == [None]
    # ...and the skip is visible rather than silent.
    assert any(r["result"].get("error_reason") == "dns_rematerialization_failed" for r in recorded)


# --- REQ-FPEFF-003: web ports follow scan evidence -------------------------

def test_443_is_not_probed_when_a_successful_scan_proved_it_closed():
    svcs = [{"port": 8080, "product": "nginx", "protocol": "tcp"}]
    assert fingerprint._web_candidate_ports(svcs, scan_succeeded=True) == [8080]


def test_443_is_probed_when_a_successful_scan_found_it_open():
    svcs = [
        {"port": 443, "product": "nginx", "protocol": "tcp"},
        {"port": 8080, "product": "nginx", "protocol": "tcp"},
    ]
    assert fingerprint._web_candidate_ports(svcs, scan_succeeded=True) == [443, 8080]


def test_negative_without_scan_evidence_443_is_still_probed():
    """Absence of evidence is not evidence of absence: a denied or unavailable
    scan must not silently stop the host being web-probed at all."""
    assert fingerprint._web_candidate_ports([], scan_succeeded=False) == [443]
    assert fingerprint._web_candidate_ports([], scan_succeeded=True) == []


def test_a_udp_service_on_443_is_not_read_as_an_https_listener():
    svcs = [{"port": 443, "product": "dns", "protocol": "udp"}]
    assert fingerprint._web_candidate_ports(svcs, scan_succeeded=True) == []


# --- REQ-FPEFF-004: deep tools deduplicate by SURFACE, not by host or IP ----
# The scan plan carries the decision: a surface identical to one already
# planned keeps its per-name checks (waf, tls) and skips the deep ones with the
# reason `duplicate_vhost_of:<host>`.

_LIVE = {"url": "https://a.example.com", "status_code": 404, "webserver": "nginx",
         "title": "404 Not Found", "content_length": 153}
_DEEP = ("header_findings", "ffuf", "nuclei:tech", "nuclei:headless", "nuclei:takeover")


def _plan_of(monkeypatch, probes, requests):
    """probes: hostname -> httpx result (or None for dead). requests: [(host, port)]
    probed in order against ONE run context. Returns {(host, port): {check_id: (state, reason)}}."""
    from app.planner import IndexInfo, Options

    monkeypatch.setattr(fingerprint, "_http_probe", lambda eid, aid, host, run, sp=None: probes.get(host))
    ctx = fingerprint._RunContext()
    surfaces = []
    for host, port in requests:
        live, surface = fingerprint._probe_web_surface(ctx, EID, f"asset-{host}", host, "1.2.3.4", RUN, port, [])
        if surface is not None:
            surfaces.append(surface)
    payload = fingerprint._plan_payload(surfaces, Options(), IndexInfo())
    return {(row["host"], row["port"]): {c["check_id"]: (c["state"], c["reason"]) for c in row["checks"]} for row in payload}


def test_identical_surfaces_on_one_ip_deep_scan_once(monkeypatch):
    plan = _plan_of(monkeypatch, {"a.example.com": _LIVE, "b.example.com": dict(_LIVE)},
                    [("a.example.com", None), ("b.example.com", None)])
    a, b = plan[("a.example.com", 443)], plan[("b.example.com", 443)]
    assert all(a[c][0] == "planned" for c in _DEEP)
    assert all(b[c] == ("skipped", "duplicate_vhost_of:a.example.com") for c in ("header_findings", "ffuf", "nuclei"))


def test_httpx_and_testssl_always_run_per_hostname(monkeypatch):
    plan = _plan_of(monkeypatch, {"a.example.com": _LIVE, "b.example.com": dict(_LIVE)},
                    [("a.example.com", None), ("b.example.com", None)])
    # A certificate presented for one name says nothing about another.
    for host in ("a.example.com", "b.example.com"):
        assert plan[(host, 443)]["testssl"][0] == "planned"
        assert plan[(host, 443)]["wafw00f"][0] == "planned"


@pytest.mark.parametrize("field,value", [
    ("status_code", 200),
    ("webserver", "Apache"),
    ("title", "Something else"),
    ("content_length", 999),
])
def test_negative_any_single_fingerprint_difference_means_both_are_scanned(monkeypatch, field, value):
    other = dict(_LIVE)
    other[field] = value
    plan = _plan_of(monkeypatch, {"a.example.com": _LIVE, "b.example.com": other},
                    [("a.example.com", None), ("b.example.com", None)])
    scanned = {h for (h, _), checks in plan.items() if checks["nuclei:tech"][0] == "planned"}
    assert scanned == {"a.example.com", "b.example.com"}, f"{field} difference was wrongly collapsed"


def test_negative_a_404_root_with_no_duplicate_is_still_fully_deep_scanned(monkeypatch):
    """The explicit non-goal: content discovery exists to find paths that
    respond where the root does not, so a 404 root is never itself a reason
    to skip ffuf."""
    plan = _plan_of(monkeypatch, {"only.example.com": _LIVE}, [("only.example.com", None)])
    checks = plan[("only.example.com", 443)]
    assert checks["ffuf"][0] == "planned" and checks["nuclei:tech"][0] == "planned"
    assert checks["header_findings"][0] == "planned"


def test_negative_an_unknown_fingerprint_is_never_deduplicated(monkeypatch):
    """No status code => un-deduplicable => both hosts scanned in full."""
    blank = {"url": "https://x", "status_code": None, "webserver": "", "title": "", "content_length": None}
    plan = _plan_of(monkeypatch, {"a.example.com": dict(blank), "b.example.com": dict(blank)},
                    [("a.example.com", None), ("b.example.com", None)])
    assert {h for (h, _), c in plan.items() if c["nuclei:tech"][0] == "planned"} == {"a.example.com", "b.example.com"}


def test_an_unresolved_host_has_no_surface_key_at_all():
    """Defensive counterpart: without a resolved IP there is no surface
    identity to compare, so nothing can ever be collapsed onto it.

    Tested directly rather than through the probe, because REQ-DISCO-004 skips
    an unresolved host before this is ever reached."""
    assert fingerprint._web_surface_key(None, 443, _LIVE) is None


def test_a_different_port_on_the_same_ip_is_a_different_surface(monkeypatch):
    plan = _plan_of(monkeypatch, {"a.example.com": _LIVE}, [("a.example.com", None), ("a.example.com", 8080)])
    assert plan[("a.example.com", 443)]["nuclei:tech"][0] == "planned"
    assert plan[("a.example.com", 8080)]["nuclei:tech"][0] == "planned"


# --- REQ-FPEFF-005: ordering ------------------------------------------------

def test_the_plan_runs_cheapest_and_most_informative_first(monkeypatch):
    from app.planner import IndexInfo, Options

    monkeypatch.setattr(fingerprint, "_http_probe", lambda eid, aid, host, run, sp=None: _LIVE)
    _, surface = fingerprint._probe_web_surface(
        fingerprint._RunContext(), EID, "asset-1", "a.example.com", "1.2.3.4", RUN, None, [])
    (row,) = fingerprint._plan_payload([surface], Options(), IndexInfo())
    order = [c["check_id"] for c in row["checks"] if c["state"] == "planned"]
    assert order[:4] == ["wafw00f", "testssl", "header_findings", "ffuf"]
    assert order.index("nuclei:tech") < order.index("nuclei:products") < order.index("nuclei:headless")
    assert order[-1] == "nuclei:takeover", "the most expensive checks run last"


def test_a_dead_port_becomes_no_surface(monkeypatch):
    monkeypatch.setattr(fingerprint, "_http_probe", lambda eid, aid, host, run, sp=None: None)
    assert fingerprint._probe_web_surface(
        fingerprint._RunContext(), EID, "asset-1", "a.example.com", "1.2.3.4", RUN, None, []) == (None, None)


def test_negative_a_failed_scan_is_never_cached_or_reported_as_a_reused_success(monkeypatch):
    """Caching a failure would be wrong twice: the reuse record would claim a
    success that never happened (nmap is load-bearing for REQ-SCAN-014's
    coverage-degraded signal), and the next host on that IP would lose a retry
    that may succeed - a stale-materialization denial clears as soon as the
    next host re-materializes.
    """
    hosts = ["a.example.com", "b.example.com"]
    attempts: list[str] = []
    monkeypatch.setattr(
        fingerprint.client, "materialize_dns",
        lambda eid, scan_run_id=None: {"resolved": [{"hostname": h, "ip_address": "1.2.3.4"} for h in hosts]},
    )
    monkeypatch.setattr(fingerprint.client, "get_scan_envelope", lambda eid, host=None: BROAD)
    monkeypatch.setattr(
        fingerprint, "_execute_port_scan",
        lambda eid, aid, target, ip, run: attempts.append(target) or ([], False),
    )
    monkeypatch.setattr(fingerprint, "_probe_web_surface", lambda *a, **k: (None, None))
    recorded: list[dict] = []
    monkeypatch.setattr(fingerprint.tool_execution, "record", lambda *a, **k: recorded.append(k))

    fingerprint.run(EID, [_asset(h, i) for i, h in enumerate(hosts)], scan_run_id=RUN)

    # Both hosts really attempted their own scan - no failure was reused.
    assert attempts == hosts
    # And nothing was recorded as a reuse (which would have claimed success).
    assert not [r for r in recorded if "reused_from" in (r.get("result", {}).get("outcome_summary") or {})]
