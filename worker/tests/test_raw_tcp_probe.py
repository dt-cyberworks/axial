"""REQ-AGENT-025: lease lifecycle for curated raw-protocol probes.

Mirrors test_raw_nmap.py's mocking style - the actual socket I/O
(tool_runner_client._raw_tcp_probe_command) is tested separately, for real,
against a live local socket (test_tool_runner_client.py). Here: the
lease-acquire/activate/deactivate/release orchestration around it.
"""

from __future__ import annotations

from app import raw_tcp_probe


def test_resolve_port_prefers_single_port_over_the_conventional_default():
    """REQ-FIDELITY-007: an engagement restricted to one non-standard port
    (every benchmark VM target this session) means THAT port is the real
    one to probe - the protocol's own conventional default (6379/61616)
    would be wrong there, since the VM's NAT remaps ports."""
    assert raw_tcp_probe.resolve_port("redis-probe", single_port=18085) == 18085
    assert raw_tcp_probe.resolve_port("activemq-banner", single_port=18085) == 18085


def test_resolve_port_falls_back_to_the_conventional_default():
    assert raw_tcp_probe.resolve_port("redis-probe", single_port=None) == 6379
    assert raw_tcp_probe.resolve_port("activemq-banner", single_port=None) == 61616


def test_execute_probe_denies_cleanly_when_lease_is_refused(monkeypatch):
    monkeypatch.setattr(raw_tcp_probe.raw_egress_gateway, "acquire_reservation",
                        lambda scan_run_id, cancel_requested=None: {"reservation_token": "rt-1"})
    released = []
    monkeypatch.setattr(raw_tcp_probe.raw_egress_gateway, "release_reservation",
                        lambda scan_run_id, token: released.append((scan_run_id, token)))
    activated = []
    monkeypatch.setattr(raw_tcp_probe.raw_egress_gateway, "activate",
                        lambda *a: activated.append(a))

    class _FakeClient:
        def acquire_raw_egress_lease(self, *a, **k):
            return {"allowed": False, "reason": "port_not_in_configured_range", "is_throttled": False}

        def is_cancel_requested(self, *a, **k):
            return False

    monkeypatch.setattr("app.control_plane_client.client", _FakeClient())

    outcome = raw_tcp_probe.execute_probe(
        "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222",
        "redis-probe", "redis.example", "192.0.2.10",
    )

    assert outcome.result["success"] is False
    assert outcome.result["error_reason"] == "port_not_in_configured_range"
    assert activated == []  # never activated a lease that was denied
    assert released == [("22222222-2222-2222-2222-222222222222", "rt-1")]  # reservation still released


def test_execute_probe_activates_dispatches_and_deactivates_on_success(monkeypatch):
    monkeypatch.setattr(raw_tcp_probe.raw_egress_gateway, "acquire_reservation",
                        lambda scan_run_id, cancel_requested=None: {"reservation_token": "rt-1"})
    calls = []
    monkeypatch.setattr(raw_tcp_probe.raw_egress_gateway, "activate",
                        lambda token, rt: calls.append(("activate", token, rt)))
    monkeypatch.setattr(raw_tcp_probe.raw_egress_gateway, "deactivate",
                        lambda token, rt: calls.append(("deactivate", token, rt)))
    monkeypatch.setattr(raw_tcp_probe.raw_egress_gateway, "release_reservation",
                        lambda run_id, rt: calls.append(("release", run_id, rt)))

    class _FakeClient:
        def acquire_raw_egress_lease(self, *a, **k):
            return {"allowed": True, "lease_token": "signed-lease", "port": 6379}

        def is_cancel_requested(self, *a, **k):
            return False

    monkeypatch.setattr("app.control_plane_client.client", _FakeClient())
    monkeypatch.setattr(raw_tcp_probe.tool_runner, "run",
                        lambda tool, ip, args, **k: {"success": True, "stdout": "asm_probe_status=ok\n", "stderr": ""})

    outcome = raw_tcp_probe.execute_probe(
        "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222",
        "redis-probe", "redis.example", "192.0.2.10", single_port=6379,
    )

    assert outcome.result["success"] is True
    assert outcome.port == 6379
    assert calls[0] == ("activate", "signed-lease", "rt-1")
    assert calls[1] == ("deactivate", "signed-lease", "rt-1")
    assert calls[2][0] == "release"


def test_execute_probe_still_releases_reservation_if_activation_raises(monkeypatch):
    """A raw_egress_gateway failure mid-flow must never leak the reservation
    slot - the FIFO queue would otherwise starve for every future scan."""
    monkeypatch.setattr(raw_tcp_probe.raw_egress_gateway, "acquire_reservation",
                        lambda scan_run_id, cancel_requested=None: {"reservation_token": "rt-1"})
    released = []
    monkeypatch.setattr(raw_tcp_probe.raw_egress_gateway, "release_reservation",
                        lambda run_id, rt: released.append((run_id, rt)))

    def boom(token, rt):
        raise RuntimeError("gateway unreachable")

    monkeypatch.setattr(raw_tcp_probe.raw_egress_gateway, "activate", boom)

    class _FakeClient:
        def acquire_raw_egress_lease(self, *a, **k):
            return {"allowed": True, "lease_token": "signed-lease"}

        def is_cancel_requested(self, *a, **k):
            return False

    monkeypatch.setattr("app.control_plane_client.client", _FakeClient())

    outcome = raw_tcp_probe.execute_probe(
        "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222",
        "activemq-banner", "mq.example", "192.0.2.10",
    )

    assert outcome.result["success"] is False
    assert released == [("22222222-2222-2222-2222-222222222222", "rt-1")]
