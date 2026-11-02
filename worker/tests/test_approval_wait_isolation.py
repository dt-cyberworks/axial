"""REQ-APPROVAL-008 (GitHub #83): a wait for one decision does not stop the run's other actions - the worker's side.

The control plane now accepts calls of a run that waits live (`waiting_approval` with the reason `approval_wait`). What the
worker owes it: set that reason with the wait, and put the run back to `running` only when the LAST open wait of the run
ends. The pipeline runs checks in several threads and a wait ends in whichever thread gets its answer."""

from __future__ import annotations

import threading
import time

import pytest

from app import approval_wait
from app.control_plane_client import client
from app.tasks import agent

ENG = "11111111-1111-1111-1111-111111111111"
RUN = "22222222-2222-2222-2222-222222222222"
OTHER_RUN = "33333333-3333-3333-3333-333333333333"
WAITING = ("waiting_approval", "approval_wait")
RUNNING = ("running", None)


class Patches:
    """What the worker wrote to the run, in order."""

    def __init__(self, monkeypatch, *, fail_on=()):
        self.calls: list[tuple[str, str, str | None]] = []
        self._fail_on = set(fail_on)
        self._lock = threading.Lock()
        monkeypatch.setattr(client, "update_scan_run", self._update)

    def _update(self, run_id, **fields):
        with self._lock:
            self.calls.append((str(run_id), fields.get("state"), fields.get("state_reason")))
        if fields.get("state") in self._fail_on:
            raise RuntimeError("control plane unreachable")
        return {}

    def states(self, run=RUN):
        return [(s, r) for rid, s, r in self.calls if rid == run]


@pytest.fixture(autouse=True)
def _no_leftover_waits():
    approval_wait._open_waits.clear()
    yield
    approval_wait._open_waits.clear()


def test_one_wait_puts_the_run_into_the_live_wait_and_back(monkeypatch):
    p = Patches(monkeypatch)
    with approval_wait.live_wait(RUN):
        assert p.states() == [WAITING]
    assert p.states() == [WAITING, RUNNING]


def test_the_run_goes_back_to_running_only_when_the_last_wait_ends(monkeypatch):
    p = Patches(monkeypatch)
    with approval_wait.live_wait(RUN):
        with approval_wait.live_wait(RUN):
            assert p.states() == [WAITING], "the second wait does not write the state again"
        assert p.states() == [WAITING], "the first wait to end must not bring the run back while another one is open"
    assert p.states() == [WAITING, RUNNING]


def test_two_threads_waiting_on_one_run(monkeypatch):
    p = Patches(monkeypatch)
    inside, release_a, release_b, done = threading.Barrier(3), threading.Event(), threading.Event(), []

    def wait(release):
        with approval_wait.live_wait(RUN):
            inside.wait(5)
            release.wait(5)
        done.append(1)

    a, b = (threading.Thread(target=wait, args=(e,), daemon=True) for e in (release_a, release_b))
    a.start(), b.start()
    inside.wait(5)
    release_a.set()
    a.join(5)
    assert done == [1] and p.states() == [WAITING], "the run must still be waiting while B waits"
    release_b.set()
    b.join(5)
    assert p.states() == [WAITING, RUNNING]


def test_waits_of_different_runs_do_not_share_a_count(monkeypatch):
    p = Patches(monkeypatch)
    with approval_wait.live_wait(RUN):
        with approval_wait.live_wait(OTHER_RUN):
            pass
        assert p.states(OTHER_RUN) == [WAITING, RUNNING]
        assert p.states(RUN) == [WAITING]
    assert p.states(RUN) == [WAITING, RUNNING]


def test_a_wait_that_raises_still_releases_the_run_and_the_count(monkeypatch):
    p = Patches(monkeypatch)
    with pytest.raises(RuntimeError, match="boom"):
        with approval_wait.live_wait(RUN):
            raise RuntimeError("boom")
    assert p.states() == [WAITING, RUNNING] and RUN not in approval_wait._open_waits


def test_no_run_means_nothing_is_written(monkeypatch):
    p = Patches(monkeypatch)
    with approval_wait.live_wait(None):
        pass
    assert p.calls == [] and approval_wait._open_waits == {}


def test_a_state_that_cannot_be_written_never_stops_the_wait_or_the_count(monkeypatch):
    p = Patches(monkeypatch, fail_on=("waiting_approval",))
    ran = []
    with approval_wait.live_wait(RUN):
        ran.append(1)
    assert ran == [1] and p.states() == [WAITING, RUNNING] and RUN not in approval_wait._open_waits


def test_negative_a_run_that_cannot_go_back_does_not_leave_a_count_that_would_hide_the_next_wait(monkeypatch):
    """The control plane refuses a state change of a finished run (409). The count must still reach zero, or the next wait
    of a resumed or later run would never write `waiting_approval` again."""
    p = Patches(monkeypatch, fail_on=("running",))
    with approval_wait.live_wait(RUN):
        pass
    assert RUN not in approval_wait._open_waits
    with approval_wait.live_wait(RUN):
        pass
    assert p.states() == [WAITING, RUNNING, WAITING, RUNNING]


# -------------------------------------------------- through the two real waits


def _wire(monkeypatch, decisions: dict[str, threading.Event]):
    """A control plane stand-in whose approvals are decided when the test sets their event."""
    monkeypatch.setattr(client, "run_info", lambda rid: {"supervision": "attended", "operating_mode": "assessment",
                                                         "approval_timeout_seconds": 30})
    monkeypatch.setattr(client, "get_approval", lambda aid: {"state": "approved" if decisions[aid].is_set() else "requested"})
    monkeypatch.setattr(client, "claim_approval", lambda aid: {"allowed": True})
    monkeypatch.setattr(client, "complete_approval", lambda aid, **k: {})
    monkeypatch.setattr(approval_wait.CancelProbe, "for_run",
                        classmethod(lambda cls, rid: type("P", (), {"is_cancelled": lambda self: False})()))
    monkeypatch.setattr(approval_wait, "POLL_SECONDS", 0.005)


def _pending(aid):
    return {"allowed": False, "is_pending": True, "reason": "pending_approval", "approval_request_id": aid}


def _until(predicate, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return False


def test_two_pipeline_checks_waiting_at_once_keep_the_run_waiting_until_both_are_decided(monkeypatch):
    p = Patches(monkeypatch)
    decisions = {"ap-1": threading.Event(), "ap-2": threading.Event()}
    _wire(monkeypatch, decisions)
    results = {}

    def check(aid):
        results[aid] = approval_wait.resolve_pending(ENG, _pending(aid), tool="nuclei", target="a.example.com", scan_run_id=RUN)

    threads = [threading.Thread(target=check, args=(aid,), daemon=True) for aid in decisions]
    [t.start() for t in threads]
    assert _until(lambda: approval_wait._open_waits.get(RUN) == 2)
    decisions["ap-1"].set()
    threads[0].join(5)
    assert results["ap-1"][1] == "approved" and p.states() == [WAITING], "check 2 still waits: the run must too"
    decisions["ap-2"].set()
    threads[1].join(5)
    assert results["ap-2"][1] == "approved" and p.states() == [WAITING, RUNNING]


def test_the_agents_wait_and_a_pipeline_wait_share_the_count(monkeypatch):
    p = Patches(monkeypatch)
    decisions = {"ap-a": threading.Event(), "ap-p": threading.Event()}
    _wire(monkeypatch, decisions)
    monkeypatch.setattr(agent.client, "is_cancel_requested", lambda rid: False)
    monkeypatch.setattr(agent, "_finish_approval", lambda *a, **k: "FINISHED")
    monkeypatch.setattr(agent, "_APPROVAL_POLL_SECONDS", 0.005)
    ctx = agent.SimpleContext(scan_run_id=RUN)
    out = {}
    t_agent = threading.Thread(daemon=True, target=lambda: out.update(agent=agent._await_approval(
        ENG, "ap-a", "asset-1", "example.org", {"method": "POST", "path": "/login"}, None, {"tool": "http_request"}, ctx)))
    t_pipe = threading.Thread(daemon=True, target=lambda: out.update(pipe=approval_wait.resolve_pending(
        ENG, _pending("ap-p"), tool="nuclei", target="a.example.com", scan_run_id=RUN)))
    t_agent.start(), t_pipe.start()
    assert _until(lambda: approval_wait._open_waits.get(RUN) == 2)
    decisions["ap-p"].set()
    t_pipe.join(5)
    assert p.states() == [WAITING], "the agent's wait is still open"
    decisions["ap-a"].set()
    t_agent.join(5)
    assert out["agent"] == "FINISHED" and p.states() == [WAITING, RUNNING]


def test_a_cancelled_run_ends_its_wait_and_is_not_brought_back_to_life(monkeypatch):
    """The control plane answers 409 to a state change of a finished run; the worker swallows it and goes on."""
    p = Patches(monkeypatch, fail_on=("running",))
    decisions = {"ap-1": threading.Event()}
    _wire(monkeypatch, decisions)
    monkeypatch.setattr(approval_wait.CancelProbe, "for_run",
                        classmethod(lambda cls, rid: type("P", (), {"is_cancelled": lambda self: True})()))
    resolved, reason = approval_wait.resolve_pending(ENG, _pending("ap-1"), tool="nuclei", target="a.example.com", scan_run_id=RUN)
    assert resolved is None and reason == "approval_cancelled"
    assert RUN not in approval_wait._open_waits


def test_an_unattended_run_still_never_waits(monkeypatch):
    p = Patches(monkeypatch)
    _wire(monkeypatch, {"ap-1": threading.Event()})
    monkeypatch.setattr(client, "run_info", lambda rid: {"supervision": "unattended", "operating_mode": "monitoring"})
    monkeypatch.setattr(client, "withdraw_approval", lambda aid, reason="": None)
    resolved, reason = approval_wait.resolve_pending(ENG, _pending("ap-1"), tool="nuclei", target="a.example.com", scan_run_id=RUN)
    assert resolved is None and reason == "approval_unavailable_unattended" and p.calls == []
