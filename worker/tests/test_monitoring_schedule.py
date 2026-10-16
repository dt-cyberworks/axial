"""The scheduler's worker side (REQ-MON-003).

The worker decides nothing here: a beat task asks the control plane to run one tick, and
whatever goes wrong with that call must never raise into the worker loop (the next tick is a
minute away and the control plane's own rules stay in force)."""

from __future__ import annotations

import httpx

from app.celery_app import celery_app
from app.control_plane_client import ControlPlaneClient, client
from app.tasks import monitoring_tasks


def test_a_tick_is_scheduled_every_minute_by_default():
    entry = celery_app.conf.beat_schedule["run-due-schedules"]
    assert entry["task"] == "asm.run_due_schedules"
    assert entry["schedule"] == 60.0


def test_the_task_is_registered():
    assert "asm.run_due_schedules" in celery_app.tasks


def test_the_task_returns_what_the_control_plane_decided(monkeypatch):
    monkeypatch.setattr(client, "run_due_schedules", lambda: {"due": 2, "started": 1, "waiting": 1})
    assert monitoring_tasks.run_due_schedules() == {"due": 2, "started": 1, "waiting": 1}


def test_a_failing_tick_never_raises_into_the_worker_loop(monkeypatch):
    def boom():
        raise httpx.ConnectError("control plane unreachable")

    monkeypatch.setattr(client, "run_due_schedules", boom)
    assert monitoring_tasks.run_due_schedules() == {"error": True}


def test_the_client_posts_to_the_internal_endpoint_and_nothing_else(monkeypatch):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"due": 0, "started": 0, "waiting": 0})

    probe = ControlPlaneClient()
    probe._client = httpx.Client(base_url="http://control-plane:8000", transport=httpx.MockTransport(handler))
    assert probe.run_due_schedules() == {"due": 0, "started": 0, "waiting": 0}
    assert len(seen) == 1
    assert seen[0].method == "POST" and seen[0].url.path == "/internal/monitoring/run-due-schedules"
    assert seen[0].content == b""  # the worker sends no engagement, no host, no interval: it only pokes
