"""GitHub issue #29: a task exceeding Celery's time limit must mark the run
failed with a reason distinguishable from a generic pipeline error (soft
limit path - the task gets a chance to run this code at all). The hard
limit's SIGKILL path has no equivalent unit test: by definition, the task
never runs any of its own Python code when that fires - that path is
covered instead by the periodic reaper picking up the resulting stale
heartbeat (control-plane/tests/integration/test_scan_run_reaper.py)."""

from celery.exceptions import SoftTimeLimitExceeded

from app.tasks import pipeline, reap


def test_soft_time_limit_exceeded_marks_run_failed_with_a_distinguishable_reason(monkeypatch):
    engagement_id = "11111111-1111-1111-1111-111111111111"
    run_id = "22222222-2222-2222-2222-222222222222"
    updates = []
    monkeypatch.setattr(pipeline.client, "is_cancel_requested", lambda *a, **k: False)
    monkeypatch.setattr(pipeline.client, "update_scan_run", lambda *a, **k: updates.append((a, k)) or {})

    def _raise(*a, **k):
        raise SoftTimeLimitExceeded()

    monkeypatch.setattr(pipeline.discovery, "run", _raise)

    try:
        pipeline.run_scan.run(engagement_id, run_id)
        assert False, "expected SoftTimeLimitExceeded to propagate out of the task"
    except SoftTimeLimitExceeded:
        pass

    assert updates, "update_scan_run was never called"
    _, last_kwargs = updates[-1]
    assert last_kwargs.get("state") == "failed"
    assert last_kwargs.get("state_reason") == "task_time_limit_exceeded"


def test_a_regular_pipeline_exception_still_gets_the_generic_reason(monkeypatch):
    """Regression: the new except SoftTimeLimitExceeded branch must not
    swallow or reclassify an ordinary bug elsewhere in the pipeline."""
    engagement_id = "11111111-1111-1111-1111-111111111111"
    run_id = "22222222-2222-2222-2222-222222222222"
    updates = []
    monkeypatch.setattr(pipeline.client, "is_cancel_requested", lambda *a, **k: False)
    monkeypatch.setattr(pipeline.client, "update_scan_run", lambda *a, **k: updates.append((a, k)) or {})

    def _raise(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(pipeline.discovery, "run", _raise)

    try:
        pipeline.run_scan.run(engagement_id, run_id)
        assert False, "expected RuntimeError to propagate"
    except RuntimeError:
        pass

    _, last_kwargs = updates[-1]
    assert last_kwargs.get("state") == "failed"
    # REQ-PIPE-021: the cause and the phase travel with the reason
    assert last_kwargs.get("state_reason") == "pipeline_error:RuntimeError:discovery"


def test_reap_stale_runs_task_calls_the_all_engagements_client_method(monkeypatch):
    calls = []
    monkeypatch.setattr(reap.client, "reap_all_stale_runs", lambda: calls.append(1) or 3)

    result = reap.reap_stale_runs.run()

    assert calls == [1]
    assert result == {"reaped": 3}
