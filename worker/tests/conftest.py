import pytest

from app import control_plane_client


@pytest.fixture(autouse=True)
def _claimable_scan_run(monkeypatch):
    """run_scan claims its scan_run first (GitHub issue #42); tests that drive
    the pipeline get a fresh first claim instead of a control-plane call."""
    monkeypatch.setattr(
        control_plane_client.client, "claim_scan_run",
        lambda *a, **k: {"attempt": 1, "phase": "discovery", "state": "running",
                         "cancel_requested": False, "checkpoint": None},
        raising=False,
    )


@pytest.fixture(autouse=True)
def _plan_io_stubs(monkeypatch):
    """The scan plan is stored and read through the control plane and the
    template index through the tool runner. No unit test may reach either: safe
    defaults here, overridden by the tests that exercise them."""
    from app import tool_runner_client as trc
    from app.tasks import fingerprint

    c = control_plane_client.client
    monkeypatch.setattr(c, "get_scan_settings", lambda eid: {"scan_profile": "standard", "max_parallel_checks": 2}, raising=False)
    monkeypatch.setattr(c, "store_scan_plan", lambda run_id, surfaces: {"surfaces_created": len(surfaces), "checks_created": 0}, raising=False)
    monkeypatch.setattr(c, "get_scan_plan", lambda run_id: {"surfaces": []}, raising=False)
    monkeypatch.setattr(c, "update_scan_run", lambda *a, **k: {}, raising=False)
    monkeypatch.setattr(c, "update_scan_check", lambda *a, **k: {}, raising=False)
    monkeypatch.setattr(c, "update_scan_surface", lambda *a, **k: {}, raising=False)
    summary = {"templates_version": "test", "total": 5883, "generic": 1980, "bound": 3903, "products": {}}
    for runner in {id(trc.tool_runner): trc.tool_runner, id(fingerprint.tool_runner): fingerprint.tool_runner}.values():
        monkeypatch.setattr(runner, "nuclei_index_summary", lambda: summary, raising=False)
        monkeypatch.setattr(runner, "nuclei_selection_count", lambda selection: 100, raising=False)
