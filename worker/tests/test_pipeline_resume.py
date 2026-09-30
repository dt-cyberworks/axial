"""TC-RESUME-003 (GitHub issue #42): a resumed run_scan task continues at the
phase after the last completed one, from the stored checkpoint."""

import pytest

from app import tool_execution
from app.control_plane_client import ScanRunNotClaimable, ScanRunSuperseded
from app.tasks import pipeline

ENG = "11111111-1111-1111-1111-111111111111"
RUN = "22222222-2222-2222-2222-222222222222"
DISCOVERED = [{"value": "a.example.com", "asset_id": "1", "asset_type": "domain"}]
SERVICES = [{"target": "a.example.com", "port": 443}]


class Harness:
    def __init__(self, monkeypatch, *, phase, checkpoint, attempt=2, cancel=False):
        self.ran, self.updates = [], []
        c = pipeline.client
        monkeypatch.setattr(c, "claim_scan_run", lambda *a, **k: {
            "attempt": attempt, "phase": phase, "state": "running", "cancel_requested": cancel, "checkpoint": checkpoint})
        monkeypatch.setattr(c, "is_cancel_requested", lambda *a, **k: cancel)
        monkeypatch.setattr(c, "update_scan_run", lambda *a, **k: self.updates.append(k) or {})
        monkeypatch.setattr(c, "materialize_graph", lambda *a, **k: None)
        monkeypatch.setattr(pipeline.discovery, "run", lambda *a, **k: self.ran.append("discovery") or DISCOVERED)
        monkeypatch.setattr(pipeline.asset_review, "gate", lambda e, r, d: self.ran.append("gate") or d)
        monkeypatch.setattr(pipeline.fingerprint, "run", lambda e, d, **k: self.ran.append(("fingerprint", d)) or SERVICES)
        monkeypatch.setattr(pipeline.correlate, "run", lambda e, services: self.ran.append(("correlate", services)) or [])
        monkeypatch.setattr(pipeline.agent, "run", lambda e, budget, **k: self.ran.append(("agent", budget, k["approval_timeout_seconds"]))
                            or type("Ctx", (), {"incomplete_reason": None})())
        monkeypatch.setattr(pipeline.score, "run", lambda *a, **k: self.ran.append("score"))
        monkeypatch.setattr(pipeline.report, "run", lambda *a, **k: self.ran.append("report"))

    def go(self):
        return pipeline.run_scan.run(ENG, RUN)


@pytest.fixture(autouse=True)
def _clean():
    tool_execution.clear_coverage(RUN)
    yield
    tool_execution.clear_coverage(RUN)


def test_a_fresh_run_goes_through_every_phase_and_checkpoints_each_boundary(monkeypatch):
    h = Harness(monkeypatch, phase="discovery", checkpoint=None, attempt=1)
    h.go()
    assert [r if isinstance(r, str) else r[0] for r in h.ran] == [
        "discovery", "gate", "fingerprint", "correlate", "agent", "score", "report"]
    by_phase = {u["phase"]: u for u in h.updates if "phase" in u}
    assert by_phase["fingerprint"]["checkpoint"]["discovered"] == DISCOVERED
    assert by_phase["correlate"]["checkpoint"]["services"] == SERVICES
    assert h.updates[-1]["state"] == "done"


def test_resume_at_correlate_skips_finished_phases_and_feeds_correlate_from_the_checkpoint(monkeypatch):
    h = Harness(monkeypatch, phase="correlate", checkpoint={
        "discovered": DISCOVERED, "review_done": True, "services": SERVICES,
        "params": {"budget_max_iterations": 9, "approval_timeout_seconds": 77}})
    h.go()
    assert h.ran[0] == ("correlate", SERVICES)
    assert "discovery" not in h.ran and "gate" not in h.ran and not any(r[0] == "fingerprint" for r in h.ran if isinstance(r, tuple))
    assert ("agent", 9, 77) in h.ran  # the original task parameters, not the defaults
    assert h.updates[-1]["state"] == "done"


def test_resume_at_fingerprint_does_not_repeat_a_decided_asset_review(monkeypatch):
    h = Harness(monkeypatch, phase="fingerprint", checkpoint={"discovered": DISCOVERED, "review_done": True})
    h.go()
    assert "gate" not in h.ran and h.ran[0] == ("fingerprint", DISCOVERED)


def test_resume_at_fingerprint_before_the_review_was_decided_runs_the_gate_again(monkeypatch):
    h = Harness(monkeypatch, phase="fingerprint", checkpoint={"discovered": DISCOVERED, "review_done": False})
    h.go()
    assert h.ran[:2] == ["gate", ("fingerprint", DISCOVERED)]


def test_resume_at_the_end_only_runs_the_remaining_phases(monkeypatch):
    h = Harness(monkeypatch, phase="score", checkpoint={"discovered": DISCOVERED, "services": SERVICES})
    h.go()
    assert h.ran == ["score", "report"]


def test_a_checkpoint_without_the_phase_input_restarts_at_the_producing_phase(monkeypatch):
    h = Harness(monkeypatch, phase="correlate", checkpoint={"discovered": DISCOVERED, "review_done": True})
    h.go()  # no services stored: fingerprint runs again instead of correlating nothing
    assert h.ran[0] == ("fingerprint", DISCOVERED)
    h = Harness(monkeypatch, phase="correlate", checkpoint={})
    h.go()
    assert h.ran[0] == "discovery"


def test_warnings_recorded_before_the_crash_survive_into_the_final_state(monkeypatch):
    h = Harness(monkeypatch, phase="score", checkpoint={
        "discovered": DISCOVERED, "services": SERVICES,
        "agent_warning": "agent_incomplete:max_iterations", "coverage_warning": "coverage_degraded:nmap=x"})
    h.go()
    assert h.updates[-1]["state"] == "done"
    assert h.updates[-1]["state_reason"] == "coverage_degraded:nmap=x; agent_incomplete:max_iterations"


def test_negative_a_cancelled_run_is_not_resumed_into_work(monkeypatch):
    h = Harness(monkeypatch, phase="correlate", checkpoint={"discovered": DISCOVERED, "services": SERVICES}, cancel=True)
    result = h.go()
    assert result["state"] == "aborted" and h.ran == []
    assert h.updates[-1] == {"state": "aborted", "state_reason": "cancelled_by_operator"}


def test_negative_a_refused_claim_runs_nothing_and_writes_nothing(monkeypatch):
    h = Harness(monkeypatch, phase="discovery", checkpoint=None)

    def _refused(*a, **k):
        raise ScanRunNotClaimable("owned_by_live_attempt")

    monkeypatch.setattr(pipeline.client, "claim_scan_run", _refused)
    assert h.go()["state"] == "not_claimed"
    assert h.ran == [] and h.updates == []


def test_negative_a_superseded_task_stops_quietly_without_marking_the_run_failed(monkeypatch):
    h = Harness(monkeypatch, phase="discovery", checkpoint=None)

    def _superseded(*a, **k):
        raise ScanRunSuperseded("superseded")

    monkeypatch.setattr(pipeline.client, "update_scan_run", _superseded)
    monkeypatch.setattr(pipeline.discovery, "run", lambda *a, **k: DISCOVERED)
    assert h.go()["state"] == "superseded"


def test_negative_a_superseded_task_that_fails_does_not_overwrite_the_new_owners_run(monkeypatch):
    h = Harness(monkeypatch, phase="discovery", checkpoint=None)
    calls = []

    def _update(*a, **k):
        calls.append(k)
        raise ScanRunSuperseded("superseded")

    monkeypatch.setattr(pipeline.client, "update_scan_run", _update)

    def _boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(pipeline.discovery, "run", _boom)
    with pytest.raises(RuntimeError):
        h.go()
    assert calls == [{"state": "failed", "state_reason": "pipeline_error"}]  # attempted, refused, swallowed


def test_req_pipe_014_a_run_stored_at_the_removed_validate_phase_continues_at_score(monkeypatch):
    h = Harness(monkeypatch, phase="validate", checkpoint={"discovered": DISCOVERED, "services": SERVICES})
    h.go()
    assert h.ran == ["score", "report"]
    assert "validate" not in pipeline.PHASES
    assert not any("validate" == u.get("phase") for u in h.updates)


def test_req_pipe_014_a_fresh_run_never_reports_a_validate_phase(monkeypatch):
    h = Harness(monkeypatch, phase="discovery", checkpoint=None, attempt=1)
    h.go()
    assert [u["phase"] for u in h.updates if "phase" in u] == ["fingerprint", "correlate", "agent", "score", "report"]


def test_start_index_never_continues_with_missing_input():
    assert pipeline._start_index("agent", {"discovered": [], "services": []}) == 3
    assert pipeline._start_index("agent", {"discovered": []}) == 1
    assert pipeline._start_index("report", {}) == 0
    assert pipeline._start_index("unknown-phase", {}) == 0


# --- the client half of the protocol -----------------------------------------------

def test_client_sends_its_attempt_and_maps_409_superseded(monkeypatch):
    import httpx
    from app.control_plane_client import ControlPlaneClient

    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, request.url.query.decode(), request.content.decode()))
        if request.url.path.endswith("/claim"):
            return httpx.Response(200, json={"attempt": 3, "phase": "agent", "state": "running", "cancel_requested": False})
        if "superseded-run" in request.url.path:
            return httpx.Response(409, text='{"detail":"superseded: newer attempt"}')
        return httpx.Response(200, json={"cancel_requested": False})

    c = ControlPlaneClient(base_url="http://cp")
    c._client = httpx.Client(base_url="http://cp", transport=httpx.MockTransport(handler))
    assert c.claim_scan_run("r1", task_id="t")["attempt"] == 3
    c.update_scan_run("r1", phase="score")
    c.is_cancel_requested("r1")
    assert '"attempt": 3' in seen[1][3] or '"attempt":3' in seen[1][3]
    assert "attempt=3" in seen[2][2]

    c._attempts["superseded-run"] = 1
    with pytest.raises(ScanRunSuperseded):
        c.update_scan_run("superseded-run", phase="score")
    with pytest.raises(ScanRunSuperseded):
        c.is_cancel_requested("superseded-run")
    c.release_scan_run("r1")
    assert "r1" not in c._attempts


def test_negative_client_reports_a_refused_claim(monkeypatch):
    import httpx
    from app.control_plane_client import ControlPlaneClient

    c = ControlPlaneClient(base_url="http://cp")
    c._client = httpx.Client(base_url="http://cp", transport=httpx.MockTransport(
        lambda r: httpx.Response(409, text='{"detail":"not claimable: terminal:done"}')))
    with pytest.raises(ScanRunNotClaimable):
        c.claim_scan_run("r1", task_id="t")
    assert "r1" not in c._attempts
