"""Operating modes on the worker (REQ-MODE-005/007/008/011/017, REQ-MON-002).

The gateway-resident rules (a monitoring engagement denying a call that needs a
person, the passive depth and held hosts denied at the gateway, the standing
consent) are not part of this change; what is verified here is what the worker
itself does so that none of them is needed to keep an unattended run from waiting
for nobody or testing what it must not."""

from __future__ import annotations

import pytest

from app import approval_wait, planner, tool_execution
from app.control_plane_client import client
from app.tasks import agent, asset_hold, fingerprint, monitoring_tasks, pipeline
from app.webhook_guard import WebhookTargetRefused, sign, validate_webhook_url

ENG = "11111111-1111-1111-1111-111111111111"
RUN = "22222222-2222-2222-2222-222222222222"


def _info(monkeypatch, **fields):
    base = {"supervision": "attended", "scan_profile": "standard", "trigger": "manual", "scope_hosts": None,
            "retest_finding_id": None, "operating_mode": "assessment", "approval_timeout_seconds": 30}
    base.update(fields)
    monkeypatch.setattr(client, "run_info", lambda rid: dict(base))


class Recorder:
    def __init__(self, monkeypatch, *, states=("approved",), claim=None):
        self.withdrawn, self.suggestions, self.claimed, self.completed, self.run_states = [], [], [], [], []
        self._states = list(states)
        monkeypatch.setattr(client, "withdraw_approval", lambda aid, reason="": self.withdrawn.append((aid, reason)))
        monkeypatch.setattr(client, "add_suggestion", lambda eid, **k: self.suggestions.append(k))
        monkeypatch.setattr(client, "get_approval", lambda aid: {"state": self._states.pop(0) if len(self._states) > 1 else self._states[0]})
        monkeypatch.setattr(client, "claim_approval", lambda aid: self.claimed.append(aid) or (claim or {"allowed": True}))
        monkeypatch.setattr(client, "complete_approval", lambda aid, **k: self.completed.append((aid, k)) or {})
        monkeypatch.setattr(client, "update_scan_run", lambda rid, **k: self.run_states.append(k.get("state")) or {})
        monkeypatch.setattr(approval_wait.CancelProbe, "for_run",
                            classmethod(lambda cls, rid: type("P", (), {"is_cancelled": lambda self: False})()))
        monkeypatch.setattr(approval_wait.time, "sleep", lambda s: None)


PENDING = {"allowed": False, "is_pending": True, "reason": "pending_approval", "approval_request_id": "ap-1"}


# ------------------------------------------------ REQ-MODE-005 / REQ-MODE-007


def test_an_attended_run_waits_for_the_decision_and_runs_only_the_claimed_call(monkeypatch):
    _info(monkeypatch)
    rec = Recorder(monkeypatch, states=("requested", "requested", "approved"))
    resolved, reason = approval_wait.resolve_pending(ENG, PENDING, tool="nuclei", target="a.example.com", scan_run_id=RUN)
    assert reason == "approved" and resolved["allowed"] is True
    assert rec.claimed == ["ap-1"] and rec.completed and rec.completed[0][1] == {"success": True}
    assert rec.run_states == ["waiting_approval", "running"]
    assert rec.withdrawn == [] and rec.suggestions == []


@pytest.mark.parametrize("state", ["rejected", "expired", "cancelled"])
def test_a_call_that_was_not_approved_is_never_executed(monkeypatch, state):
    _info(monkeypatch)
    rec = Recorder(monkeypatch, states=(state,))
    resolved, reason = approval_wait.resolve_pending(ENG, PENDING, tool="nuclei", target="a.example.com", scan_run_id=RUN)
    assert resolved is None and reason == f"approval_{state}"
    assert rec.claimed == [] and rec.completed == []
    assert rec.run_states[-1] == "running"


def test_an_approved_call_the_gateway_no_longer_allows_is_not_executed(monkeypatch):
    _info(monkeypatch)
    rec = Recorder(monkeypatch, claim={"allowed": False, "reason": "outside_time_window"})
    resolved, reason = approval_wait.resolve_pending(ENG, PENDING, tool="nuclei", target="a.example.com", scan_run_id=RUN)
    assert resolved is None and reason == "approval_claim_denied:outside_time_window"
    assert rec.completed == []


def test_nobody_answering_expires_after_the_timeout(monkeypatch):
    _info(monkeypatch, approval_timeout_seconds=9)
    Recorder(monkeypatch, states=("requested",))
    resolved, reason = approval_wait.resolve_pending(ENG, PENDING, tool="nuclei", target="a.example.com", scan_run_id=RUN)
    assert resolved is None and reason == "approval_expired"


@pytest.mark.parametrize("fields", [{"supervision": "unattended"}, {"operating_mode": "monitoring", "supervision": None}])
def test_an_unattended_run_never_waits_it_withdraws_and_keeps_a_suggestion(monkeypatch, fields):
    _info(monkeypatch, **fields)
    rec = Recorder(monkeypatch, states=("requested",))
    monkeypatch.setattr(approval_wait, "wait_for_decision", lambda *a, **k: pytest.fail("an unattended run must not wait"))
    resolved, reason = approval_wait.resolve_pending(ENG, PENDING, tool="nuclei", target="a.example.com", scan_run_id=RUN)
    assert resolved is None and reason == "approval_unavailable_unattended"
    assert rec.withdrawn == [("ap-1", "unattended_run")]
    assert rec.suggestions and rec.suggestions[0]["tool"] == "nuclei" and rec.suggestions[0]["target"] == "a.example.com"
    assert rec.run_states == [], "the run is never put into waiting_approval"


def test_the_pipeline_check_waits_instead_of_skipping_and_leaving_a_popup(monkeypatch):
    _info(monkeypatch)
    rec = Recorder(monkeypatch, states=("approved",))
    monkeypatch.setattr(client, "authorize", lambda eid, payload: PENDING)
    seen = []
    monkeypatch.setattr(tool_execution, "note_denied", lambda tool, reason: seen.append((tool, reason)))
    decision = fingerprint._propose(ENG, "nuclei", "vuln", "a.example.com", {"mode": "takeover"}, RUN)
    assert decision is not None and decision["allowed"] is True
    assert rec.claimed == ["ap-1"] and seen == []


def test_the_pipeline_check_in_an_unattended_run_is_recorded_as_not_executed(monkeypatch):
    _info(monkeypatch, supervision="unattended", operating_mode="monitoring")
    rec = Recorder(monkeypatch)
    monkeypatch.setattr(client, "authorize", lambda eid, payload: PENDING)
    seen = []
    monkeypatch.setattr(tool_execution, "note_denied", lambda tool, reason: seen.append((tool, reason)))
    assert fingerprint._propose(ENG, "nuclei", "vuln", "a.example.com", {}, RUN) is None
    assert seen == [("nuclei", "approval_unavailable_unattended")]
    assert rec.withdrawn == [("ap-1", "unattended_run")] and rec.claimed == []


def test_the_agent_does_not_wait_in_an_unattended_run(monkeypatch):
    rec = Recorder(monkeypatch)
    ctx = agent.SimpleContext(scan_run_id=RUN, unattended=True)
    monkeypatch.setattr(agent.time, "sleep", lambda s: pytest.fail("must not poll"))
    out = agent._await_approval(ENG, "ap-9", "asset-1", "a.example.com", {"method": "POST", "path": "/login"},
                                None, {"tool": "http_request", "target": "a.example.com"}, ctx)
    assert out.startswith("NOT EXECUTED") and "suggestion" in out
    assert rec.withdrawn == [("ap-9", "unattended_run")]
    assert rec.suggestions[0]["tool"] == "http_request" and "POST /login" in rec.suggestions[0]["rationale"]
    assert ctx.denied and ctx.denied[0]["reason"] == "approval_unavailable_unattended"


def test_the_agent_still_waits_in_an_attended_run(monkeypatch):
    Recorder(monkeypatch)
    ctx = agent.SimpleContext(scan_run_id=RUN, unattended=False)
    polled = []
    monkeypatch.setattr(client, "get_approval", lambda aid: polled.append(aid) or {"state": "rejected"})
    monkeypatch.setattr(agent, "CancelProbe", type("CP", (), {
        "for_run": classmethod(lambda cls, rid: type("P", (), {"is_cancelled": lambda self: False})())}))
    out = agent._await_approval(ENG, "ap-9", "asset-1", "a.example.com", {}, None,
                                {"tool": "nuclei", "target": "a.example.com"}, ctx, tool="nuclei")
    assert polled == ["ap-9"] and "rejected" in out


# ------------------------------------------------- REQ-MODE-008 / REQ-MODE-017


def _found():
    return [{"asset_id": "a1", "value": "kept.example.com"}, {"asset_id": "a2", "value": "new.example.com"}]


def test_held_hosts_are_left_out_of_a_monitoring_run(monkeypatch):
    _info(monkeypatch, operating_mode="monitoring", supervision="unattended")
    monkeypatch.setattr(client, "evaluate_hold", lambda rid, cands: {"released": ["a1"], "held": ["a2"]})
    assert asset_hold.apply(RUN, _found()) == [{"asset_id": "a1", "value": "kept.example.com"}]


def test_when_the_hold_policy_cannot_be_asked_nothing_is_tested(monkeypatch):
    _info(monkeypatch, operating_mode="monitoring", supervision="unattended")

    def boom(*a, **k):
        raise RuntimeError("control plane down")

    monkeypatch.setattr(client, "evaluate_hold", boom)
    assert asset_hold.apply(RUN, _found()) == []


def test_an_assessment_is_untouched_by_the_hold_policy(monkeypatch):
    _info(monkeypatch)
    monkeypatch.setattr(client, "evaluate_hold", lambda *a, **k: pytest.fail("must not be asked"))
    assert asset_hold.apply(RUN, _found()) == _found()


def test_a_scoped_run_tests_only_the_named_hosts():
    assert asset_hold.limit_to_hosts(_found(), ["NEW.example.com."]) == [{"asset_id": "a2", "value": "new.example.com"}]
    assert asset_hold.limit_to_hosts(_found(), None) == _found()
    assert asset_hold.limit_to_hosts(_found(), ["other.example.com"]) == []


# ---------------------------------------------------------- REQ-MODE-011


def _web(**kw):
    return planner.SurfaceInput(host="a.example.com", port=443, service_class="web", scheme="https", **kw)


def test_light_plans_only_the_cheap_stable_checks():
    checks = planner.plan_surface(_web(), planner.Options(scan_profile="light"))
    planned = {c.check_id for c in checks if c.state == "planned"}
    assert planned == {"wafw00f", "testssl", "header_findings", "nuclei:takeover"}
    skipped = {c.check_id: c.reason for c in checks if c.state == "skipped"}
    assert skipped["ffuf"] == "light_profile" and skipped["katana"] == "light_profile"


def test_light_never_plans_more_than_standard_does():
    standard = {c.check_id for c in planner.plan_surface(_web(), planner.Options(scan_profile="standard")) if c.state == "planned"}
    light = {c.check_id for c in planner.plan_surface(_web(), planner.Options(scan_profile="light")) if c.state == "planned"}
    assert light < standard


def test_light_ignores_switches_that_would_add_checks():
    options = planner.Options(scan_profile="light", crawling=True, screenshots=True, oob=True)
    planned = {c.check_id for c in planner.plan_surface(_web(), options) if c.state == "planned"}
    assert "katana" not in planned and "screenshot" not in planned and not any(c.startswith("nuclei:oob") for c in planned)


def test_light_on_a_duplicate_vhost_does_not_repeat_the_deep_checks():
    checks = planner.plan_surface(_web(duplicate_of="b.example.com"), planner.Options(scan_profile="light"))
    assert {c.check_id for c in checks if c.state == "planned"} == {"wafw00f", "testssl"}


def test_a_passive_run_fingerprints_nothing_and_asks_no_agent(monkeypatch):
    _info(monkeypatch, scan_profile="passive", operating_mode="monitoring", supervision="unattended")
    ran = []
    updates = []
    monkeypatch.setattr(client, "claim_scan_run", lambda *a, **k: {
        "attempt": 1, "phase": "discovery", "state": "running", "cancel_requested": False, "checkpoint": None})
    monkeypatch.setattr(client, "is_cancel_requested", lambda *a, **k: False)
    monkeypatch.setattr(client, "update_scan_run", lambda *a, **k: updates.append(k) or {})
    monkeypatch.setattr(client, "materialize_graph", lambda *a, **k: None)
    monkeypatch.setattr(pipeline.discovery, "run", lambda *a, **k: ran.append("discovery") or [
        {"value": "a.example.com", "asset_id": "1", "asset_type": "domain"}])
    monkeypatch.setattr(pipeline.asset_review, "gate", lambda e, r, d: d)
    monkeypatch.setattr(pipeline.fingerprint, "run", lambda *a, **k: ran.append("fingerprint") or [])
    monkeypatch.setattr(pipeline.correlate, "run", lambda *a, **k: ran.append("correlate") or [])
    monkeypatch.setattr(pipeline.agent, "run", lambda *a, **k: ran.append("agent"))
    monkeypatch.setattr(pipeline.score, "run", lambda *a, **k: ran.append("score"))
    monkeypatch.setattr(pipeline.report, "run", lambda *a, **k: ran.append("report"))
    tool_execution.clear_coverage(RUN)
    pipeline.run_scan.run(ENG, RUN)
    assert ran == ["discovery", "correlate", "score", "report"]
    assert updates[-1]["state"] == "done"


# ------------------------------------------------------------ REQ-MON-002


def test_alerts_due_together_are_sent_as_one_signed_digest_and_results_are_recorded(monkeypatch):
    due = [
        {"id": "1", "event": "asset_new", "payload": {"title": "New asset: a"}, "url": "https://h.example.org/x",
         "secret": "s", "attempts": 0, "immediate": False},
        {"id": "2", "event": "port_opened", "payload": {"title": "New port: b"}, "url": "https://h.example.org/x",
         "secret": "s", "attempts": 0, "immediate": False},
        {"id": "3", "event": "target_degraded", "payload": {"title": "degraded"}, "url": "https://other.example.org/y",
         "secret": None, "attempts": 0, "immediate": True},
    ]
    monkeypatch.setattr(client, "due_alerts", lambda: due)
    results = []
    monkeypatch.setattr(client, "report_alert_result", lambda aid, **k: results.append((aid, k["delivered"], k.get("error"))))
    sent = []

    def post(url, secret, body, event):
        sent.append((url, body, event))
        return (url.startswith("https://h."), None if url.startswith("https://h.") else "http_500")

    out = monitoring_tasks.deliver_due_alerts(post=post)
    assert out == {"delivered": 2, "failed": 1}
    digest = [s for s in sent if s[0].startswith("https://h.")]
    assert len(digest) == 1 and digest[0][2] == "digest" and len(digest[0][1]["events"]) == 2
    assert sorted(results) == [("1", True, None), ("2", True, None), ("3", False, "http_500")]


def test_the_sender_signs_the_body_and_never_follows_redirects(monkeypatch):
    captured = {}

    class Resp:
        status_code = 204

    def fake_post(url, content, headers, timeout, follow_redirects):
        captured.update(url=url, content=content, headers=headers, follow=follow_redirects)
        return Resp()

    monkeypatch.setattr(monitoring_tasks, "validate_webhook_url", lambda u: u)
    monkeypatch.setattr(monitoring_tasks.httpx, "post", fake_post)
    ok, err = monitoring_tasks._post("https://h.example.org/x", "topsecret", {"title": "t"}, "asset_new")
    assert ok is True and err is None
    assert captured["follow"] is False
    ts = captured["headers"]["X-Axial-Timestamp"]
    assert captured["headers"]["X-Axial-Signature"] == sign("topsecret", ts, captured["content"])


def test_a_refused_target_is_not_sent_to(monkeypatch):
    monkeypatch.setattr(monitoring_tasks.httpx, "post", lambda *a, **k: pytest.fail("must not send"))
    ok, err = monitoring_tasks._post("https://10.0.0.5/x", None, {}, "asset_new")
    assert ok is False and err.startswith("target_refused")


@pytest.mark.parametrize("url", [
    "http://hooks.example.org/x", "https://localhost/x", "https://127.0.0.1/x", "https://10.0.0.5/x",
    "https://169.254.169.254/latest", "https://user:pw@hooks.example.org/x", "https://svc.internal/x",
])
def test_the_worker_guard_refuses_what_the_control_plane_guard_refuses(url):
    with pytest.raises(WebhookTargetRefused):
        validate_webhook_url(url, resolve=lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))])
