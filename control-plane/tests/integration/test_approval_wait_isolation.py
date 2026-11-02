"""REQ-APPROVAL-008 (GitHub #83): a wait for one decision does not stop the run's other actions.

Found on int (2026-10-20): one action waited for approval, the run was marked `waiting_approval`, and the gateway
refused every other call of the run as `scan_run_not_active` - 37 of 60 checks, each recorded as denied and never
retried. The same "running only" test sat in the raw-egress lease, the budget context and the observation recorder.

Only a run that waits live (`waiting_approval` with the marker `approval_wait`) keeps executing. A parked run and an
asset-review pause are also `waiting_approval`, and nothing may run in those two."""

from __future__ import annotations

import datetime as dt
import pathlib
import re

import pytest
from sqlalchemy import select

from app.api.internal import _active_run_id, add_finding, internal_raw_egress_lease, update_scan_run
from app.gateway.authorize import ToolCall, authorize
from app.models.approval import ApprovalRequest
from app.models.engagement import Engagement, ScopeAsset, ToolGrant
from app.models.finding import FindingObservation
from app.models.resolved_host import ResolvedHost
from app.models.scan_run import LIVE_WAIT_REASON, ScanRun, executes_calls, executing_run_clause
from app.schemas.internal import FindingIn, RawEgressLeaseIn, ScanRunUpdate

TARGET = "metasploitable2"
PARKED = {"parked": {"approval_id": "ap-1", "since": "2026-10-31T08:00:00+00:00"}}

# (state, state_reason, checkpoint) - what a run is in when it waits for something.
LIVE = ("waiting_approval", LIVE_WAIT_REASON, None)
NOT_LIVE_WAITING = [
    pytest.param(("waiting_approval", None, None), id="waiting-no-reason"),
    pytest.param(("waiting_approval", "asset_review_pending", None), id="asset-review-pause"),
    pytest.param(("waiting_approval", "something_else", None), id="unknown-reason"),
    pytest.param(("waiting_approval", None, PARKED), id="parked-semi-attended"),
    pytest.param(("waiting_approval", LIVE_WAIT_REASON, PARKED), id="parked-even-with-the-marker"),
    pytest.param(("waiting_approval", LIVE_WAIT_REASON, {"parked": {}}), id="an-empty-parked-record-is-still-parked"),
]
FINISHED = [pytest.param(s, id=s) for s in ("done", "failed", "aborted")]


def _run(db, engagement_id, *, shape=("running", None, None), phase="fingerprint", budget_max=200, used=0, cancel=False):
    state, reason, checkpoint = shape
    run = ScanRun(engagement_id=engagement_id, phase=phase, state=state, state_reason=reason, checkpoint=checkpoint,
                  budget_tool_calls_max=budget_max, budget_tool_calls_used=used, cancel_requested=cancel, attempt=1)
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _twin(db, eng):
    """Another engagement with the scope and grants of `eng`: only one run per engagement may be active at a time."""
    twin = Engagement(title="Twin", source=eng.source, status="active", owner_user_id=eng.owner_user_id,
                      authorized_from=eng.authorized_from, authorized_until=eng.authorized_until,
                      ai_testing_allowed=eng.ai_testing_allowed)
    db.add(twin)
    db.flush()
    for a in db.scalars(select(ScopeAsset).where(ScopeAsset.engagement_id == eng.id)):
        db.add(ScopeAsset(engagement_id=twin.id, rule=a.rule, asset_type=a.asset_type, value=a.value,
                          active_allowed=a.active_allowed, authorization_verified=a.authorization_verified))
    for g in db.scalars(select(ToolGrant).where(ToolGrant.engagement_id == eng.id)):
        db.add(ToolGrant(engagement_id=twin.id, tool_category=g.tool_category, mode=g.mode,
                         requires_manual_approval=g.requires_manual_approval))
    db.commit()
    return twin


def _call(eng, run, *, tool="httpx", category="fingerprint", target=TARGET, phase="fingerprint", args=None, **kw):
    return ToolCall(engagement_id=eng.id, tool=tool, category=category, mode="active", target=target,
                    args=args if args is not None else {}, is_automated=True, phase=phase,
                    scan_run_id=run.id if run is not None else None, **kw)


@pytest.fixture
def eng(db, lab_engagement):
    lab_engagement.ai_testing_allowed = True
    db.commit()
    return lab_engagement


# ------------------------------------------------------------------ the shared rule


def test_the_rule_in_python_and_in_sql_agree(db, eng):
    """One definition (`executes_calls`), two forms of it; they must never disagree about a run, and both must say
    what the requirement says: a running run, and a run that waits live and is not parked."""
    cases = [
        (("running", None, None), True),
        (("running", LIVE_WAIT_REASON, None), True),
        (LIVE, True),
        (("waiting_approval", LIVE_WAIT_REASON, {"phase_note": "x"}), True),
        (("waiting_approval", LIVE_WAIT_REASON, {"parked": None}), True),  # a JSON null is no record, in Python and in SQL
        *[(p.values[0], False) for p in NOT_LIVE_WAITING],
        (("done", None, None), False),
        (("failed", LIVE_WAIT_REASON, None), False),
        (("aborted", LIVE_WAIT_REASON, None), False),
    ]
    runs = [(_run(db, _twin(db, eng).id, shape=shape), expected) for shape, expected in cases]
    in_sql = set(db.scalars(select(ScanRun.id).where(ScanRun.id.in_([r.id for r, _ in runs]), executing_run_clause())))
    for run, expected in runs:
        assert executes_calls(run) is expected, (run.state, run.state_reason, run.checkpoint)
        assert (run.id in in_sql) is expected, (run.state, run.state_reason, run.checkpoint)


# ------------------------------------------------------------------ the gateway


@pytest.mark.parametrize("phase, tool, category", [
    ("fingerprint", "httpx", "fingerprint"), ("fingerprint", "nuclei", "vuln"), ("agent", "httpx", "fingerprint"),
    ("agent", "http_request", "vuln"),
])
def test_a_live_wait_does_not_stop_the_runs_other_calls(db, eng, phase, tool, category):
    run = _run(db, eng.id, shape=LIVE, phase=phase)
    args = {"method": "GET", "path": "/"} if tool == "http_request" else {}
    decision = authorize(db, _call(eng, run, tool=tool, category=category, phase=phase, args=args))
    assert decision.allowed is True, decision.reason
    assert decision.reason != "scan_run_not_active"


def test_the_decision_for_a_live_wait_is_the_one_for_a_running_run(db, eng):
    """Not merely 'allowed': the same answer for a call that is refused for another reason."""
    twin = _twin(db, eng)
    live, running = _run(db, eng.id, shape=LIVE), _run(db, twin.id)
    for target, tool, category in [("clean-nginx", "httpx", "fingerprint"), ("unknown.example.test", "httpx", "fingerprint"),
                                   (TARGET, "nuclei", "exploit"), (TARGET, "not-a-tool", "fingerprint")]:
        a = authorize(db, _call(eng, live, target=target, tool=tool, category=category))
        b = authorize(db, _call(twin, running, target=target, tool=tool, category=category))
        assert (a.allowed, a.reason) == (b.allowed, b.reason), (target, tool, a.reason, b.reason)
        assert a.allowed is False


def test_negative_everything_else_still_decides_during_a_wait(db, eng):
    run = _run(db, eng.id, shape=LIVE)
    assert authorize(db, _call(eng, run, target="clean-nginx")).reason == "explicit_out_of_scope"
    assert authorize(db, _call(eng, run, target="unknown.example.test")).reason == "target_out_of_scope"
    assert authorize(db, _call(eng, run, tool="nmap", category="exploit")).allowed is False
    eng.authorized_until = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    db.commit()
    assert authorize(db, _call(eng, run)).reason == "outside_time_window"


@pytest.mark.parametrize("phase", ["fingerprint", "agent"])
def test_negative_a_cancel_request_wins_during_a_wait(db, eng, phase):
    run = _run(db, eng.id, shape=LIVE, phase=phase, cancel=True)
    assert authorize(db, _call(eng, run, phase=phase)).reason == "scan_run_cancelled"


def test_negative_a_run_of_another_engagement_is_not_found(db, eng):
    other = _run(db, eng.id, shape=LIVE)
    assert authorize(db, _call(_twin(db, eng), other)).reason == "scan_run_not_found"


@pytest.mark.parametrize("shape", NOT_LIVE_WAITING)
@pytest.mark.parametrize("phase", ["fingerprint", "agent"])
def test_negative_a_run_that_waits_for_anything_else_is_still_refused(db, eng, shape, phase):
    run = _run(db, eng.id, shape=shape, phase=phase)
    decision = authorize(db, _call(eng, run, phase=phase))
    assert decision.allowed is False and decision.reason == "scan_run_not_active"


@pytest.mark.parametrize("state", [p.values[0] for p in FINISHED])
@pytest.mark.parametrize("phase", ["fingerprint", "agent"])
def test_negative_a_finished_run_is_still_refused_even_with_the_marker(db, eng, state, phase):
    run = _run(db, eng.id, shape=(state, LIVE_WAIT_REASON, None), phase=phase)
    assert authorize(db, _call(eng, run, phase=phase)).reason == "scan_run_not_active"


def test_a_call_during_a_wait_is_counted_against_the_budget_and_the_ceiling_still_denies(db, eng):
    run = _run(db, eng.id, shape=LIVE, budget_max=2)
    assert authorize(db, _call(eng, run)).allowed and authorize(db, _call(eng, run)).allowed
    db.refresh(run)
    assert run.budget_tool_calls_used == 2
    third = authorize(db, _call(eng, run))
    assert third.allowed is False and third.reason == "budget_exhausted"


def test_the_budget_of_a_call_that_names_no_run_follows_the_live_wait_not_nothing(db, eng):
    """Without the fix `_active_scan_run` saw no run, so such a call was neither counted nor limited."""
    run = _run(db, eng.id, shape=LIVE, budget_max=1)
    none_bound = lambda: ToolCall(engagement_id=eng.id, tool="httpx", category="fingerprint", mode="active",  # noqa: E731
                                  target=TARGET, args={})
    assert authorize(db, none_bound()).allowed is True
    db.refresh(run)
    assert run.budget_tool_calls_used == 1
    assert authorize(db, none_bound()).reason == "budget_exhausted"


@pytest.mark.parametrize("shape", NOT_LIVE_WAITING)
def test_negative_a_run_that_waits_for_anything_else_gives_no_budget_context(db, eng, shape):
    run = _run(db, eng.id, shape=shape, budget_max=5)
    authorize(db, ToolCall(engagement_id=eng.id, tool="httpx", category="fingerprint", mode="active", target=TARGET, args={}))
    db.refresh(run)
    assert run.budget_tool_calls_used == 0


def test_the_action_that_needs_a_decision_still_waits_for_it(db, eng):
    """The wait is not a release: a state-changing request during a live wait is still `pending_approval`, creates its own
    approval, and is only executed after that approval is claimed (REQ-APPROVAL-004)."""
    run = _run(db, eng.id, shape=LIVE, phase="agent")
    post = lambda: _call(eng, run, tool="http_request", category="vuln", phase="agent", rationale="r",  # noqa: E731
                         args={"method": "POST", "path": "/rest/user/login", "body": "a=1"},
                         risk={"level": "low", "description": "logs in with a test body"})
    pending = authorize(db, post())
    assert pending.allowed is False and pending.is_pending is True and pending.approval_request_id is not None
    approval = db.get(ApprovalRequest, pending.approval_request_id)
    assert approval.state == "requested"
    # Not approved yet: a claim is refused and nothing is consumed.
    assert authorize(db, post(), approved_request_id=approval.id).allowed is False
    approval.state = "approved"
    db.commit()
    claimed = authorize(db, post(), approved_request_id=approval.id)
    assert claimed.allowed is True
    assert db.get(ApprovalRequest, approval.id).state == "executing"


def test_negative_an_approval_cannot_be_claimed_into_a_parked_run(db, eng):
    run = _run(db, eng.id, shape=("waiting_approval", None, PARKED), phase="agent")
    approval = ApprovalRequest(engagement_id=eng.id, state="approved",
                               tool_call=_call(eng, run, tool="http_request", category="vuln", phase="agent", rationale="r",
                                               args={"method": "POST", "path": "/x", "body": "a=1"},
                                               risk={"level": "low", "description": "d"}).as_jsonable(),
                               expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5))
    db.add(approval)
    db.commit()
    call = _call(eng, run, tool="http_request", category="vuln", phase="agent", rationale="r",
                 args={"method": "POST", "path": "/x", "body": "a=1"}, risk={"level": "low", "description": "d"})
    decision = authorize(db, call, approved_request_id=approval.id)
    assert decision.allowed is False and decision.reason == "scan_run_not_active"
    assert db.get(ApprovalRequest, approval.id).state == "approved"


# ------------------------------------------------------------------ the raw-egress lease


def _lease(db, eng, run):
    db.add(ResolvedHost(engagement_id=eng.id, hostname=TARGET, ip_address="192.0.2.10",
                        resolved_at=dt.datetime.now(dt.timezone.utc)))
    db.commit()
    return internal_raw_egress_lease(eng.id, RawEgressLeaseIn(
        scan_run_id=run.id, authorized_target=TARGET, resolved_target="192.0.2.10", phase="fingerprint",
        port_profile="full_tcp"), db)


def test_a_live_wait_does_not_stop_the_raw_egress_lease(db, eng):
    result = _lease(db, eng, _run(db, eng.id, shape=LIVE))
    assert result.allowed is True and result.lease_token


@pytest.mark.parametrize("shape", NOT_LIVE_WAITING)
def test_negative_no_lease_for_a_run_that_waits_for_anything_else(db, eng, shape):
    result = _lease(db, eng, _run(db, eng.id, shape=shape))
    assert result.allowed is False and result.reason == "scan_run_not_active" and not result.lease_token


@pytest.mark.parametrize("shape", [*NOT_LIVE_WAITING, *[pytest.param((s, LIVE_WAIT_REASON, None), id=s) for s in ("done", "failed", "aborted")]])
def test_negative_the_lease_checks_the_run_itself_not_only_through_the_gateway(db, eng, shape, monkeypatch):
    """The lease is a second layer: with the gateway stubbed to allow, the lease still refuses a run that is not doing
    work. Without this the lease check could be loosened and every other test would still pass."""
    from app.gateway import raw_egress_lease
    from app.gateway.authorize import Decision

    monkeypatch.setattr(raw_egress_lease, "authorize", lambda *a, **k: Decision(allowed=True, reason="stub"))
    result = _lease(db, eng, _run(db, eng.id, shape=shape))
    assert result.allowed is False and result.reason == "scan_run_not_active" and not result.lease_token


@pytest.mark.parametrize("state", [p.values[0] for p in FINISHED])
def test_negative_no_lease_for_a_finished_run_with_the_marker(db, eng, state):
    result = _lease(db, eng, _run(db, eng.id, shape=(state, LIVE_WAIT_REASON, None)))
    assert result.allowed is False and result.reason == "scan_run_not_active"


def test_negative_no_lease_for_a_cancelled_run_in_a_wait(db, eng):
    result = _lease(db, eng, _run(db, eng.id, shape=LIVE, cancel=True))
    assert result.allowed is False and result.reason == "scan_run_not_active"


# ------------------------------------------------------------------ the observation recorder


def test_a_finding_written_during_a_wait_is_recorded_as_seen_in_the_run(db, eng):
    """Without the fix the finding had no run to be observed in, so the next diff could call it fixed."""
    run = _run(db, eng.id, shape=LIVE)
    assert _active_run_id(db, eng.id) == run.id
    add_finding(eng.id, FindingIn(category="exposure", title="Open admin panel", confidence="validated"), db)
    seen = db.scalars(select(FindingObservation.scan_run_id).where(FindingObservation.engagement_id == eng.id)).all()
    assert seen == [run.id]


@pytest.mark.parametrize("shape", NOT_LIVE_WAITING)
def test_negative_a_run_that_waits_for_anything_else_records_no_observation(db, eng, shape):
    _run(db, eng.id, shape=shape)
    assert _active_run_id(db, eng.id) is None
    add_finding(eng.id, FindingIn(category="exposure", title="Open admin panel", confidence="validated"), db)
    assert db.scalars(select(FindingObservation).where(FindingObservation.engagement_id == eng.id)).all() == []


# ------------------------------------------------------------------ the marker on the control plane


def _patch(db, run, **fields):
    return update_scan_run(run.id, ScanRunUpdate(attempt=1, **fields), db)


def test_the_marker_is_set_with_the_wait_and_cleared_when_the_run_runs_again(db, eng):
    run = _run(db, eng.id)
    out = _patch(db, run, state="waiting_approval", state_reason=LIVE_WAIT_REASON)
    assert (out.state, out.state_reason) == ("waiting_approval", LIVE_WAIT_REASON)
    out = _patch(db, run, state="running")
    assert out.state == "running" and out.state_reason is None


@pytest.mark.parametrize("state", ["done", "failed", "aborted"])
def test_the_marker_never_outlives_the_wait_when_the_run_ends(db, eng, state):
    run = _run(db, eng.id, shape=LIVE)
    out = _patch(db, run, state=state)
    assert out.state == state and out.state_reason is None


def test_a_real_reason_given_with_the_end_of_the_run_is_kept(db, eng):
    run = _run(db, eng.id, shape=LIVE)
    out = _patch(db, run, state="failed", state_reason="pipeline_error")
    assert (out.state, out.state_reason) == ("failed", "pipeline_error")


def test_another_reason_is_not_touched_when_the_run_runs_again(db, eng):
    run = _run(db, eng.id, shape=("waiting_approval", "asset_review_pending", None))
    out = _patch(db, run, state="running")
    assert out.state_reason == "asset_review_pending"


def test_a_run_that_is_waiting_keeps_its_marker_across_updates_that_do_not_change_the_state(db, eng):
    run = _run(db, eng.id, shape=LIVE)
    out = _patch(db, run, phase="fingerprint")
    assert (out.state, out.state_reason) == ("waiting_approval", LIVE_WAIT_REASON)


# ------------------------------------------------------------------ one definition, no second copy


_ROOT = pathlib.Path(__file__).resolve().parents[2] / "app"
_RAW_RUNNING_TEST = re.compile(r"""state\s*(==|!=)\s*["']running["']""")


@pytest.mark.parametrize("module, allowed", [
    ("gateway/authorize.py", []),
    ("gateway/raw_egress_lease.py", []),
    # The asset review is created from a run that is running; a run in a wait is not paused a second time.
    ("api/internal.py", ['if run is not None and run.state == "running":']),
])
def test_the_modules_that_gate_on_the_run_use_the_one_definition(module, allowed):
    lines = [ln.strip() for ln in (_ROOT / module).read_text().splitlines()
             if _RAW_RUNNING_TEST.search(ln) and not ln.strip().startswith("#")]
    assert lines == allowed, f"{module} tests the run state by itself again: {lines}"
