"""scan_run-Orchestrierung: eine Phase je Schritt, wiederaufsetzbar
(Architektur Kap. 4.1). Der Celery-Task treibt die Zustandsmaschine
discovery -> fingerprint -> correlate -> agent -> score -> report
und meldet jeden Uebergang an control-plane, die ihn im audit_log
protokolliert (Live-View der Operator-Konsole, UI Kap. 3.1)."""

import json
import logging
import time
import uuid

from celery.exceptions import SoftTimeLimitExceeded

from app import tool_execution
from app.cancel_probe import CancelProbe, CancellationStatusUnavailable
from app.celery_app import celery_app
from app.control_plane_client import ScanRunNotClaimable, ScanRunSuperseded, client
from app.tasks import agent, asset_review, correlate, discovery, fingerprint, report, score

logger = logging.getLogger(__name__)

# REQ-SCAN-014: tools whose total failure silently guts the run's detection
# coverage rather than merely narrowing it.
#   nmap  - the sole input to the correlate phase; without it a non-HTTP
#           service (database, mail, message queue) is never even seen, and
#           CVE correlation for every port has nothing to work from.
#   httpx - gates the whole web suite in _web_suite(); if it never succeeds,
#           nikto/wafw00f/testssl/nuclei are all skipped for that host.
# A failure of e.g. nikto alone narrows coverage but leaves the rest intact,
# so it is deliberately not treated as run-level degradation.
LOAD_BEARING_TOOLS = ("nmap", "httpx")


def _coverage_warning(scan_run_id) -> str | None:
    """`coverage_degraded:<tool>=<reason>[,...]` when a load-bearing tool was
    attempted and never once succeeded; `coverage_partial:<tool>=<n>[,...]`
    (REQ-PIPE-006) when checks stopped at their own time budget - real results,
    but not full coverage. None when neither applies."""
    warnings = []
    degraded = tool_execution.degraded_tools(str(scan_run_id), LOAD_BEARING_TOOLS)
    if degraded:
        parts = [f"{tool}={'|'.join(reasons) or 'unknown'}" for tool, reasons in sorted(degraded.items())]
        warnings.append("coverage_degraded:" + ",".join(parts))
    partial = tool_execution.partial_tools(str(scan_run_id))
    if partial:
        warnings.append("coverage_partial:" + ",".join(f"{tool}={count}" for tool, count in sorted(partial.items())))
    return "; ".join(warnings) or None


# GitHub issue #42: the phases in order. scan_run.phase always names the NEXT
# phase to run, so a resumed task continues exactly where the last one stopped.
PHASES = ("discovery", "fingerprint", "correlate", "agent", "score", "report")

# REQ-PIPE-014: the validate phase performed no validation and was removed. A
# run stored at it before that change continues at the phase that followed it.
_RETIRED_PHASES = {"validate": "score"}


def _start_index(phase: str, checkpoint: dict) -> int:
    """Where to (re)start. A phase whose input the checkpoint does not hold is
    replaced by the phase that produces it - re-running an earlier phase is
    safe (it is idempotent and every target contact goes through the gateway)."""
    phase = _RETIRED_PHASES.get(phase, phase)
    index = PHASES.index(phase) if phase in PHASES else 0
    if index >= 2 and checkpoint.get("services") is None:
        index = 1
    if index >= 1 and checkpoint.get("discovered") is None:
        index = 0
    return index


def _plain(value):
    """A phase result as plain JSON, so storing a checkpoint can never be what
    fails a scan."""
    return json.loads(json.dumps(value, default=str))


def _combine_reasons(*reasons: str | None) -> str | None:
    present = [r for r in reasons if r]
    return "; ".join(present) if present else None


@celery_app.task(name="asm.run_scan", bind=True)
def run_scan(self, engagement_id: str, scan_run_id: str, budget_max_iterations: int = 50, approval_timeout_seconds: int = 900):
    # GitHub issue #18: the control plane creates the scan_run row itself
    # (app.scan_lifecycle.start_scan_run, race-safe via a partial unique
    # index) BEFORE enqueueing, and hands us its ID.
    # GitHub issue #42: the task then CLAIMS the run. The claim says where to
    # continue (phase + checkpoint), which makes this task safe to run again
    # after a worker crash: the control plane's reaper queues a new task for
    # the same run and this function picks up at the phase after the last one
    # that completed. A duplicate delivery is refused by the claim.
    scan_run_id = uuid.UUID(scan_run_id)
    try:
        claim = client.claim_scan_run(
            scan_run_id, task_id=self.request.id or str(uuid.uuid4()),
            budget_max_iterations=budget_max_iterations, approval_timeout_seconds=approval_timeout_seconds,
        )
    except ScanRunNotClaimable as exc:
        logger.warning("scan_run %s not claimed: %s", scan_run_id, exc.reason)
        return {"scan_run_id": str(scan_run_id), "state": "not_claimed"}
    except Exception as exc:  # noqa: BLE001 - the control plane is unreachable: try again shortly
        raise self.retry(exc=exc, countdown=15, max_retries=8)

    checkpoint: dict = dict(claim.get("checkpoint") or {})
    params = checkpoint.get("params") or {}
    budget_max_iterations = params.get("budget_max_iterations") or budget_max_iterations
    approval_timeout_seconds = params.get("approval_timeout_seconds") or approval_timeout_seconds
    start = _start_index(claim.get("phase") or "discovery", checkpoint)
    if claim.get("attempt", 1) > 1:
        logger.warning("scan_run %s resumed (attempt %s) at phase %s", scan_run_id, claim.get("attempt"), PHASES[start])

    discovered = checkpoint.get("discovered")
    services = checkpoint.get("services")
    review_done = bool(checkpoint.get("review_done"))
    agent_warning = checkpoint.get("agent_warning")
    carried_coverage = checkpoint.get("coverage_warning")

    def _coverage() -> str | None:
        current = _coverage_warning(scan_run_id)
        return current if current == carried_coverage else _combine_reasons(carried_coverage, current)

    cancel_probe = CancelProbe.for_run(scan_run_id)
    phase = PHASES[start]  # the phase being worked on, for the failure cause

    def _stopped() -> bool:
        """Kooperativer Stopp (REQ-RUN-001): an jeder Phasengrenze geprueft.

        GitHub issue #49: an unreadable answer is never "not cancelled"; the probe
        retries within REQ-FIDELITY-001's tolerance and raises
        CancellationStatusUnavailable beyond it (handled below, fail closed)."""
        if cancel_probe.is_cancelled():
            logger.info("scan_run %s cancelled by operator", scan_run_id)
            client.update_scan_run(scan_run_id, state="aborted", state_reason="cancelled_by_operator")
            return True
        return False

    def _aborted() -> dict:
        return {"scan_run_id": str(scan_run_id), "state": "aborted"}

    try:
        if start <= 0:
            phase = "discovery"
            if _stopped():
                return _aborted()
            # REQ-CIDRDISC-001: discovery includes an active, run-bound step
            # (the ip/cidr host-discovery sweep), so it needs the scan_run_id.
            discovered = discovery.run(engagement_id, scan_run_id=str(scan_run_id))
            # REQ-GRAPH-001: (re)materialize the attack-surface graph at each
            # phase boundary. Best effort - never fails the scan.
            client.materialize_graph(uuid.UUID(engagement_id))
            review_done = False
            client.update_scan_run(scan_run_id, phase="fingerprint",
                                   checkpoint={"discovered": _plain(discovered), "review_done": False})

        if start <= 1:
            phase = "fingerprint"
            if _stopped():
                return _aborted()
            if not review_done:
                # REQ-ASSETREVIEW-002/006: optional pause; opt-in, otherwise a
                # no-op. An expired/declined review aborts the run fail-closed
                # instead of continuing with the full candidate list.
                discovered = asset_review.gate(engagement_id, str(scan_run_id), discovered)
                if discovered is None:
                    client.update_scan_run(scan_run_id, state="aborted", state_reason="asset_review_expired")
                    return _aborted()
                review_done = True
                client.update_scan_run(scan_run_id, checkpoint={"discovered": _plain(discovered), "review_done": True})
            if _stopped():
                return _aborted()
            services = fingerprint.run(
                engagement_id, discovered, scan_run_id=str(scan_run_id),
                resume_services=checkpoint.get("fp_services"),
            )
            client.materialize_graph(uuid.UUID(engagement_id))
            client.update_scan_run(scan_run_id, phase="correlate",
                                   checkpoint={"services": _plain(services), "coverage_warning": _coverage()})

        if start <= 2:
            phase = "correlate"
            if _stopped():
                return _aborted()
            correlate.run(engagement_id, services=services)
            # Graph now carries CVE/finding nodes; the agent phase reads it next.
            client.materialize_graph(uuid.UUID(engagement_id))
            client.update_scan_run(scan_run_id, phase="agent")

        if start <= 3:
            phase = "agent"
            if _stopped():
                return _aborted()
            # scan_run_id to the agent: it records steps + checks the stop itself.
            agent_context = agent.run(
                engagement_id, budget_max_iterations, scan_run_id=str(scan_run_id),
                approval_timeout_seconds=approval_timeout_seconds,
            )
            agent_warning = (
                f"agent_incomplete:{agent_context.incomplete_reason}"
                if agent_context.incomplete_reason else None
            )
            # REQ-SCAN-014: surface a gutted detection phase alongside (not
            # instead of) the agent warning - independent failures, both shown.
            run_warning = _combine_reasons(_coverage(), agent_warning)
            client.update_scan_run(scan_run_id, phase="score", state_reason=run_warning,
                                   checkpoint={"agent_warning": agent_warning, "coverage_warning": _coverage()})

        if start <= 4:
            phase = "score"
            if _stopped():
                return _aborted()
            score.run(engagement_id)
            client.update_scan_run(scan_run_id, phase="report")

        phase = "report"
        if _stopped():
            return _aborted()
        report.run(engagement_id, scan_run_id=str(scan_run_id))
        if _stopped():
            return _aborted()
        # REQ-SCAN-014: a run that reaches "done" having produced ZERO successful
        # executions of a load-bearing tool must not present as a clean scan.
        # Recomputed here (not reused from the agent boundary) so anything the
        # later phases attempted is included.
        client.update_scan_run(scan_run_id, state="done", state_reason=_combine_reasons(_coverage(), agent_warning))
    except ScanRunSuperseded:
        # A newer attempt owns the run now: stop quietly, write nothing more.
        logger.warning("scan_run %s was taken over by a newer worker attempt - stopping", scan_run_id)
        return {"scan_run_id": str(scan_run_id), "state": "superseded"}
    except SoftTimeLimitExceeded:
        # GitHub issue #29: distinguishable from a generic pipeline error so
        # an operator (or automation) can tell "this ran into the task time
        # limit" apart from "the pipeline code itself raised" - see
        # celery_app.py for why the limit is deliberately generous.
        logger.exception("scan_run %s exceeded the task time limit", scan_run_id)
        _mark_failed(scan_run_id, "task_time_limit_exceeded")
        raise
    except CancellationStatusUnavailable:
        # GitHub issue #49: the control plane would not say whether the operator
        # cancelled, so target-facing work stops (fail closed, like the per-tool
        # loop) and the run ends with that reason - not as a bare pipeline_error.
        logger.error("scan_run %s stopped: cancel status unavailable in phase %s", scan_run_id, phase)
        _end_run(scan_run_id, "aborted", "cancellation_status_unavailable")
        return _aborted()
    except Exception as exc:
        logger.exception("scan_run %s failed", scan_run_id)
        _mark_failed(scan_run_id, pipeline_error_reason(exc, phase))
        raise
    finally:
        # REQ-SCAN-014: the per-run coverage accumulator is in-process state and
        # must not outlive the run on ANY exit path (done, aborted, failed) -
        # otherwise a long-lived worker leaks one dict per scan forever.
        tool_execution.clear_coverage(str(scan_run_id))
        client.release_scan_run(scan_run_id)

    return {"scan_run_id": str(scan_run_id)}


def pipeline_error_reason(exc: BaseException, phase: str) -> str:
    """`pipeline_error:<ExceptionType>:<phase>` - the cause an operator needs without
    opening the worker log. Only the class name, never the message (it can carry a
    URL or a credential)."""
    return f"pipeline_error:{type(exc).__name__}:{phase}"


# GitHub issue #49: ending a run is a write to the control plane, which is exactly
# what may be unavailable when a run ends abnormally. A few short retries; if they
# all fail the run stays claimed and the reaper resumes or aborts it (REQ-RESUME-003).
_END_RUN_BACKOFF_SECONDS = (0.5, 1.0, 2.0)


def _end_run(scan_run_id: uuid.UUID, state: str, reason: str) -> None:
    for attempt, delay in enumerate((*_END_RUN_BACKOFF_SECONDS, None)):
        try:
            client.update_scan_run(scan_run_id, state=state, state_reason=reason)
            return
        except ScanRunSuperseded:
            return  # a newer attempt owns the run; it decides how the run ends
        except Exception as exc:  # noqa: BLE001
            if delay is None:
                logger.error("scan_run %s could not be marked %s/%s: %s", scan_run_id, state, reason, exc)
                return
            logger.warning("marking scan_run %s %s failed (attempt %d): %s", scan_run_id, state, attempt + 1, exc)
            time.sleep(delay)


def _mark_failed(scan_run_id: uuid.UUID, reason: str) -> None:
    _end_run(scan_run_id, "failed", reason)
