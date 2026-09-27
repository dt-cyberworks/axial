"""scan_run-Orchestrierung: eine Phase je Schritt, wiederaufsetzbar
(Architektur Kap. 4.1). Der Celery-Task treibt die Zustandsmaschine
discovery -> fingerprint -> correlate -> agent -> validate -> score -> report
und meldet jeden Uebergang an control-plane, die ihn im audit_log
protokolliert (Live-View der Operator-Konsole, UI Kap. 3.1)."""

import logging
import uuid

from celery.exceptions import SoftTimeLimitExceeded

from app import tool_execution
from app.celery_app import celery_app
from app.control_plane_client import client
from app.tasks import agent, asset_review, correlate, discovery, fingerprint, report, score, validate

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
    attempted and never once succeeded - otherwise None."""
    degraded = tool_execution.degraded_tools(str(scan_run_id), LOAD_BEARING_TOOLS)
    if not degraded:
        return None
    parts = [f"{tool}={'|'.join(reasons) or 'unknown'}" for tool, reasons in sorted(degraded.items())]
    return "coverage_degraded:" + ",".join(parts)


def _combine_reasons(*reasons: str | None) -> str | None:
    present = [r for r in reasons if r]
    return "; ".join(present) if present else None


@celery_app.task(name="asm.run_scan", bind=True)
def run_scan(self, engagement_id: str, scan_run_id: str, budget_max_iterations: int = 50, approval_timeout_seconds: int = 900):
    # GitHub issue #18: the control plane now creates the scan_run row itself
    # (app.scan_lifecycle.start_scan_run, race-safe via a partial unique
    # index) BEFORE enqueueing, and hands us its ID - the worker no longer
    # creates its own row via a second, independently-racing check-then-
    # insert. The row already exists in state="running", phase="discovery".
    scan_run_id = uuid.UUID(scan_run_id)

    def _stopped() -> bool:
        """Kooperativer Stopp (REQ-RUN-001): an jeder Phasengrenze geprueft."""
        if client.is_cancel_requested(scan_run_id):
            logger.info("scan_run %s cancelled by operator", scan_run_id)
            client.update_scan_run(scan_run_id, state="aborted", state_reason="cancelled_by_operator")
            return True
        return False

    try:
        if _stopped():
            return {"scan_run_id": str(scan_run_id), "state": "aborted"}
        # REQ-CIDRDISC-001: discovery now includes an active, run-bound step
        # (the ip/cidr host-discovery sweep) alongside its purely-passive
        # domain enumeration, so it needs the exact scan_run_id like every
        # other target-touching phase.
        discovered = discovery.run(engagement_id, scan_run_id=str(scan_run_id))
        # REQ-GRAPH-001: (re)materialize the attack-surface graph at each phase
        # boundary. Best effort - never fails the scan.
        client.materialize_graph(uuid.UUID(engagement_id))
        client.update_scan_run(scan_run_id, phase="fingerprint")

        if _stopped():
            return {"scan_run_id": str(scan_run_id), "state": "aborted"}
        # REQ-ASSETREVIEW-002/006: optionale Pause; opt-in, sonst No-Op. Ein
        # abgelaufenes/abgelehntes Review bricht den Lauf fail-closed ab, statt
        # mit der vollen Kandidatenliste weiterzulaufen.
        discovered = asset_review.gate(engagement_id, str(scan_run_id), discovered)
        if discovered is None:
            client.update_scan_run(scan_run_id, state="aborted", state_reason="asset_review_expired")
            return {"scan_run_id": str(scan_run_id), "state": "aborted"}

        if _stopped():
            return {"scan_run_id": str(scan_run_id), "state": "aborted"}
        services = fingerprint.run(engagement_id, discovered, scan_run_id=str(scan_run_id))
        client.materialize_graph(uuid.UUID(engagement_id))
        client.update_scan_run(scan_run_id, phase="correlate")

        if _stopped():
            return {"scan_run_id": str(scan_run_id), "state": "aborted"}
        correlate.run(engagement_id, services=services)
        # Graph now carries CVE/finding nodes; the agent phase reads it next.
        client.materialize_graph(uuid.UUID(engagement_id))
        client.update_scan_run(scan_run_id, phase="agent")

        if _stopped():
            return {"scan_run_id": str(scan_run_id), "state": "aborted"}
        # scan_run_id an den Agenten: er zeichnet Steps auf + prueft selbst den Stopp.
        agent_context = agent.run(
            engagement_id, budget_max_iterations, scan_run_id=str(scan_run_id),
            approval_timeout_seconds=approval_timeout_seconds,
        )
        agent_warning = (
            f"agent_incomplete:{agent_context.incomplete_reason}"
            if agent_context.incomplete_reason else None
        )
        # REQ-SCAN-014: surface a gutted detection phase alongside (not instead
        # of) the agent warning - they are independent failures and an operator
        # needs to see both.
        run_warning = _combine_reasons(_coverage_warning(scan_run_id), agent_warning)
        client.update_scan_run(scan_run_id, phase="validate", state_reason=run_warning)

        if _stopped():
            return {"scan_run_id": str(scan_run_id), "state": "aborted"}
        validate.run(engagement_id, inferred_finding_ids=[])
        client.update_scan_run(scan_run_id, phase="score")

        if _stopped():
            return {"scan_run_id": str(scan_run_id), "state": "aborted"}
        score.run(engagement_id)
        client.update_scan_run(scan_run_id, phase="report")

        if _stopped():
            return {"scan_run_id": str(scan_run_id), "state": "aborted"}
        report.run(engagement_id, scan_run_id=str(scan_run_id))
        if _stopped():
            return {"scan_run_id": str(scan_run_id), "state": "aborted"}
        # REQ-SCAN-014: a run that reaches "done" having produced ZERO successful
        # executions of a load-bearing tool must not present as a clean scan.
        # Recomputed here (not reused from the validate boundary) so anything the
        # later phases attempted is included.
        client.update_scan_run(scan_run_id, state="done",
                               state_reason=_combine_reasons(_coverage_warning(scan_run_id), agent_warning))
    except SoftTimeLimitExceeded:
        # GitHub issue #29: distinguishable from a generic pipeline error so
        # an operator (or automation) can tell "this ran into the task time
        # limit" apart from "the pipeline code itself raised" - see
        # celery_app.py for why the limit is deliberately generous.
        logger.exception("scan_run %s exceeded the task time limit", scan_run_id)
        client.update_scan_run(scan_run_id, state="failed", state_reason="task_time_limit_exceeded")
        raise
    except Exception:
        logger.exception("scan_run %s failed", scan_run_id)
        client.update_scan_run(scan_run_id, state="failed", state_reason="pipeline_error")
        raise
    finally:
        # REQ-SCAN-014: the per-run coverage accumulator is in-process state and
        # must not outlive the run on ANY exit path (done, aborted, failed) -
        # otherwise a long-lived worker leaks one dict per scan forever.
        tool_execution.clear_coverage(str(scan_run_id))

    return {"scan_run_id": str(scan_run_id)}
