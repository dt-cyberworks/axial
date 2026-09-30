"""Durable, bounded tool-execution outcome telemetry."""

from __future__ import annotations

import contextlib
import contextvars
import threading
import uuid

from app.control_plane_client import client

# REQ-PIPE-006: every check ends as complete, partial, failed or skipped:<why>.
# `budget_reached` is the one error_reason that means "stopped by its own time
# budget, everything printed before that is real": the output is kept, but the
# check never reads as a clean result.
BUDGET_REACHED = "budget_reached"
# Failures that are really "this check did not apply / was not possible" and
# are reported as skipped rather than failed.
SKIP_REASONS = frozenset({
    "not_a_tls_service", "materialized_ip_missing", "oob_unavailable", "no_tool_grant",
    "raw_egress_unavailable", "scan_run_missing",
})


def outcome_of(result: dict) -> str:
    """complete | partial | failed | skipped:<reason> for one tool result."""
    explicit = result.get("outcome")
    if explicit:
        return str(explicit)
    if result.get("success"):
        return "complete"
    reason = result.get("error_reason")
    if reason == BUDGET_REACHED:
        return "partial"
    if reason in SKIP_REASONS:
        return f"skipped:{reason}"
    return "failed"


def usable_output(result: dict) -> bool:
    """Whether stdout holds real results: a complete run, or one that was cut
    by its own budget after printing (partial)."""
    return bool(result.get("success")) or result.get("error_reason") == BUDGET_REACHED


def skipped_result(reason: str, **summary) -> dict:
    """A check that was deliberately not run. Successful in the sense that
    nothing went wrong, but never `complete`: the outcome says `skipped`."""
    return {
        "success": True, "exit_code": 0, "stdout": "", "stderr": f"skipped:{reason}",
        "error_reason": None, "outcome": f"skipped:{reason}",
        "outcome_summary": {"skip_reason": reason, **summary},
    }


# REQ-SCAN-014: in-process, per-run coverage accumulator.
#
# Every tool in the worker already funnels its terminal outcome through
# record() below, which makes this the one place that sees all of them - no
# per-tool plumbing, and a tool added later is covered automatically.
#
# Keyed by scan_run_id rather than held as a single global because a worker
# process may run more than one scan concurrently (Celery thread/eventlet
# pools); a flat global would attribute one run's failures to another.
# Bounded by construction: one small dict per active run, dropped by
# clear_coverage() at the end of the run.
_COVERAGE: dict[str, dict[str, dict]] = {}
_COVERAGE_LOCK = threading.Lock()


class CheckCollector:
    """What one scan check did, gathered while it runs (REQ-PIPE-006): every
    terminal tool result it recorded, every call the gateway refused, and how
    many findings it stored. The executor turns this into the check's outcome."""

    def __init__(self) -> None:
        self.results: list[dict] = []
        self.denials: list[tuple[str, str]] = []
        self.findings = 0


_COLLECTOR: contextvars.ContextVar[CheckCollector | None] = contextvars.ContextVar("asm_check_collector", default=None)


@contextlib.contextmanager
def collect():
    """Collect the results of everything the current thread records. Scoped per
    thread/context, so two checks running in parallel never see each other's."""
    collector = CheckCollector()
    token = _COLLECTOR.set(collector)
    try:
        yield collector
    finally:
        _COLLECTOR.reset(token)


def note_denied(tool: str, reason: str) -> None:
    collector = _COLLECTOR.get()
    if collector is not None:
        collector.denials.append((tool, str(reason)))


def note_finding(count: int = 1) -> None:
    collector = _COLLECTOR.get()
    if collector is not None:
        collector.findings += count


def check_outcome(collector: CheckCollector) -> tuple[str, str | None]:
    """(complete | partial | failed | skipped, detail) of one check.

    failed beats partial beats complete; a check is skipped only when nothing it
    attempted ran (every result skipped, or the gateway refused the call)."""
    outcomes = [outcome_of(r) for r in collector.results]
    if not outcomes:
        if collector.denials:
            tool, reason = collector.denials[0]
            return "skipped", f"gateway_denied:{reason}"
        return "complete", None
    if any(r.get("error_reason") in ("cancelled_by_operator", "cancellation_status_unavailable") for r in collector.results):
        return "skipped", "cancelled_by_operator"
    if all(o.startswith("skipped") for o in outcomes):
        return "skipped", outcomes[0].partition(":")[2] or "skipped"
    if any(o == "failed" for o in outcomes):
        failed = next(r for r in collector.results if outcome_of(r) == "failed")
        return "failed", str(failed.get("error_reason") or "failed")
    if any(o == "partial" for o in outcomes):
        return "partial", BUDGET_REACHED
    return "complete", None


def failed_result(reason: str, error: Exception | None = None) -> dict:
    detail = str(error) if error is not None else reason
    return {
        "success": False,
        "exit_code": -1,
        "stderr": detail[:1000],
        "error_reason": reason,
        "stdout": "",
    }


def record(
    engagement_id: str,
    *,
    scan_run_id: str | None,
    tool: str,
    phase: str,
    authorized_target: str,
    resolved_target: str | None,
    port_range: str | None,
    result: dict,
    discovered_services: int = 0,
    response: str | None = None,
) -> None:
    """Persist one terminal result; telemetry failure does not rewrite outcome."""
    collector = _COLLECTOR.get()
    if collector is not None:
        collector.results.append(result)
    _accumulate_coverage(scan_run_id, tool, result)
    client.record_tool_execution(
        uuid.UUID(engagement_id),
        scan_run_id=scan_run_id,
        tool=tool,
        phase=phase,
        authorized_target=authorized_target,
        resolved_target=resolved_target,
        port_range=port_range,
        success=bool(result.get("success")),
        exit_code=result.get("exit_code"),
        error_reason=result.get("error_reason"),
        stderr_summary=str(result.get("stderr") or "")[:1000] or None,
        discovered_services=max(0, int(discovered_services)),
        outcome_summary={**(result.get("outcome_summary") or {}), "outcome": outcome_of(result)},
        # REQ-AUDIT-003: the invocation actually used, already redacted by
        # tool_runner_client (REQ-AUDIT-004). Absent for a tool whose
        # invocation could not be rendered - never a fabricated one.
        command=result.get("command"),
        # REQ-AUDIT-006/007: the full target response for http_request,
        # already redacted by the caller (dispatch.py::_run). Absent for
        # every other tool - their raw output is already parsed into
        # services/findings/outcome_summary, so duplicating it here would
        # just bloat the audit table without adding operator-visible value.
        response=response,
    )


def _accumulate_coverage(scan_run_id: str | None, tool: str, result: dict) -> None:
    if not scan_run_id:
        return
    succeeded = bool(result.get("success"))
    reason = None if succeeded else (result.get("error_reason") or "unknown")
    with _COVERAGE_LOCK:
        per_run = _COVERAGE.setdefault(str(scan_run_id), {})
        entry = per_run.setdefault(tool, {"attempted": 0, "succeeded": 0, "partial": 0, "reasons": []})
        entry["attempted"] += 1
        if result.get("error_reason") == BUDGET_REACHED:
            entry["partial"] += 1
        if succeeded:
            entry["succeeded"] += 1
        elif reason not in entry["reasons"]:
            # Distinct reasons only, and bounded - a host list of any size must
            # not turn this into an unbounded string.
            if len(entry["reasons"]) < 5:
                entry["reasons"].append(reason)


def coverage_summary(scan_run_id: str | None) -> dict[str, dict]:
    """tool -> {attempted, succeeded, reasons} for this run so far."""
    if not scan_run_id:
        return {}
    with _COVERAGE_LOCK:
        return {tool: dict(entry, reasons=list(entry["reasons"]))
                for tool, entry in _COVERAGE.get(str(scan_run_id), {}).items()}


def partial_tools(scan_run_id: str | None) -> dict[str, int]:
    """REQ-PIPE-006: tool -> number of checks this run that stopped at their
    own time budget. A partial check is real output but not full coverage."""
    return {
        tool: entry["partial"]
        for tool, entry in coverage_summary(scan_run_id).items()
        if entry.get("partial")
    }


def clear_coverage(scan_run_id: str | None) -> None:
    if not scan_run_id:
        return
    with _COVERAGE_LOCK:
        _COVERAGE.pop(str(scan_run_id), None)


def degraded_tools(scan_run_id: str | None, tools: tuple[str, ...]) -> dict[str, list[str]]:
    """Of `tools`, those that were ATTEMPTED at least once and NEVER succeeded,
    mapped to their distinct failure reasons.

    "Attempted at least once" is the load-bearing part: a tool that never ran
    (no in-scope asset called for it) is not degraded, and a tool that ran and
    legitimately found nothing is not degraded either. Only "we tried and every
    single attempt failed" counts - that is the state that is otherwise
    indistinguishable from a clean result.
    """
    summary = coverage_summary(scan_run_id)
    return {
        tool: entry["reasons"]
        for tool, entry in summary.items()
        if tool in tools and entry["attempted"] > 0 and entry["succeeded"] == 0
    }
