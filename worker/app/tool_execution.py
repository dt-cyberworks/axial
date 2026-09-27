"""Durable, bounded tool-execution outcome telemetry."""

from __future__ import annotations

import threading
import uuid

from app.control_plane_client import client

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
        outcome_summary=result.get("outcome_summary") or {},
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
        entry = per_run.setdefault(tool, {"attempted": 0, "succeeded": 0, "reasons": []})
        entry["attempted"] += 1
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
