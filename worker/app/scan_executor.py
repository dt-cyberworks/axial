"""Check executor (REQ-PIPE-006, REQ-PIPE-008, REQ-PIPE-015).

Runs the checks of a persisted scan plan: in plan order, at most
`max_parallel` at a time, each as one row whose state is the checkpoint. A
resumed run reads the same plan and continues with the checks that were not
finished - a `running` row (its worker died) runs again, a `complete`,
`partial`, `failed` or `skipped` one never does.

The executor knows nothing about tools. A handler (worker/app/tasks/
fingerprint.py) does the work of one check through the unchanged gateway ->
runner path; the executor records what happened, honestly (`complete`,
`partial`, `failed` or `skipped`), and never lets one check's error stop the
others.
"""

from __future__ import annotations

import concurrent.futures
import dataclasses
import logging
import time
from collections.abc import Callable

from app import tool_execution
from app.control_plane_client import ScanRunSuperseded

logger = logging.getLogger(__name__)

_TERMINAL = {"complete", "partial", "failed", "skipped"}
_UNFINISHED = {"planned", "running"}
_POLL_SECONDS = 1.0


@dataclasses.dataclass
class CheckRun:
    """What a handler gets for one check, and where it reports back."""

    engagement_id: str
    scan_run_id: str
    surface: dict
    check: dict
    dependencies: dict[str, dict]
    # Set by the handler when it changes what is stored on the check row.
    args: dict | None = None
    reason: str | None = None
    budget_s: int | None = None
    forced_state: tuple[str, str] | None = None  # (state, detail) when the handler decides
    outcome_summary: dict = dataclasses.field(default_factory=dict)

    @property
    def host(self) -> str:
        return str(self.surface["host"])

    @property
    def port(self) -> int:
        return int(self.surface["port"])

    @property
    def single_port(self) -> int | None:
        """The port to pass to the tools: None means the default (443)."""
        return None if self.port == 443 else self.port

    @property
    def asset_id(self) -> str | None:
        return self.surface.get("asset_id")

    @property
    def fingerprint(self) -> dict:
        return self.surface.get("fingerprint") or {}

    @property
    def protocol(self) -> str | None:
        return self.fingerprint.get("protocol") or self.surface.get("scheme")

    def skip(self, detail: str) -> None:
        self.forced_state = ("skipped", detail)


Handler = Callable[[CheckRun], None]


@dataclasses.dataclass
class ExecutionResult:
    ran: int = 0
    by_state: dict[str, int] = dataclasses.field(default_factory=dict)
    cancelled: bool = False


def _dependency_ready(check: dict, states: dict[tuple[str, str], dict], surface_id: str) -> bool:
    dep = check.get("depends_on")
    if not dep:
        return True
    row = states.get((surface_id, dep))
    # A dependency that does not exist cannot ever finish: do not wait for it.
    return row is None or row["state"] in _TERMINAL


def _run_one(
    client, scan_run_id: str, engagement_id: str, surface: dict, check: dict,
    handler: Handler | None, dependencies: dict[str, dict],
) -> dict:
    started = time.monotonic()
    client.update_scan_check(scan_run_id, check["id"], state="running")
    run = CheckRun(engagement_id, scan_run_id, surface, check, dependencies)
    crashed: Exception | None = None
    with tool_execution.collect() as collector:
        if handler is None:
            crashed = LookupError("no handler for check")
        else:
            try:
                handler(run)
            except ScanRunSuperseded:
                raise
            except Exception as exc:  # noqa: BLE001 - one check's error never stops the others
                logger.exception("check %s on %s:%s failed", check["check_id"], run.host, run.port)
                crashed = exc
    state, detail = tool_execution.check_outcome(collector)
    if run.forced_state is not None:
        state, detail = run.forced_state
    if crashed is not None:
        state, detail = "failed", f"handler_error:{type(crashed).__name__}"
    fields: dict = {
        "state": state, "findings": collector.findings,
        "duration_s": round(time.monotonic() - started, 2),
        "outcome_summary": {**run.outcome_summary, **({"detail": detail} if detail else {})},
    }
    if state == "skipped" and detail:
        fields["reason"] = detail
    elif run.reason:
        fields["reason"] = run.reason
    if run.args is not None:
        fields["args"] = run.args
    if run.budget_s is not None:
        fields["budget_s"] = run.budget_s
    return client.update_scan_check(scan_run_id, check["id"], **fields)


def execute_plan(
    *, client, scan_run_id: str, engagement_id: str, resolve_handler: Callable[[dict], Handler | None],
    max_parallel: int, is_cancelled: Callable[[], bool],
) -> ExecutionResult:
    plan = client.get_scan_plan(scan_run_id)
    surfaces = {s["id"]: s for s in plan["surfaces"]}
    rows = [(s["id"], c) for s in plan["surfaces"] for c in s["checks"]]
    rows.sort(key=lambda item: item[1]["seq"])
    states: dict[tuple[str, str], dict] = {(sid, c["check_id"]): c for sid, c in rows}
    pending = [(sid, c) for sid, c in rows if c["state"] in _UNFINISHED]
    result = ExecutionResult()
    running: dict[concurrent.futures.Future, tuple[str, dict]] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, max_parallel), thread_name_prefix="check") as pool:
        while pending or running:
            if not result.cancelled and is_cancelled():
                result.cancelled = True
            while not result.cancelled and pending and len(running) < max(1, max_parallel):
                ready = next(((sid, c) for sid, c in pending if _dependency_ready(c, states, sid)), None)
                if ready is None:
                    break
                pending.remove(ready)
                sid, check = ready
                deps = {k[1]: v for k, v in states.items() if k[0] == sid}
                future = pool.submit(
                    _run_one, client, scan_run_id, engagement_id, surfaces[sid], check,
                    resolve_handler(check), deps,
                )
                running[future] = (sid, check)
            if result.cancelled:
                pending.clear()
            if not running:
                if pending:  # nothing runnable and nothing running: unreachable dependencies
                    logger.error("scan plan of %s has %d checks that can never run", scan_run_id, len(pending))
                    for sid, check in pending:
                        client.update_scan_check(
                            scan_run_id, check["id"], state="skipped", reason="dependency_never_finished",
                        )
                    pending.clear()
                break
            done, _ = concurrent.futures.wait(running, timeout=_POLL_SECONDS, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                sid, check = running.pop(future)
                finished = future.result()  # re-raises a superseded worker
                states[(sid, check["check_id"])] = finished
                result.ran += 1
                result.by_state[finished["state"]] = result.by_state.get(finished["state"], 0) + 1
    return result
