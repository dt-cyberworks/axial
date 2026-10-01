"""Tolerant, fail-closed reading of the operator's cancel flag (GitHub issue #49,
REQ-PIPE-020, builds on REQ-FIDELITY-001).

The worker asks the control plane "has the operator cancelled this run?" at every
phase boundary and between checks. The per-tool wait loop already survives a
single failed answer and fails closed after sustained ones; the plan executor,
the phase boundaries and the agent loop did not - one timed-out answer crashed
the whole run as a bare `pipeline_error`.

The rules, for every caller:
  * an answer that could not be read is never taken as "not cancelled";
  * a few consecutive unreadable answers are absorbed (a restart or a busy moment);
  * sustained unavailability raises CancellationStatusUnavailable, and the caller
    must stop target-facing work - the same fail-closed outcome as the per-tool loop.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable

from app.control_plane_client import ScanRunSuperseded, client
from app.tool_runner_client import CANCEL_POLL_SECONDS, CANCEL_STATUS_FAILURE_TOLERANCE

logger = logging.getLogger(__name__)


class CancellationStatusUnavailable(RuntimeError):
    """The control plane would not say whether the operator cancelled the run."""


class CancelProbe:
    def __init__(
        self,
        fetch: Callable[[], bool],
        *,
        tolerance: int | None = None,
        retry_seconds: float | None = None,
        label: str = "scan run",
    ):
        self._fetch = fetch
        self._tolerance = tolerance or CANCEL_STATUS_FAILURE_TOLERANCE
        self._retry_seconds = CANCEL_POLL_SECONDS if retry_seconds is None else retry_seconds
        self._label = label
        self._failures = 0

    @classmethod
    def for_run(cls, scan_run_id: str | uuid.UUID) -> "CancelProbe":
        run_id = uuid.UUID(str(scan_run_id))
        return cls(lambda: client.is_cancel_requested(run_id), label=f"scan run {run_id}")

    def check(self) -> bool | None:
        """True: cancelled. False: not cancelled. None: no answer yet, still within
        the tolerance - hold (start nothing new) and ask again. Raises
        CancellationStatusUnavailable once the failures are sustained; a run that
        was taken over by a newer attempt (ScanRunSuperseded) is passed through."""
        try:
            cancelled = bool(self._fetch())
        except ScanRunSuperseded:
            raise
        except Exception as exc:  # noqa: BLE001 - timeouts, 5xx, connection errors all mean "no answer"
            self._failures += 1
            logger.warning("cancel status of %s unavailable (%d/%d): %s: %s",
                           self._label, self._failures, self._tolerance, type(exc).__name__, exc)
            if self._failures >= self._tolerance:
                raise CancellationStatusUnavailable(
                    f"cancel status of {self._label} unavailable after {self._failures} attempts: "
                    f"{type(exc).__name__}"
                ) from exc
            return None
        self._failures = 0
        return cancelled

    def is_cancelled(self) -> bool:
        """Blocking form for code that just needs an answer: waits and retries
        within the tolerance, and raises CancellationStatusUnavailable beyond it."""
        while True:
            status = self.check()
            if status is not None:
                return status
            time.sleep(self._retry_seconds)
