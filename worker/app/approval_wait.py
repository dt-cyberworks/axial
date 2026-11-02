"""A decision a person has to make, for a call the deterministic pipeline proposed
(REQ-MODE-005, REQ-MODE-007).

Before this, a pipeline call that the gateway answered with `pending_approval` was
logged as denied and skipped, while the gateway had already created an approval
request: the console showed a popup that nothing waited for, and approving it did
nothing. Now:

  * a run nobody supervises (a monitoring run, or one started unattended) never
    waits: the approval is withdrawn and the check is recorded as not executed;
  * otherwise the worker waits for the decision exactly as the agent does -
    cancel-aware, bounded by the approval timeout - and runs the call only after
    the gateway has re-checked and claimed the exact stored call.
"""

from __future__ import annotations

import contextlib
import logging
import threading
import time
import uuid

from app.cancel_probe import CancelProbe
from app.control_plane_client import client

logger = logging.getLogger(__name__)

POLL_SECONDS = 3
_DECIDED = ("approved", "rejected", "expired", "consumed", "cancelled")

# REQ-APPROVAL-008 (GitHub #83). While the worker waits for the decision on ONE action, the run is `waiting_approval`
# (REQ-APPROVAL-003) but its other actions go on, so the run says why it waits. The control plane accepts calls of a run
# in that state ONLY with this exact reason (a parked run and an asset-review pause are `waiting_approval` too).
# It must equal control-plane/app/models/scan_run.py LIVE_WAIT_REASON (scripts/tests/test_live_wait_marker_parity.py).
LIVE_WAIT_REASON = "approval_wait"

# How many actions of a run wait right now. The pipeline runs checks in several threads and a wait ends in whichever
# thread gets its answer, so the run goes back to `running` only when the LAST wait ends. The lock is held across the
# state change on purpose: a leaver's "running" must not overtake a newcomer's "waiting_approval".
_open_waits: dict[str, int] = {}
_open_waits_lock = threading.Lock()


def _set_run_state(run_id: str, **fields) -> None:
    try:
        client.update_scan_run(uuid.UUID(run_id), **fields)
    except Exception as exc:  # noqa: BLE001 - the state is a display; it must never stop a scan or a wait
        logger.warning("could not set the run state %s: %s", fields.get("state"), exc)


@contextlib.contextmanager
def live_wait(scan_run_id: str | None):
    """Around the wait for one action's decision: the run shows `waiting_approval` (with the live-wait reason) from the
    first open wait until the last one ends. Never raises; a state that cannot be written is logged and the wait goes on."""
    if not scan_run_id:
        yield
        return
    with _open_waits_lock:
        _open_waits[scan_run_id] = _open_waits.get(scan_run_id, 0) + 1
        if _open_waits[scan_run_id] == 1:
            _set_run_state(scan_run_id, state="waiting_approval", state_reason=LIVE_WAIT_REASON)
    try:
        yield
    finally:
        with _open_waits_lock:
            left = _open_waits.get(scan_run_id, 1) - 1
            if left > 0:
                _open_waits[scan_run_id] = left
            else:
                _open_waits.pop(scan_run_id, None)
                # The control plane takes the live-wait reason away with this transition.
                _set_run_state(scan_run_id, state="running")


def is_unattended(scan_run_id: str | None) -> bool:
    info = client.run_info(scan_run_id)
    return info.get("supervision") == "unattended" or info.get("operating_mode") == "monitoring"


def wait_for_decision(approval_id: str, scan_run_id: str | None, timeout_seconds: int, *, sleep=time.sleep) -> str:
    """The approval's state once decided, `expired` when nobody answered in time,
    `cancelled` when the run was stopped meanwhile."""
    probe = CancelProbe.for_run(scan_run_id) if scan_run_id else None
    waited = 0
    while waited < timeout_seconds:
        if probe is not None and probe.is_cancelled():  # fails closed when unreadable
            return "cancelled"
        state = client.get_approval(str(approval_id)).get("state")
        if state in _DECIDED:
            return state
        sleep(POLL_SECONDS)
        waited += POLL_SECONDS
    return "expired"


def resolve_pending(
    engagement_id: str, decision: dict, *, tool: str, target: str, scan_run_id: str | None,
) -> tuple[dict | None, str]:
    """Returns (decision, reason). `decision` is an allowed gateway decision when the
    call may run now, None when it must not; `reason` says why not."""
    approval_id = decision.get("approval_request_id")
    if not approval_id:
        return None, "pending_no_id"

    if is_unattended(scan_run_id):
        # The control plane keeps the exact call of a withdrawn approval as a held-back request (REQ-RETEST-004).
        client.withdraw_approval(str(approval_id), "unattended_run")
        return None, "approval_unavailable_unattended"

    info = client.run_info(scan_run_id)
    with live_wait(scan_run_id):
        state = wait_for_decision(str(approval_id), scan_run_id, int(info.get("approval_timeout_seconds") or 900))

    if state != "approved":
        return None, f"approval_{state}"

    claim = client.claim_approval(str(approval_id))
    if not claim.get("allowed"):
        return None, f"approval_claim_denied:{claim.get('reason', 'denied')}"
    # The gateway re-checked the exact stored call and handed it to this run. The
    # pipeline executes the same call right after returning; the approval is closed
    # now so no `executing` row is left behind if the process stops in between.
    try:
        client.complete_approval(str(approval_id), success=True)
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not complete approval %s: %s", approval_id, exc)
    return {"allowed": True, "reason": "approved_by_operator", "approval_request_id": str(approval_id)}, "approved"
