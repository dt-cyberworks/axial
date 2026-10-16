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

import logging
import time
import uuid

from app.cancel_probe import CancelProbe
from app.control_plane_client import client

logger = logging.getLogger(__name__)

POLL_SECONDS = 3
_DECIDED = ("approved", "rejected", "expired", "consumed", "cancelled")


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
    engagement_id: str, decision: dict, *, tool: str, target: str, scan_run_id: str | None, rationale: str = "",
) -> tuple[dict | None, str]:
    """Returns (decision, reason). `decision` is an allowed gateway decision when the
    call may run now, None when it must not; `reason` says why not."""
    approval_id = decision.get("approval_request_id")
    if not approval_id:
        return None, "pending_no_id"

    if is_unattended(scan_run_id):
        client.withdraw_approval(str(approval_id), "unattended_run")
        client.add_suggestion(
            uuid.UUID(engagement_id), tool=tool, target=target,
            rationale=rationale or f"{tool} on {target} needs a person's decision",
        )
        return None, "approval_unavailable_unattended"

    info = client.run_info(scan_run_id)
    run_uuid = uuid.UUID(scan_run_id) if scan_run_id else None
    if run_uuid is not None:
        try:
            client.update_scan_run(run_uuid, state="waiting_approval")
        except Exception as exc:  # noqa: BLE001
            logger.warning("could not set the waiting_approval state: %s", exc)
    try:
        state = wait_for_decision(str(approval_id), scan_run_id, int(info.get("approval_timeout_seconds") or 900))
    finally:
        if run_uuid is not None:
            try:
                client.update_scan_run(run_uuid, state="running")
            except Exception:  # noqa: BLE001
                pass

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
