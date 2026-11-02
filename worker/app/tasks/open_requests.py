"""Sending the requests a person confirmed for this run (REQ-RETEST-006/007).

Each approval was created already approved when the person pressed "Send this request", bound to the exact stored
call with this run's id. The worker does not trust anything it holds in memory: it claims the approval through the
control plane (which re-runs every gateway check and refuses a changed or expired call) and executes only the call
the claim hands back. A request that could not be sent is not a failure of the run; the control plane reopens it
when the run ends (control-plane/app/open_items.py reconcile_sent).
"""

from __future__ import annotations

import logging
import uuid

from app.control_plane_client import client
from app.target_envelope import single_port_from_envelope
from app.tasks import agent, dispatch

logger = logging.getLogger(__name__)


def _event(engagement_id: str, scan_run_id: str, event: str, *, decision: str, reason: str, **payload) -> None:
    agent._audit_agent_event(engagement_id, event, scan_run_id=scan_run_id, decision=decision, reason=reason, **payload)


def send_confirmed(engagement_id: str, scan_run_id: str, approval_ids: list[str]) -> None:
    if not approval_ids:
        return
    asset_by_host, ip_by_host = agent._load_scope(engagement_id, scan_run_id)
    for approval_id in approval_ids:
        claim = client.claim_approval(str(approval_id))
        if not claim.get("allowed"):
            reason = str(claim.get("reason") or "approval_claim_denied")
            logger.warning("confirmed request %s was not sent: %s", approval_id, reason)
            _event(engagement_id, scan_run_id, "open_request_not_sent", decision="DENY", reason=reason,
                   approval_id=str(approval_id))
            continue
        exact = claim.get("tool_call") or {}
        tool, target = str(exact.get("tool") or ""), str(exact.get("target") or "")
        args = exact.get("args") or {}
        proposal = {"tool": tool, "target": target, "method": args.get("method"), "path": args.get("path")}
        asset_id = asset_by_host.get(target.lower())
        if asset_id is None:
            client.complete_approval(str(approval_id), success=False, error="approved_target_not_loaded")
            _event(engagement_id, scan_run_id, "open_request_not_sent", decision="DENY", reason="approved_target_not_loaded",
                   approval_id=str(approval_id), proposal=proposal)
            continue
        _event(engagement_id, scan_run_id, "open_request_sending", decision="ALLOW", reason="individually_confirmed",
               approval_id=str(approval_id), proposal=proposal)
        try:
            single_port = single_port_from_envelope(client.get_scan_envelope(uuid.UUID(engagement_id), host=target))
        except Exception:  # noqa: BLE001 - best effort, as in the agent phase
            single_port = None
        try:
            obs = dispatch.dispatch(
                engagement_id, asset_id, tool, target, ip_by_host.get(target.lower()), args=args,
                scan_run_id=scan_run_id, single_port=single_port,
            )
        except Exception as exc:  # noqa: BLE001 - one request's error never stops the others
            client.complete_approval(str(approval_id), success=False, error=str(exc)[:500])
            _event(engagement_id, scan_run_id, "open_request_not_sent", decision="DENY", reason="runner_execution_failed",
                   approval_id=str(approval_id), proposal=proposal)
            continue
        client.complete_approval(str(approval_id), success=True)
        _event(engagement_id, scan_run_id, "open_request_sent", decision="ALLOW", reason="request_sent",
               approval_id=str(approval_id), proposal=proposal, observation=obs.as_text()[:2000])
