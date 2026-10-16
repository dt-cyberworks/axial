"""Periodic work of the monitoring mode (REQ-MON-002, REQ-MODE-012).

  * alert delivery: signed webhooks, retried with backoff by the control plane's
    bookkeeping; a failed delivery is recorded and never touches a run;
  * housekeeping: missed runs and authorization review, raised once each.

The worker only sends what the control plane hands it. The URL is checked again
right before sending (names can change what they resolve to), redirects are never
followed, and nothing but the alert's own small body is sent.
"""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict

import httpx

from app.celery_app import celery_app
from app.control_plane_client import client
from app.webhook_guard import WebhookTargetRefused, sign, validate_webhook_url

logger = logging.getLogger(__name__)

SEND_TIMEOUT_SECONDS = 10.0


def _post(url: str, secret: str | None, body: dict, event: str) -> tuple[bool, str | None]:
    try:
        validate_webhook_url(url)
    except WebhookTargetRefused as exc:
        return False, f"target_refused:{exc}"
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    headers = {
        "Content-Type": "application/json", "User-Agent": "Axial-Alerts/1", "X-Axial-Event": event,
        "X-Axial-Timestamp": timestamp,
    }
    if secret:
        headers["X-Axial-Signature"] = sign(secret, timestamp, raw)
    try:
        resp = httpx.post(url, content=raw, headers=headers, timeout=SEND_TIMEOUT_SECONDS, follow_redirects=False)
    except httpx.HTTPError as exc:
        return False, type(exc).__name__
    if 200 <= resp.status_code < 300:
        return True, None
    return False, f"http_{resp.status_code}"


def deliver_due_alerts(post=_post) -> dict:
    """One POST per alert; non-urgent alerts due together for one URL are sent as one digest."""
    due = client.due_alerts()
    by_url: dict[str, list[dict]] = defaultdict(list)
    for alert in due:
        by_url[alert["url"]].append(alert)
    delivered = failed = 0
    for url, alerts in by_url.items():
        secret = alerts[0].get("secret")
        digest = len(alerts) > 1 and not any(a.get("immediate") for a in alerts)
        groups = [alerts] if digest else [[a] for a in alerts]
        for group in groups:
            if len(group) > 1:
                body = {"digest": True, "events": [a["payload"] for a in group]}
                event = "digest"
            else:
                body, event = group[0]["payload"], group[0]["event"]
            ok, error = post(url, secret, body, event)
            for alert in group:
                try:
                    client.report_alert_result(alert["id"], delivered=ok, error=error)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("could not record the result of alert %s: %s", alert["id"], exc)
            delivered += len(group) if ok else 0
            failed += 0 if ok else len(group)
    return {"delivered": delivered, "failed": failed}


@celery_app.task(name="asm.deliver_alerts")
def deliver_alerts() -> dict:
    try:
        return deliver_due_alerts()
    except Exception:  # noqa: BLE001 - never let alert plumbing raise into the worker loop
        logger.exception("alert delivery failed")
        return {"delivered": 0, "failed": 0, "error": True}


@celery_app.task(name="asm.monitoring_housekeeping")
def monitoring_housekeeping() -> dict:
    try:
        return client.monitoring_housekeeping()
    except Exception:  # noqa: BLE001
        logger.exception("monitoring housekeeping failed")
        return {"error": True}


@celery_app.task(name="asm.run_due_schedules")
def run_due_schedules() -> dict:
    """REQ-MON-003: ask the control plane to start the runs that are due. Never raises into the
    worker loop; a failed tick is simply tried again a minute later."""
    try:
        return client.run_due_schedules()
    except Exception:  # noqa: BLE001
        logger.exception("scheduler tick failed")
        return {"error": True}


@celery_app.task(name="asm.resume_parked_runs")
def resume_parked_runs() -> dict:
    """REQ-MODE-016: a parked run whose approval expired (nobody answered) continues
    with 'not approved'. A decision made in the console resumes the run at once."""
    try:
        return {"resumed": client.resume_parked_runs()}
    except Exception:  # noqa: BLE001
        logger.exception("resuming parked runs failed")
        return {"resumed": 0, "error": True}
