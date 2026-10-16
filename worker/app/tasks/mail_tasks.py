"""Delivery of queued e-mail (REQ-MAIL-003). The control plane has no route to the
internet, so it queues and this worker task sends; the outcome of every attempt is
reported back and a failure never affects a scan."""

from __future__ import annotations

import logging
import smtplib

from app import mail_sender
from app.celery_app import celery_app
from app.control_plane_client import client

logger = logging.getLogger(__name__)


def _reason(exc: Exception) -> str:
    """A short, secret-free reason: the kind of failure, never a recipient or a body."""
    if isinstance(exc, mail_sender.MailRefused):
        return f"refused:{exc}"[:200]
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "relay_authentication_failed"
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "recipient_refused"
    if isinstance(exc, smtplib.SMTPResponseException):
        return f"relay_response_{exc.smtp_code}"
    return type(exc).__name__


def deliver_due_mail(send=mail_sender.send) -> dict:
    payload = client.due_mail()
    relay, messages = payload.get("relay"), payload.get("messages") or []
    sent = failed = 0
    if not relay:
        return {"sent": 0, "failed": 0, "relay": False}
    for message in messages:
        try:
            send(relay, to=message["to"], subject=message["subject"], body=message["body"])
            delivered, error = True, None
        except Exception as exc:  # noqa: BLE001 - one bad message must not stop the others
            delivered, error = False, _reason(exc)
        try:
            client.report_mail_result(message["id"], delivered=delivered, error=error)
        except Exception as exc:  # noqa: BLE001
            logger.warning("could not record the result of a message: %s", type(exc).__name__)
        sent += 1 if delivered else 0
        failed += 0 if delivered else 1
    return {"sent": sent, "failed": failed, "relay": True}


@celery_app.task(name="asm.deliver_mail")
def deliver_mail() -> dict:
    try:
        return deliver_due_mail()
    except Exception:  # noqa: BLE001
        logger.warning("mail delivery failed", exc_info=False)
        return {"sent": 0, "failed": 0, "error": True}
