"""Sending one message over SMTP (REQ-MAIL-003/005).

The relay is chosen by an administrator, so the worker, which lives inside the
platform's networks, checks what the host name resolves to before it connects and
refuses a loopback or link-local address. TLS is always on (STARTTLS or implicit),
with certificate verification. Nothing here logs a recipient, a subject, a body or a
password.
"""

from __future__ import annotations

import email.utils
import ipaddress
import smtplib
import socket
import ssl
from email.message import EmailMessage

TIMEOUT_SECONDS = 20


class MailRefused(Exception):
    """The message was not sent for a reason that retrying cannot fix."""


def _line(value: str) -> str:
    if any(ch in value for ch in "\r\n\x00"):
        raise MailRefused("a header value contains a line break")
    return value


def build_message(*, sender: str, sender_name: str, to: str, subject: str, body: str) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = email.utils.formataddr((_line(sender_name), _line(sender))) if sender_name else _line(sender)
    msg["To"] = _line(to)
    msg["Subject"] = _line(subject)
    msg["Date"] = email.utils.formatdate(localtime=False)
    msg["Message-ID"] = email.utils.make_msgid(domain=sender.split("@", 1)[-1])
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(body, charset="utf-8")
    return msg


def _refuse_internal(host: str, port: int, resolve=socket.getaddrinfo) -> None:
    try:
        infos = resolve(host, port, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise MailRefused(f"the relay does not resolve: {host}") from exc
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if addr.is_loopback or addr.is_link_local or addr.is_unspecified or addr.is_multicast:
            raise MailRefused("the relay resolves to a loopback or link-local address")


def send(relay: dict, *, to: str, subject: str, body: str, smtp_factory=None, resolve=socket.getaddrinfo) -> None:
    """Raises MailRefused or an smtplib/OSError on failure; returns when the relay
    accepted the message."""
    msg = build_message(
        sender=relay["from_address"], sender_name=relay.get("from_name") or "", to=to, subject=subject, body=body,
    )
    host, port = relay["host"], int(relay["port"])
    _refuse_internal(host, port, resolve)
    context = ssl.create_default_context()
    if smtp_factory is None:
        if relay["security"] == "tls":
            server = smtplib.SMTP_SSL(host, port, timeout=TIMEOUT_SECONDS, context=context)
        else:
            server = smtplib.SMTP(host, port, timeout=TIMEOUT_SECONDS)
    else:
        server = smtp_factory(host, port)
    try:
        if relay["security"] == "starttls":
            server.starttls(context=context)
        if relay.get("username"):
            server.login(relay["username"], relay.get("password") or "")
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except Exception:  # noqa: BLE001
            pass
