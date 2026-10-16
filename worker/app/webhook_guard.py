"""Webhook target validation and signing (REQ-MON-002).

A webhook URL is an outgoing request chosen by a user, so it is checked twice:
when it is saved (control plane) and again right before delivery (this worker),
because a name can change what it resolves to. Only https URLs whose every
resolved address is a public one are accepted; redirects are never followed by
the sender. Mirrors control-plane/app/webhook_guard.py (the two cannot share code
across the process boundary); a test keeps their verdicts equal.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import socket
from urllib.parse import urlsplit

MAX_URL_LENGTH = 2000


class WebhookTargetRefused(ValueError):
    """The URL is not an acceptable webhook target (message is safe to show)."""


def _public(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
        or ip.is_reserved or ip.is_unspecified
        or (isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None and not _public(str(ip.ipv4_mapped)))
    )


def validate_webhook_url(url: str, *, resolve=socket.getaddrinfo) -> str:
    """Returns the URL, or raises WebhookTargetRefused."""
    value = (url or "").strip()
    if not value or len(value) > MAX_URL_LENGTH:
        raise WebhookTargetRefused("the webhook URL is empty or too long")
    parts = urlsplit(value)
    if parts.scheme != "https":
        raise WebhookTargetRefused("the webhook URL must use https")
    if parts.username or parts.password:
        raise WebhookTargetRefused("the webhook URL must not contain credentials")
    host = (parts.hostname or "").strip().lower()
    if not host or host == "localhost" or host.endswith((".local", ".internal", ".localhost")):
        raise WebhookTargetRefused("the webhook host is not a public name")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not _public(str(literal)):
            raise WebhookTargetRefused("the webhook address is not public")
        return value
    try:
        infos = resolve(host, parts.port or 443, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise WebhookTargetRefused(f"the webhook host does not resolve: {host}") from exc
    addresses = {info[4][0] for info in infos}
    if not addresses:
        raise WebhookTargetRefused(f"the webhook host does not resolve: {host}")
    if not all(_public(a) for a in addresses):
        raise WebhookTargetRefused("the webhook host resolves to a non-public address")
    return value


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """`sha256=<hex>` over `<timestamp>.<body>`, the value of X-Axial-Signature."""
    mac = hmac.new(secret.encode("utf-8"), timestamp.encode("ascii") + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()
