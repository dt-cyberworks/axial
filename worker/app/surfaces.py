"""Web-surface classification helpers (REQ-PIPE-001). Pure functions.

A port whose only answer is a redirect to another surface of the same host that
this run scans anyway (the classic `http://host:80 -> https://host:443`) is an
alias of that surface: it gets no deep checks of its own, the target gets them
once.
"""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlsplit

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_DEFAULT_PORTS = {"http": 80, "https": 443}


def redirect_alias_port(
    status_code: int | None, location: str | None, host: str, port: int, live_ports: Iterable[int],
) -> int | None:
    """The port this surface is an alias of, or None when it is a surface of its own.

    Conservative on purpose - anything unclear stays a full surface:
    - only 301/302/303/307/308 count;
    - the Location must be absolute, on the SAME host name, http or https;
    - the target port must differ from this one and already be confirmed live
      in this run (so an alias never points at something that was not scanned).
    """
    try:
        status = int(status_code) if status_code is not None else None
    except (TypeError, ValueError):
        return None
    if status not in _REDIRECT_STATUSES or not location:
        return None
    try:
        parts = urlsplit(location.strip())
        target_port = parts.port or _DEFAULT_PORTS.get(parts.scheme)
    except ValueError:
        return None
    if parts.scheme not in _DEFAULT_PORTS or not parts.hostname:
        return None
    if parts.hostname.lower().rstrip(".") != host.strip().lower().rstrip("."):
        return None
    if target_port is None or target_port == port or target_port not in set(live_ports):
        return None
    return target_port


# --- Service classes of non-web ports (REQ-PIPE-001/009) -------------------------

# Services that speak TLS from the first byte (testssl connects directly).
_IMPLICIT_TLS_PORTS = frozenset({465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 5061, 6697})
_IMPLICIT_TLS_NAMES = frozenset({"smtps", "imaps", "pop3s", "ldaps", "ftps", "nntps", "sips", "ircs", "ssl", "tls"})
# Services that upgrade to TLS with a STARTTLS command; value = testssl's --starttls protocol.
_STARTTLS_NAMES = {
    "smtp": "smtp", "submission": "smtp", "imap": "imap", "pop3": "pop3", "ftp": "ftp", "ldap": "ldap",
    "xmpp": "xmpp", "xmpp-client": "xmpp", "nntp": "nntp", "postgresql": "postgres", "mysql": "mysql",
}
_STARTTLS_PORTS = {25: "smtp", 587: "smtp", 143: "imap", 110: "pop3", 21: "ftp", 389: "ldap", 5222: "xmpp"}
_UNIDENTIFIED = frozenset({"", "unknown", "tcpwrapped"})


def classify_open_port(port: int | None, service_name: str | None, product: str | None = None) -> tuple[str, str | None]:
    """(service class, testssl --starttls protocol) of an open, non-web TCP port.

    `tls_service` for an implicit-TLS or STARTTLS-capable service, `service` for
    any other identified service, `unknown` for the rest. The class only decides
    which checks are planned; it never authorizes contact.
    """
    name = (service_name or "").strip().lower().removeprefix("ssl/")
    if port in _IMPLICIT_TLS_PORTS or name in _IMPLICIT_TLS_NAMES:
        return "tls_service", None
    starttls = _STARTTLS_NAMES.get(name) or (_STARTTLS_PORTS.get(port) if name in _UNIDENTIFIED | {"smtp", "imap"} else None)
    if starttls:
        return "tls_service", starttls
    if name in _UNIDENTIFIED:
        return ("service", None) if (product or "").strip().lower() not in _UNIDENTIFIED else ("unknown", None)
    return "service", None
