"""The mail relay settings (REQ-MAIL-001/002).

Optional and off by default: an installation that configures nothing behaves as it
always did. The relay password is stored encrypted with the settings key (like the
LLM provider's key), is never returned, and is only handed to the worker, over the
internal token, when it has a message to send.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import ipaddress
import re

from sqlalchemy.orm import Session

from app.models.app_setting import AppSetting
from app.settings_store import SettingsCipherUnavailable, _decrypt_api_key, _encrypt_api_key

MAIL_CONFIG_KEY = "mail_config"
SECURITIES = ("starttls", "tls")
_ADDRESS = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")


class MailConfigError(ValueError):
    """The submitted settings are not acceptable (message is safe to show)."""


@dataclasses.dataclass
class MailConfig:
    enabled: bool = False
    host: str = ""
    port: int = 587
    security: str = "starttls"
    username: str = ""
    password_set: bool = False
    from_address: str = ""
    from_name: str = ""


def valid_address(value: str) -> bool:
    """One plain address: no line break, no space, no display name, a dotted domain."""
    candidate = (value or "").strip()
    return bool(candidate) and len(candidate) <= 254 and bool(_ADDRESS.match(candidate))


def _clean_line(value: str, field: str, *, max_len: int = 200) -> str:
    text = (value or "").strip()
    if any(ch in text for ch in "\r\n\x00") or len(text) > max_len:
        raise MailConfigError(f"{field} must be one short line")
    return text


def validate_host(host: str) -> str:
    """A relay on the internet or on a corporate network. Refused: nothing, a service
    name of the internal networks (no dot), and loopback, link-local, multicast or
    unspecified addresses - the worker that sends is inside the platform's networks."""
    value = _clean_line(host, "host", max_len=253).lower().rstrip(".")
    if not value:
        raise MailConfigError("the relay host is required")
    try:
        literal = ipaddress.ip_address(value)
    except ValueError:
        literal = None
    if literal is not None:
        if literal.is_loopback or literal.is_link_local or literal.is_multicast or literal.is_unspecified:
            raise MailConfigError("the relay address must not be a loopback, link-local or unspecified address")
        return value
    if "." not in value or value == "localhost" or value.endswith((".local", ".internal", ".localhost")):
        raise MailConfigError("the relay host must be a name with a domain, not a service of this installation")
    if not re.fullmatch(r"[a-z0-9.-]+", value):
        raise MailConfigError("the relay host contains characters a host name cannot have")
    return value


def _row(db: Session) -> dict:
    row = db.get(AppSetting, MAIL_CONFIG_KEY)
    return dict(row.value) if row and isinstance(row.value, dict) else {}


def get_mail_config(db: Session) -> MailConfig:
    stored = _row(db)
    try:
        port = int(stored.get("port", 587))
    except (TypeError, ValueError):
        port = 587
    return MailConfig(
        enabled=bool(stored.get("enabled", False)), host=str(stored.get("host", "")), port=port,
        security=stored.get("security") if stored.get("security") in SECURITIES else "starttls",
        username=str(stored.get("username", "")), password_set=bool(stored.get("password_enc")),
        from_address=str(stored.get("from_address", "")), from_name=str(stored.get("from_name", "")),
    )


def is_available(db: Session) -> bool:
    """Mail is configured and switched on. Everything that depends on mail asks this."""
    cfg = get_mail_config(db)
    return bool(cfg.enabled and cfg.host and valid_address(cfg.from_address))


def set_mail_config(
    db: Session, *, enabled: bool, host: str, port: int, security: str, username: str,
    password: str | None, from_address: str, from_name: str,
) -> MailConfig:
    """Validates, then stores. `password=None` or "" keeps the stored password."""
    if security not in SECURITIES:
        raise MailConfigError("security must be starttls or tls")
    if not 1 <= int(port) <= 65535:
        raise MailConfigError("port must be between 1 and 65535")
    clean_host = validate_host(host) if (host or enabled) else ""
    sender = _clean_line(from_address, "sender address")
    if (sender or enabled) and not valid_address(sender):
        raise MailConfigError("the sender must be a plain e-mail address")
    stored = _row(db)
    entry = {
        "enabled": bool(enabled), "host": clean_host, "port": int(port), "security": security,
        "username": _clean_line(username, "username"), "from_address": sender,
        "from_name": _clean_line(from_name, "sender name", max_len=100),
        "password_enc": stored.get("password_enc"),
    }
    if password:
        if any(ch in password for ch in "\r\n\x00"):
            raise MailConfigError("the password must not contain a line break")
        entry["password_enc"] = _encrypt_api_key(password)
    row = db.get(AppSetting, MAIL_CONFIG_KEY)
    if row is None:
        db.add(AppSetting(key=MAIL_CONFIG_KEY, value=entry))
    else:
        row.value = entry
        row.updated_at = dt.datetime.now(dt.timezone.utc)
    db.commit()
    return get_mail_config(db)


def relay_credentials(db: Session) -> dict | None:
    """What the worker needs to send, including the decrypted password. Internal use
    only; None when mail is not available. Raises SettingsCipherUnavailable when the
    stored password cannot be read."""
    if not is_available(db):
        return None
    stored = _row(db)
    cfg = get_mail_config(db)
    password = None
    if stored.get("password_enc"):
        password = _decrypt_api_key(stored["password_enc"])
    return {
        "host": cfg.host, "port": cfg.port, "security": cfg.security, "username": cfg.username,
        "password": password, "from_address": cfg.from_address, "from_name": cfg.from_name,
    }


__all__ = [
    "MailConfig", "MailConfigError", "SettingsCipherUnavailable", "get_mail_config", "is_available",
    "relay_credentials", "set_mail_config", "valid_address", "validate_host",
]
