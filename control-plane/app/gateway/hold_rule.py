"""The hold rule of the Scope Gateway (REQ-MODE-008, GitHub #79; the withheld rule "G3").

A monitoring engagement can hold a newly found host: it is listed and inventoried, and nothing is sent to it until
the owner releases it. The scan pipeline already left held hosts out; the Vector Agent did not, and the gateway had no
rule for it, so five requests reached a held host. This is the gateway's own net: an active call whose target is a
held host of the call's engagement is denied `asset_held_for_review` before any approval is created or claimed, so an
approval can never override it (deny beats allow) and a held host can never produce an approval request.

It only narrows. It reads one row set (the engagement's held hosts), writes nothing and cannot allow anything.
"""

from __future__ import annotations

import re
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.asset import DiscoveredAsset

_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://")


def normalize_host(target: str) -> str:
    """The host a target string names: lower case, without scheme, userinfo, port, path, query or a trailing dot.
    `HTTPS://Dev.Example.Test.:8443/login?x=1`, `dev.example.test:8443` and `dev.example.test` are one host."""
    host = _SCHEME.sub("", (target or "").strip().lower())
    host = re.split(r"[/?#]", host, maxsplit=1)[0].rsplit("@", 1)[-1]
    if host.startswith("["):  # [v6]:port
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:  # host:port; a bare IPv6 literal has several colons and is left alone
        host = host.split(":", 1)[0]
    return host.rstrip(".")


def is_held_host(db: Session, engagement_id: uuid.UUID, target: str) -> bool:
    """Whether `target` is a host of this engagement that the hold policy is holding. Another engagement's host of
    the same name does not count."""
    key = normalize_host(target)
    if not key:
        return False
    return db.scalar(
        select(DiscoveredAsset.id).where(
            DiscoveredAsset.engagement_id == engagement_id,
            DiscoveredAsset.hold_state == "held",
            func.lower(DiscoveredAsset.value).in_((key, key + ".")),
        ).limit(1)
    ) is not None
