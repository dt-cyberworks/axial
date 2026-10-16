"""Capabilities of a monitoring engagement (REQ-MODE-006).

A capability is a named function of the scanner that an engagement switches on or
off once, for every run. It is *one view over settings that already exist*: tool
grants, per-tool campaign overrides, the discovery switches and the agent switch
stay the source of truth, so the Scope Gateway reads exactly what it always read
and a change applies from the next call of any run, scheduled or manual.

Nothing here can grant more than the gateway allows: enabling a capability only
removes a campaign "off" override, turns a switch on and makes sure the active
tool grant of the category exists, without per-call approval. Disabling only
narrows. `cred` and `exploit` are not capabilities and cannot be enabled here.
"""

from __future__ import annotations

import dataclasses
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import config_resolver
from app.models.engagement import Engagement, ToolApprovalPolicy, ToolGrant
from app.tools import registry


@dataclasses.dataclass(frozen=True)
class Capability:
    id: str
    label: str
    description: str
    # Tools this capability switches (campaign override), and the grant they run under.
    tools: tuple[str, ...] = ()
    category: str | None = None
    mode: str | None = None
    # Engagement boolean column this capability sets, when it has one.
    switch: str | None = None
    # Tools that must be enabled for it to work, which it does not switch itself.
    requires_tools: tuple[str, ...] = ()
    agent: bool = False


CAPABILITIES: tuple[Capability, ...] = (
    Capability(
        "public_discovery", "Public-source discovery",
        "Certificate logs, DNS and passive subdomain sources. Nothing is sent to your systems.",
        tools=("subfinder",), category="recon", mode="passive", switch="subfinder_enabled",
    ),
    Capability(
        "port_service_scan", "Port and service scan",
        "TCP port scan and service detection inside the engagement's port envelope.",
        tools=("nmap",), category="fingerprint", mode="active",
    ),
    Capability(
        "web_fingerprint", "Web fingerprint, TLS and security headers",
        "Which web server and technology runs, its TLS setup and its security headers.",
        tools=("httpx", "wafw00f", "testssl"), category="fingerprint", mode="active",
    ),
    Capability(
        "vulnerability_templates", "Vulnerability templates",
        "Template-based checks for known weaknesses in the services that were found.",
        tools=("nuclei", "nikto"), category="vuln", mode="active",
    ),
    Capability(
        "content_discovery", "Content discovery",
        "Looks for exposed files and paths on web services.",
        tools=("ffuf",), category="vuln", mode="active",
    ),
    Capability(
        "crawling", "Crawling and URL history",
        "Follows links and reads web archives to find endpoints.",
        tools=("katana",), category="fingerprint", mode="active", switch="crawling_enabled",
    ),
    Capability(
        "screenshots", "Web screenshots",
        "One screenshot per web page, for review.",
        tools=("screenshot",), category="fingerprint", mode="active", switch="screenshots_enabled",
    ),
    Capability(
        "out_of_band", "Out-of-band interaction testing",
        "Detects blind weaknesses through a callback server.",
        switch="oob_enabled", requires_tools=("nuclei",),
    ),
    Capability(
        "agent", "Vector Agent",
        "An AI model proposes further checks. Every proposal goes through the Scope Gateway; "
        "nothing that needs a person's decision runs in a monitoring engagement.",
        agent=True,
    ),
)
BY_ID = {c.id: c for c in CAPABILITIES}


class CapabilityError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _tool_enabled(db: Session, engagement_id: uuid.UUID, tool: str) -> bool:
    return config_resolver.effective_tool_config(db, engagement_id, tool).enabled


def _unavailable_reason(cap: Capability) -> str | None:
    missing = [t for t in (*cap.tools, *cap.requires_tools) if (registry.get(t) is None or not registry.get(t).installed)]
    if cap.tools and len(missing) == len(cap.tools):
        return "not installed in this deployment"
    return None


def _has_grant(db: Session, engagement_id: uuid.UUID, cap: Capability) -> bool:
    if cap.category is None:
        return True
    return db.get(ToolGrant, {"engagement_id": engagement_id, "tool_category": cap.category, "mode": cap.mode}) is not None


def is_enabled(db: Session, eng: Engagement, cap: Capability) -> bool:
    if cap.agent:
        return bool(eng.ai_testing_allowed)
    if cap.switch is not None and not bool(getattr(eng, cap.switch)):
        return False
    if cap.tools and not all(
        _tool_enabled(db, eng.id, t) for t in cap.tools if registry.get(t) is not None and registry.get(t).installed
    ):
        return False
    if cap.requires_tools and not all(_tool_enabled(db, eng.id, t) for t in cap.requires_tools):
        return False
    if cap.tools and not _has_grant(db, eng.id, cap):
        return False
    return not (cap.tools and _unavailable_reason(cap))


def view(db: Session, eng: Engagement) -> list[dict]:
    out = []
    for cap in CAPABILITIES:
        out.append({
            "id": cap.id, "label": cap.label, "description": cap.description,
            "enabled": is_enabled(db, eng, cap), "unavailable_reason": _unavailable_reason(cap),
        })
    return out


def _clear_off_override(db: Session, engagement_id: uuid.UUID, tool: str) -> None:
    row = db.get(ToolApprovalPolicy, {"engagement_id": engagement_id, "tool_name": tool})
    if row is None or row.enabled is not False:
        return
    row.enabled = None
    if not row.requires_manual_approval:
        db.delete(row)


def _set_off_override(db: Session, engagement_id: uuid.UUID, tool: str) -> None:
    row = db.get(ToolApprovalPolicy, {"engagement_id": engagement_id, "tool_name": tool})
    if row is None:
        db.add(ToolApprovalPolicy(engagement_id=engagement_id, tool_name=tool, requires_manual_approval=False, enabled=False))
        db.flush()
    else:
        row.enabled = False


def _enable(db: Session, eng: Engagement, cap: Capability) -> None:
    if cap.agent:
        eng.ai_testing_allowed = True
        return
    if cap.switch is not None:
        setattr(eng, cap.switch, True)
    for tool in cap.tools:
        _clear_off_override(db, eng.id, tool)
    if cap.tools and cap.category is not None:
        # Without per-call approval: a monitoring run has nobody to decide.
        existing = db.get(ToolGrant, {"engagement_id": eng.id, "tool_category": cap.category, "mode": cap.mode})
        if existing is None:
            db.add(ToolGrant(
                engagement_id=eng.id, tool_category=cap.category, mode=cap.mode, requires_manual_approval=False,
            ))
            db.flush()  # sessions here do not autoflush: the next capability of this category must see it
    for tool in cap.requires_tools:
        _clear_off_override(db, eng.id, tool)


def _disable(db: Session, eng: Engagement, cap: Capability) -> None:
    if cap.agent:
        eng.ai_testing_allowed = False
        return
    if cap.switch is not None:
        setattr(eng, cap.switch, False)
    for tool in cap.tools:
        _set_off_override(db, eng.id, tool)


def apply(db: Session, eng: Engagement, changes: dict[str, bool]) -> dict:
    """Apply capability changes; returns {id: {"from": bool, "to": bool}} for the ones
    that actually changed. Raises CapabilityError for an unknown id or one that
    cannot be on here. The caller commits and audits."""
    unknown = sorted(set(changes) - set(BY_ID))
    if unknown:
        raise CapabilityError(422, f"unknown capability: {', '.join(unknown)}")
    applied: dict[str, dict] = {}
    for cap_id, wanted in changes.items():
        cap = BY_ID[cap_id]
        before = is_enabled(db, eng, cap)
        if wanted and not before:
            reason = _unavailable_reason(cap)
            if reason:
                raise CapabilityError(409, f"{cap.label} cannot be enabled: {reason}")
            _enable(db, eng, cap)
        elif not wanted and before:
            _disable(db, eng, cap)
        else:
            continue
        db.flush()
        applied[cap_id] = {"from": before, "to": is_enabled(db, eng, cap)}
    return applied


def widens(db: Session, eng: Engagement, changes: dict[str, bool]) -> bool:
    """True when a change turns a capability on that is off now."""
    return any(
        wanted and cap_id in BY_ID and not is_enabled(db, eng, BY_ID[cap_id])
        for cap_id, wanted in changes.items()
    )


def apply_defaults(db: Session, eng: Engagement, defaults: dict) -> None:
    """REQ-MODE-006: a new monitoring engagement starts with the installation's
    defaults, copied now. Nothing is inherited later."""
    for cap in CAPABILITIES:
        wanted = bool(defaults.get("capabilities", {}).get(cap.id, False))
        if wanted:
            if not _unavailable_reason(cap):
                _enable(db, eng, cap)
        else:
            _disable(db, eng, cap)
    db.flush()


def existing_active_grants(db: Session, engagement_id: uuid.UUID) -> list[tuple[str, str]]:
    return [
        (g.tool_category, g.mode)
        for g in db.scalars(select(ToolGrant).where(ToolGrant.engagement_id == engagement_id))
    ]
