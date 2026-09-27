"""Effektive Konfiguration aus den Schichten aufloesen.

    Registry-Boden (Code)  ->  globale Policy (app_setting)  ->  Kampagnen-Override

Der Boden ist unverhandelbar: ein Tool, das nicht installiert ist, kann nie
aktiviert werden; die arg-safety/der envelope/Scope bleiben im Gateway
erzwungen, egal was hier konfiguriert ist. Konfiguration tunt NUR *innerhalb*
des Bodens (welche Tools, welche Autonomie, welche Anweisung).

Die aufgeloeste Config ist deterministisch und damit auditierbar: ein Report
kann zeigen, mit welchen effektiven Einstellungen eine Kampagne lief.
"""

from __future__ import annotations

import dataclasses
import uuid

from sqlalchemy.orm import Session

from app.models.engagement import Engagement, ToolApprovalPolicy
from app.settings_store import (
    get_global_agent_max_iterations,
    get_global_agent_max_tokens,
    get_global_agent_prompt,
    get_global_approval_timeout_seconds,
    get_global_tool_policy,
)
from app.tools import registry


@dataclasses.dataclass(frozen=True)
class ToolConfig:
    tool: str
    enabled: bool
    requires_approval: bool
    # Herkunft je Feld (fuer GUI/Audit): "registry" | "global" | "campaign"
    enabled_source: str
    approval_source: str


def effective_tool_config(db: Session, engagement_id: uuid.UUID, tool: str) -> ToolConfig:
    spec = registry.get(tool)
    # Boden: unbekannt/nicht installiert -> hart aus, Freigabe erzwungen.
    if spec is None or not spec.installed:
        return ToolConfig(tool, enabled=False, requires_approval=True,
                          enabled_source="registry", approval_source="registry")

    enabled = spec.default_enabled
    enabled_source = "registry"
    requires_approval = False
    approval_source = "registry"

    # Schicht 2: globale Policy
    g = get_global_tool_policy(db).get(tool, {})
    if isinstance(g, dict):
        if "enabled" in g:
            enabled = bool(g["enabled"])
            enabled_source = "global"
        if g.get("requires_approval"):
            requires_approval = True
            approval_source = "global"

    # Schicht 4: Kampagnen-Override
    pol = db.get(ToolApprovalPolicy, {"engagement_id": engagement_id, "tool_name": tool})
    if pol is not None:
        if pol.enabled is not None:
            enabled = bool(pol.enabled)
            enabled_source = "campaign"
        if pol.requires_manual_approval:
            requires_approval = True
            approval_source = "campaign"

    # Boden erneut anwenden: nie ueber "installiert" hinaus aktivierbar.
    enabled = enabled and spec.installed
    return ToolConfig(tool, enabled=enabled, requires_approval=requires_approval,
                      enabled_source=enabled_source, approval_source=approval_source)


def effective_tool_policy(db: Session, engagement_id: uuid.UUID) -> list[ToolConfig]:
    """Effektive Config fuer ALLE Registry-Tools (fuer GUI/Audit + enabled_tools)."""
    return [effective_tool_config(db, engagement_id, name) for name in sorted(registry.REGISTRY)]


def enabled_tools(db: Session, engagement_id: uuid.UUID) -> list[str]:
    """Tools, die dem Vector Agent als verfuegbar gemeldet werden (REQ-TOOL-004):
    enabled UND vom Worker dispatch-faehig. Ein Tool anzubieten, das der Worker
    nicht ausfuehren kann (z. B. whatweb/sslscan/subfinder/amass/default-cred-
    check), verschwendet nur Agent-Zuege ('unbekanntes Tool')."""
    dispatchable = registry.agent_dispatchable()
    return [c.tool for c in effective_tool_policy(db, engagement_id) if c.enabled and c.tool in dispatchable]


def global_tool_policy_view(db: Session) -> list[dict]:
    """Effektive GLOBALE Policy je Tool (Registry ueberlagert von app_setting),
    ohne Kampagnen-Schicht - fuer die globale Settings-GUI."""
    glob = get_global_tool_policy(db)
    out: list[dict] = []
    for name in sorted(registry.REGISTRY):
        spec = registry.REGISTRY[name]
        g = glob.get(name, {}) if isinstance(glob.get(name), dict) else {}
        enabled = bool(g["enabled"]) if "enabled" in g else spec.default_enabled
        enabled = enabled and spec.installed
        out.append({
            "tool": name,
            "category": spec.category,
            "installed": spec.installed,
            "enabled": enabled,
            "requires_approval": bool(g.get("requires_approval", False)),
        })
    return out


def effective_agent_prompt(db: Session, engagement_id: uuid.UUID) -> str:
    """Kampagne (Schicht 5) -> global (Schicht 3) -> "" (Worker nutzt dann den
    eingebauten Prompt). Leerstrings zaehlen als 'nicht gesetzt'."""
    eng = db.get(Engagement, engagement_id)
    if eng is not None and (eng.agent_prompt_override or "").strip():
        return eng.agent_prompt_override.strip()
    return get_global_agent_prompt(db)


def effective_agent_max_iterations(db: Session, engagement_id: uuid.UUID) -> int:
    """Kampagne (Schicht 5) -> global (Schicht 3) -> eingebauter Default (50)
    (REQ-AGENT-008)."""
    eng = db.get(Engagement, engagement_id)
    if eng is not None and eng.agent_max_iterations_override is not None:
        return eng.agent_max_iterations_override
    return get_global_agent_max_iterations(db)


def effective_agent_max_tokens(db: Session, engagement_id: uuid.UUID) -> int:
    """Kampagne (Schicht 5) -> global (Schicht 3) -> eingebauter Default (8192)
    (REQ-AGENT-026)."""
    eng = db.get(Engagement, engagement_id)
    if eng is not None and eng.agent_max_tokens_override is not None:
        return eng.agent_max_tokens_override
    return get_global_agent_max_tokens(db)


def effective_approval_timeout_seconds(db: Session, engagement_id: uuid.UUID) -> int:
    """Kampagne (Schicht 5) -> global (Schicht 3) -> eingebauter Default (900s)
    (REQ-APPROVAL-005)."""
    eng = db.get(Engagement, engagement_id)
    if eng is not None and eng.approval_timeout_seconds_override is not None:
        return eng.approval_timeout_seconds_override
    return get_global_approval_timeout_seconds(db)
