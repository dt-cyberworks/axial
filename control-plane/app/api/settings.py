"""Betriebs-Einstellungen fuer die Operator-Konsole (GUI).

Der OpenAI-kompatible LLM-Provider des Vector Agent (base_url/model/api_key)
und der optionale NVD-API-Key (REQ-CORR-008) fuer die Live-CVE-Korrelation.
Beide api_key-Felder werden in GET-Antworten NIE zurueckgegeben (nur
api_key_set: bool) - die GUI zeigt ein Passwortfeld, das leer bleibt, wenn der
Schluessel unveraendert bleiben soll.
"""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import config_resolver
from app.db.base import get_db
from app.settings_store import (
    MAX_AGENT_MAX_ITERATIONS,
    MAX_AGENT_MAX_TOKENS,
    MAX_APPROVAL_TIMEOUT_SECONDS,
    MIN_AGENT_MAX_ITERATIONS,
    MIN_AGENT_MAX_TOKENS,
    MIN_APPROVAL_TIMEOUT_SECONDS,
    SUBFINDER_PROVIDERS,
    SettingsCipherUnavailable,
    get_global_agent_max_iterations,
    get_global_agent_max_tokens,
    get_global_agent_prompt,
    get_global_approval_timeout_seconds,
    get_llm_config,
    get_nvd_config,
    get_scan_policy,
    set_global_agent_max_iterations,
    set_global_agent_max_tokens,
    set_global_agent_prompt,
    set_global_approval_timeout_seconds,
    set_global_tool_policy,
    set_llm_config,
    set_nvd_config,
    set_scan_policy,
    set_subfinder_keys,
    subfinder_providers_with_key,
)

router = APIRouter(prefix="/settings", tags=["settings"])


class LlmConfigOut(BaseModel):
    base_url: str
    model: str
    api_key_set: bool
    source: str  # db | env | unset
    is_usable: bool


class LlmConfigIn(BaseModel):
    base_url: str = ""
    model: str = ""
    # None/weggelassen -> gespeicherten Schluessel unveraendert lassen.
    api_key: str | None = None


class ScanPolicyOut(BaseModel):
    max_rps: float
    auto_throttle_enabled: bool
    source: str  # db | env


class ScanPolicyIn(BaseModel):
    max_rps: float = 5.0
    auto_throttle_enabled: bool = False


def _to_out(cfg) -> LlmConfigOut:
    return LlmConfigOut(
        base_url=cfg.base_url, model=cfg.model, api_key_set=bool(cfg.api_key),
        source=cfg.source, is_usable=cfg.is_usable,
    )


@router.get("/llm", response_model=LlmConfigOut)
def read_llm_config(db: Session = Depends(get_db)):
    try:
        return _to_out(get_llm_config(db))
    except SettingsCipherUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc


@router.put("/llm", response_model=LlmConfigOut)
def update_llm_config(body: LlmConfigIn, db: Session = Depends(get_db)):
    try:
        cfg = set_llm_config(db, base_url=body.base_url, model=body.model, api_key=body.api_key)
    except SettingsCipherUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    return _to_out(cfg)


class NvdConfigOut(BaseModel):
    api_key_set: bool
    source: str  # db | env | unset


class NvdConfigIn(BaseModel):
    # None/weggelassen -> gespeicherten Schluessel unveraendert lassen.
    api_key: str | None = None


@router.get("/nvd", response_model=NvdConfigOut)
def read_nvd_config(db: Session = Depends(get_db)):
    try:
        cfg = get_nvd_config(db)
    except SettingsCipherUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    return NvdConfigOut(api_key_set=bool(cfg.api_key), source=cfg.source)


@router.put("/nvd", response_model=NvdConfigOut)
def update_nvd_config(body: NvdConfigIn, db: Session = Depends(get_db)):
    try:
        cfg = set_nvd_config(db, api_key=body.api_key)
    except SettingsCipherUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    return NvdConfigOut(api_key_set=bool(cfg.api_key), source=cfg.source)


class SubfinderKeysOut(BaseModel):
    providers: list[dict]  # [{"name": str, "key_set": bool}] - the keys themselves are never returned


class SubfinderKeysIn(BaseModel):
    # provider -> key. Omitted = unchanged, "" = remove. Unknown providers are rejected.
    keys: dict[str, str | None] = Field(default_factory=dict)


def _subfinder_out(configured: list[str]) -> SubfinderKeysOut:
    return SubfinderKeysOut(providers=[{"name": n, "key_set": n in configured} for n in SUBFINDER_PROVIDERS])


@router.get("/subfinder", response_model=SubfinderKeysOut)
def read_subfinder_keys(db: Session = Depends(get_db)):
    return _subfinder_out(subfinder_providers_with_key(db))


@router.put("/subfinder", response_model=SubfinderKeysOut)
def update_subfinder_keys(body: SubfinderKeysIn, db: Session = Depends(get_db)):
    for name, value in body.keys.items():
        if name not in SUBFINDER_PROVIDERS:
            raise HTTPException(422, f"unknown subfinder provider: {name}")
        # The worker writes these into subfinder's provider file, so only plain
        # token characters are accepted (no YAML syntax, no whitespace).
        if value is not None and value.strip() and not re.fullmatch(r"[A-Za-z0-9._:-]{1,256}", value.strip()):
            raise HTTPException(422, f"invalid key format for {name}")
    try:
        configured = set_subfinder_keys(db, body.keys)
    except SettingsCipherUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    return _subfinder_out(configured)


@router.get("/scan-policy", response_model=ScanPolicyOut)
def read_scan_policy(db: Session = Depends(get_db)):
    return ScanPolicyOut(**get_scan_policy(db).__dict__)


@router.put("/scan-policy", response_model=ScanPolicyOut)
def update_scan_policy(body: ScanPolicyIn, db: Session = Depends(get_db)):
    policy = set_scan_policy(db, max_rps=body.max_rps, auto_throttle_enabled=body.auto_throttle_enabled)
    return ScanPolicyOut(**policy.__dict__)


# --- Globale Tool-Policy (Schicht 2) ---

class ToolPolicyEntry(BaseModel):
    tool: str
    category: str | None = None
    installed: bool | None = None
    enabled: bool
    requires_approval: bool = False


@router.get("/tool-policy", response_model=list[ToolPolicyEntry])
def read_tool_policy(db: Session = Depends(get_db)):
    """Effektive globale Policy je Tool (Registry-Defaults + globale Overrides)."""
    return [ToolPolicyEntry(**e) for e in config_resolver.global_tool_policy_view(db)]


@router.put("/tool-policy", response_model=list[ToolPolicyEntry])
def update_tool_policy(body: list[ToolPolicyEntry], db: Session = Depends(get_db)):
    set_global_tool_policy(
        db, {e.tool: {"enabled": e.enabled, "requires_approval": e.requires_approval} for e in body}
    )
    return [ToolPolicyEntry(**e) for e in config_resolver.global_tool_policy_view(db)]


# --- Globale Agent-Anweisung (Schicht 3) ---

class AgentPromptOut(BaseModel):
    prompt: str
    is_set: bool


class AgentPromptIn(BaseModel):
    prompt: str = ""


@router.get("/agent-prompt", response_model=AgentPromptOut)
def read_agent_prompt(db: Session = Depends(get_db)):
    p = get_global_agent_prompt(db)
    return AgentPromptOut(prompt=p, is_set=bool(p))


@router.put("/agent-prompt", response_model=AgentPromptOut)
def update_agent_prompt(body: AgentPromptIn, db: Session = Depends(get_db)):
    p = set_global_agent_prompt(db, body.prompt)
    return AgentPromptOut(prompt=p, is_set=bool(p))


# --- Globales Agent-Iterationsbudget (Schicht 3, REQ-AGENT-008) ---

class AgentMaxIterationsOut(BaseModel):
    value: int


class AgentMaxIterationsIn(BaseModel):
    value: int = Field(ge=MIN_AGENT_MAX_ITERATIONS, le=MAX_AGENT_MAX_ITERATIONS)


@router.get("/agent-max-iterations", response_model=AgentMaxIterationsOut)
def read_agent_max_iterations(db: Session = Depends(get_db)):
    return AgentMaxIterationsOut(value=get_global_agent_max_iterations(db))


@router.put("/agent-max-iterations", response_model=AgentMaxIterationsOut)
def update_agent_max_iterations(body: AgentMaxIterationsIn, db: Session = Depends(get_db)):
    try:
        value = set_global_agent_max_iterations(db, body.value)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return AgentMaxIterationsOut(value=value)


# --- Globales Agent-Token-Limit (Schicht 3, REQ-AGENT-026) ---

class AgentMaxTokensOut(BaseModel):
    value: int


class AgentMaxTokensIn(BaseModel):
    value: int = Field(ge=MIN_AGENT_MAX_TOKENS, le=MAX_AGENT_MAX_TOKENS)


@router.get("/agent-max-tokens", response_model=AgentMaxTokensOut)
def read_agent_max_tokens(db: Session = Depends(get_db)):
    return AgentMaxTokensOut(value=get_global_agent_max_tokens(db))


@router.put("/agent-max-tokens", response_model=AgentMaxTokensOut)
def update_agent_max_tokens(body: AgentMaxTokensIn, db: Session = Depends(get_db)):
    try:
        value = set_global_agent_max_tokens(db, body.value)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return AgentMaxTokensOut(value=value)


# --- Manuelle-Freigabe-Timeout (REQ-APPROVAL-005) ---

class ApprovalTimeoutSecondsOut(BaseModel):
    value: int


class ApprovalTimeoutSecondsIn(BaseModel):
    value: int = Field(ge=MIN_APPROVAL_TIMEOUT_SECONDS, le=MAX_APPROVAL_TIMEOUT_SECONDS)


@router.get("/approval-timeout-seconds", response_model=ApprovalTimeoutSecondsOut)
def read_approval_timeout_seconds(db: Session = Depends(get_db)):
    return ApprovalTimeoutSecondsOut(value=get_global_approval_timeout_seconds(db))


@router.put("/approval-timeout-seconds", response_model=ApprovalTimeoutSecondsOut)
def update_approval_timeout_seconds(body: ApprovalTimeoutSecondsIn, db: Session = Depends(get_db)):
    try:
        value = set_global_approval_timeout_seconds(db, body.value)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return ApprovalTimeoutSecondsOut(value=value)
