"""Laufzeit-Einstellungen: DB (app_setting) ueberschreibt Env-Defaults.

Verbraucher: Vector/Lens-Agent-LLM-Provider (OpenAI-kompatibel) und globale Scan-Policy.
Aufloesungsreihenfolge pro Feld: app_setting['llm_config'] -> Settings (Env) ->
"". So kann der Operator den Provider zur Laufzeit ueber die GUI setzen, ohne
Neudeploy; ohne DB-Eintrag gelten die Env-Defaults (config files).
"""

from __future__ import annotations

import dataclasses
import datetime as dt

from sqlalchemy.orm import Session

from app.config import get_settings
from app.crypto import InvalidToken, build_cipher, decrypt as _crypto_decrypt, encrypt as _crypto_encrypt
from app.default_prompts import DEFAULT_AGENT_PROMPT
from app.models.app_setting import AppSetting

LLM_CONFIG_KEY = "llm_config"
NVD_CONFIG_KEY = "nvd_config"
SUBFINDER_CONFIG_KEY = "subfinder_config"  # REQ-COVER-001: {"keys_enc": {provider: ciphertext}}
# Key-only passive sources subfinder can use. The allowlist is also what stops
# a caller from writing arbitrary provider-config lines (REQ-COVER-001).
SUBFINDER_PROVIDERS = (
    "virustotal", "securitytrails", "shodan", "chaos", "fullhunt", "binaryedge", "bevigil", "c99", "github",
)
SCAN_POLICY_KEY = "scan_policy"
TOOL_POLICY_KEY = "tool_policy"      # global: {tool: {enabled: bool, requires_approval: bool}}
AGENT_PROMPT_KEY = "agent_prompt"    # global: {prompt: str}
AGENT_MAX_ITERATIONS_KEY = "agent_max_iterations"  # global: {value: int}
DEFAULT_AGENT_MAX_ITERATIONS = 50
MIN_AGENT_MAX_ITERATIONS = 1
MAX_AGENT_MAX_ITERATIONS = 500

# REQ-AGENT-026: caps a single completion's OUTPUT (reasoning + the tool-call
# JSON itself), not the context window. Truncating mid-JSON breaks the tool
# call outright, so the default is deliberately generous; the 1024-32768 clamp
# matches the range the worker env var already enforced.
AGENT_MAX_TOKENS_KEY = "agent_max_tokens"  # global: {value: int}
DEFAULT_AGENT_MAX_TOKENS = 8192
MIN_AGENT_MAX_TOKENS = 1024
MAX_AGENT_MAX_TOKENS = 32768

# REQ-APPROVAL-005: configurable manual-approval timeout. Default (900s = 15m)
# matches the previously-hardcoded literal in gateway/authorize.py, so an
# unconfigured deployment behaves exactly as before.
APPROVAL_TIMEOUT_SECONDS_KEY = "approval_timeout_seconds"  # global: {value: int}
DEFAULT_APPROVAL_TIMEOUT_SECONDS = 900
MIN_APPROVAL_TIMEOUT_SECONDS = 60
MAX_APPROVAL_TIMEOUT_SECONDS = 86400


class SettingsCipherUnavailable(RuntimeError):
    """GitHub issue #25: raised - and deliberately never swallowed into an
    empty/default value - when a stored provider API key cannot be
    encrypted or decrypted: SETTINGS_ENCRYPTION_KEY is missing/malformed, or
    (for a decrypt) no configured key (current or rotated-out "previous")
    can open the stored ciphertext. Either case is an operator-visible
    misconfiguration, not "no key configured"."""


def _api_key_cipher():
    settings = get_settings()
    if not settings.settings_encryption_key:
        raise SettingsCipherUnavailable(
            "SETTINGS_ENCRYPTION_KEY is not configured - cannot store or read an "
            "encrypted provider API key"
        )
    previous = [k for k in settings.settings_encryption_key_previous.split(",") if k.strip()]
    try:
        return build_cipher(settings.settings_encryption_key, previous)
    except ValueError as exc:
        raise SettingsCipherUnavailable(f"SETTINGS_ENCRYPTION_KEY is malformed: {exc}") from exc


def _encrypt_api_key(plaintext: str) -> str:
    return _crypto_encrypt(_api_key_cipher(), plaintext)


def _decrypt_api_key(ciphertext: str) -> str:
    try:
        return _crypto_decrypt(_api_key_cipher(), ciphertext)
    except InvalidToken as exc:
        raise SettingsCipherUnavailable(
            "a stored provider API key could not be decrypted with the configured "
            "SETTINGS_ENCRYPTION_KEY (or any SETTINGS_ENCRYPTION_KEY_PREVIOUS) - it "
            "may have been rotated incorrectly, or the key was lost"
        ) from exc


def _migrate_legacy_plaintext_api_key(db: Session, row: AppSetting, plaintext: str) -> None:
    """Lazily migrates a pre-#25 plaintext 'api_key' field to encrypted
    'api_key_enc' on first read after this fix is deployed - the acceptance
    criterion is that existing plaintext values get migrated, not that an
    operator has to re-enter them. Best-effort: if encryption is not
    currently available (e.g. SETTINGS_ENCRYPTION_KEY not set yet), leave
    the legacy plaintext in place rather than losing the value - the next
    read retries the migration."""
    try:
        ciphertext = _encrypt_api_key(plaintext)
    except SettingsCipherUnavailable:
        return
    new_value = dict(row.value)
    new_value.pop("api_key", None)
    new_value["api_key_enc"] = ciphertext
    row.value = new_value
    row.updated_at = dt.datetime.now(dt.timezone.utc)
    db.commit()


@dataclasses.dataclass
class LlmConfig:
    base_url: str
    model: str
    api_key: str
    source: str  # "db" | "env" | "unset" - woher die aktiven Werte stammen

    @property
    def is_usable(self) -> bool:
        return bool(self.base_url and self.api_key and self.model)


@dataclasses.dataclass
class NvdConfig:
    api_key: str  # "" = unset - an unset key is a fully supported state (REQ-CORR-008)
    source: str   # "db" | "env" | "unset"


@dataclasses.dataclass
class ScanPolicy:
    max_rps: float
    auto_throttle_enabled: bool
    source: str  # "db" | "env"


def get_scan_policy(db: Session) -> ScanPolicy:
    settings = get_settings()
    row = db.get(AppSetting, SCAN_POLICY_KEY)
    stored = row.value if row and isinstance(row.value, dict) else {}

    try:
        max_rps = float(stored.get("max_rps", settings.default_max_rps))
    except (TypeError, ValueError):
        max_rps = settings.default_max_rps
    max_rps = max(0.1, min(max_rps, 100.0))
    auto_throttle_enabled = bool(stored.get("auto_throttle_enabled", False))
    return ScanPolicy(
        max_rps=max_rps,
        auto_throttle_enabled=auto_throttle_enabled,
        source="db" if row else "env",
    )


def set_scan_policy(db: Session, *, max_rps: float, auto_throttle_enabled: bool) -> ScanPolicy:
    max_rps = max(0.1, min(float(max_rps), 100.0))
    payload = {"max_rps": max_rps, "auto_throttle_enabled": bool(auto_throttle_enabled)}
    row = db.get(AppSetting, SCAN_POLICY_KEY)
    if row is None:
        row = AppSetting(key=SCAN_POLICY_KEY, value=payload)
        db.add(row)
    else:
        row.value = payload
        row.updated_at = dt.datetime.now(dt.timezone.utc)
    db.commit()
    return get_scan_policy(db)


def _put_setting(db: Session, key: str, value: dict) -> None:
    row = db.get(AppSetting, key)
    if row is None:
        db.add(AppSetting(key=key, value=value))
    else:
        row.value = value
        row.updated_at = dt.datetime.now(dt.timezone.utc)
    db.commit()


def get_global_tool_policy(db: Session) -> dict[str, dict]:
    """Globale per-Tool-Defaults (Schicht 2). Rohes Dict {tool: {enabled,
    requires_approval}}; fehlende Tools/Felder erbt der Resolver von der
    Registry (Schicht 1)."""
    row = db.get(AppSetting, TOOL_POLICY_KEY)
    return dict(row.value) if row and isinstance(row.value, dict) else {}


def set_global_tool_policy(db: Session, policy: dict[str, dict]) -> dict[str, dict]:
    clean: dict[str, dict] = {}
    for tool, cfg in (policy or {}).items():
        if not isinstance(cfg, dict):
            continue
        entry: dict = {}
        if "enabled" in cfg:
            entry["enabled"] = bool(cfg["enabled"])
        if "requires_approval" in cfg:
            entry["requires_approval"] = bool(cfg["requires_approval"])
        clean[str(tool)] = entry
    _put_setting(db, TOOL_POLICY_KEY, clean)
    return get_global_tool_policy(db)


def get_global_agent_prompt(db: Session) -> str:
    """Effektiver globaler Prompt (Schicht 3): ein gespeichertes Override, sonst
    der eingebaute Default (REQ-AGENT-011) - NIE ein leerer String, damit die
    Settings-GUI immer den tatsaechlich laufenden Prompt zeigt und editierbar
    macht, statt eine leere Box, aus der man den echten Text nicht erraten kann."""
    row = db.get(AppSetting, AGENT_PROMPT_KEY)
    if row and isinstance(row.value, dict):
        stored = str(row.value.get("prompt") or "")
        if stored.strip():
            return stored
    return DEFAULT_AGENT_PROMPT


def set_global_agent_prompt(db: Session, prompt: str) -> str:
    _put_setting(db, AGENT_PROMPT_KEY, {"prompt": str(prompt or "").strip()})
    return get_global_agent_prompt(db)


def get_global_agent_max_iterations(db: Session) -> int:
    """Globaler Default (Schicht 3) fuer das Agent-Iterationsbudget
    (REQ-AGENT-008). Ungesetzt/ungueltig -> eingebauter Default (50)."""
    row = db.get(AppSetting, AGENT_MAX_ITERATIONS_KEY)
    if row and isinstance(row.value, dict):
        try:
            value = int(row.value.get("value"))
        except (TypeError, ValueError):
            return DEFAULT_AGENT_MAX_ITERATIONS
        if MIN_AGENT_MAX_ITERATIONS <= value <= MAX_AGENT_MAX_ITERATIONS:
            return value
    return DEFAULT_AGENT_MAX_ITERATIONS


def set_global_agent_max_iterations(db: Session, value: int) -> int:
    if not MIN_AGENT_MAX_ITERATIONS <= value <= MAX_AGENT_MAX_ITERATIONS:
        raise ValueError(
            f"agent_max_iterations must be between {MIN_AGENT_MAX_ITERATIONS} and {MAX_AGENT_MAX_ITERATIONS}"
        )
    _put_setting(db, AGENT_MAX_ITERATIONS_KEY, {"value": int(value)})
    return get_global_agent_max_iterations(db)


def get_global_agent_max_tokens(db: Session) -> int:
    """Globaler Default (Schicht 3) fuer das Completion-Token-Limit des Agenten
    (REQ-AGENT-026). Ungesetzt/ungueltig -> eingebauter Default (8192)."""
    row = db.get(AppSetting, AGENT_MAX_TOKENS_KEY)
    if row and isinstance(row.value, dict):
        try:
            value = int(row.value.get("value"))
        except (TypeError, ValueError):
            return DEFAULT_AGENT_MAX_TOKENS
        if MIN_AGENT_MAX_TOKENS <= value <= MAX_AGENT_MAX_TOKENS:
            return value
    return DEFAULT_AGENT_MAX_TOKENS


def set_global_agent_max_tokens(db: Session, value: int) -> int:
    if not MIN_AGENT_MAX_TOKENS <= value <= MAX_AGENT_MAX_TOKENS:
        raise ValueError(
            f"agent_max_tokens must be between {MIN_AGENT_MAX_TOKENS} and {MAX_AGENT_MAX_TOKENS}"
        )
    _put_setting(db, AGENT_MAX_TOKENS_KEY, {"value": int(value)})
    return get_global_agent_max_tokens(db)


def get_global_approval_timeout_seconds(db: Session) -> int:
    """Globaler Default (REQ-APPROVAL-005) fuer die Freigabe-Ablauffrist.
    Ungesetzt/ungueltig -> eingebauter Default (900s = 15min)."""
    row = db.get(AppSetting, APPROVAL_TIMEOUT_SECONDS_KEY)
    if row and isinstance(row.value, dict):
        try:
            value = int(row.value.get("value"))
        except (TypeError, ValueError):
            return DEFAULT_APPROVAL_TIMEOUT_SECONDS
        if MIN_APPROVAL_TIMEOUT_SECONDS <= value <= MAX_APPROVAL_TIMEOUT_SECONDS:
            return value
    return DEFAULT_APPROVAL_TIMEOUT_SECONDS


def set_global_approval_timeout_seconds(db: Session, value: int) -> int:
    if not MIN_APPROVAL_TIMEOUT_SECONDS <= value <= MAX_APPROVAL_TIMEOUT_SECONDS:
        raise ValueError(
            f"approval_timeout_seconds must be between {MIN_APPROVAL_TIMEOUT_SECONDS} and {MAX_APPROVAL_TIMEOUT_SECONDS}"
        )
    _put_setting(db, APPROVAL_TIMEOUT_SECONDS_KEY, {"value": int(value)})
    return get_global_approval_timeout_seconds(db)


def _read_stored_api_key(db: Session, row: AppSetting | None, stored: dict) -> tuple[str, bool]:
    """Returns (api_key, was_stored_in_db). GitHub issue #25: 'api_key_enc' is
    the current (encrypted) field; a bare legacy 'api_key' means a plaintext
    value written before this fix, which is used as-is for this read AND
    lazily migrated to 'api_key_enc' so it stops being plaintext-at-rest."""
    enc = stored.get("api_key_enc")
    if enc:
        return _decrypt_api_key(str(enc)), True
    legacy_plain = str(stored.get("api_key") or "").strip()
    if legacy_plain and row is not None:
        _migrate_legacy_plaintext_api_key(db, row, legacy_plain)
        return legacy_plain, True
    return "", False


def get_llm_config(db: Session) -> LlmConfig:
    settings = get_settings()
    row = db.get(AppSetting, LLM_CONFIG_KEY)
    stored = row.value if row and isinstance(row.value, dict) else {}

    def pick(field: str, env_default: str) -> tuple[str, bool]:
        val = str(stored.get(field) or "").strip()
        if val:
            return val, True
        return env_default, False

    base_url, b_db = pick("base_url", settings.llm_base_url)
    model, m_db = pick("model", settings.llm_model)
    api_key, k_db = _read_stored_api_key(db, row, stored)
    if not k_db:
        api_key = settings.llm_api_key

    from_db = b_db or m_db or k_db
    any_set = bool(base_url or model or api_key)
    source = "db" if from_db else ("env" if any_set else "unset")
    return LlmConfig(base_url=base_url, model=model, api_key=api_key, source=source)


def set_llm_config(db: Session, *, base_url: str, model: str, api_key: str | None) -> LlmConfig:
    """Persistiert die vom Operator gesetzten Werte. api_key=None laesst einen
    bereits gespeicherten Schluessel unveraendert (die GUI sendet ihn nicht
    zurueck, wenn er nicht geaendert wird). GitHub issue #25: a non-empty
    api_key is encrypted before it ever reaches the JSONB column; raises
    SettingsCipherUnavailable (fails loud) if no usable encryption key is
    configured, rather than silently falling back to storing plaintext."""
    row = db.get(AppSetting, LLM_CONFIG_KEY)
    current = dict(row.value) if row and isinstance(row.value, dict) else {}

    current["base_url"] = base_url.strip()
    current["model"] = model.strip()
    if api_key is not None:
        stripped = api_key.strip()
        current.pop("api_key", None)  # drop any not-yet-migrated legacy plaintext remnant
        if stripped:
            current["api_key_enc"] = _encrypt_api_key(stripped)
        else:
            current.pop("api_key_enc", None)

    if row is None:
        row = AppSetting(key=LLM_CONFIG_KEY, value=current)
        db.add(row)
    else:
        row.value = current
        row.updated_at = dt.datetime.now(dt.timezone.utc)
    db.commit()
    return get_llm_config(db)


def get_nvd_config(db: Session) -> NvdConfig:
    """REQ-CORR-008: resolution order db -> env -> unset. Unset is valid - the
    worker paces to NVD's public unauthenticated rate limit when no key is
    configured."""
    row = db.get(AppSetting, NVD_CONFIG_KEY)
    stored = row.value if row and isinstance(row.value, dict) else {}

    api_key, from_db = _read_stored_api_key(db, row, stored)
    if not api_key:
        api_key = get_settings().nvd_api_key
    source = "db" if from_db else ("env" if api_key else "unset")
    return NvdConfig(api_key=api_key, source=source)


def set_nvd_config(db: Session, *, api_key: str | None) -> NvdConfig:
    """api_key=None leaves an already-stored key unchanged (mirrors
    set_llm_config, including the encrypt-before-store behaviour)."""
    row = db.get(AppSetting, NVD_CONFIG_KEY)
    current = dict(row.value) if row and isinstance(row.value, dict) else {}
    if api_key is not None:
        stripped = api_key.strip()
        current.pop("api_key", None)
        if stripped:
            current["api_key_enc"] = _encrypt_api_key(stripped)
        else:
            current.pop("api_key_enc", None)

    if row is None:
        row = AppSetting(key=NVD_CONFIG_KEY, value=current)
        db.add(row)
    else:
        row.value = current
        row.updated_at = dt.datetime.now(dt.timezone.utc)
    db.commit()
    return get_nvd_config(db)


def get_subfinder_keys(db: Session) -> dict[str, str]:
    """REQ-COVER-001: decrypted provider keys for the worker. Never returned
    by any public endpoint; unset is the normal state (free sources only)."""
    row = db.get(AppSetting, SUBFINDER_CONFIG_KEY)
    stored = row.value.get("keys_enc") if row and isinstance(row.value, dict) else None
    if not isinstance(stored, dict):
        return {}
    return {
        name: _decrypt_api_key(token)
        for name, token in stored.items()
        if name in SUBFINDER_PROVIDERS and isinstance(token, str) and token
    }


def set_subfinder_keys(db: Session, updates: dict[str, str | None]) -> list[str]:
    """Per provider: None leaves the stored key unchanged, "" removes it, any
    other value replaces it (encrypted before storage). Returns the names that
    have a key afterwards."""
    row = db.get(AppSetting, SUBFINDER_CONFIG_KEY)
    current = dict(row.value) if row and isinstance(row.value, dict) else {}
    enc = dict(current.get("keys_enc") or {})
    for name, value in updates.items():
        if name not in SUBFINDER_PROVIDERS:
            raise ValueError(f"unknown subfinder provider: {name}")
        if value is None:
            continue
        stripped = value.strip()
        if stripped:
            enc[name] = _encrypt_api_key(stripped)
        else:
            enc.pop(name, None)
    current["keys_enc"] = enc
    if row is None:
        db.add(AppSetting(key=SUBFINDER_CONFIG_KEY, value=current))
    else:
        row.value = current
        row.updated_at = dt.datetime.now(dt.timezone.utc)
    db.commit()
    return sorted(enc)


def subfinder_providers_with_key(db: Session) -> list[str]:
    row = db.get(AppSetting, SUBFINDER_CONFIG_KEY)
    stored = row.value.get("keys_enc") if row and isinstance(row.value, dict) else None
    return sorted(n for n in (stored or {}) if n in SUBFINDER_PROVIDERS)
