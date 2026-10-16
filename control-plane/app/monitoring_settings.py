"""Monitoring defaults and limits (REQ-MODE-006, REQ-MON-001).

What a NEW monitoring engagement starts with. The values are *copied* into the
engagement when it is created, never inherited live: a change here must not
silently widen an engagement whose authorization a customer already signed. This
is the deliberate difference from the live "Inherit global" of the tool policy.

Kept apart from settings_store.py, which holds the provider secrets.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy.orm import Session

from app.models.app_setting import AppSetting

MONITORING_DEFAULTS_KEY = "monitoring_defaults"
MAX_CONCURRENT_MONITORING_KEY = "max_concurrent_monitoring_runs"
DEFAULT_MAX_CONCURRENT_MONITORING = 1
MIN_MAX_CONCURRENT_MONITORING = 1
MAX_MAX_CONCURRENT_MONITORING = 4

SCAN_PROFILES = ("passive", "light", "standard", "thorough")
CAPABILITY_IDS = (
    "public_discovery", "port_service_scan", "web_fingerprint", "vulnerability_templates",
    "content_discovery", "crawling", "screenshots", "out_of_band", "agent",
)
DEFAULT_MONITORING_DEFAULTS: dict = {
    "capabilities": {
        "public_discovery": True, "port_service_scan": True, "web_fingerprint": True,
        "vulnerability_templates": True, "content_discovery": True, "crawling": False,
        "screenshots": False, "out_of_band": False, "agent": False,
    },
    "scan_profile": "standard",
    # `hold` for customer engagements (the unattended form of the asset review),
    # `auto` otherwise.
    "new_asset_policy_customer": "hold",
    "new_asset_policy_other": "auto",
    "fragility_breaker": True,
}


def _put(db: Session, key: str, value: dict) -> None:
    row = db.get(AppSetting, key)
    if row is None:
        db.add(AppSetting(key=key, value=value))
    else:
        row.value = value
        row.updated_at = dt.datetime.now(dt.timezone.utc)
    db.commit()


def get_monitoring_defaults(db: Session) -> dict:
    """The stored defaults merged over the built-in ones, so a missing or
    malformed value can never make a new engagement start with something undefined."""
    merged = {
        **DEFAULT_MONITORING_DEFAULTS,
        "capabilities": dict(DEFAULT_MONITORING_DEFAULTS["capabilities"]),
    }
    row = db.get(AppSetting, MONITORING_DEFAULTS_KEY)
    if row and isinstance(row.value, dict):
        stored = row.value
        caps = stored.get("capabilities")
        if isinstance(caps, dict):
            for key in CAPABILITY_IDS:
                if key in caps:
                    merged["capabilities"][key] = bool(caps[key])
        if stored.get("scan_profile") in SCAN_PROFILES:
            merged["scan_profile"] = stored["scan_profile"]
        for key in ("new_asset_policy_customer", "new_asset_policy_other"):
            if stored.get(key) in ("auto", "hold"):
                merged[key] = stored[key]
        if "fragility_breaker" in stored:
            merged["fragility_breaker"] = bool(stored["fragility_breaker"])
    return merged


def set_monitoring_defaults(db: Session, values: dict) -> dict:
    current = get_monitoring_defaults(db)
    caps = values.get("capabilities")
    if isinstance(caps, dict):
        for key, flag in caps.items():
            if key not in CAPABILITY_IDS:
                raise ValueError(f"unknown capability {key!r}")
            current["capabilities"][key] = bool(flag)
    if values.get("scan_profile") is not None:
        if values["scan_profile"] not in SCAN_PROFILES:
            raise ValueError("scan_profile must be passive, light, standard or thorough")
        current["scan_profile"] = values["scan_profile"]
    for key in ("new_asset_policy_customer", "new_asset_policy_other"):
        if values.get(key) is not None:
            if values[key] not in ("auto", "hold"):
                raise ValueError(f"{key} must be auto or hold")
            current[key] = values[key]
    if values.get("fragility_breaker") is not None:
        current["fragility_breaker"] = bool(values["fragility_breaker"])
    _put(db, MONITORING_DEFAULTS_KEY, current)
    return get_monitoring_defaults(db)


def get_max_concurrent_monitoring_runs(db: Session) -> int:
    row = db.get(AppSetting, MAX_CONCURRENT_MONITORING_KEY)
    if row and isinstance(row.value, dict):
        try:
            value = int(row.value.get("value"))
        except (TypeError, ValueError):
            return DEFAULT_MAX_CONCURRENT_MONITORING
        if MIN_MAX_CONCURRENT_MONITORING <= value <= MAX_MAX_CONCURRENT_MONITORING:
            return value
    return DEFAULT_MAX_CONCURRENT_MONITORING


def set_max_concurrent_monitoring_runs(db: Session, value: int) -> int:
    if not MIN_MAX_CONCURRENT_MONITORING <= value <= MAX_MAX_CONCURRENT_MONITORING:
        raise ValueError(
            f"max_concurrent_monitoring_runs must be between {MIN_MAX_CONCURRENT_MONITORING} "
            f"and {MAX_MAX_CONCURRENT_MONITORING}"
        )
    _put(db, MAX_CONCURRENT_MONITORING_KEY, {"value": int(value)})
    return get_max_concurrent_monitoring_runs(db)
