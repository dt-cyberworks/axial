"""Authenticated proxy-to-control-plane audit submission."""

from __future__ import annotations

import json
import os
import urllib.request

CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://control-plane:8000").rstrip("/")
INTERNAL_API_TOKEN = os.environ.get("INTERNAL_API_TOKEN", "change-me-in-dev")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development").lower()
if ENVIRONMENT == "production" and INTERNAL_API_TOKEN in {"", "change-me-in-dev"}:
    raise RuntimeError("insecure production configuration: internal_api_token")


def submit_audit(engagement_id: str, decision: str, reason: str, payload: dict) -> None:
    body = json.dumps(
        {
            "decision": decision,
            "reason": reason,
            "payload": payload,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{CONTROL_PLANE_URL}/internal/engagements/{engagement_id}/proxy-audit",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-ASM-Internal-Token": INTERNAL_API_TOKEN,
        },
    )
    with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 - fixed internal base URL
        if response.status != 201:
            raise RuntimeError(f"audit ingestion returned {response.status}")

