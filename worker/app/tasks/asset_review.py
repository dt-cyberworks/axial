"""Post-Discovery Asset Review Gate (REQ-ASSETREVIEW-001..006).

Optionale, per-Engagement-Pause zwischen discovery und fingerprint: der
Operator prueft die aktuell in-scope entdeckten Assets und kann einzelne
ausschliessen, bevor der Rest der Pipeline (fingerprint/correlate/agent/...)
sie beruehrt. Reines Opt-in (Engagement.asset_review_enabled) - ist es nicht
gesetzt, verhaelt sich die Pipeline exakt wie vorher.

Die eigentliche Autorisierungs-Wirkung einer Abwahl (eine echte, vom Scope
Gateway durchgesetzte deny-Regel) entsteht auf der control-plane beim
Entscheidungs-Endpunkt - dieses Modul wartet nur auf das Ergebnis.
"""

from __future__ import annotations

import logging
import time
import uuid

from app.control_plane_client import client

logger = logging.getLogger(__name__)

_REVIEW_POLL_SECONDS = 3
_REVIEW_MAX_WAIT_SECONDS = 900


def gate(engagement_id: str, scan_run_id: str, discovered: list[dict]) -> list[dict] | None:
    """Liefert die (ggf. eingeschraenkte) discovered-Liste zurueck, oder None,
    wenn die Review nicht rechtzeitig/positiv entschieden wurde. Der Aufrufer
    MUSS den Lauf dann abbrechen (REQ-ASSETREVIEW-006, fail closed) - niemals
    mit der vollen Kandidatenliste weiterlaufen."""
    if not client.asset_review_required(uuid.UUID(engagement_id)):
        return discovered
    if not discovered:
        return discovered  # nichts zu pruefen, keine Pause noetig

    # REQ-CIDRDISC-003: discovery.py now returns real per-candidate asset_type
    # (domain or ip) - the review's excluded-candidate deny row must carry the
    # SAME type the discovered_asset actually has (control-plane's
    # decide_asset_review reads this straight through), not a hardcoded
    # "domain" that would create a wrongly-typed deny rule for an IP.
    candidates = [
        {"asset_id": a["asset_id"], "value": a["value"], "asset_type": a.get("asset_type", "domain")}
        for a in discovered
    ]
    try:
        review = client.create_asset_review(uuid.UUID(engagement_id), uuid.UUID(scan_run_id), candidates)
    except Exception as exc:  # noqa: BLE001
        logger.warning("asset review konnte nicht angelegt werden: %s", exc)
        return None
    review_id = review.get("id")
    if not review_id:
        return None

    waited = 0
    decision_state = "expired"
    excluded_values: list[str] = []
    while waited < _REVIEW_MAX_WAIT_SECONDS:
        if client.is_cancel_requested(uuid.UUID(scan_run_id)):
            decision_state = "cancelled"
            break
        try:
            status = client.get_asset_review(str(review_id))
        except Exception as exc:  # noqa: BLE001
            logger.warning("asset review poll fehlgeschlagen: %s", exc)
            time.sleep(_REVIEW_POLL_SECONDS)
            waited += _REVIEW_POLL_SECONDS
            continue
        state = status.get("state")
        if state in ("submitted", "expired", "cancelled"):
            decision_state = state
            excluded_values = status.get("excluded_values") or []
            break
        time.sleep(_REVIEW_POLL_SECONDS)
        waited += _REVIEW_POLL_SECONDS

    if decision_state != "submitted":
        return None

    excluded = set(excluded_values)
    return [a for a in discovered if a["value"] not in excluded]
