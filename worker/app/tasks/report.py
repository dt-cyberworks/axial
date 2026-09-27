"""Phase 7 - Reporting (Architektur Kap. 6): das eigentliche Verkaufsprodukt.

REQ-REPORT-003: erzeugt jetzt einen echten Report fuer DIESEN Lauf. Das
Rendering selbst liegt in der control-plane (einziger DB-Schreiber, s.
Deployment-Architektur Kap. 2) - der Worker stoesst es nur an und ordnet es
dem gerade abgeschlossenen scan_run zu.
"""

import logging
import uuid

from app.control_plane_client import client

logger = logging.getLogger(__name__)


def run(engagement_id: str, scan_run_id: str | None = None) -> dict:
    """Ein fehlgeschlagener Report darf einen ansonsten erfolgreichen Scan
    nicht zum Fehlschlag machen: die Befunde sind bereits persistiert und
    sichtbar. Der Fehlversuch wird in der control-plane als Report mit
    status='failed' samt Grund festgehalten, ist also nicht still."""
    try:
        return client.request_report(
            uuid.UUID(engagement_id),
            scan_run_id=uuid.UUID(scan_run_id) if scan_run_id else None,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("report phase: Reporterzeugung fehlgeschlagen: %s", exc)
        return {"status": "failed", "error": str(exc)[:500]}
