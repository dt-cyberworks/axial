"""Phase 6 - Scoring (Architektur Kap. 5.2/5.3): EPSS-dominiert, KEV-Override."""

import uuid

from app.control_plane_client import client


def run(engagement_id: str) -> dict:
    return client.rescore(uuid.UUID(engagement_id))
