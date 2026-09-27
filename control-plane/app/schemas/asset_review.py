import datetime
import uuid

from pydantic import BaseModel, ConfigDict


class AssetReviewCandidate(BaseModel):
    asset_id: uuid.UUID
    value: str
    asset_type: str


class AssetReviewOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    engagement_id: uuid.UUID
    scan_run_id: uuid.UUID
    candidate_assets: list[AssetReviewCandidate]
    state: str
    excluded_values: list[str] | None = None
    expires_at: datetime.datetime
    decided_at: datetime.datetime | None = None
    decided_by: str | None = None


class AssetReviewDecisionIn(BaseModel):
    # Werte aus candidate_assets, die NICHT weiter gescannt werden sollen. Alles
    # ausserhalb der urspruenglichen Kandidatenliste wird ignoriert
    # (REQ-ASSETREVIEW-004 - die Pruefung kann Scope nur einschraenken).
    excluded_values: list[str] = []
