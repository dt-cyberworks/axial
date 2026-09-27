import datetime
import uuid

from pydantic import BaseModel, ConfigDict


class ApprovalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    engagement_id: uuid.UUID
    tool_call: dict
    state: str
    approved_by: str | None
    expires_at: datetime.datetime
    approved_at: datetime.datetime | None = None
    execution_started_at: datetime.datetime | None = None
    execution_finished_at: datetime.datetime | None = None
    execution_error: str | None = None


class ApprovalDecision(BaseModel):
    # Intentionally empty: actor identity comes only from authentication.
    pass
