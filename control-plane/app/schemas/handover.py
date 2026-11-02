"""REQ-HANDOVER-001..003 (GitHub #84): the request to start an assessment from a monitor."""

from __future__ import annotations

import datetime
import uuid
from typing import Literal

from pydantic import BaseModel, Field


class HandoverIn(BaseModel):
    """The window is required and never inherited (the monitor's usually runs a year); hosts are the owner's choice."""

    title: str | None = Field(default=None, min_length=1, max_length=200)
    authorized_from: datetime.datetime
    authorized_until: datetime.datetime
    emergency_contact: str | None = Field(default=None, max_length=200)
    scope_mode: Literal["hosts", "same_scope"] = "hosts"
    hosts: list[str] = Field(default_factory=list, max_length=200)


class HandoverCreatedOut(BaseModel):
    id: uuid.UUID
    title: str
    status: str
    scope_mode: str
    overlap: str
    notices: list[str]
