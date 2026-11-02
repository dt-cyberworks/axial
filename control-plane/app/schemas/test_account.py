"""Request bodies of the test-account endpoints (REQ-TESTACCT-001..006). A secret appears in these inputs only; no output carries it."""

from __future__ import annotations

from pydantic import BaseModel, Field


class HostAssignmentIn(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    login_path: str | None = Field(default=None, max_length=300)


class TestAccountCreateIn(BaseModel):
    __test__ = False

    label: str
    role: str
    kind: str
    username: str | None = None
    secret: str = Field(repr=False)          # repr=False: a stray log of the model never prints it
    login_path: str | None = None
    header_name: str | None = Field(default=None, max_length=80)
    hosts: list[HostAssignmentIn] = []
    attested: bool = False


class SecretIn(BaseModel):
    secret: str = Field(repr=False)


class HostsIn(BaseModel):
    hosts: list[HostAssignmentIn]
    attested: bool = False
    consent: bool = False


class OutcomeIn(BaseModel):
    label: str
    host: str
    outcome: str


class OutcomesIn(BaseModel):
    outcomes: list[OutcomeIn]
