"""TC-APPROVAL-005: global Settings/engagement-config endpoints for the
manual-approval timeout (REQ-APPROVAL-005)."""

from __future__ import annotations

import pytest

from app.api.engagements import get_engagement_config, put_engagement_config
from app.api.settings import (
    ApprovalTimeoutSecondsIn,
    read_approval_timeout_seconds,
    update_approval_timeout_seconds,
)
from app.schemas.engagement import EngagementConfigIn


def test_global_get_defaults_and_put_roundtrips(db):
    assert read_approval_timeout_seconds(db).value == 900
    out = update_approval_timeout_seconds(ApprovalTimeoutSecondsIn(value=1800), db)
    assert out.value == 1800
    assert read_approval_timeout_seconds(db).value == 1800


def test_global_put_rejects_out_of_range(db):
    with pytest.raises(Exception):  # pydantic ValidationError at the Field(ge=,le=) boundary
        ApprovalTimeoutSecondsIn(value=59)
    with pytest.raises(Exception):
        ApprovalTimeoutSecondsIn(value=86401)


def test_engagement_config_reports_effective_value_and_override_flag(db, lab_engagement, test_user):
    cfg = get_engagement_config(lab_engagement.id, db)
    assert cfg["approval_timeout_seconds"] == 900
    assert cfg["approval_timeout_seconds_overridden"] is False

    put_engagement_config(lab_engagement.id, EngagementConfigIn(approval_timeout_seconds_override=300), db, user=test_user)
    cfg = get_engagement_config(lab_engagement.id, db)
    assert cfg["approval_timeout_seconds"] == 300
    assert cfg["approval_timeout_seconds_overridden"] is True


def test_engagement_config_clears_override_when_field_explicitly_null(db, lab_engagement, test_user):
    put_engagement_config(lab_engagement.id, EngagementConfigIn(approval_timeout_seconds_override=300), db, user=test_user)
    assert get_engagement_config(lab_engagement.id, db)["approval_timeout_seconds_overridden"] is True

    body = EngagementConfigIn.model_validate({"approval_timeout_seconds_override": None})
    put_engagement_config(lab_engagement.id, body, db, user=test_user)
    cfg = get_engagement_config(lab_engagement.id, db)
    assert cfg["approval_timeout_seconds_overridden"] is False
    assert cfg["approval_timeout_seconds"] == 900


def test_engagement_config_omitted_field_leaves_override_untouched(db, lab_engagement, test_user):
    put_engagement_config(lab_engagement.id, EngagementConfigIn(approval_timeout_seconds_override=300), db, user=test_user)
    put_engagement_config(lab_engagement.id, EngagementConfigIn(), db, user=test_user)
    cfg = get_engagement_config(lab_engagement.id, db)
    assert cfg["approval_timeout_seconds_overridden"] is True
    assert cfg["approval_timeout_seconds"] == 300
