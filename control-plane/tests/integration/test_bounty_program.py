"""TC-AUTH-001 / REQ-AUTH-006: bug-bounty program policy is reachable
through the GUI-facing endpoints (upsert, never accumulating duplicates),
and the worker-facing internal endpoint returns the identification a
bug_bounty engagement's tool calls must carry - nulls for everything else."""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import select

from app.api.engagements import add_bounty_program, get_bounty_program
from app.api.internal import get_bounty_ident
from app.models.engagement import BountyProgram, Engagement
from app.schemas.engagement import BountyProgramCreate


def _engagement(db, *, source="own_domain") -> Engagement:
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        title="Bounty test", source=source, status="draft",
        authorized_from=now - dt.timedelta(hours=1), authorized_until=now + dt.timedelta(days=1),
    )
    db.add(eng)
    db.commit()
    db.refresh(eng)
    return eng


def _policy(**overrides) -> BountyProgramCreate:
    defaults = dict(
        platform="hackerone", program_ref="acme-corp",
        automation_allowed=True, ai_testing_allowed=False,
        max_rps=1.5, max_concurrency=1,
        ident_header_name="X-Bug-Bounty", ident_header_value="researcher-handle-42",
        ua_suffix="(+contact: researcher@example.com)",
    )
    defaults.update(overrides)
    return BountyProgramCreate(**defaults)


def test_negative_add_bounty_program_requires_source_bug_bounty(db):
    eng = _engagement(db, source="own_domain")
    with pytest.raises(HTTPException) as exc:
        add_bounty_program(eng.id, _policy(), db=db)
    assert exc.value.status_code == 400


def test_add_bounty_program_succeeds_for_a_bug_bounty_engagement(db):
    eng = _engagement(db, source="bug_bounty")
    out = add_bounty_program(eng.id, _policy(), db=db)
    assert out.engagement_id == eng.id
    assert out.ident_header_value == "researcher-handle-42"


def test_add_bounty_program_upserts_never_accumulates_duplicates(db):
    eng = _engagement(db, source="bug_bounty")
    first = add_bounty_program(eng.id, _policy(ident_header_value="v1"), db=db)
    second = add_bounty_program(eng.id, _policy(ident_header_value="v2"), db=db)
    assert first.id != second.id  # a genuinely new row, not a mutated one
    rows = db.scalars(select(BountyProgram).where(BountyProgram.engagement_id == eng.id)).all()
    assert len(rows) == 1
    assert rows[0].ident_header_value == "v2"


def test_get_bounty_program_returns_none_when_unset(db):
    eng = _engagement(db, source="bug_bounty")
    assert get_bounty_program(eng.id, db=db) is None


def test_get_bounty_program_returns_the_current_policy(db):
    eng = _engagement(db, source="bug_bounty")
    add_bounty_program(eng.id, _policy(), db=db)
    out = get_bounty_program(eng.id, db=db)
    assert out is not None
    assert out.platform == "hackerone"


def test_bounty_ident_is_null_for_a_non_bug_bounty_engagement(db):
    eng = _engagement(db, source="own_domain")
    ident = get_bounty_ident(eng.id, db=db)
    assert ident == {"ident_header_name": None, "ident_header_value": None, "ua_suffix": None, "max_rps": None}


def test_bounty_ident_is_null_for_a_bug_bounty_engagement_with_no_policy_submitted_yet(db):
    eng = _engagement(db, source="bug_bounty")
    ident = get_bounty_ident(eng.id, db=db)
    assert ident == {"ident_header_name": None, "ident_header_value": None, "ua_suffix": None, "max_rps": None}


def test_bounty_ident_returns_the_configured_identification(db):
    eng = _engagement(db, source="bug_bounty")
    add_bounty_program(eng.id, _policy(ua_suffix="ua-tag"), db=db)
    ident = get_bounty_ident(eng.id, db=db)
    assert ident == {
        "ident_header_name": "X-Bug-Bounty",
        "ident_header_value": "researcher-handle-42",
        "ua_suffix": "ua-tag",
        "max_rps": 1.5,
    }


def test_bounty_ident_ua_suffix_is_null_when_not_configured(db):
    eng = _engagement(db, source="bug_bounty")
    add_bounty_program(eng.id, _policy(ua_suffix=None), db=db)
    ident = get_bounty_ident(eng.id, db=db)
    assert ident["ua_suffix"] is None


def test_bounty_ident_returns_the_configured_max_rps(db):
    """REQ-RATE-004: the worker uses this to tighten nuclei/ffuf's own
    internal rate flag - a program like Aylo/Brazzers's real "max. 7
    requests/sec" clause must be readable here, not just stored."""
    eng = _engagement(db, source="bug_bounty")
    add_bounty_program(eng.id, _policy(max_rps=7), db=db)
    ident = get_bounty_ident(eng.id, db=db)
    assert ident["max_rps"] == 7.0


def test_add_bounty_program_succeeds_with_no_identification_header(db):
    """REQ-AUTH-006 (amended 2026-08-12): not every real program requires a
    custom header - e.g. Port of Antwerp-Bruges on Intigriti identifies
    researchers via an out-of-band email alias, not a header. Only platform
    and program_ref stay mandatory."""
    eng = _engagement(db, source="bug_bounty")
    out = add_bounty_program(eng.id, _policy(ident_header_value=None), db=db)
    assert out.ident_header_value is None


def test_bounty_ident_ident_header_value_is_null_when_program_has_none_configured(db):
    """NEGATIVE (REQ-AUTH-006 amended): a header-less policy must not be
    mistaken for "no policy at all" - the platform/program_ref/automation/
    max_rps configuration still applies, only the header injection no-ops."""
    eng = _engagement(db, source="bug_bounty")
    add_bounty_program(eng.id, _policy(ident_header_value=None, max_rps=5), db=db)
    ident = get_bounty_ident(eng.id, db=db)
    assert ident["ident_header_value"] is None
    assert ident["max_rps"] == 5.0  # REQ-RATE-004 tightening must still be reachable


def test_tcp_syn_scan_profile_defaults_to_none(db):
    """GitHub issue #37: a policy that never mentions the new field must
    preserve the pre-existing behavior exactly - opt-in, never inferred."""
    policy = _policy()
    assert policy.tcp_syn_scan_profile == "none"
    assert policy.raw_max_packets_per_second is None
    assert policy.network_scan_authorization_evidence is None


def test_negative_full_profile_without_evidence_is_rejected_at_schema_level():
    """GitHub issue #37's own explicit acceptance criterion: 'full' must be
    rejected as early as possible (schema validation, not just the gateway)
    when no authorization evidence is recorded."""
    with pytest.raises(ValidationError, match="network_scan_authorization_evidence"):
        _policy(tcp_syn_scan_profile="full")


def test_negative_full_profile_with_blank_evidence_is_rejected_at_schema_level():
    with pytest.raises(ValidationError, match="network_scan_authorization_evidence"):
        _policy(tcp_syn_scan_profile="full", network_scan_authorization_evidence="   ")


def test_full_profile_with_evidence_is_accepted_at_schema_level():
    policy = _policy(
        tcp_syn_scan_profile="full",
        network_scan_authorization_evidence="Program brief section 4 explicitly authorizes full TCP port scans.",
    )
    assert policy.tcp_syn_scan_profile == "full"


def test_negative_tcp_syn_scan_profile_rejects_an_unknown_value():
    with pytest.raises(ValidationError):
        _policy(tcp_syn_scan_profile="aggressive")


def test_add_bounty_program_persists_the_network_scan_profile_fields(db):
    """Round-trip through the real add_bounty_program/get_bounty_program
    endpoints - not just schema construction - proves the new columns are
    actually wired to the ORM model, not just declared on the Pydantic side."""
    eng = _engagement(db, source="bug_bounty")
    add_bounty_program(eng.id, _policy(
        tcp_syn_scan_profile="full",
        raw_max_packets_per_second=250.0,
        network_scan_authorization_evidence="Explicit written authorization from program owner, ref TICKET-123.",
    ), db=db)

    out = get_bounty_program(eng.id, db=db)

    assert out is not None
    assert out.tcp_syn_scan_profile == "full"
    assert out.raw_max_packets_per_second == 250.0
    assert out.network_scan_authorization_evidence == "Explicit written authorization from program owner, ref TICKET-123."
