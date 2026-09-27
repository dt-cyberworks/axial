"""REQ-AUDITUI-003: actor/action audit filters accept multiple values.

Against a real Postgres: the filter is a SQL `IN` over the append-only
audit_log, and the point of the requirement is which rows come back.
"""

from __future__ import annotations

import datetime as dt

from app.api.stream import _MAX_FACET_FILTER_VALUES, audit_facets, list_audit
from app.gateway.audit import append_audit_log
from app.models.audit import AuditLog
from app.models.engagement import Engagement

ROWS = [
    ("egress-proxy", "network_request", "ALLOW"),
    ("egress-proxy", "network_request", "DENY"),
    ("gateway", "tool_call", "ALLOW"),
    ("worker", "tool_execution", "ALLOW"),
    ("user:alice@example.test", "engagement_config_updated", "ALLOW"),
    ("lens_agent", "lens_explanation", "ALLOW"),
]


def _engagement(db) -> Engagement:
    now = dt.datetime.now(dt.timezone.utc)
    eng = Engagement(
        title="Audit filter test", source="own_domain", status="active",
        authorized_from=now - dt.timedelta(days=1), authorized_until=now + dt.timedelta(days=1),
    )
    db.add(eng)
    db.commit()
    db.refresh(eng)
    return eng


def _seed(db, eng) -> None:
    for actor, action, decision in ROWS:
        append_audit_log(
            db, engagement_id=eng.id, actor=actor, action=action,
            decision=decision, reason="seeded", payload={"actor": actor},
        )
    db.commit()


def _actors(result) -> list[str]:
    return sorted(entry["actor"] for entry in result["entries"])


def test_two_actor_values_return_both_and_exclude_the_rest(db):
    eng = _engagement(db)
    _seed(db, eng)

    result = list_audit(eng.id, actor=["gateway", "worker"], db=db)

    assert _actors(result) == ["gateway", "worker"]


def test_two_action_values_return_both_and_exclude_the_rest(db):
    eng = _engagement(db)
    _seed(db, eng)

    result = list_audit(eng.id, action=["tool_call", "lens_explanation"], db=db)

    assert sorted(e["action"] for e in result["entries"]) == ["lens_explanation", "tool_call"]


def test_a_single_value_behaves_exactly_like_the_previous_equality_filter(db):
    eng = _engagement(db)
    _seed(db, eng)

    result = list_audit(eng.id, actor=["egress-proxy"], db=db)

    assert _actors(result) == ["egress-proxy", "egress-proxy"]


def test_actor_and_action_filters_combine_as_and(db):
    eng = _engagement(db)
    _seed(db, eng)

    result = list_audit(eng.id, actor=["egress-proxy", "gateway"], action=["tool_call"], db=db)

    assert len(result["entries"]) == 1
    assert result["entries"][0]["actor"] == "gateway"


def test_omitting_the_filters_returns_everything_for_the_engagement(db):
    eng = _engagement(db)
    _seed(db, eng)

    assert len(list_audit(eng.id, db=db)["entries"]) == len(ROWS)


def test_an_unknown_value_matches_nothing_rather_than_everything(db):
    eng = _engagement(db)
    _seed(db, eng)

    assert list_audit(eng.id, actor=["does-not-exist"], db=db)["entries"] == []


def test_empty_strings_are_ignored_not_treated_as_a_value(db):
    """A client that appends a blank param must not accidentally filter to
    'actor = ""' and show nothing."""
    eng = _engagement(db)
    _seed(db, eng)

    assert len(list_audit(eng.id, actor=[""], db=db)["entries"]) == len(ROWS)


def test_the_in_list_is_bounded(db):
    eng = _engagement(db)
    _seed(db, eng)
    oversized = [f"actor-{i}" for i in range(_MAX_FACET_FILTER_VALUES * 3)] + ["gateway"]

    result = list_audit(eng.id, actor=oversized, db=db)

    # "gateway" sits past the bound, so it is truncated away - the request is
    # honored only up to the documented limit rather than building an
    # unbounded IN list.
    assert result["entries"] == []


def test_filtering_never_mutates_the_audit_rows_or_their_hash_chain(db):
    eng = _engagement(db)
    _seed(db, eng)
    before = [(r.id, r.row_hash, r.prev_hash) for r in db.query(AuditLog).order_by(AuditLog.ts)]

    list_audit(eng.id, actor=["gateway"], db=db)
    list_audit(eng.id, action=["tool_call", "tool_execution"], db=db)

    after = [(r.id, r.row_hash, r.prev_hash) for r in db.query(AuditLog).order_by(AuditLog.ts)]
    assert before == after


def test_facets_still_enumerate_every_actor_and_action(db):
    eng = _engagement(db)
    _seed(db, eng)

    facets = audit_facets(eng.id, db=db)

    assert set(facets["actors"]) == {actor for actor, _, _ in ROWS}
    assert set(facets["actions"]) == {action for _, action, _ in ROWS}


def test_decision_filter_still_composes_with_multi_actor(db):
    eng = _engagement(db)
    _seed(db, eng)

    result = list_audit(eng.id, actor=["egress-proxy"], decision="DENY", db=db)

    assert len(result["entries"]) == 1
    assert result["entries"][0]["decision"] == "DENY"


def test_a_bare_string_is_one_value_not_a_sequence_of_characters(db):
    """Regression: treating a string as an iterable would filter on single
    characters, and rejecting it outright would silently drop the filter and
    show everything. Both are wrong; a string is one value."""
    eng = _engagement(db)
    _seed(db, eng)

    result = list_audit(eng.id, actor="gateway", db=db)

    assert _actors(result) == ["gateway"]
