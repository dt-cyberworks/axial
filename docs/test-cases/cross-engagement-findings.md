---
title: Cross-engagement findings verification
status: ready
risk: R3
owner: security-engineering
---

# Cross-Engagement Findings Verification

Verifies [`../requirements/cross-engagement-findings.md`](../requirements/cross-engagement-findings.md).

Mutation check (2026-09-29): with the ownership condition removed from
`app/api/portfolio.py`, the three negative ownership tests fail; with one
`/findings*` removed from a single list in `edge/Caddyfile`, both
path-list consistency tests fail. Both changes were reverted.

## TC-PORTFOLIO-001: Ownership, filters, and paging of `GET /findings`

Requirements:

- REQ-PORTFOLIO-001

Automated tests:

- `control-plane/tests/integration/test_cross_engagement_findings.py`

Objective:

Prove the endpoint returns only findings of engagements the caller can see —
in the items, the total, and every count — and that filters, order, and
paging work.

Expected results:

- `test_negative_an_operator_sees_only_findings_of_own_engagements` - only own items; total and counts exclude the other user's critical finding.
- `test_negative_another_users_engagement_id_gives_the_same_empty_answer_as_an_unknown_id` - identical empty responses, so existence is not revealed.
- `test_negative_search_never_reaches_another_users_findings` - by title, by target, and in other status/severity views.
- `test_negative_without_a_session_the_endpoint_answers_401`.
- `test_admin_sees_findings_of_all_engagements`.
- `test_negative_unknown_status_severity_and_bad_paging_are_rejected` - `422`.
- `test_order_is_severity_then_risk_score_and_paging_keeps_the_total`, `test_items_carry_the_engagement_title_and_the_usual_finding_fields`, `test_filters_by_status_severity_and_engagement_with_matching_counts`, `test_search_matches_title_or_target_case_insensitively_and_literally`.

## TC-PORTFOLIO-002: Edge routing of `/findings`

Requirements:

- REQ-PORTFOLIO-002

Automated tests:

- `scripts/tests/test_edge_caddy_routing.py`

Objective:

Prove both Caddyfiles route `/findings` like the other shared paths, and that
their shared-prefix lists cannot drift apart.

Expected results:

- `test_negative_every_shared_prefix_list_in_a_caddyfile_is_the_same` (both files) and `test_negative_both_caddyfiles_route_the_same_shared_prefixes`.
- Real Caddy in Docker: a browser navigation to `/findings` gets the console, an API request reaches the backend (both files); `/findings` answers with `Cache-Control: no-store` and `Vary: Accept` for both kinds of request.
