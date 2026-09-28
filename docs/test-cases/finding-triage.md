---
title: Finding triage verification
status: ready
risk: R2
owner: engineering
---

# Finding Triage Verification

Verifies [`../requirements/finding-triage.md`](../requirements/finding-triage.md).
Against the code before the change, the re-observation cases fail with two
rows where one is expected: a triaged finding came back as a new open one.

## TC-TRIAGE-001: The triage API

Requirements:

- REQ-TRIAGE-001

Automated tests:

- `control-plane/tests/integration/test_finding_triage.py`

Objective:

Prove owners can triage with a recorded, audited reason, and nobody else can.

Expected results:

- `test_owner_marks_a_false_positive_with_a_note` - status, note, e-mail, time, and one audit entry.
- `test_negative_dismissing_a_finding_requires_a_reason` - `422` for no, empty, blank, or too-short notes; status unchanged.
- `test_resolved_and_reopen_need_no_note`, `test_negative_unknown_status_is_rejected`.
- `test_negative_another_operator_cannot_triage`, `test_negative_a_finding_of_another_engagement_is_not_reachable_through_mine` - `404`, nothing changed.

## TC-TRIAGE-002: Decisions survive re-scans

Requirements:

- REQ-TRIAGE-002

Automated tests:

- `control-plane/tests/integration/test_finding_triage.py`

Objective:

Prove a scan never undoes a triage decision and reopens regressions.

Expected results:

- `test_a_triaged_finding_stays_triaged_when_seen_again` - one row, status and note kept, observation recorded for the running scan.
- `test_a_resolved_finding_seen_again_reopens_and_is_audited` - `open`, changed by `scan`, audit entry from `resolved`.
- `test_a_different_finding_is_still_created_normally`.

## TC-TRIAGE-003: Console and counts

Requirements:

- REQ-TRIAGE-003

Automated tests:

- `control-plane/tests/integration/test_finding_triage.py`
- `frontend/tests/finding_triage_requirements.test.mjs`

Objective:

Prove the counts are per status and the console offers the triage controls.

Expected results:

- `test_summary_counts_open_findings_and_every_status` - severity counts cover open only; `counts_by_status` covers all four.
- The frontend test checks the status tabs, the PATCH call, the required reason, and the Reopen action.
- Checked in a real browser against a local stack (see the change's QA notes).

## TC-TRIAGE-004: The report

Requirements:

- REQ-TRIAGE-004

Automated tests:

- `control-plane/tests/integration/test_finding_triage.py`

Objective:

Prove the rendered PDF shows accepted risks with their reason and hides false positives.

Expected results:

- `test_report_lists_accepted_risks_and_only_counts_false_positives` - model and extracted PDF text.
