---
title: English runtime text verification
status: ready
risk: R2
owner: engineering
---

# English Runtime Text Verification

Verifies [`../requirements/english-runtime-text.md`](../requirements/english-runtime-text.md).
Before the change the scan listed 131 German runtime strings (found with a
German-only word list and a dictionary comparison); after it, none.

## TC-TEXT-001: No German runtime text; titles keep their identity

Requirements:

- REQ-TEXT-001

Automated tests:

- `scripts/tests/test_english_runtime_text.py`
- `control-plane/tests/integration/test_english_finding_titles.py`

Objective:

Prove runtime text is English and that translating finding titles neither
duplicates findings nor loses triage decisions.

Expected results:

- `test_runtime_strings_are_english` finds nothing; `test_negative_the_scan_finds_german_text` finds the planted German.
- Each of the five translated titles, reported after its German original, lands on the same row and keeps `accepted_risk`.
- `test_negative_other_titles_are_not_mapped` - unrelated titles stay separate findings.
- Migration 0032 renames all five, keeps every fingerprint, and is a no-op the second time.
