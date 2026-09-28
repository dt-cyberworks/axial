---
title: Finding triage
status: implemented
risk: R2
owner: engineering
---

# Finding Triage

Context: the 2026-09-27 review found that findings already had the
statuses `accepted_risk`, `false_positive`, and `resolved` in the data
model, but nothing could set them: every finding stayed "open" in the
console, the counts, and every report, false positives included. And had
a status been set directly, the next scan would have recreated the same
finding as a new open one, because a re-observation only matched open
findings. Triage is the core loop of an ASM tool; without it, findings
cannot be worked down.

**Risk class: R2** (API, persistence: migration `0031_finding_triage.sql`
adds three nullable columns). No change to scanning, scope, or the
gateway.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

## REQ-TRIAGE-001: Operators can triage a finding, with a reason

Acceptance criteria:

- `PATCH /engagements/{engagement_id}/findings/{finding_id}` sets the
  status to `open`, `accepted_risk`, `false_positive`, or `resolved`, with
  an optional note of up to 1000 characters.
- [Negative test] `accepted_risk` and `false_positive` require a note of at
  least three non-blank characters; without one the request is rejected
  (`422`) and nothing changes.
- The finding records the note, the time, and the operator's e-mail; the
  response returns them.
- Every change is appended to the engagement's hash-chained audit log
  (action `finding_triage`, from/to status, note, actor).
- [Negative test] Another operator cannot triage the finding (`404`, via
  engagement ownership), and a finding of another engagement cannot be
  reached through one's own engagement's path (`404`).

## REQ-TRIAGE-002: Triage decisions survive the next scan

Acceptance criteria:

- When a scan observes a finding again, it updates the existing finding
  in this order of preference: an open one; otherwise one marked
  `false_positive` or `accepted_risk`, which keeps its status and note;
  otherwise a `resolved` one.
- [Negative test] Re-observing a false positive or accepted risk creates no
  new open duplicate.
- A resolved finding observed again is reopened (a regression): status
  `open`, changed by `scan`, with an audit log entry.
- The re-observation is recorded for the running scan, so the scan diff
  does not report a triaged finding as fixed.

## REQ-TRIAGE-003: The console shows and changes the status

Acceptance criteria:

- The engagement's findings list has one tab per status (Open, Accepted
  risk, False positive, Resolved), each with its count; Open is the
  default. The summary endpoint returns `counts_by_status`.
- Severity tiles and the header's open-findings count cover open findings
  only.
- A finding's detail view shows its status, who changed it and when, and
  the note; it offers Mark resolved, Accept risk, and Mark false positive
  for an open finding, and Reopen otherwise.
- Accept risk and Mark false positive ask for the reason before
  confirming; the confirm button stays disabled until one is given.

## REQ-TRIAGE-004: The report reflects triage

Acceptance criteria:

- The report's findings are open findings only (unchanged).
- Accepted risks appear in their own table with severity, finding, asset,
  justification, and the date accepted. The operator's identity is not
  printed; it stays in the audit log.
- False positives are not listed; the report states how many there were.

Security invariants:

- Triage never changes scope, scanning, or authorization; it only
  classifies results.
- The audit trail records every decision, including automatic reopening.
