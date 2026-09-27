---
title: Generated customer report (PDF)
status: implemented
risk: R3
owner: security-engineering
---

# Generated Customer Report

Context: reported 2026-08-09 - the "Queue report" button appeared to do
nothing. Investigation found two compounding defects. The backend
(`request_report` in `api/findings.py`) was an explicit placeholder: it minted
a `job_id`, stored `"queued"` in a module-level dict that nothing ever read
again, and returned. No PDF was ever rendered, and there was no status
endpoint, no worker job, and no download link. The pipeline's own phase-7
`report.run()` called an internal route that did the same thing. Separately,
the frontend called `api.requestReport(id)` bare - no `useMutation`, no
loading state, no success or error handling - so even a working backend would
have produced no visible confirmation.

The report is the customer-facing product (Architektur Kap. 6.1) and the
artifact that closes the loop with the audit trail for compliance purposes, so
this is implemented end to end rather than downgraded to an honest "not yet
available" message.

**Risk class: R3.** The report is the one artifact deliberately produced to
LEAVE the platform - an operator sends it to a customer, an insurer, or an
auditor. Its inputs include `finding.evidence`, which for an `http_request`
finding can contain an `Authorization` header, a session cookie, or a login
body, and the cached Lens Agent explanation is generated from a context that
includes that same evidence blob verbatim. Rendering those into a distributed
document is a credential-disclosure surface, which puts this on the same
footing as REQ-AUDIT-003/004 and requires the negative tests below plus human
security review. It also writes to the hash-chained audit trail. No Scope
Gateway, egress, authorization, or tool-execution behavior changes.

## REQ-REPORT-001: The report endpoint generates a real PDF with the specified structure

Acceptance criteria:

- `POST /engagements/{id}/report` renders and persists an actual PDF and
  returns a job-shaped response (`job_id`, `status`, ...) per the documented
  contract (Kap. 6.3), where `job_id` is the report's own id so a caller can
  poll or download using the identifier it already holds.
- The PDF contains all five sections specified in Kap. 6.1: executive summary
  (risk light, trend vs. the previous run, top-3 actions), risk overview
  (counts by severity plus the NEW / no-longer-observed / persisting diff),
  detailed findings (what, where, category/confidence/score, CVE data,
  remediation), asset inventory (assets, services, shadow-IT hints), and
  methodology & scope.
- The methodology & scope section is **mandatory and never omitted** (⚖ Kap.
  6.1/6.4): it states the authorized window, the authorization source, the
  authorization document reference (`scope_doc_sha256`), what was in scope,
  what was explicitly excluded, and how testing was constrained.
- Generation performs no network calls and no LLM requests. Cached Lens
  explanations already stored on a finding are reused when present; a report
  never triggers a provider call, so producing a customer deliverable cannot
  depend on an external service being reachable.
- A generated report is persisted and re-downloadable unchanged. A later scan
  run must not retroactively alter a document the customer already received.
- The stored report records `sha256` and `byte_size`, and the generation is
  recorded in the audit trail with those values, so a later download can be
  proven identical to what was generated.
- Reports are listable (`GET /engagements/{id}/reports`, metadata only) and
  downloadable (`GET /engagements/{id}/reports/{report_id}`), both under the
  authenticated, ownership-checked engagement router. A report id belonging to
  a different engagement is a 404 on the download route, not a successful read.
- A run that completed with degraded coverage (REQ-SCAN-014) is called out
  explicitly in the report, so a short findings list is not read as a clean
  result.

## REQ-REPORT-002: Credentials never reach a generated report

Acceptance criteria:

- Raw tool output and raw request/response captures are not reproduced in the
  report (Kap. 6.2 puts them in the evidence store). Only scalar evidence
  fields are summarized; nested structures - which are exactly those raw
  captures - are skipped rather than flattened, so they cannot be smuggled back
  in one key at a time.
- Evidence fields whose key names a credential (`password`, `token`, `secret`,
  `api_key`, `auth`, `cookie`, `session`, `credential`, `private_key`, matched
  case-insensitively as substrings) are redacted, never dropped: the field name
  stays readable, the value does not.
- Free prose rendered into the report (the cached Lens explanation, finding
  titles) is scanned for credential *shapes* that carry no key to match on -
  `Bearer <token>`, `Basic <base64>`, `Cookie:`/`Set-Cookie:` values,
  `X-Api-Key:`/`api_key=` style assignments, and JWTs - and those values are
  replaced while the surrounding sentence stays readable.
- Individual rendered values are length-bounded so one pathological evidence
  field cannot push real content out of the document.
- [Negative test, the required R3 one] given a finding whose evidence contains
  a real-shaped bearer token, a session cookie, an API key, and a password, and
  a cached Lens explanation that echoes them in prose, none of those secret
  values appear as substrings anywhere in the generated PDF bytes - asserted
  against the secret values directly, not against an expected-output template
  that could be updated to match a regression.

Security invariants:

- Redaction is implemented in the control plane rather than imported from
  `worker/app/command_redaction.py`. The worker and control plane are
  independently deployed services and this codebase duplicates safety logic
  across service boundaries deliberately (see the egress-proxy /
  `raw_egress_lease.py` precedent) rather than coupling them.
- The model is instructed not to echo credentials, but that instruction is not
  a control. Redaction is applied to the model's output regardless.

## REQ-REPORT-003: The pipeline's report phase produces a real report for that run

Acceptance criteria:

- The phase-7 report step generates a real report scoped to the scan run that
  just finished, so the report's trend/diff section describes that run rather
  than defaulting to whatever ran most recently.
- The report is attributed to `pipeline`, not to an operator identity - the
  worker boundary grants no user context.
- A report failure never fails an otherwise-successful scan run: findings are
  already persisted and visible. The failure is recorded as a report row with
  `status="failed"` and its reason, and audited, so it is visible rather than
  silent.

## REQ-REPORT-004: Generating a report is a visible action with a visible result

Acceptance criteria:

- The button runs through a mutation with a pending state and a disabled
  control while in flight, matching every other action on the page.
- Success, backend-reported failure (`status: "failed"`), and request failure
  are each surfaced as distinct visible messages.
- Previously generated reports are listed with their timestamp, the run they
  cover, status, and size, each with a download control.
- The download uses the authenticated request path (REQ-DOWNLOAD-001), not a
  bare anchor.

## REQ-REPORT-005: The report renders as a professionally formatted document

Context: reported 2026-08-10 - the generated PDF was structurally complete
(all five Kap. 6.1 sections were present) but visually was wrapped monospace
Helvetica text with no cover page, no tables, no color, and no page numbers -
indistinguishable from a debug dump. Research into industry pentest-report
practice (PTES, PlexTrac/BrowserStack/e-council report guides) confirms the
*content* set was already right; this closes the *presentation* gap.

**Risk class: R3**, inherited from REQ-REPORT-001/002: this renderer draws the
same finding evidence and cached Lens explanations into the one artifact that
deliberately leaves the platform, so the REQ-REPORT-002 redaction guarantee
must hold for the new renderer exactly as it did for the old one, and is
re-verified rather than assumed to carry over.

Acceptance criteria:

- The document opens with a cover page: engagement title, generated-at
  timestamp, engagement id, and a confidentiality notice. It does not carry
  a customer logo (none is available); a wordmark-only wordmark identifies
  the platform as `app/pdf_report.py`'s renderer, not the authorization-
  document writer.
- Every page (cover excluded) carries a running footer with the engagement
  title, "CONFIDENTIAL", and a page-number / page-count marker, so a printed
  or partially-forwarded page is still traceable and marked non-public.
- Severity is color-coded consistently everywhere it appears (the findings
  summary table, the risk-overview counts, and each detailed-finding heading)
  using one fixed severity-to-color mapping.
- A findings-summary table (severity, title, asset, status) appears before
  the detailed-findings section, so a reader can triage before reading every
  finding in full.
- The risk-overview section renders severity counts as a real table, not
  wrapped prose lines, plus a simple proportional bar visualizing the
  severity distribution.
- A short, fixed paragraph explains what "critical/high/medium/low/info" and
  the risk score mean, so a non-technical reader does not have to infer the
  rating scale.
- The five Kap. 6.1 sections, their content, and the exact facts they state
  (authorization window, `scope_doc_sha256`, allow/deny scope, diff counts,
  degraded-coverage warning, evidence redaction) are unchanged from
  REQ-REPORT-001/002 - this requirement changes layout and typography only,
  never the underlying facts or what is/isn't included.
- `app/pdf.py::simple_pdf` (the authorization-document writer, which needs
  byte-for-byte determinism for its configuration checksum) is untouched;
  the new renderer is a separate module used only for the customer report.
- [Negative test, re-verifying the R3 gate] REQ-REPORT-002's credential
  negative test is re-run against the new renderer's output: a finding whose
  evidence and cached Lens explanation carry real-shaped secrets produces a
  PDF whose bytes (extracted via a real PDF text-extraction library, not a
  format-specific regex) contain none of those secret values.
