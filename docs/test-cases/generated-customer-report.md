---
title: Generated customer report verification
status: ready
risk: R3
owner: security-engineering
---

# Generated Customer Report Verification

Verifies [`../requirements/generated-customer-report.md`](../requirements/generated-customer-report.md).
R3: the report is the artifact that deliberately leaves the platform, and its
inputs include finding evidence and an LLM explanation derived from that same
evidence - so TC-REPORT-002's negative tests are the load-bearing ones, not the
structure tests.

## TC-REPORT-001: A real PDF with the specified structure is generated and retrievable

Requirements:

- REQ-REPORT-001

Automated tests:

- `control-plane/tests/integration/test_report_generation.py`

Objective:

Verify the endpoint renders a genuine PDF containing every section Kap. 6.1
specifies, persists it, and serves it back unchanged.

Expected results:

- `POST /engagements/{id}/report` returns 202 with a job-shaped body whose
  `job_id` equals `report_id` and whose status is terminal (`done`).
- The stored bytes start with `%PDF-` and the recorded `byte_size`/`sha256`
  match the stored content exactly.
- The rendered text contains all five section headings, including the
  mandatory methodology & scope section with the authorized window and the
  `scope_doc_sha256` authorization reference.
- Allow-scope entries appear as tested scope and deny-scope entries appear as
  explicit exclusions.
- The severity breakdown reflects the engagement's open findings, and the
  detailed-findings section names each open finding.
- `GET /engagements/{id}/reports` lists the report as metadata without bytes;
  `GET /engagements/{id}/reports/{id}` returns `application/pdf` with content
  byte-identical to what was generated, and appends a `report_downloaded`
  audit entry.
- A report id belonging to a different engagement returns 404 on the download
  route.
- Generation appends a `report_generated` audit entry carrying the sha256.
- A run whose `state_reason` contains `coverage_degraded:` produces an
  explicit reduced-coverage warning in the report body.

## TC-REPORT-002: Credentials never reach the generated PDF

Requirements:

- REQ-REPORT-002

Automated tests:

- `control-plane/tests/test_report_redaction.py`
- `control-plane/tests/integration/test_report_generation.py`

Objective:

Prove that secrets which genuinely occur in real finding evidence, and in an
LLM explanation generated from that evidence, are absent from the distributed
document.

Expected results:

- **Negative test (the required R3 one):** a finding whose evidence carries a
  real-shaped bearer token, a session cookie, an API key, and a password, and
  whose cached Lens explanation repeats them in prose, produces a PDF whose
  bytes contain none of those secret values as substrings - asserted against
  the secret values themselves.
- Credential-named evidence keys are redacted with the key name preserved.
- A non-credential evidence field in the same blob remains fully readable.
- Nested (non-scalar) evidence values are skipped entirely, so raw
  request/response captures cannot enter the report field by field.
- `Bearer`, `Basic`, `Cookie:`, `X-Api-Key:`, `api_key=` and JWT shapes are
  redacted inside free prose, with the surrounding text left readable.
- Redaction is case-insensitive for key matching.
- Over-long values are truncated to the documented bound.

## TC-REPORT-003: The pipeline generates a real report without endangering the run

Requirements:

- REQ-REPORT-003

Automated tests:

- `worker/tests/test_report_phase.py`

Objective:

Verify the pipeline's phase-7 step produces a report bound to the run that just
finished, and that a reporting failure degrades to a recorded failure instead of
taking down a scan whose findings are already persisted.

Expected results:

- The report phase passes the finishing run's id through to the control plane,
  so the report is scoped to that run.
- A control-plane failure during the report phase is caught and returned as a
  failed result rather than propagating - an otherwise-successful scan run
  still completes.
- The pipeline calls the report phase with the current `scan_run_id`.

## TC-REPORT-004: The report action is visible in the console

Requirements:

- REQ-REPORT-004

Automated tests:

- `frontend/tests/report_generation_ui.test.mjs`

Objective:

Confirm the button reports what happened in every outcome, so it can never
again read as a dead control.

Expected results:

- The button is wired through a mutation with a pending state and is disabled
  while in flight.
- Request failure, backend-reported `status: "failed"`, and success each render
  a distinct message.
- A reports list renders previous reports with a download control that uses the
  authenticated download path.

## TC-REPORT-005: The report is professionally formatted and the redaction gate still holds

Requirements:

- REQ-REPORT-005

Automated tests:

- `control-plane/tests/integration/test_report_generation.py`

Objective:

Verify the new reportlab-based renderer produces the specified visual
structure, and re-verify - against the new renderer's actual output, not by
assumption - that REQ-REPORT-002's credential guarantee still holds.

Expected results:

- The document's first page (the cover) contains the engagement title and a
  confidentiality notice.
- Every content page's extracted text contains "CONFIDENTIAL" and a page
  number.
- The findings-summary table (rendered before the detailed-findings section)
  lists every open finding's severity, title, asset, and status.
- The risk-overview section's severity counts appear as a table, and the
  fixed risk-rating explanation paragraph is present.
- All REQ-REPORT-001 structural assertions (five sections, methodology facts,
  severity counts, diff, shadow-IT hints, degraded-coverage warning) still
  hold against the new renderer's text, extracted with a real PDF
  text-extraction library rather than a format-specific regex.
- **Re-verified negative test (R3 gate):** the REQ-REPORT-002 scenario (a
  finding whose evidence and cached Lens explanation carry a real-shaped
  bearer token, session cookie, API key, and password) produces a PDF whose
  extracted text and raw bytes contain none of those secret values, run
  against the reportlab renderer's actual compressed output.
- `app/pdf.py::simple_pdf` and the authorization-document route are
  unaffected: the authorization-summary PDF is still generated by the
  original writer, unchanged.
