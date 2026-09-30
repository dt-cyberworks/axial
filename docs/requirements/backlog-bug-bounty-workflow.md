---
title: Bug-bounty workflow (scope import and submission export)
status: backlog
risk: R3
owner: product-engineering
---

# Bug-Bounty Workflow

From the 2026-09-27 review (finding A6): program policy is modeled well,
but scope is typed by hand and there is no way to turn a finding into a
submission.

## REQ-BBW-001: Import program scope from the platform

Acceptance criteria:

- For Intigriti and HackerOne programs, an operator can import the
  program's in-scope and out-of-scope assets and its policy fields
  (identification header, rate limits) into a bug-bounty engagement.
- The import creates a reviewable proposal; nothing becomes active scope
  until the operator confirms it (existing activation and attestation
  rules unchanged).
- [Negative test] Out-of-scope entries become deny rules, and wildcards or
  assets the scanner cannot express are listed as needing manual handling,
  never silently widened.

## REQ-BBW-002: Export a finding as a submission draft

Acceptance criteria:

- A finding can be exported as Markdown in the usual submission shape:
  title, severity, affected asset, summary, steps to reproduce (from
  recorded evidence and agent steps), impact, and remediation.
- The export applies the same redaction as the PDF report.

Value and context:

- Removes manual copying between platform and scanner, and reduces
  scope mistakes when typing assets by hand.

Open questions and dependencies:

- Platform API credentials (per user? admin setting?) and their storage.
- Terms of service of each platform for automated scope retrieval.

Implementation authorization:

- None until this requirement is promoted out of `backlog` through SDLC
  review by johannes.

Backlog decision log:

- 2026-09-27 — proposed by the review agent.
- 2026-09-29 — johannes: not needed yet; stays in backlog, deferred.

Security invariants:

- Imported scope is a proposal; the operator's confirmation, attestation,
  deny precedence, and the gateway remain the only way anything becomes
  scannable.
