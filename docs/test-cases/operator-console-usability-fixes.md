---
title: Operator console usability fixes verification
status: ready
risk: R2
owner: product-engineering
---

# Operator Console Usability Fixes Verification

Verifies [`../requirements/operator-console-usability-fixes.md`](../requirements/operator-console-usability-fixes.md).

## TC-RUNUI-001: The live run clock advances on its own

Requirements:

- REQ-RUNUI-001

Automated tests:

- `frontend/tests/live_run_clock.test.mjs`

Objective:

Confirm a ticking clock exists, is gated on the run being in progress, is
cleaned up, and is actually consumed by both elapsed-time call sites - so the
"frozen timer" defect cannot reappear through any one of those links breaking.

Expected results:

- A ticker hook sets an interval of 1000ms and clears it on cleanup.
- The interval is only scheduled while active; an inactive ticker returns
  early without scheduling.
- `RunDetail` calls the ticker with its `isRunning` flag.
- Both `fmtDuration` call sites in `RunDetail` (the header duration and the
  current-tool banner) pass the ticking value.
- `fmtDuration` accepts the current time as an explicit third parameter and
  ignores it when an end timestamp is present.

## TC-DOWNLOAD-001: Authorization PDF downloads through the authenticated path

Requirements:

- REQ-DOWNLOAD-001

Automated tests:

- `frontend/tests/authenticated_document_download.test.mjs`

Objective:

Prove the document is fetched with the bearer token and saved as a Blob, that
failures become visible, and that the broken bare-anchor pattern is gone from
the codebase rather than merely unused.

Expected results:

- The client has a blob-download helper that attaches
  `Authorization: Bearer` and reads the response as a Blob.
- A non-OK response throws an error carrying the status code.
- The object URL is revoked in a `finally` block.
- The saved filename comes from `Content-Disposition` when present.
- `authorizationPdfUrl` no longer exists anywhere in the frontend source, and
  neither call site uses `<a href=... target="_blank">` for the PDF.
- Both call sites render a pending state and surface an error message.

## TC-ASSETREVIEW-008: The asset-review table fits the modal

Requirements:

- REQ-ASSETREVIEW-008

Automated tests:

- `frontend/tests/asset_review_table_width.test.mjs`

Objective:

Confirm the asset-review table is exempted from the shared wide-table minimum
without changing that minimum for the app's genuinely wide tables.

Expected results:

- The asset-review table carries the compact modifier class.
- A CSS rule sets `min-width: 0` for that modifier on `.data-table`.
- `.data-table`'s own 760px minimum is unchanged, so findings/audit tables
  keep their existing behavior.
