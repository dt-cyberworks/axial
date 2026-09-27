---
title: Operator console usability fixes (live run clock, authenticated downloads, asset-review table)
status: implemented
risk: R2
owner: product-engineering
---

# Operator Console Usability Fixes

Context: three separate console defects reported 2026-08-09 after live use.
They are grouped here because they are all "the console shows the operator
something wrong or nothing at all", but each has an independent root cause and
its own acceptance criteria.

**Risk class: R2.** REQ-RUNUI-001 and REQ-ASSETREVIEW-008 are presentation
only. REQ-DOWNLOAD-001 changes how an authenticated document is retrieved and
is the reason this document is not R1: the authorization PDF is the signature
document an operator sends to a customer before activating an engagement, so
a silently-failing download is a workflow and evidence problem, not a cosmetic
one. No server-side authorization, gateway, or audit behavior changes - the
endpoint and its `require_user` dependency are untouched; only the client's
retrieval path moves onto the app's designed authenticated path.

## REQ-RUNUI-001: Elapsed-time text on a live run advances on its own

Context: on the run detail page the banner shows `started 14s ago`, computed
by `fmtDuration(run.current_started_at, null)`, which reads `Date.now()` at
render time. Nothing drove re-renders on a clock, so the value sat frozen
until a page reload or a tab switch. The page's existing 4s `refetchInterval`
does not fix this: react-query's structural sharing means a refetch returning
an unchanged run row produces no re-render at all.

Acceptance criteria:

- While a run is in progress (`running` or `waiting_approval`), the elapsed
  time updates at least once per second with no reload or tab switch.
- The run header's total duration and the current-tool banner's "started X
  ago" both advance; they are the same defect in two places.
- The timer only runs while a run is in progress - a finished run schedules
  no interval, and the interval is cleared on unmount.
- `fmtDuration` takes the current time as an explicit parameter, so "which
  clock is this reading" is visible at the call site rather than being a
  hidden `Date.now()` side effect. When an end timestamp exists the parameter
  is ignored, which is why finished runs need no ticker.

## REQ-DOWNLOAD-001: Authenticated documents download through the authenticated path

Context: "Authorization PDF" opened a new tab at
`GET /engagements/{id}/authorization-pdf` via a plain
`<a href target="_blank">`, and rendered blank. That endpoint requires
`require_user`, but a bare anchor navigation is neither of the app's two
designed auth paths: it is not a `fetch()` (so no `Authorization: Bearer`
header) and cookie auth was only ever built and verified for EventSource,
which cannot send custom headers. The request therefore depended on the
session cookie happening to be sent, and a 401 rendered as an empty tab with
no error surfaced anywhere.

Acceptance criteria:

- Both call sites (engagement detail and the wizard's activation step) fetch
  the PDF through the app's authenticated request path, which attaches the
  bearer token, and save it via a Blob object URL.
- A failure is shown to the operator as a message including the status code,
  never as a blank page or a silent no-op.
- The saved filename uses the server's `Content-Disposition` when present, so
  the file on disk matches what the audit trail recorded being generated.
- The object URL is revoked on every path, including when the click handler
  throws, so blobs are not pinned in memory for the document's lifetime.
- The old `authorizationPdfUrl` helper is removed rather than kept alongside
  the new one - a bare navigable URL is precisely the broken pattern, and
  leaving it exported invites its reuse.

Security invariants:

- No change to `download_authorization_pdf`, its `require_user` dependency, or
  the `authorization_pdf_generated` audit entry. This requirement moves the
  client onto the already-designed authenticated path; it does not add,
  weaken, or bypass an authentication mechanism, and explicitly does not
  introduce a signed or token-bearing URL.

## REQ-ASSETREVIEW-008: The asset-review table fits its modal

Context: the "Review discovered assets" modal shows a 3-column table
(checkbox, Value, Type) inside `.modal-card`, capped at 620px. The shared
`.data-table` class carries `min-width: 760px`, sized for the app's wide
findings/audit tables, so `.responsive-table`'s `overflow-x: auto` engaged and
pushed the Type column behind a horizontal scrollbar.

This matters beyond aesthetics: deselecting a host in this modal is what
prevents it from being scanned, so an operator who does not notice the hidden
column is making a scope decision on partial information.

Acceptance criteria:

- All three columns are visible without horizontal scrolling at the modal's
  default width.
- The fix narrows this specific table rather than widening the modal or
  changing `.data-table` globally, so the app's genuinely wide tables keep
  their existing minimum width and scroll behavior.
- A regression test asserts the asset-review table does not use the shared
  760px minimum, so a future `.data-table` change cannot silently reintroduce
  the overflow.
