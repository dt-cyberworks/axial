---
title: Global approval surfacing verification
status: ready
risk: R2
owner: engineering
---

# Global Approval Surfacing Verification

Verifies [`../requirements/global-approval-surfacing.md`](../requirements/global-approval-surfacing.md).

## TC-APPROVALUI-001: The approval popup is surfaced app-wide

Requirements:

- REQ-APPROVALUI-001

Automated tests:

- `frontend/tests/global_approval_surfacing.test.mjs`

Objective:

Verify a single approval watcher is mounted in the authenticated shell, polls
the caller-scoped pending-approvals queue, and renders the shared approval
popup — and that the Run detail view no longer renders its own separate popup.

Expected results:

- `App.tsx` imports and renders `<GlobalApprovalWatcher />` inside the
  authenticated shell (so it is present on every page and never on login).
- `GlobalApprovalWatcher` polls `GET /approvals?state=requested` and renders the
  shared `ApprovalModal`, which names the owning engagement and keeps What / Why
  / Risk and Approve / Reject.
- `RunDetail.tsx` contains no local `ApprovalModal` definition or render; it
  defers to the global watcher.
- The frontend `tsc --noEmit` build gate passes with the new components.

## TC-APPROVALUI-002: Approving jumps to the run

Requirements:

- REQ-APPROVALUI-002

Automated tests:

- `frontend/tests/global_approval_surfacing.test.mjs`

Objective:

Verify that approving navigates to the approval's own run so the operator can
watch the write execute, while rejecting does not navigate.

Expected results:

- The watcher uses `useNavigate` and, on the approve branch only, navigates to
  `/engagements/{engagement_id}/runs/{scan_run_id}` derived from the approval's
  stored `tool_call.scan_run_id`.
- When `scan_run_id` is absent, navigation falls back to the engagement page
  rather than failing.
- The reject branch performs no navigation.
