---
title: Global approval surfacing and jump-to-run on approve
status: implemented
risk: R2
owner: engineering
---

# Global Approval Surfacing

Context: when the Vector Agent proposes a state-changing HTTP request, the
scan run enters `waiting_approval` and a popup asks the operator to approve or
reject it (REQ-APPROVAL-001..003 in
[`manual-approval-and-full-http.md`](manual-approval-and-full-http.md)). That
popup is only rendered inside the Run detail view and only for the current
engagement. If the operator is anywhere else in the console — the dashboard,
settings, documentation, another engagement — the pending approval is
invisible, so the agent silently waits until the request expires. Operators
miss approvals simply because of where they happen to be standing.

**Risk class: R2.** This is a presentation/navigation change in the operator
console. It does **not** change who may approve, how approvals are authorized,
or how the approved call is re-authorized and executed — those remain governed
by REQ-APPROVAL-001..003 and the Scope Gateway (the approve/reject endpoints
and the atomic claim/re-authorization are unchanged). Verification is the
frontend structural test plus the `tsc` build gate, consistent with the other
operator-console requirements.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

## REQ-APPROVALUI-001: The approval popup appears anywhere in the console

A pending approval must reach the operator regardless of the current screen.

Acceptance criteria:

- A single global watcher, mounted in the authenticated app shell, polls for
  the caller's pending approvals (`GET /approvals?state=requested`, already
  scoped server-side to the caller's own engagements / all for admins) and
  renders the approval popup over whatever page is currently shown.
- The popup shows the same What / Why / Risk detail and Approve / Reject
  actions as before (REQ-APPROVAL-002), plus which engagement the request
  belongs to (since the operator may be viewing something unrelated).
- When more than one approval is pending, they are presented one at a time
  (the others remain queued and surface after the current one is decided),
  with an indication that more are waiting.
- The watcher is only active for an authenticated operator and never appears on
  the login screen.
- The Run detail view no longer renders its own separate approval popup; the
  global watcher is the single surface, so the popup can never double-render.

## REQ-APPROVALUI-002: Approving jumps to the run so execution is visible

After approving, the operator is taken to the run so they can see the approved
request actually execute — approval is not a fire-and-forget action.

Acceptance criteria:

- On **approve**, once the decision is recorded, the console navigates directly
  to the Run detail screen of the approval's own run
  (`/engagements/{engagement_id}/runs/{scan_run_id}`, taken from the approval's
  stored `tool_call.scan_run_id`), where the resuming agent and the approved
  request's execution are shown live.
- If the approval carries no `scan_run_id` (defensive), the console navigates to
  that approval's engagement page rather than failing.
- On **reject**, no navigation happens — there is nothing to watch; the popup
  closes and any further queued approval is shown.
