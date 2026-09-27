---
title: Scan-run workflow and transparency
status: implemented
risk: R2
owner: product-engineering
---

# Scan Run Workflow, Control & Transparency Requirements

This document is the requirement source for the operator-facing scan-run
lifecycle, the engagement → run → run-detail navigation model, agent
transparency, and in-app documentation. Tests must verify these requirements
directly. Do not weaken tests to match implementation; update implementation
when it violates this document.

Context: a scan is a `scan_run` belonging to an `engagement`. Findings are
engagement-wide and de-duplicated by fingerprint; per-run granularity comes from
`finding_observation`. The operator must be able to start, watch, understand,
and stop individual runs, and to inspect exactly what the Vector Agent did.

---

## REQ-RUN-001: Running scans can be stopped from the GUI

An operator must be able to stop an active scan, including while it waits for a manual approval.

Acceptance criteria:
- A run in `running` or `waiting_approval` exposes a `Stop scan` action in the GUI.
- The backend exposes `POST /engagements/{engagement_id}/scan-runs/{run_id}/cancel`.
- The endpoint atomically records `cancel_requested=true`, terminal state
  `aborted`, `state_reason=cancelled_by_operator`, and `finished_at`; the GUI
  therefore shows a completed stop even if a worker disappeared or restarted.
- Pending, approved, or executing manual approvals bound to that exact run are
  closed as `cancelled`; approvals belonging to another run remain unchanged.
- Every target-touching fingerprint/agent authorization and runner request is
  bound to the exact `scan_run_id`. The gateway denies a missing, foreign,
  cancelled, or non-running run and serializes authorize-vs-cancel on that row.
- The worker checks cancellation at every phase/tool boundary and while a tool is
  running. Under a healthy control plane and runner, an in-flight HexStrike
  process group is terminated within 15 seconds without terminating another
  run's process; Nmap then revokes its active raw-egress lease in `finally`.
- If cancellation status cannot be obtained, target-facing execution fails
  closed and the process is terminated instead of silently continuing.
- A cancelled run is terminal and immutable: delayed/stale worker updates cannot
  change its phase, state, reason, or finish time.
- Deployment reconciles historical `cancel_requested=true` rows left active by
  the former implementation, idempotently and without touching other runs.
- Cancelling a terminal/non-active run returns 409 and does not change state.
- Starting a second run while one is `running` or `waiting_approval` returns 409.

## REQ-RUN-002: Blocking conditions are checked before a scan starts

Starting a scan that cannot succeed (e.g. outside the authorized time window)
must be prevented up front, not by letting every tool call be denied at runtime.

Acceptance criteria:
- The backend exposes `GET /engagements/{engagement_id}/scan-readiness` returning
  `{ ready: bool, blockers: [{code, message}] }`.
- Readiness checks mirror the gateway's engagement-wide blocking conditions:
  engagement is `active`; `now` is within `[authorized_from, authorized_until]`;
  at least one active-allowed in-scope asset exists; at least one active tool
  grant exists; for `bug_bounty`, a bounty program with an identification header
  is configured.
- `POST /engagements/{id}/scan` refuses with `409` and the blocker list when not
  ready; it does not enqueue a doomed run.
- The GUI shows readiness and blockers before the `Start run` action and disables
  the action when not ready.

## REQ-RUN-003: Phase view shows the tools used in each phase

Each pipeline phase in the progress view must indicate which tools it uses, so
the operator understands what actually runs.

Acceptance criteria:
- Each phase node lists the concrete tools it may dispatch (e.g. Fingerprint:
  httpx, nmap, nikto, wafw00f, testssl; Vector Agent: httpx, nmap, nikto,
  wafw00f, testssl, nuclei, http_request, ffuf).
- Phases that run no external tools (Discovery-internal, Correlate, Validate,
  Risk scoring, Report) are labelled as internal / no target-touching tools.
- The tool list is visible when a phase is expanded.

## REQ-RUN-004: Phase-transition log noise is removed from the operator view

The raw "Pipeline moved to X" phase-transition entries must not clutter the
operator-facing activity view.

Acceptance criteria:
- `scan_run_transition` audit entries are not rendered as activity rows in the
  live/run detail event lists.
- Phase progress/state is still derived correctly (from the run's phase/state),
  independent of those entries.
- The full audit trail (including transitions) remains available on the Audit
  view for compliance.

## REQ-RUN-005: Consistent Engagement → Run → Run-detail navigation

The GUI navigation model must make it unambiguous what the user is looking at.

Acceptance criteria:
- The main page lists engagements (existing Overview).
- Clicking an engagement opens an **Engagement detail** page showing engagement
  summary, scope/agent readiness, aggregate findings summary, and a **list of its
  runs**, with a `Start run` action.
- Each run in the list shows run number, started/finished, duration, phase, state.
- Clicking a run opens a **Run detail** page scoped to that run.
- Run detail presents run-scoped views as tabs: Progress, Diff (vs previous run),
  Agent (steps), and Log (run-scoped activity).
- A breadcrumb (Engagements → {engagement} → Run #{n} → {tab}) is always visible.
- Engagement-wide findings live on the Engagement detail page; run-scoped deltas
  (diff, agent steps, log) live on the Run detail page.

## REQ-RUN-006: Vector Agent steps are drillable (prompt + response)

The operator must be able to see, per agent step, the input given to the model
and the model's response, to make agent behavior transparent.

Acceptance criteria:
- Each Vector Agent iteration is persisted with: iteration index, the request
  context sent to the model (system prompt + messages), the model's raw response
  text, and any tool calls it produced.
- The backend exposes `GET /engagements/{id}/scan-runs/{run_id}/agent-steps`.
- The Run detail `Agent` tab lists steps; clicking a step expands to show the
  full input prompt and the full model response for that step.
- Persistence is internal/operator-only; API keys are never stored or returned.
- If no agent steps exist (agent did not run), the tab states so clearly.
- Each iteration's persisted `request_messages` is the full cumulative
  conversation at that point (system prompt + every prior turn), which is
  correct for the audit record but must not be *displayed* in full for every
  step: the expanded view shows only the messages new since the previous
  step (the full initial context once, for step 1), so the tab reads as one
  growing conversation rather than repeating the same early turns at every
  iteration.

## REQ-DOC-001: In-app user documentation

The application must provide human-facing documentation, reachable from the GUI,
that explains every screen, function, and field.

Acceptance criteria:
- A `Help` / `Documentation` entry is present in primary navigation and routes to
  an in-app documentation page (no external site required).
- The documentation covers each screen (Overview, Engagement detail, Run detail
  and its tabs, New engagement wizard, Agent settings, Audit) and explains every
  field and action shown there, in plain language, including what it is and how
  to use it.
- The documentation explains the core safety model in operator terms (Scope
  Gateway decides every tool call; agent proposals are advisory; runs are
  cooperative-cancellable; findings accumulate and de-duplicate across runs).
- The documentation is navigable (section index / anchors).
