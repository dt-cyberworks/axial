---
title: Live activity progress
status: implemented
risk: R1
owner: product-engineering
---

# Live Activity Progress Requirements

The Live operations page must help an operator understand scan progress while the scan is running. It should not be a raw gateway log. The raw audit trail remains available in Audit; Live operations presents the scan as a phase tree with expandable details.

## REQ-LIVE-001: Live activity is organized by main scan phase

The page must present the primary scan phases as the first-level structure, similar to a CI job page where high-level steps can be expanded.

Acceptance criteria:

- The UI renders a `Scan progress` section.
- Each pipeline phase is represented as an expandable progress node.
- Phase headers show status plus aggregated counts for events, allowed tool calls, blocked tool calls, approvals, and throttling where applicable.
- The page does not rely on a flat `Recent activity` list as the primary scan explanation.

## REQ-LIVE-002: Expanded phases show how one step feeds the next

Each phase expansion must explain what the phase consumes and what it produces, so the operator can understand how results from one phase become input to the next phase.

Acceptance criteria:

- Each phase has `Uses` and `Produces` handoff text.
- Each phase except the final phase identifies the next phase that consumes its output.
- Vector Agent is labeled as the attack-path validation phase, while internal phase id `agent` may remain for compatibility.

## REQ-LIVE-003: Detailed events remain bounded and phase-local

Detailed gateway/tool events are useful only after the operator expands a phase. The list must remain bounded to avoid the high CPU/memory behavior previously seen in the live UI.

Acceptance criteria:

- The SSE history limit is bounded.
- The in-memory log is bounded.
- Each expanded phase renders only a bounded number of recent detail events and reports hidden older events.
- Detailed gateway/network evidence remains delegated to the Audit page.

## REQ-LIVE-004: Activity events use human language and truthful outcomes

The run activity view shall translate audit events into concise operator language without changing the underlying evidence.

Acceptance criteria:

- Every visible event has a human title, an explanatory sentence, time, phase, and outcome label.
- Tool results show tool, authorized target, materialized IP, port range, discovered-service count, and failure context when available.
- Gateway authorization is not presented as successful execution; terminal success comes only from tool-execution evidence.
- Denied actions explain that nothing was sent to the target when applicable, and throttled actions explain that execution paused for a bounded retry.
- Raw reason codes and bounded technical facts remain available through progressive disclosure, while full evidence links to Audit.
- Unknown event types receive a neutral fallback without inventing a result.
- DNS materialization events count hosts and IPs from the audited `resolved` list evidence (one entry per hostname/IP pair); a materialization that actually resolved names to IPs is never displayed as "0 hostnames / 0 IPs / No target IP".

## REQ-LIVE-005: The default view prioritizes operator-relevant signals

The default activity view shall suppress orchestration noise and emphasize results, failures, blocks, approvals, and conclusions.

Acceptance criteria:

- A run summary shows completed tool executions, discovered services, blocked actions, and attention items.
- High-signal events remain visible by default; repeated lifecycle checks and duplicate authorization telemetry are marked routine and hidden by default.
- The operator can explicitly show routine events for debugging.
- Events needing attention use text labels as well as color and remain associated with their phase.

## REQ-LIVE-006: Activity is scoped to one run and remains bounded

The activity projection shall not mix events from earlier or later runs of the same engagement.

Acceptance criteria:

- Events outside the selected run start/finish window are excluded.
- An event carrying a scan-run identifier is included only when it matches the selected run.
- SSE reconnect duplicates are removed before rendering.
- The current phase opens automatically; the latest relevant phase and phases with blocks or attention items are surfaced automatically.
- Each expanded phase shows at most twelve recent events, and hidden older-event counts are disclosed.
