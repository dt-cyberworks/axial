# Human-readable run activity

## Purpose

The run activity view is the operator explanation of a scan. It is derived
from the append-only audit stream but is not a raw audit-log renderer. The
Audit page remains the source for complete gateway and network evidence.

The activity view must let a human answer, in this order:

1. Is the run healthy, complete, waiting, failed, or stopped?
2. What phase is active, and what does that phase consume and produce?
3. What did the scanner actually do to which target?
4. Was the action authorized, blocked, throttled, or waiting for approval?
5. What did the executed tool discover, and did it finish successfully?
6. Is there anything that needs operator attention?
7. What did the Vector Agent conclude from the deterministic evidence?

## Information hierarchy

### Always visible

- Run state, current/last phase, elapsed time, and tool budget.
- Counts for completed tool executions, discovered services, blocked actions,
  and attention items.
- One human sentence summarizing the run outcome.
- The seven pipeline phases with status and compact event counters.
- High-signal events: DNS materialization outcome, tool completion/failure,
  blocks, throttling, approvals, incomplete LLM results, cancellation, and the
  final Vector Agent summary.

### Visible after expanding a phase or event

- What the phase uses, what it produces, and which phase consumes the result.
- Tool, authorized hostname, materialized IP, tested port range, service count,
  exit code, retry delay, and bounded error summary when available.
- Stable technical reason code and event source.
- Routine authorization and agent orchestration events.

### Audit only

- Full gateway arguments and unabridged audit payloads.
- Individual network requests and proxy evidence.
- Repeated low-level lifecycle checks.
- Hash-chain evidence.

## Translation rules

- Never show a raw snake_case reason as the primary event text.
- A gateway ALLOW means the action was authorized, not that execution
  succeeded. Success is taken only from a terminal tool-execution event.
- A DENY says explicitly that nothing was sent to the target when that is true.
- THROTTLE says that the worker paused and will retry; it must not look like a
  started or failed tool execution.
- PENDING says that execution is waiting for an operator decision.
- Empty, malformed, DNS-failed, or zero-target Nmap output remains a failure
  and is never summarized as a clean target.
- Unknown event types use a neutral fallback and retain their technical source
  without inventing an outcome.

## Layout

```text
┌ Run activity ─────────────────────────────────────────────────────────────┐
│ Human outcome sentence                                      View Audit → │
│ [Tools completed] [Services found] [Blocked] [Needs attention]           │
├ Phase tree ───────────────────────────────────────────────────────────────┤
│ ▸ Discovery        complete    1 result                                  │
│ ▾ Fingerprint      complete    4 tools · 1 failed                        │
│   Uses              Produces              Next step                       │
│   scoped assets     services + evidence   Correlate                       │
│                                                                          │
│   09:32  Nmap completed configured TCP discovery                 Completed     │
│          6 services found on 203.0.113.10 · ports 1–65535                │
│          ▸ Technical details                                              │
│                                                                          │
│ ▸ Correlate        complete    internal                                  │
│ ▸ Vector Agent     complete    12 observations · 1 blocked               │
│ ▸ Validate         complete                                               │
│ ▸ Risk scoring     complete                                               │
│ ▸ Report           complete                                               │
└──────────────────────────────────────────────────────────────────────────┘
```

The current phase, the latest high-signal phase, and phases with blocks or
attention items open automatically. Operators can show routine events when
debugging, but the default remains the high-signal human view. Each expanded
phase renders at most twelve recent events and reports how many older events
are hidden.

