---
title: Scan run resume after worker loss
status: implemented
risk: R3
owner: security-engineering
---

# Scan Run Resume After Worker Loss

GitHub issue #42 (the "real resume" follow-up to #29). A scan can run for
hours. When its worker process died (deploy, crash, out-of-memory kill), the
periodic reaper aborted the run and all work was lost; the operator had to
start over, and every target was contacted again from the beginning.

The run now continues instead: the reaper queues a new worker task for the same
run, and that task picks up at the phase after the last one that completed.

**Risk class: R3.** A resumed run sends real traffic. Resuming re-queues the
same `scan_run` only: it never widens scope, never skips a check, and every
target contact of a resumed phase goes through the Scope Gateway like any other.
Negative tests prove a finished or cancelled run is never resumed and that a
replaced worker cannot write.

**Security review:** approved by johannes (project/security owner) on
2026-09-29 ("I approve all changes"), after the negative tests and the
mutation checks listed in the linked test cases. Live verification on the
dev stack is still owed at deploy time and is recorded in the test case.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

---

## REQ-RESUME-001: A run remembers where it stopped

Acceptance criteria:

- `scan_run.checkpoint` (JSON) holds what the next phase needs: the discovered
  assets (before and after asset review), the fingerprinted services, the agent
  and coverage warnings, and the task parameters. It is written together with
  the phase transition, so the phase and its input never disagree.
- The checkpoint is internal: no operator-facing API returns it.
- A checkpoint that lacks the input of the recorded phase makes the run restart
  at the earlier phase that produces it, never continue with missing input.

## REQ-RESUME-002: One worker attempt owns a run at a time

Acceptance criteria:

- A worker task claims its run before doing anything. Each claim raises
  `scan_run.attempt`; the response carries the phase and checkpoint to continue
  from.
- [Negative test] A claim on a finished (`done`, `failed`, `aborted`) or unknown
  run is refused.
- [Negative test] A claim by a different task while the current attempt has
  shown life within the stale window is refused, so a duplicate delivery of the
  same message never runs a scan twice in parallel.
- Every later write by a worker (phase update, cancel poll, heartbeat) carries
  its attempt. [Negative test] A write from a replaced attempt is refused with
  409 and the worker stops without writing anything more.

## REQ-RESUME-003: The reaper resumes a lost run instead of aborting it

Acceptance criteria:

- A claimed run whose heartbeat is stale is queued again for a new worker task
  (same run, same task parameters) and gets a fresh heartbeat; an audit entry
  `scan_run_resumed` records it.
- At most `scan_max_resumes` (default 2) resumes per run; after that the run is
  aborted as before (`reaped_stale_heartbeat`).
- [Negative test] A run the operator asked to cancel is never resumed.
- A run that was never claimed, or whose queueing fails, is aborted as before.

## REQ-RESUME-004: A worker that waits is alive

Acceptance criteria:

- A cancel-flag poll from the run's current attempt refreshes the heartbeat, so
  a worker waiting for an operator's approval or asset review is not mistaken
  for a lost one.
- [Negative test] A poll from a replaced attempt does not refresh it.

## REQ-RESUME-005: A resumed run behaves like an uninterrupted one

Acceptance criteria:

- Phases that completed are not run again; the run continues at the recorded
  phase with the stored task parameters.
- Cancellation, the asset-review gate, the coverage-degradation warning and the
  agent-incomplete warning apply to a resumed run exactly as to a fresh one; a
  warning recorded before the crash is still present in the final state.
- A superseded task ends quietly (no failed state, no further writes).
- The agent phase restarts from its beginning when the loss happened inside it;
  the tool-call budget already used stays counted.
