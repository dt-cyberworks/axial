---
title: Scan run resume verification
status: ready
risk: R3
owner: security-engineering
---

# Scan Run Resume Verification

Verifies [`../requirements/scan-run-resume.md`](../requirements/scan-run-resume.md).

## TC-RESUME-001: Claim, fencing and checkpoint (control plane)

Requirements:

- REQ-RESUME-001
- REQ-RESUME-002
- REQ-RESUME-004

Automated tests:

- `control-plane/tests/integration/test_scan_run_resume.py`

Objective:

Prove the claim raises the attempt and returns the checkpoint, is refused for
finished runs and live foreign attempts, and that a replaced attempt cannot
write, poll-refresh or heartbeat.

Expected results:

- `test_claim_*`, `test_negative_claim_*`, `test_negative_a_replaced_attempt_*`,
  `test_checkpoint_*`, `test_a_cancel_poll_*`.

## TC-RESUME-002: The reaper resumes, within limits

Requirements:

- REQ-RESUME-003

Automated tests:

- `control-plane/tests/integration/test_scan_run_resume.py`

Objective:

Prove a claimed stale run is re-queued with its stored parameters and audited,
and that cancelled, never-claimed, over-budget and unqueueable runs abort.

Expected results:

- `test_reaper_resumes_*`, `test_negative_reaper_does_not_resume_*`.

## TC-RESUME-003: The pipeline continues at the recorded phase (worker)

Requirements:

- REQ-RESUME-001
- REQ-RESUME-005

Automated tests:

- `worker/tests/test_pipeline_resume.py`

Objective:

Prove a resumed task skips completed phases, feeds later phases from the
checkpoint, keeps earlier warnings, stops quietly when superseded, and does not
run at all when the claim is refused.

Expected results:

- `test_resume_*`, `test_negative_*`.

## Live verification (2026-09-30/10-01, dev stack)

Not planned as a test: the host of the dev stack was rebooted in the middle of a real scan
(engagement "breakout test", `standard`, run `01a0f3b5`, killed mid-fingerprint). After the stack
was started again the periodic reaper resumed the run by itself:

- Exactly one `scan_run_resumed` audit row (`reason=worker_lost`, `phase=fingerprint`, `attempt=1`).
- The run took attempt 2 and continued with the checks that were not finished: the 10 checks that
  were `complete` kept `attempt=1` and were not run again, the 10 skipped ones stayed skipped, and
  only the check that was `running` at the kill (`nuclei:generic:3of5`) ran again (`attempt=2`).
- It then went on through correlate and the agent phase and ended `done` with
  `coverage_partial:nuclei=1` (that check reached its own time budget, as recorded honestly),
  with exactly one terminal transition.

Controlled kills (2026-10-01, dev, a real scan of the project's own confirmed-safe external target per run; the worker container
was killed with SIGKILL, started again four seconds later, and nothing else was done by hand):

- **Killed inside discovery** (before any check existed): the reaper resumed the run by itself after
  the stale window; exactly one `scan_run_resumed`; the run took attempt 2, started over from
  discovery (REQ-RESUME-005: that phase restarts from its beginning), went through fingerprint,
  correlate, agent, score and report, and ended `done` with exactly one terminal transition.
- **Killed inside the agent phase** (15 checks complete, the agent had taken its first step): the
  run resumed by itself, took attempt 2 and ended `done`; after the resume no earlier phase ran
  again (the transitions after it are only score and report), no discovery or fingerprint tool ran
  again, no check was run again (all kept `attempt=1`), one `scan_run_resumed`, one terminal
  transition.

Together with the mid-fingerprint resume above, every phase boundary the issue names (discovery,
fingerprint mid-check, agent) has been killed and resumed on a live stack. What is deliberately not
done: `acks_late` was not enabled (johannes decided on 2026-09-30 to close the issue without it: the
approved design resumes through the reaper and the attempt fencing, and a lost run is resumed or
aborted, never silently gone).
