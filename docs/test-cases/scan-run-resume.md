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
