---
title: Discovery and detection coverage verification
status: ready
risk: R3
owner: security-engineering
---

# Discovery and Detection Coverage Verification

Verifies [`../requirements/discovery-detection-coverage.md`](../requirements/discovery-detection-coverage.md).

## TC-COVER-001: The takeover tag runs and exclusions hold (worker)

Requirements:

- REQ-COVER-002

Automated tests:

- `worker/tests/test_nuclei_tags.py`

Objective:

Prove the dedicated takeover pass carries `takeover` (and the main pass does
not), that the fingerprint phase dispatches it, and that it still excludes the
intrusive, dos, fuzz and csp-bypass tags.

Expected results:

- The takeover and exclusion tests in the file pass.

Manual/live verification:

- Dev run against a target with a dangling record; record the finding and the
  added run time in the follow-up 08 document.

## TC-COVER-002: Retired tools are off and denied (control plane)

Requirements:

- REQ-COVER-005

Automated tests:

- `control-plane/tests/test_tool_registry.py`
- `control-plane/tests/integration/test_enabled_tools_dispatchable.py`
- `control-plane/tests/integration/test_gateway_lab.py`

Objective:

Prove the retired tools are not default-enabled, that every enabled tool has a
caller or a documented exception, and that the gateway denies the retired tools.

Expected results:

- The registry, dispatchability and retired-tool denial tests pass.

## TC-COVER-010: The main pass runs as bounded, typed selections (worker + gateway)

Requirements:

- REQ-COVER-002

Automated tests:

- `worker/tests/test_nuclei_tags.py`
- `control-plane/tests/integration/test_extended_discovery.py`

Objective:

Prove every selection keeps the conservative flags, that the selection command and the
template index share their tag set, exclusions and directories, that a malformed
selection never becomes a command, that hits from a timed-out pass become findings while
the pass is not recorded complete, and that the gateway accepts only the typed shape.

Expected results:

- Group `generic`, `products` and `all` with valid shards and product keys are allowed;
  paths, tags, `part`, wrongly typed values, bad shards and bad product keys are
  `unsafe_arguments`.
- Every selection carries the full tag set, `-etags intrusive,dos,fuzz,csp-bypass`, the
  excluded template ids, `-no-interactsh` and the rate limit.

Manual/live verification:

- `nuclei -tl` in the tool-runner: the index equals the former single pass minus `network/`
  and `javascript/` (5,883 templates, 2026-09-30).
- A live dev scan: each selection of about 400 templates finishes well within its budget.
