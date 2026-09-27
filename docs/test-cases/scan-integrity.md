---
title: Scan execution integrity verification
status: ready
risk: R4
owner: security-engineering
---

# Scan execution integrity verification

## TC-AGENT-007: Length-limited responses retry without execution

Requirements:

- REQ-AGENT-007

Automated tests:

- `worker/tests/test_agent.py`
- `frontend/tests/agent_finish_reason.test.mjs`

Objective:

Prove that provider truncation is visible, bounded, and cannot authorize an action.

Expected results:

- A length-limited response is retried within the configured bound.
- Exhausted retries produce no conclusion or dispatch.
- The UI displays `finish_reason=length` and an accurate empty-response label.

## TC-SCAN-007: Nmap uses only materialized, policy-protected targets

Requirements:

- REQ-SCAN-007
- REQ-SCAN-008

Automated tests:

- `worker/tests/test_scan_integrity.py`
- `control-plane/tests/integration/test_tool_execution_audit.py`

Objective:

Prove that raw-network execution is deployment-gated, IP-bound, and truthfully recorded.

Expected results:

- Compose mode records Nmap as unavailable without dispatch.
- Scope-restricted mode dispatches the materialized IP.
- DNS/zero-target output is unsuccessful and cannot become a clean result.
- Fingerprint services reach correlation.

## TC-EGRESS-003: Proxy concurrency is bounded

Requirements:

- REQ-EGRESS-003

Automated tests:

- `egress-proxy/tests/test_backpressure.py`
- `egress-proxy/tests/test_audit_client.py`

Objective:

Prove that scanner bursts cannot exhaust proxy execution capacity or bypass audit.

Expected results:

- No more than the configured number of clients enter the request handler.
- Excess clients receive `503 proxy_capacity_exhausted`; new clients proceed after capacity is released.
- Audit submission failure still denies the request.

## TC-SCAN-009: Signed lease enforces Compose raw egress

Requirements:

- REQ-SCAN-009

Automated tests:

- `control-plane/tests/integration/test_raw_egress_lease.py`
- `raw-egress-gateway/tests/test_gateway.py`
- `worker/tests/test_raw_nmap.py`

Objective:

Prove that only the authorized materialized target receives a temporary TCP
egress rule and that invalid, concurrent, expired, or failed leases remain
deny-all.

Expected results:

- Valid control-plane leases activate one exact target and expire automatically.
- Tampered, stale, unmaterialized, and out-of-scope targets are denied.
- A second run receives a FIFO reservation without target egress and proceeds
  only after the active run deactivates and releases its slot.
- Policy installation and revocation failures are not reported as clean scans.

## TC-SCAN-010: Complete authorized TCP discovery feeds bounded service detection

Requirements:

- REQ-SCAN-010

Automated tests:

- `worker/tests/test_raw_nmap.py`
- `worker/tests/test_nmap_parse.py`

Objective:

Prove that complete authorized TCP discovery precedes service detection and that only open
ports enter the second scan and persistence pipeline.

Expected results:

- The first invocation covers the persisted engagement range (default
  `1-65535`) with the configured rate and timeout.
- The second invocation receives only the sorted open-port list.
- XML services are parsed and malformed results fail without a clean conclusion.


## TC-SCAN-014: A run with no successful load-bearing detection is reported as degraded

Requirements:

- REQ-SCAN-014

Automated tests:

- `worker/tests/test_pipeline_coverage_degradation.py`
- `frontend/tests/scan_coverage_degradation.test.mjs`

Objective:

Verify a scan run whose port-discovery or HTTP-liveness tooling never
succeeded is visibly reported as reduced-coverage rather than as a clean
completion, and — critically — that a successful scan which legitimately found
nothing is NOT flagged.

Expected results:

- All nmap attempts failing -> `state_reason` carries
  `coverage_degraded:nmap=<reason>`.
- All httpx attempts failing -> the same for httpx; both degraded -> both named.
- NEGATIVE: nmap/httpx succeeding with zero findings -> no warning at all.
- NEGATIVE: a tool never attempted -> no warning.
- NEGATIVE: partial success (one failure, one success) -> no warning.
- NEGATIVE: a non-load-bearing tool (nikto, testssl) failing -> no run-level
  warning.
- Coverage and agent-incomplete warnings combine rather than overwrite.
- Per-run isolation: one run's failures never appear in another run's warning.
- The accumulator is released by `clear_coverage`, and distinct failure
  reasons are bounded.
- The run detail view renders a distinct "reduced coverage" indicator and an
  explanation stating the result is not a clean bill of health.
