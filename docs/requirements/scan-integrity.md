---
title: Scan execution integrity and truthful agent outcomes
status: approved
risk: R4
owner: security-engineering
---

# Scan execution integrity

## REQ-AGENT-007: Incomplete model output never becomes a conclusion

The Vector Agent shall distinguish a complete assistant response from a
provider response truncated by its output limit.

Acceptance criteria:

- `finish_reason=length` is recorded as incomplete and never as a conclusion.
- An incomplete response never dispatches a tool call.
- The worker retries an incomplete response at most the configured bounded
  retry count and uses a bounded larger output budget.
- Exhausted retries produce an audited degraded-agent reason while the
  deterministic pipeline may finish.
- The operator UI shows the actual finish reason and distinguishes empty
  responses from responses containing only tool calls.

## REQ-SCAN-007: Raw-network tools require an enforced egress mode

Nmap and other raw-network tools shall run only when the workload environment
asserts that a current, per-engagement network allowlist is enforced.

Acceptance criteria:

- Compose enables raw-network execution only when the deny-all lease gateway confirms policy enforcement.
- Missing/unhealthy gateway state records Nmap as unavailable and does not dispatch.
- In scope-restricted mode, Nmap receives the audited materialized target IP
  while authorization remains bound to the original hostname.
- Missing materialization fails closed.
- No implementation enables general runner Internet egress as a shortcut.

## REQ-SCAN-008: Tool execution results are truthful and durable

Tool transport success shall not be confused with successful target execution.

Acceptance criteria:

- DNS failures, zero-target Nmap output, non-zero exits, and runner-declared
  failure are unsuccessful even when the runner HTTP response is `200`.
- A hash-chained audit event persists tool, phase, scan run, authorized target,
  resolved target, port range, success, exit code, bounded stderr summary, and
  discovered-service count.
- Empty or failed Nmap output is never described as a clean port scan.
- Fingerprint results are passed to the correlation phase.

## REQ-EGRESS-003: Proxy work is bounded

The egress proxy shall bound concurrent client handling and audit submissions
so a scanner burst cannot exhaust process file descriptors.

Acceptance criteria:

- A configured concurrency limit applies backpressure before opening target or
  audit connections.
- Excess connections receive explicit fail-closed backpressure instead of bypassing audit.
- Audit failure remains fail-closed.
- Tests prove the concurrency limit and recovery after a request completes.

## REQ-SCAN-009: Compose raw egress is lease-bound and fail-closed

Nmap in Docker Compose shall execute only while a control-plane-signed,
short-lived lease is enforced in a dedicated network namespace.

Acceptance criteria:

- The Scope Gateway authorizes the exact Nmap target and scan profile before a
  lease is signed.
- A lease binds one engagement, scan run, authorized hostname, audited
  materialized IP, TCP port envelope, rate ceiling, nonce, and expiry.
- The raw-egress gateway starts deny-all, accepts only authentic bounded
  leases, permits only their destination IP/ports, and automatically closes
  egress at expiry.
- The offensive runner has `NET_RAW` only; `NET_ADMIN` and Docker socket access
  remain outside the runner.
- Compose admits one active raw lease and uses bounded FIFO reservations so
  concurrent engagements wait without sharing or replacing a mutable allowlist.
- Gateway absence, invalid/stale lease, policy installation failure, or cleanup
  failure is surfaced as an unsuccessful scan, never as a clean target.

## REQ-SCAN-010: Nmap performs complete authorized TCP discovery before fingerprinting

For authorized own-domain/customer targets, Nmap shall discover the complete
persisted engagement TCP envelope before running service detection only on
open ports.

Acceptance criteria:

- Discovery uses the audited materialized IP, no runner-side DNS, TCP SYN,
  `-Pn`, `-n`, the explicit persisted range (default `1-65535`), maximum packet
  rate, retry bound, and host timeout.
- Service/version detection runs only for ports proven open by discovery.
- Machine-readable XML is parsed; malformed or empty output fails truthfully.
- The execution record distinguishes the tested range and number of open
  services.
- Bug-bounty or other constrained sources may select a narrower approved
  profile; widening is never controlled by an LLM-provided raw argument.


## REQ-SCAN-014: A run with no successful load-bearing detection is reported as degraded, not clean

**Risk class: R2** (worker orchestration + read-back of telemetry that is
already persisted; no Scope Gateway, authorization, or egress change).

Context: this is REQ-SCAN-008's principle ("tool transport success is not
target-execution success") applied one level up, at the *run*. Today every
tool failure is recorded honestly per execution — and then the run finishes
`state="done"` regardless. `fingerprint._nmap_scan` records the failure, logs
a warning and returns `[]`; `pipeline` carries on. The same early-return shape
applies to `_web_enum`, `_waf_detect`, `_tls_scan` and `_nuclei_pass`.

The consequence is that **a run in which every nmap execution failed is
indistinguishable, at the run level, from a clean scan of a host with nothing
open.** Measured live 2026-08-03: the benchmark tool-runner was built from an
image that never applied `setcap` to nmap, so every `-sS` failed; the run
still reported `done`, the operator-visible outcome was "fewer findings", and
the ensuing investigation spent hours pursuing a nonexistent host-level kernel
restriction (`docs/benchmarking/benchmark-design.md` §18.2). Had the run said
"nmap: attempted 4, succeeded 0", the cause would have been immediate.

For a customer engagement the same failure mode silently under-reports the
attack surface — the most damaging possible outcome for an ASM product,
because it is invisible.

Acceptance criteria:

- A run in which a load-bearing tool was attempted at least once and **never
  once succeeded** is reported as coverage-degraded, with the tool name(s) and
  distinct failure reason(s), on both the run record and the operator UI.
- Load-bearing means a tool whose total failure guts detection rather than
  narrowing it: `nmap` (sole input to the correlate phase; without it a
  non-HTTP service is never seen at all) and `httpx` (gates the entire web
  suite). A failure of e.g. nikto alone is not run-level degradation.
- **A tool that ran successfully and legitimately found nothing is never
  flagged.** "No findings" and "no coverage" must remain clearly distinct —
  conflating them would make the signal worthless and train operators to
  ignore it.
- A tool that was never attempted (no in-scope asset called for it) is not
  degradation.
- Partial success (one host unreachable, others scanned) is not degradation.
- The coverage warning and an independent agent-incompleteness warning are
  both surfaced when both apply; neither replaces the other.
- The degraded state is a *warning*, not a failure: the run still completes
  and its real findings are still persisted and reported.
- Per-run accumulation is isolated between concurrently executing runs and is
  released on every exit path (done, aborted, failed).

**Live gap found and fixed (2026-08-09):** the acceptance criteria above were
implemented and approved against the deterministic fingerprint phase only.
`worker/app/tasks/dispatch.py` (the Vector Agent's own tool-call path) had a
parallel, never-wired execution helper (`_run()`) that caught a dispatch
exception, logged it only to the worker's own process log, and returned
`None` - every caller then read that as "no result", indistinguishable from
a genuinely clean target. Found live on `int`: with the tool-runner
container not running, every agent-proposed httpx/testssl/nuclei/nikto call
silently no-opped, and the agent's own final summary reported the target
clean having never actually tested it - the exact scenario this requirement
exists to catch (see the nmap/`setcap` incident above), just not reachable
from the agent path. Fixed by routing `_run()` through the same
`tool_execution.record()` telemetry the fingerprint phase already uses, for
both success and failure - a **bug fix completing this already-approved
requirement's coverage, not a new capability** (risk unchanged at R2: worker
orchestration + read-back of already-persisted telemetry, no Scope Gateway,
authorization, or egress change). Regression tests:
`worker/tests/test_dispatch_port_targeting.py`
(`test_negative_a_dispatch_exception_is_recorded_not_silently_swallowed`,
`test_negative_a_graceful_transport_failure_is_also_recorded`,
`test_a_successful_dispatch_is_also_recorded` - the last one required
because recording only failures would make a tool that failed once and then
succeeded read as fully degraded). Live-verified against the real, originally-
broken run on `int` (`docs/requirements/per-target-port-scoping.md`'s
companion memory has the full incident).

Not yet closed: `redis-probe`/`activemq-banner` (REQ-AGENT-025) go through a
separate helper (`worker/app/raw_tcp_probe.py::execute_probe`) that also
never calls `tool_execution.record()`. Lower priority - neither is a
load-bearing tool, so this does not affect the coverage-degraded signal
itself, only per-tool audit visibility for those two specifically.
