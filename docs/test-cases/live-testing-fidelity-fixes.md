---
title: Live-testing fidelity fixes verification
status: ready
risk: R3
owner: security-engineering
---

# Live-Testing Fidelity Fixes Verification

Verifies [`../requirements/live-testing-fidelity-fixes.md`](../requirements/live-testing-fidelity-fixes.md).

## TC-FIDELITY-001: A transient cancellation-check failure does not kill the tool

Requirements:

- REQ-FIDELITY-001

Automated tests:

- `worker/tests/test_tool_runner_client.py`

Objective:

Verify a single failed cancellation-status poll is tolerated (tool result
still returned), while sustained consecutive failures still fail closed, and a
genuine cancel is still honored immediately.

Expected results:

- One failed poll followed by tool completion returns the real tool result,
  not a cancelled result.
- N consecutive failed polls (at the configured bound) still terminate the
  tool and return `cancellation_status_unavailable`.
- A poll reporting `cancelled=true` terminates the tool immediately as before.

## TC-FIDELITY-002: Activity stream is scoped to one run

Requirements:

- REQ-FIDELITY-002

Automated tests:

- `control-plane/tests/integration/test_stream_run_scoping.py`

Objective:

Verify the stream endpoint, given a run id, returns only that run's own
events: exact `scan_run_id` matches, plus payload-less events within that
run's time window, and never another run's `scan_run_id`-tagged event even if
temporally adjacent.

Expected results:

- An event tagged with the queried run's `scan_run_id` is included.
- An event tagged with a *different* run's `scan_run_id` is excluded, even if
  its timestamp falls inside the queried run's window.
- An event with no `scan_run_id` at all is included only if its timestamp
  falls within `[run.started_at, run.finished_at or now]`.
- An older, finished run queried on its own no longer returns empty just
  because a newer run generated more total engagement events.

## TC-FIDELITY-003: HTTP tools target the configured single port

Requirements:

- REQ-FIDELITY-003

Automated tests:

- `worker/tests/test_fingerprint_port_targeting.py`

Objective:

Verify httpx/nikto/wafw00f/testssl/nuclei target a configured single
non-default port instead of an implicit 443, while a full/multi-port envelope
leaves current behavior unchanged.

Expected results:

- With `tcp_port_from == tcp_port_to == 4280`, the constructed target URL/port
  argument for each tool reflects port 4280, and recorded `port_range`/service
  port reflect 4280, not `"443"`.
- With the default full range (1-65535) or any other multi-port envelope,
  behavior is unchanged (implicit 443 as before).
- With `tcp_port_from == tcp_port_to == 443` (explicitly the default), behavior
  is unchanged (no redundant port suffix).

## TC-FIDELITY-004: Severity override survives rescoring

Requirements:

- REQ-FIDELITY-004

Automated tests:

- `control-plane/tests/integration/test_finding_severity_override.py`

Objective:

Verify a finding's explicit severity assessment (e.g. agent-reported
`critical`) is persisted and survives `rescore_open_findings`, while a finding
with no override still rescoring normally, and a later override-less
observation of the same finding does not clear an earlier override.

Expected results:

- Creating a finding with `severity_override="critical"` persists
  `severity_override` and sets `severity="critical"`.
- Calling `rescore_open_findings` afterward leaves `severity="critical"`
  unchanged (risk_score may still update).
- A finding created without an override still rescoring to a
  `compute_severity`-derived value as before.
- Re-observing the same fingerprint without an override this time does not
  clear the previously persisted override.

## TC-FIDELITY-005: Egress-proxy enforces the engagement's TCP port envelope

Requirements:

- REQ-FIDELITY-005

Automated tests:

- `egress-proxy/tests/test_port_scope.py`

Objective:

Verify `evaluate()` denies an in-scope host on an out-of-scope port with
reason `out_of_scope_port`, allows it inside the configured window (including
at both boundaries), leaves the default full-range envelope unchanged, and
that deny-by-host / not-in-scope precedence over the port check is preserved
(negative and precedence tests, per the R3 proxy-change gate).

Expected results:

- `tcp_port_from == tcp_port_to == 4280`: port 443 on an in-scope host is
  denied `out_of_scope_port`; port 4280 on the same host is allowed.
- Default envelope (`1..65535`): any port on an in-scope host is allowed,
  unchanged from prior behavior.
- Ports exactly at `tcp_port_from`/`tcp_port_to` are allowed; one below/above
  the window is denied.
- A host matched by an explicit deny rule is denied `out_of_scope_deny`
  regardless of whether the requested port is inside the window.
- A host that fails the allow/materialized-IP check is denied `not_in_scope`
  regardless of the requested port.

## TC-FIDELITY-006: Run detail shows the currently executing tool

Requirements:

- REQ-FIDELITY-006

Automated tests:

- `control-plane/tests/integration/test_scan_run_current_activity.py`
- `worker/tests/test_tool_runner_current_activity.py`

Objective:

Verify `current_tool`/`current_target`/`current_started_at` are set before a
tool dispatch and cleared after, survive unrelated phase/state transitions,
never affect the tool's own result on a reporting failure, and don't add
audit-log noise; and that the Run detail page's persistent banner reflects
this state while the run is active.

Expected results:

- Setting `current_tool`/`current_target` via `update_scan_run` persists both
  and stamps `current_started_at`; clearing both resets `current_started_at`
  to null.
- A phase-only (or state-only) update leaves a previously set
  `current_tool`/`current_target` untouched.
- An activity-only update does not add a `scan_run_transition` audit row; a
  phase/state update still does, unchanged from before.
- `ToolRunnerClient.run()` reports `{tool, target}` before dispatch and clears
  it after, for a representative tool, in that order.
- A reporting failure (control-plane unreachable) does not change the
  returned tool result, and does not prevent the dispatch from happening; a
  `scan_run_id=None` call never reports activity at all.
- Activity is still cleared even when the dispatch itself raises.

## TC-FIDELITY-007: Agent dispatch targets the engagement's configured port

Requirements:

- REQ-FIDELITY-007

Automated tests:

- `worker/tests/test_target_envelope.py`
- `worker/tests/test_dispatch_port_targeting.py`
- `worker/tests/test_agent.py`

Objective:

Verify the shared port/target-URL helper behaves identically for both
callers, that every agent-dispatchable tool (httpx/nikto/wafw00f/testssl/
nuclei/http_request/ffuf) targets the configured single port when set, that
an already-ported target string is not double-ported, and that
`agent.run()` resolves the envelope once and threads it through, with an
`out_of_scope_port` denial surfaced as an explicit `EGRESS BLOCKED`
observation.

Expected results:

- `single_port_from_envelope`/`target_url` behave identically to the
  fingerprint-phase behavior verified in TC-FIDELITY-003 (single custom port,
  full range, explicit default ports, existing scheme untouched).
- A target already in `host:port` form is not given a second port suffix.
- Each of httpx/nikto/wafw00f/testssl/nuclei/http_request/ffuf, dispatched
  with `single_port=4280`, calls `tool_runner.run` with a URL ending in
  `:4280`; with `single_port=None`, the implicit 443 behavior is unchanged.
- `agent.run()` calls `client.get_scan_envelope` once and passes the derived
  single port to every `dispatch.dispatch(...)` call for the run.
- A tool result whose evidence contains `out_of_scope_port` produces an
  observation containing `EGRESS BLOCKED`, not a silent "no response".

## TC-FIDELITY-008: Run-scoped Activity never freezes at connect time, and every event type is tagged

Requirements:

- REQ-FIDELITY-008

Automated tests:

- `control-plane/tests/integration/test_run_scoped_audit_tagging.py`
- `worker/tests/test_agent.py`

Objective:

Prove `agent_event`/`dns_materialization`/`approval`/`approval_execution`
audit rows all carry a top-level `scan_run_id` when known, that the stream's
run-scoped time window is recomputed fresh on every call rather than frozen
at connection time, and that cross-run leakage remains impossible.

Expected results:

- Each of the four event types produces an `AuditLog.payload["scan_run_id"]`
  matching the run, exercised via the real internal endpoints/handlers
  (`internal_agent_event`, `approve`, `reject`, `internal_complete_approval`,
  `materialize`).
- `worker/tests/test_agent.py` confirms the worker actually sends
  `scan_run_id` on every `agent_event` call during a run.
- A clause built once, then reused after real wall-clock time has passed,
  misses an event created in between (sanity check reproducing the original
  bug); a freshly-built clause at the later time does not.
- An event tagged for a different run never matches, regardless of
  timestamp proximity.
- An unknown or cross-engagement run identifier fails fast with 404 before
  any stream opens.

## TC-FIDELITY-009: Scheme-dependent tools receive the confirmed protocol

Requirements:

- REQ-FIDELITY-009

Automated tests:

- `worker/tests/test_target_envelope.py`
- `worker/tests/test_dispatch_port_targeting.py`
- `worker/tests/test_fingerprint_port_targeting.py`

Objective:

Verify the protocol httpx actually confirmed for a host/port reaches every
tool that needs an explicit scheme, in both the deterministic fingerprint
phase and agent dispatch, and that an unknown protocol still falls back to the
historical https default rather than to a schemeless target.

Expected results:

- `target_url(host, port, "http")` -> `http://host:port`;
  `target_url(host, port, "https")` -> `https://host:port`.
- NEGATIVE: `target_url` with None/empty/`tcp`/junk still yields `https://`,
  never a schemeless or bogus-scheme target.
- nikto, wafw00f and nuclei each receive `http://target:port` when the
  confirmed protocol is http, and `https://...` when it is https or unknown.
- http_request and ffuf receive the confirmed scheme.
- `fingerprint.run` threads the confirmed protocol into `_web_enum`,
  `_waf_detect`, `_tls_scan` and `_nuclei_scan` (alongside the port).
- NEGATIVE: the agent's testssl dispatch is skipped entirely for a
  confirmed-http port and issues no tool call.
- nikto records the confirmed protocol on its service row, never a hardcoded
  "https".

## TC-FIDELITY-010: httpx always targets an explicit scheme, never bare host

Requirements:

- REQ-FIDELITY-010

Automated tests:

- `worker/tests/test_target_envelope.py`
- `worker/tests/test_dispatch_port_targeting.py`
- `worker/tests/test_fingerprint_port_targeting.py`
- `worker/tests/test_tool_runner_client.py`

Objective:

Verify `httpx_target()` never returns a schemeless string under any input
shape, and that its explicit `http://` output is preserved unmodified through
dispatch, the fingerprint phase, and the httpx command builder.

Expected results:

- A bare host, a bare host:port, and a host with no port all produce an
  explicit `http://...` target.
- A caller-supplied `https://` or `http://` scheme is left untouched.
- `dispatch()` and `fingerprint._http_probe()` pass the explicit-scheme target
  to the tool runner unchanged.
- `_httpx_command` does not add, strip, or override whatever scheme it
  receives.
- Regression invariant: every `httpx_target()` output starts with `http://`
  or `https://`, checked directly rather than only via the specific examples
  that motivated the fix.
