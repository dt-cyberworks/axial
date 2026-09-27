---
title: Live-testing fidelity fixes (cancellation tolerance, run-scoped activity, HTTP tool port targeting, egress-proxy port enforcement)
status: implemented
risk: R3
owner: security-engineering
---

# Live-Testing Fidelity Fixes

Five defects found while live-testing the asset review gate on real engagements.
None touch the Scope Gateway's authorization decision directly; the first four
make an existing promise actually hold (a tool that should run doesn't get
killed by a transient blip; the Run detail view shows the correct run's own
activity; a scan against a non-standard port actually tests that port instead
of silently testing the wrong one; a critical finding doesn't get silently
downgraded). REQ-FIDELITY-005 closes a real network-layer scope-enforcement
gap in the egress-proxy — the redundant, independent check described in the
Deployment Architecture (Kap. 6.2) as the thing that controls what actually
*leaves the network*, distinct from the Scope Gateway which controls what is
*commissioned*.

**Risk class: R3** (`docs/engineering/sdlc.md` §2: "Scope Gateway, auth,
audit, runner, **proxy**, secrets"). REQ-FIDELITY-003 changes which port
active tools connect to; REQ-FIDELITY-005 changes the proxy's own
authorization logic. A wrong fix in either could widen effective scanning
surface or continue to silently miss/exceed the authorized target. Both
require positive and negative tests; REQ-FIDELITY-005 additionally requires
security-owner review per the SDLC gate for `R3` proxy changes — an
automated agent cannot self-approve this decision.

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

---

## REQ-FIDELITY-001: A transient cancellation-check failure does not kill a running tool

Context: `_post_cancellable` polls `is_cancel_requested` roughly every second
while a tool (nmap/nikto/nuclei, sometimes minutes long) runs in a background
thread. On the **first** failed poll (e.g. a momentary control-plane restart
or network blip), it terminated the tool and reported
`cancellation_status_unavailable` — indistinguishable from a real operator
cancel, even though nothing was actually wrong with the tool.

Acceptance criteria:
- A single failed cancellation-status poll does not terminate the tool or
  return a cancelled result; polling continues.
- Only after a bounded number of **consecutive** failed polls (fail-closed
  after sustained unavailability, not one blip) does the tool get terminated
  with `cancellation_status_unavailable`.
- A single transient failure followed by a successful poll (or a normal tool
  completion) never affects the outcome — the tool's real result is returned.
- A genuine operator cancel (successful poll reporting `cancelled=true`) is
  still honored immediately, unchanged from before.

## REQ-FIDELITY-002: The Run detail Activity view shows only that run's own events

Context: the SSE stream backing the Activity/Progress views is filtered only
by engagement and a fixed row-count cap (`limit`), with no run boundary. Two
consequences: (a) opening an older run can show nothing, because a newer run's
higher event volume evicts the older run's rows from the capped window: and
(b) an unrelated, temporally-separate event from a *different* run (e.g. an
earlier failed DNS materialization) can appear to belong to the run currently
being viewed.

Acceptance criteria:
- The stream endpoint accepts an optional run identifier. When provided, only
  events belonging to that run are returned: an event whose payload carries a
  matching `scan_run_id` is included; an event whose payload carries no
  `scan_run_id` at all is included only if it falls within that run's own
  `[started_at, finished_at-or-now]` window.
- An event carrying a *different* run's `scan_run_id` is excluded even if it
  falls inside the queried run's time window (no cross-run leakage from clock
  proximity).
- The Run detail page requests the stream scoped to the run being viewed. An
  older, already-finished run now shows its own historical activity instead of
  an empty feed.

## REQ-FIDELITY-003: Active HTTP-layer tools target the engagement's configured port

Context: `httpx`/`nikto`/`wafw00f`/`testssl`/`nuclei` are invoked against a
bare hostname; several hardcode `https://{target}` and `port_range="443"` with
no reference to the engagement's authorized TCP envelope
(`tcp_port_from`/`tcp_port_to`). When an engagement authorizes a single
non-standard port (e.g. 4280), every one of these tools silently probes port
443 instead — a false negative: the authorized service is never actually
tested, and the recorded evidence looks like a completed check.

Acceptance criteria:
- When the engagement's authorized TCP envelope is a single, non-default port
  (`tcp_port_from == tcp_port_to`, not port 80/443), httpx/nikto/wafw00f/
  testssl/nuclei target that port instead of an implicit 443.
- A full-range or multi-port envelope (the common case) leaves current
  behavior unchanged (no attempt to guess a single port from a range).
- Recorded evidence (`tool_execution.port_range`, `service.port`) reflects the
  port actually targeted, not a hardcoded `443` string regardless of the real
  target.
- This only changes *which port on an already-authorized host* is targeted —
  it does not authorize a new host, widen scope, or bypass the Scope Gateway.

## REQ-FIDELITY-004: An explicit severity assessment survives rescoring

Context: the scoring phase (`rescore_open_findings`) runs on every scan and
unconditionally recomputed every open finding's severity from `compute_severity`,
discarding any previously-set `severity_override` (a tool's own assessment, or
the Vector Agent's self-reported severity via `report_finding`). A finding the
agent itself flagged `critical` (e.g. unauthenticated PII/SSH-key/API-key
exposure) was silently downgraded to `low` on the very next rescore — a
false-negative-producing correctness bug, not a cosmetic one.

Acceptance criteria:
- `finding.severity_override` is persisted (mirrors the existing `is_kev`
  persistence pattern), set whenever `add_finding` receives a valid
  `severity_override`.
- A later observation of the same finding (same fingerprint) that carries no
  `severity_override` does not clear a previously persisted one.
- `rescore_open_findings` uses the persisted override as the finding's severity
  when present, and only falls back to `compute_severity(risk_score, is_kev)`
  when no override is set.
- `risk_score` itself continues to be recomputed on every rescore regardless
  (used for prioritization/sorting) — only the displayed severity is protected
  from being silently downgraded.

## REQ-FIDELITY-005: The egress-proxy enforces the engagement's TCP port envelope

Context: found while live-verifying REQ-FIDELITY-003. The engagement's
`tcp_port_from`/`tcp_port_to` window was, until this fix, used *only* to build
tool command targets (nmap `-p`, and — after REQ-FIDELITY-003 — the HTTP
tools' target URL). Neither authorization layer actually enforced it as a
boundary: the Scope Gateway (`control-plane/app/gateway/authorize.py`) never
references it, and the egress-proxy's `evaluate()` — the one component whose
own docstring describes it as controlling "was das Netzwerk tatsaechlich
VERLAESST", independently of the Gateway — checked only host allow/deny,
never the port. An engagement scoped to port 4280 only had every CONNECT to
port 443 on an in-scope host allowed and relayed onto the real network,
observed directly in the raw-egress audit trail (`ALLOW CONNECT
pentest-ground.com:443` for an engagement configured for port 4280 only).
Any tool bug, misconfiguration, or future change that constructs a request
against the wrong port on an in-scope host would reach the real network
undetected — the exact class of failure the redundant proxy layer exists to
catch.

Threat model: this closes a gap where an in-scope **host** could be reached
on an out-of-scope **port** despite the operator's explicit engagement
configuration — a real, network-observable scope violation, not a cosmetic
one. It does not introduce any new capability; it only narrows what the
proxy already relays. Negative test: an in-scope host on an out-of-scope port
must be denied with reason `out_of_scope_port` even when every other check
(host allow-match, active window, deny-list) would pass. Deny-precedence
regression test: a denied host is never "rescued" by an in-window port.

Acceptance criteria:
- `evaluate()` denies a request whose port falls outside
  `[tcp_port_from, tcp_port_to]` for the resolved engagement, with reason
  `out_of_scope_port`, for both `CONNECT` (TLS tunnels) and plain-HTTP
  requests.
- The default full-range envelope (`1..65535`, the common case for engagements
  that don't restrict ports) allows any port, unchanged from prior behavior.
- Explicit deny-by-host still wins even when the port would otherwise be
  in-window (deny precedence is unconditional, checked before the port test).
- A host that fails the allow/materialized-IP check is denied `not_in_scope`
  regardless of port — the port check never masks a host-scope failure.
- No change to the Scope Gateway's own authorization decision — this is
  strictly the redundant network-layer check tightening to match what the
  Gateway/operator already configured.

## REQ-FIDELITY-006: The Run detail view shows what is currently executing

Context: a long-running tool (nmap, nuclei, testssl — sometimes minutes) shows
only its proposal-time `ALLOW` row in the Activity view for its entire
duration, with nothing distinguishing "still running" from "silently stuck".
The operator asked to see what is currently being executed, not just the
history of what already happened.

Acceptance criteria:
- `scan_run` carries a `current_tool`/`current_target`/`current_started_at`
  that reflects the tool currently dispatched for that run, or all-null when
  no tool is in flight.
- The worker's single common tool-dispatch entry point
  (`ToolRunnerClient.run`) sets the current activity immediately before
  dispatch and clears it immediately after, for every tool it runs
  (nmap/httpx/nikto/wafw00f/testssl/nuclei/http_request/ffuf/etc.), regardless
  of success, failure, or an exception during dispatch.
- A pure activity update (no phase/state change) is best-effort telemetry: a
  failure to report it never affects the tool's own result, and it must not
  clobber or be clobbered by an unrelated phase/state transition on the same
  run (each is applied only when the request body actually carries it).
- A pure activity update does not add a `scan_run_transition` audit-log
  entry — the terminal outcome is already captured via the existing
  `tool_execution` record; this would otherwise be one extra audit row per
  tool call for no compliance benefit.
- The Run detail page shows a persistent, visible indicator — not just
  another log row — for the currently running tool while the run is active,
  and it disappears once nothing is in flight.

## REQ-FIDELITY-007: Agent-proposed tool calls also honor the engagement's configured port

Context: found while live-verifying REQ-FIDELITY-003/005 with two engagements
scanning concurrently, one restricted to a single non-standard port (4280).
REQ-FIDELITY-003 fixed the deterministic fingerprint phase's own tool
construction (`fingerprint.py`) to target the configured port, but the Vector
Agent's tool calls go through a separate path (`dispatch.py`, driven by
`agent.py`) that builds its own `https://{target}` URLs independently and had
no knowledge of the single-port envelope at all. Once REQ-FIDELITY-005 made
the egress-proxy actually enforce the port, every agent-proposed
httpx/nikto/wafw00f/testssl/nuclei/http_request/ffuf call on the port-4280
engagement kept defaulting to the implicit 443, got denied
(`out_of_scope_port`), and — because that denial reason wasn't in
`dispatch.py`'s known proxy-block token list — surfaced to the LLM as an
ambiguous "no response" rather than a clear infrastructure block. In the
observed run this produced over 13,000 blocked network attempts and an agent
that had to reverse-engineer the port itself mid-conversation
(`"target": "pentest-ground.com:4280"`) instead of it simply working.

Acceptance criteria:
- The single-port-from-envelope and target-URL construction logic is shared
  (one implementation) between the fingerprint phase and agent dispatch, not
  duplicated with divergent behavior.
- `agent.run()` resolves the engagement's TCP envelope once per scan run and
  passes the resulting single port to every dispatched tool call
  (httpx/nikto/wafw00f/testssl/nuclei/http_request/ffuf), regardless of which
  in-scope host the agent picks.
- A target string the agent already qualified with an explicit port itself
  (`host:port`) is never given a second, conflicting port.
- A failure to resolve the envelope (control-plane unreachable) falls back to
  the pre-existing implicit-443 behavior; it never aborts the agent phase.
- An `out_of_scope_port` denial from the egress-proxy is recognized as an
  explicit infrastructure block (`EGRESS BLOCKED`) in the agent's observation,
  exactly like the other proxy-denial reasons — never silently treated as
  "no response" — so the agent does not retry the same blocked call blindly.

## REQ-FIDELITY-008: The run-scoped Activity view never freezes at connection-open time, and every event type is properly tagged

Context: REQ-FIDELITY-002 already states the intent ("an event tagged with
this run's scan_run_id always matches"), but the implementation had two
gaps, found live: (1) `_run_scoped_clause` computed the untagged-fallback
time window's upper bound (`window_end`) **once**, at SSE-connect time, and
reused it for the life of the connection — for an active run this froze
`window_end` at almost exactly the run's start, so any untagged event
created afterward (essentially the whole run) never appeared. (2) several
audit actions never carried a top-level `scan_run_id` in their payload at
all, relying entirely on that now-frozen fallback: `agent_event` (all Vector
Agent telemetry), `dns_materialization`, `approval`, and `approval_execution`.
Together, opening a freshly-started run's Activity tab could show it as
empty.

Acceptance criteria:
- `agent_event`, `dns_materialization`, `approval`, and `approval_execution`
  audit rows all carry a top-level `scan_run_id` in their payload when one is
  known, exactly like `tool_call` and `raw_egress_lease` already did.
- The stream endpoint's run-scoped time window is recomputed on every poll
  for an active run, not fixed once at connection time, so any event type
  that still falls back to time-window matching stays correctly bounded
  regardless of how long the connection has been open.
- A run identifier that never existed (or belongs to a different engagement)
  still fails the request immediately with 404, before the SSE stream opens
  — this fast-fail behavior is unchanged by the per-poll recomputation.
- No cross-run leakage: an event tagged with a *different* run's
  `scan_run_id` is still excluded regardless of timestamp proximity.

Security invariants:
- This only adds/hoists an audit-correlation tag and fixes a query-timing
  snapshot; it does not change any ALLOW/DENY decision path, the Scope
  Gateway, or what is executed — purely an audit-visibility fix.

## REQ-FIDELITY-009: Scheme-dependent tools use the protocol the fingerprint phase confirmed

**Risk class: R3** (this requirement changes *what active tools connect to* —
the same classification REQ-FIDELITY-003/007 carry, for the same reason).
Approved by johannes 2026-08-03.

Context: `worker/app/target_envelope.py::target_url()` unconditionally
prepended `https://`. REQ-FIDELITY-003 fixed exactly one consumer of that
pattern — httpx — via a separate schemeless `httpx_target()`, because httpx
natively auto-probes https-then-http. Ten other call sites were left forcing
https: six in the agent path (`dispatch.py`: nikto, wafw00f, testssl, nuclei,
http_request, ffuf) and — more importantly, because they run on **every**
scan whether or not the agent is enabled — four in the deterministic
fingerprint phase (`fingerprint.py`: `_web_enum`, `_waf_detect`, `_tls_scan`,
`_nuclei_scan`).

Measured live 2026-08-03 against a plain-HTTP service: nuclei found 2 real
template matches when given `http://`, and **0** when given the forced
`https://` — silently, reported as "Scan completed. No results found." with
no error. A schemeless target is not an alternative: nuclei's embedded httpx
reported "Found 0 URL from httpx" and also scored 0. Verified per tool that
nikto (`-ssl`/`-nossl`), ffuf (`-u` needs a full URL) and wafw00f likewise
require an explicit, correct scheme and do not probe the other one.

The fingerprint phase already knows the answer: `_web_suite` computes
`protocol_from_httpx_url(live["url"])` — httpx's own reported URL — and used
it only to gate `_tls_scan`.

A second defect surfaced with it: `client.add_service(...)` was called with a
hardcoded `protocol="https"` by nikto in both paths, and
`add_service` performs **no upsert** — every call inserts a row. A real
engagement (`pentest-ground.com:4280`) accumulated `https/http`,
`https/nginx` and `tcp/nginx` rows simultaneously; all are rendered into the
Vector Agent's evidence block, feeding it self-contradictory input.

Acceptance criteria:

- Every tool that requires an explicit scheme receives the protocol httpx
  confirmed for that exact host/port, in both the deterministic fingerprint
  phase and agent dispatch.
- A confirmed-`http` host/port is scanned over `http://`; a confirmed-`https`
  one over `https://`.
- When the protocol is genuinely unknown (no successful httpx probe), the
  historical `https://` default is preserved — unknown must never degrade to a
  schemeless target, which would break real HTTPS targets for tools that do
  not auto-probe.
- Only a literal `http` (case-insensitive) downgrades the scheme; any other
  value (empty, a transport name such as `tcp`, or junk) falls back to
  `https://` rather than producing a bogus scheme.
- The agent's ad-hoc testssl call skips a port httpx confirmed is plain HTTP,
  matching the gate `fingerprint.py::_tls_scan` already applies — no more
  "TLS 1.2/1.3 not offered" findings on ports with no TLS layer at all.
- No finding-creation path records a hardcoded protocol for a service whose
  protocol is already known; a service row must never contradict the httpx
  observation for the same host/port.
- httpx itself is unaffected and keeps its schemeless target
  (REQ-FIDELITY-003) — it is the one tool that genuinely benefits from
  auto-probing.

## REQ-FIDELITY-010: httpx targets an explicit http:// scheme, never a bare/schemeless host

**Risk class: R3** (same classification as REQ-FIDELITY-003/007/009 - changes
what an active tool connects to). Approved by johannes 2026-08-04.

Context: REQ-FIDELITY-003's fix for the httpx-forces-https bug
(`target_envelope.httpx_target()`) made the target schemeless, reasoning that
"httpx natively auto-probes https-then-http when given a bare host[:port]".
That claim was never verified against a non-standard port and was wrong.

Found live 2026-08-04 deploying OWASP Benchmark (TLS-only, self-signed
certificate, non-standard port 18093): a schemeless httpx target on a
non-standard port does not probe https at all - it assumes http outright and
accepts whatever answers. Here that was Tomcat's own literal response to a
plain-HTTP request on an HTTPS-only connector, `400 Bad Request: This
combination of host and port requires TLS`, which httpx reported as
`"scheme":"http","failed":false` - a confirmed, successful plain-HTTP probe.
Every downstream consumer of that wrong confirmed protocol
(REQ-FIDELITY-009's thread-through) was then misdirected: testssl was skipped
as `not_a_tls_service`, and the Vector Agent's `http_request`/`ffuf` calls
were all sent as plain HTTP and all got the identical 400. nikto and nuclei
also received the same wrong target and returned only generic "missing
security header" findings **derived from that 400 response itself**, not from
ever reaching the real application. In effect the entire target went untested
behind a wall of identical, structurally-guaranteed-empty responses, while
every tool involved reported success.

Verified empirically which direction actually self-corrects, against two
real, live, opposite-shaped targets:
- Explicit `http://` against the OWASP Benchmark target (TLS-only) correctly
  auto-upgraded itself to `https://` and returned the real Tomcat response.
- Explicit `https://` against DVWA (a real plain-HTTP-only target) did **not**
  fall back to `http://` - no result at all, silently.
- The original schemeless input reproduced the bug both times: no https probe
  attempted on a non-standard port.

So neither "no scheme" nor "start from https" is correct; "start from an
explicit http://" is the one direction proven to self-correct in both
directions.

Acceptance criteria:

- `target_envelope.httpx_target()` never returns a bare/schemeless host string
  under any input shape - it always returns a URL with an explicit `http://`
  or (when the caller already supplied one) whatever scheme the caller chose.
- A caller-supplied scheme (`https://...` or `http://...`) already present on
  the input is preserved untouched, never overridden.
- No other consumer (`_httpx_command` in `tool_runner_client.py`, the
  dispatch/fingerprint call sites) re-derives or second-guesses the scheme
  `httpx_target()` already chose.
- Regression coverage locks the invariant directly (every output of
  `httpx_target()` starts with `http://` or `https://`), not only the specific
  examples that motivated the fix, so a future edit cannot silently
  reintroduce a schemeless return for some other input shape.
