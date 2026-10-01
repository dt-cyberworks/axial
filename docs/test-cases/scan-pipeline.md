---
title: Evidence-driven scan pipeline verification
status: ready
risk: R3
owner: security-engineering
---

# Evidence-Driven Scan Pipeline Verification

Verifies [`../requirements/scan-pipeline.md`](../requirements/scan-pipeline.md).

## TC-PIPE-001: A redirect-only port is an alias and gets no deep checks (worker)

Requirements:

- REQ-PIPE-001
- REQ-PIPE-003

Automated tests:

- `worker/tests/test_scan_pipeline_v2.py`

Objective:

Prove that a port whose only answer is a redirect to another surface of the same
host, already confirmed live in this run, runs no deep check of its own and
records each skipped check with its reason, and that every unclear case stays a
full surface.

Expected results:

- `http://host:80 -> https://host:443` with 443 live: no waf, tls, ffuf, nuclei,
  katana or screenshot step runs on port 80; each is recorded as
  `skipped:web_alias` naming `host:443`.
- A relative redirect, a redirect to another host name, to a port not live in
  this run, to its own port, a non-redirect status, a malformed location and a
  redirect whose target was not scanned are all scanned fully.

Manual/live verification:

- Dev run against `cloud.example.com`: port 80 records skipped checks and no
  nuclei time is spent on it (recorded in the follow-up run notes).

## TC-PIPE-004: nuclei templates are selected from evidence (worker + gateway + runner)

Requirements:

- REQ-PIPE-004

Automated tests:

- `worker/tests/test_scan_planner.py`
- `worker/tests/test_scan_pipeline_v2.py`
- `worker/tests/test_nuclei_tags.py`
- `control-plane/tests/integration/test_extended_discovery.py`
- `tool-runner/tests/test_nuclei_index.py`

Objective:

Prove the template index holds exactly the former main pass minus the `network/` and
`javascript/` directories, that a standard scan selects generic shards plus only the
product templates for the identified technologies (the common-product list when nothing
was identified), that `thorough` selects everything, that a caller can name only a group,
a shard and product keys (never a path), and that a malformed or unresolvable selection
never becomes a command or a clean result.

Expected results:

- The index excludes `network/`, `javascript/`, the excluded tags and ids; selections are
  exact partitions; a product selection never returns unbound templates; no products
  means no templates.
- The gateway allows the typed shapes and refuses paths, tags, `part`, bad shards, bad
  product keys and wrongly typed values.
- A selection that matches nothing is skipped; an unreadable index fails the check.

Manual/live verification:

- `nuclei -tl` with the same flags equals the index (5,883 templates, 2026-09-30); a dev
  scan runs generic shards of about 400 templates in about one to two minutes each.

## TC-PIPE-006: Every check ends with an honest outcome (worker)

Requirements:

- REQ-PIPE-006

Automated tests:

- `worker/tests/test_scan_pipeline_v2.py`

Objective:

Prove that a check stopped by its time budget is `partial` (never a clean
result), keeps what it printed, and is counted in the run's coverage warning.

Expected results:

- A runner kill at the budget, a tool's own `timeout` (exit 124), and a
  self-limiting tool (ffuf, katana) that ran its whole deadline are `partial`.
- `complete`, `partial`, `failed` and `skipped:<reason>` are distinct; a partial
  or failed result is never `complete`.
- A nuclei pass cut by its budget still stores its hits as findings and is
  recorded `partial`.
- The stored outcome is part of the audit record.

## TC-PIPE-007: Check budgets are declared and enforced by the runner (runner + worker)

Requirements:

- REQ-PIPE-007

Automated tests:

- `tool-runner/tests/test_runner_auth.py`
- `worker/tests/test_scan_pipeline_v2.py`
- `scripts/tests/test_runner_process_reaping.py`

Objective:

Prove the runner enforces the worker's declared budget bounded by a hard
maximum a request cannot raise, that a request without a budget gets the
default, that malformed budgets are ignored, that the build patch fails loudly
when its anchors change, and that killed processes are reaped by an init
process.

Expected results:

- The build patch injects the budget helper and the executor receives it.
- 1801 seconds and larger are clamped to 1800; missing, zero, negative and
  non-numeric budgets get the default; a misconfigured default is bounded too.
- Every declared worker budget is within the runner maximum; the HTTP call
  carries the header and a read timeout above the budget.
- The tool-runner service runs with an init process and stays read-only and
  capability-free.

Manual/live verification:

- Dev: a check killed at its budget leaves no defunct process in the runner.

## TC-PIPE-013: nikto is retired and header findings come from httpx (worker)

Requirements:

- REQ-PIPE-013

Automated tests:

- `worker/tests/test_scan_pipeline_v2.py`

Objective:

Prove the scan runs no nikto, that missing security headers are derived from
the headers httpx recorded without a request to the target, and that responses
which cannot be judged produce no finding.

Expected results:

- Missing HSTS (https only), CSP, X-Content-Type-Options, X-Frame-Options
  (satisfied by CSP `frame-ancestors`) and Referrer-Policy produce the same
  finding title nikto produced, with evidence tool `httpx`.
- A redirect response, a response with no recorded headers and a complete header
  set produce no finding.
- No step of the web suite proposes or runs nikto.

## TC-PIPE-014: The validate phase is removed (worker)

Requirements:

- REQ-PIPE-014

Automated tests:

- `worker/tests/test_pipeline_resume.py`
- `worker/tests/test_scan_integrity.py`

Objective:

Prove a run goes from agent to score, and that a run stored at the removed
phase continues at score.

Expected results:

- A fresh run reports the phases fingerprint, correlate, agent, score, report.
- A run stored at `validate` runs score and report only.

## TC-PIPE-002: Each surface has a technology profile (worker)

Requirements:

- REQ-PIPE-002
- REQ-PIPE-016

Automated tests:

- `worker/tests/test_scan_planner.py`
- `worker/tests/test_scan_pipeline_v2.py`

Objective:

Prove the profile is merged from httpx, nmap and nuclei's technology templates
into normalized product keys with optional versions, that noise is not a
technology, that an empty profile stays empty, that session headers are never
stored with a surface, and that the fixed common-product list matches its
documentation.

Expected results:

- `Nextcloud`, `Nginx`, `PHP:8.2.7`, `Apache httpd 2.4.57` normalize to product keys
  (with versions where known); `HSTS`, `Ubuntu` and empty input yield nothing.
- The profile of a scanned surface holds nmap's versioned product first, then
  httpx's detections and the server header, then what the technology check adds.
- The normalization equals the template index's own.
- `set-cookie` and other session-bearing headers are absent from the stored surface.
- The common-product list in code equals the one in the requirement and design.

## TC-PIPE-003: The planner is deterministic and every check has a reason (worker + control plane)

Requirements:

- REQ-PIPE-003

Automated tests:

- `worker/tests/test_scan_planner.py`
- `control-plane/tests/integration/test_scan_plan.py`

Objective:

Prove the same inputs give the same plan, every planned or skipped check names
its reason, the planner only produces fixed typed selections, and the plan is
stored idempotently and readable through the API.

Expected results:

- Equal inputs give equal plans; no check has an empty reason.
- A stored plan keeps check order and reasons; storing it again creates nothing.
- Checks can only be created `planned` or `skipped`, with a reason and a bounded budget.

## TC-PIPE-005: A scan depth profile is set per engagement (control plane + worker + console)

Requirements:

- REQ-PIPE-005

Automated tests:

- `control-plane/tests/integration/test_scan_plan.py`
- `worker/tests/test_scan_planner.py`
- `worker/tests/test_scan_pipeline_v2.py`
- `frontend/tests/scan_plan_requirements.test.mjs`

Objective:

Prove the depth is `standard` by default, can be set at creation and changed at any
status with an audit entry, is recorded on the run, reaches the plan, and never
widens scope, grants or switches.

Expected results:

- Only `standard` and `thorough` are accepted; a null value changes nothing.
- A run keeps the depth it started with when the engagement setting changes later.
- `thorough` plans every template in shards; `standard` plans generic shards and product templates.
- Changing the depth leaves scope, status and the discovery switches untouched.
- The wizard and the engagement settings offer the choice.

## TC-PIPE-008: Checks are resumable one by one (worker + control plane)

Requirements:

- REQ-PIPE-008

Automated tests:

- `worker/tests/test_scan_executor.py`
- `worker/tests/test_scan_pipeline_v2.py`
- `control-plane/tests/integration/test_scan_plan.py`

Objective:

Prove a resumed run continues with the next unfinished check without scanning again,
a finished check never runs twice, a check that was running runs again, and a
replaced worker cannot write.

Expected results:

- Only `planned` and `running` checks run on resume; `complete`, `partial`, `failed`
  and `skipped` ones do not.
- A resume with a stored plan does not repeat discovery; without one it starts over.
- A worker that lost its claim is refused with 409 and writes nothing more.

## TC-PIPE-009: TLS on non-web services is checked (worker + gateway)

Requirements:

- REQ-PIPE-009

Automated tests:

- `worker/tests/test_scan_pipeline_v2.py`
- `worker/tests/test_scan_planner.py`
- `control-plane/tests/integration/test_testssl_starttls.py`

Objective:

Prove every TLS service is planned for testssl, STARTTLS where the protocol needs
it, that findings name service and port, that the STARTTLS protocol is a fixed set,
and that a service testssl cannot test is never reported clean.

Expected results:

- SMTP 25/587 use `--starttls smtp`; 465 and 993 are checked directly.
- The same weakness on two ports of one host is two findings, each naming its port.
- Only the known STARTTLS protocols pass the gateway; anything else is `unsafe_arguments`.
- A non-TLS answer is skipped (`not_a_tls_service`), a scan problem is failed.
- testssl is listed in the engagement's tool list; selected, the gateway allows it (web and
  STARTTLS calls) with no pending approval; switched off, it is refused with `tool_disabled`
  and the plan shows its checks as skipped (`tool_disabled`); other tools are unaffected.

Manual/live verification:

- Dev run against `cloud.example.com`: ports 25, 465, 587 and 993 each get a testssl
  check; results are recorded in the run notes.

## TC-PIPE-010: The operator sees the plan and its progress (control plane + console)

Requirements:

- REQ-PIPE-010

Automated tests:

- `control-plane/tests/integration/test_scan_plan.py`
- `frontend/tests/scan_plan_requirements.test.mjs`

Objective:

Prove the run's plan is readable by its owner only, shows each surface with class and
technologies and each check with reason, state, duration and findings, and refreshes
while the run executes.

Expected results:

- The owner reads the plan; another user or another engagement gets 404; no credentials get 401.
- Response headers are not part of the public shape.
- The Plan tab polls while the run is active and lists skipped checks with their reason.

## TC-PIPE-011: The report states coverage (control plane)

Requirements:

- REQ-PIPE-011

Automated tests:

- `control-plane/tests/integration/test_report_generation.py`

Objective:

Prove the report lists, per service of the report run, which checks were complete,
partial, failed or skipped and why, and that any partial or failed check is stated in
the executive summary.

Expected results:

- The coverage table shows each service with its class, technologies and counts.
- Partial and failed checks, and skips that are not configuration, are listed.
- A fully covered run carries no warning; a run without a plan still produces a report.
- The plan of an older run is not mixed into the report run.

## TC-PIPE-012: Egress throughput is measured (script)

Requirements:

- REQ-PIPE-012

Automated tests:

- `scripts/tests/test_measure_egress_throughput.py`

Objective:

Prove the measurement is repeatable, bounded, and uses a throwaway target with a
synthetic engagement that is removed afterwards; the recorded result is in
`docs/reviews/2026-09-30-egress-throughput-measurement.md`.

Expected results:

- The load generator counts every request and reports rate and percentiles; a
  denial is counted as its status; an unreachable proxy is an error count.
- The run size is bounded; the target is a synthetic name, never a real host.

## TC-PIPE-015: At most two checks run in parallel per engagement (worker + control plane)

Requirements:

- REQ-PIPE-015

Automated tests:

- `worker/tests/test_scan_executor.py`
- `worker/tests/test_scan_pipeline_v2.py`
- `control-plane/tests/integration/test_scan_plan.py`

Objective:

Prove two checks run at once and never three, that a failing check does not stop the
others, that parallel checks do not see each other's results, and that a bug-bounty
program's own concurrency cap can only lower the number.

Expected results:

- The observed maximum of running checks is two (one when asked for one).
- The settings endpoint returns two, or the program's cap when lower.
- Settings that cannot be read fall back to one check at a time.

## TC-PIPE-016: The common-product fallback list is fixed and reviewable (worker)

Requirements:

- REQ-PIPE-016

Automated tests:

- `worker/tests/test_scan_planner.py`

Objective:

Prove the list is the documented one and that code and documents agree.

Expected results:

- The list equals wordpress, drupal, joomla, apache, nginx, iis, tomcat, jenkins,
  gitlab, grafana, confluence, jira, php, spring.
- The test fails when code and the requirement or design diverge.

## TC-PIPE-017: The thorough profile plans a deep content-discovery sweep (worker + gateway)

Requirements:

- REQ-PIPE-017

Automated tests:

- `worker/tests/test_deep_content_discovery.py`
- `frontend/tests/scan_plan_requirements.test.mjs`

Objective:

Prove the thorough plan holds one deep ffuf check per real web surface with a budget
that fits its list, that the standard plan is unchanged, that nothing is added where no
deep check runs, and that the check reuses the existing tool, wordlist keys and rate.

Expected results:

- Under `thorough` a web surface plans `ffuf:deep` (`raft-medium-dirs`) after its
  nuclei checks; under `standard` there is none.
- A duplicate virtual host, a redirect-only alias and a campaign that switched ffuf off
  skip it with the reason; TLS, other and unknown surfaces plan none.
- The budget covers a whole pass of the list (entries / rate) and never exceeds the
  runner maximum; a list too large for the maximum gets the maximum; candidates, an
  unknown key or no list keep the fixed floor. The wordlist table has exactly the allowed
  keys, matching the gateway's set.
- ffuf's `-maxtime` is long enough for the whole list; a bug-bounty cap only lowers the rate.
- The handler passes a stored wordlist on only when it is a known key (a path, a list or
  nothing falls back to the baseline list); hits become one `inferred` finding naming the
  wordlist, a cut-short run keeps its hits, a failed run reports none, and a catch-all
  answer is discarded.
- The thorough depth choice and the plan tell the operator what the sweep is and costs.

Manual/live verification:

- A thorough scan of a real target: `ffuf:deep` completes or ends `partial` inside its
  budget and the plan shows its time. Run on dev before int.

## TC-PIPE-018: The Vector Agent sees what ran, and a partial result is reported as partial (worker + control plane)

Requirements:

- REQ-PIPE-018

Automated tests:

- `worker/tests/test_deep_content_discovery.py`
- `control-plane/tests/integration/test_scan_plan.py`

Objective:

Prove the agent's context lists the run's finished and skipped checks without anything the
target returned, that its evidence block and prompt use it, and that an agent ffuf stopped by
its limit returns its hits marked partial (the defect found on int, 2026-09-30).

Expected results:

- `agent-context` lists, per host, checks that are complete, partial, failed or skipped
  (port, tool, state, ffuf wordlist, cut skip reason) and none that are still planned or
  running; an empty list without a running run; at most 60 per host.
- No fingerprint header, cookie or tool argument other than the wordlist key reaches it; a
  non-string wordlist is left out.
- The evidence block shows what ran per port (nuclei collapsed, an alias naming its target,
  switch-offs not listed as done) and adds nothing when there are no checks; an older
  control plane without the field still renders.
- An agent ffuf that reached its limit returns its hits with a PARTIAL note and an upper
  bound of the list tried; without hits it says so without claiming absence; with the
  agent's own candidates it makes no list claim; a complete run has no note; a failed run
  reports no hits and no partial claim; the cap stays 240 s.
- The prompt and the tool description say the baseline ran, that a four-minute call cannot
  sweep a large list, and that a PARTIAL observation proves nothing absent.

Manual/live verification:

- On dev, an agent run after a thorough or standard fingerprint no longer repeats the
  baseline and its ffuf observation, when cut short, carries the note.

## TC-PIPE-019: The proxy's audit events are batched, chained and still fail closed

Requirements:

- REQ-PIPE-019

Automated tests:

- `control-plane/tests/integration/test_audit_batch_and_load.py`
- `egress-proxy/tests/test_audit_batching.py`
- `egress-proxy/tests/test_audit_client.py`

Objective:

Prove a batch is one verifiable chain, the verifier catches every kind of tampering, and the
proxy still never forwards before its record is committed and denies every waiter of a failed
batch.

Expected results:

- A batch of 50 is one chain with strictly increasing timestamps; it continues an existing
  chain; concurrent single and batch writers form one chain (72 rows verify).
- An empty batch writes nothing; a malformed entry leaves no part of the batch behind; one
  invalid decision rejects the whole batch with 422; an unknown engagement is 404; more than
  200 events or none is refused.
- `verify_audit_chain` fails on a modified, a removed, an inserted and a reordered row and
  names the first bad row; an engagement without rows is fine.
- The batcher sends an idle event at once, groups events that arrive during a send (60 events
  in at most 3 requests, each exactly once, in order), never exceeds the batch limit, never
  mixes engagements, and does not release a request before its batch is committed.
- A failed batch fails every request waiting on it (each is denied 503 `audit_unavailable`),
  the next batch succeeds, and nothing is dropped or duplicated.
- The client retries a 503 (nothing was written) up to twice more and never retries a 500,
  404, timeout or connection error; a non-201 answer is a failure.

Manual/live verification:

- On dev, a real `standard` scan with the Live Scan page open: the proxy's audit traffic
  arrives in batches and `verify_audit_chain` passes for that engagement afterwards.

Live result (2026-10-01, dev, a real `standard` scan of the project's own confirmed-safe external target with the Live Scan
page open in two browser tabs): the run ended `done` after about 14.5 minutes with no coverage
warning; 3,680 proxy `network_request` rows were written by 1,099 batch requests (none through the
single-event endpoint); `verify_audit_chain` passed over all 3,761 rows of the engagement.

## TC-PIPE-020: Audit traffic cannot starve the control plane, and the stream stays off the event loop

Requirements:

- REQ-PIPE-020

Automated tests:

- `control-plane/tests/integration/test_audit_batch_and_load.py`
- `control-plane/tests/test_stream_event_loop.py`
- `control-plane/tests/test_production_config.py`

Objective:

Reproduce the #49 failure in miniature (a three-connection pool, twelve flooding threads, a
cancel poller, an open stream) and show the control path stays responsive.

Expected results:

- Without a free bulk slot the audit and rate-reservation endpoints answer 503 and write
  nothing; the slot is released after every call, also after a failing one.
- With the flood running, no cancel check waits one second and the written chain verifies.
  Mutation check (2026-10-01): with 12 slots instead of 2 this test fails.
- A poll that blocks for 0.6 s lets the event loop tick at least 25 times; a poll that hits a
  pool timeout is skipped and the history is still sent on the next successful poll; the
  stream only follows rows newer than the last one sent.
- A poll within 15 s of the last heartbeat does not write the run row; a stale one is still
  refreshed (REQ-RESUME-004).
- Production refuses a pool size outside 1-100, an overflow outside 0-100, a timeout outside
  1-60 s and bulk slots that could take every connection.

Manual/live verification:

- With the Live Scan page open during a real scan: no `QueuePool limit` error in the
  control-plane log and `cancel-requested` answers well inside 2 s.

Live result (same run as TC-PIPE-019): 835 `cancel-requested` polls, one per second, answered with
a median of 4 ms and a maximum of 10 ms and without one error; the control-plane log has no
`QueuePool` line. (The audit rate of this run was about 4 events/s, not the 110-150/s of the
incident, which is why the flood itself is reproduced by the integration test against a
three-connection pool.)

## TC-PIPE-021: A missing cancel answer stops the run safely and a failed run says why

Requirements:

- REQ-PIPE-021

Automated tests:

- `worker/tests/test_cancel_resilience.py`
- `worker/tests/test_pipeline_durability.py`
- `worker/tests/test_pipeline_resume.py`
- `frontend/tests/failure_cause_requirements.test.mjs`
- `control-plane/tests/test_report_failure_reason_text.py`

Objective:

Inject timeouts and errors into every cancel check the worker makes and show the run degrades
safely instead of crashing, and that what the operator reads is the real cause.

Expected results:

- An unreadable answer is unknown, not `False`; failures are counted consecutively and reset
  on success; every kind of failed answer counts; a superseded run passes through.
- The executor survives one lost answer and runs every check; starts nothing while the answer
  is unknown; with silence from the start starts nothing and raises, leaving every check
  `planned`; with silence mid-run records the running check, starts no more and raises.
- The pipeline ends `aborted / cancellation_status_unavailable` (no exception, no phase
  started) and does the same when the silence is found inside a phase.
- A failed run records `pipeline_error:<Type>:<phase>` for each phase, never the message.
- A check write that times out is retried; a superseded write and a 422 are not.
- Ending a run is retried and never raises.
- A tool stopped by an unreadable cancel status is a `failed` check with that reason; an
  operator stop is still `skipped`. The console, plan view and report have text for it.

Manual/live verification:

- On dev, pausing the control plane for 15 s during a real scan ends the run
  `aborted / cancellation_status_unavailable` with its running tools terminated.

Live result (2026-10-01, dev, real scan of the project's own confirmed-safe external target, `docker pause` of the control
plane for 15 s once checks were running): the run ended `aborted / cancellation_status_unavailable`
(never `pipeline_error`), the tool-runner received 3 `terminate-scan-run` calls, the control-plane
log has no `QueuePool` line, and the audit chain of the engagement verifies (34 rows).
