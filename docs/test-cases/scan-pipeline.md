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
