---
title: Evidence-driven scan pipeline (v2)
status: implemented
risk: R3
owner: security-engineering
---

# Evidence-Driven Scan Pipeline (v2)

Architecture: [`../design/scan-pipeline-architecture.md`](../design/scan-pipeline-architecture.md).
johannes decided D1–D6 on 2026-09-29 (design section 8) and approved these
requirements for implementation the same day; the runner's hard maximum per
check is 30 minutes. Human security review of the finished R3 implementation
is still owed. Motivated by the live dev run of
2026-09-29 (design section 0, problems P1–P11).

## REQ-PIPE-001: Every open port becomes a classified surface

The system shall turn each open TCP port of an approved asset into exactly one
surface with a service class (`web`, `web_alias`, `tls_service`, `service`,
`unknown`) before any deep check runs.

Acceptance criteria:

- A port httpx confirms as live HTTP(S) is `web`.
- A port whose only answer is a redirect to another surface of the same
  engagement that is scanned in this run is `web_alias` of that surface.
- An implicit-TLS or STARTTLS-capable service identified by nmap `-sV` is
  `tls_service`; other identified services are `service`; the rest `unknown`.
- A port nmap proved closed never becomes a surface.

Security invariants:

- Classification contacts the target only through tools the gateway already
  authorizes (nmap, httpx); it adds no new target contact.

## REQ-PIPE-002: Each surface has a technology profile

The system shall record per surface a normalized technology profile merged
from httpx tech detection, nmap `-sV` product/version and nuclei's
technology-detection templates.

Acceptance criteria:

- Entries are normalized product keys with an optional version.
- The profile is stored with the surface and shown to the operator.
- An empty profile is recorded as empty, never guessed.

Security invariants:

- None beyond REQ-PIPE-001.

## REQ-PIPE-003: A deterministic planner decides what runs and why

The system shall build, before execution, a persisted check plan per surface
from its service class, technology profile and the engagement's options. Every
check is either planned with a reason or skipped with a reason.

Acceptance criteria:

- The planner is a pure function of its inputs; the same inputs give the same
  plan.
- Each planned check names its reason (e.g. `generic_web`,
  `product:nextcloud`, `tls_service`); each skipped check names its reason
  (e.g. `web_alias_of:<surface>`, `product_not_observed`, `switch_off`).
- A `web_alias` surface gets no deep checks; its target surface gets them once.
- The plan is readable through the API and the console.

Security invariants:

- The planner only selects among fixed, worker-built invocations; it never
  produces free-form tool arguments.
- Every planned check is still authorized by the Scope Gateway at execution
  time; a plan is never an authorization.

## REQ-PIPE-004: nuclei templates are selected from evidence

The system shall select nuclei templates for a `web` surface from a template
index built at image build time: generic templates always, product-bound
templates only when the product is in the surface's profile.

Acceptance criteria:

- The index lists every baked template with id, path, tags, protocol, ports,
  severity and declared vendor/product.
- A product-bound template runs only when its product is in the profile.
- `network/` and `javascript/` templates never run against a `web` surface.
- An empty profile selects the generic templates plus the product-bound
  templates of the common-product list (REQ-PIPE-016).
- The union of all selections under the `thorough` profile equals the former
  complete template set minus the `network/` and `javascript/` templates
  (measured with `nuclei -tl`; clarified 2026-09-29 while implementing, because
  those two directories can never run against a web surface by the criterion
  above).

Security invariants:

- The existing exclusions (`intrusive`, `dos`, `fuzz`, `csp-bypass`) apply to
  every selection.
- The gateway accepts only index-derived selections (no caller-supplied paths).

## REQ-PIPE-005: A scan depth profile is set per engagement

The system shall offer a per-engagement scan depth: `standard` (default,
evidence-driven) or `thorough` (the complete former check set).

Acceptance criteria:

- The setting is shown and changeable in the engagement configuration.
- `thorough` runs every template on every `web` surface.
- The chosen profile is recorded on the scan run.

Security invariants:

- Neither profile widens scope, grants or switches; `thorough` only selects
  more of the same conservative templates.

## REQ-PIPE-006: Every check ends with an honest outcome

The system shall end every check as `complete`, `partial`, `failed` or
`skipped:<reason>`.

Acceptance criteria:

- A check stopped by its time budget is `partial`; results printed before the
  stop are kept as findings.
- A `partial` or `failed` check never reads as a clean result in the run, the
  API or the report.
- nikto's "maximum execution time reached" and nuclei's executor timeout are
  `partial`, not success.

Security invariants:

- None.

## REQ-PIPE-007: Check budgets are declared and enforced by the runner

The system shall run each check with its own declared time budget, enforced
by the tool-runner, instead of a fixed executor-wide cap.

Acceptance criteria:

- The runner accepts a per-request timeout bounded by a hard maximum.
- A request without a timeout gets the runner default.
- Processes killed on timeout are reaped; no zombie processes remain.

Security invariants:

- The hard maximum cannot be raised by a request.
- Runner authentication (REQ-HARDEN-001) is unchanged.

## REQ-PIPE-008: Checks are resumable one by one

The system shall persist each check job, so that a resumed run continues with
the next unfinished check.

Acceptance criteria:

- A worker restart during execution does not repeat `complete`, `partial` or
  `skipped` checks.
- A check that was `running` at the restart runs again.
- The audit trail shows the resume and which checks ran again.

Security invariants:

- A resumed check is authorized again by the gateway (no cached decision).

## REQ-PIPE-009: TLS on non-web services is checked

The system shall run testssl on every `tls_service` surface, using STARTTLS
where the protocol requires it.

Acceptance criteria:

- SMTP 25/587 use `--starttls smtp`; implicit-TLS ports (465, 993, 995, …)
  are checked directly.
- Findings name the service and port.
- testssl is one of the tools in the engagement's own tool list. Selected there, it
  runs on web and non-web services alike with no further approval; switched off
  there, it runs nowhere and the plan shows its checks as skipped
  (`tool_disabled`) (johannes, 2026-09-30).

Security invariants:

- testssl stays non-destructive (no `--heartbleed` exploitation beyond the
  existing `--vulnerable` checks).

## REQ-PIPE-010: The operator sees the plan and its progress

The system shall show the plan in the run detail: surfaces with class and
technologies, and per surface the checks with reason, state, duration and
findings.

Acceptance criteria:

- The Plan view updates while the run executes.
- Skipped checks are visible with their reason.

Security invariants:

- None.

## REQ-PIPE-011: The report states coverage

The system shall include a coverage section in the customer report: per
surface, which checks ran completely, partially, failed or were skipped, and
why.

Acceptance criteria:

- A run with any `partial` or `failed` check says so in the report summary.

Security invariants:

- None.

## REQ-PIPE-012: Egress throughput is measured and meets a target

The system shall measure requests per second through the egress proxy for one
engagement and for two in parallel, and document the result against a target
agreed with the owner.

Acceptance criteria:

- A repeatable measurement script exists and its result is recorded.
- Any change to the proxy's per-connection audit path is a separate R3/R4
  requirement with its own security review (decision D5).

Security invariants:

- Every forwarded connection stays audited and scope-checked.

## REQ-PIPE-013: nikto is retired; header findings come from httpx

The system shall no longer run nikto in the automatic pipeline, and shall
derive missing-security-header findings from the response headers httpx
already records.

Acceptance criteria:

- No scan run executes nikto; the registry note says why (always truncated at
  its budget, checks covered by nuclei's generic templates).
- Missing `Strict-Transport-Security`, `Content-Security-Policy`,
  `X-Content-Type-Options`, `X-Frame-Options` (or CSP `frame-ancestors`) and
  `Referrer-Policy` on a `web` surface produce the same findings nikto produced,
  without an extra request to the target.
- REQ-SCANQUAL-002 is marked superseded by this requirement.

Security invariants:

- None (removes a tool; adds no target contact).

## REQ-PIPE-014: The validate phase is removed until it has content

The system shall not run or display the validate phase while it performs no
validation.

Acceptance criteria:

- A scan run goes from agent to score directly; resumed runs stored at the old
  `validate` phase continue at `score`.
- The console no longer lists a validate phase.
- Concrete validations return only as their own requirement.

Security invariants:

- None.

## REQ-PIPE-015: At most two checks run in parallel per engagement

The system shall execute at most two check jobs of one engagement at the same
time.

Acceptance criteria:

- A third ready job waits until one of the two finishes.
- Jobs of different engagements do not count against each other.

Security invariants:

- Concurrency never bypasses the gateway, the rate policy or bug-bounty
  concurrency caps; the stricter limit wins.

## REQ-PIPE-016: The common-product fallback list is fixed and reviewable

The system shall keep the list of common web products used for surfaces with
an empty technology profile in one place in code, mirrored in the design
document.

Acceptance criteria:

- Initial list: wordpress, drupal, joomla, apache, nginx, iis, tomcat,
  jenkins, gitlab, grafana, confluence, jira, php, spring.
- A test fails when code and documentation diverge.

Security invariants:

- None.


## REQ-PIPE-017: The thorough profile plans a deep content-discovery sweep

The system shall, under the `thorough` scan profile, plan one deep
content-discovery check per web surface with a time budget sized to its
wordlist, instead of leaving that sweep to the Vector Agent's time-capped call.

Motivation: the `raft-medium-dirs` list has 29,999 entries; at the fixed rate
of 20 requests per second one pass needs about 25 minutes, but the agent's
ffuf call is capped at 240 s, so an agent-chosen sweep only ever tried the
first ~15 % of the list (int, 2026-09-30).

Acceptance criteria:

- Under `thorough`, every `web` surface that is neither an alias nor a
  duplicate virtual host has a planned check `ffuf:deep` (wordlist
  `raft-medium-dirs`) after its `ffuf` (`quickhits`) check. Under `standard`
  there is none; the `standard` plan is unchanged.
- The check's budget follows from the wordlist's entry count and the request
  rate (entries divided by rate, with a margin and the set-up time of ffuf's
  catch-all calibration), at most the runner maximum of 1,800 s. Entry counts
  of the allowed wordlists are kept in one table next to their keys; a test
  fails when a key has no count.
- A sweep cut short by its budget (slow target, or a bug-bounty program's
  lower rate cap) is `partial`: the hits found so far are kept and reported,
  and the check is never presented as a complete sweep.
- The hits become one finding of confidence `inferred` that names the
  wordlist; a catch-all responder is discarded as in REQ-DISCO-001.
- The check follows the engagement's tool list (ffuf switched off: skipped as
  `tool_disabled`) and is resumable like every check (REQ-PIPE-008).

Security invariants:

- Same tool, same allowlisted wordlist key, same per-call gateway
  authorization, same egress proxy and the same request rate as the existing
  ffuf check (a bug-bounty program's cap can only lower it). No new argument,
  wordlist key or path is introduced.
- The profile never widens scope, grants or switches; `thorough` only sends
  more of the same conservative requests (about 30,000 per web surface).

## REQ-PIPE-018: The Vector Agent sees what the pipeline already ran, and a partial result is reported as partial

The system shall tell the Vector Agent which checks the current scan run has
already finished or skipped, and shall never report the output of a check that
was stopped by its time limit as "no hits".

Acceptance criteria:

- The agent context lists, per host, the checks of the current run that are
  `complete`, `partial`, `failed` or skipped, with port, tool, outcome and, for
  ffuf, the wordlist; the list is compact and capped.
- The agent's evidence block shows it, and the agent prompt states that a
  completed check with the same tool and wordlist is not repeated, that full
  wordlist sweeps are the `thorough` plan's job, and that the agent's own
  ffuf is for targeted paths, reasoned candidates and small lists.
- An agent-dispatched ffuf that reaches its time limit returns the hits it
  found, marked partial, with an upper bound of how much of the wordlist was
  tried. It is never reported as "no hits" when output was discarded (defect
  found on int, 2026-09-30: the observation read "no hits" after a run that
  had been stopped by its limit).
- The agent's ffuf time cap (240 s) is unchanged.

Security invariants:

- The context is read-only; the agent still only proposes and the Scope Gateway
  decides. No argument validation or allowlist changes.
- The plan data given to the agent contains no target output, no credentials
  and no tool arguments other than the wordlist key and the nuclei mode.

## REQ-PIPE-019: Audit events of the egress proxy are committed in batches, and each request still waits for its own

GitHub issue #49 (R3: audit chain and proxy). During the fingerprint phase the
egress proxy sent one blocking request to the control plane per proxied
request - up to 150 per second, 2,176 in 30 seconds on 2026-09-30 - and each
took a pooled database connection and queued on the engagement's audit lock.
That starved the control plane (REQ-PIPE-020).

The system shall write the proxy's audit events in batches, under one lock
acquisition and one commit, without weakening the audit guarantees of
REQ-EGRESS-003 and REQ-AUDIT-001/002.

Acceptance criteria:

- The proxy sends the events of one engagement together (one request, at most
  200 events); the first event of an idle engagement is sent at once, so an
  idle proxy adds no delay, and events that arrive while a send is in flight go
  out together in the next one.
- The control plane chains and stores a batch under one per-engagement lock
  and one commit. A batch is all or nothing: any invalid event rejects the
  whole batch (422), and a failed write leaves no part of it behind.
- Timestamps within an engagement's audit log strictly increase, also inside a
  batch, so the predecessor lookup and the live stream's cursor are
  unambiguous; the predecessor lookup has a deterministic tie-break.
- `verify_audit_chain` recomputes every row's hash and predecessor link for an
  engagement and reports the first bad row. It passes after single, batched and
  concurrent writes.
- [Negative test] It detects a modified, a removed, an inserted and a reordered
  row.
- [Negative test] Fail closed, unchanged: a request is never forwarded before
  its audit record is committed, and when a batch cannot be written (control
  plane unavailable, refused, timed out) every request waiting on that batch is
  denied `503 audit_unavailable`. No event is dropped silently or sent
  fire-and-forget.
- [Negative test] Only an explicit 503 from the control plane (returned before
  anything was written) is retried, at most twice more; a timeout or any other
  failure is not retried, because the batch may have been committed and a retry
  would write the same events twice.
- The single-event endpoint remains for a proxy image that has not been
  rebuilt yet (rolling deployment).

Security invariants:

- Actor, action and the trimming of untrusted network metadata (20 keys, 64/500
  characters, reason 100) are identical to the single-event path; the batch
  endpoint accepts the same internal token only.
- The hash chain keeps its construction (`sha256(prev_hash || canonical_json(row))`);
  existing rows still verify.

## REQ-PIPE-020: A flood of audit traffic cannot starve the control plane

GitHub issue #49. The database pool was left at SQLAlchemy's default (5 + 10
connections, 30 s checkout), the live audit stream did blocking database calls
on the event loop, and a full pool therefore froze every request, including the
worker's cancel check (2 s timeout).

Acceptance criteria:

- Pool size, overflow and checkout timeout are settings (`DB_POOL_SIZE` 10,
  `DB_MAX_OVERFLOW` 10, `DB_POOL_TIMEOUT_SECONDS` 10); the default checkout
  timeout is shorter than the previous 30 s.
- The proxy's audit (single and batch) and rate-reservation calls share
  `INTERNAL_BULK_DB_SLOTS` (4) database slots. A caller that cannot get a slot
  within `INTERNAL_BULK_WAIT_SECONDS` (3) receives 503 before anything is
  written, and the proxy fails closed.
- [Negative test] With the pool held down to three connections, twelve threads
  flooding the audit endpoints do not delay a cancel check beyond one second,
  and the chain written under that load verifies. (Mutation check: with the
  slots effectively unlimited the test fails.)
- The live audit stream does no database work on the event loop: each poll runs
  in a worker thread, opens and closes its own session before any row is
  yielded, and a poll that cannot get a connection is skipped and retried, with
  the history still owed.
- [Negative test] A slow poll does not stop the event loop from running other
  work.
- A cancel poll rewrites `heartbeat_at` only when it is older than 15 s (the
  stale window is 300 s), so REQ-RESUME-004 is unchanged.
- [Negative test] In production the settings are refused when the pool or the
  timeout is out of range or when the bulk slots could take every connection.

Security invariants:

- No authorization, audit content or egress rule changes. A refused bulk call
  stops the proxied request (fail closed); it is never allowed through.

## REQ-PIPE-021: A missing cancel answer stops the run safely and a failed run says why

GitHub issue #49. The worker's "has the operator cancelled?" check was tolerant
in the per-tool wait loop (REQ-FIDELITY-001) but not in the plan executor, at
the phase boundaries, in the asset-review wait or in the agent loop: one
timed-out answer crashed the run as a bare `pipeline_error`, and a tool stopped
for that reason was recorded as `cancelled_by_operator`.

Acceptance criteria:

- An answer that could not be read is never taken as "not cancelled". One lost
  answer (or up to `ASM_CANCEL_STATUS_FAILURE_TOLERANCE`-1 consecutive ones) is
  absorbed; while it is unknown no new check is started.
- [Negative test] When the answer stays unreadable, nothing target-facing is
  started or continued: the executor starts no further checks, the checks
  already running finish and are recorded, unstarted ones stay `planned`
  (resumable), and the run ends `aborted` with the reason
  `cancellation_status_unavailable` - never as `pipeline_error`.
- A real operator cancel and a run taken over by a newer attempt behave as before.
- A tool stopped because the cancel status was unreadable makes its check
  `failed / cancellation_status_unavailable` (so coverage reads as degraded),
  not `skipped / cancelled_by_operator`. The console, the plan view and the
  customer report name the real reason.
- A check-row write that times out or gets a 5xx is retried; a superseded
  attempt (409) and any other client error are not.
- A run that fails for another reason records `pipeline_error:<ExceptionType>:<phase>`
  (type name only, never the message, which can carry a URL or a credential),
  and the console explains it. Ending a run is retried, and never raises; if it
  cannot be recorded the run stays claimed and the reaper resumes or aborts it
  (REQ-RESUME-003). (Amends the bare `pipeline_error` reason of issue #29; the
  `task_time_limit_exceeded` reason is unchanged.)

Security invariants:

- The fail-closed property of cancellation is kept and made consistent: a
  missing answer never lets target-facing work continue.

**Security review:** pending - human review by johannes (project/security
owner) is owed for REQ-PIPE-019..021 (R3: audit chain, egress proxy, fail-closed
cancellation). Rolled out to int on his explicit instruction (2026-10-01) ahead
of that review, per the precedent of REQ-PIPE-017/018.
