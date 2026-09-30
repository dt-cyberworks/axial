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

