---
title: Operator authorization workflow
status: implemented
risk: R3
owner: product-engineering
---

# Operator Authorization UX Requirements

This document is the requirement source for the operator-facing authorization flow. Tests must verify these requirements directly. Do not weaken tests to match implementation; update implementation when it violates this document.

## REQ-AUTH-001: Engagement Source Is Hidden From The Default Operator Flow

Operators create a normal ASM engagement without choosing an internal `source` profile. The product may keep an internal `source` field for compatibility, but the default new-engagement wizard must not show a source-selection step or source-segmented control.

**Amended 2026-08-11 (GitHub issue #12):** a real gap existed - bug-bounty program policy (rate cap, mandatory self-identification) was only reachable via a direct API call, invisible in the GUI, and the HTTPS identification path was silently broken (see REQ-AUTH-006). Closing that gap needs `source=bug_bounty` to be settable from the wizard somehow. The amendment is narrow and deliberate: ONE opt-in toggle ("this engagement follows a bug bounty program's rules of engagement") inside the existing `Tools` step, which internally sets `source` as a side effect of that specific, clearly-labeled choice. This is not the general-purpose `source` picker this requirement forbids - see the sharpened acceptance criteria below.

Acceptance criteria:
- The wizard step list is exactly: `Window`, `Scope`, `Tools`, `Review`, `Authorize` - unchanged; the bounty toggle lives inside `Tools`, not a new step.
- The wizard does not render a labeled `Engagement source` field or control anywhere.
- The wizard does not offer a general picker of `lab`, `own_domain`, `bug_bounty`, or `customer` as parallel choices. The ONE exception is the single bug-bounty opt-in checkbox (REQ-AUTH-006) - checking it is a policy decision ("this program requires X"), not a source-profile selection, and it never exposes `lab` or `customer` as reachable choices at all.
- New engagements can still be created without the frontend providing `source` (the default, unchanged path). `source` is sent ONLY when the bounty-program checkbox is explicitly checked.

## REQ-AUTH-002: Operator Language Uses Authorization, Not Ownership

The operator is attesting permission to test, not proving DNS/domain ownership in the UI. The visible GUI language must therefore use authorization terms.

Acceptance criteria:
- The scope editor uses `authorization attested` for the checkbox label.
- The live activation panel uses `Attest authorization` for the action button.
- User-facing warning/error text refers to `authorization attestation` or `authorization`, not `ownership`.
- Internal API/model field names may remain unchanged until a database migration is planned.

## REQ-AUTH-003: Internal Source Is Not Shown In Operator List/Edit Screens

The dashboard and metadata edit page must not expose the internal source profile as normal operator configuration.

**Amended 2026-08-11 (GitHub issue #12):** same narrow carve-out as REQ-AUTH-001, mirrored on the edit page so an operator can enable/correct a bug-bounty program's policy on an existing engagement, not only a brand-new one.

Acceptance criteria:
- The dashboard engagement table has no `Source` column.
- The edit page has no general source selector (no dropdown of `lab`/`own_domain`/`bug_bounty`/`customer`).
- The routine Metadata save (title, dates, contact, AI-testing toggle, asset-review toggle, scan envelope) never sends `source` - only the dedicated bug-bounty program policy section's own save action can, and only when that section's opt-in checkbox is checked (REQ-AUTH-006).

## REQ-AUTH-004: Authorization PDF Is Available From The GUI

Before activation, the operator must be able to download a customer-understandable PDF that documents exactly what is configured and can be signed.

Acceptance criteria:
- The final wizard step contains `Download authorization PDF`.
- The live engagement view contains an `Authorization PDF` link.
- The frontend API exposes an `authorizationPdfUrl(id)` helper using `/engagements/{id}/authorization-pdf`.

## REQ-AUTH-005: Authorization PDF Content Is Customer Understandable

The generated PDF must summarize the engagement in customer-readable language and include enough detail for signature.

Acceptance criteria:
- The backend exposes `GET /engagements/{engagement_id}/authorization-pdf`.
- The response media type is `application/pdf`.
- The generated document includes the engagement title, ID, test window, emergency contact, scope allow/deny entries, tool grants, manual approval tools, guardrails, a checksum, and customer/provider signature fields.
- PDF generation is audited with an `authorization_pdf_generated` audit action.

## REQ-AUTH-006: A Bug-Bounty Program's Rules Of Engagement Are Configurable And Actually Honored On HTTPS

Context: reported as GitHub issue #12, 2026-08-11. `Engagement.source = "bug_bounty"` plus a linked `bounty_program` row (platform, program reference, policy hash, rate/concurrency caps, a mandatory identification header, an optional User-Agent suffix) already existed end to end in the data model and gateway - but was reachable only via a direct API call, invisible in the GUI (REQ-AUTH-001/003 forbade any UI for it at all, not just a raw `source` picker). Worse: the egress-proxy's own mandatory-identification injection (`egress-proxy/app/proxy.py::_forward_plain_http`) only covers plain HTTP - for HTTPS (a `CONNECT` tunnel, the payload is opaque to the proxy), the proxy's own docstring says injection "happens at the application level in the worker" - but nothing in `worker/app` implemented that. Running this scanner against a real HTTPS bug-bounty target would have silently violated a mandatory identification requirement with no visible indication that it wasn't being honored. This document's frontmatter risk moves R2 -> R3 to reflect that.

**Amended 2026-08-12:** live-testing the new GUI against two real Intigriti programs (Port of Antwerp-Bruges, Brazzers/Aylo, looked up via Intigriti's researcher API) surfaced two problems with the original acceptance criteria, both reported by johannes and confirmed by inspection:

1. `policy_sha256` assumed every program publishes a stable, hashable "rules-of-engagement document." Real programs expose their rules as dynamic, company-editable API/webpage prose with no downloadable artifact and no version marker visible to researchers - there is no single byte sequence "the document" unambiguously refers to. The field was also never read anywhere downstream (`control-plane/app/gateway`, `egress-proxy`, and `worker` all ignore it - confirmed by grep), so it functioned only as a mandatory box blocking save, not an enforced integrity check. **It is removed** - dropped from the schema, model, and database column entirely, not merely made optional.
2. Mandating an identification header/value assumed every program requires one. Port of Antwerp-Bruges does not (`requestHeader: null` in Intigriti's own API) - its identification mechanism is an out-of-band `<handle>@intigriti.me` email alias used at account signup, which HTTP header injection cannot express and this feature does not attempt to. The identification header/value and User-Agent suffix become **optional**: when unset, the worker injects nothing, exactly like today's already-implemented non-bug_bounty behavior - `worker/app/tool_runner_client.py`'s `_bounty_ident_for`/`_bounty_h_flags` already treat a missing name/value as "inject nothing" (this was written defensively from the start to cover the non-bug_bounty case; this amendment only makes that same path reachable for a bug_bounty engagement that itself has no header requirement). Platform and program reference remain mandatory - they identify which program's policy this is.

Acceptance criteria:

- An operator can see and set a bug-bounty program's policy (platform, program reference - both mandatory; max requests/second, max concurrency, identification header name/value, optional User-Agent suffix - all optional) from the engagement wizard's `Tools` step, behind the one opt-in toggle described in REQ-AUTH-001's amendment, and from the engagement edit page (same fields, same toggle, mirrored per REQ-AUTH-003's amendment).
- Submitting the toggle sets `Engagement.source = "bug_bounty"` and creates (or, on a later resubmission, replaces) exactly one linked `bounty_program` row for that engagement - never more than one.
- Whatever identification header/value is configured is actually sent on every automated request to the target for a bug_bounty engagement, on **every** HTTP-proxied tool (`httpx`, `nikto`, `wafw00f`, `testssl`, `nuclei`, `http_request`, `ffuf`) - including HTTPS, where the egress-proxy cannot see or inject it itself. The configured User-Agent suffix is sent wherever the tool exposes a User-Agent override.
- The injection point is server-side, inside `worker/app/tool_runner_client.py`'s single dispatch chokepoint (`ToolRunnerClient.run()`), never something an agent proposal's own arguments can set, omit, or override - an agent-supplied header of the same name is superseded, never merged or left in place.
- A non-bug_bounty engagement's tool invocations are completely unaffected - no header, no UA change, no extra lookup cost beyond one cached-per-run config check.
- **NEGATIVE**: a bug-bounty engagement's `http_request` call where the agent itself supplies a conflicting value for the mandatory identification header (or a `User-Agent` header) still sends the platform's configured value, not the agent's.
- **NEGATIVE**: a lookup failure (control-plane unreachable) degrades to sending the request unidentified, exactly like a non-bug_bounty engagement - it must never abort the scan.
- **NEGATIVE**: a bug_bounty engagement whose program has no identification header configured (both `ident_header_value` and `ident_header_name` absent, or `ident_header_value` empty) behaves identically to a non-bug_bounty engagement for header/UA injection purposes - no header is sent, this is not treated as a lookup failure, and it does not block saving the policy or activating the engagement.

**Amended 2026-08-12 (GitHub issue #32):** the previous amendment's "does not
block ... activating the engagement" criterion was implemented in the
worker's injection call sites only. Three other enforcement points still
assumed a header was mandatory and were never updated to match: the Scope
Gateway (`control-plane/app/gateway/authorize.py`) hard-denied every active
call for a header-less program, `scan_readiness.evaluate()` reported such
an engagement as permanently blocked, and the egress-proxy
(`egress-proxy/app/proxy.py::_forward_plain_http`) could send a literal
`X-Bug-Bounty: None` header to the real target (`bounty_program_for()`
returns a truthy dict whenever a `bounty_program` row exists, even with
`ident_header_value IS NULL`). Fixed: readiness and the gateway now require
only that a `bounty_program` row exists (platform/program_ref remain
mandatory) - an unset header is no longer itself a blocker; the gateway's
dedicated ident-header-presence check (previously step 7) was removed
outright rather than narrowed, since the earlier "does a program exist at
all" check (step 3) already covers the only case that must still deny. The
egress-proxy's injection guard now checks the header value is actually
present (`prog and prog.get("ident_header_value")`), not just that the row
exists, mirroring the worker's own `if ident_name and ident_value:` pattern.

Additional acceptance criteria (2026-08-12 amendment):

- `scan_readiness.evaluate()` reports a bug_bounty engagement ready (no
  `bounty_program_missing` blocker) once a `bounty_program` row exists,
  regardless of whether `ident_header_value` is set.
- The Scope Gateway's `authorize()` allows an otherwise-valid active call
  for such an engagement - the only remaining bug_bounty-specific denial is
  `bounty_program_missing` when no program row exists at all.
- The egress-proxy never sends a header whose value is the string `None` or
  empty for a bug_bounty engagement with no configured header; plain-HTTP
  requests are forwarded with the same header set as a non-bug_bounty
  engagement.
- **NEGATIVE (regression guard)**: a bug_bounty engagement with no
  `bounty_program` row at all is still denied by both readiness
  (`bounty_program_missing`) and the gateway (`bounty_program_missing`) -
  only the "row exists, header unset" case is relaxed.
- **NEGATIVE (regression guard)**: a bug_bounty engagement with a
  configured header continues to have it enforced/injected at every point
  exactly as before this amendment.
