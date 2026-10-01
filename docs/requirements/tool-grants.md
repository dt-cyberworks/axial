---
title: Tool grant semantics
status: implemented
risk: R3
owner: security-engineering
---

# Tool Grant Semantics Requirements

The operator must be able to understand which tool permissions authorize OSINT-only enrichment and which permissions authorize target-touching checks. Passive mode is intentionally narrow: it is useful for discovery and enrichment from public or third-party sources, not for validating live service behavior.

## REQ-TOOL-001: Passive grants are only offered for real passive tools

The Tool grants UI must only offer a passive checkbox for a category when the capability registry exposes at least one enabled tool in that category with `execution_class == "passive"`.

Acceptance criteria:

- Categories without enabled passive tools show `No passive tools` instead of a passive checkbox.
- The category summary names the concrete passive tools when passive mode is available.
- Passive help text explains that passive tools use OSINT or public/third-party data sources and do not run target-touching checks.

## REQ-TOOL-002: Passive grants are persisted only when they can be executed

Saving the Tool grants step must not create passive grants for categories that have no enabled passive tools. This keeps the engagement policy aligned with the actual capability registry and avoids misleading audit artifacts.

Acceptance criteria:

- The wizard derives passive availability from the tool capability registry.
- Passive grants are saved only for categories where the derived passive tool list is non-empty.
- Recon can be passive when tools such as `subfinder` or `amass` are enabled; fingerprint, vuln, cred, and exploit are not shown as passive unless future registry entries add real passive tools.

## REQ-TOOL-003: Gateway enforces passive mode as a real permission

The Scope Gateway must treat passive mode as an explicit grant, not as an implicit bypass. A passive call must still be in scope, whitelisted, argument-safe, and backed by a passive category grant.

Acceptance criteria:

- A passive tool call without `tool_grant(mode="passive")` is denied with `no_tool_grant`.
- A passive tool call for a non-passive registry tool is denied with `passive_not_supported`.
- Audit UI explains `passive_not_supported` in operator-readable language.

## REQ-TOOL-006: Tool categories can be granted after an engagement has left draft

GitHub issue #48 (R3: changes what an engagement is authorized to run). An
engagement created without ticking a tool category was stuck: the console showed
`no_active_tool_grant`, the grants editor only existed for drafts, and the
"Campaign tool overrides" cannot create a grant. The GUI had two separate tool
settings and nothing explained the difference.

Acceptance criteria:

- Tool grants are editable for every engagement that is not `completed` or
  `revoked`: on the draft's detail page and on the Edit page, next to the
  per-tool switches. The API enforces the same (409 for `completed`/`revoked`).
- An engagement created with no tool category can have one granted afterwards,
  and the `no_active_tool_grant` blocker clears without recreating the
  engagement. The blocker is a plain sentence that links to the place where it
  is fixed (`action: "tool_grants"`).
- [Negative test] Granting an ACTIVE category on an engagement that has left
  draft needs an explicit confirmation (`confirm_widening`). Without it the
  request is refused (409 `confirmation_required`) and nothing is written. The
  console asks with a dialog that names the category and says the change
  widens the engagement's authority. Passive grants, repeated saves of an
  existing grant and every change while still a draft need no confirmation.
- [Negative test] While a scan is running (`running` or `waiting_approval`),
  no grant is added or changed (409 `scan_run_active`, nothing written); the
  console says to wait or cancel the scan. Removing a grant is always allowed.
- [Negative test] `tool_category` and `mode` are validated (an unknown value is
  422, not a database error).
- The Scope Gateway is unchanged: it reads the grants on every call, so a change
  applies from the next tool call, including when an approval resumes.

Security invariants:

- Only the engagement's owner or an admin can change grants (the router-level
  ownership check, REQ-IAM-007); anyone else gets 404 and nothing is written.
- No override or GUI state lets a tool run without a matching category grant.

## REQ-TOOL-007: A tool category grant can be taken away

Acceptance criteria:

- `DELETE /engagements/{id}/tool-grants/{category}/{mode}` removes a grant
  (404 if there is none; 409 for a `completed`/`revoked` engagement). The
  Tool grants table removes a saved grant when its box is unticked - saving
  used to only add.
- [Negative test] After a removal the gateway denies that category from the next
  call (`no_tool_grant`), also while a scan is running and also for an approval
  that resumes; "Force on" for a tool never replaces the grant.
- Removing a grant leaves the campaign's per-tool switches and approval flags
  untouched.

## REQ-TOOL-008: Grant changes are audited, never reset a campaign's switches, and the tool settings explain themselves

Acceptance criteria:

- Every grant addition and removal is written to the hash-chained audit log in
  the same transaction as the change, with the acting user, the category, the
  mode, whether it replaced an existing grant, the manual-approval tools, the
  engagement status and whether the widening was confirmed
  (`tool_grant_added`, `tool_grant_removed`). The audit page shows who did what.
- [Negative test] Saving grants keeps a campaign's on/off switch (`Force on`,
  `Force off`): only the approval flag of a category's tools is written by the
  grants editor, and a row with nothing left in it is removed. (Saving an active
  grant used to delete every such row of the category, silently resetting the
  Force off chosen on the Edit page.)
- The authorization export (`_authorization_config_payload`) lists the current
  grants and the campaign's per-tool switches, so an export made after a change
  matches what the gateway will enforce.
- The Edit page explains the layers (built into this version, then Settings, then
  this campaign), what "Force on" cannot do, and what the Approval box means. The
  tool table says whether each tool can run and, if not, why: not installed, its
  category is not granted (with a link to the grants), off in Settings, off for
  this campaign, or off by default. `GET /engagements/{id}/config` returns
  `granted` and `unavailable_reason` per tool.
- The audit reasons `no_tool_grant` and `tool_disabled` say where to fix it.

**Security review:** pending - human review by johannes (project/security owner)
is owed for REQ-TOOL-006..008 (R3: authorization, audit). Rolled out to int on his
explicit instruction (2026-10-01) ahead of that review.
