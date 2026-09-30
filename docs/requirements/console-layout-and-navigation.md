---
title: Console layout, navigation, and admin access consolidation
status: implemented
risk: R2
owner: product-engineering
---

# Console Layout, Navigation, and Admin Access Consolidation

Context: several small operator-console issues were reported together after
live use of the console: the layout doesn't adapt well to phones or very wide
monitors, admin-facing pages (Agent settings, Users, Account audit) were
scattered across separate top-level nav entries with an inconsistent
access-control story (Agent settings was open to every operator; Users and
Account audit were already admin-only), and a static sidebar banner restating
the Scope Gateway's behavior added no operator value. A question about a
"legacy shared token" menu was also raised and is answered here rather than
built, since no such UI exists.

**Risk class: R2** for the navigation/layout changes (plain frontend
restructuring). The admin-menu consolidation additionally **tightens access
control** (see REQ-CONSOLE-002) — confirmed explicitly with the repository
owner (2026-07-29) rather than assumed, since it changes who can reach
Settings.

## REQ-CONSOLE-001: The layout adapts to both small and very wide viewports

Acceptance criteria:

- The app shell has a maximum width on very wide monitors (previously
  uncapped, so content stretched edge-to-edge indefinitely); it stays
  centered rather than expanding without bound.
- Existing breakpoints (reflowing the sidebar to stack above content, then to
  a single-column nav) continue to work correctly down to a 375px phone
  viewport; data tables scroll horizontally within their own container
  rather than breaking page layout at any width.
- No new navigation paradigm (hamburger/off-canvas menu) is introduced —
  existing reflow behavior is the correct foundation and is preserved.

## REQ-CONSOLE-002: Admin-facing pages are consolidated under one nav entry, admin-only

Acceptance criteria:

- Agent settings, Users, and Account audit are reachable from a single
  `Admin` nav item and route (`/admin`), presented as tabs, rather than three
  separate top-level nav entries.
- The `Admin` nav item and route are visible and reachable **only** for the
  `admin` role — this is enforced by the page itself (not only by hiding the
  nav link), so a non-admin operator navigating directly to `/admin` or
  `/settings` sees a clear "you need an administrator role" message instead
  of the page content.
- This is an explicit, deliberate **tightening** of prior behavior: Agent
  settings (LLM provider config, tool policy, scan rate policy, NVD API key,
  agent prompt/iteration budget) was previously reachable by every operator;
  it is now admin-only, matching Users and Account audit.
- Old direct links (`/settings`, `/admin/users`, `/admin/audit`) redirect to
  `/admin` rather than 404ing, so no existing bookmark or saved link breaks.
- The three underlying pages' own behavior (Settings/Users/Account audit) is
  unchanged — only their navigation entry point and access gate move.

Security invariants:

- No change to the Scope Gateway, tool authorization, or audit trail — this
  is an operator-console access-control change only, using the same
  `role === "admin"` check already enforced server-side for the Users/Audit
  endpoints.

## REQ-CONSOLE-003: The static sidebar guardrail banner is removed

Acceptance criteria:

- The persistent sidebar text ("Default guardrails" / "Scope Gateway
  authorizes every active tool call. Deny decisions win and agent proposals
  stay advisory.") is removed; it restated the Scope Gateway's behavior
  without giving the operator anything actionable.
- The unrelated, legitimate near-duplicate phrase in the engagement wizard's
  step-4 authorization review (`Scope enforcement: Scope Gateway authorizes
  every active tool call`) is explicitly out of scope and unaffected — it is
  a per-engagement config review row, not a persistent banner.

## REQ-CONSOLE-004: "Legacy shared token" — answered, not built

Context: the operator asked what the "legacy shared token" menu is and
whether it is a user or admin setting. This is a documented answer, not a
code change.

Acceptance criteria:

- There is no shared/legacy-token page or menu anywhere in the console
  today. The old shared operator token (`OPERATOR_API_TOKEN`) was already
  fully replaced, frontend-side, by the per-user session cookie
  (`HttpOnly`, see REQ-IAM-018) as part of REQ-IAM-002's multi-user authentication
  system.
- `INTERNAL_API_TOKEN` (control-plane ↔ worker) and `RUNNER_API_TOKEN`
  (tool-runner auth) are unrelated, backend-only, server-to-server secrets
  configured via environment variables — they are not, and should not
  become, a console menu item; there is nothing for a user or admin to
  manage for these through the GUI.

## REQ-CONSOLE-005: The account nav entry has a fixed label, not the user's name

Context: reported 2026-08-09 - the sidebar's link to `/account` rendered
`{me.display_name}`, so for a user named "Test Account" the navigation read
"Test Account", which looks like a separate feature rather than "this is your
account". The destination is unambiguously a settings page (change password,
MFA re-enrollment, active sessions, log out).

Acceptance criteria:

- The nav entry's label is the fixed string `Account`, independent of who is
  signed in.
- The signed-in identity is still visible in the sidebar, as a secondary line
  within the same entry rather than as the label itself - "who am I signed in
  as" is genuinely useful and is not lost by this change.
- No route, permission, or page behavior changes; this is a labeling change
  only.

## REQ-CONSOLE-006: The admin settings tab is labeled for what it actually contains

Context: reported 2026-08-09 - the Admin page's first tab was labeled "Agent
settings", but it opens `Settings.tsx`, whose seven sections are mostly
platform-wide operational config (scan rate policy, LLM provider, NVD API key,
tool policy, manual-approval timeout); only two are agent-specific (iteration
budget, instructions). The page's own heading already reads "Settings" under
the eyebrow "Operational guardrails" - only the tab button disagreed.

Acceptance criteria:

- The tab label reflects the page's real scope (`Operational settings`) rather
  than implying agent-only configuration.
- The other two tab labels (`Users`, `Account audit`) are unchanged.
- A regression test covers the admin tab labels, so any future relabeling is a
  deliberate, visible change rather than silent drift.

## REQ-CONSOLE-007: Logging out is reachable in one click from anywhere

Context: reported as GitHub issue #11, 2026-08-10 - a working logout action
existed (`Account.tsx`), but was reachable only by first navigating into
`/account` and finding it there; nothing in the sidebar itself was labeled
"Log out" or hinted that it lived on the Account page. For an operator
console handling authenticated sessions, one-click logout from any page is
the expected baseline, not something requiring a detour through settings.

Acceptance criteria:

- A "Log out" action is present directly in the sidebar, reachable from every
  page, without first navigating to the Account page.
- Both the sidebar action and the Account page's own "Log out" button perform
  the exact same logout (session revoked server-side, local session state
  cleared, redirect to `/login`) via one shared implementation - not two
  copies of the same three steps that could silently drift apart.
- No route, permission, or session-lifetime behavior changes; this is a
  discoverability/placement fix only.
