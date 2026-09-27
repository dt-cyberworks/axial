---
title: Console layout, navigation, and admin access verification
status: ready
risk: R2
owner: product-engineering
---

# Console Layout, Navigation, and Admin Access Verification

## TC-CONSOLE-001: Layout adapts to wide and narrow viewports

Requirements:

- REQ-CONSOLE-001

Automated tests:

- `frontend/tests/console_layout_requirements.test.mjs`

Objective:

Prove the app shell is capped on wide monitors and existing narrow-viewport
reflow breakpoints remain intact.

Expected results:

- `.app-shell` has a `max-width` rule.
- All pre-existing media-query breakpoints (1040/900/760/720/620px) are
  still present.
- Data tables scroll horizontally within their own container.

## TC-CONSOLE-002: Admin pages are consolidated and access-gated

Requirements:

- REQ-CONSOLE-002

Automated tests:

- `frontend/tests/console_layout_requirements.test.mjs`

Objective:

Prove Agent settings, Users, and Account audit are reachable from one
admin-gated `Admin` nav entry/route, the gate is enforced by the page itself
(not only nav visibility), and the three underlying pages are unchanged.

Expected results:

- One `Admin` nav link/route exists; the three former separate nav entries
  are gone.
- `AdminHome` checks the caller's role and shows an access-denied message for
  non-admins, rather than relying solely on the nav link being hidden.
- Old direct links (`/settings`, `/admin/users`, `/admin/audit`) redirect to
  `/admin`.
- `Settings`/`AdminUsers`/`AdminAudit` components are unchanged.

## TC-CONSOLE-003: Static sidebar banner is removed without collateral damage

Requirements:

- REQ-CONSOLE-003

Automated tests:

- `frontend/tests/console_layout_requirements.test.mjs`

Objective:

Prove the persistent sidebar guardrail banner and its CSS are gone, while the
unrelated engagement-wizard review row using similar wording is untouched.

Expected results:

- No `guardrail-panel` element or "Default guardrails" text remains in the
  sidebar; no dead CSS for it remains.
- The wizard's step-4 "Scope enforcement" review row is unaffected.

## TC-CONSOLE-004: Legacy shared token — documented answer

Requirements:

- REQ-CONSOLE-004

Automated tests:

- `frontend/tests/console_layout_requirements.test.mjs`

Objective:

Prove the requirements doc records the answer (no such UI exists) as a
durable reference, since no code change accompanies this item.

Expected results:

- The requirements doc states plainly that no shared/legacy-token page or
  menu exists in the console today.

## TC-CONSOLE-005: The account nav entry is labeled, not named

Requirements:

- REQ-CONSOLE-005

Automated tests:

- `frontend/tests/console_layout_requirements.test.mjs`

Objective:

Confirm the sidebar entry carries a fixed destination label while still showing
who is signed in.

Expected results:

- The nav entry renders the literal label `Account`.
- `me.display_name` is no longer the nav entry's label; it renders as a
  secondary line within the entry.
- The `/account` route itself is unchanged.

## TC-CONSOLE-006: The admin settings tab is labeled for its real scope

Requirements:

- REQ-CONSOLE-006

Automated tests:

- `frontend/tests/console_layout_requirements.test.mjs`

Objective:

Confirm the Admin page's settings tab is labeled for what `Settings.tsx`
actually contains (mostly platform-wide operational config), not as if it
were agent-only, and that the other two tab labels are untouched.

Expected results:

- The settings tab renders the label `Operational settings`.
- The misleading `Agent settings` label is gone.
- The `Users` and `Account audit` tab labels are unchanged.

## TC-CONSOLE-007: Logout is a one-click sidebar action, shared with the Account page

Requirements:

- REQ-CONSOLE-007

Automated tests:

- `frontend/tests/console_layout_requirements.test.mjs`

Objective:

Confirm a logout action exists directly in the sidebar (not only inside the
Account page), and that it performs the same logout as the Account page's own
button via one shared implementation rather than a duplicated copy.

Expected results:

- The sidebar renders a `Log out` action.
- Both the sidebar and `Account.tsx` obtain their logout behavior from the
  same shared `useLogout` hook, not two independent implementations of
  session-clear + redirect.
- The `/account` route and its own logout button are otherwise unchanged.

Objective:

Pin the admin tab labels so a rename is a deliberate, visible change.

Expected results:

- The settings tab label reads `Operational settings`.
- The label `Agent settings` no longer appears in `AdminHome.tsx`.
- The `Users` and `Account audit` labels are unchanged.
