---
title: Console information architecture (findings first, mobile, on-demand loading)
status: implemented
risk: R1
owner: product-engineering
---

# Console Information Architecture

Context: the 2026-09-27 review (findings D6, D7) found that the engagement
page puts findings — what users come for — last, below runs, reports, a
large graph, and DNS; that there is no single list of findings across
engagements; and that phones get the full sidebar before any content. The
build also warns that the main bundle is too large, mostly because of the
graph library. johannes approved the recommended tabbed layout and the
implementation of these items on 2026-09-29.

**Risk class: R1** (UI only). The API and edge changes for the
cross-engagement list are R3 and live in
[`cross-engagement-findings.md`](cross-engagement-findings.md).

Tests must verify these requirements directly. Do not weaken tests to match
implementation; update implementation when it violates this document.

## REQ-CONSOLE-013: The engagement page opens on its findings

Acceptance criteria:

- Below the header, status band, authorization and draft blocks, and the
  "Start a scan run" panel, the page has three tabs: **Findings** (default),
  **Assets** (attack-surface graph, DNS & hosting), and **Runs & reports**.
- The selected tab is part of the URL (`?tab=assets`, `?tab=runs`); no or an
  unknown value shows Findings. Changing tabs adds a history entry, so Back
  returns to the previous tab, and a reload keeps the tab.
- `?finding=<id>` (optionally with `&status=<status>`) opens the Findings
  tab with that finding expanded and scrolled into view.
- Data for a tab is requested only while that tab is shown. Always loaded:
  the engagement, readiness, summary, runs (for the header and the start
  button), and scope assets (for the authorization block).
- Existing links keep working: `/engagements/:id`, `…/runs/:runId`,
  `…/edit`, `…/audit`, and the `/live` and `/results` redirects.
- [Negative test] An unknown engagement still shows only "Engagement not
  found" (REQ-CONSOLE-008): no tabs, no tab content, no requests for it.
- For an active engagement on a 1440×900 screen, the findings table header
  and first row are visible without scrolling, also when the engagement
  cannot scan yet and lists its blockers. To make room, readiness and the
  Start run button share one compact panel, and the severity filter is a row
  of chips inside the findings panel (counts shown on the Open tab, where
  they apply) instead of a separate panel.
- On a phone the four header metrics take two rows, not four.

## REQ-CONSOLE-014: Navigation collapses on small screens

Acceptance criteria:

- At 1040 px wide and narrower (the existing one-column breakpoint) the
  sidebar is replaced by a top bar with the logo and a menu button; the
  navigation opens as a drawer over the content. While closed, the drawer's
  links are not reachable with Tab.
- The menu button is a `<button>` with `aria-expanded`, `aria-controls`, and
  the accessible name "Open navigation" / "Close navigation".
- The drawer closes when a page is chosen, on Escape, and on a click on the
  backdrop. Focus moves into the drawer when it opens and back to the menu
  button when it closes; Tab stays inside the open drawer.
- Pending approvals still surface on every page (REQ-APPROVALUI-001).
- At 390 px wide no console page scrolls horizontally; wide tables scroll
  inside their own container.
- Wider than 1040 px the layout is unchanged.

## REQ-CONSOLE-015: Heavy libraries load only where they are used

Acceptance criteria:

- The graph library (`cytoscape`, `cytoscape-dagre`) is in its own chunk,
  loaded when the attack-surface graph is first shown.
- The QR-code library is loaded only when an MFA enrollment QR code is
  drawn (login enrollment and re-enrollment on the Account page).
- While a chunk loads, a short placeholder is shown; if it fails to load
  (for example after a deploy replaced the files), an error with a reload
  button is shown instead of an empty area.
- The production build has no chunk-size warning (every chunk below 500 kB
  minified); the warning limit is not raised.
- No Content-Security-Policy change is needed: chunks are same-origin
  scripts (REQ-WEBSEC-001).

## REQ-CONSOLE-016: One findings list across engagements

Acceptance criteria:

- A sidebar entry "Findings" opens `/findings`: the findings of every
  engagement the user can see, from the API in REQ-PORTFOLIO-001.
- Default view: open findings, sorted by severity, then risk score.
- Status tabs (Open, Accepted risk, False positive, Resolved) with counts;
  filters for severity, engagement, and a text search on finding and
  target; 50 findings per page with next/previous.
- The filters are part of the URL, so a filtered view can be reloaded and
  shared with another user who can see the same engagements.
- Each row shows severity, finding, engagement, target, and last seen.
  Opening a row shows the same detail as the engagement page (Lens Agent
  analysis, triage, facts, evidence) and a link that opens the finding in
  its engagement (`/engagements/:id?finding=<id>&status=<status>`).
- Triage from this page uses the engagement's triage endpoint
  (REQ-TRIAGE-001), so ownership and audit are unchanged.
- An empty result says why (no engagements, nothing open, or no match for
  the filters).

Security invariants:

- None changed. The console only shows what the API returns; ownership is
  enforced server-side (REQ-PORTFOLIO-001, REQ-IAM-007).

Verification log:

- 2026-09-29 — implemented; source checks, a real-browser run (39/39), and
  the build size are recorded in
  [`../test-cases/console-information-architecture.md`](../test-cases/console-information-architecture.md).
