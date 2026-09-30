---
title: Console information architecture verification
status: ready
risk: R1
owner: product-engineering
---

# Console Information Architecture Verification

Verifies [`../requirements/console-information-architecture.md`](../requirements/console-information-architecture.md).
The source-level checks below run in CI. The behavior was also checked on
2026-09-29 in a real browser (system Chrome via Playwright) against a local
stack: the control plane from the working tree, the real `edge/Caddyfile`
serving a production build, and a seeded database with two operators and an
admin — 39 of 39 checks passed, at 1440×900, 1041×900, and 390×844.
The browser check found three problems the source checks could not, all fixed
before this record: the findings table started below the fold at 1440×900,
the pager showed the next page's range before its rows had loaded, and
opening the drawer did not move focus into it (a CSS visibility transition).

## TC-CONSOLE-013: Findings-first engagement page

Requirements:

- REQ-CONSOLE-013

Automated tests:

- `frontend/tests/console_information_architecture.test.mjs`
- `frontend/tests/console_robustness_requirements.test.mjs`
- `frontend/tests/finding_triage_requirements.test.mjs`

Objective:

Prove the engagement page opens on its findings, keeps the tab and the
opened finding in the URL, and requests a tab's data only while it is shown.

Expected results:

- Tabs in the order Findings, Assets, Runs & reports; no or an unknown `?tab=` shows Findings.
- A tab change pushes a history entry; expanding a finding or changing the status filter replaces it.
- Only the active tab is mounted; the reports query is enabled only on the runs tab.
- The not-found page is returned before any tab is rendered.
- Existing routes and redirects are still defined.
- Browser: the findings table header and first row are visible at 1440×900; no graph, DNS, or report request on the Findings tab; Back/reload keep the tab; `?finding=` reopens the finding after a reload.

## TC-CONSOLE-014: Navigation on small screens

Requirements:

- REQ-CONSOLE-014

Automated tests:

- `frontend/tests/console_information_architecture.test.mjs`

Objective:

Prove the sidebar becomes an accessible drawer at the one-column breakpoint
and stays unchanged on wider screens.

Expected results:

- Menu button with `aria-expanded`, `aria-controls`, and "Open navigation" / "Close navigation".
- Escape, a backdrop click, and navigation close the drawer; focus returns to the menu button; Tab stays in the drawer.
- The closed drawer is `visibility: hidden` (not reachable with Tab); every z-index stays below the approval modal.
- Browser at 390 px: all of the above, and no horizontal page scroll on overview, findings, engagement (all tabs), wizard, docs, and account. At 1041 px: sidebar visible, no top bar.

## TC-CONSOLE-015: On-demand loading

Requirements:

- REQ-CONSOLE-015

Automated tests:

- `frontend/tests/console_information_architecture.test.mjs`
- `frontend/tests/surface_graph_requirements.test.mjs`

Objective:

Prove the graph and QR-code libraries are not in the main bundle and that a
failed load is shown.

Expected results:

- `SurfaceGraph` is imported with `React.lazy` inside `ChunkErrorBoundary` and `Suspense`; no other module imports `cytoscape` or `SurfaceGraph` statically.
- Login and Account load `qrcode` through `qrCodeDataUrl()` and show loading and failure text.
- `vite.config.ts` does not raise `chunkSizeWarningLimit`.
- Build (2026-09-29): main chunk 421.7 kB (126.4 kB gzip), before 933.1 kB (295.1 kB gzip); graph chunks 443.7 kB and 46.0 kB and the QR chunk 25.8 kB load on demand; no size warning.
- Browser: the graph chunks are requested only when the Assets tab opens; no CSP violation.

## TC-CONSOLE-016: All-findings page

Requirements:

- REQ-CONSOLE-016

Automated tests:

- `frontend/tests/console_information_architecture.test.mjs`

Objective:

Prove the cross-engagement list is reachable, filterable through the URL,
and reuses the engagement page's finding detail and triage.

Expected results:

- Sidebar entry and `/findings` route; the page calls `api.allFindings` with 50 per page.
- Status, severity, engagement, search, and page are read from the URL; status defaults to open.
- A row opens `FindingDetail` (Lens, triage through the engagement endpoint) and links to `/engagements/:id?finding=…&status=…`.
- Browser: 50 of 63 rows on page 1 and 13 on page 2; severity, engagement, and search filters; another operator's finding never appears (also not when searched for); the link opens the finding expanded in the right status tab; resolving from this page moves it to Resolved; an admin sees every engagement's findings.
