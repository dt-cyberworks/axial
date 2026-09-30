# Architecture and GUI: Findings-First Console

Design for [`../requirements/console-information-architecture.md`](../requirements/console-information-architecture.md)
(REQ-CONSOLE-013..016, R1) and [`../requirements/cross-engagement-findings.md`](../requirements/cross-engagement-findings.md)
(REQ-PORTFOLIO-001/002, R3). SDLC phases 2 (architecture) and 3 (GUI).

## 1. Requirement map

| Requirement | Backend | Edge | Frontend |
|---|---|---|---|
| REQ-CONSOLE-013 | — | — | `EngagementDetail.tsx` tabs, `FindingsSection.tsx` URL-driven expansion |
| REQ-CONSOLE-014 | — | — | `App.tsx` top bar + drawer, `styles.css` |
| REQ-CONSOLE-015 | — | — | `React.lazy` for `SurfaceGraph`, dynamic `import("qrcode")`, `ChunkErrorBoundary` |
| REQ-CONSOLE-016 | — | — | new page `AllFindings.tsx`, shared `FindingDetail.tsx` |
| REQ-PORTFOLIO-001 | `GET /findings` in `app/api/portfolio.py` | — | `api.allFindings()` |
| REQ-PORTFOLIO-002 | — | `/findings*` in every path list of both Caddyfiles | — |

No data-model change and no migration: the endpoint reads `finding`,
`finding_observation`, `engagement`, and `discovered_asset`.

## 2. API: `GET /findings`

Router: new `portfolio_router` (`prefix="/findings"`), included in the
`public_router` (so `require_user` applies). `enforce_engagement_ownership`
also runs but does nothing, because the path has no `engagement_id`. The
handler therefore applies the ownership rule itself:

```text
visible = select(Engagement.id)            -- admins: all
          .where(owner_user_id == user.id)  -- operators
base    = select(Finding)
          .join(Engagement)
          .outerjoin(DiscoveredAsset, Finding.asset_id == DiscoveredAsset.id)
          .where(Finding.engagement_id IN visible)
          [.where(Finding.engagement_id == engagement_id)]
          [.where(title ILIKE :q OR asset.value ILIKE :q)]   -- q escaped
page    = base [+ status, severity] ORDER BY severity rank, risk_score DESC NULLS LAST,
          first_seen DESC, id LIMIT/OFFSET
total   = count(base + status + severity)
counts_by_status   = base + severity, GROUP BY status
counts_by_severity = base + status,   GROUP BY severity
```

Response (`FindingPage`): `items: list[PortfolioFindingOut]` (`FindingOut` +
`engagement_title`), `total`, `limit`, `offset`, `counts_by_status`,
`counts_by_severity`. `last_seen` comes from one grouped query over
`finding_observation` for the page's finding ids (as in issue #15).
`status`/`severity` are validated against `FINDING_STATUSES` and the
severity list (422). `limit` 1..200, `offset` ≥ 0.

## 3. Edge

Both Caddyfiles list the shared prefixes in four places: the cache rule
(`@shared_paths`), the console fallback (`@app_shell` / `not path`), the
compression exclusion (`@not_api`), and the API matcher (`@api`). `/findings*`
is added to all four. A new static test parses every list in both files and
requires them to hold the same prefixes (`/callback*` is the documented
exception: it has its own matcher and is not in `@api`).

## 4. GUI

### Routes

| Route | Page | Change |
|---|---|---|
| `/findings` | All findings (new) | sidebar entry "Findings", between Overview and New engagement |
| `/engagements/:id` | Engagement | tabs; `?tab=findings|assets|runs`, `?finding=<id>`, `?status=<status>` |
| others | unchanged | |

### Engagement page

```text
breadcrumb
header (title, status line, Edit · Authorization PDF · Audit)
status band (risk signal, runs, open findings, readiness)   2×2 on phones
[authorization not attested]   (only when needed)
[tool grants + activate]       (drafts only)
[readiness banner ........ Start run]   one compact panel, aria-label "Start a scan run"
┌ Findings (n open) ┬ Assets ┬ Runs & reports (n) ┐   role=tablist, page-tabs
│ Findings: status tabs · severity chips (counts on Open) · findings table
│ Assets:   attack-surface graph (lazy) · DNS & hosting
│ Runs & reports: runs table · reports table
```

Tabs are links-in-state: `setSearchParams({tab})` pushes a history entry;
expanding a finding replaces `finding`/`status` in the URL (no history
entry per click). Only the active tab's component is mounted, so its
queries run only while it is shown.

### All findings page (`/findings`)

| Element | Content |
|---|---|
| Header | "Findings", subtitle "Across all engagements you can see" |
| Status tabs | Open · Accepted risk · False positive · Resolved, counts from `counts_by_status` |
| Filters | severity select (All, Critical…Info with counts), engagement select (from `GET /engagements`), search input "Search finding or target" (applied after 300 ms) |
| Table | Severity · Finding (title + problem summary) · Engagement (link) · Target · Last seen |
| Row detail | `FindingDetail` (Lens, triage, facts, evidence) + "Open in engagement →" |
| Pager | "1–50 of 312" · Previous · Next |
| Empty | no engagements → link to wizard; otherwise "No findings match these filters." |

URL: `?status=&severity=&engagement=&q=&page=`.

### Small screens (≤ 1040 px)

```text
┌──────────────────────────────┐
│ [logo]              [☰ Menu] │  top bar, sticky
└──────────────────────────────┘
drawer: fixed, left, 280 px, full height, z-index 90 (approval modal is 110)
backdrop: fixed, rgba overlay, click closes
```

The sidebar element is reused as the drawer (same links, no duplicate
navigation). On desktop the top bar and backdrop are `display: none`.

### Lazy loading

- `const SurfaceGraph = lazy(() => import("../components/SurfaceGraph"))`
  inside `<ChunkErrorBoundary><Suspense fallback="Loading graph…">`.
- `ChunkErrorBoundary` (class component): on error shows "This part of the
  console could not be loaded" + "Reload page".
- QR code: `import("qrcode").then(({ default: QRCode }) => QRCode.toDataURL(...))`.

## 5. Changes found by the browser check

The first browser run showed the findings table starting at y≈934 on a
1440×900 screen for an engagement with two readiness blockers. The separate
"Start a scan run" panel (heading, banner, button row) and the separate
"Severity distribution" panel took ~460 px. Both were compacted (section 4);
the table header now starts at ~y 625 and the first row is fully visible.
