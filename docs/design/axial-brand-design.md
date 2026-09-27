# Axial brand design

## Purpose

Defines the visual identity implementing `docs/requirements/axial-rebrand.md`
(REQ-BRAND-001): product name, logo, color tokens, and typography. Scope is
skin only — the existing route map, nav destinations, and page structure in
`frontend/src/App.tsx` are unchanged.

## Identity

- Name: **Axial**. Lockup used in the sidebar/auth brand block: "AXIAL" (bold)
  over "AGENT" (small, accent-colored, letter-spaced) — reads as
  product + role, not a marketing tagline.
- Logo: a single SVG mark — a triangular "A" built from two converging
  strokes and a crossbar, flanked by two reticle-bracket arcs and a center
  dot — reading simultaneously as a letterform and a targeting/scope
  reticle. Rendered once in `frontend/src/components/Logo.tsx`
  (`<Logo size withWordmark />`) and reused by the sidebar, the auth screen,
  and `frontend/public/favicon.svg`. One source, no per-page duplication.

## Color tokens (`frontend/src/styles.css` `:root`)

| Token | Value | Role |
|---|---|---|
| `--bg` | `#0b0f14` | Page background |
| `--surface` | `#151a23` | Cards, sidebar, panels |
| `--surface-2` | `#1e2633` | Nested panels, table headers, hover fills |
| `--line` / `--line-strong` | `#232c3a` / `#34445a` | Borders |
| `--text` / `--ink-soft` / `--muted` | `#eef3f8` / `#c7d0dc` / `#8a97a8` | Primary / secondary / tertiary text |
| `--purple` / `--purple-dark` | `#6c5ce7` / `#5847c9` | Primary actions, brand mark |
| `--blue` / `--blue-dark` | `#3d8bff` / `#2c6fd6` | Info accents, low-severity |
| `--teal` / `--teal-dark` | `#00d1b2` / `#00a892` | Links, authorized/success accents |
| `--cyan` | `#a6e6ff` | Light accent (outline buttons) |
| `--green` / `--yellow` / `--red` / `--red-critical` | `#33d17a` / `#ffb020` / `#ff5c6c` / `#7a1f33` | Semantic good/warn/bad/critical |
| `--tint-good-*` / `--tint-warn-*` / `--tint-bad-*` / `--tint-accent-*` / `--tint-info-*` | low-alpha `rgba()` of the paired semantic color | Badge/panel washes on a dark surface |

Every literal hex previously scattered through `styles.css` (light-theme tint
pastels, ad hoc grays) resolves through one of the tokens above. `color-scheme:
dark` is set on `:root` so native form controls follow.

Button hierarchy matches the reference: primary actions fill `--purple`;
`.secondary-action`/outline buttons use a `--line-strong` border with
`--teal` on hover — no separate "accent" button variant was introduced since
the app only has primary/secondary actions today.

## Typography

- Headings (`h1`–`h4`, brand wordmark): Space Grotesk, loaded via Google
  Fonts `<link>` in `index.html`.
- Body/UI text: Inter (unchanged from before).

## Rollout / rollback

Frontend-only static asset change (CSS, one new component, copy strings).
Ships with the normal `frontend-build` step; rollback is reverting the
commit, no migration or backend coordination involved.
