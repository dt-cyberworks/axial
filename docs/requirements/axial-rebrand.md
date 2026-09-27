---
title: Axial rebrand — product name and visual identity
status: implemented
risk: R1
owner: product-engineering
---

# Axial Rebrand

Context: the console shipped under the working name "ASM Console" with a
generic light theme (`docs/design/axial-brand-design.md` has the full token
table). johannes chose the product name **Axial** and supplied a reference
mockup (dark surface, purple/blue/teal accent family, a triangular "A"
mark, Space Grotesk headings) to replace it. This document covers the
rename and visual system; it does not add, remove, or restructure any route,
page, or capability — same information architecture, new skin and identity.

**Risk class: R1.** Presentation-only: copy strings, CSS custom properties,
and a new logo asset. No API, data model, auth, or gateway behavior changes.

## REQ-BRAND-001: Product identity is "Axial" throughout the console

The system shall present the product as "Axial" (mark + wordmark) everywhere
the previous "ASM Console" name/mark appeared, and shall render the console
in the dark Axial color system by default.

Acceptance criteria:

- Browser tab title, sidebar brand block, login/auth screen brand block, and
  the in-app documentation intro read "Axial" (or "Axial Agent" per the
  logo lockup), not "ASM Console" / "ASM-Konsole".
- A single reusable logo component renders the mark (and optional wordmark)
  used by the sidebar, the auth screen, and the browser favicon — one SVG
  source, not duplicated per call site.
- `:root` exposes the Axial color tokens (surfaces, text, brand purple/blue/
  teal/cyan, and semantic good/warn/bad/info tints) and every hardcoded
  literal color previously in `styles.css` resolves through a token, so a
  future palette change is a token edit, not a file-wide search.
- Headings render in the Space Grotesk family; body text remains Inter.
- No route, nav destination, or field is added, removed, or renamed beyond
  the brand strings above — `frontend/tests/console_layout_requirements.test.mjs`
  and the other `test:requirements` suites continue to pass unmodified.

Security invariants: None — no gateway, auth, or audit-path code is touched.
