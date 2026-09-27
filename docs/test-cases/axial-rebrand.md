---
title: Axial rebrand verification
status: ready
risk: R1
owner: product-engineering
---

# Axial Rebrand Verification

Verifies [`../requirements/axial-rebrand.md`](../requirements/axial-rebrand.md).

## TC-BRAND-001: The console presents as "Axial" everywhere the old name appeared

Requirements:

- REQ-BRAND-001

Automated tests:

- `frontend/tests/axial_rebrand_requirements.test.mjs`
- `frontend/tests/console_layout_requirements.test.mjs`

Objective:

Prove the rename and visual system are complete and consistent - one shared
logo asset, no leftover "ASM Console" strings, the full color-token set
present, and the heading/body font pairing applied - without any route,
nav destination, or field changing (the pre-existing layout/navigation
suite continues to pass unmodified).

Expected results:

- The browser tab title, sidebar brand block, and auth-screen brand block
  all read "Axial"; none of them still carry "ASM Console".
- Exactly one `Logo` component supplies the mark, reused (not
  reimplemented) by the sidebar, the auth screen, and the browser favicon.
- `:root` defines the full Axial token set (surfaces, text, brand
  purple/blue/teal, and the semantic good/warn/bad tint pairs) referenced
  by name, not hardcoded literals, at each call site checked.
- Headings resolve through the Space Grotesk heading-font token; body text
  stays on the Inter token.
- `console_layout_requirements.test.mjs` continues to pass unmodified,
  confirming no route, nav entry, or field was added, removed, or renamed
  by the rebrand.
