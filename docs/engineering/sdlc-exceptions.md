# Active SDLC Exceptions

Exceptions are temporary, visible debt. They do not change product
requirements.

## EXC-2026-001: Legacy static frontend requirement suites

- Owner: product-engineering
- Opened: 2026-07-25
- Review by: 2026-08-15
- Scope:
  - `agent_lens_requirements.test.mjs`
  - `live_activity_progress_requirements.test.mjs`
  - `operator_authorization_requirements.test.mjs`
  - `scan_rate_policy_requirements.test.mjs`
- Reason: these tests reference the removed `LiveScan.tsx` and `Results.tsx`
  pages. The current UI uses `RunDetail.tsx`, `EngagementDetail.tsx`, and
  `FindingsSection.tsx`; the static assertions have not been reconciled with
  that architecture.
- Compensating control: the TypeScript/Vite production build remains required,
  the passing tool-grant requirement suite remains a CI gate, and
  `npm run test:requirements:all` exposes the quarantined failures.
- Exit criteria: update the affected requirement specifications and test cases
  to the current UI, implement any missing accepted behavior, make all suites
  pass, then change `test:requirements` to execute `tests/*.test.mjs`.
- Approval required: product owner and security owner because rate and
  authorization presentation are included.

