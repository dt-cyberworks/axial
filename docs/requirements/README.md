# Requirements as Code

This directory is the source of truth for product and security requirements.
The governing lifecycle is `docs/engineering/sdlc.md`.

Each requirement document must start with this front matter:

```yaml
---
title: Short document title
status: draft
risk: R2
owner: engineering
---
```

Allowed statuses are `backlog`, `draft`, `reviewed`, `approved`,
`implemented`, `verified`, and `retired`. Requirements use headings of the
form:

```markdown
## REQ-DOMAIN-001: Observable behavior

The system shall ...

Acceptance criteria:

- Observable result one.
- Observable result two.
```

Each approved or later requirement must be covered by a documented test case
under `docs/test-cases/`. Copy `_template.md` when starting a new document.

Backlog proposals use `_template-backlog.md`. Humans and coding agents may
create them after discussion or directly when the value is already clear.
They are documentation only until a human selects them for implementation.
Promotion is recorded in the backlog decision log; the document may then be
implemented in place so its history stays visible.

