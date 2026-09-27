# Documentation

This `docs/` directory bundles the ASM scanner's technical documentation.
The binding functional/legal specification lives in
[`spec/`](spec/) (seven documents); the pages here summarize it for
developers and link to the code.

| Page | Content |
|---|---|
| [spec/](spec/) | The binding specification — Rules of Engagement, tool allowlist, lab environment, scanner specification, operator console UI, deployment architecture, technical architecture |
| [architecture.md](architecture.md) | Layers, zones, data flow, process topology |
| [security-model.md](security-model.md) | Scope Gateway, defense in depth, audit trail, threat model |
| [security/tool-catalog.md](security/tool-catalog.md) | The exact tool catalog — every static command line, argument, and rationale, for security researchers |
| [data-model.md](data-model.md) | Entities, ER diagram, scope resolution |
| [api.md](api.md) | The control-plane's REST/SSE contracts |
| [../INSTALL.md](../INSTALL.md) | Installation and deployment: Compose, Kubernetes, hardening |
| [testing.md](testing.md) | Test concept, lab test loop, positive/negative/regression testing |
| [roadmap.md](roadmap.md) | Maturity path lab → own_domain → bug_bounty → customer |
| [legal.md](legal.md) | ⚖ Legal prerequisites before the first scan |

## Guiding principle

> The language model **plans and proposes** — a deterministic control layer
> (the **Scope Gateway**) **decides and executes**. Control is enforced
> technically, not through prompt wording.

This principle runs through every component and is why the control and
execution planes are strictly separated (see
[security-model.md](security-model.md)).
