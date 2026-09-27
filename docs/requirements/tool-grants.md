---
title: Tool grant semantics
status: implemented
risk: R3
owner: security-engineering
---

# Tool Grant Semantics Requirements

The operator must be able to understand which tool permissions authorize OSINT-only enrichment and which permissions authorize target-touching checks. Passive mode is intentionally narrow: it is useful for discovery and enrichment from public or third-party sources, not for validating live service behavior.

## REQ-TOOL-001: Passive grants are only offered for real passive tools

The Tool grants UI must only offer a passive checkbox for a category when the capability registry exposes at least one enabled tool in that category with `execution_class == "passive"`.

Acceptance criteria:

- Categories without enabled passive tools show `No passive tools` instead of a passive checkbox.
- The category summary names the concrete passive tools when passive mode is available.
- Passive help text explains that passive tools use OSINT or public/third-party data sources and do not run target-touching checks.

## REQ-TOOL-002: Passive grants are persisted only when they can be executed

Saving the Tool grants step must not create passive grants for categories that have no enabled passive tools. This keeps the engagement policy aligned with the actual capability registry and avoids misleading audit artifacts.

Acceptance criteria:

- The wizard derives passive availability from the tool capability registry.
- Passive grants are saved only for categories where the derived passive tool list is non-empty.
- Recon can be passive when tools such as `subfinder` or `amass` are enabled; fingerprint, vuln, cred, and exploit are not shown as passive unless future registry entries add real passive tools.

## REQ-TOOL-003: Gateway enforces passive mode as a real permission

The Scope Gateway must treat passive mode as an explicit grant, not as an implicit bypass. A passive call must still be in scope, whitelisted, argument-safe, and backed by a passive category grant.

Acceptance criteria:

- A passive tool call without `tool_grant(mode="passive")` is denied with `no_tool_grant`.
- A passive tool call for a non-passive registry tool is denied with `passive_not_supported`.
- Audit UI explains `passive_not_supported` in operator-readable language.
