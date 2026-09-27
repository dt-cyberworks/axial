# Architecture: CNAME/DNS Inventory & Takeover Detection

Implements [`../requirements/dns-cname-inventory-and-takeover.md`](../requirements/dns-cname-inventory-and-takeover.md).

## Design principle

DNS resolution is a **discovery/metadata** concern, strictly separated from the
**authorization** concern. The resolver builds facts (the CNAME graph); it never
writes scope and never creates a scannable asset. This mirrors the existing
"propose vs. decide" boundary: the Scope Gateway stays the sole gate for active
scanning.

Two distinct DNS paths therefore exist and stay separate:
- `gateway/dns_materialization.py` (control-plane, trust anchor) — resolves
  **in-scope names → IPs for raw egress**. Unchanged by this feature.
- `worker/app/dns_intel.py` (worker, passive) — resolves **the CNAME graph +
  provider classification + dangling detection** for inventory and findings.

## Data model (migration 0008)

New table `dns_record` — one row per in-scope FQDN per discovery pass. It is
metadata; nothing here authorizes a scan.

| column | type | note |
|---|---|---|
| `id` | uuid pk | |
| `engagement_id` | uuid fk | |
| `asset_id` | uuid fk → `discovered_asset` | the originating FQDN (the asset) |
| `fqdn` | text | resolved name |
| `cname_chain` | jsonb | ordered `[fqdn, cname₁, …, terminal]` |
| `terminal_target` | text \| null | last CNAME target (null if no CNAME) |
| `terminal_ips` | jsonb | resolved A/AAAA of the terminal |
| `hosting_provider` | text \| null | e.g. `aws-elb`, `okta`, `github-pages` |
| `is_cdn` / `is_saas` / `is_idp` / `is_shared_infra` | bool | classification |
| `dns_status` | text | `resolved` \| `dangling` \| `unresolved` |
| `takeover_suspected` | bool | dangling CNAME signal |
| `resolved_at` | timestamptz | |

The CNAME **target** never becomes a `discovered_asset` and is never added to
`resolved_host`. It exists only inside `cname_chain` / `terminal_target`.

## Provider classification

`dns_intel` matches the terminal (else any chain hop) against a static suffix
map: `(suffix, provider, flags, takeoverable)`. Flags feed the classification
columns; `takeoverable` feeds the dangling confidence context. The map is the
single source of truth and is unit-tested.

## Dangling / takeover decision flow

```
resolve_chain(fqdn):
  chain = [fqdn]; name = fqdn
  repeat (max depth, loop-guarded):
      c = CNAME(name)
      if none: break
      chain.append(c); name = c
  ips = A/AAAA(name)
  provider, flags = classify(terminal or chain)
  if fqdn itself unresolvable and no chain:   dns_status = unresolved
  elif chain has CNAME and ips == []:         dns_status = dangling; takeover_suspected = True
  else:                                        dns_status = resolved
  # DNS ONLY — never fetch the third-party target over HTTP
```

Discovery calls this for each in-scope FQDN, POSTs a `dns_record`, and when
`takeover_suspected` POSTs a `misconfig` / `inferred` finding
("Potential subdomain takeover (dangling DNS)") with the chain in evidence.
Dedup and severity are the control-plane's existing responsibility.

## Endpoints

- `POST /internal/engagements/{id}/dns-records` — upsert a `dns_record` (worker).
- `GET  /engagements/{id}/dns-records` — inventory for the operator console.
- Takeover findings reuse `POST /internal/engagements/{id}/findings`.

## GUI

A compact **DNS & Hosting** panel on Engagement detail: FQDN → chain → provider,
with dangling rows flagged. The takeover finding appears in the existing findings
list; its chain renders through the existing finding-evidence view.

## Requirement → change map

| Requirement | Change |
|---|---|
| REQ-DNS-001 | `dns_intel.resolve_chain`, `dns_record` table, target-never-asset (negative test) |
| REQ-DNS-002 | provider suffix map + classification columns |
| REQ-DNS-003 | dangling detection (DNS-only) + inferred takeover finding |
