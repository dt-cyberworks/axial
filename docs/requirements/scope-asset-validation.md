---
title: Scope-asset input validation and maximum host-discovery range
status: implemented
risk: R2
owner: security-engineering
---

# Scope-Asset Input Validation Requirements

This document is the requirement source for scope-asset creation's input
validation. Tests must verify these requirements directly. Do not weaken
tests to match implementation; update implementation when it violates this
document.

Context: reported as GitHub issue #35, found during a full-codebase review.
`ScopeAssetCreate` (`control-plane/app/schemas/engagement.py`) accepted
arbitrary strings for `rule`/`asset_type`/`value` with no format validation
anywhere in the stack, and no maximum host-discovery network size existed
anywhere - a `cidr` scope asset of any size, including `0.0.0.0/0`, could be
registered as `active_allowed` with no operator-visible warning.

## REQ-SCOPEVAL-001: Scope-Asset Values Are Format-Validated And Canonicalized At Creation Time

Acceptance criteria:
- `rule` is restricted to `allow`/`deny`; `asset_type` to
  `domain`/`wildcard`/`ip`/`cidr`/`cloud_account` - any other string is
  rejected with a 422 at the schema layer, not accepted and silently
  matching nothing downstream.
- `domain`/`wildcard` values are validated against a permissive
  hostname/fnmatch-pattern character set - deliberately NOT a strict
  RFC-1035 validator: this codebase's own lab fixtures use bare, dotless
  internal Docker hostnames (`metasploitable2`) as legitimate domain-type
  scope values, and existing wildcard scope assets use bare fnmatch
  patterns with no leading `*.` (`metasploit*`, `*.example`). The goal is
  rejecting obviously-wrong input (a URL, a path, whitespace, a stray `@`)
  at create time, not re-validating DNS syntax the rest of the stack never
  required. `domain` values are lowercased and have any trailing dot
  stripped.
- `ip`/`cidr` values are parsed via `ipaddress.ip_address`/`ip_network(...,
  strict=False)` and re-serialized to their canonical form before storage -
  two operator-entered CIDRs denoting the same network (e.g.
  `10.0.0.5/24` and `10.0.0.0/24`) are normalized to the identical stored
  value, not two distinct-looking rows. A malformed value (bad syntax, an
  out-of-range prefix length) is rejected with a 422 naming the offending
  value.
- IPv6 `ip`/`cidr` values are explicitly rejected at input time with a
  clear reason (`"IPv6 scope is not yet supported end-to-end"`), rather
  than silently accepted by the schema and then failing - or not - somewhere
  later in the raw-egress chain. No test in this codebase proves an IPv6
  scope asset works end-to-end through discovery/raw-egress-gateway's
  nftables enforcement (`allowed_v6`/`proxy_v6` scaffolding exists but is
  unexercised), so acceptance is deferred rather than assumed.
- `cloud_account` values are accepted as any non-empty string - no
  canonical format is known or enforced anywhere else in this codebase for
  this asset type (matched only by exact-string equality in
  `authorize.py`).
- **NEGATIVE**: an empty or whitespace-only `value` is rejected for every
  `asset_type`.
- **NEGATIVE**: this validation change does not alter `ScopeAsset` ORM rows
  created directly (not through the `ScopeAssetCreate` schema) - e.g.
  fixtures and internal helpers that construct the model directly remain
  unaffected, matching this codebase's existing pattern of schema
  validation applying only at the API boundary.

## REQ-SCOPEVAL-002: A Maximum Host-Discovery CIDR Size Is Enforced

Acceptance criteria:
- `POST /engagements/{id}/scope-assets` rejects a `cidr` value whose address
  count exceeds a configured maximum (`Settings.max_host_discovery_addresses`,
  default 65536 - a /16 for IPv4) with a 422 naming the address count and the
  configured limit. Enforced in the endpoint, not the schema, since it needs
  the deployment-configured limit from `Settings` (schemas in this codebase
  stay config-independent) - mirrors the existing port-range-within-ceiling
  check, which is also endpoint-side for the same reason.
- The default (65536) is a conservative, order-of-magnitude estimate, not a
  full packet-budget model: at `nmap_max_rate`'s own default (300 pps, 2
  discovery ports/host per REQ-CIDRDISC-002), that many addresses take
  roughly 7 minutes. A proper packet-budget-informed capability model
  (raw packet rate distinct from HTTP rate, bounded runtime/concurrency,
  pre-scan estimates) is tracked separately (GitHub issue #37) and may
  revise this default.
- The check applies only to `asset_type=cidr` - `domain`/`ip`/`cloud_account`
  values have no "size" to bound and are unaffected.
- **NEGATIVE**: a CIDR at or under the configured maximum is accepted
  unchanged.
- **NEGATIVE**: the check is not bypassable via `active_allowed=false` - it
  applies at creation time regardless, since there is no endpoint to later
  flip `active_allowed` on an existing scope asset (only create/delete
  exist), so a passive-only oversized CIDR today would otherwise have no
  other gate before someone deletes and re-creates it as active.
