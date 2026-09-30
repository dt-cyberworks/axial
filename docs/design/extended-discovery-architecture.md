# Architecture: Extended discovery (subfinder, crawling, out-of-band, screenshots)

Design spec for [`../requirements/extended-discovery.md`](../requirements/extended-discovery.md)
(R4, authorized by johannes 2026-09-29). SDLC phase 2 (architecture) and phase 3
(GUI). One row per requirement in section 6.

## 0. Principles

1. **The gateway decides.** Every new call (`subfinder`, `katana`, `screenshot`,
   `nuclei` modes `endpoints` and `oob`) is authorized by the Scope Gateway like
   any other call. The four per-engagement switches are step 5c of the gateway
   chain, after scope, mode/grant, whitelist and argument validation, before the
   rate reservation. A switch can only remove capability.
2. **Pipeline-only tools.** `katana`, `screenshot` and `subfinder` have
   `ToolSpec.agent_callable = False`. The Vector Agent is never offered them and
   the gateway denies them for `phase = agent` (`tool_not_agent_callable`).
3. **Fail closed.** If the worker cannot read the engagement's switches it treats
   all four as off (including subfinder).
4. **No new route to a target.** Everything that touches a target goes through
   the egress proxy, under the scan rate policy and the bug-bounty rules. The
   only new network path is runner -> interaction server, one address and one
   port, opened in the gateway's nftables policy.

## 1. Data model (migration `0035_extended_discovery.sql`, idempotent)

| Change | Purpose | Requirement |
|---|---|---|
| `engagement.subfinder_enabled` (default true), `crawling_enabled`, `oob_enabled`, `screenshots_enabled` (default false) | per-engagement switches | REQ-COVER-007 |
| new table `discovered_endpoint` (`engagement_id`, `scan_run_id`, `url` without query, `host`, `port`, `method`, `source`, `param_names` JSONB, `first_seen_at`; unique `(engagement_id, method, url)`) | crawled and archived endpoints | REQ-COVER-003 |
| new table `web_screenshot` (`engagement_id`, `scan_run_id`, `url`, `host`, `port`, `byte_size`, `sha256`, `content` BYTEA, `created_at`) | screenshots (PNG, at most 2 MB, cap 200 per engagement) | REQ-COVER-006 |
| encrypted settings row for subfinder provider keys | optional source keys | REQ-COVER-001 |

Both tables cascade on engagement delete.

## 2. Control-plane endpoints

| Endpoint | Caller | Behavior |
|---|---|---|
| `PATCH /engagements/{id}` | console | accepts the four booleans at any engagement status; a `null` is ignored; the change is audited |
| `GET /internal/engagements/{id}/discovery-options` | worker | the four switches as `{subfinder, crawling, oob, screenshots}` |
| `GET /internal/subfinder-config` | worker | provider keys, decrypted, internal token only |
| `POST /internal/engagements/{id}/discovered-endpoints` | worker | 409 if crawling is off; drops out-of-scope and denied URLs; merges parameter names; cap 5000 |
| `POST /internal/engagements/{id}/web-screenshots` | worker | 409 if screenshots are off; PNG magic bytes, 2 MB cap; replaces the same URL; cap 200 |
| `GET /engagements/{id}/endpoints`, `/screenshots`, `/screenshots/{sid}/image` | console | list (max 1000); image with `image/png`, `nosniff`, `Cache-Control: private, no-store`; ownership enforced router-wide, and the row's own engagement is compared |
| `GET/PUT /settings/subfinder` | admin | provider allowlist; key characters restricted; keys never returned, only `key_set` |
| agent context (`GET /internal/.../agent-context`) | worker | gains `endpoints` |

No new URL prefix: both edge Caddyfiles already route `/engagements`, `/settings`
and `/internal` correctly.

## 3. Gateway changes (`control-plane/app/gateway/`)

- `registry.py`: specs for `katana`, `screenshot` (category `fingerprint`, no
  arguments) and `subfinder` (`recon`, passive); all `agent_callable=False`.
- `args_safety.py`: nuclei `mode` in `headless | endpoints | oob`; `urls` only
  with `endpoints` (max 50, http/https, no userinfo, at most 2048 characters);
  no other argument for `oob`; no interaction server or token argument exists.
- `authorize.py` step 5c denial reasons: `tool_not_agent_callable`,
  `subfinder_not_enabled`, `crawling_not_enabled`, `oob_not_enabled`,
  `screenshots_not_enabled`, `screenshots_not_permitted_for_bounty`,
  `endpoint_out_of_scope` (every URL of an `endpoints` call is checked against
  scope, deny rules, port window and path rules, not only the call's target).

## 4. Worker and runner

| Piece | What it does |
|---|---|
| `worker/app/tasks/discovery.py` | step 4b: subfinder (gateway -> subprocess in the worker image, passive, hard timeout, private 0600 key file, minimal environment, scope filter, deny wins). Step 4c: URL history from Wayback and CommonCrawl when crawling is on, filtered by scope before storage |
| `worker/app/tasks/fingerprint.py` `_web_suite` | after enumeration and content discovery: screenshot (if on) -> crawl (if on) -> main nuclei pass -> endpoints pass -> OOB pass (if on). nuclei stays last |
| `worker/app/discovery_parse.py` | katana JSONL and URL-list parsing, normalisation, static-file and credential filters, candidate selection for the endpoints pass |
| `worker/app/tool_runner_client.py` | command builders for katana, screenshot and the nuclei `endpoints` and `oob` modes; the interaction server comes from the worker's environment after the gateway, never from arguments; the token is read from the runner's environment, never in a command line |
| `raw-egress-gateway` | optional `OOB_SERVER_HOST`/`OOB_SERVER_PORT`: one extra nftables accept rule (that address, that tcp port). Unset or unresolvable -> no rule, policy unchanged |
| `docker-compose.yml` | profile `oob`: `interactsh` (digest-pinned) on the `edge` network for its published DNS port (it binds only to that address, found in live verification), and `oob-relay` (socat, digest-pinned, non-root, read-only, no capabilities, never published) forwarding its HTTP port to the internal `oob` network (members: oob-relay and raw-egress-gateway only, so the runner shares it through its network namespace). The relay's alias on `oob` is `OOB_DOMAIN`, so nuclei's payload domain is the real one and resolves to the relay inside the stack. The server still starts an LDAP listener (v1.3.1 always does); it is unpublished and unreachable from the runner (one accepted address:port); `-skip-acme`, no wildcard/LDAP/SMB/FTP/responder modes, retention `OOB_RETENTION_DAYS` (default 7), read-only, all capabilities dropped |
| `worker/Dockerfile` | multi-stage: subfinder v2.16.0, SHA-256 per architecture, copied into the final image |
| `tool-runner/runner.Dockerfile` | katana added (Chromium is already there) |

Production overlay: `OOB_TOKEN` is required (`:?`), `scripts/gen_production_env.py`
generates it, and `OOB_DOMAIN`, `OOB_PUBLISH_HOST`, `OOB_PUBLISH_DNS_PORT` are the
operator's knobs. By default only loopback is published; receiving callbacks from
the internet needs the operator to delegate an NS record and publish the DNS port
on purpose.

## 5. GUI design (SDLC phase 3)

| Screen | Change |
|---|---|
| Create wizard, step 1, "Advanced options" (already folded away) | four switches (`DiscoverySwitches`), each with a label and a one-sentence description; subfinder on by default, the rest off. Steps 4 and 5 list the switches that are on |
| Engagement edit | section "Discovery extras" with the same four switches. Editable at any status (they only narrow); the text says the change applies from the next scan |
| Engagement detail header | "Discovery extras: ..." with the names of the switches that are on |
| Engagement detail, Assets tab | below "DNS & hosting": "Crawled endpoints" table (URL, method, parameters, source) and "Web screenshots" grid of thumbnails that open the full image. Both appear only if the switch is on or results exist. No new tab (REQ-CONSOLE-013 keeps three) |
| Admin -> Settings | "Subdomain source keys (optional)": one write-only password field per provider, "(key set)" state, Remove button; empty field keeps the current key |
| In-app documentation | new entries for each tool, the switches, the new Assets sections and the keys page |

Fields: no field ever renders a stored key or the interaction token.

## 6. Requirement traceability

| Requirement | Data | API | Gateway | Worker / runner | GUI | Tests |
|---|---|---|---|---|---|---|
| REQ-COVER-001 subfinder | settings row | `/settings/subfinder`, `/internal/subfinder-config` | registry spec, 5c | `discovery.py` step 4b, worker image | Settings keys | TC-COVER-004, TC-COVER-009 |
| REQ-COVER-003 crawl + history | `discovered_endpoint` | endpoints list + internal store | 5c, `urls` validation | `_crawl`, endpoints pass, step 4c | Assets tab table | TC-COVER-005 |
| REQ-COVER-004 OOB | none (server keeps 7 days in memory) | none | 5c, `oob` args | `_nuclei_oob_pass`, gateway nftables rule, compose profile | switch | TC-COVER-006 |
| REQ-COVER-006 screenshots | `web_screenshot` | screenshots list, image, internal store | 5c, bounty denial | `_screenshot` | Assets tab grid | TC-COVER-007 |
| REQ-COVER-007 switches | four columns | `PATCH`, `discovery-options` | 5c | `get_discovery_options` (fail closed) | switches, header | TC-COVER-003, TC-COVER-008 |
