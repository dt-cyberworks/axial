# Troubleshooting

**Who this is for:** operators and admins who see a message, a code or an empty result and want to know what it means and what to do.
**After this page you can:** look up every blocker, run reason, check reason and gateway denial the console shows, and work out why a scan found nothing or an agent did nothing.

<!-- ui-labels: Scan readiness | Choose targets | Discover again | Start run | Activate engagement | Edit engagement | Tool grants | Campaign tool overrides | Discovery extras | Scope assets | Stop scan | Plan | Activity | Vector Agent | Audit | reduced coverage | partial coverage | Automatic runs | Run now -->

Where to look first:

| You see | Look at |
|---|---|
| **Start run** is disabled, or *This engagement cannot scan yet* | [Scan readiness messages](#scan-readiness-messages) |
| A run ended `aborted` or `failed`, or has a reason beside its state | [Why a run stopped](#why-a-run-stopped) |
| A check is *skipped*, *failed* or *partial* in the **Plan** tab | [Why a check was skipped or failed](#why-a-check-was-skipped-or-failed) |
| A denied row in **Audit** or **Activity** | [Why the Scope Gateway denied a call](#why-the-scope-gateway-denied-a-call) |
| **Activate engagement** refuses | [Why an engagement cannot be activated](#why-an-engagement-cannot-be-activated) |
| You cannot sign in | [Sign-in problems](#sign-in-problems) |
| The agent or an explanation does nothing | [The agent or the Lens Agent does nothing](#the-agent-or-the-lens-agent-does-nothing) |
| The scan found nothing | [The scan found nothing](#the-scan-found-nothing) |

## Scan readiness messages

The panel above the tabs of an engagement lists every reason a run cannot start. Each is a code with a sentence; the code is shown when you hover over the sentence.

| Code | The sentence says | Fix |
|---|---|---|
| `engagement_not_found` | the engagement does not exist | you followed a stale link; open the engagement from the overview |
| `engagement_not_active` | the engagement is `draft`, not `active` | choose **Activate engagement**; see [Authorize and activate](guides/authorize-and-activate.md) |
| `before_time_window` | the authorised window starts on a later date; every call would be denied until then | wait, or change **Authorized from** on **Edit engagement** |
| `after_time_window` | the authorised window has ended | extend **Authorized until** on **Edit engagement**, if you are still authorised |
| `no_active_scope` | no in-scope asset is marked active-allowed, so active checks would have no target | on **Edit engagement → Scope assets**, add an allow row with **active** ticked |
| `no_active_tool_grant` | no tool category is granted for active testing | grant at least one under **Tool grants**; the message links there. See [Control which tools run](guides/control-which-tools-run.md) |
| `targets_not_confirmed` | a monitor's targets are not confirmed yet: the discovery is still running, has finished and waits for your choice, or did not finish | open **Choose targets** (the message links there, and so does the [inbox](reference/inbox.md)), pick the hosts to monitor and confirm; after a failed discovery choose **Discover again** first. See [Monitor an attack surface](guides/monitor-an-attack-surface.md#choose-the-targets) |
| `bounty_program_missing` | a bug-bounty engagement has no program policy | fill in **Bug bounty program policy**; see [Define an engagement](guides/define-an-engagement.md#bug-bounty-engagements) |

Two more things stop the **Start run** button: a run is already active on this engagement (**A run is already active**), or the page could not check readiness (it says so; reload).

## Why a run stopped

The reason is shown beside the run's state, on the run page and in the runs table.

| Reason | Meaning | What to do |
|---|---|---|
| `cancelled_by_operator` | someone chose **Stop scan** | start a new run when you are ready |
| `cancellation_status_unavailable` | the control plane could not say whether you had cancelled, so all work against the targets was stopped as a safety measure. Nothing was left out on purpose | start the run again. If it recurs, the control plane is overloaded or restarting; ask an administrator to check it |
| `reaped_stale_heartbeat` | the worker running it stopped sending signs of life and the run could not be resumed (it had never been claimed, it had already been resumed twice, or it could not be queued again) | start a new run; ask an administrator to check the worker |
| `engagement_paused` | the engagement was paused, which stops its active run | resume it, then start a new run |
| `engagement_revoked` | the authorization was revoked, which stops its active run for good | nothing; the engagement cannot scan again |
| `asset_review_pending` | the run is waiting for you to review the discovered hosts (a `waiting_approval` run). Not a failure | answer the **Review discovered assets** popup; see [Run detail](reference/run-detail.md#asset-review) |
| `approval_wait` | one action of the run is waiting for your decision (the run shows `waiting_approval`). Not a failure, and the other actions of the run carry on meanwhile | approve or reject it in the popup; the run goes back to `running` when the last open decision is made |
| `asset_review_expired` | the asset review popup was not answered within 15 minutes, so the run stopped rather than scan everything | start a run and answer the review, or switch the review off |
| `task_time_limit_exceeded` | the whole scan task ran into the worker's time limit | narrow the scope or the scan depth, or split the engagement |
| `pipeline_error:<type>:<phase>` | an internal error ended the run. The *type* is the kind of error and the *phase* where it happened. A run that ended with only `pipeline_error` is from an older version that did not record the cause | start it again; if it repeats with the same type and phase, report both to an administrator |
| `coverage_degraded:<tool>=<why>` | a tool the scan depends on (`nmap` or `httpx`) was attempted but never once succeeded. **Not** a clean result | find out why the tool failed (the *why* is in the text), fix it and rerun |
| `coverage_partial:<tool>=<n>` | `n` checks of that tool stopped at their time budget, or (for `nmap`) `n` port scans have gaps, see [When the port scan has gaps](#when-the-port-scan-has-gaps). What they reported is real, but not everything was examined | rerun, or use **Thorough** scan depth, or accept the partial result knowingly. For `nmap`, follow the next section |
| `coverage_degraded:tool_call_budget=exhausted_<n>_denied` | the run used up its tool-call budget and the Scope Gateway refused `n` further calls, so the checks behind them did not run. **Not** a clean result | an administrator raises the budget under **Admin → Operational settings → Tool-call budget per run (global)** by at least `n`, then run again; see [Settings](reference/settings.md#tool-call-budget-per-run-global) |
| `agent_incomplete:<why>` | the Vector Agent ended before it finished its plan; the deterministic phases are unaffected | check the AI provider and the agent budgets; see [Configure the AI provider](guides/configure-the-llm.md) |

A run that stopped *without* your action for a reason that is not about the target can simply be started again; the findings of earlier runs are kept.

## Why a check was skipped or failed

In the **Plan** tab each check has a state and a reason.

| State | Means |
|---|---|
| **complete** | ran to the end |
| **partial** | stopped at its own time budget (`budget_reached`); what it printed before is real, but it did not finish. **Not clean** |
| **failed** | the tool or its handler failed; the reason says how (`handler_error:<type>`, or the tool's own error). **Not clean** |
| **skipped** | not run, for the stated reason. **Not clean** unless the reason says it did not apply, or the reason is `not_in_this_run` |

Reasons you will see:

| Reason | Meaning |
|---|---|
| `switch_off` | the discovery extra it belongs to is off for this engagement |
| `tool_disabled` | the tool is switched off in Settings or for this campaign |
| `no_tool_grant` | its category is not granted on this engagement |
| `not_a_tls_service` | the port speaks plain HTTP or another protocol, so there is no TLS to test |
| `not_a_web_service` | the port is not a web service |
| `no_endpoints` | the crawl found no URL with parameters to test |
| `no_matching_templates` | no template matches what was identified |
| `oob_unavailable` | the platform's interaction server is not set up, so the templates that confirm through a callback could not run: blind-vulnerability templates (blind injection, SSRF, XXE and similar) and the CVE templates that call back (2015-2022 and 2023-2026). The **Plan** tab and the report name these classes. Templates that do not need a callback are not affected and ran as usual; a short findings list still does not mean the targets are free of blind vulnerabilities |
| `not_in_this_run` | the run was restricted to the checks you chose ([retest](guides/retest-and-open-items.md)) and did not look at this one. It says nothing about the check: not a failure, nothing is missing, and an earlier result of the check still stands | nothing; run the check from **Not done yet** if you want a fresh result |
| `run_ended_early` | the run ended (stopped, failed or aborted) before this check ran, so nothing is known about it. It is listed on **Not done yet** | run it again from **Not done yet** |
| `not_sent:<reason>` | a request you chose to send was not sent: the Scope Gateway checked it again and refused it (the reason is one from the table of denials below), the confirmation ran out, or the run was stopped. It is **open again** on **Not done yet**, nothing was lost, and the run is not marked as failed | fix what the reason says (for example the test window), then choose it again |
| `materialized_ip_missing` | the **name has no DNS address**, so nothing was sent to it, by any tool (Nmap, HTTPX, WAF detection, TLS test, content discovery, Nuclei). It is shown as one *skipped* row for the name. Often an old, internal or retired name found in certificate logs | usually nothing. If it should resolve, fix its DNS record; if it should not be scanned, add a deny rule or remove it from the scope |
| `ipv6_scanning_off` | an administrator switched IPv6 port scanning off (`NMAP_SCAN_IPV6=false`), so this host's IPv6 address was not port-scanned; its IPv4 address was. This is a choice, not a failure, and the run is not marked partial for it. A port that is open over IPv6 only will not be found while it is off | an administrator sets `NMAP_SCAN_IPV6=true` on the worker again, unless the scanner's network has no IPv6 |
| `raw_egress_unavailable` | the network-scan gateway was not available |
| `scan_run_missing` | no valid run context, so the tool did not start |
| `dependency_never_finished` | a check this one depends on never finished |
| `web_alias_of:<surface>` | the port only redirects to another scanned port, which is checked there |
| `duplicate_vhost_of:<surface>` | the same site as another name, checked once there |
| `gateway_denied:<reason>` | the Scope Gateway refused the call; the reason is one from the next table. The **Activity** tab shows this once, as the refusal, not twice |
| `cancelled_by_operator` | the run was stopped |
| `cancellation_status_unavailable` | stopped as a safety measure; see above (a *failed* check) |
| `approval_unavailable_unattended` | the check needed a person's decision and the run is unattended (a monitoring run, or one started that way). It was not made and is in the [inbox](reference/inbox.md) as **Held back for you**, where you can send it later; see [Retest and run only what is open](guides/retest-and-open-items.md) |
| `approval_rejected`, `approval_expired`, `approval_cancelled` | the check waited for a decision (**Start run** as a test) and it was *no*, nobody answered within the approval timeout, or the run was stopped. It was not made |
| `approval_claim_denied:<reason>` | it was approved, but the gateway checked it again before running and no longer allowed it (the window ended, the scope changed, the engagement was paused); the reason is one from the next table |

## When the port scan has gaps

The port scan (Nmap) is not a check in the **Plan** tab; it is a step of the **Activity** tab, and a run that has a gap in it ends with `coverage_partial:nmap=<n>`. The step is titled *Nmap completed TCP discovery, but the result is incomplete* and says why. **A port missing from such a list does not mean the port is closed.**

| Reason | Meaning | What to do |
|---|---|---|
| `probes_dropped` | some of Nmap's probes were refused by the scanner's own firewall rules before they left, so a port that is open may have looked silent. The number is "this many or more": Nmap stops reporting after a few | run the scan again. If it recurs, tell an administrator: the scanner's packet rate and the gateway's limit have drifted apart |
| `ports_no_longer_open` | ports that recent earlier runs found open were not found this time, even after a second, slower check of just those ports. The step lists what the second check saw for each port: `closed` means the target answered "nothing here", `filtered` means it stayed silent | find out why on the target: a service that was stopped, a changed firewall rule, or an automatic block of the scanner's address (for example fail2ban). If nothing changed there, run the scan again |

A host with several addresses (for example an IPv4 and an IPv6 address) is port-scanned on **every** address, and the open ports of all of them are merged. If the scan of one address failed while other scans of the run worked, that address has its own *failed* Nmap step with the reason (for example `zero_targets_scanned`, or probes that could not leave the network), the run ends `coverage_partial:nmap=<n>`, its health reads *degraded*, and the report says the port scan had gaps. If a port is open over IPv6 but not over IPv4, the run reports it as a finding, *Port N is open over IPv6 only*: the IPv4 side is often protected and the IPv6 side was forgotten.

The step also shows how many ports Nmap saw in each state (*open*, *closed*, *filtered*) and, for each port checked again, whether it was found. A port that was missing but found again on the second check is reported as found; it is not a gap.

## What the reason codes in the Activity tab mean

The **Activity** tab shows a reason code under each step. This section lists the ones not explained elsewhere on this page. A code the console does not know is shown as *Unexplained reason: `<code>`*: that is a gap in the console, not a diagnosis, so report it.

A step is *skipped* when the check did not apply or was not possible (an unresolvable name, a plain-HTTP port for a TLS test, a missing grant). It is *failed* when the tool itself did not finish. A skip is not a clean result: the **Plan** tab and the run's *reduced coverage* label still say what was not examined.

### Why a tool did not finish

| Code | What happened | What to do |
|---|---|---|
| `nonzero_exit` | the tool exited with an error | open the step's technical details for the tool's own message; run again, and report it if it repeats |
| `runner_dispatch_failed` | the isolated tool runner could not be reached or could not execute the request | an administrator checks that the runner container is up; then run again |
| `runner_execution_failed` | the runner could not complete an action that was approved | the same; the approval is used up, so approve it again |
| `runner_reported_failure` | the runner ran the tool and reported that it failed | open the technical details; run again |
| `runner_error` | the runner reported an error while executing the tool | open the technical details; an administrator checks the runner if it repeats |
| `egress_proxy_blocked` | the network egress policy refused the request, for example an address that is not allowed. The technical details name the proxy's reason; two of them are about capacity, not about scope: `engagement_share_exhausted` (the proxy shares its connections between engagements and this one was already using its share; the request was refused at once so that another engagement could have the connection) and `destination_busy` (the optional cap on parallel requests to one host was reached and none finished within the wait) | nothing to do for a scope reason: the policy is working. Check the target's address if you expected it to be reachable. For a capacity reason, run again later or ask an administrator to raise the proxy's connection pool or the destination cap |
| `egress_proxy_unreachable` | the scanner's tool runner could not open a connection to its own egress proxy, so the tool was not started and nothing was sent (typically right after the proxy was restarted or replaced). It is a failed check, never a clean "nothing found" | run again after a minute; if it repeats, an administrator checks that the egress proxy is up and that the raw-egress gateway reports it reachable (`/health`, `egress.proxy.reachable`) |
| `dns_resolution_failed` | the name could not be resolved to an address the scanner may use | check the DNS record; see also `materialized_ip_missing` above |
| `dns_rematerialization_failed` | the names could not be looked up again just before the tool started | check that DNS answers from the scanner, then run again |
| `zero_targets_scanned` | Nmap did not scan any target. This is a failed result, never a clean one | check that the name resolves and is in scope; run again |
| `content_discovery_catch_all` | the site answers every path with the same page, so hits cannot be told from misses | read "no hits" as *not checked*. Nothing to do unless you can make the site answer with real 404s |
| `screenshot_empty` | the browser produced no screenshot of the page | the page may need a login or block automated browsers; nothing to do |
| `selection_unavailable` | the template selection of the check could not be read from the scanner image | an administrator checks that the tool runner image is current |
| `subfinder_not_installed` | subfinder is not in the tool runner image | an administrator rebuilds the runner image |
| `subfinder_timeout` | subfinder did not finish in its time limit | public sources can be slow; run again later |
| `unsafe_domain` | the domain name failed the safety check for tool arguments, so the tool was not started | check the name for odd characters |

### The network path of the port scan

| Code | What happened | What to do |
|---|---|---|
| `lease_issued` | a short-lived network rule was opened for Nmap, limited to the audited address and ports | nothing; this is the normal start of a port scan |
| `raw_egress_lease_denied` | the rule was not issued, so Nmap did not start | the gateway checks scope and window again; fix the cause shown next to it |
| `resolved_target_blocked_address` | the name resolves to an address that can never be a scan target: this machine itself (loopback), a link-local address (including the cloud-metadata address), a multicast or reserved address, or an address that cannot be read. The same rule refuses it for web tools, and one such answer refuses the whole name. Nothing was sent | nothing to do: the control is working. If you expected the name to be scanned, fix its DNS records (a private address such as 10.x or fc00::/7 is not refused) |
| `raw_egress_queue_timeout` | another scan held the shared Nmap gateway for longer than the bounded wait | run again later |
| `raw_egress_queue_cancelled` | the queued request was removed because the run was stopped | nothing to do |
| `raw_egress_queue_or_dispatch_failed` | the shared gateway could not schedule or start the scan | run again; an administrator checks the gateway if it repeats |
| `raw_egress_activation_or_dispatch_failed` | the network rule could not be opened or the scan could not be started | the same |
| `raw_egress_reservation_failed` | the scan could not reserve its slot at the gateway | the same |
| `raw_egress_reservation_release_failed` | the queue slot could not be confirmed as released | an administrator checks the gateway; the slot times out by itself |
| `raw_egress_heartbeat_failed` | the active rule lost its heartbeat and was closed | run the scan again |
| `raw_egress_revoke_failed` | the rule could not be confirmed as closed | an administrator checks the gateway |
| `raw_scan_incomplete` | the port scan did not run to the end, so its list is incomplete | run the scan again |
| `udp_discovery_not_enabled` | bounded UDP discovery is not switched on for this engagement | switch it on under **Edit engagement** if you want it |
| `udp_no_port_states` | UDP returned no port states | incomplete, not clean: run again or check the UDP settings |
| `udp_results_ambiguous` | UDP returned only *filtered* or *open or filtered* | inconclusive, not clean: UDP cannot tell closed from silent without an answer |
| `udp_port_profile_invalid` | the UDP port list of the engagement is not valid | correct it under **Edit engagement** |

### Vector Agent

| Code | What happened | What to do |
|---|---|---|
| `agent_phase_skipped` | the Vector Agent is off for this engagement (or its bug-bounty program forbids it), so the scan did not start it; the reason is shown with the step and no request was made to the model | nothing is wrong; to use the agent, switch it on under **Edit engagement** |
| `agent_permission_unreadable` | the control plane did not say whether the agent may run, so the scan did not start it | check that the control plane and worker are the same version, then run again |
| `llm_provider_missing` | the agent phase was skipped because the model provider is not fully configured | an administrator completes it under **Operational settings → Provider**; see [Configure the AI provider](guides/configure-the-llm.md) |
| `openai_sdk_missing` | the agent phase was skipped because its client library is not installed | an administrator updates the worker image |
| `llm_call_failed` | the request to the model provider failed | the deterministic results remain; check the provider and run again |
| `finish_reason_length` | the model's output limit was reached, so the incomplete reply was not executed | raise **Max tokens** under **Operational settings** |
| `empty_response` | the model returned no answer and no tool call | nothing was done; run again |
| `empty_proposal` | the proposal contained no action, so it was skipped | nothing to do |
| `unknown_tool` | the model proposed a tool outside the supported registry | nothing was run; nothing to do |
| `not_in_scope_list` | the proposed target was not in the agent's evidence scope | nothing was sent; nothing to do |
| `no_in_scope_assets` | the agent had no in-scope discovered assets to evaluate | check the scope and the discovery result |
| `deterministic_full_scan_only` | the full Nmap discovery belongs to the pipeline, so the agent did not repeat it | nothing to do |
| `agent_phase_started`, `agent_phase_finished`, `llm_provider_usable`, `requesting_next_action` | the agent phase began, ended, found its provider usable, or is choosing its next check | information only |
| `llm_proposed_tool`, `llm_proposed_http_request`, `llm_proposed_content_discovery` | the agent proposed a tool, an HTTP request, or a bounded content discovery. A proposal is advice; the gateway decides | information only |
| `tool_observed`, `tool_observed_after_approval`, `agent_reported`, `llm_finish`, `llm_finished_without_tool` | the agent received a tool result, recorded a finding or ended its analysis | information only |

### Approvals and the gateway's yes

| Code | What happened | What to do |
|---|---|---|
| `all_checks_passed`, `gateway_allowed` | the gateway confirmed target, authorization, window, tool and rate | information only: this records authorization, and execution is reported separately |
| `completed` | the tool returned a successful terminal result | information only |
| `reauthorized` | an approved action passed a fresh gateway check before it ran | information only |
| `pending_approval`, `awaiting_operator_approval` | the action waits for a one-time operator decision | decide it; see [Approve or deny a tool call](guides/approve-or-deny-a-tool-call.md) |
| `manual_approval`, `manual_rejection` | the operator approved or rejected this one stored action | information only |
| `cancelled`, `rejected`, `expired` | a waiting approval was cancelled, rejected, or ran out | request the action again if it is still wanted |
| `rate_limited_wait` | the worker paused for the configured rate limit and retries | nothing to do |
| `approval_not_claimable` | the approval could not be used (already used, rejected or expired) | request the action again |

### Warnings before a run

A warning is shown above **Start run**. It does not stop a run.

| Code | What it says | What to do |
|---|---|---|
| `subfinder_without_passive_grant` | *Passive subdomain sources* is on, but `recon / passive` is not granted, so subfinder will be skipped | tick *Passive* for *Recon* under **Tool grants**. The switch alone does not authorize anything |
| `crawling_without_grant` | *Crawling and URL history* is on, but `fingerprint / active` is not granted, so the crawler will be skipped | grant it under **Tool grants** |
| `screenshots_without_grant` | *Web screenshots* is on, but `fingerprint / active` is not granted | the same |
| `oob_without_grant` | *Out-of-band interaction testing* is on, but `vuln / active` is not granted | the same |

## Why the Scope Gateway denied a call

A denied call appears as a *deny* row in **Audit** and in the **Activity** tab, with the reason code. A denial means **nothing was sent to the target**. Most denials are the system working as intended.

| Code | Meaning | What to do |
|---|---|---|
| `target_out_of_scope` | no allow row matches the target | check the spelling; a wildcard such as `*.example.com` does not cover `example.com`. Add a row only if you are entitled to |
| `explicit_out_of_scope` | a deny row matches the target. Deny always wins | remove the deny row only if it is wrong |
| `asset_held_for_review` | the target is a host of a monitoring engagement that the hold policy is holding: it is listed but nothing is sent to it until you release it. The Scope Gateway refuses every active call to it, whoever asks (the scan, the Vector Agent) and whatever was approved | release the host from its inbox item, or choose it on **Review targets**; see [Monitor an attack surface](guides/monitor-an-attack-surface.md) |
| `active_not_allowed` | the target is in scope but not marked active | tick **active** (and **authorization attested**) on its allow row |
| `no_tool_grant` | the engagement does not grant the tool's category in the mode it needs. The **Activity** tab names it (for example `recon / passive`) | grant exactly that under **Edit engagement → Tool grants** (tick *Passive* for *Recon* in that example). A per-tool switch cannot replace the grant. Adding a grant is refused while a scan runs |
| `tool_disabled` | the tool is switched off, in Settings or for this campaign | **Campaign tool overrides**, or an admin in **Settings** |
| `tool_not_whitelisted` | the tool is not in this version's allow-list | cannot be changed |
| `passive_not_supported` | the tool has no passive mode | use an active grant, if active testing is authorised |
| `unsafe_arguments` | the arguments failed the safety policy | cannot be overridden; it needs a code change |
| `outside_time_window` | the authorised window is not open | change the dates, if you are authorised |
| `engagement_not_active` | the engagement is not active | activate it |
| `engagement_not_found` | the engagement does not exist | internal; report it |
| `scan_run_required` | the call has no run context | internal; report it |
| `scan_run_not_found` | the run does not exist for this engagement | internal; report it |
| `scan_run_not_active` | the run was not doing work at that moment: it had finished or stopped, it is parked while a semi-attended decision is open, or it is paused for the review of discovered hosts. A run that merely waits for your decision on *one* action is not in this list: its other actions go on | if the run ended or was stopped, nothing; if it is parked or in a review, answer the open decision |
| `scan_run_cancelled` | the run was stopped | nothing to do |
| `budget_exhausted` | the run used its tool-call budget (200 by default; an administrator sets it under **Operational settings**) | the run is marked *reduced coverage*; raise the budget and run again, or narrow the scope |
| `rate_limited` | the request rate is exhausted | with *automatically slow down* on, the worker waits and retries; otherwise an admin can raise the limit in **Settings** |
| `ai_testing_not_enabled` | the Vector Agent is not enabled on this engagement | tick the switch on **Edit engagement** |
| `credential_tool_not_allowed` | a test account's credential was about to be used in a tool other than a plain HTTP request; nothing was sent | nothing to fix; the account goes only into `http_request` |
| `credential_host_not_usable` | the request carried a test account to a host it is not assigned to, or one that is held, denied, flagged as a possible takeover or suspended; the reason is named; nothing was sent | assign the account to the host under **Test accounts → Edit hosts**, or release the host |
| `credential_wrong_use` | a login account's password was about to be used outside its login request (or the request named an account this engagement does not have); nothing was sent | nothing to fix; check the account's login path under **Test accounts** if the login itself was refused |
| `login_attempt_limit` | the account was already tried twice on this host in this run (or twenty times overall), so it is not tried again | nothing to fix in this run; check the credentials at the target, then run again |
| `testaccount_login` | a monitor's declared login, covered by your login consent, was allowed without a per-call approval | nothing; this is the consent working |
| `credential_unresolvable` | the test account was no longer available when the request was about to go out, so it was not sent | run again |
| `authenticated_coverage_lost` | a test account's login was rejected, or never produced a session, so what is behind the login was not tested | check the account under **Test accounts**; replace the secret or **Resume** after fixing it at the target |
| `login_consent_required` | a monitor has a test account whose login no current consent covers, so it cannot be activated | give the **Login consent** on the Authorize step or on the **Test accounts** tab |
| `testaccount_cipher_unavailable` | the server has no encryption key for test accounts, so nothing was saved | an administrator sets `TESTACCOUNT_ENCRYPTION_KEY` (`make env` creates it) and restarts the control plane |
| `testaccount_host_not_allowed` | a host you ticked is not a concrete host of the scope, or a deny rule blocks it | tick hosts from the list |
| `testaccount_attestation_required` | you did not confirm that this is a dedicated test account you may use | tick the confirmation |
| `ai_testing_forbidden` | the bug-bounty program does not permit AI testing | the agent may not run on this engagement |
| `automation_forbidden` | the bug-bounty program does not permit automated testing | automated scanning is not allowed here |
| `bounty_program_missing` | a bug-bounty engagement has no program policy | fill it in |
| `subfinder_not_enabled` | passive subdomain sources are switched off | **Discovery extras** |
| `crawling_not_enabled` | crawling and URL history are switched off | **Discovery extras** |
| `oob_not_enabled` | out-of-band testing is switched off | **Discovery extras** |
| `screenshots_not_enabled` | web screenshots are switched off | **Discovery extras** |
| `screenshots_not_permitted_for_bounty` | the program requires an identification header on every request, which screenshots cannot carry | screenshots are unavailable on this engagement |
| `endpoint_out_of_scope` | a crawled URL's host or path is outside the scope, or carries credentials | it is never requested; nothing to do |
| `target_is_range_not_permitted_for_tool` | only the host-discovery sweep may target a whole range | internal; report it |
| `tool_not_agent_callable` | the tool is a fixed pipeline step (katana, screenshot, subfinder) and cannot be proposed by the agent | nothing to do |
| `risk_statement_required` | a request that could change data came without a risk statement | the agent must supply one; nothing for you to do |
| `approval_not_found` | the approval does not exist for this engagement | the request is no longer waiting; propose it again |
| `approval_expired` | the approval timed out before it was used | the request was rejected; propose it again |
| `approval_call_mismatch` | the call being run is not the one that was approved | an approval covers exactly one stored request; approve the real one |

For the **operator override** on some of these, see [Audit](reference/audit.md#details-and-overrides).

## Why an engagement cannot be activated

**Activate engagement** refuses with a sentence that says which condition is unmet:

| Message (shortened) | Fix |
|---|---|
| add at least one in-scope target | add an allow row |
| confirm your authorization for every target that allows active testing | tick **authorization attested** on each active allow row |
| the test window is missing or ends before it starts | correct the dates |
| a bug-bounty engagement needs its program details | fill in the program policy |
| the allow-scope overlaps another currently active engagement's allow-scope: "Title" (owner Name, email) | the message names the active engagement that already covers some of these hosts (up to three; "and N more" if there are more), and its owner. This only happens on an installation whose administrator has **switched the signed run identity off** (`EGRESS_REQUIRE_TOKEN=false`); there the two cannot both be responsible. Change one scope, or ask the owner to finish theirs. **A normal installation does not refuse this** (see below) |

On an installation where the egress proxy requires the signed run identity, which is the default, two engagements that cover the same host can both be active. Activation then succeeds and the engagement page shows a note, *This engagement shares hosts with "Title" (owner …). Both can run: each request is judged by the authorization of its own engagement. The target will see traffic from both.* Nothing is refused; the note is the reminder that the target's owner sees both engagements' traffic.

## Why a change was refused

You can read every engagement, but only its owner and administrators can change it (see [Roles and ownership](concepts.md#roles-and-ownership)). A change from anyone else is refused, and nothing is written.

| Message | Meaning and what to do |
|---|---|
| only the owner of this engagement or an administrator can change it | the engagement belongs to someone else. Ask its owner (the notice at the top of the page names them), or an administrator, to make the change or to hand the engagement to you |
| admin role required | the action (for example reassigning an owner, or anything under **Admin**) is for administrators only |
| This page is out of date or a browser extension removed its security header | the server refused a change because the request did not carry the header the console always adds. Reload the page without the cache (**Ctrl+Shift+R**) and try again. If it persists, try a private window with extensions off. Nothing was changed |

The console hides the buttons that would be refused, so you meet this message only through a stale page or a direct request.

## Sign-in problems

| You see | Do |
|---|---|
| *invalid credentials* | check the email and password; five wrong passwords lock the account for a short time, growing up to 15 minutes |
| *invalid code* | check the phone's clock; a code from the previous 30 seconds can be refused once it has been used. Wait for the next code. A one-time backup code also works, once |
| *too many sign-in attempts from this address - try again later* | wait a few minutes; the limit is per source address |
| the account is disabled | ask an admin to **Enable** it |
| lost password, lost phone | an admin uses **Reset password** or **Reset MFA** |

See [Users and two-factor authentication](guides/users-and-mfa.md).

## The agent or the Lens Agent does nothing

1. Is an AI provider configured? Without one the agent phase is skipped and the Lens Agent says it is not configured. Check **Admin → Operational settings → Provider**. See [Configure the AI provider](guides/configure-the-llm.md).
2. Is the agent switched on for this engagement? The switch is on **Edit engagement**, and it is off by default.
3. Open the run's **Vector Agent** tab: if it says *No agent steps recorded*, it gives the reason. If steps exist but the agent stalls, a reply may have been cut off: raise **Max tokens** or **Max iterations**.
4. A bug-bounty engagement needs the program to permit AI testing.
5. A **Lens Agent** explanation that is cut off, or that lacks one of its four sections, is flagged on the page and is never kept as the final answer. Choose **Regenerate** to ask again. The platform already retries once with a larger budget; if explanations are still cut off, an administrator raises **Lens Agent max tokens** under **Operational settings** (default 4,096, up to 16,384).

## A monitor did not run by itself

Open the engagement's **Automatic runs** panel: when a run is due but waiting, it names the reason. The reasons and what to do are listed in [Monitor an attack surface](guides/monitor-an-attack-surface.md#automatic-runs). Most often the engagement is paused, the authorization review date has passed, a run is still going, or the engagement is not ready to scan (the [inbox](reference/inbox.md) then holds an item). If the panel says *Off*, no interval is set. Setting an interval never starts a run at once. The first run of a new monitor starts when you confirm its targets (`targets_not_confirmed` below); for a monitor that existed before that step it is yours with **Run now**.

## The scan found nothing

An empty list is a result, but not necessarily a clean one. Work through:

1. **Is the scope right?** Names outside it are never scanned. Look at the **Plan** tab: which hosts and ports were checked?
2. **Did it cover them?** Look for **reduced coverage** or **partial coverage** on the run, and for *failed*, *partial* or *skipped* checks in the **Plan** tab. A check that did not run says nothing about its target.
3. **Were the tools allowed?** A category that is not granted, or a tool that is switched off, shows as skipped with `no_tool_grant` or `tool_disabled`.
4. **Was the host up?** A host that is down looks clean. Look at the **Activity** tab for blocked or failed steps.
5. **Is the depth right?** **Standard** only runs templates for what it identified. **Thorough** runs more.

If the run really covered everything and still found nothing, that is a good outcome. See [Safety, legal and limits](safety-legal-limits.md#what-axial-does-not-cover) for what even a complete run cannot tell you.

## Test deeper: starting an assessment from a monitor

These are the refusals of **Test deeper** (see [Test a monitored target in depth](guides/test-a-monitored-target-in-depth.md)). Nothing is created when one of them is shown.

| Code | What it means | What to do |
|---|---|---|
| `handover_monitor_not_active` | the engagement is not a monitor, or it is a draft, closed or revoked | only an active or paused monitor can start one; a revoked authorization cannot seed a new engagement |
| `handover_source_unsupported` | the monitor belongs to a bug-bounty program; its rules are not carried over | create the assessment from the wizard, with its own program details |
| `handover_host_unknown` | a host you chose is not known to the monitor and is not covered by its scope | pick hosts from the list |
| `handover_host_denied` | a host you chose is matched by one of the monitor's deny rules | a denied host can never be tested; pick another |
| `handover_window_invalid` | the test window ends before it starts, or is missing | give a start and an end, the end after the start |
| `handover_hosts_required` | no host was chosen | pick at least one, or choose the whole scope |
| `handover_hosts_not_allowed` | hosts were sent together with the whole scope | choose one or the other |
| `handover_forbidden` | you are neither the monitor's owner nor an administrator | ask the owner |

## Installation problems

A service that restarts, a certificate that is not issued, an API that does not answer, active tools that are unavailable: see [INSTALL.md §6](../../INSTALL.md#6-troubleshooting).
