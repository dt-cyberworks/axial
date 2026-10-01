# Troubleshooting

**Who this is for:** operators and admins who see a message, a code or an empty result and want to know what it means and what to do.
**After this page you can:** look up every blocker, run reason, check reason and gateway denial the console shows, and work out why a scan found nothing or an agent did nothing.

<!-- ui-labels: Scan readiness | Start run | Activate engagement | Edit engagement | Tool grants | Campaign tool overrides | Discovery extras | Scope assets | Stop scan | Plan | Activity | Vector Agent | Audit | reduced coverage | partial coverage -->

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
| `bounty_program_missing` | a bug-bounty engagement has no program policy | fill in **Bug bounty program policy**; see [Define an engagement](guides/define-an-engagement.md#bug-bounty-engagements) |

Two more things stop the **Start run** button: a run is already active on this engagement (**A run is already active**), or the page could not check readiness (it says so; reload).

## Why a run stopped

The reason is shown beside the run's state, on the run page and in the runs table.

| Reason | Meaning | What to do |
|---|---|---|
| `cancelled_by_operator` | someone chose **Stop scan** | start a new run when you are ready |
| `cancellation_status_unavailable` | the control plane could not say whether you had cancelled, so all work against the targets was stopped as a safety measure. Nothing was left out on purpose | start the run again. If it recurs, the control plane is overloaded or restarting; ask an administrator to check it |
| `reaped_stale_heartbeat` | the worker running it stopped sending signs of life and the run could not be resumed (it had never been claimed, it had already been resumed twice, or it could not be queued again) | start a new run; ask an administrator to check the worker |
| `asset_review_pending` | the run is waiting for you to review the discovered hosts (a `waiting_approval` run). Not a failure | answer the **Review discovered assets** popup; see [Run detail](reference/run-detail.md#asset-review) |
| `asset_review_expired` | the asset review popup was not answered within 15 minutes, so the run stopped rather than scan everything | start a run and answer the review, or switch the review off |
| `task_time_limit_exceeded` | the whole scan task ran into the worker's time limit | narrow the scope or the scan depth, or split the engagement |
| `pipeline_error:<type>:<phase>` | an internal error ended the run. The *type* is the kind of error and the *phase* where it happened. A run that ended with only `pipeline_error` is from an older version that did not record the cause | start it again; if it repeats with the same type and phase, report both to an administrator |
| `coverage_degraded:<tool>=<why>` | a tool the scan depends on (`nmap` or `httpx`) was attempted but never once succeeded. **Not** a clean result | find out why the tool failed (the *why* is in the text), fix it and rerun |
| `coverage_partial:<tool>=<n>` | `n` checks of that tool stopped at their time budget. What they reported is real, but not everything was examined | rerun, or use **Thorough** scan depth, or accept the partial result knowingly |
| `agent_incomplete:<why>` | the Vector Agent ended before it finished its plan; the deterministic phases are unaffected | check the AI provider and the agent budgets; see [Configure the AI provider](guides/configure-the-llm.md) |

A run that stopped *without* your action for a reason that is not about the target can simply be started again; the findings of earlier runs are kept.

## Why a check was skipped or failed

In the **Plan** tab each check has a state and a reason.

| State | Means |
|---|---|
| **complete** | ran to the end |
| **partial** | stopped at its own time budget (`budget_reached`); what it printed before is real, but it did not finish. **Not clean** |
| **failed** | the tool or its handler failed; the reason says how (`handler_error:<type>`, or the tool's own error). **Not clean** |
| **skipped** | not run, for the stated reason. **Not clean** unless the reason says it did not apply |

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
| `oob_unavailable` | the platform's interaction server is not set up, so out-of-band testing cannot run |
| `materialized_ip_missing` | the name did not resolve to an address that could be audited |
| `raw_egress_unavailable` | the network-scan gateway was not available |
| `scan_run_missing` | no valid run context, so the tool did not start |
| `dependency_never_finished` | a check this one depends on never finished |
| `web_alias_of:<surface>` | the port only redirects to another scanned port, which is checked there |
| `duplicate_vhost_of:<surface>` | the same site as another name, checked once there |
| `gateway_denied:<reason>` | the Scope Gateway refused the call; the reason is one from the next table |
| `cancelled_by_operator` | the run was stopped |
| `cancellation_status_unavailable` | stopped as a safety measure; see above (a *failed* check) |

## Why the Scope Gateway denied a call

A denied call appears as a *deny* row in **Audit** and in the **Activity** tab, with the reason code. A denial means **nothing was sent to the target**. Most denials are the system working as intended.

| Code | Meaning | What to do |
|---|---|---|
| `target_out_of_scope` | no allow row matches the target | check the spelling; a wildcard such as `*.example.com` does not cover `example.com`. Add a row only if you are entitled to |
| `explicit_out_of_scope` | a deny row matches the target. Deny always wins | remove the deny row only if it is wrong |
| `active_not_allowed` | the target is in scope but not marked active | tick **active** (and **authorization attested**) on its allow row |
| `no_tool_grant` | the engagement does not grant the tool's category in the mode it needs | grant it under **Tool grants**. A per-tool switch cannot replace the grant |
| `tool_disabled` | the tool is switched off, in Settings or for this campaign | **Campaign tool overrides**, or an admin in **Settings** |
| `tool_not_whitelisted` | the tool is not in this version's allow-list | cannot be changed |
| `passive_not_supported` | the tool has no passive mode | use an active grant, if active testing is authorised |
| `unsafe_arguments` | the arguments failed the safety policy | cannot be overridden; it needs a code change |
| `outside_time_window` | the authorised window is not open | change the dates, if you are authorised |
| `engagement_not_active` | the engagement is not active | activate it |
| `engagement_not_found` | the engagement does not exist | internal; report it |
| `scan_run_required` | the call has no run context | internal; report it |
| `scan_run_not_found` | the run does not exist for this engagement | internal; report it |
| `scan_run_not_active` | the run is no longer running | the run ended; nothing to do |
| `scan_run_cancelled` | the run was stopped | nothing to do |
| `budget_exhausted` | the run used its tool-call budget (200 by default) | start a new run, or narrow the scope |
| `rate_limited` | the request rate is exhausted | with *automatically slow down* on, the worker waits and retries; otherwise an admin can raise the limit in **Settings** |
| `ai_testing_not_enabled` | the Vector Agent is not enabled on this engagement | tick the switch on **Edit engagement** |
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
| the allow-scope overlaps another currently active engagement's allow-scope: "Title" (owner Name, email) | the message names the active engagement that already covers some of these hosts (up to three; "and N more" if there are more), and its owner. The two cannot both be responsible. Change one scope, or ask the owner to finish theirs |
| a customer engagement needs the signed scope document | record who signed it and the document's SHA-256 |

## Why a change was refused

You can read every engagement, but only its owner and administrators can change it (see [Roles and ownership](concepts.md#roles-and-ownership)). A change from anyone else is refused, and nothing is written.

| Message | Meaning and what to do |
|---|---|
| only the owner of this engagement or an administrator can change it | the engagement belongs to someone else. Ask its owner (the notice at the top of the page names them), or an administrator, to make the change or to hand the engagement to you |
| admin role required | the action (for example reassigning an owner, or anything under **Admin**) is for administrators only |

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
5. A **Lens Agent** explanation can be cut off by the provider's length limit; the page says so.

## The scan found nothing

An empty list is a result, but not necessarily a clean one. Work through:

1. **Is the scope right?** Names outside it are never scanned. Look at the **Plan** tab: which hosts and ports were checked?
2. **Did it cover them?** Look for **reduced coverage** or **partial coverage** on the run, and for *failed*, *partial* or *skipped* checks in the **Plan** tab. A check that did not run says nothing about its target.
3. **Were the tools allowed?** A category that is not granted, or a tool that is switched off, shows as skipped with `no_tool_grant` or `tool_disabled`.
4. **Was the host up?** A host that is down looks clean. Look at the **Activity** tab for blocked or failed steps.
5. **Is the depth right?** **Standard** only runs templates for what it identified. **Thorough** runs more.

If the run really covered everything and still found nothing, that is a good outcome. See [Safety, legal and limits](safety-legal-limits.md#what-axial-does-not-cover) for what even a complete run cannot tell you.

## Installation problems

A service that restarts, a certificate that is not issued, an API that does not answer, active tools that are unavailable: see [INSTALL.md §6](../../INSTALL.md#6-troubleshooting).
