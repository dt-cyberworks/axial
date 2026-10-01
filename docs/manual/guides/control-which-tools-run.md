# Control which tools run

**Who this is for:** operators who set up an engagement, and anyone asking "why won't this tool run here?".
**After this page you can:** tell the three tool controls apart, grant or remove a category on an engagement that is already active, switch a single tool off for one campaign, make a tool wait for your approval, and read the reason a tool is unavailable.

<!-- ui-labels: Tool grants | Campaign tool overrides | Allow passive | Allow active | Require approval for these active tools | Save tool grants | Confirm and save | Confirm: this widens what the engagement is authorized to do | Inherit global | Force on | Force off | Approval | Available | This campaign | Save campaign config | Tool policy (global defaults) | Edit engagement | Go to tool grants | Open tool grants -->

Axial has **three separate controls** over tools. They are easy to mix up, because the console shows them in different places. They answer different questions, and a tool runs only when all of them agree.

| Control | Question it answers | Where | Granularity |
|---|---|---|---|
| **Tool grants** | Is this *kind* of testing authorised on this engagement at all? | Wizard, **Tools** step; **Edit engagement → Tool grants** | a category (recon, fingerprint, vuln, cred, exploit) × passive or active |
| **Tool switches** | Is this *single tool* switched on? | **Settings → Tool policy (global defaults)** for everyone; **Edit engagement → Campaign tool overrides** for one campaign | one tool |
| **Approval** | Must a person approve each call? | either of the places above, and **Require approval for these active tools** in the grants | one tool |

## The order of the checks

Every call is checked, in this order, by the Scope Gateway. The first check that fails denies the call and the reason is recorded.

1. **Built into this version.** A tool that is not installed in this version can never run, whatever you set.
2. **The grant.** The engagement must grant the tool's category, in the mode the tool runs in: *passive* for public-source (OSINT) tools, *active* for everything else. No grant, no run (`no_tool_grant`).
3. **The switches.** The global tool policy in Settings, then this campaign's override. A tool switched off at either level does not run (`tool_disabled`).
4. **Approval.** If the tool needs approval, the call waits for you.

Scope, test window, argument safety, the rate limit and the budget are checked as well, for every tool; see [Concepts](../concepts.md#scope-gateway).

The consequence that surprises people: **a switch can only narrow what the grants allow. It can never create a grant.** "Force on" for a tool whose category is not granted changes nothing; the call is still denied with `no_tool_grant`.

## Grant a category

![The tool grants table and the Campaign tool overrides on the Edit page](../img/edit-tool-grants.png)

Open **Edit engagement → Tool grants** (on a draft, the same table is on the engagement page). For each category you can tick:

- **Allow passive**: public-source enrichment only. It is offered only for categories that really have a passive tool.
- **Allow active**: target-touching tools of that category.
- **Require approval for these active tools**: the tools you tick wait for your approval on every call. For the `vuln`, `cred` and `exploit` categories every tool is pre-selected when you first grant active.

Choose **Save tool grants**. The change applies from the next tool call.

On an engagement that is **already active**, two guards apply because the change widens what the engagement may do:

- Adding an **active** category asks you to confirm: *Confirm: this widens what the engagement is authorized to do.* Nothing is written until you choose **Confirm and save**. Adding a passive category, or saving a grant you already have, needs no confirmation.
- **Nothing can be added or changed while a scan is running.** Wait for the run to finish, or stop it. The editor tells you so.

## Remove a category

Untick the box and save. Removing narrows what the engagement may do, so it needs no confirmation and **works at any time, also while a scan is running**: from the next tool call the gateway denies that category. Your per-tool switches and approval flags are left alone. Grants of a `completed` or `revoked` engagement can no longer be changed.

Every addition and removal is written to the [audit log](../reference/audit.md) with your name, the category, the mode, and (for an addition) whether the widening was confirmed.

## Switch a single tool off, or on, for one campaign

Under **Edit engagement → Campaign tool overrides**, each tool has a choice in the column **This campaign**:

- **Inherit global**: follow Settings. This is the normal state.
- **Force off**: the tool does not run on this engagement, even if Settings enables it. Use it to switch off one tool you do not want here, for example a tool the customer excluded.
- **Force on**: enable the tool here even though Settings switches it off. It still needs its category granted, and it cannot enable a tool that is not installed.

Choose **Save campaign config**. Saving the grants never resets these choices.

An admin sets the defaults for everyone under **Settings → Tool policy (global defaults)**; see [Settings](../reference/settings.md).

## Make a tool wait for your approval

Tick **Approval** for the tool in the overrides table, or tick it in the grants table under **Require approval for these active tools**. It is the same setting in two places. From then on every call of that tool pauses the run until you decide; see [Approve or deny a tool call](approve-or-deny-a-tool-call.md). Approval only applies to active tools: a category has to be granted for active before a tool in it can ask.

## Why can't this tool run?

The **Available** column of the overrides table says whether a tool can run on this engagement, and if not, why:

| It says | Meaning | Fix |
|---|---|---|
| can run | grant, switches and installation all agree | nothing to do |
| Its category is not granted | the engagement does not grant this tool's category (in the mode the tool needs) | grant it under **Tool grants**; the row has a link |
| Switched off for this campaign | this campaign has **Force off** | set **Inherit global** or **Force on** |
| Switched off in Settings | the global policy has it off | an admin enables it in Settings, or you use **Force on** |
| Off by default in this version | it is not part of the default tool set | enable it in Settings if you want it |
| Not installed in this version | the tool is not in the runner | cannot be enabled |

The column beside it says which layer decided: this version's default, Settings, or this campaign. When a scan cannot start because no category is granted for active testing, the engagement page says so and links here.

## Examples

**"This engagement cannot scan yet: no tool category is granted for active testing."** The engagement was created without ticking a category. Open **Edit engagement → Tool grants**, tick **Allow active** for `fingerprint` and `vuln`, choose **Save tool grants**, confirm the widening, and start the run.

**"The customer does not want TLS testing."** Under **Campaign tool overrides**, set `testssl` to **Force off** and choose **Save campaign config**. Its checks show as skipped in the plan.

**"I want to approve every nuclei call myself."** Tick **Approval** for `nuclei`. Expect the run to pause often, because the scan makes many nuclei calls.
