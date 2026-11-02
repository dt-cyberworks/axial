# Monitor an attack surface

**Who this is for:** operators who want Axial to watch a scope again and again and say what changed, without anyone at the screen.
**After this page you can:** set up a monitoring engagement, decide what it does on every run, read what it reports, and know what it will not do by itself.

<!-- ui-labels: Monitor an attack surface | Test a target | What to monitor | Capabilities | Alerts | Authorize | Activate and discover | Choose targets | Review targets | Select all shown | Select none shown | Discover again | Run now | Changes | Capabilities & alerts | Save capabilities | Add webhook | Inbox | Pause engagement | Resume engagement | Close engagement | Revoke authorization | Monitoring defaults | Release all | Automatic runs | Switch on | Switch off | Change -->

A *monitoring* engagement is one you set up once and let run. It is the other of the two uses of Axial; the first is a *test* that a person starts and decides along the way. Read [Concepts](../concepts.md#operating-modes) for the difference. What they share is everything that keeps a scan safe: the scope, the deny rules, the authorization, the window and the audit log.

## What a monitor does and does not do

| It does | It does not |
|---|---|
| Run the same checks every time, so two runs can be compared | Wait for a person during a run. Nothing pauses on a popup or on a review |
| Tell you what changed: a new host, a new open port, a new version, a new or fixed finding | Make a request that needs a person's approval. Such a call is not made; the whole request is kept and listed in the inbox as **Held back for you**, to be sent by you, one request at a time |
| Keep a newly found host out of the testing until you release it, if you choose so | Test credentials or exploit anything. Those categories cannot be granted to a monitor |
| Say when it is quiet, degraded or about to need a review | Report something as fixed from a run that did not look at everything |

## Set it up

Choose **New engagement**, then **Monitor an attack surface**. The wizard has four steps.

1. **What to monitor.** A name, an emergency contact, the dates between which monitoring is authorized, and the scope. Add an *allow* row for each domain, address or range, and tick **I am authorized to test this**. A *deny* row always wins. The default period is a year: a monitoring authorization is standing and is reviewed once a year.
2. **Capabilities.** What it does on every run (below), the scan depth, and what happens with a new host.
3. **Alerts.** Where to send a message when something changes.
4. **Authorize.** What will run without anyone watching, and what can never happen. Download the authorization document for signature, then **Activate and discover**.

Activation does not scan anything yet. It starts a **passive discovery**: public sources and DNS only, nothing is sent to your systems. When it has finished, the engagement page and the [inbox](../reference/inbox.md) ask you to **Choose targets**. Nothing is scanned, by you or by the schedule, until you have done that (see [Choose the targets](#choose-the-targets)). Then the first scan runs on exactly the hosts you chose. The first healthy run is the baseline: it reports nothing as changed, because there is nothing yet to compare with. The next run shows what is different.

## Choose the targets

A monitor is not activated into a scan. Activation starts a passive discovery and then waits for you: a monitor that tested whatever public sources happened to list, before you had seen the list, would also test names that point at addresses nobody on your side owns (a dangling DNS record, for example). So the choice is yours, and it is a visible step.

1. **Discovery.** The engagement page says *Discovering your attack surface*. This takes a few minutes; large domains take longer. Public sources and DNS only: nothing reaches your systems.
2. **Choose targets.** When it has finished, the engagement page, the [inbox](../reference/inbox.md) and (if you set one up) your alerts tell you. Open **Choose targets** (the screen is `/engagements/:id/targets`). It lists every host the discovery found with the address it resolves to, its hosting provider, where it was found, and where it points:
   - *Same address as a root*: it resolves to the same address as one of your allow rows. These are selected for you.
   - *Resolves elsewhere*: it points at an address none of your roots uses. It is **not** selected, and carries a warning: select it only if you are authorized to test whatever answers there.
   - *Does not resolve*: it has no DNS address and nothing can be tested on it. These names are hidden until you choose **Show names that do not resolve**.

   You can search, **Group by address**, and use **Select all shown**, **Select none shown** or **Select suggested (same address as a root)**. A root of your scope cannot be left out.
3. **New hosts later.** Choose what happens to a host found after this baseline: *Hold until I release them* (recommended; it is listed in the inbox and not tested) or *Test as soon as the scope covers them*.
4. **Confirm.** The screen says how many hosts will be excluded. Each one gets an explicit *deny* row, so the decision is on the record, in the audit log per host and as one decision. Your allow rows stay: they are the record of what you are authorized to test. Then the first scan runs on exactly the hosts you chose, and the interval of the [automatic runs](#automatic-runs) counts from it.

Until you confirm, **Run now** answers that the targets are not confirmed, and the schedule starts nothing. A discovery that did not finish shows *The discovery did not finish*: choose **Discover again**.

**Review targets.** The same screen stays available (**Review targets** on the engagement page). **Discover again** refreshes the list with another passive discovery and blocks nothing: the monitor keeps running. Leaving a host out takes effect at once. Including a host you excluded before widens what is tested, so the screen asks you to confirm it, and it is refused while a run is active.

**Held hosts.** A host the hold policy is holding carries a **held** marker on this screen: it is listed but not tested. **Choosing it releases it**: confirming releases every held host you chose, clears its inbox item and records it in the audit log, and the next run tests it. Releasing widens what is tested, so the screen asks you to confirm it naming the hosts, and it is refused while a run is active. A held host you leave out stays held and is excluded.

**Hosts a run did not test.** The **Plan** tab of a run and the PDF report list the hosts that are in scope but that the run did not test, with the reason: *held back by the monitor's hold policy until the owner releases it*, *the name has no DNS address*, or *no open port was found on it*. A short findings list therefore never hides a host nothing was sent to.

Only the owner of the engagement or an administrator can choose; everyone else can read the list.

## Capabilities

A capability is a function of the scanner that this engagement switches on or off **once**. It applies to every run, never to a single one, and a run that is already going picks a change up on its next call.

| Capability | What it is |
|---|---|
| Public-source discovery | Certificate logs, DNS and passive subdomain sources. Nothing is sent to your systems |
| Port and service scan | TCP port scan and service detection inside the engagement's port limits |
| Web fingerprint, TLS and security headers | Which web server and technology runs, its TLS setup and its headers |
| Vulnerability templates | Template-based checks for known weaknesses in what was found |
| Content discovery | Looks for exposed files and paths on web services |
| Crawling and URL history, Web screenshots, Out-of-band interaction testing | The three discovery extras; off by default |
| Vector Agent | An AI model proposes further checks. Off by default. Whatever it proposes that would need a person's decision is not made but kept whole as **Held back for you** |

![The capabilities panel of a monitoring engagement](../img/monitor-capabilities.png)

A capability can only select among what the scope, the tool grants and your attested authorization already allow. It never goes beyond them.

**Scan depth.** *Passive* uses public sources only and sends nothing to your systems. *Light* checks fingerprint, TLS, security headers and takeover only, which is cheap enough to run daily. *Standard* is the usual depth. *Thorough* runs all non-intrusive web templates, whether or not their product was identified, plus a deep content sweep, and takes much longer.

**New hosts.** This is about hosts found *after* the baseline. *Hold until I release them* (the default) inventories a new host and tells you, but does not test it until you release it in the [inbox](../reference/inbox.md). *Test as soon as the scope covers them* tests it at once, so nobody looks at it first. A host you wrote into the scope yourself is never held, and neither is one that was already there before you switched the policy on. There is one default for every engagement, whoever's systems they are: what matters is that you are authorized to test them. You choose again for this engagement on the target screen.

**Widening after activation.** Turning a capability on, going to a deeper scan depth or switching hold off after activation asks you to confirm, because it widens what runs unattended. It is refused while a run is active. Narrowing is always possible.

The administrator sets what a *new* monitoring engagement starts with under **Monitoring defaults** in the admin settings. The values are copied when the engagement is created; changing them later does not change an engagement that already exists, because a customer may already have signed for what it does.

**Monitoring runs at the same time** (also under **Monitoring defaults**, 1 to 4, default 1) is how many *scheduled* monitoring runs may be active across the whole installation. A due run beyond that waits for the next check, a minute later, and its panel says so. A change applies from the next check, without a restart. It does not limit a run a person starts with **Run now**.

## Automatic runs

![The Automatic runs panel: every 7 days and the time of the next run](../img/monitor-schedule.png)

A monitor can run by itself every so many days. Set the number on the **Automatic runs** panel of the engagement page, or in step 2 of the wizard (the wizard starts with 7). **Switch on** starts it, **Change** alters the number of days, and **Switch off** goes back to starting every run yourself with **Run now**. It is whole days, from 1 to 90, and there is no time of day: the point is that the interval is simple.

How the count works:

- The next run is due one interval after the **latest** of: when you set the interval, when the engagement last became active (activation, or **Resume engagement**), and when the last run started, whoever started it. A **Run now** therefore restarts the count.
- Setting the interval never starts a run at once. The first run of a new monitor starts when you confirm its [targets](#choose-the-targets); until then nothing is scheduled. For a monitor that existed before that step, start the first run yourself with **Run now**. The first healthy run is the baseline.
- A scheduled run is exactly a run you could start: the same readiness check, the same scope, grants and limits, and it never waits for a person. Its start is recorded in the audit log with the schedule as the actor.

When a due run does not start, the panel says why, the reason is recorded, and the run starts by itself as soon as the cause is gone:

| Reason | What it means |
|---|---|
| The engagement is paused (or not active) | Resume it. Nothing runs while it is paused, draft, completed or revoked |
| The authorized window is not open | The test window has not begun or has ended |
| The authorization review date has passed | Review the authorization to continue; an item appears in the inbox |
| A run is still going | The next one starts after it; runs of one engagement never overlap |
| Waiting for capacity | Other scheduled runs are using the installation's capacity (one at a time unless the administrator raised the limit) |
| Not ready to scan | A readiness blocker, such as scope without an attested authorization; an item appears in the inbox |

A failed run is not retried by the schedule: the next run is due one interval after it started, or when you run it yourself. If a monitor has no healthy run for twice its interval, the inbox shows it and an alert is sent.

## Read what it reports

![The Changes tab of a monitoring engagement](../img/monitor-changes.png)

The engagement page shows **What changed** above its tabs, and the **Changes** tab lists everything: a new or missing host, an opened or closed port, a changed service version, a new, fixed or returned finding. Three rules make it trustworthy:

- The comparison is always with the last **healthy** run. A run that was cut short, or whose important tools failed, is marked *reduced coverage* and is never the comparison for the next one.
- A short run never reports something as gone or fixed. It can only say what it found.
- A finding is reported as fixed only after two healthy runs in a row did not see it, so a check that merely flickers does not look like a fix.

A finding that you have accepted as a risk or marked a false positive does not alert again.

## Alerts

Add a signed webhook on the **Capabilities & alerts** tab, under **Alerts**. The address must be a public https address; an internal or private address is refused. If you give a signing secret, every message carries an HMAC-SHA256 signature so the receiver can check where it came from. The secret is never shown again.

A message names the engagement, what changed and a link to the console. It contains no evidence, no request or response and no credential. Critical and known-exploited findings are sent at once; the rest as a daily digest. Delivery is retried with growing pauses; a failed delivery is shown with its error and never affects a run.

## The inbox

Everything a monitor could not decide for itself ends up in the [inbox](../reference/inbox.md): a held host, a request held back for you, a run with reduced coverage, a run that did not finish, a monitor that has gone quiet and an authorization that needs review. Open items are counted next to **Inbox** in the navigation.

## Go deeper

A monitor never sends a request that changes data and never waits for a person. When you want a person to test what it watches more deeply, choose **Test deeper** in the **Controls** row: it creates a draft assessment from the monitor, filled in with the hosts you pick and what the monitor found, and authorizes nothing. See [Test a monitored target in depth](test-a-monitored-target-in-depth.md).

## Stop it, or end it

On the engagement page:

- **Pause engagement** stops the active run and makes the gateway deny every call until you choose **Resume engagement**. Use it when a customer calls.
- **Close engagement** ends a finished engagement. It cannot be resumed; its findings, runs and reports stay.
- **Revoke authorization** is the kill switch. It stops everything now and the engagement can never scan again.

Only the engagement's owner and administrators can use these.

## What is not part of a monitor in this version

- **A time of day, windows or several schedules.** There is one interval per engagement, counted from the last run. A run starts when it is due, not at a chosen hour.
- **Requests that change data.** A request that could change data on a target is not made by a monitor, and the agent's proposal for one is kept whole as **Held back for you**. You can send it from **Not done yet**, one request at a time, in a run you start and watch ([Retest and run only what is open](retest-and-open-items.md)). Per-command approval remains the rule.
- **E-mail.** Alerts go to a webhook.

See also [Safety, legal and limits](../safety-legal-limits.md).
