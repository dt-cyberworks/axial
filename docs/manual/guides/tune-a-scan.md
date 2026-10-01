# Tune a scan

**Who this is for:** operators who want a scan to look further, go deeper, or be gentler on a target.
**After this page you can:** choose between Standard and Thorough, switch the discovery extras on or off, and set the pace of a scan, knowing what each costs in time and in traffic.

<!-- ui-labels: Discovery extras | Scan depth | Edit engagement | Advanced options (discovery extras, UDP discovery, Vector Agent, asset review) | Enable bounded UDP discovery (53, 123, 161, 443, 500, 1900, 4500, 5060, 5353) | Scan rate policy | Maximum allowed tool calls per second -->

Every setting on this page only ever **narrows or deepens inside** what the scope and the tool grants already allow. None of them can reach a target that is not in scope.

## Scan depth

Under **Scan depth** (wizard: advanced options; later: **Edit engagement**):

| Depth | What it does | Cost |
|---|---|---|
| **Standard** (default) | for each web service, runs the generic templates plus only those written for the technologies it identified | the normal scan, typically 10 to 20 minutes for one small site |
| **Thorough** | runs every template on every web service whatever was identified, and adds a deep content-discovery sweep of about 30,000 likely paths per web service | much slower: the sweep alone is about 25 minutes per web service, and there is far more traffic |

Choose Thorough when a complete sweep matters more than time, for example before a major release or for a site that is hard to identify. If a slow target, or a bug-bounty rate cap, cuts a sweep short, it is marked *partial* rather than complete. Scan depth can be changed at any status; it applies from the next scan, and every run records the depth it started with. It never widens scope, tool grants or the discovery switches.

## Discovery extras

Four switches, under **Discovery extras** in the wizard's advanced options and on the Edit page. They apply from the next scan, can be changed at any time, and are checked on every tool call.

| Switch | Default | Use it when | What to expect |
|---|---|---|---|
| Passive subdomain sources | **on** | you want the most complete list of names | no traffic to your systems; only public sources are asked |
| Crawling and URL history | off | the site has pages and parameters its front page does not list | a shallow crawl (two levels) of in-scope sites under the rate limit; archived URLs from web archives; nuclei then tests up to 50 URLs with parameters |
| Out-of-band testing | off | you want blind vulnerabilities found (those where the target has to call back) | needs the platform's own interaction server; if it is not set up the pass is recorded as unavailable |
| Web screenshots | off | you want to see what each page looks like and spot forgotten apps | one page load per service; screenshots are shown on the **Assets** tab and kept out of the PDF report |

What each does exactly: [Tools](../tools.md#optional-discovery-extras). The engagement's header lists the ones that are on, and the [authorization PDF](authorize-and-activate.md) states the state of each, so tell your client before you switch one on after they signed.

## Pace

Three things set the pace of a scan.

- **The installation's rate limit.** An admin sets the maximum number of tool calls per second under **Settings → Scan rate policy** (5 by default). With *automatically slow down* on, a call that exceeds it waits and retries rather than failing.
- **A bug-bounty program's cap**, if the engagement follows one: its own maximum requests per second and concurrency apply on top, in both the gateway and the egress proxy.
- **The tools' own limits.** The web tools are rate-limited, at most two checks run in parallel per engagement, and every check has a time budget of at most 30 minutes.

To make a scan gentler, ask an admin to lower the rate, switch off the extras you do not need and keep **Standard**. To make it wider, switch on the extras and choose **Thorough**, and plan for the time.

## Network discovery options

- **Port range.** The engagement's TCP range (all ports by default) is an outer limit; each scope row can narrow it for one target. Narrowing it is the easiest way to make a port scan shorter.
- **UDP discovery.** Off by default. If you opt in (**Enable bounded UDP discovery**), it covers a fixed list of nine common UDP ports and nothing else. UDP gives *inconclusive* answers often, and those are reported as inconclusive, never as clean.
- **Asset review.** **Pause after discovery for manual asset review** makes each run stop after discovery so you can drop hosts that should not be scanned. See [Run detail](../reference/run-detail.md#asset-review).
