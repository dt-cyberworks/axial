# Settings (Admin)

**Who this is for:** administrators who configure the installation.
**After this page you can:** say what each global setting does, what its default is, and which of them an individual engagement can override.

<!-- ui-labels: Admin | Operational settings | Users | Account audit | Operational guardrails | Provider source | API key | Max RPS | Auto slow down | Scan rate policy | Maximum allowed tool calls per second | Automatically slow down and retry rate-limited tool calls | Provider | Base URL | Model | NVD API key (optional) | Tool policy (global defaults) | Needs approval | Vector Agent iteration budget (global default) | Max iterations | Vector Agent max tokens (global default) | Max tokens | Manual approval timeout (global default) | Timeout (seconds) | Vector Agent instructions (global default) | Subdomain source keys (optional) | Monitoring defaults | E-mail (SMTP relay) | Send e-mail | Relay host | Send a test message to me | Tool-call budget per run (global) | Tool calls per run | Save tool-call budget -->

## The Admin hub (`/admin`)

**Admin** is only in the navigation for administrators; an operator who opens the address sees *You need an administrator role to view this page*. It has three tabs: **Operational settings** (this page), **Users** and **Account audit** (see [Account, sign-in and administration](account-and-admin.md)). The old addresses `/settings`, `/admin/users` and `/admin/audit` open this hub.

## Operational settings

![The operational settings tab](../img/admin-settings.png)

The page is titled *Settings*, with the subtitle *Operational guardrails*: provider access and traffic policy. The Scope Gateway still decides every action regardless of anything here. A strip at the top shows the **Provider source**, whether the **API key** is set, the **Max RPS** and whether **Auto slow down** is on.

### Provider

The AI provider used by the Vector Agent and the Lens Agent: a **Base URL**, a **Model** and an **API key**. The client speaks the Chat Completions format used by OpenAI and many compatible gateways. A base URL ending in `/responses` is normalised before use, but the provider must still offer a compatible `/chat/completions` endpoint. The API key is write-only: the page shows whether one is set, never the key. The **Provider source** tells you whether the values come from the environment or from what an admin saved here; a value saved here overrides the environment. Without a provider the agent phase does nothing and the Lens Agent cannot explain findings. Step by step: [Configure the AI provider](../guides/configure-the-llm.md).

### Scan rate policy

**Maximum allowed tool calls per second** (default 5): the gateway always enforces it. With **Automatically slow down and retry rate-limited tool calls** on, a worker whose call is rate-limited waits for the gateway's retry delay and asks again instead of treating it as a hard denial. A bug-bounty engagement's own request-rate cap is enforced on top of it for that engagement.

### NVD API key (optional)

Used by the live CVE correlation (NVD, EPSS and the CISA known-exploited list) for services the scan fingerprinted. It works without a key at NVD's public rate limit (5 requests per 30 seconds); a free NVD API key raises that to 50. It is never required.

### Tool policy (global defaults)

Per tool: **Enabled**, and whether it **Needs approval** (one-time, per call). A tool that is not installed can never be enabled, and scope and argument safety stay enforced whatever you set. A campaign can override these per engagement under **Campaign tool overrides**. How the layers combine: [Control which tools run](../guides/control-which-tools-run.md).

### Vector Agent iteration budget (global default)

**Max iterations**: the number of tool-call round-trips the agent may make per run before it must conclude. Default 50, between 1 and 500. Higher values let it investigate more but cost more time and tokens. A malformed or rejected proposal still uses one iteration, so raise this if the agent runs out of budget before it finishes. A campaign can override it.

### Tool-call budget per run (global)

**Tool calls per run**: the most tool calls one scan run may make, the planned checks and the Vector Agent together. It is a whole number from 20 to 5000; the default is 200. Only an administrator can change it, and there is no per-engagement value.

- **When it applies.** A new value applies to the runs that start after you save it. A run that is already going keeps the budget it started with, and each run's start is recorded in the audit log with the budget it had.
- **What happens when a run uses it up.** The Scope Gateway refuses every further call. The checks behind them do not run (they show as *skipped*, `gateway_denied:budget_exhausted`), and the run is marked **reduced coverage**: its health is *degraded*, it is not the baseline for the next comparison, a monitor puts it in the [inbox](inbox.md), and the report says so. It is never presented as a clean run.
- **How much to set.** A small site needs a few dozen calls. A scan of many web services, and the **Thorough** depth in particular, needs far more: every check of every web service is a call, so the number grows with the number of hosts. If a run ends with *reduced coverage* and `tool_call_budget=exhausted_<n>_denied`, raise the budget by at least `n` and run again.
- **What it does not do.** Raising it never widens scope, tool grants, capabilities or any other gateway rule. It only lets a run make more of the calls those rules already allow, which also means more traffic to the target.

### Vector Agent max tokens (global default)

**Max tokens**: the cap on the model's output in one turn, its reasoning plus the tool-call JSON itself, *not* the context window. Default 8,192, between 1,024 and 32,768. Set too low, a turn is cut off in the middle of the JSON, the tool call fails to parse and the agent stalls without an obvious reason. A campaign can override it.

### Manual approval timeout (global default)

**Timeout (seconds)**: how long a state-changing request waits for an operator's decision before it is rejected automatically, so a scan cannot hang if nobody is at the desk. Default 900 seconds (15 minutes), between 60 seconds and 24 hours. A campaign can override it.

### Vector Agent instructions (global default)

The agent's system prompt, always shown. It starts as the built-in default (a platform overview, awareness of the engagement's parameters and a check list based on the OWASP Top 10) and is editable in place. **Editing it is safe:** the Scope Gateway decides every action regardless of the prompt, so no prompt can cause an out-of-scope or destructive action. Save an empty box to return to the built-in default. Each engagement's Edit page shows the same effective text and can save its own override.

### E-mail (SMTP relay)

Optional and off by default. It lets the console send plain-text messages; the first use is the password-reset link on the sign-in page. With it off, no e-mail is sent, the sign-in page offers no **Forgot password?** link, and an administrator's **Reset password** keeps working.

| Field | Meaning |
|---|---|
| **Send e-mail** | the switch. Off keeps everything as it was |
| **Relay host**, **Port**, **Security** | the SMTP relay and how to reach it: STARTTLS (usually 587) or TLS from the start (usually 465). Plain, unencrypted SMTP is not offered. The host has to be a name with a domain or a public address; a service of this installation and a loopback address are refused |
| **Username**, **Password** | the relay's login. The password is stored encrypted and is never shown again; leave it empty to keep the stored one |
| **Sender address**, **Sender name** | what the message says it is from |
| **Send a test message to me** | queues one message to your own address (five an hour) and shows whether it was delivered |

Messages are queued and sent by the worker, because the control plane has no route to the internet. A message that cannot be delivered is tried again with growing pauses and then reported as failed; it never affects a scan.

### Monitoring defaults

What a **new** monitoring engagement starts with: which capabilities are on, the scan depth, whether new hosts of a customer's systems and of your own systems are held until released, whether a monitor whose target starts failing pauses itself, and how many monitoring runs may be active at the same time. The values are *copied* when an engagement is created: changing them here does not alter an engagement that exists, because someone may already have signed for what it does. See [Monitor an attack surface](../guides/monitor-an-attack-surface.md#capabilities).

### Subdomain source keys (optional)

Optional API keys for subfinder's data sources. subfinder works without keys; some sources return more with a free key. Keys are stored encrypted, are write-only (the page shows whether one is set, never the key), and are used only for these lookups. Leave a field empty to keep the current key; **Remove** deletes it.
