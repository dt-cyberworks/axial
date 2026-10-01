# Configure the AI provider

**Who this is for:** administrators who want the Vector Agent and the finding explanations to work.
**After this page you can:** connect a provider, switch the agent on for an engagement, check that it is working, and judge what you are sending to the provider.

<!-- ui-labels: Admin | Operational settings | Provider | Base URL | Model | API key | Provider source | Vector Agent iteration budget (global default) | Max iterations | Vector Agent max tokens (global default) | Max tokens | Vector Agent instructions (global default) | Allow Vector Agent autonomous proposals for this engagement | Edit engagement | Vector Agent | Explain with Lens Agent -->

Two features need an AI model: the **Vector Agent**, which proposes further checks during a scan, and the **Lens Agent**, which explains a finding in plain language. Everything else in Axial works without one. Without a provider the agent phase does nothing (the run shows that the agent was skipped because the provider configuration is incomplete), and **Explain with Lens Agent** answers that the provider is not configured. The deterministic scan results are unaffected.

## Connect a provider

1. Sign in as an administrator and open **Admin**, tab **Operational settings**.
2. In **Provider**, enter the **Base URL**, the **Model** and the **API key** and save. For example the base URL `https://api.openai.com/v1` and a model name your provider offers.
3. The strip at the top of the page then shows the **Provider source** and that the **API key** is *set*. The key is write-only: it is never shown again.

What the provider has to offer:

- An **OpenAI-compatible Chat Completions** endpoint. OpenAI itself, and many gateways and local servers, speak it. A base URL that ends in `/responses` or `/chat/completions` is normalised for you, but the provider must still serve `/chat/completions`.
- A model that supports **tool (function) calling**, because the Vector Agent proposes checks as tool calls.

You can also preconfigure the provider with the environment variables `LLM_BASE_URL`, `LLM_API_KEY` and `LLM_MODEL` when you install; see [`INSTALL.md`](../../../INSTALL.md). A value saved on the Settings page overrides the environment, and **Provider source** shows which one is in use.

## Switch the agent on for an engagement

The agent is **off by default** and is a per-engagement decision. On **Edit engagement**, tick **Allow Vector Agent autonomous proposals for this engagement**. The Lens Agent needs no switch.

For a bug-bounty engagement the program must also allow it: if the program's policy does not permit AI testing, the gateway denies the agent's calls.

## Check that it works

Start a run on an engagement with the agent on, and open the run's **Vector Agent** tab. Each step shows the exact input sent to the model and its reply with the tool calls it proposed. If the tab says *No agent steps recorded*, it also says why: no provider, the agent switched off, or the run stopped before the agent phase. For the Lens Agent, open a finding and choose **Explain with Lens Agent**.

## Cost and limits

The agent works in round-trips: each is one model call plus the tool call it proposed.

- **Max iterations** under **Vector Agent iteration budget (global default)**: how many round-trips per run (50 by default, 1 to 500). A malformed or rejected proposal still uses one. If the agent regularly runs out before it finishes, raise it; expect more time and tokens.
- **Max tokens** under **Vector Agent max tokens (global default)**: the cap on one model reply, its reasoning plus the tool-call JSON (8,192 by default, 1,024 to 32,768). Too low, and a reply is cut off in the middle of the JSON: the tool call cannot be read and the agent stalls without an obvious reason.
- Each of these, and the agent's instructions, can be overridden for a single engagement on its Edit page.

## What you send to the provider

The model needs context to be useful, so the provider receives what the agent works with: your engagement's scope and parameters, the hosts and services the scan found, tool results and evidence (with secret values redacted), and the agent's own earlier steps. The **Vector Agent** tab shows exactly what was sent for each step. The Lens Agent sends one finding's recorded evidence.

Decide with that in mind. For a customer who forbids sending their data to a third party, use a provider you host yourself, or leave the agent off: the rest of the scan does not need it. The agent can only propose; no prompt can make it do anything the Scope Gateway has not authorised, which is also why its instructions are safe to edit under **Vector Agent instructions (global default)**.
