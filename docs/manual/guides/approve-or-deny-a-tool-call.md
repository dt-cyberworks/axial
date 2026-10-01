# Approve or deny a tool call

**Who this is for:** operators who may be asked to decide on a request during a scan.
**After this page you can:** read an approval popup, decide with confidence, and know exactly what your click authorises.

<!-- ui-labels: Approval required — state-changing request | What it will do | Why (agent rationale) | Risk assessment (by the agent) | Approve & open run | Reject | Manual approval timeout (global default) | Manual approval timeout (campaign override) | Require approval for these active tools -->

## When you are asked

A scan runs on its own, with three exceptions. A call waits for you when:

1. **It could change data on the target.** An HTTP request with a method other than GET, HEAD or OPTIONS (POST, PUT, DELETE, PATCH), or any request with a body, never runs on its own. The Vector Agent can propose one; a human decides.
2. **It is a tool that is always supervised.** The proof of one specific ActiveMQ flaw (`activemq-openwire-probe`) asks every single time.
3. **You marked the tool for approval.** Tick **Approval** for a tool in the campaign overrides, or **Require approval for these active tools** in the grants. See [Control which tools run](control-which-tools-run.md).

The run then shows `waiting_approval` and a popup appears **on whichever page you are on**, naming the engagement it belongs to. If you are not at the screen, the request simply waits.

## Read the popup

![The approval popup: what the request will do, why the agent wants it, and its risk](../img/approval-popup.png)

The popup, **Approval required — state-changing request**, has three parts:

- **What it will do**: the exact request, so you see the method, the target and the body, not a summary.
- **Why (agent rationale)**: why the agent wants to send it.
- **Risk assessment (by the agent)**: the agent's own risk level and description. A state-changing request must come with one; a proposal without a risk statement is denied.

Ask yourself three questions: *Is this target and path in scope and meant to be changed by a test? Could it delete, overwrite or charge for something? Do I accept the risk the agent describes?* If you are not sure, reject. Rejecting costs one check; approving a destructive request cannot be undone.

## Decide

- **Approve & open run** authorises this one request and takes you to the run so you can watch it execute and see its result handed back to the agent.
- **Reject** skips it. The agent is told it was rejected and carries on with something else.
- **Do nothing**: after the approval timeout the request is rejected automatically. The default is 15 minutes; an admin can change it under **Settings → Manual approval timeout (global default)**, and each campaign can override it with **Manual approval timeout (campaign override)**.

There is one popup per request; if several are pending they queue and appear one after another.

## What your click authorises

- **Exactly that stored request, once.** Not the tool in general, not later requests of the same kind.
- It is **checked again** by the Scope Gateway at the moment it runs, against the current scope, window and grants. If the scope changed in the meantime, or the engagement is no longer active, it is denied even though you approved it.
- It is **recorded**: the proposal, your decision and the execution are all in the [audit log](../reference/audit.md).
- If the run is stopped while a request waits, the approval is closed with it and the request is never sent.

## Reduce the interruptions

If you are asked more often than you want, the cause is almost always a tool marked for approval. In the wizard the tools of the `vuln`, `cred` and `exploit` categories are pre-selected, and a scan makes many nuclei calls. Untick the tools you do not need to supervise. Keep approval on for anything that can change data. The agent's state-changing requests always ask, whatever you set.
