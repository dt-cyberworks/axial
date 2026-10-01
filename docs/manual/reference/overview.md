# Overview and All findings

**Who this is for:** operators and admins starting their day in the console.
**After this page you can:** read the overview of your engagements, understand each column and status, and use the cross-engagement findings list to see what needs attention first.

<!-- ui-labels: Operator overview | Engagement queue | Engagements | Active scans | Agent armed | Needs setup | Authorized window | All findings | All severities | All engagements | Previous | Next | Open in engagement → | Create an engagement | Start with your first engagement -->

## Overview (`/`)

![The overview: the metric strip and the engagement queue](../img/overview.png)

The landing page lists every engagement you can see, with its status. Click an engagement to open its detail page. Operators see their own engagements; admins see all of them.

An empty installation shows **Start with your first engagement**, a short reminder that an engagement is one authorised assessment (what you may test, when, and with which tools), and a button, **Create an engagement**.

### The metric strip

| Metric | Counts |
|---|---|
| **Engagements** | all engagements |
| **Active scans** | engagements with a run in progress |
| **Agent armed** | engagements where the Vector Agent is switched on |
| **Needs setup** | engagements still in `draft` or `awaiting_signature` |

### The engagement queue

| Column | Meaning |
|---|---|
| **Engagement** | the title. Click it to open the engagement |
| Status | `draft` until you activate it, then `active`. Only an active engagement can scan. See [Concepts](../concepts.md#engagement) |
| Agent | whether autonomous Vector Agent proposals are enabled (opt-in) |
| **Authorized window** | the dates in which scanning is permitted. Outside it every tool call is denied, so a scan is blocked before it starts |
| Views | **Open** the engagement, **Edit** its settings, open its **Audit** trail, or **Delete** it |

Deleting an engagement removes its findings and scope. The audit trail is retained.

## All findings (`/findings`)

![All findings: status tabs, filters and findings from every engagement you can see](../img/all-findings.png)

Every finding from every engagement you can see, in one list, most severe first and then by risk score. It is the place to start the day. Open it with **Findings** in the navigation.

| Part | What it does |
|---|---|
| Status tabs | **Open**, **Accepted risk**, **False positive** and **Resolved**, each with its count; the same statuses as on an engagement's Findings tab |
| **Severity** | filters to one severity; **All severities** clears it |
| **Engagement** | filters to one engagement; **All engagements** clears it |
| **Search** | matches the finding's title or the target's name |
| Columns | **Severity**, **Finding**, **Engagement**, **Target** and **Last seen** |
| **Previous** and **Next** | 50 findings per page |

Click a row to open the same detail as on the engagement page: the Lens Agent explanation, triage (resolve, accept risk, false positive), the facts and the evidence. **Open in engagement →** jumps to the finding inside its engagement. See [Triage findings](../guides/triage-findings.md).

The filters are part of the page address, so you can bookmark a view or send it to a colleague. The server decides which findings you get: operators see only their own engagements' findings, admins see all. A search or engagement filter can never reveal another user's findings.
