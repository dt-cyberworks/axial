# Triage findings

**Who this is for:** operators working through what a scan found.
**After this page you can:** read a finding and its evidence, get a plain-language explanation, give every finding a status with a reason, and know how your decisions behave in later scans and in the report.

<!-- ui-labels: Findings | Open | Accepted risk | False positive | Resolved | All severities | Triage | Mark resolved | Accept risk… | Mark false positive… | Reopen | Lens Agent analysis | Explain with Lens Agent | Show Lens analysis | Evidence | Open in engagement → | Click for evidence and explanation | Click for evidence, explanation, and triage | Select all findings in this view | Clear selection | Mark resolved… | Reopen… | Undo -->

## Where findings are

- On an engagement: the **Findings** tab, which opens first. It lists the engagement's findings, accumulated and de-duplicated across all its runs.
- Across engagements: **Findings** in the navigation, which lists findings from every engagement you can see, most severe first. See [Overview and All findings](../reference/overview.md).

Both have one tab per status, **Open**, **Accepted risk**, **False positive** and **Resolved**, each with its count, and a severity filter (**All severities**, or one severity). On **Open**, each severity shows how many open findings it has. The tab and an open finding are part of the page address, so you can link a colleague straight to one.

## Read a finding

![An opened finding: Lens Agent analysis, triage buttons, facts and evidence](../img/finding-detail.png)

Click a row (**Click for evidence and explanation**) to expand it. You see:

| Field | Meaning |
|---|---|
| Severity and score | the 0 to 100 risk score and the severity it maps to; see [Concepts](../concepts.md#risk-score-and-severity) |
| Confidence | **validated** (the weakness was demonstrated) or **inferred** (reasoned from a banner or context). Treat inferred findings as leads to confirm |
| **Target**, **Asset type**, **Service** | where it was found |
| **Evidence location** and **Detected by** | which tool, and where the proof is |
| **CVEs** and **CVSS / EPSS** | the public vulnerability data, where there is any |
| **Raw reference** and **Finding ID** | identifiers for tickets and audits |
| **Evidence** | the recorded proof: the fields the tool returned, with secret values redacted. If none was attached it says so |

*Found on*, *First seen* and *Last seen* tell you whether this is new or has been there since the first scan.

## Get an explanation

Choose **Explain with Lens Agent** (it needs an AI provider; see [Configure the AI provider](configure-the-llm.md)). Asking is for the engagement's owner and administrators; on someone else's engagement you can read an explanation that already exists, but not request one. The **Lens Agent analysis** explains in plain language what the finding is, what it could mean for you and how to fix it, using only the evidence that was recorded. Once generated it is kept; **Show Lens analysis** shows it again. If the provider cut the answer off, the page says so and some sections may be missing. A report includes an explanation only if one was already generated, so explain the findings you want in the report *before* you generate it; see [Reports](reports.md).

## Decide what to do

Under **Triage**, the engagement's owner or an administrator chooses one. On someone else's engagement you see the status, who set it and why, but not the buttons; ask the owner.

| Action | Status | Reason required? | Use it when |
|---|---|---|---|
| **Mark resolved** | Resolved | no | it has been fixed |
| **Accept risk…** | Accepted risk | **yes** | it is real and you decided to live with it |
| **Mark false positive…** | False positive | **yes** | the tool was wrong; nothing is there |
| **Reopen** | Open | no | you changed your mind, or it came back |

The two that ask *why* need a reason of at least 3 characters (up to 1,000), because a decision that removes a finding from the open list has to say why, and that reason is what a reader of the report sees. Write a real sentence. The finding then shows who changed its status, when, and the reason, and every change is written to the audit log.

## Confirm that a fix worked

Under **Retest**, the owner or an administrator can press **Retest this finding** on an open finding. It runs only the check that found it, on its host, after you have seen on **Review before you run** what that is; the finding becomes **Resolved** only if that check ran to the end and did not see it again. See [Retest and run only what is open](retest-and-open-items.md).

## Triage many findings at once

![Three findings ticked in the list, with the bulk bar and its confirmation](../img/findings-bulk-triage.png)

The same finding is usually reported once per host and per port, so one judgement may apply to dozens of findings. Instead of repeating it, tick them in the list:

1. On the **Findings** tab, tick the rows you want, or the box in the header (**Select all findings in this view**) for every row of the tab and severity filter you are looking at. In a finding's detail, **Select this and the N other findings with the same title** ticks the others that carry exactly that title.
2. A bar appears with the actions that fit the tab: on **Open**, **Mark false positive…**, **Accept risk…** and **Mark resolved…**; on the other tabs, **Reopen…**.
3. Choose one. The bar states how many findings will change. For a false positive or an accepted risk write the reason once (at least 3 characters); it is stored with each finding.
4. **Apply** changes them. **Undo**, shown right afterwards, puts back exactly what that one action changed.

What a bulk change is, and is not:

- **Each finding is changed on its own.** It gets its own status, reason, time and operator and its own audit entry; the entries of one action share an identifier so the audit log shows they were one decision.
- **It applies to those findings only.** There is no rule behind it: the same vulnerability on a host that is not in the list is still reported as open. Only that vulnerability on that host stays out of the open list, and it does not come back on later runs (see below).
- **It is all or nothing.** If any selected finding is not found, nothing changes. One action covers up to 500 findings.
- **Undo does not overwrite later decisions.** A finding that was changed again since (by you, or by a scan that reopened it) is left as it is, and the message says how many were skipped. An action can be undone once.
- Only the engagement's owner and administrators see the tick boxes.

## What happens in later scans

Findings are matched across scans by a fingerprint, so a finding is never duplicated. Your decision survives:

- An **accepted risk** or **false positive** that is seen again stays as you set it.
- A **resolved** finding that is seen again is **reopened automatically**: it is a regression, and you should know.
- A finding no longer seen is simply not observed in that run; see [Compare runs](compare-runs.md) for what that does and does not prove.

## In the report

Open findings are listed in full. **Accepted risks** get their own table with your justification. **False positives** are only counted, not listed. The risk overview shows what is new, what was resolved and what persists since the previous run.

## A sensible routine

1. Start with **Open**, most severe first.
2. For each: read the evidence, ask the Lens Agent if the cause is not obvious, then triage it.
3. Do not mark something *resolved* until a later run no longer sees it; rescan to confirm.
4. If a run showed **partial coverage** or **reduced coverage**, an empty or short list is not a finding that nothing is wrong. See [Troubleshooting](../troubleshooting.md#why-a-run-stopped).
