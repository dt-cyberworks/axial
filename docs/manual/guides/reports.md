# Reports

**Who this is for:** operators and consultants who hand results to a customer or a manager.
**After this page you can:** generate the PDF report, say what is in it and what deliberately is not, and read its coverage section.

<!-- ui-labels: Runs & reports | Reports | Generate report | Download PDF | Authorization PDF | Covers run | no completed run | Explain with Lens Agent -->

## Generate a report

Open the engagement, choose the **Runs & reports** tab and, under **Reports**, choose **Generate report**. When it is ready it appears in the list with when it was generated (**Generated**), which run it covers (**Covers run**), its status and its size. Choose **Download PDF**. A report covers the latest run that has **ended** (`done`, `aborted` or `failed`; a run still in progress is never used, because its findings are mid-flight). If there is none, the list says *no completed run*, and a report of an engagement that has never run a scan has little to say.

Generating a report does not start a scan and never calls an AI provider.

## What is in it

A styled PDF with a cover page and five sections:

1. **Executive summary.** An overall risk signal, the trend against the previous run, and the three actions that matter most.
2. **Risk overview.** The number of findings by severity, and what is new, resolved or persisting since the previous run.
3. **Detailed findings.** For each finding: what it is, where it is, the proof and what to do about it. If the finding has an explanation from the Lens Agent, it is included.
4. **Asset inventory.** What was discovered: hosts, services and hints of assets nobody listed.
5. **Methodology and scope.** What was authorised: scope, window, exclusions and authorisation. This is the section a client or an insurer reads to see that the testing was inside its mandate.

A **coverage** part states what the run did *not* do: checks that stopped at their time budget, failed, or were skipped, each with the reason in plain words. It is there so that a reader does not mistake a short findings list for a clean result.

## What is deliberately not in it

- **Raw tool output.** The report summarises redacted evidence fields and says where the full evidence lives; it never pastes raw requests or responses. Secret values are redacted before anything is written.
- **Screenshots.** A page can contain personal data, so screenshots stay on the **Assets** tab and out of the PDF.
- **False positives**, except as a count. **Accepted risks** are listed in their own table, with your justification.
- **New AI text.** Only explanations that already exist are reused, so the report never depends on a provider being reachable and its cost and timing do not change when you press the button.

## Before you generate

1. **Triage first.** Mark false positives and give accepted risks a reason; the report reflects the current statuses.
2. **Explain the findings you want explained.** Open them and choose **Explain with Lens Agent**; see [Triage findings](triage-findings.md). An unexplained finding shows its structured facts instead.
3. **Check coverage.** If the run carries **partial coverage** or **reduced coverage**, decide whether to rerun it before you send the report.
4. **Run again after fixes** to show improvement; see [Compare runs](compare-runs.md).

## The authorisation PDF is a different document

The **Authorization PDF** on the engagement page states what was *agreed*: scope, window, tools and signature lines, for signature before the scan. The report states what was *found*. See [Authorize and activate](authorize-and-activate.md).

## Handle it with care

A report names the targets, their weaknesses and how to reach them. Treat it as confidential, send it only to the people entitled to it, and keep it with the written authorisation for the same engagement.
