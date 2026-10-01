# Authorize and activate

**Who this is for:** operators finishing an engagement, and whoever has to sign the authorisation.
**After this page you can:** attest your authorisation, produce the document for signature, activate the engagement, and know what can still be changed afterwards.

<!-- ui-labels: Review authorization | Authorization checklist | Download authorization PDF | Activate engagement | Authorization not attested | Authorization PDF | authorization attested | Edit engagement -->

An engagement is a draft until you activate it, and only an active engagement can scan. Activation is where Axial checks that the engagement is complete, and where you record that you are permitted to run it.

## 1. Attest your authorisation

Every active allow row in the scope has the tick **authorization attested**. Ticking it means: *I am permitted to test this target.* Active checks are blocked for any active row that is not attested. You can tick it in the wizard, or later from the engagement page, which lists unattested rows under **Authorization not attested** with a button for each.

The attestation is a statement by you, kept with the row and in the audit log. It does not prove anything to Axial: the proof is the written authorisation you hold. Keep that with the engagement.

## 2. Produce the document for signature

In the wizard's last step, **Authorization checklist**, choose **Download authorization PDF**. It is also available any time from the **Authorization PDF** link on the engagement page. The PDF states exactly what is configured:

- the engagement and its emergency contact, and the authorised window;
- the authorised scope and, separately, everything explicitly denied;
- the tool permissions, and the concrete tools that need manual approval;
- the state of each discovery switch (enabled or disabled);
- a **configuration checksum** that identifies this exact configuration;
- the guardrails (every active call is authorised by the Scope Gateway; active checks are limited to allowed scope and the window; the default posture is non-destructive with bounded budgets);
- signature lines for the customer and for the operator.

Have it signed by whoever is entitled to authorise the testing, and keep the signed copy. The PDF is generated from the **current** configuration each time, so download it again after you change the scope or the tools, and check that the checksum matches what was signed.

## 3. Activate

Choose **Activate engagement**. Activation refuses, and says which condition is unmet, if:

- there is no allow row at all, or an active allow row is not attested;
- the test window is missing, or ends before it starts;
- a bug-bounty engagement has no program policy yet;
- the scope overlaps another **active** engagement's scope (any owner), so two engagements cannot be responsible for the same host; the refusal names that engagement and its owner, so you know whom to ask;
- for an engagement of the customer type, the signed scope document has not been recorded.

If everything passes, the engagement becomes `active` and opens on its page. Activation does not start a scan; you do that with **Start run**, see [Start and watch a scan](run-a-scan.md). A scan also needs an active tool grant, and it can only run inside the test window.

You can also activate a draft from its own page, for example when the wizard was not finished.

## After activation

Most things can still change, and each change is recorded:

| Can change | Applies | Note |
|---|---|---|
| Scope rows (add, remove) | from the next request | a new deny row stops the next call |
| Tool grants | from the next tool call | adding an active category asks for confirmation, and nothing can be added while a scan runs |
| Tool switches, approval flags | from the next call | [Control which tools run](control-which-tools-run.md) |
| Discovery extras, scan depth | from the next scan | |
| Title, contact, window, agent switch | immediately | extend a window before it ends, not after |
| Port range and UDP discovery | **not at all** | only while the engagement is a draft; the signed network envelope of the raw scan is built from them |

If the scope or the tools change materially after signing, generate a new PDF and have it signed again.
