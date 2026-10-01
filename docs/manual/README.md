# Axial user manual

**Who this is for:** anyone who will use, install, review or sign off on Axial: operators who run scans, admins who look after the installation, and security or legal reviewers who want to know what it does before they allow it.
**After this page you can:** tell what Axial is and is not, find the page you need, and start with the right chapter.

## What Axial does

Most organisations do not know everything they have on the internet: forgotten subdomains, an old admin page, a test server that was never switched off. Axial finds that out, and reports it, **without ever touching anything you have not authorised**.

You describe an *engagement*: what you may test (the scope), when (the test window) and with which kinds of tools. Axial then runs a *scan*:

1. It finds the hosts and services that belong to your scope.
2. It looks at what runs on them and checks them with a fixed set of conservative, non-destructive tests.
3. It compares what it found with public vulnerability data.
4. Optionally, an AI model suggests further checks. It can only *suggest*. A deterministic gatekeeper, the **Scope Gateway**, decides every single action, and anything that could change data on the target waits for your explicit approval.

The result is a list of **findings** with evidence, a risk score, a comparison with the previous scan and a PDF report. Everything the system did is recorded in a tamper-evident audit log.

## What Axial is not

Axial is an attack-surface scanner with a strict safety model. It is not a replacement for a manual penetration test, it does not exploit systems, and it does not scan anything you have not put in scope. [Safety, legal and limits](safety-legal-limits.md) says plainly what it covers and what it does not.

## Where to start

| You want to | Read |
|---|---|
| Try it, from nothing to a first report | [Quickstart](quickstart.md) |
| Understand the ideas every screen builds on | [Concepts](concepts.md) |
| Do one specific job | [Guides](guides/README.md) |
| Look up a screen, a tab or a field | [Screen reference](reference/README.md) |
| Know what each scanning tool does and why | [Tools](tools.md) |
| Install, back up, upgrade, harden | [Operations](operations.md) |
| Decide whether you may run it, and what it cannot do | [Safety, legal and limits](safety-legal-limits.md) |
| Work out why something is blocked or failed | [Troubleshooting](troubleshooting.md) |
| Check a word | [Glossary](glossary.md) |

## Conventions

- Names you see on screen are written in **bold**, exactly as the console shows them.
- Things you type, addresses and codes are written in `monospace`.
- *Admin* marks a screen or action that only administrators can use.
- Every page begins with who it is for and what you will be able to do afterwards.
- Screenshots come from a throwaway installation filled with invented demo data: a company called Example Corp, hosts under `example.com`, addresses in the documentation range `203.0.113.0/24`. None is from a real installation.

## Other documentation

This manual is for people who use Axial. The developer and security documentation lives next to it and is linked where it helps:

- [`INSTALL.md`](../../INSTALL.md): installation step by step.
- [`docs/security-model.md`](../security-model.md): how the Scope Gateway and the isolation work.
- [`docs/security/tool-catalog.md`](../security/tool-catalog.md): the exact command line of every tool, for security researchers.
- [`docs/legal.md`](../legal.md): the legal prerequisites before the first scan.
- [`docs/api.md`](../api.md): the REST and live-stream contracts.
