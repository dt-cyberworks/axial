# Test behind a login

**Who this is for:** the owner of an engagement, or an administrator, who wants the Vector Agent to test what sits behind a login.
**After this page you can:** enter a dedicated test account, assign it to the hosts it is valid on, give a monitor the one consent it needs, and read what became of the logins.

<!-- ui-labels: Test accounts | Add a test account | Save account | Replace secret | Edit hosts | Resume | Delete | Select all shown | Login consent | Give login consent | Revoke login consent | Can be used on | Cannot be used on | Hosts this account is valid on -->

## The idea

Most real applications keep their interesting functions behind a login, and a scan that never logs in reports a clean-looking surface for everything behind it. A **test account** lets the Vector Agent log in. You create the account at the target, enter it into the engagement and **assign it to specific hosts**. It is bound to those hosts only: the Scope Gateway refuses to let it be used anywhere else, in any tool but a plain HTTP request, or in any request but its own login (for a password).

This is not the default-credential check. Axial never guesses a password; you supply an account you are entitled to use.

## Before you start

- Create a **dedicated test account** at the target. Not a person's account, not the administrator you use every day, **without a second factor** (the agent cannot answer a code), with the least rights that still reach what you want tested. For an access-control test, create a second account with a different role.
- The account is sent to the **language-model provider** with every request of a run, because the agent reads it to log in. That is the cost of letting the agent do the login itself. A dedicated, low-rights account keeps it small. Disable the account at the target when the engagement ends; Axial erases its copy. Nothing Axial keeps holds the password: not the database, the audit trail, a report, a log of any service (the tool runner's included, which masks it and every session cookie), or the queue.
- An administrator must have set the encryption key for test accounts (`make env` creates it). Without it the page says so and nothing can be saved.

## Enter an account

1. Open the engagement and choose the **Test accounts** tab, then **Add a test account**.
2. Give it a **label** (letters, digits, `-` and `_`), a **role** (for example `user` or `admin`) and how the target logs in: a login form, a JSON login, HTTP Basic, or a bearer or API-key header.
3. For a login form or JSON login, give the **login path** (for example `/login`). The login is a `POST` to exactly that path. If one host logs in somewhere else, give that host its own path in the host list.
4. Enter the username and the password or token. The password field is write-only: it is never shown again, not even to you.
5. Tick the **hosts this account is valid on**. The list is the hosts the engagement knows or covers. A host held for review, blocked by a deny rule or flagged as a possible subdomain takeover can be ticked in advance but is not used until the cause is gone. **Select all shown** ticks the hosts listed now and nothing found later.
6. Confirm that it is a dedicated test account you are entitled to use on those hosts, and save.

A host that is discovered or added to the scope **after** this gets no credential until you assign it. That is on purpose.

## What the agent is told

At the start of a run the agent receives the account and, for each account, two lists in plain words: **Can be used on** and **Cannot be used on**, with the reason for each host (not assigned, held for review, blocked by a deny rule, possible subdomain takeover, suspended after rejected logins). You see the same two lists under the account. The Scope Gateway enforces them on every request, so a host that becomes held in the middle of a run is refused even though the agent's list was drawn earlier.

## Assessments and monitors

- **In an assessment** the login is a `POST`, so it waits for your approval like every request that changes data. The approval shows the account's name, never its password.
- **A monitor logs in without anyone watching**, so you give one consent when you approve the monitor, instead of answering per run. The **Login consent** block lists exactly which account logs in on which host and with which login path, and covers those and nothing else. After the login the monitor stays read-only: it does not change data through the session. Activating a monitor whose accounts are not covered is refused. If you assign a further host to an account of an active monitor, tick the consent in the same action, or that host gets no login. You can revoke the consent at any time; it takes effect on the next call.

## When a login fails

- The platform tries a login at most **twice per host in a run** and never again after the target rejected it, so a wrong password cannot lock the customer's account.
- After **two runs in a row** in which the login on a host was rejected, the account is **suspended on that host**. It shows under the account. Replace the secret or choose **Resume** once you have fixed it at the target.
- A run in which a login was rejected, or an account never got a session, is marked **reduced coverage** with the reason *authenticated coverage lost*. It is never presented as a clean result, and the report says which accounts were tested on which hosts and which were not. A monitor also records a *Login lost* and *Login regained* change.

## When the engagement ends

Closing or revoking the engagement, deleting it, or the end of its authorized window erases the encrypted secret and revokes the consent. The accounts stay listed as *erased* so the history shows what was used. Disable the account at the target too.

## What this does not do

It does not guess passwords, does not handle two-factor, single sign-on or OAuth, and does not carry the session into the deterministic tools (nuclei, ffuf, the crawler). A password the agent hand-encodes in a way Axial does not recognize cannot be searched for; the field-name redaction of the audit trail still applies. See [Safety, legal limits and what to expect](../safety-legal-limits.md).
