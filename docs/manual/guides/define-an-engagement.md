# Define an engagement and its scope

**Who this is for:** operators creating or changing an engagement.
**After this page you can:** write a scope that covers exactly what you are authorised to test, understand what each kind of scope row matches, and set up an engagement that follows a bug-bounty program.

<!-- ui-labels: New engagement | Parties and test window | Emergency contact | Authorized from | Authorized until | Scope assets | Add scope row | active | authorization attested | Edit engagement | Remove | This engagement follows a bug bounty program's rules of engagement | Platform | Program reference | Program terms explicitly permit automated (not only manual) testing | Max requests/second | Max concurrency | Identification header name (optional) | Identification header value (optional) | User-Agent suffix (optional) | Network (TCP SYN) scan tier | Raw scan packet rate cap, packets/second (optional) | Network-scan authorization evidence (required for the Full tier) -->

## Before you start

Have these ready. Axial cannot judge whether you are *allowed* to test something; it enforces what you tell it, so what you tell it has to be right.

- **Written authorisation** from the owner of every target, or proof that the target invites testing (your own domain, a program's published scope, a practice platform). [Safety, legal and limits](../safety-legal-limits.md) and [`docs/legal.md`](../../legal.md) list the prerequisites.
- **An exact scope**: domains and address ranges, not "the whole company".
- **A test window** and **someone to call** if a test causes trouble.
- **Exclusions**: anything that must not be touched, even if it sits inside an allowed domain.

## Create the draft

Choose **New engagement** and fill the first step, **Parties and test window**: a title, the **Emergency contact**, **Authorized from** and **Authorized until**. Leave the port range at its default (all TCP ports) unless the authorisation limits you to fewer; use the same number twice to allow a single port. This range is the outer limit for every target and can only be changed while the engagement is a draft. The other settings are explained in the [wizard reference](../reference/wizard.md).

## Write the scope

On the **Scope** step, add one row per thing you are allowed to test. Every row has a rule, a type and a value.

| Type | Value looks like | Matches |
|---|---|---|
| `domain` | `example.com` | the domain itself **and every subdomain** of it |
| `wildcard` | `*.example.com` or `staging*` | names that fit the pattern. `*.example.com` covers subdomains but **not** `example.com` itself |
| `ip` | `203.0.113.7` | that one IPv4 address |
| `cidr` | `203.0.113.0/28` | every IPv4 address in that range. At most 65,536 addresses (a /16) |
| `cloud_account` | an account identifier | exactly that string, nothing else |

Three rules to remember:

1. **Deny always wins.** A `deny` row beats any `allow` row that also matches. Use it for exclusions: allow `example.com`, deny `legacy.example.com`.
2. **Nothing is allowed by default.** A name or address that no allow row matches is out of scope and receives nothing, including names that discovery finds.
3. **Values are cleaned.** Domains are lower-cased, a trailing dot is dropped, and addresses are rewritten to their canonical form. Do not enter a URL, a path or an email address; they are rejected. IPv6 is not supported and is rejected with a message.

Two ticks control what may be done to an allow row:

- **active**: the scan may send requests to it. Without it the target can only be looked at passively (public records).
- **authorization attested**: you confirm that you are permitted to test it. Active checks need this for every active allow row; see [Authorize and activate](authorize-and-activate.md).

Each row can also carry its own port range. Leave it blank to inherit the engagement's range; a row's range can only narrow it.

### Two things to know about IP ranges

- Host discovery inside a range only probes **TCP 80 and 443**, a deliberate, bounded policy. A host that answers on neither (for example one that offers only SSH) is not found by the sweep, and reads the same as a host that is not there. If you need such a host scanned, add it as its own `ip` row.
- The sweep itself is authorised against the range as a whole. The hosts it finds are then scanned one by one, and a deny row for any of them is respected.

### A worked example

You are authorised to test `example.com`, but `legacy.example.com` is run by another team and a range of one customer-facing server is in scope too:

| Rule | Type | Value | active | attested |
|---|---|---|---|---|
| allow | domain | `example.com` | yes | yes |
| deny | domain | `legacy.example.com` | | |
| allow | cidr | `203.0.113.0/28` | yes | yes |

`www.example.com` is scanned. `legacy.example.com` and its subdomains are not, even though they end in `example.com`. `203.0.113.5` is scanned; `203.0.113.200` is not. `example.net` is not, because nothing allows it.

## Change the scope later

On **Edit engagement → Scope assets** you can add and remove rows at any time. The Scope Gateway reads the scope on every call, so a change applies to the very next request: a new deny row stops the next call to that target, even in a run that is already going. Hosts you excluded in an asset review appear here as deny rows; remove one to include the host again in future scans.

An allow row that overlaps another **active** engagement's allow row is refused, so two engagements cannot both be responsible for the same host. The message tells you to resolve the conflict.

## Bug-bounty engagements

Use this only for a real bug-bounty or vulnerability-disclosure program that requires self-identification and a request-rate cap. In the wizard's **Tools** step, tick **This engagement follows a bug bounty program's rules of engagement**; on an existing engagement it is on the Edit page under **Bug bounty program policy**. Fill in:

| Field | What it does |
|---|---|
| **Platform** and **Program reference** | which program this is (for example the platform's name and the program's slug) |
| **Program terms explicitly permit automated (not only manual) testing** | if you do not tick it, every automated request is denied, so a scan cannot run. Tick it only if the program's terms really say so |
| **Max requests/second** and **Max concurrency** | the program's caps. They are enforced on every automated request, both in the Scope Gateway and in the egress proxy |
| **Identification header name / value** and **User-Agent suffix** | the identification the program requires. It is added to every automated web request by the egress proxy; the agent cannot set, omit or override it. Leave them blank if the program needs none |
| **Network (TCP SYN) scan tier** | *None* (the default) keeps discovery to the liveness sweep; *Common* also uses the engagement's port ranges; *Full* uses all 65,535 TCP ports |
| **Raw scan packet rate cap** | an optional ceiling in packets per second for the network scan |
| **Network-scan authorization evidence** | required for the *Full* tier: a quote or link from the program's own scope policy that explicitly permits full-port scanning. "Automated testing is permitted" is deliberately not enough |

A bug-bounty engagement needs its program policy before it can start: the pre-flight check says so otherwise. Web screenshots are not available when the program requires an identification header on every request.
