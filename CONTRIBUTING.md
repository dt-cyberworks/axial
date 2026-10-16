# Contributing

Thanks for your interest. This project is licensed under AGPL-3.0 (see
[LICENSE](LICENSE)) — contributions are welcome. The conventions below apply
to every change.

## How a change is made

1. **Describe the behaviour change** in the pull request: what is different
   for an operator, and why.
2. **Classify the risk** (table below).
3. **Add tests that verify the behaviour directly.** For anything
   security-relevant, a negative test comes first: it proves the thing that must
   not happen does not happen.
4. **Run the gates** and keep them green:

```bash
make verify               # manual check, script tests, control-plane tests, frontend tests and build (needs Postgres)
```

Security-sensitive `R3`/`R4` changes require negative tests and human security
review. Automated agents cannot approve their own SDLC exceptions or weaken a
requirement or test to make a gate pass.

### Risk classes

| Risk | Typical change | Minimum verification |
|---|---|---|
| `R0` | Comments, copy, non-functional formatting | Relevant static check |
| `R1` | Normal UI or isolated application behavior | Unit tests and build |
| `R2` | API, persistence, worker orchestration | Unit and integration tests; migration/rollback assessment |
| `R3` | Scope Gateway, auth, audit, runner, proxy, secrets | Threat-model assessment, positive and negative tests, integration gates, security-owner review |
| `R4` | New active capability, widened egress, destructive potential | Explicit human authorization, security review, isolated validation, staged release |

A change may be classified upward at any time. Downgrading an `R3` or `R4`
change requires a documented human decision.

## Ground rules

1. **The security layer is not negotiable.** Changes must not weaken the
   separation "the LLM proposes / the gateway decides." Control lives in DB
   state, never in the prompt. See
   [docs/security-model.md](docs/security-model.md).
2. **Fail-closed stays fail-closed.** New gateway checks extend the chain,
   they never weaken it.
3. **Every new active capability needs its test first** — especially a
   negative test (see [docs/testing.md](docs/testing.md)).

## Development environment

```bash
# Backend
cd control-plane && python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# Frontend
cd frontend && npm install
```

## Before every commit

```bash
make test-unit          # must be green (no infra needed)
make test-integration   # against local Postgres (TEST_DATABASE_URL)
make frontend-build     # typecheck + build
```

For security-relevant changes, also run `make scope-check`, which proves the
Scope Gateway denies out-of-scope targets and unsafe arguments.

## Code conventions

- **Python**: type annotations, docstrings referencing the relevant
  specification chapter (`docs/spec/…`), no tool execution outside the
  gateway path.
- **TypeScript**: `strict`; the UI is a pure API client and **not** a
  security boundary — every check happens server-side.
- **Commits**: short, imperative subject line; reference the chapter/issue
  in the body.

## Adding a new tool to the allowlist

Every addition of an active/offensive tool is a deliberate decision that
needs maintainer review — never a casual `apt install`.
Process:

1. Add the tool to
   [`tool-runner/runner.Dockerfile`](tool-runner/runner.Dockerfile) and
   check the build guard.
2. Extend the category `WHITELIST` in
   [`authorize.py`](control-plane/app/gateway/authorize.py).
3. Add argument hardening in
   [`args_safety.py`](control-plane/app/gateway/args_safety.py).
4. Add a test in `control-plane/tests/`.
