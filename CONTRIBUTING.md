# Contributing

Thanks for your interest. This project is licensed under AGPL-3.0 (see
[LICENSE](LICENSE)) — contributions are welcome. The conventions below apply
to every change.

## Mandatory SDLC

[`docs/engineering/sdlc.md`](docs/engineering/sdlc.md) is the binding source
for the development process. Non-trivial changes need a `REQ-*` requirement
in `docs/requirements/`, a risk classification, and linked `TC-*` test cases
in `docs/test-cases/`.

```bash
make requirements-check  # check schema and traceability
make traceability         # regenerate the matrix after changes
make verify               # full local gates (needs Postgres)
```

The traceability matrix is generated, never hand-edited. `R3`/`R4` changes
need negative tests and human security review.

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

For security-relevant changes, also run the full lab test loop:

```bash
make lab-test           # isolation + scope enforcement (hard gates)
```

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
needs a renewed legal/insurance review — never a casual `apt install`.
Process:

1. Add the tool to
   [`tool-runner/runner.Dockerfile`](tool-runner/runner.Dockerfile) and
   check the build guard.
2. Extend the category `WHITELIST` in
   [`authorize.py`](control-plane/app/gateway/authorize.py).
3. Add argument hardening in
   [`args_safety.py`](control-plane/app/gateway/args_safety.py).
4. Add a test in `control-plane/tests/`.
