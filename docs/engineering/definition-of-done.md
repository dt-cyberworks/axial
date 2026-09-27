# Definition of Done

- [ ] Requirement IDs and acceptance criteria are current.
- [ ] Risk is classified and required design/threat-model work is complete.
- [ ] Test-case records cover the affected requirements.
- [ ] Executable positive and negative tests exist where applicable.
- [ ] Models, schemas, migrations, APIs, worker, and UI remain aligned.
- [ ] Security invariants and trust boundaries remain intact.
- [ ] Documentation touchpoints in `AGENTS.md` are updated.
- [ ] `make requirements-check` passes.
- [ ] `make traceability` produces no diff.
- [ ] `make verify` passes.
- [ ] `make lab-test` passes for applicable `R3`/`R4` changes.
- [ ] A change to scan/detection/agent-dispatch behavior is verified with a
      real dev-environment run against the relevant deployed benchmark
      target(s) (`benchmark/cli.py seed --only <substr> && ... scan && ...
      score`, see `docs/requirements/benchmark-mvp.md`'s 2026-08-11
      addendum) - not only mocked unit/integration tests. Scope to the
      target(s) that exercise the changed capability; the full sweep is not
      required for a single-change verification.
- [ ] Deployment verification and rollback are documented.
- [ ] Required human review is complete.

