## What and why

<!-- What does this pull request change for an operator, and why? Link the issue. -->

## Risk

- Risk class (`R0`-`R4`, see CONTRIBUTING.md):
- [ ] For `R3`/`R4`: the effect on the threat model, a negative test and a human security review are described.
- [ ] Rollout and rollback are described, or not needed.

## Security check

- [ ] The split "the LLM proposes, the gateway decides" is intact.
- [ ] Control still lives in database state, not in the prompt.
- [ ] The gateway still fails closed (no check was weakened).
- [ ] For a new active capability: a negative test was added.

## Tests

- [ ] `make verify` is green
- [ ] For security-relevant changes: `make scope-check` is green

## Notes

<!-- Open points, breaking changes, follow-ups. -->
