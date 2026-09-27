# Change Risk Classification

Use the highest applicable class.

- `R0`: no runtime behavior changes.
- `R1`: bounded application behavior with no trust-boundary or persistence
  effect.
- `R2`: API contracts, database state, background orchestration, or material
  availability effects.
- `R3`: authentication, authorization, scope, audit, secrets, egress, runner
  execution, customer isolation, or security policy.
- `R4`: a new active/offensive capability, wider target access, destructive
  behavior, credential attacks, or material legal/contractual exposure.

Record the class in requirement front matter and in the pull request. If a
change spans several requirements, use the highest risk.

