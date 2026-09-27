## Was & Warum

<!-- Kurz: was ändert dieser PR und warum? Verweis auf Kapitel/Issue. -->

## SDLC und Traceability (Pflicht)

- Anforderungs-IDs (`REQ-*`):
- Testfall-IDs (`TC-*`):
- Risikoklasse (`R0`–`R4`):
- [ ] Akzeptanzkriterien und Traceability sind aktuell.
- [ ] `make requirements-check` ist grün.
- [ ] Bei `R3`/`R4`: Threat-Model-Auswirkung, Negativtest und menschliches Security-Review dokumentiert.
- [ ] Rollout und Rollback sind beschrieben oder nicht erforderlich.

## Sicherheits-Check (Pflicht)

- [ ] Die Trennung „LLM schlägt vor / Gateway entscheidet" bleibt intakt.
- [ ] Kontrolle liegt weiterhin in DB-Zustand, nicht im Prompt.
- [ ] Das Gateway bleibt fail-closed (keine Prüfung abgeschwächt).
- [ ] Bei neuer aktiver Fähigkeit: Negativ-Test ergänzt.

## Tests

- [ ] `make test-unit` grün
- [ ] `make test-integration` grün
- [ ] `make frontend-build` grün
- [ ] Bei sicherheitsrelevanten Änderungen: `make lab-test` grün

## Notizen

<!-- Offene Punkte, Breaking Changes, Follow-ups. -->
