# ASM-Scanner — Entwickler-Kommandos.
# Details zu den Stufen (M1–M6): README.md und docs/testing.md.

.PHONY: help up down logs test test-unit test-integration lab-up lab-down \
        lab-verify lab-test frontend-build frontend-requirements requirements-check \
        requirements-test traceability verify fmt scan uat-venv seed-uat-account uat \
        reference-scan

help:  ## Diese Hilfe anzeigen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# --- Scanner-Stack (M1: lab / M2–M3: own_domain) ---
up:  ## Scanner-Stack starten (control-plane, worker, egress-proxy, DB)
	docker compose up -d --build

down:  ## Scanner-Stack stoppen und Volumes entfernen
	docker compose down -v

logs:  ## Logs des Scanner-Stacks folgen
	docker compose logs -f

bootstrap-admin:  ## First admin account (REQ-IAM-008/011; needs INITIAL_ADMIN_EMAIL set)
	docker compose exec control-plane python scripts/bootstrap_admin.py

# --- Requirements as code / SDLC ---
requirements-check:  ## Requirements, test cases, and generated traceability validate
	python3 scripts/requirements_pipeline.py check

requirements-test:  ## Unit tests for the requirements pipeline
	python3 -m pytest scripts/tests -q

traceability:  ## Requirements-to-tests matrix regenerate
	python3 scripts/requirements_pipeline.py generate

# --- Tests ---
test: test-unit test-integration  ## Alle Tests (Unit + Integration)

test-unit:  ## Reine Logik-Tests (ohne DB/Infra)
	cd control-plane && python -m pytest tests -q --ignore=tests/integration

test-integration:  ## Gateway-Integrationstests gegen Postgres (TEST_DATABASE_URL nötig)
	cd control-plane && python -m pytest tests/integration -q

# --- Lab-Testloop (ASM_Lab_Umgebung.docx) ---
lab-up:  ## Verwundbare Lab-Ziele starten (isoliertes Netz)
	docker compose -f lab/lab-compose.yml up -d

lab-down:  ## Lab-Ziele stoppen
	docker compose -f lab/lab-compose.yml down -v

lab-verify:  ## Isolations-Checks (Pflicht vor jedem Lab-Einsatz)
	bash lab/verify-isolation.sh

lab-test:  ## Vollständiger Lab-Testloop: Isolation + Scope-Durchsetzung + Orakel
	bash lab/run-lab-test.sh

# --- Supply chain (REQ-SUPPLY-001/002) ---
scan:  ## Supply-chain scan: image-pin guard + Trivy (deps/secrets + Dockerfile/compose misconfig)
	PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest scripts/tests/test_image_pinning.py -q
	trivy fs --scanners vuln,secret --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 .
	trivy config --severity HIGH,CRITICAL --ignorefile .trivyignore.yaml --exit-code 1 .

# --- Frontend ---
frontend-build:  ## Operator-Konsole bauen (Typecheck + Vite)
	cd frontend && npm ci && npm run build

frontend-requirements:  ## Executable requirement tests for the operator console
	cd frontend && npm run test:requirements

verify: requirements-check requirements-test test frontend-requirements frontend-build  ## Full local SDLC verification (DB required)

# --- User-acceptance testing (REQ-UAT-001..004) ---
uat-venv:  ## One-time venv for the UAT harness (Playwright/pyotp/httpx; needs system Chrome/Chromium)
	python3 -m venv uat/.venv
	uat/.venv/bin/pip install -q -r uat/requirements.txt

seed-uat-account:  ## Idempotent UAT service-account creation inside control-plane (needs UAT_ACCOUNT_EMAIL)
	docker compose exec control-plane python scripts/seed_uat_account.py

uat:  ## Run UAT against ENV=dev|int|prod (golden path; +scan journey for int/prod). See uat/environments.py.
	uat/.venv/bin/python uat/run_uat.py --env $(ENV)

reference-scan:  ## On-demand reference scan against pentest-ground.com:4280 (REQ-REFSCAN-001); default ENV=dev. Not part of `make uat`/CI.
	uat/.venv/bin/python uat/reference_scan.py --env $(or $(ENV),dev)

