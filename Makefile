# ASM-Scanner — Entwickler-Kommandos.
# Details zu den Stufen (M1–M6): README.md und docs/testing.md.

.PHONY: help up down logs test test-unit test-integration lab-up lab-down \
        lab-verify lab-test frontend-build frontend-requirements requirements-check \
        requirements-test traceability verify fmt scan uat-venv seed-uat-account uat \
        reference-scan

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# --- Scanner-Stack (M1: lab / M2–M3: own_domain) ---
up:  ## Start the scanner stack (control-plane, worker, egress-proxy, database)
	docker compose up -d --build

down:  ## Stop the stack and DELETE its volumes - all engagements and findings are lost
	docker compose down -v

logs:  ## Follow the scanner stack's logs
	docker compose logs -f

bootstrap-admin:  ## First admin account (REQ-IAM-008/011; needs INITIAL_ADMIN_EMAIL set)
	docker compose exec control-plane python scripts/bootstrap_admin.py

# --- Requirements as code / SDLC ---
requirements-check:  ## Validate requirements, test cases, and the generated traceability matrix
	python3 scripts/requirements_pipeline.py check

requirements-test:  ## Unit tests for the requirements pipeline
	python3 -m pytest scripts/tests -q

traceability:  ## Regenerate the requirements-to-tests matrix
	python3 scripts/requirements_pipeline.py generate

# --- Tests ---
test: test-unit test-integration  ## All control-plane tests (unit + integration)

test-unit:  ## Unit tests (no database or other infrastructure)
	cd control-plane && python -m pytest tests -q --ignore=tests/integration

test-integration:  ## Integration tests against Postgres (needs TEST_DATABASE_URL)
	cd control-plane && python -m pytest tests/integration -q

# --- Lab-Testloop (ASM_Lab_Umgebung.docx) ---
lab-up:  ## Start the deliberately vulnerable lab targets (isolated network)
	docker compose -f lab/lab-compose.yml up -d

lab-down:  ## Stop the lab targets
	docker compose -f lab/lab-compose.yml down -v

lab-verify:  ## Isolation checks - mandatory before every lab use
	bash lab/verify-isolation.sh

lab-test:  ## Full lab test loop (isolation, scope enforcement, oracle); tears the main stack down incl. volumes unless KEEP_UP=1
	bash lab/run-lab-test.sh

# --- Supply chain (REQ-SUPPLY-001/002) ---
scan:  ## Supply-chain scan: image-pin guard + Trivy (deps/secrets + Dockerfile/compose misconfig)
	PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest scripts/tests/test_image_pinning.py -q
	trivy fs --scanners vuln,secret --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 .
	trivy config --severity HIGH,CRITICAL --ignorefile .trivyignore.yaml --exit-code 1 .

# --- Frontend ---
frontend-build:  ## Build the operator console (typecheck + Vite)
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

