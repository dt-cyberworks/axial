# Axial - developer and operator commands. Run `make help` for the list.
# Details on the test tiers: README.md and docs/testing.md.
#
# REQ-INSTALL-006: every target in THIS file works from a clean public
# checkout. Targets that need the private test harnesses (lab, UAT, reference
# scan, screenshot generation) live in Makefile.private, which is not part of
# the public export and is included below only when present.

.PHONY: help env up down logs bootstrap-admin scope-check install-smoke \
        test test-unit test-integration frontend-build frontend-requirements \
        requirements-check requirements-test traceability manual-check verify scan

help:  ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# --- Scanner stack ---
env:  ## Create or complete .env for local evaluation (generates the encryption keys; never overwrites a set value)
	python3 scripts/init_dev_env.py

up: env  ## Start the scanner stack (control-plane, worker, egress-proxy, database) and wait until the API answers
	docker compose up -d --build
	@bash scripts/wait_for_api.sh

# The runner and oob profiles are named on purpose: a plain `docker compose down` does not include
# the services in a profile, so tool-runner and raw-egress-gateway kept running (REQ-INSTALL-001).
down:  ## Stop the stack and DELETE its volumes - all engagements and findings are lost
	docker compose --profile runner --profile oob down -v

logs:  ## Follow the scanner stack's logs
	docker compose logs -f

bootstrap-admin:  ## First admin account (REQ-IAM-008/011; needs INITIAL_ADMIN_EMAIL set)
	@test -n "$$INITIAL_ADMIN_EMAIL" || { echo "set INITIAL_ADMIN_EMAIL, e.g. INITIAL_ADMIN_EMAIL=you@example.com make bootstrap-admin" >&2; exit 1; }
	docker compose exec -e INITIAL_ADMIN_EMAIL="$$INITIAL_ADMIN_EMAIL" -e INITIAL_ADMIN_DISPLAY_NAME="$$INITIAL_ADMIN_DISPLAY_NAME" control-plane python scripts/bootstrap_admin.py

# REQ-INSTALL-006: the pre-scan safety check that needs no lab. It runs the Scope
# Gateway's deny-path tests (scope matching, argument safety, raw-egress policy,
# rate window) inside the built control-plane image: no database, nothing started.
scope-check:  ## Prove the Scope Gateway denies out-of-scope targets and unsafe arguments (runs in the image; no lab needed)
	docker compose run --rm --no-deps -T -v "$(CURDIR)/control-plane/tests:/app/tests:ro" \
	  -e PYTHONDONTWRITEBYTECODE=1 control-plane python -m pytest -p no:cacheprovider -q \
	  tests/test_scope_matching.py tests/test_args_safety.py tests/test_raw_egress_policy.py tests/test_rate_window.py

# REQ-INSTALL-001/008: follow INSTALL.md from a fresh checkout and fail on the first step that
# does not work. STAGE=local|production|all (default all). Meant for a throwaway host or CI runner.
install-smoke:  ## Follow the install guide end to end on a copy of the tree (STAGE=local|production|all); needs free ports; removes only its own containers
	bash scripts/install_smoke.sh $(or $(STAGE),all)

# --- Requirements as code / SDLC ---
requirements-check:  ## Validate requirements, test cases, and the generated traceability matrix
	python3 scripts/requirements_pipeline.py check

requirements-test:  ## Unit tests for the requirements pipeline
	python3 -m pytest scripts/tests -q

traceability:  ## Regenerate the requirements-to-tests matrix
	python3 scripts/requirements_pipeline.py generate

# --- User manual (REQ-MANUAL-001..006) ---
manual-check:  ## Check docs/manual: links, anchors, UI labels, codes, images, no private data (standard library only)
	python3 scripts/check_manual.py

# --- Tests ---
test: test-unit test-integration  ## All control-plane tests (unit + integration)

test-unit:  ## Unit tests (no database or other infrastructure)
	cd control-plane && python -m pytest tests -q --ignore=tests/integration

test-integration:  ## Integration tests against Postgres (needs TEST_DATABASE_URL)
	cd control-plane && python -m pytest tests/integration -q

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

verify: requirements-check manual-check requirements-test test frontend-requirements frontend-build  ## Full local SDLC verification (DB required)

# Private-checkout-only targets (lab, UAT, reference scan, manual screenshots).
-include Makefile.private
