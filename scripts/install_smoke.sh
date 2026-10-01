#!/usr/bin/env bash
# REQ-INSTALL-001 / REQ-INSTALL-008: follow INSTALL.md from a fresh checkout and fail on the
# first step that does not work.
#
#   scripts/install_smoke.sh [local|production|all]        (default: all)
#
# local       INSTALL.md section 3: `make env`, `make up`, health, first administrator, a complete
#             first login with TOTP, the object store, `make scope-check`, the operator console.
# production  INSTALL.md section 4: the generated production configuration, the documented
#             `config --quiet` validation, the production stack with its reverse proxy, TLS, the
#             documented first-administrator command, a login through the proxy, and which ports
#             are published.
#
# Why this exists: on 2026-10-01 a published release did not install - a withdrawn upstream image,
# an empty encryption key that made the first login impossible although /health was green, and a
# production settings block the stack refused. A developer machine hides all of that (cached
# images, existing keys). This script is what runs on a CLEAN machine: a fresh VM, or the GitHub
# runner of the release workflow (.github/workflows/install-smoke.yml). It pulls and builds with
# whatever cache the host has - use a clean host for a meaningful result.
#
# Safe to run on a machine that has a stack: it works on a COPY of the tree (your .env and data
# are never touched), uses its own compose project and network prefix, and refuses to start when a
# port it needs is taken. It does remove ITS OWN containers and volumes on exit.
#
# Environment: SMOKE_DOMAIN (default smoke.internal - a name Caddy serves with its internal CA, so
# no DNS or public certificate is needed), SMOKE_RUNNER=1 (also start the active-scanning profile;
# slow: it builds the tool-runner image), SMOKE_SKIP_FRONTEND=1, SMOKE_API_PORT (default 8000),
# SMOKE_KEEP=1 (leave the stack and work copy for inspection).
set -euo pipefail

STAGE="${1:-all}"
case "$STAGE" in local | production | all) ;; *) echo "usage: $0 [local|production|all]" >&2; exit 2 ;; esac

SOURCE="$(cd "$(dirname "$0")/.." && pwd)"
DOMAIN="${SMOKE_DOMAIN:-smoke.internal}"
API_PORT="${SMOKE_API_PORT:-8000}"
ADMIN_EMAIL="admin@example.com"

# --- own project identity: never share containers, volumes or networks with another stack ---
export COMPOSE_PROJECT_NAME="axial-smoke-$$"
export ASM_NETWORK_PREFIX="axial_smoke_$$"
export CONTROL_PLANE_PUBLISH_PORT="$API_PORT"

WORK="$(mktemp -d -t axial-smoke-XXXXXX)"
SECRETS="$(mktemp -d -t axial-smoke-secrets-XXXXXX)"
chmod 700 "$SECRETS"
PROD_FILES=(-f docker-compose.yml -f docker-compose.prod.yml)
VITE_PID=""

say() { printf '\n== %s\n' "$*"; }
run() { printf '+ %s\n' "$*"; "$@"; }
fail() { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }

# `npm run dev` starts a node process of its own, so killing the npm PID leaves Vite holding
# :5173 (found on the second run on the same host). Stop it by its unique work-copy path: only
# THIS run's Vite matches, never a developer's own dev server.
stop_console() {
    [ -n "$VITE_PID" ] && kill "$VITE_PID" 2>/dev/null || true
    pkill -f "$WORK/frontend/node_modules" 2>/dev/null || true
    VITE_PID=""
}

cleanup() {
    local status=$?
    local own="label=com.docker.compose.project=$COMPOSE_PROJECT_NAME"
    stop_console
    if [ "$status" -ne 0 ]; then
        # A failure on a CI runner with no logs is not diagnosable: show what each container said.
        echo "---- containers of this run ----" >&2
        docker ps -a --filter "$own" --format '{{.Names}}  {{.Status}}' >&2 || true
        for container in $(docker ps -aq --filter "$own"); do
            echo "---- last log lines: $(docker inspect --format '{{.Name}}' "$container")" >&2
            docker logs --tail 40 "$container" >&2 2>&1 || true
        done
    fi
    if [ "${SMOKE_KEEP:-0}" = 1 ]; then
        echo "SMOKE_KEEP=1: left the work copy ($WORK) and project $COMPOSE_PROJECT_NAME running"
    else
        ( cd "$WORK" && docker compose down -v --remove-orphans >/dev/null 2>&1 || true
          docker compose "${PROD_FILES[@]}" --profile runner --profile production down -v --remove-orphans >/dev/null 2>&1 || true )
        # Belt and braces if compose could not render its files: remove whatever carries THIS run's project label.
        docker ps -aq --filter "$own" | xargs -r docker rm -f >/dev/null 2>&1 || true
        docker volume ls -q --filter "$own" | xargs -r docker volume rm >/dev/null 2>&1 || true
        docker network ls -q --filter "$own" | xargs -r docker network rm >/dev/null 2>&1 || true
        rm -rf "$WORK" "$SECRETS"
    fi
    [ "$status" -eq 0 ] && echo && echo "INSTALL SMOKE PASSED ($STAGE)" || echo "INSTALL SMOKE FAILED ($STAGE)" >&2
    exit "$status"
}
trap cleanup EXIT

port_free() { ! (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
need_free() {
    for port in "$@"; do
        port_free "$port" || fail "port $port is already in use on this host (a running stack?). Run the smoke on a clean machine or stop what holds it; nothing was changed."
    done
}
wait_for() { # label, attempts, command...
    local label="$1" attempts="$2"; shift 2
    for _ in $(seq 1 "$attempts"); do "$@" >/dev/null 2>&1 && return 0; sleep 3; done
    fail "$label did not become ready"
}

# --- a work copy of the tree: whatever the guide does to .env and the volumes happens here ---
say "work copy of $SOURCE (without .git, .env, node_modules, secrets)"
( cd "$SOURCE" && tar --exclude=./.git --exclude=./.env --exclude=./.env.* --exclude=./node_modules \
      --exclude=./frontend/node_modules --exclude=./secrets --exclude=./uat/.venv -cf - . ) | tar -xf - -C "$WORK"
cp "$SOURCE/.env.example" "$WORK/.env.example"
cd "$WORK"

compose_prod() { docker compose "${PROD_FILES[@]}" "${PROFILES[@]}" "$@"; }

# ------------------------------------------------------------------ local evaluation
stage_local() {
    need_free "$API_PORT"
    say "INSTALL.md 3: configuration (make env)"
    run make env
    grep -Eq '^MFA_ENCRYPTION_KEY=.{40,}$' .env || fail "make env did not generate MFA_ENCRYPTION_KEY"
    grep -Eq '^SETTINGS_ENCRYPTION_KEY=.{40,}$' .env || fail "make env did not generate SETTINGS_ENCRYPTION_KEY"

    say "INSTALL.md 3: start and verify the backend (make up)"
    run make up
    run docker compose ps
    # NO waiting here, on purpose: the guide's very next step is `curl --fail .../health`, typed by a
    # person the moment `make up` returns. A wait loop in this script hid the race in which `make up`
    # returned before the API accepted connections ("Connection reset by peer" on a clean machine).
    [ "$(curl --fail --silent --show-error "http://localhost:$API_PORT/health")" = '{"status":"ok"}' ] \
        || fail "the guide's first check (curl --fail .../health) did not pass right after make up"

    say "INSTALL.md 3: the first administrator (make bootstrap-admin)"
    # REQ-INSTALL-005 [negative]: an address the sign-in form would reject must not create an account.
    if INITIAL_ADMIN_EMAIL="admin@example.test" make bootstrap-admin >"$SECRETS/rejected.out" 2>&1; then
        fail "bootstrap-admin accepted an address the sign-in form rejects"
    fi
    grep -q "cannot be used" "$SECRETS/rejected.out" || fail "bootstrap-admin did not explain the rejected address"
    INITIAL_ADMIN_EMAIL="$ADMIN_EMAIL" make bootstrap-admin | tee "$SECRETS/bootstrap.out" | sed -E 's/(temporary password: *)[^ ]+/\1<hidden>/'
    grep -q "temporary password:" "$SECRETS/bootstrap.out" || fail "bootstrap-admin did not print a temporary password"

    say "INSTALL.md 3: sign in for the first time (password change, TOTP enrollment, second sign-in)"
    run python3 scripts/smoke_first_login.py "http://localhost:$API_PORT" "$ADMIN_EMAIL" "$SECRETS/bootstrap.out"

    say "REQ-INSTALL-004 [negative]: with the MFA key blank, enrollment must answer 503 and say how to fix it"
    local key; key="$(grep '^MFA_ENCRYPTION_KEY=' .env | cut -d= -f2-)"
    sed -i 's/^MFA_ENCRYPTION_KEY=.*/MFA_ENCRYPTION_KEY=/' .env
    run docker compose up -d --force-recreate control-plane
    wait_for "the control-plane /health" 60 curl --fail --silent "http://localhost:$API_PORT/health"
    INITIAL_ADMIN_EMAIL="second@example.com" make bootstrap-admin >"$SECRETS/second.out"
    if python3 scripts/smoke_first_login.py "http://localhost:$API_PORT" second@example.com "$SECRETS/second.out" >"$SECRETS/blank.out" 2>&1; then
        fail "the first login succeeded with a blank MFA key"
    fi
    grep -q 'FAIL  start TOTP enrollment -> 503' "$SECRETS/blank.out" || { cat "$SECRETS/blank.out" >&2; fail "a blank MFA key did not produce the documented 503"; }
    grep -q 'MFA_ENCRYPTION_KEY' "$SECRETS/blank.out" || fail "the 503 did not name MFA_ENCRYPTION_KEY"
    sed -i "s|^MFA_ENCRYPTION_KEY=.*|MFA_ENCRYPTION_KEY=$key|" .env
    run docker compose up -d --force-recreate control-plane
    wait_for "the control-plane /health" 60 curl --fail --silent "http://localhost:$API_PORT/health"

    say "REQ-INSTALL-002: the object store requires credentials and is isolated"
    docker compose exec -T control-plane python - control-plane <scripts/smoke_object_store.py
    docker compose exec -T worker python - worker <scripts/smoke_object_store.py

    say "INSTALL.md 3: the pre-scan safety check (make scope-check)"
    run make scope-check

    if [ "${SMOKE_SKIP_FRONTEND:-0}" != 1 ] && command -v node >/dev/null 2>&1; then
        say "INSTALL.md 3: the operator console (npm ci, npm run dev)"
        need_free 5173
        ( cd frontend && npm ci --no-audit --no-fund --loglevel=error )
        ( cd frontend && exec npm run dev >"$SECRETS/vite.log" 2>&1 ) &
        VITE_PID=$!
        wait_for "the operator console on :5173" 40 curl --fail --silent http://localhost:5173/
        curl --silent http://localhost:5173/ | grep -q '<title>' || fail "the operator console served no page"
        stop_console
        port_free 5173 || { sleep 2; port_free 5173; } || fail "the operator console is still holding :5173 after it was stopped"
    fi

    if [ "${SMOKE_RUNNER:-0}" = 1 ]; then
        say "INSTALL.md 3: enable active scanning (--profile runner)"
        run docker compose --profile runner up -d --build
        run docker compose --profile runner ps
        wait_for "raw-egress-gateway to be healthy" 60 bash -c 'docker compose --profile runner ps raw-egress-gateway --format "{{.Status}}" | grep -q healthy'
        docker compose --profile runner ps tool-runner --format '{{.Status}}' | grep -q '^Up' || fail "tool-runner is not running"
    fi

    say "INSTALL.md 3: stop the local installation (verbatim) - nothing of it may keep running"
    # A plain `docker compose down` left tool-runner and raw-egress-gateway running (they sit in the
    # `runner` profile), found by running the guide literally; the guide now says --profile runner.
    run docker compose --profile runner down
    [ -z "$(docker ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME")" ] \
        || fail "the guide's stop command left containers of this installation running"

    say "local stage done - removing this stack's volumes"
    docker compose --profile runner down -v --remove-orphans >/dev/null 2>&1 || true
}

# ------------------------------------------------------------------ single-host production
stage_production() {
    need_free 80 443
    PROFILES=(--profile production)
    [ "${SMOKE_RUNNER:-0}" = 1 ] && PROFILES=(--profile runner --profile production)

    say "INSTALL.md 4: production secrets (scripts/gen_production_env.py)"
    rm -f .env
    run python3 scripts/gen_production_env.py --domain "$DOMAIN" --out .env
    [ "$(stat -c %a .env)" = 600 ] || fail ".env is not mode 600"

    say "INSTALL.md 4: validate (config --quiet), with BOTH profiles as documented"
    run docker compose "${PROD_FILES[@]}" --profile runner --profile production config --quiet
    # [Negative] a production file missing a required variable must be refused, not started (the 2026-10-01 OOB_TOKEN failure).
    grep -v '^OOB_TOKEN=' .env >"$SECRETS/broken.env"
    if docker compose --env-file "$SECRETS/broken.env" "${PROD_FILES[@]}" --profile runner --profile production config --quiet >"$SECRETS/broken.out" 2>&1; then
        fail "config --quiet accepted a production .env without OOB_TOKEN"
    fi
    grep -q 'OOB_TOKEN' "$SECRETS/broken.out" || fail "the refusal did not name the missing variable"

    say "INSTALL.md 4: start the production stack"
    run compose_prod up -d --build
    run compose_prod ps
    wait_for "the console over HTTPS ($DOMAIN)" 80 curl --silent --fail --insecure --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/"
    curl --silent --insecure --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/" | grep -q '<title>' || fail "the console page was not served"
    curl --silent --insecure --resolve "$DOMAIN:443:127.0.0.1" -D - -o /dev/null "https://$DOMAIN/" | grep -qi '^strict-transport-security:' || fail "no HSTS header"
    [ "$(curl --silent --insecure --resolve "$DOMAIN:443:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$DOMAIN/internal/anything")" = 404 ] || fail "/internal/* is not blocked at the proxy"
    # The proxy serves the console HTML by itself, so a served page says nothing about the backend
    # behind it - wait for THE API to answer (found as a race: the check ran seconds after `up`).
    api_answers_401() { [ "$(curl --silent --insecure --resolve "$1:443:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$1/engagements")" = 401 ]; }
    wait_for "the API behind the proxy (an unauthenticated call must be 401)" 60 api_answers_401 "$DOMAIN"
    api_answers_401 "$DOMAIN" || fail "an unauthenticated API call is not a 401"

    say "INSTALL.md 4: the first administrator (the documented command)"
    docker compose "${PROD_FILES[@]}" exec -e INITIAL_ADMIN_EMAIL="$ADMIN_EMAIL" control-plane python scripts/bootstrap_admin.py \
        | tee "$SECRETS/bootstrap-prod.out" | sed -E 's/(temporary password: *)[^ ]+/\1<hidden>/'
    grep -q "temporary password:" "$SECRETS/bootstrap-prod.out" || fail "the documented bootstrap command printed no temporary password"

    say "INSTALL.md 4: sign in through the proxy"
    run python3 scripts/smoke_first_login.py "https://$DOMAIN" "$ADMIN_EMAIL" "$SECRETS/bootstrap-prod.out" --connect 127.0.0.1 --insecure

    say "INSTALL.md 4: only ports 80 and 443 may be published on every interface"
    docker compose "${PROD_FILES[@]}" "${PROFILES[@]}" ps --format json | python3 -c '
import json, sys
text = sys.stdin.read().strip()
rows = json.loads(text) if text.startswith("[") else [json.loads(line) for line in text.splitlines() if line.strip()]
public, loopback = [], []
for row in rows:
    for pub in row.get("Publishers") or []:
        if not pub.get("PublishedPort"):
            continue
        item = (row["Service"], pub["URL"], pub["PublishedPort"])
        (loopback if pub["URL"] in ("127.0.0.1", "::1") else public).append(item)
print("  published on every interface:", sorted({(s, p) for s, _, p in public}))
print("  published on loopback only  :", sorted({(s, p) for s, _, p in loopback}))
bad = [i for i in public if i[2] not in (80, 443) or i[0] != "caddy"]
if bad:
    sys.exit(f"FAIL: unexpected public exposure: {bad}")
if any(s == "seaweedfs" for s, _, _ in public + loopback):
    sys.exit("FAIL: the object store must publish no port at all")
'

    say "REQ-INSTALL-002: the object store with the GENERATED credentials"
    docker compose "${PROD_FILES[@]}" exec -T control-plane python - control-plane <scripts/smoke_object_store.py
    docker compose "${PROD_FILES[@]}" exec -T worker python - worker <scripts/smoke_object_store.py

    say "production stage done - removing this stack"
    compose_prod down -v --remove-orphans >/dev/null 2>&1 || true
}

case "$STAGE" in
    local) stage_local ;;
    production) stage_production ;;
    all) stage_local; stage_production ;;
esac
