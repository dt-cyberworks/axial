#!/usr/bin/env bash
# REQ-INSTALL-001: wait until the control plane answers /health, then return.
#
# `make up` used to return as soon as the containers were STARTED - a moment before the
# API accepted connections. The install guide's very next step (`curl --fail
# http://localhost:8000/health`) then failed with "Connection reset by peer" on a clean
# machine, found by following the published guide literally (2026-10-01). Waiting here
# makes the guide's own first check pass the first time it is typed.
#
#   scripts/wait_for_api.sh [URL]       URL defaults to the published port of the control-plane
#   WAIT_SECONDS=180                    how long to wait before giving up (exit 1)
#
# Needs only curl (a documented prerequisite) and, to find a non-default port, docker compose.
set -u

URL="${1:-}"
if [ -z "$URL" ]; then
    # `docker compose port` knows the real published address even when CONTROL_PLANE_PUBLISH_PORT is set.
    mapping="$(docker compose port control-plane 8000 2>/dev/null | head -n 1)"
    port="${mapping##*:}"
    URL="http://localhost:${port:-8000}/health"
fi

limit="${WAIT_SECONDS:-180}"
deadline=$(( $(date +%s) + limit ))
printf 'waiting for the control plane (%s) ' "$URL"
until curl --fail --silent --show-error --max-time 3 --output /dev/null "$URL" 2>/dev/null; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
        echo
        echo "the control plane did not answer within ${limit}s - look at: docker compose logs control-plane" >&2
        exit 1
    fi
    printf '.'
    sleep 2
done
echo " up"
