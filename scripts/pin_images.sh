#!/usr/bin/env bash
# REQ-SUPPLY-001: maintenance aid for the pinned base-image digests.
#
# Reports, per image reference used by the stack, the digest currently pinned in
# the repo versus the digest the tag resolves to now - so bumping (e.g. to pick
# up base-image security fixes, especially the rolling Kali runner base) is a
# quick, auditable diff. It does NOT rewrite files; apply changes deliberately.
#
# Usage:  scripts/pin_images.sh
# Requires: docker (pulls each referenced tag to resolve its current digest).

set -euo pipefail
cd "$(dirname "$0")/.."

files=$(git ls-files '*Dockerfile' '*.Dockerfile' docker-compose.yml docker-compose.prod.yml 2>/dev/null || \
        find . -path ./node_modules -prune -o \( -name '*Dockerfile' -o -name '*.Dockerfile' -o -name 'docker-compose*.yml' \) -print)

# Collect "repo:tag@sha256:pinned" tokens from FROM and image: lines.
refs=$(grep -hE '^\s*(FROM|image:)\s' $files 2>/dev/null \
        | sed -E 's/^\s*(FROM|image:)\s+//' \
        | awk '{print $1}' \
        | grep '@sha256:' | sort -u || true)

if [ -z "$refs" ]; then
  echo "no digest-pinned image references found"
  exit 0
fi

drift=0
printf '%-46s %-14s %-14s\n' "IMAGE" "PINNED" "CURRENT"
while IFS= read -r ref; do
  tag="${ref%@*}"
  pinned="${ref#*@}"
  if docker pull -q "$tag" >/dev/null 2>&1; then
    current=$(docker image inspect "$tag" --format '{{index .RepoDigests 0}}' 2>/dev/null | sed 's/.*@//')
  else
    current="<unresolved>"
  fi
  short_pinned="${pinned#sha256:}"; short_pinned="${short_pinned:0:12}"
  short_current="${current#sha256:}"; short_current="${short_current:0:12}"
  mark=""
  if [ "$current" != "$pinned" ] && [ "$current" != "<unresolved>" ]; then mark="  <-- DRIFT"; drift=1; fi
  printf '%-46s %-14s %-14s%s\n' "$tag" "$short_pinned" "$short_current" "$mark"
done <<< "$refs"

if [ "$drift" = "1" ]; then
  echo
  echo "Drift detected. Update the @sha256 pins in the Dockerfiles/compose deliberately,"
  echo "then rebuild and re-run the test suite. 'make scan' re-checks pinning + vulns."
fi
