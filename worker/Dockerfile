# worker: orchestriert Scans, fuehrt selbst nichts aus - keine offensiven
# Tools, kein DB-Zugriff (nur ueber die interne control-plane-API).
# REQ-COVER-001 (R3, architecture decision by johannes 2026-09-29): subfinder
# runs in the worker image, passive sources only. It never contacts the target,
# so it needs no tool-runner and no egress-proxy path; the discovery phase asks
# the Scope Gateway before every run. Pinned to a release and verified against
# its published SHA-256, per architecture (this file's stage is discarded).
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS subfinder
ARG TARGETARCH
ARG SUBFINDER_VERSION=2.16.0
ARG SUBFINDER_SHA256_AMD64=1b7f9c608e9a5bd59e609a5e09710d63c5485e92d3d49dc2c16eb4fdbe10cb60
ARG SUBFINDER_SHA256_ARM64=c81d49559c0f630177be9e347e502e7a3d474aacc6ff78291ffcb4964367d63d
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip \
 && case "${TARGETARCH:-amd64}" in \
      amd64) sha="${SUBFINDER_SHA256_AMD64}" ;; \
      arm64) sha="${SUBFINDER_SHA256_ARM64}" ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/subfinder.zip \
      "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${TARGETARCH:-amd64}.zip" \
 && echo "${sha}  /tmp/subfinder.zip" | sha256sum -c - \
 && unzip -j /tmp/subfinder.zip subfinder -d /out \
 && chmod 0755 /out/subfinder

FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

WORKDIR /app
COPY --from=subfinder /out/subfinder /usr/local/bin/subfinder

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN useradd -r -u 10003 -s /usr/sbin/nologin worker
USER worker

# GitHub issue #29: --beat runs the periodic scheduler (app/tasks/reap.py)
# embedded in this same process - fine at the current single-worker-replica
# deployment scale (docs/deployment.md's M1-M3 maturity stages: one Docker
# Compose host). Running MULTIPLE worker replicas with --beat would each run
# their own scheduler and duplicate-dispatch every periodic task; a
# dedicated `celery beat` process (or a scheduler with a distributed lock,
# e.g. redbeat) is needed before that becomes true (M4+, per the same doc).
#
# --schedule points beat's persistence file at /tmp: WORKDIR (/app, the
# default schedule location) is owned by root from the build stage, and this
# container deliberately runs as the unprivileged `worker` user - found live
# on first deploy, beat silently fell back to an in-memory (never persisted)
# schedule instead of failing the container, only visible as a permission
# warning in the logs.
CMD ["celery", "-A", "app.celery_app.celery_app", "worker", "--beat", "--schedule=/tmp/celerybeat-schedule", "--loglevel=INFO"]
