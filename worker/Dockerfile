# worker: orchestriert Scans, fuehrt selbst nichts aus - keine offensiven
# Tools, kein DB-Zugriff (nur ueber die interne control-plane-API).
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

WORKDIR /app

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
