import os

from celery import Celery

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery("asm_worker", broker=REDIS_URL, backend=REDIS_URL)

# GitHub issue #29: previously no time limit at all - a hung external call
# (a target that accepts a connection and never responds, a wedged worker
# process) parked a task, and therefore a worker slot, forever with no error
# anywhere. These defaults are deliberately generous rather than tight: the
# single asm.run_scan task per scan run can legitimately block for a long
# time NOT from a hang but because _await_approval (app/tasks/agent.py) does
# a blocking in-task poll for an operator's manual approval decision, up to
# approval_timeout_seconds (configurable per campaign, up to 24h - see
# settings_store.MAX_APPROVAL_TIMEOUT_SECONDS in control-plane) - and the
# agent can hit that wait multiple times across its iteration budget. A
# tight limit would kill a run that is waiting correctly, not hung, which is
# worse than today's "no limit" (a false failure instead of a slow-but-real
# one). Tightening this for real needs the approval wait decoupled from the
# task's own wall-clock (tracked in the deferred "real resume" follow-up to
# #29) - not just a smaller number here.
SCAN_TASK_SOFT_TIME_LIMIT_SECONDS = int(os.environ.get("SCAN_TASK_SOFT_TIME_LIMIT_SECONDS", 172800))  # 48h
SCAN_TASK_TIME_LIMIT_SECONDS = int(os.environ.get("SCAN_TASK_TIME_LIMIT_SECONDS", 176400))  # +1h grace past soft

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # Soft limit raises SoftTimeLimitExceeded INSIDE the task - run_scan
    # catches it and marks the run 'failed' with a distinguishable reason
    # (app/tasks/pipeline.py). Hard limit is the backstop: if the task is
    # stuck somewhere that can't even handle that exception (e.g. blocked in
    # an uninterruptible call), Celery SIGKILLs the worker child process
    # outright - the run then has no way to mark itself failed, which is
    # exactly what the periodic reaper below (heartbeat-based) is for.
    task_soft_time_limit=SCAN_TASK_SOFT_TIME_LIMIT_SECONDS,
    task_time_limit=SCAN_TASK_TIME_LIMIT_SECONDS,
    # Periodic reconciliation, independent of any inbound control-plane
    # request (app/tasks/reap.py) - reaps a run whose worker died/was killed
    # and never got a chance to mark itself failed. Interval deliberately
    # shorter than control-plane's stale_run_seconds (default 300s) so an
    # abandoned run doesn't sit much longer than that ceiling before being
    # caught, instead of only when someone happens to start another scan on
    # that same engagement.
    beat_schedule={
        "reap-stale-scan-runs": {
            "task": "asm.reap_stale_runs",
            "schedule": float(os.environ.get("REAP_STALE_RUNS_INTERVAL_SECONDS", 60)),
        },
        # REQ-MON-002: alerts of monitoring engagements (signed webhooks). Retried by
        # the control plane's own bookkeeping; never touches a run.
        "deliver-alerts": {
            "task": "asm.deliver_alerts",
            "schedule": float(os.environ.get("DELIVER_ALERTS_INTERVAL_SECONDS", 60)),
        },
        # REQ-MAIL-003: queued e-mail (password reset, test message) is sent by the worker,
        # because the control plane has no route to the internet.
        "deliver-mail": {
            "task": "asm.deliver_mail",
            "schedule": float(os.environ.get("DELIVER_MAIL_INTERVAL_SECONDS", 15)),
        },
        # REQ-MODE-016: a parked run whose approval expired continues with "not approved".
        "resume-parked-runs": {
            "task": "asm.resume_parked_runs",
            "schedule": float(os.environ.get("RESUME_PARKED_RUNS_INTERVAL_SECONDS", 60)),
        },
        # REQ-MON-001/003: start the monitoring runs that are due ("every N days"). The control
        # plane decides; a tick that finds nothing due does nothing.
        "run-due-schedules": {
            "task": "asm.run_due_schedules",
            "schedule": float(os.environ.get("RUN_DUE_SCHEDULES_INTERVAL_SECONDS", 60)),
        },
        # REQ-MODE-012: missed runs and authorization review (inbox items and alerts only).
        "monitoring-housekeeping": {
            "task": "asm.monitoring_housekeeping",
            "schedule": float(os.environ.get("MONITORING_HOUSEKEEPING_INTERVAL_SECONDS", 900)),
        },
    },
)

# Registriert die Phasen-/Wartungs-Tasks (Architektur Kap. 4.1) beim celery-Worker-Prozess.
import app.tasks.pipeline  # noqa: E402,F401
import app.tasks.reap  # noqa: E402,F401
import app.tasks.monitoring_tasks  # noqa: E402,F401
import app.tasks.mail_tasks  # noqa: E402,F401
