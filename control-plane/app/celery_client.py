"""Producer-only Celery-Client: enqueued Scan-Tasks beim worker, ohne dessen
Code zu importieren (control-plane und worker sind getrennte Deployment-
Einheiten, s. Deployment-Architektur Kap. 2). Spiegelt den 'enqueue'-Pfeil im
Prozess-Topologie-Diagramm der Architektur (Abb. 1: Orchestrator -> enqueue -> Celery Worker).
"""

from celery import Celery

from app.config import get_settings

settings = get_settings()

_celery = Celery("asm_control_plane_producer", broker=settings.redis_url, backend=settings.redis_url)


def enqueue_scan(
    engagement_id: str, scan_run_id: str, budget_max_iterations: int = 50, approval_timeout_seconds: int = 900,
) -> str:
    # GitHub issue #18: scan_run_id is created by the caller (start_scan,
    # race-safe against the database's own unique index) and handed to the
    # worker - the worker no longer creates its own scan_run row via a
    # second, independently-racing check-then-insert.
    result = _celery.send_task(
        "asm.run_scan", args=[engagement_id],
        kwargs={
            "scan_run_id": scan_run_id,
            "budget_max_iterations": budget_max_iterations,
            "approval_timeout_seconds": approval_timeout_seconds,
        },
    )
    return result.id
