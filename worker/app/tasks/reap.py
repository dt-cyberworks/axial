"""GitHub issue #29: periodic reconciliation, independent of any inbound
control-plane request. reap_stale_runs (control-plane/app/scan_lifecycle.py)
previously only ever ran opportunistically from inside start_scan/
create_scan_run - an abandoned run on an engagement nobody happened to
interact with again stayed 'running' forever. Wired into Celery beat in
celery_app.py."""

import logging

from app.celery_app import celery_app
from app.control_plane_client import client

logger = logging.getLogger(__name__)


@celery_app.task(name="asm.reap_stale_runs")
def reap_stale_runs() -> dict:
    reaped = client.reap_all_stale_runs()
    if reaped:
        logger.info("periodic reap: %d stale scan_run(s) reaped", reaped)
    return {"reaped": reaped}
