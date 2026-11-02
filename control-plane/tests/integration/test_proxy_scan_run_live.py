"""REQ-EGRESS-007 (GitHub #81): the egress proxy asks the database whether a run is still live, as its own read-only role.

The proxy's question runs from egress-proxy/app/db.py (loaded by path: it is another package called `app`) against the
migrated test database, connected as `asm_proxy_ro` - the real role with the real grants of migration 0044. So this also
proves that the grant is enough and no wider than the question."""

from __future__ import annotations

import datetime as dt
import importlib.util
import os
import sys
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from app.models.engagement import Engagement
from app.models.scan_run import ScanRun
from tests.integration.owners import make_owner

NOW = dt.datetime.now(dt.timezone.utc)
PROXY_DB = Path(__file__).resolve().parents[3] / "egress-proxy/app/db.py"


@pytest.fixture
def proxy_db(engine, monkeypatch):
    url = make_url(os.environ["TEST_DATABASE_URL"]).set(username="asm_proxy_ro", password="-".join(("asm", "proxy", "dev")))
    probe = create_engine(url, future=True)
    try:
        with probe.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"the proxy role is not reachable with its development password: {exc}")
    monkeypatch.setenv("DATABASE_URL", url.render_as_string(hide_password=False))
    monkeypatch.setenv("ENVIRONMENT", "development")
    spec = importlib.util.spec_from_file_location("proxy_db_under_test", PROXY_DB)
    module = importlib.util.module_from_spec(spec)
    sys.modules["proxy_db_under_test"] = module
    spec.loader.exec_module(module)
    yield module
    module.engine.dispose()
    probe.dispose()
    sys.modules.pop("proxy_db_under_test", None)


def _run(db, *, state="running", cancel=False, eng=None) -> ScanRun:
    if eng is None:
        eng = Engagement(title="T", source="own_domain", status="active", owner_user_id=make_owner(db).id,
                         authorized_from=NOW - dt.timedelta(hours=1), authorized_until=NOW + dt.timedelta(days=1))
        db.add(eng)
        db.flush()
    run = ScanRun(engagement_id=eng.id, phase="fingerprint", state=state, cancel_requested=cancel, trigger="manual")
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


@pytest.mark.parametrize("state", ["running", "waiting_approval"])
def test_a_live_run_of_the_engagement_is_live(db, proxy_db, state):
    run = _run(db, state=state)
    assert proxy_db.scan_run_live(str(run.id), str(run.engagement_id)) is True


@pytest.mark.parametrize("state", ["done", "failed", "aborted"])
def test_negative_a_finished_run_is_not_live(db, proxy_db, state):
    run = _run(db, state=state)
    assert proxy_db.scan_run_live(str(run.id), str(run.engagement_id)) is False


def test_negative_a_run_whose_cancellation_was_requested_is_not_live(db, proxy_db):
    run = _run(db, cancel=True)
    assert proxy_db.scan_run_live(str(run.id), str(run.engagement_id)) is False


def test_negative_a_run_of_another_engagement_or_an_unknown_run_is_not_live(db, proxy_db):
    run, other = _run(db), _run(db)
    assert proxy_db.scan_run_live(str(run.id), str(other.engagement_id)) is False
    assert proxy_db.scan_run_live(str(uuid.uuid4()), str(run.engagement_id)) is False


def test_negative_the_proxy_role_reads_only_the_columns_of_the_question_and_writes_nothing(db, proxy_db):
    run = _run(db)
    with proxy_db.engine.connect() as conn:
        assert conn.execute(text("SELECT state, cancel_requested FROM scan_run WHERE id = :i"), {"i": str(run.id)}).first()
    for statement in (
        "SELECT state_reason FROM scan_run",
        "SELECT checkpoint FROM scan_run",
        "SELECT * FROM scan_run",
        "UPDATE scan_run SET state = 'done'",
        "DELETE FROM scan_run",
    ):
        with proxy_db.engine.connect() as conn:
            with pytest.raises(DBAPIError, match="permission denied"):
                conn.execute(text(statement))
