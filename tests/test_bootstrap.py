"""Session 1 bootstrap checks: app boots, health route works, schema initializes."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gatorcast.config import Settings
from gatorcast.db import init_db
from gatorcast.main import create_app


def _test_settings(tmp_path: Path) -> Settings:
    """Settings pointed at a temporary data directory."""
    return Settings(data_dir=tmp_path, syslog_tcp_port=0)


def test_healthz_and_lifespan(tmp_path: Path) -> None:
    """App boots through its lifespan and the health route returns OK."""
    app = create_app(_test_settings(tmp_path))
    with TestClient(app) as client:
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    # Lifespan startup creates the database file.
    assert (tmp_path / "gatorcast.db").exists()


@pytest.mark.asyncio
async def test_schema_created(tmp_path: Path) -> None:
    """init_db creates the sessions table and its indexes."""
    settings = _test_settings(tmp_path)
    conn = await init_db(settings.db_path)
    try:
        cur = await conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'"
        )
        row = await cur.fetchone()
        assert row is not None
        assert row["name"] == "sessions"

        cur = await conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' "
            "AND name LIKE 'idx_sessions_%'"
        )
        indexes = {r["name"] for r in await cur.fetchall()}
        assert {
            "idx_sessions_resource",
            "idx_sessions_started",
            "idx_sessions_status",
        } <= indexes
    finally:
        await conn.close()
