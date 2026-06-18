"""Schema/migration tests for the Session 8 findings table + session columns."""

import aiosqlite
import pytest

from gatorcast.db import init_db


@pytest.mark.asyncio
async def test_new_table_and_columns(tmp_path):
    db = await init_db(tmp_path / "gatorcast.db")
    try:
        cur = await db.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
        names = {r["name"] for r in await cur.fetchall()}
        assert "findings" in names
        assert "session_text" not in names  # sidecar model: no FTS5 table
        cols = {
            r["name"]
            for r in await (await db.execute("PRAGMA table_info(sessions)")).fetchall()
        }
        assert {"finding_count", "max_severity"} <= cols
        # findings is writable with the expected shape
        await db.execute(
            "INSERT INTO findings (conn_id, rule_id, category, severity, label, offset_seconds) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("c1", "recursive-delete", "dangerous-command", "high", "Recursive delete (rm -rf)", 1.5),
        )
        await db.commit()
        cur = await db.execute("SELECT conn_id, rule_id FROM findings WHERE conn_id = ?", ("c1",))
        row = await cur.fetchone()
        assert row["rule_id"] == "recursive-delete"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_migration_adds_columns_to_existing_db(tmp_path):
    # Simulate a pre-Session-8 DB: a sessions table without the new columns.
    path = tmp_path / "old.db"
    conn = await aiosqlite.connect(path)
    await conn.execute("CREATE TABLE sessions (conn_id TEXT PRIMARY KEY, status TEXT)")
    await conn.commit()
    await conn.close()
    db = await init_db(path)  # must add columns idempotently, not crash
    try:
        cols = {
            r[1]
            for r in await (await db.execute("PRAGMA table_info(sessions)")).fetchall()
        }
        assert {"finding_count", "max_severity"} <= cols
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_init_db_is_idempotent(tmp_path):
    path = tmp_path / "gatorcast.db"
    db = await init_db(path)
    await db.close()
    db = await init_db(path)  # second call must not raise (IF NOT EXISTS + guarded ALTER)
    try:
        cols = {
            r[1]
            for r in await (await db.execute("PRAGMA table_info(sessions)")).fetchall()
        }
        assert {"finding_count", "max_severity"} <= cols
    finally:
        await db.close()
