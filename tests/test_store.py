"""Tests for store.sessions (SessionRepository) and store.casts (CastStore).

Covers:
  - upsert_start creates provisional rows; add_chunk_meta refreshes them
  - provisional guard: upsert does not clobber a complete row
  - finalize: provisional → complete with metadata; idempotent (complete guard)
  - finalize_from_disk path
  - list_systems: distinct resource_address, counts, last-seen ordering; NULL bucket
  - list_sessions: newest-first; NULL/unknown bucket
  - get: present and missing
  - CastStore: write/read/delete (missing-file tolerant)/total_size_bytes
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gatorcast.db import init_db
from gatorcast.store.casts import CastStore
from gatorcast.store.sessions import SessionRepository

# A minimal valid asciicast v2 document for cast-file tests.
SMALL_CAST = (
    '{"version":2,"width":80,"height":24,"timestamp":1700000000,"user":"ubuntu"}\n'
    '[0.1,"o","hello"]\n'
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def db(tmp_path: Path):
    """A fresh schema-initialized aiosqlite connection."""
    conn = await init_db(tmp_path / "gatorcast.db")
    yield conn
    await conn.close()


@pytest.fixture
async def repo(db):
    """A SessionRepository over the fixture DB."""
    return SessionRepository(db)


@pytest.fixture
def casts_dir(tmp_path: Path) -> Path:
    """A dedicated directory for .cast files."""
    d = tmp_path / "casts"
    d.mkdir()
    return d


@pytest.fixture
def cast_store(casts_dir: Path) -> CastStore:
    """A CastStore backed by the fixture directory."""
    return CastStore(casts_dir)


# ---------------------------------------------------------------------------
# SessionRepository — upsert_start / add_chunk_meta
# ---------------------------------------------------------------------------


async def test_upsert_start_creates_provisional_row(repo: SessionRepository, db) -> None:
    """upsert_start creates a new provisional row with the given fields."""
    await repo.upsert_start(
        conn_id="cid-1",
        username="alice@x",
        resource_address="host.example.com",
        started_at="2026-01-01T00:00:00Z",
    )
    cur = await db.execute("SELECT * FROM sessions WHERE conn_id = 'cid-1'")
    row = await cur.fetchone()
    await cur.close()
    assert row is not None
    assert row["status"] == "provisional"
    assert row["username"] == "alice@x"
    assert row["resource_address"] == "host.example.com"
    assert row["started_at"] == "2026-01-01T00:00:00Z"


async def test_upsert_start_idempotent_backfills_nulls(
    repo: SessionRepository, db
) -> None:
    """Repeated upsert_start backfills NULL fields but keeps first non-null values."""
    await repo.upsert_start(
        conn_id="cid-2", username=None, resource_address=None, started_at=None
    )
    await repo.upsert_start(
        conn_id="cid-2",
        username="bob@x",
        resource_address="srv",
        started_at="2026-01-01T00:00:00Z",
    )
    cur = await db.execute("SELECT * FROM sessions WHERE conn_id = 'cid-2'")
    row = await cur.fetchone()
    await cur.close()
    assert row["username"] == "bob@x"
    assert row["resource_address"] == "srv"
    assert row["started_at"] == "2026-01-01T00:00:00Z"


async def test_upsert_start_keeps_first_started_at(repo: SessionRepository, db) -> None:
    """started_at is set once and never overwritten by subsequent upserts."""
    await repo.upsert_start(
        conn_id="cid-3",
        username="u@x",
        resource_address="h",
        started_at="2026-01-01T00:00:00Z",
    )
    await repo.upsert_start(
        conn_id="cid-3",
        username="u@x",
        resource_address="h",
        started_at="2099-12-31T23:59:59Z",  # later timestamp — must NOT overwrite
    )
    cur = await db.execute("SELECT started_at FROM sessions WHERE conn_id = 'cid-3'")
    row = await cur.fetchone()
    await cur.close()
    assert row["started_at"] == "2026-01-01T00:00:00Z"


async def test_add_chunk_meta_refreshes_provisional(repo: SessionRepository, db) -> None:
    """add_chunk_meta creates or refreshes the provisional row."""
    await repo.add_chunk_meta(
        conn_id="cid-4",
        username="carol@x",
        started_at="2026-02-01T00:00:00Z",
    )
    cur = await db.execute("SELECT * FROM sessions WHERE conn_id = 'cid-4'")
    row = await cur.fetchone()
    await cur.close()
    assert row is not None
    assert row["status"] == "provisional"
    assert row["username"] == "carol@x"


async def test_upsert_does_not_clobber_complete_row(repo: SessionRepository, db) -> None:
    """upsert_start is guarded: a complete row is never touched."""
    # Insert a complete row directly.
    await db.execute(
        """
        INSERT INTO sessions (conn_id, status, username, resource_address)
        VALUES ('cid-5', 'complete', 'original@x', 'orig-host')
        """
    )
    await db.commit()

    # Attempt to upsert over it.
    await repo.upsert_start(
        conn_id="cid-5",
        username="overwrite@x",
        resource_address="new-host",
        started_at=None,
    )
    cur = await db.execute("SELECT * FROM sessions WHERE conn_id = 'cid-5'")
    row = await cur.fetchone()
    await cur.close()
    assert row["status"] == "complete"
    assert row["username"] == "original@x"
    assert row["resource_address"] == "orig-host"


# ---------------------------------------------------------------------------
# SessionRepository — finalize
# ---------------------------------------------------------------------------


async def test_finalize_transitions_provisional_to_complete(
    repo: SessionRepository, db, casts_dir: Path
) -> None:
    """finalize sets status=complete and fills all metadata columns."""
    await repo.upsert_start(
        conn_id="fin-1", username="u@x", resource_address="host", started_at=None
    )
    cast_path = str(casts_dir / "fin-1.cast")
    await repo.finalize(
        "fin-1",
        username="u@x",
        shell_user="ubuntu",
        started_at="2026-01-01T00:00:00Z",
        ended_at="2026-01-01T00:05:00Z",
        duration_seconds=300.0,
        width=80,
        height=24,
        chunk_count=3,
        size_bytes=4096,
        cast_path=cast_path,
        status="complete",
    )
    cur = await db.execute("SELECT * FROM sessions WHERE conn_id = 'fin-1'")
    row = await cur.fetchone()
    await cur.close()
    assert row["status"] == "complete"
    assert row["shell_user"] == "ubuntu"
    assert row["duration_seconds"] == 300.0
    assert row["width"] == 80
    assert row["height"] == 24
    assert row["chunk_count"] == 3
    assert row["size_bytes"] == 4096
    assert row["cast_path"] == cast_path


async def test_finalize_preserves_provisional_started_at(
    repo: SessionRepository, db, casts_dir: Path
) -> None:
    """finalize keeps the start-event timestamp; header timestamp only falls back."""
    await repo.upsert_start(
        conn_id="fin-2",
        username="u@x",
        resource_address="host",
        started_at="2026-01-01T00:00:00Z",  # from start event
    )
    await repo.finalize(
        "fin-2",
        username="u@x",
        shell_user=None,
        started_at="2099-12-31T00:00:00Z",  # from header — must NOT overwrite
        ended_at=None,
        duration_seconds=None,
        width=None,
        height=None,
        chunk_count=1,
        size_bytes=100,
        cast_path=str(casts_dir / "fin-2.cast"),
        status="complete",
    )
    cur = await db.execute("SELECT started_at FROM sessions WHERE conn_id = 'fin-2'")
    row = await cur.fetchone()
    await cur.close()
    assert row["started_at"] == "2026-01-01T00:00:00Z"


async def test_finalize_is_guarded_complete_noop(
    repo: SessionRepository, db, casts_dir: Path
) -> None:
    """Re-finalizing a complete row is a no-op (status != 'complete' guard)."""
    await repo.upsert_start(
        conn_id="fin-3", username="u@x", resource_address="h", started_at=None
    )
    cast_path = str(casts_dir / "fin-3.cast")
    await repo.finalize(
        "fin-3",
        username="u@x",
        shell_user="ubuntu",
        started_at="2026-01-01T00:00:00Z",
        ended_at=None,
        duration_seconds=10.0,
        width=80,
        height=24,
        chunk_count=1,
        size_bytes=500,
        cast_path=cast_path,
        status="complete",
    )
    # Second finalize with different values — should be ignored.
    await repo.finalize(
        "fin-3",
        username="other@x",
        shell_user="root",
        started_at="2099-01-01T00:00:00Z",
        ended_at="2099-01-01T01:00:00Z",
        duration_seconds=9999.0,
        width=1,
        height=1,
        chunk_count=99,
        size_bytes=1,
        cast_path="/different/path.cast",
        status="error",
    )
    cur = await db.execute("SELECT * FROM sessions WHERE conn_id = 'fin-3'")
    row = await cur.fetchone()
    await cur.close()
    assert row["status"] == "complete"
    assert row["duration_seconds"] == 10.0
    assert row["chunk_count"] == 1


async def test_finalize_error_status(
    repo: SessionRepository, db, casts_dir: Path
) -> None:
    """finalize can mark a session as error (unparsable recording)."""
    await repo.upsert_start(
        conn_id="fin-err", username=None, resource_address=None, started_at=None
    )
    await repo.finalize(
        "fin-err",
        username=None,
        shell_user=None,
        started_at=None,
        ended_at=None,
        duration_seconds=None,
        width=None,
        height=None,
        chunk_count=1,
        size_bytes=50,
        cast_path=str(casts_dir / "fin-err.cast"),
        status="error",
    )
    cur = await db.execute("SELECT status FROM sessions WHERE conn_id = 'fin-err'")
    row = await cur.fetchone()
    await cur.close()
    assert row["status"] == "error"


# ---------------------------------------------------------------------------
# SessionRepository — finalize_from_disk
# ---------------------------------------------------------------------------


async def test_finalize_from_disk(
    repo: SessionRepository, db, casts_dir: Path
) -> None:
    """finalize_from_disk recovers a crash-window session from its .cast file."""
    await repo.upsert_start(
        conn_id="disk-1",
        username="u@x",
        resource_address="host",
        started_at="2026-01-01T00:00:00Z",
    )
    cast_path = str(casts_dir / "disk-1.cast")
    await repo.finalize_from_disk(
        "disk-1",
        shell_user="ubuntu",
        started_at="2026-01-01T00:00:00Z",
        duration_seconds=55.0,
        width=80,
        height=24,
        size_bytes=2048,
        cast_path=cast_path,
        status="complete",
    )
    cur = await db.execute("SELECT * FROM sessions WHERE conn_id = 'disk-1'")
    row = await cur.fetchone()
    await cur.close()
    assert row["status"] == "complete"
    assert row["shell_user"] == "ubuntu"
    assert row["duration_seconds"] == 55.0
    assert row["ended_at"] is not None  # set to datetime('now')
    assert row["chunk_count"] == 0  # unrecoverable from disk; stays at default


async def test_finalize_from_disk_guarded_noop(
    repo: SessionRepository, db, casts_dir: Path
) -> None:
    """finalize_from_disk is idempotent on a complete row."""
    # Finalize first time.
    await repo.upsert_start(
        conn_id="disk-2", username="u@x", resource_address="h", started_at=None
    )
    await repo.finalize_from_disk(
        "disk-2",
        shell_user="ubuntu",
        started_at="2026-01-01T00:00:00Z",
        duration_seconds=5.0,
        width=80,
        height=24,
        size_bytes=100,
        cast_path=str(casts_dir / "disk-2.cast"),
        status="complete",
    )
    # Second call — should be a no-op.
    await repo.finalize_from_disk(
        "disk-2",
        shell_user="root",
        started_at="2099-01-01T00:00:00Z",
        duration_seconds=9999.0,
        width=1,
        height=1,
        size_bytes=1,
        cast_path="/other.cast",
        status="error",
    )
    cur = await db.execute("SELECT * FROM sessions WHERE conn_id = 'disk-2'")
    row = await cur.fetchone()
    await cur.close()
    assert row["status"] == "complete"
    assert row["duration_seconds"] == 5.0


# ---------------------------------------------------------------------------
# SessionRepository — list_systems
# ---------------------------------------------------------------------------


async def _insert_session(
    db,
    conn_id: str,
    resource_address: str | None,
    status: str = "complete",
    started_at: str | None = None,
) -> None:
    """Helper: insert a session row directly for query tests."""
    await db.execute(
        """
        INSERT INTO sessions (conn_id, resource_address, status, started_at,
                               updated_at, created_at)
        VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))
        """,
        (conn_id, resource_address, status, started_at),
    )
    await db.commit()


async def test_list_systems_empty(repo: SessionRepository) -> None:
    systems = await repo.list_systems()
    assert systems == []


async def test_list_systems_distinct_addresses(repo: SessionRepository, db) -> None:
    """Each distinct resource_address appears exactly once."""
    await _insert_session(db, "c1", "host-a")
    await _insert_session(db, "c2", "host-a")
    await _insert_session(db, "c3", "host-b")
    systems = await repo.list_systems()
    addresses = {s.resource_address for s in systems}
    assert addresses == {"host-a", "host-b"}


async def test_list_systems_counts(repo: SessionRepository, db) -> None:
    """session_count reflects all sessions for that system."""
    await _insert_session(db, "d1", "multi")
    await _insert_session(db, "d2", "multi")
    await _insert_session(db, "d3", "multi")
    await _insert_session(db, "d4", "single")
    systems = await repo.list_systems()
    by_addr = {s.resource_address: s.session_count for s in systems}
    assert by_addr["multi"] == 3
    assert by_addr["single"] == 1


async def test_list_systems_null_bucket(repo: SessionRepository, db) -> None:
    """NULL resource_address rows are collected under a None bucket."""
    await _insert_session(db, "e1", None)
    await _insert_session(db, "e2", None)
    systems = await repo.list_systems()
    null_system = next(s for s in systems if s.resource_address is None)
    assert null_system.session_count == 2


async def test_list_systems_ordered_by_last_seen(repo: SessionRepository, db) -> None:
    """Systems are returned newest-first by last updated_at."""
    # Insert in a defined order; rely on updated_at being set by DB trigger.
    # We override updated_at explicitly to control ordering.
    await db.execute(
        "INSERT INTO sessions (conn_id, resource_address, status, updated_at, created_at) "
        "VALUES ('f1', 'older', 'complete', '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
    )
    await db.execute(
        "INSERT INTO sessions (conn_id, resource_address, status, updated_at, created_at) "
        "VALUES ('f2', 'newer', 'complete', '2026-06-01 00:00:00', '2026-06-01 00:00:00')"
    )
    await db.commit()
    systems = await repo.list_systems()
    assert systems[0].resource_address == "newer"
    assert systems[1].resource_address == "older"


async def test_list_systems_findings_summary(repo: SessionRepository, db) -> None:
    """finding_count sums and max_severity is the highest across a system's sessions."""
    await _insert_session(db, "g1", "risky")
    await _insert_session(db, "g2", "risky")
    await _insert_session(db, "g3", "clean")
    await repo.update_finding_summary("g1", 2, "high")
    await repo.update_finding_summary("g2", 1, "critical")
    # g3 keeps the schema defaults (0 findings, NULL severity).

    by_addr = {s.resource_address: s for s in await repo.list_systems()}
    assert by_addr["risky"].finding_count == 3
    assert by_addr["risky"].max_severity == "critical"  # highest across g1/g2
    assert by_addr["clean"].finding_count == 0
    assert by_addr["clean"].max_severity is None


# ---------------------------------------------------------------------------
# SessionRepository — list_sessions
# ---------------------------------------------------------------------------


async def test_list_sessions_returns_sessions_for_address(
    repo: SessionRepository, db
) -> None:
    """list_sessions returns only sessions for the given resource_address."""
    await _insert_session(db, "g1", "host-x", started_at="2026-01-01T00:00:00Z")
    await _insert_session(db, "g2", "host-x", started_at="2026-02-01T00:00:00Z")
    await _insert_session(db, "g3", "host-y", started_at="2026-01-15T00:00:00Z")
    sessions = await repo.list_sessions("host-x")
    conn_ids = [s.conn_id for s in sessions]
    assert set(conn_ids) == {"g1", "g2"}
    assert "g3" not in conn_ids


async def test_list_sessions_newest_first(repo: SessionRepository, db) -> None:
    """list_sessions returns sessions newest started_at first."""
    await _insert_session(db, "h1", "srv", started_at="2026-01-01T00:00:00Z")
    await _insert_session(db, "h2", "srv", started_at="2026-06-01T00:00:00Z")
    await _insert_session(db, "h3", "srv", started_at="2026-03-01T00:00:00Z")
    sessions = await repo.list_sessions("srv")
    conn_ids = [s.conn_id for s in sessions]
    assert conn_ids == ["h2", "h3", "h1"]


async def test_list_sessions_null_bucket(repo: SessionRepository, db) -> None:
    """list_sessions(None) returns only sessions with NULL resource_address."""
    await _insert_session(db, "i1", None)
    await _insert_session(db, "i2", None)
    await _insert_session(db, "i3", "known")
    sessions = await repo.list_sessions(None)
    conn_ids = {s.conn_id for s in sessions}
    assert conn_ids == {"i1", "i2"}


async def test_list_sessions_empty_for_unknown_address(
    repo: SessionRepository,
) -> None:
    sessions = await repo.list_sessions("no-such-host")
    assert sessions == []


# ---------------------------------------------------------------------------
# SessionRepository — get
# ---------------------------------------------------------------------------


async def test_get_returns_session(repo: SessionRepository, db) -> None:
    """get returns the Session model for an existing conn_id."""
    await _insert_session(db, "j1", "host-j", started_at="2026-05-01T00:00:00Z")
    session = await repo.get("j1")
    assert session is not None
    assert session.conn_id == "j1"
    assert session.resource_address == "host-j"


async def test_get_returns_none_for_missing(repo: SessionRepository) -> None:
    """get returns None for a conn_id that does not exist."""
    result = await repo.get("does-not-exist")
    assert result is None


# ---------------------------------------------------------------------------
# CastStore — write / read / delete / total_size_bytes
# ---------------------------------------------------------------------------


async def test_cast_store_write_and_read(cast_store: CastStore) -> None:
    """write_cast persists a recording; read_cast retrieves it unchanged."""
    path, size = await cast_store.write_cast("conn-ww", SMALL_CAST)
    assert path.exists()
    assert size > 0
    content = await cast_store.read_cast("conn-ww")
    assert content == SMALL_CAST


async def test_cast_store_read_via_path(cast_store: CastStore) -> None:
    """read_cast accepts a concrete Path (the stored cast_path)."""
    path, _ = await cast_store.write_cast("conn-rp", SMALL_CAST)
    content = await cast_store.read_cast(path)
    assert content == SMALL_CAST


async def test_cast_store_read_missing_raises(cast_store: CastStore) -> None:
    """read_cast raises FileNotFoundError for a missing file."""
    with pytest.raises(FileNotFoundError):
        await cast_store.read_cast("no-such-conn")


async def test_cast_store_delete_returns_true_when_exists(
    cast_store: CastStore,
) -> None:
    """delete_cast returns True when the file was present and removed."""
    path, _ = await cast_store.write_cast("conn-del", SMALL_CAST)
    result = await cast_store.delete_cast(path)
    assert result is True
    assert not path.exists()


async def test_cast_store_delete_tolerates_missing_file(
    cast_store: CastStore, casts_dir: Path
) -> None:
    """delete_cast returns False when the file is already absent (no exception)."""
    missing = casts_dir / "ghost.cast"
    result = await cast_store.delete_cast(missing)
    assert result is False


async def test_cast_store_total_size_bytes_empty(cast_store: CastStore) -> None:
    """total_size_bytes returns 0 when the casts directory is empty."""
    size = await cast_store.total_size_bytes()
    assert size == 0


async def test_cast_store_total_size_bytes_sums_files(cast_store: CastStore) -> None:
    """total_size_bytes sums sizes of all .cast files."""
    _, s1 = await cast_store.write_cast("conn-sz1", SMALL_CAST)
    _, s2 = await cast_store.write_cast("conn-sz2", SMALL_CAST * 2)
    total = await cast_store.total_size_bytes()
    assert total == s1 + s2


async def test_cast_store_path_for(cast_store: CastStore) -> None:
    """path_for returns a .cast path inside the casts directory."""
    path = cast_store.path_for("test-conn")
    assert path.name == "test-conn.cast"
    assert path.parent == cast_store.casts_dir


async def test_cast_store_stat_size_missing(cast_store: CastStore) -> None:
    """stat_size returns 0 for a missing file."""
    missing = cast_store.casts_dir / "ghost.cast"
    assert cast_store.stat_size(missing) == 0


# ---------------------------------------------------------------------------
# CastStore — encryption at rest (Session 7)
# ---------------------------------------------------------------------------


@pytest.fixture
def enc_cast_store(casts_dir: Path) -> CastStore:
    """A CastStore with a real Cryptor (encryption enabled)."""
    import base64
    import os

    from gatorcast.crypto import Cryptor

    key = base64.b64encode(os.urandom(32)).decode("ascii")
    return CastStore(casts_dir, cryptor=Cryptor(key))


async def test_cast_store_encrypted_file_is_ciphertext_on_disk(
    enc_cast_store: CastStore, casts_dir: Path
) -> None:
    """With encryption on, the on-disk file holds no plaintext header/content."""
    await enc_cast_store.write_cast("conn-enc", SMALL_CAST)
    raw = (casts_dir / "conn-enc.cast").read_bytes()
    assert b'{"version":2' not in raw
    assert b"hello" not in raw
    assert raw.startswith(b"GCST\x01\x00")


async def test_cast_store_encrypted_round_trip(enc_cast_store: CastStore) -> None:
    """read_cast returns the original text after an encrypted write."""
    await enc_cast_store.write_cast("conn-enc2", SMALL_CAST)
    assert await enc_cast_store.read_cast("conn-enc2") == SMALL_CAST


async def test_cast_store_encrypted_size_is_ciphertext(
    enc_cast_store: CastStore, casts_dir: Path
) -> None:
    """Reported size matches the on-disk ciphertext file size."""
    _, size = await enc_cast_store.write_cast("conn-enc3", SMALL_CAST)
    assert size == (casts_dir / "conn-enc3.cast").stat().st_size
    # Ciphertext is framed (magic + nonce + tag), so larger than the plaintext.
    assert size > len(SMALL_CAST.encode("utf-8"))


async def test_cast_store_disabled_is_plaintext_unchanged(
    cast_store: CastStore, casts_dir: Path
) -> None:
    """With no cryptor, the on-disk bytes are the verbatim UTF-8 recording."""
    await cast_store.write_cast("conn-plain", SMALL_CAST)
    raw = (casts_dir / "conn-plain.cast").read_bytes()
    assert raw == SMALL_CAST.encode("utf-8")


# ---------------------------------------------------------------------------
# CastStore — encrypted plaintext sidecars (Session 8)
# ---------------------------------------------------------------------------

SIDECAR_TEXT = "alice ran: vault login s.SECRETROOT\nhello from the shell\n"


@pytest.fixture
def sidecar_store(casts_dir: Path) -> CastStore:
    """A CastStore with a sidecar cryptor keyed by the distinct sidecar info."""
    import base64
    import os

    from gatorcast.crypto import SIDECAR_HKDF_INFO, Cryptor

    key = base64.b64encode(os.urandom(32)).decode("ascii")
    return CastStore(
        casts_dir, sidecar_cryptor=Cryptor(key, info=SIDECAR_HKDF_INFO)
    )


async def test_sidecar_round_trip_plaintext(
    cast_store: CastStore, casts_dir: Path
) -> None:
    """With no sidecar cryptor: round-trip works and on-disk bytes are raw UTF-8."""
    size = await cast_store.write_sidecar("conn-sc", SIDECAR_TEXT)
    assert size > 0
    assert await cast_store.read_sidecar("conn-sc") == SIDECAR_TEXT

    path = casts_dir / "conn-sc.txt.enc"
    assert path.name.endswith(".txt.enc")
    assert path.read_bytes() == SIDECAR_TEXT.encode("utf-8")


async def test_sidecar_round_trip_encrypted(
    sidecar_store: CastStore, casts_dir: Path
) -> None:
    """With a sidecar cryptor: read returns the original; on-disk is ciphertext."""
    await sidecar_store.write_sidecar("conn-sce", SIDECAR_TEXT)
    assert await sidecar_store.read_sidecar("conn-sce") == SIDECAR_TEXT

    raw = (casts_dir / "conn-sce.txt.enc").read_bytes()
    assert raw != SIDECAR_TEXT.encode("utf-8")
    assert b"vault login" not in raw
    assert raw.startswith(b"GCST\x01\x00")


async def test_sidecar_read_missing_raises(cast_store: CastStore) -> None:
    """read_sidecar raises FileNotFoundError when no sidecar exists."""
    with pytest.raises(FileNotFoundError):
        await cast_store.read_sidecar("no-such-conn")


async def test_sidecar_delete_and_has_sidecar(cast_store: CastStore) -> None:
    """delete_sidecar returns True then False; has_sidecar tracks presence."""
    assert cast_store.has_sidecar("conn-scd") is False
    await cast_store.write_sidecar("conn-scd", SIDECAR_TEXT)
    assert cast_store.has_sidecar("conn-scd") is True

    assert await cast_store.delete_sidecar("conn-scd") is True
    assert await cast_store.delete_sidecar("conn-scd") is False
    assert cast_store.has_sidecar("conn-scd") is False


async def test_sidecar_key_separation_fails_with_cast_info(
    sidecar_store: CastStore, casts_dir: Path
) -> None:
    """A sidecar written under the sidecar info must not decrypt under cast info.

    Writes a sidecar with the sidecar-info cryptor, then reads through a store whose
    sidecar cryptor uses the DEFAULT (cast) info derived from the same master key.
    Authentication must fail (InvalidTag), proving the distinct-info requirement.
    """
    import base64
    import os

    from cryptography.exceptions import InvalidTag

    from gatorcast.crypto import SIDECAR_HKDF_INFO, Cryptor

    key = base64.b64encode(os.urandom(32)).decode("ascii")
    writer = CastStore(
        casts_dir, sidecar_cryptor=Cryptor(key, info=SIDECAR_HKDF_INFO)
    )
    await writer.write_sidecar("conn-sep", SIDECAR_TEXT)

    # Same master key, but default (cast) HKDF info → independent, wrong key.
    reader = CastStore(casts_dir, sidecar_cryptor=Cryptor(key))
    with pytest.raises(InvalidTag):
        await reader.read_sidecar("conn-sep")
