"""Per-connection reassembly of asciicast fragments into a stored recording.

The assembler holds an in-memory map ``conn_id -> SessionBuffer``. Events flow in
from the classifier; on a finalize signal (close event or idle timeout) the buffer
is reassembled into one asciicast v2 document and written to ``<conn_id>.cast`` on
the volume, with metadata recorded in SQLite.

Key rules enforced here (CLAUDE.md):
  * Concatenate ALL fragments (seq-ordered) FIRST, then parse — a flush may split
    a single asciicast line mid-tuple (rule 3).
  * Keying fragments by ``seq`` makes redelivery harmless (last write wins).
  * Finalize is idempotent: re-finalizing a finished ``conn_id`` is a no-op.
  * Recording payloads are never written to application logs (rule 5).

Persistence is delegated: SQLite metadata via ``SessionRepository``, ``.cast`` files
via ``CastStore``. The assembler owns only the in-memory buffering and reassembly
contract; the repository and cast store own all SQL and file I/O.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from gatorcast.logging import get_logger
from gatorcast.models import RecordingChunk, SessionEnd, SessionStart
from gatorcast.pipeline.detect import detect, load_rules, max_severity
from gatorcast.pipeline.extract import extract_plaintext
from gatorcast.store.casts import CastStore
from gatorcast.store.search import SearchStore
from gatorcast.store.sessions import SessionRepository

log = get_logger(__name__)

# SQLite's datetime('now') renders as "YYYY-MM-DD HH:MM:SS" in UTC.
_SQLITE_TS = "%Y-%m-%d %H:%M:%S"

# Cap on the set of finalized conn_ids remembered to reject late/redelivered
# events. Bounded to avoid unbounded memory growth; once exceeded the set is
# cleared (the only cost of forgetting is that a very-late redelivered chunk for
# a long-gone connection could re-create a buffer — acceptable and rare).
_FINALIZED_MAX = 10_000


@dataclass(slots=True)
class AsciicastMeta:
    """Metadata derived from a (re)assembled asciicast document."""

    ok: bool
    width: int | None = None
    height: int | None = None
    shell_user: str | None = None
    started_at: str | None = None
    duration_seconds: float | None = None
    event_count: int = 0
    error: str | None = None


def _epoch_to_iso(value: object) -> str | None:
    """Convert an epoch-seconds header timestamp to an ISO8601 UTC string."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except (OverflowError, OSError, ValueError):
        return None


def parse_asciicast(text: str) -> AsciicastMeta:
    """Parse a reassembled asciicast v2 document and derive its metadata.

    Defensive by contract: malformed input never raises. A missing or invalid
    header yields ``ok=False`` so the caller can mark the session ``error`` while
    still keeping the raw ``.cast`` for inspection.

    Args:
        text: The concatenated asciicast document.

    Returns:
        An ``AsciicastMeta``. ``ok`` is False (with ``error`` set) when the header
        is absent or not a valid version-2 header.
    """
    lines = text.splitlines()

    header_line: str | None = None
    body_start = 0
    for index, line in enumerate(lines):
        if line.strip():
            header_line = line
            body_start = index + 1
            break

    if header_line is None:
        return AsciicastMeta(ok=False, error="empty")

    try:
        header = json.loads(header_line)
    except (json.JSONDecodeError, ValueError):
        return AsciicastMeta(ok=False, error="header_not_json")

    if not isinstance(header, dict) or header.get("version") != 2:
        return AsciicastMeta(ok=False, error="bad_header")

    width = header.get("width")
    height = header.get("height")
    shell_user = header.get("user")

    max_offset = 0.0
    event_count = 0
    for line in lines[body_start:]:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            event = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            # Tolerate a trailing partial/garbage line (shouldn't occur after
            # concat, but stay defensive rather than discard a whole recording).
            continue
        if (
            isinstance(event, list)
            and len(event) >= 2
            and isinstance(event[0], (int, float))
            and not isinstance(event[0], bool)
        ):
            event_count += 1
            if event[0] > max_offset:
                max_offset = float(event[0])

    return AsciicastMeta(
        ok=True,
        width=width if isinstance(width, int) and not isinstance(width, bool) else None,
        height=(
            height if isinstance(height, int) and not isinstance(height, bool) else None
        ),
        shell_user=shell_user if isinstance(shell_user, str) else None,
        started_at=_epoch_to_iso(header.get("timestamp")),
        duration_seconds=max_offset if event_count else 0.0,
        event_count=event_count,
    )


@dataclass(slots=True)
class SessionBuffer:
    """In-memory accumulation of one connection's fragments and metadata."""

    conn_id: str
    username: str | None = None
    resource_address: str | None = None
    first_ts: str | None = None
    last_ts: str | None = None
    chunks: dict[int, str] = field(default_factory=dict)
    last_activity: float = 0.0  # monotonic seconds; drives idle finalize


class Assembler:
    """Demuxes events by ``conn_id`` and reassembles each into a stored recording."""

    def __init__(
        self,
        repo: SessionRepository,
        casts: CastStore,
        idle_timeout_seconds: int,
        clock: Callable[[], float] = time.monotonic,
        *,
        search: SearchStore | None = None,
        detection_enabled: bool = True,
    ) -> None:
        """Initialize the assembler.

        Args:
            repo: Session metadata repository (all SQL).
            casts: Cast file store (all ``.cast`` file I/O).
            idle_timeout_seconds: Silence after which a buffer is finalized.
            clock: Monotonic clock source (injectable for tests).
            search: Optional findings/search store. When provided (and
                ``detection_enabled``), each finalize runs a post-finalize scan that
                indexes the plaintext sidecar and stores detection findings. When
                ``None`` no scan runs and behavior is exactly as before (back-compat).
            detection_enabled: Master switch for the post-finalize scan. Has no effect
                when ``search`` is ``None``.
        """
        self._repo = repo
        self._casts = casts
        self._idle = idle_timeout_seconds
        self._clock = clock
        self._search = search
        self._detection_enabled = detection_enabled
        self._buffers: dict[str, SessionBuffer] = {}
        self._lock = asyncio.Lock()
        # conn_ids already finalized to disk. A late/redelivered chunk or start
        # for one of these must be ignored: re-creating a buffer would let the
        # next idle sweep write a truncated .cast OVER the good file (the row is
        # guarded by status!='complete', but the file is not). Bounded; see
        # ``_FINALIZED_MAX``.
        self._finalized: set[str] = set()
        # Debug counter: late events ignored because their conn_id is finalized.
        self._ignored_finalized = 0

    @property
    def active_count(self) -> int:
        """Number of sessions currently buffering (provisional, in memory)."""
        return len(self._buffers)

    async def handle(self, event: RecordingChunk | SessionStart | SessionEnd) -> None:
        """Apply one classified event to the buffer map."""
        match event:
            case SessionStart():
                await self._on_start(event)
            case RecordingChunk():
                await self._on_chunk(event)
            case SessionEnd():
                await self.finalize(event.conn_id)

    async def _on_start(self, event: SessionStart) -> None:
        """Pre-register a session: annotate the buffer and upsert a provisional row."""
        async with self._lock:
            if event.conn_id in self._finalized:
                # Already finalized to disk; ignore the late event so we never
                # re-create a buffer that could clobber the good .cast file.
                self._ignored_finalized += 1
                log.debug("assembler.ignore_finalized", phase="start")
                return
            buf = self._buffers.get(event.conn_id)
            if buf is None:
                buf = SessionBuffer(conn_id=event.conn_id)
                self._buffers[event.conn_id] = buf
            if event.resource_address is not None:
                buf.resource_address = event.resource_address
            if event.username is not None:
                buf.username = event.username
            if buf.first_ts is None:
                buf.first_ts = event.ts
            if event.ts is not None:
                buf.last_ts = event.ts
            buf.last_activity = self._clock()
            await self._repo.upsert_start(
                conn_id=buf.conn_id,
                username=buf.username,
                resource_address=buf.resource_address,
                started_at=buf.first_ts,
            )

    async def _on_chunk(self, event: RecordingChunk) -> None:
        """Store a fragment by seq (lazy-creating the buffer) and refresh the idle timer."""
        async with self._lock:
            if event.conn_id in self._finalized:
                # Already finalized to disk; ignore the late/redelivered chunk so
                # the next idle sweep cannot write a truncated .cast over the
                # good file. Never log the chunk content (rule 5).
                self._ignored_finalized += 1
                log.debug("assembler.ignore_finalized", phase="chunk")
                return
            buf = self._buffers.get(event.conn_id)
            if buf is None:
                buf = SessionBuffer(conn_id=event.conn_id)
                self._buffers[event.conn_id] = buf
            buf.chunks[event.seq] = event.asciicast  # last write wins → dup-safe
            if event.username is not None and buf.username is None:
                buf.username = event.username
            if buf.first_ts is None:
                buf.first_ts = event.ts
            if event.ts is not None:
                buf.last_ts = event.ts
            buf.last_activity = self._clock()
            await self._repo.add_chunk_meta(
                conn_id=buf.conn_id,
                username=buf.username,
                started_at=buf.first_ts,
            )

    async def finalize(self, conn_id: str) -> None:
        """Finalize a single connection. No-op if nothing is buffered (idempotent)."""
        async with self._lock:
            buf = self._buffers.pop(conn_id, None)
        if buf is None:
            return
        await self._finalize_buffer(buf)

    async def finalize_idle(self) -> None:
        """Finalize every buffer that has been silent for at least the idle timeout.

        Intended to run on an APScheduler interval.
        """
        now = self._clock()
        async with self._lock:
            stale = [
                conn_id
                for conn_id, buf in self._buffers.items()
                if now - buf.last_activity >= self._idle
            ]
            buffers = [self._buffers.pop(conn_id) for conn_id in stale]
        for buf in buffers:
            await self._finalize_buffer(buf)

    async def sweep_startup(self) -> None:
        """Reconcile provisional rows left behind by a crash/restart.

        Buffers are in-memory only, so after a restart a provisional row can never
        complete on its own. For each: if a ``.cast`` already exists on disk (the
        crash window between writing the file and updating the row), finalize from
        it; otherwise, if it is older than the idle timeout, sweep it away.
        """
        rows = await self._repo.find_provisional()

        cutoff = datetime.now(tz=timezone.utc) - timedelta(seconds=self._idle)
        swept = 0
        recovered = 0
        for conn_id, created_at in rows:
            path = self._casts.path_for(conn_id)
            if path.is_file() and path.stat().st_size > 0:
                await self._finalize_from_disk(conn_id, path)
                recovered += 1
            elif self._older_than(created_at, cutoff):
                await self._repo.delete_provisional(conn_id)
                swept += 1
        if swept or recovered:
            log.info("assembler.sweep", swept=swept, recovered=recovered)

    # --- internals -------------------------------------------------------------

    async def _post_finalize_scan(self, conn_id: str, cast_text: str) -> None:
        """Index plaintext to the encrypted sidecar + run detection for a finalized session.

        Writes the ANSI-stripped plaintext to the encrypted ``.txt.enc`` sidecar (feeding
        content search) and stores rule findings + the denormalized risk summary. Never
        logs recorded/extracted content (CLAUDE.md rule 5).

        Args:
            conn_id: The connection id whose recording was just finalized.
            cast_text: The fully reassembled asciicast document for that connection.
        """
        assert self._search is not None  # gated by callers; narrows the type
        extract = await asyncio.to_thread(extract_plaintext, cast_text)
        await self._casts.write_sidecar(conn_id, extract.text)
        findings = await asyncio.to_thread(detect, extract, load_rules())
        await self._search.replace_findings(conn_id, findings)
        await self._repo.update_finding_summary(
            conn_id, len(findings), max_severity(findings)
        )
        log.info("assembler.scan", conn_id=conn_id, finding_count=len(findings))

    async def _maybe_scan(self, conn_id: str, cast_text: str) -> None:
        """Run the post-finalize scan if enabled, swallowing any scan failure.

        A scan failure must NEVER break finalize: the ``.cast`` is already written and
        the row already complete, so a failed scan only forfeits search/detection for
        that session. Only the exception type is logged, never any content (rule 5).

        Args:
            conn_id: The connection id whose recording was just finalized.
            cast_text: The fully reassembled asciicast document for that connection.
        """
        if self._search is None or not self._detection_enabled:
            return
        try:
            await self._post_finalize_scan(conn_id, cast_text)
        except Exception as exc:
            log.warning(
                "assembler.scan_error", conn_id=conn_id, error=type(exc).__name__
            )

    async def _mark_finalized(self, conn_id: str) -> None:
        """Record a conn_id as finalized so later events for it are ignored.

        Bounded: clears the set once it exceeds ``_FINALIZED_MAX`` to keep memory
        flat. Forgetting an old conn_id only risks re-buffering a very-late
        redelivery for a long-closed connection, which is rare and harmless.
        """
        async with self._lock:
            if len(self._finalized) >= _FINALIZED_MAX:
                self._finalized.clear()
            self._finalized.add(conn_id)

    @staticmethod
    def _older_than(created_at: str | None, cutoff: datetime) -> bool:
        """True if a SQLite ``created_at`` string is older than ``cutoff`` (UTC)."""
        if not isinstance(created_at, str):
            return True  # unknown age → treat as stale and sweepable
        try:
            created = datetime.strptime(created_at, _SQLITE_TS).replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            return True
        return created <= cutoff

    async def _finalize_buffer(self, buf: SessionBuffer) -> None:
        """Reassemble a buffer to disk and mark its row complete (or error)."""
        chunks_sorted = [buf.chunks[seq] for seq in sorted(buf.chunks)]
        cast_text = "".join(chunks_sorted)
        meta = parse_asciicast(cast_text)
        path, size = await self._casts.write_cast(buf.conn_id, cast_text)
        status = "complete" if meta.ok else "error"

        await self._repo.finalize(
            buf.conn_id,
            username=buf.username,
            shell_user=meta.shell_user,
            started_at=meta.started_at,
            ended_at=buf.last_ts,
            duration_seconds=meta.duration_seconds,
            width=meta.width,
            height=meta.height,
            chunk_count=len(buf.chunks),
            size_bytes=size,
            cast_path=str(path),
            status=status,
        )
        # Remember this conn_id so a late/redelivered event cannot re-buffer it
        # and clobber the file just written (finding 1).
        await self._mark_finalized(buf.conn_id)
        log.info(
            "assembler.finalize",
            conn_id=buf.conn_id,
            status=status,
            chunk_count=len(buf.chunks),
            size_bytes=size,
        )
        # Scan runs AFTER the .cast is written and the row finalized, so a scan
        # failure leaves a complete, replayable session (gated + swallowed inside).
        await self._maybe_scan(buf.conn_id, cast_text)

    async def _finalize_from_disk(self, conn_id: str, path: Path) -> None:
        """Finalize a crash-recovered session from its existing ``.cast`` file."""
        cast_text = await self._casts.read_cast(path)
        meta = parse_asciicast(cast_text)
        status = "complete" if meta.ok else "error"
        await self._repo.finalize_from_disk(
            conn_id,
            shell_user=meta.shell_user,
            started_at=meta.started_at,
            duration_seconds=meta.duration_seconds,
            width=meta.width,
            height=meta.height,
            size_bytes=self._casts.stat_size(path),
            cast_path=str(path),
            status=status,
        )
        await self._mark_finalized(conn_id)
        # Same post-finalize scan for crash-recovered sessions (gated + swallowed).
        await self._maybe_scan(conn_id, cast_text)
