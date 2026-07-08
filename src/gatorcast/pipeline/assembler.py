"""Per-connection reassembly of asciicast fragments into a stored recording.

The assembler holds an in-memory map ``conn_id -> SessionBuffer``. Events flow in
from the classifier; on a finalize signal (close event or idle timeout) the buffer
is reassembled into one asciicast v2 document and written to ``<conn_id>.cast`` on
the volume, with metadata recorded in SQLite.

Reassembly contract (confirmed against the Gateway's ``internal/sessionrecorder``):
  * Each flushed chunk is a SELF-CONTAINED mini-document: the Gateway prepends the
    asciicast header to every flush and resets its event buffer after each, so a
    chunk is ``header + only-the-events-since-the-last-flush``. Chunks are NOT
    fragments of one document split mid-tuple, and events are always whole lines.
  * Therefore reassembly is line-based, not raw concatenation: keep the header
    once and concatenate every event line across chunks in ``seq`` order. See
    ``reassemble_asciicast``. (This supersedes the old "concat then parse / may
    split mid-tuple" assumption.)
  * Keying fragments by ``seq`` makes redelivery harmless (last write wins).
  * The Gateway's final flush (``message == "session finished"``) is a reliable
    end-of-session signal; finalize triggers on it. The idle sweep is only a
    backstop for sessions whose Gateway died without that final flush.
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


def reassemble_asciicast(chunks_in_seq_order: list[str]) -> str:
    """Rebuild one asciicast v2 document from the Gateway's per-flush chunks.

    The Gateway emits each flush as a self-contained value: the header line
    followed by only the events recorded since the previous flush (its recorder
    prepends the header to every flush and clears its event buffer afterward). So
    the correct reassembly is NOT a raw concatenation — that would repeat the
    header mid-stream and, because chunks carry no trailing newline, fuse the last
    event of one chunk to the header of the next and lose both.

    Instead we split every chunk into lines and classify each line purely by its
    JSON *shape*, so the logic survives Gateway changes to header fields, the
    asciicast version number, or the set of event types:

      * the first JSON **object** line is the header (kept once; later per-chunk
        header copies are dropped),
      * every JSON **array** line is an event (kept, in seq/arrival order — this
        preserves any future event types beyond ``"o"``),
      * blank lines, non-JSON boundary fragments, and JSON scalars are skipped.

    Event offsets are absolute, so concatenating events across chunks yields
    correct playback timing.

    Args:
        chunks_in_seq_order: The raw ``asciicast`` chunk values, already ordered by
            ``asciicast_sequence_num``.

    Returns:
        A single newline-terminated asciicast document. If no header line is found
        anywhere, returns just the event lines (empty string when there are none)
        so the caller can mark the session ``error`` while still keeping a raw
        ``.cast`` for inspection.
    """
    header: str | None = None
    events: list[str] = []
    for chunk in chunks_in_seq_order:
        for raw_line in chunk.split("\n"):
            line = raw_line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                # A boundary fragment or garbage line — drop it defensively rather
                # than corrupt the document. Never log the content (rule 5).
                continue
            if isinstance(parsed, dict):
                if header is None:
                    header = line  # first header wins; drop duplicates
            elif isinstance(parsed, list):
                events.append(line)
            # other JSON scalars: ignore
    body = "".join(event + "\n" for event in events)
    if header is None:
        return body
    return header + "\n" + body


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
class InProgress:
    """In-memory state for one connection whose recording is being assembled.

    File-first model: the plaintext ``.cast`` on disk is the durable copy, rewritten
    on every append. This structure holds the per-``seq`` chunks so reassembly stays
    correctly ordered regardless of arrival order, plus a ``baseline`` — the prior
    document text — set when a session is reopened from a sealed file or re-adopted
    after a restart.
    """

    conn_id: str
    username: str | None = None
    resource_address: str | None = None
    first_ts: str | None = None
    last_ts: str | None = None
    chunks: dict[int, str] = field(default_factory=dict)
    baseline: str | None = None
    last_activity: float = 0.0  # monotonic seconds; drives the idle sweep

    def documents(self) -> list[str]:
        """Texts to reassemble: any baseline first, then chunks in ascending seq."""
        docs: list[str] = []
        if self.baseline:
            docs.append(self.baseline)
        docs.extend(self.chunks[seq] for seq in sorted(self.chunks))
        return docs

    @property
    def has_data(self) -> bool:
        """True once any recording content (a chunk or a baseline) is present."""
        return bool(self.chunks) or bool(self.baseline)


class Assembler:
    """Demuxes events by ``conn_id`` and assembles each into a stored recording.

    File-first: as chunks arrive they are reassembled and written to a plaintext
    ``.cast`` on disk immediately (durable across restarts) and scanned live for
    findings. A session is *sealed* — encrypted (if enabled) and marked ``complete``
    — either terminally on the Gateway's ``"session finished"`` flush / a close
    event, or reopenably on the idle backstop. A reopenable-sealed session that
    receives a late chunk is decrypted, appended to, and re-sealed.
    """

    def __init__(
        self,
        repo: SessionRepository,
        casts: CastStore,
        idle_timeout_seconds: int,
        clock: Callable[[], float] = time.monotonic,
        *,
        session_max_idle_seconds: int = 3600,
        search: SearchStore | None = None,
        detection_enabled: bool = True,
    ) -> None:
        """Initialize the assembler.

        Args:
            repo: Session metadata repository (all SQL).
            casts: Cast file store (all ``.cast`` file I/O).
            idle_timeout_seconds: Silence after which a *chunkless* (start-only)
                in-progress entry is dropped as an abandoned/non-recording
                connection. A session that has received recording data is NOT sealed
                at this threshold — it keeps its on-disk file and buffering state so a
                pause (no output) and later resume still recombine under one
                ``conn_id``.
            clock: Monotonic clock source (injectable for tests).
            session_max_idle_seconds: Idle backstop. An in-progress recording silent
                this long is sealed anyway (assume the Gateway died without its final
                ``"session finished"`` flush) — but *reopenably*, so a still-later
                chunk reopens and extends it. Also the window a recording stays
                plaintext on disk before encryption; should exceed the longest
                expected interactive pause.
            search: Optional findings/search store. When provided (and
                ``detection_enabled``), detection runs live on every append and the
                encrypted search sidecar is written at seal. When ``None`` no scan
                runs.
            detection_enabled: Master switch for detection/search. No effect when
                ``search`` is ``None``.
        """
        self._repo = repo
        self._casts = casts
        self._idle = idle_timeout_seconds
        self._max_idle = session_max_idle_seconds
        self._clock = clock
        self._search = search
        self._detection_enabled = detection_enabled
        self._buffers: dict[str, InProgress] = {}
        self._lock = asyncio.Lock()
        # conn_ids already sealed. Value = reopenable: True means a late chunk should
        # reopen (decrypt → append → re-seal); False means the session ended
        # terminally ("session finished"/close) and late chunks are ignored. Bounded
        # (see ``_FINALIZED_MAX``); forgetting an old entry only risks a rare re-buffer.
        self._sealed: dict[str, bool] = {}
        # Debug counter: late chunks ignored because their conn_id is terminally sealed.
        self._ignored_finalized = 0

    @property
    def active_count(self) -> int:
        """Number of sessions currently in progress (provisional, buffering)."""
        return len(self._buffers)

    async def handle(self, event: RecordingChunk | SessionStart | SessionEnd) -> None:
        """Apply one classified event."""
        match event:
            case SessionStart():
                await self._on_start(event)
            case RecordingChunk():
                await self._on_chunk(event)
                # The Gateway's final flush is both the last chunk and a reliable end
                # signal: it was persisted+scanned above, now seal terminally.
                if event.is_final:
                    await self.finalize(event.conn_id)
            case SessionEnd():
                await self.finalize(event.conn_id)

    async def _on_start(self, event: SessionStart) -> None:
        """Pre-register a session: annotate in-progress state and upsert its row."""
        async with self._lock:
            if event.conn_id in self._sealed:
                # Already sealed (terminal or reopenable). A bare start carries no
                # recording data, so there is nothing to reopen for — ignore it.
                self._ignored_finalized += 1
                log.debug("assembler.ignore_sealed", phase="start")
                return
            buf = self._buffers.get(event.conn_id)
            if buf is None:
                buf = InProgress(conn_id=event.conn_id)
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
        """Store a chunk, persist the growing plaintext ``.cast``, and scan live."""
        async with self._lock:
            buf = self._buffers.get(event.conn_id)
            if buf is None:
                sealed_reopenable = self._sealed.get(event.conn_id)
                if sealed_reopenable is False:
                    # Terminally ended ("session finished"/close): a late/redelivered
                    # chunk must not reopen or clobber the file. Never log content.
                    self._ignored_finalized += 1
                    log.debug("assembler.ignore_sealed", phase="chunk")
                    return
                if sealed_reopenable is True:
                    # Reopen a backstop-sealed session: decrypt the file back to
                    # plaintext, revert the row to provisional, and continue appending.
                    baseline = await self._casts.reopen(event.conn_id)
                    await self._repo.reopen(event.conn_id)
                    del self._sealed[event.conn_id]
                    buf = InProgress(conn_id=event.conn_id, baseline=baseline)
                    log.info("assembler.reopen", conn_id=event.conn_id)
                else:
                    buf = InProgress(conn_id=event.conn_id)
                self._buffers[event.conn_id] = buf

            buf.chunks[event.seq] = event.asciicast  # last write wins → dup-safe
            if event.username is not None and buf.username is None:
                buf.username = event.username
            if buf.first_ts is None:
                buf.first_ts = event.ts
            if event.ts is not None:
                buf.last_ts = event.ts
            buf.last_activity = self._clock()
            # Persist the plaintext .cast now (durable) and scan it live.
            cast_text = await self._persist(buf)
            await self._maybe_scan(buf.conn_id, cast_text, write_sidecar=False)

    async def finalize(self, conn_id: str) -> None:
        """Seal a connection terminally (end signal / close). Idempotent no-op if unknown."""
        async with self._lock:
            buf = self._buffers.pop(conn_id, None)
            if buf is None:
                return
            await self._seal(buf, reopenable=False)

    async def finalize_idle(self) -> None:
        """Idle sweep. Intended to run on an APScheduler interval.

        Two silence thresholds, by whether the entry holds any recording data:

          * **Chunkless (start-only)**, silent >= ``idle_timeout``: authenticated but
            recorded nothing — an abandoned/non-recording connection. Drop the
            in-memory entry and leave its ``provisional`` row (reclaimed by the
            startup sweep). NOT sealed, so a later recording still records normally.
          * **Has data**, silent >= ``session_max_idle``: normally sealed by the
            Gateway's ``"session finished"``; reaching this backstop means that never
            came. Seal *reopenably* — the on-disk recording is preserved and encrypted,
            and a still-later chunk will reopen and extend it (nothing is lost).

        An in-progress recording only *idle_timeout*-silent is left untouched so a long
        interactive pause keeps recombining under one ``conn_id``.
        """
        now = self._clock()
        async with self._lock:
            drop_empty = [
                conn_id
                for conn_id, buf in self._buffers.items()
                if not buf.has_data and now - buf.last_activity >= self._idle
            ]
            hard_stale = [
                conn_id
                for conn_id, buf in self._buffers.items()
                if buf.has_data and now - buf.last_activity >= self._max_idle
            ]
            for conn_id in drop_empty:
                self._buffers.pop(conn_id, None)  # drop; not sealed, not locked
            if drop_empty:
                log.debug("assembler.drop_empty", count=len(drop_empty))
            for conn_id in hard_stale:
                buf = self._buffers.pop(conn_id)
                log.info("assembler.backstop_seal", conn_id=conn_id)
                await self._seal(buf, reopenable=True)

    async def sweep_startup(self) -> None:
        """Reconcile provisional rows left behind by a restart.

        In-progress state is in memory only, so after a restart each provisional row
        is re-adopted from its on-disk plaintext ``.cast`` (the durable copy) as an
        active session — so continuation chunks keep appending and it seals normally
        (on "session finished" or the backstop). A provisional row with no ``.cast``
        that is older than the idle timeout is a stale empty start and is swept away.
        """
        rows = await self._repo.find_provisional()
        cutoff = datetime.now(tz=timezone.utc) - timedelta(seconds=self._idle)
        readopted = 0
        swept = 0
        now = self._clock()
        async with self._lock:
            for conn_id, created_at in rows:
                path = self._casts.path_for(conn_id)
                if path.is_file() and path.stat().st_size > 0:
                    # In-progress files are plaintext (only sealed rows are encrypted).
                    baseline = await self._casts.read_plaintext(path)
                    self._buffers[conn_id] = InProgress(
                        conn_id=conn_id, baseline=baseline, last_activity=now
                    )
                    readopted += 1
                elif self._older_than(created_at, cutoff):
                    await self._repo.delete_provisional(conn_id)
                    swept += 1
        if swept or readopted:
            log.info("assembler.sweep", swept=swept, readopted=readopted)

    # --- internals -------------------------------------------------------------

    async def _persist(self, buf: InProgress) -> str:
        """Reassemble the buffer, write the plaintext ``.cast``, and refresh the row.

        Called on every append. Writes the current document as plaintext (never
        encrypted mid-session) and mirrors derived metadata onto the ``provisional``
        row. Returns the reassembled text for the live scan. Content is never logged.
        """
        cast_text = reassemble_asciicast(buf.documents())
        meta = parse_asciicast(cast_text)
        path, size = await self._casts.write_plaintext(buf.conn_id, cast_text)
        # Ensure the row exists (a session may start with a chunk, no auth line first).
        await self._repo.add_chunk_meta(
            conn_id=buf.conn_id, username=buf.username, started_at=buf.first_ts
        )
        await self._repo.update_progress(
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
        )
        return cast_text

    async def _seal(self, buf: InProgress, *, reopenable: bool) -> None:
        """Seal an in-progress recording: final scan, encrypt, mark complete.

        Writes the search sidecar and runs a final detection pass over the plaintext,
        then encrypts the ``.cast`` (a no-op when encryption is disabled) and marks the
        row ``complete`` (or ``error`` if it never carried a valid header). The conn_id
        is recorded in ``_sealed`` with ``reopenable`` so a late chunk is either
        ignored (terminal) or reopens the session (backstop). Caller holds the lock and
        has already removed ``buf`` from the active map.
        """
        if not buf.has_data:
            # A start-only entry with nothing recorded — nothing to seal, don't lock.
            log.debug("assembler.seal_skip_empty", conn_id=buf.conn_id)
            return
        cast_text = reassemble_asciicast(buf.documents())
        meta = parse_asciicast(cast_text)
        status = "complete" if meta.ok else "error"
        # Sidecar + final detection run over plaintext, BEFORE encrypting.
        await self._maybe_scan(buf.conn_id, cast_text, write_sidecar=True)
        # write_cast encrypts when a cryptor is configured (else rewrites plaintext).
        path, size = await self._casts.write_cast(buf.conn_id, cast_text)
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
        self._mark_sealed(buf.conn_id, reopenable)
        log.info(
            "assembler.seal",
            conn_id=buf.conn_id,
            status=status,
            reopenable=reopenable,
            size_bytes=size,
        )

    async def _run_scan(
        self, conn_id: str, cast_text: str, *, write_sidecar: bool
    ) -> None:
        """Extract plaintext, (optionally) write the search sidecar, store findings.

        Detection runs live on every append (``write_sidecar=False``); the encrypted
        content-search sidecar is written only at seal (``write_sidecar=True``). Never
        logs recorded/extracted content (CLAUDE.md rule 5).
        """
        assert self._search is not None  # gated by callers; narrows the type
        extract = await asyncio.to_thread(extract_plaintext, cast_text)
        if write_sidecar:
            await self._casts.write_sidecar(conn_id, extract.text)
        findings = await asyncio.to_thread(detect, extract, load_rules())
        await self._search.replace_findings(conn_id, findings)
        await self._repo.update_finding_summary(
            conn_id, len(findings), max_severity(findings)
        )

    async def _maybe_scan(
        self, conn_id: str, cast_text: str, *, write_sidecar: bool
    ) -> None:
        """Run detection if enabled, swallowing any failure.

        A scan failure must never break the pipeline: the ``.cast`` is already on disk,
        so a failed scan only forfeits findings/search for that pass. Only the
        exception type is logged, never any content (rule 5).
        """
        if self._search is None or not self._detection_enabled:
            return
        try:
            await self._run_scan(conn_id, cast_text, write_sidecar=write_sidecar)
        except Exception as exc:
            log.warning(
                "assembler.scan_error", conn_id=conn_id, error=type(exc).__name__
            )

    def _mark_sealed(self, conn_id: str, reopenable: bool) -> None:
        """Record a conn_id as sealed (``reopenable`` flag). Caller holds the lock.

        Bounded: clears the map once it exceeds ``_FINALIZED_MAX`` to keep memory flat.
        Forgetting an old entry only risks re-buffering a very-late redelivery for a
        long-closed connection, which is rare and harmless.
        """
        if len(self._sealed) >= _FINALIZED_MAX:
            self._sealed.clear()
        self._sealed[conn_id] = reopenable

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
