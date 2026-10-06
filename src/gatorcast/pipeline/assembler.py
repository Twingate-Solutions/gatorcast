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
  * The seal mode (terminal vs. reopenable) is persisted on the session row
    (``sealed_terminal``). After a restart or a cache eviction, the row — not
    memory — decides whether a late chunk is ignored or reopens the recording, so
    a sealed ``.cast`` is never replaced by a fragment.
  * Recording payloads are never written to application logs (rule 5).

Connection lifecycle (kubectl activity spec §6). ``Authenticated connection``
creates only a hidden *pending connection* in the ``connections`` table — no
``sessions`` row. From there:

  * the first recording chunk *promotes* it: the in-memory buffer is seeded from
    the connection (identity, cluster, start time), a ``provisional`` session row
    is created, and the connection becomes ``recording``. A k8s exec/attach chunk's
    ``request_id`` is stored on the session row (SSH chunks carry none);
  * an API audit line (``ApiRequest``) is stored once per ``request_id`` (redelivery
    is a no-op), scanned by the API rules, and marks the connection ``api`` — an
    API-only connection never gets a session row;
  * a connection with neither chunks nor audits within ``session_max_idle_seconds``
    is expired by the idle sweep into today's visible ``error`` session row.

All state transitions run under one lock, serialized with chunk handling. Raw
audit lines, URLs, and header values are never logged — counters and ``conn_id``
only.

Persistence is delegated: SQLite metadata via ``SessionRepository``, connection
and API-request metadata via ``ActivityStore``, ``.cast`` files via ``CastStore``.
The assembler owns only the in-memory buffering, the lifecycle transitions, and
the reassembly contract; the stores own all SQL and file I/O.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Literal

from gatorcast.logging import get_logger
from gatorcast.models import ApiRequest, RecordingChunk, SessionEnd, SessionStart
from gatorcast.pipeline.detect import Finding, detect, detect_api, load_rules, max_severity
from gatorcast.pipeline.extract import extract_plaintext
from gatorcast.store.activity import ActivityStore
from gatorcast.store.casts import CastStore
from gatorcast.store.search import SearchStore
from gatorcast.store.sessions import SessionRepository

log = get_logger(__name__)

# SQLite's datetime('now') renders as "YYYY-MM-DD HH:MM:SS" in UTC.
_SQLITE_TS = "%Y-%m-%d %H:%M:%S"

# Cap on the in-memory cache of sealed conn_ids (and pending shell users). Bounded
# to avoid unbounded memory growth; once exceeded the map is cleared. Forgetting an
# entry is safe: a chunk with no buffer and no cache entry falls back to the
# session row (``Assembler._resolve_unbuffered``), which records the seal mode.
_FINALIZED_MAX = 10_000

# What a chunk with no in-memory buffer may do, decided from the session row.
UnbufferedAction = Literal["promote", "reopen", "ignore", "adopt"]


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
    shell_user: str | None = None  # envelope session_start only; header wins
    first_ts: str | None = None
    last_ts: str | None = None
    request_id: str | None = None  # k8s exec/attach only; first chunk carrying one wins
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

    Connections without a recording live only in the ``connections`` table
    (``pending`` / ``api`` / ``error``) until a chunk promotes them; see the module
    docstring and kubectl activity spec §6.
    """

    def __init__(
        self,
        repo: SessionRepository,
        casts: CastStore,
        idle_timeout_seconds: int,
        clock: Callable[[], float] = time.monotonic,
        *,
        activity: ActivityStore,
        session_max_idle_seconds: int = 3600,
        search: SearchStore | None = None,
        detection_enabled: bool = True,
    ) -> None:
        """Initialize the assembler.

        Args:
            repo: Session metadata repository (all SQL).
            casts: Cast file store (all ``.cast`` file I/O).
            activity: Connection + API-request store. Holds pending connections
                (so they survive restarts) and the deduplicated API audit metadata.
            idle_timeout_seconds: Sweep granularity / startup-sweep cutoff. Not a
                finalize trigger: it sets how often the idle sweep runs (see
                ``main``) and, on restart, the age past which a provisional row with
                no ``.cast`` is treated as an abandoned start and swept.
            clock: Monotonic clock source (injectable for tests).
            session_max_idle_seconds: Idle backstop for a session that never got its
                terminal ``"session finished"`` flush. After this much silence a
                buffer *with* data is sealed reopenably (a still-later chunk reopens
                and extends it), and a *pending* connection (authenticated, but no
                chunk and no API audit line) becomes a visible ``error`` session
                row. Must exceed the Gateway's flush interval (a quiet-but-active
                session is chunkless until its first flush) and, under encryption,
                also bounds how long a recording stays plaintext on disk before it
                seals. Pending connections are aged on SQLite wall-clock time
                (``last_seen_at``), not on ``clock``, so the backstop survives
                restarts.
            search: Optional findings/search store. When provided (and
                ``detection_enabled``), detection runs live on every append and the
                encrypted search sidecar is written at seal. When ``None`` no cast
                scan runs.
            detection_enabled: Master switch for detection. Gates the cast scan
                (which also needs ``search``) and the API-request rules.
        """
        self._repo = repo
        self._casts = casts
        self._activity = activity
        self._idle = idle_timeout_seconds
        self._max_idle = session_max_idle_seconds
        self._clock = clock
        self._search = search
        self._detection_enabled = detection_enabled
        self._buffers: dict[str, InProgress] = {}
        self._lock = asyncio.Lock()
        # conn_ids already sealed. Value = reopenable: True means a late chunk should
        # reopen (decrypt → append → re-seal); False means the session ended
        # terminally ("session finished"/close) and late chunks are ignored. A cache
        # only: the seal mode is persisted on the session row, and a miss falls back
        # to it (``_resolve_unbuffered``). Bounded (see ``_FINALIZED_MAX``).
        self._sealed: dict[str, bool] = {}
        # Debug counter: late chunks/starts ignored because their conn_id is sealed
        # terminally (or, for a legacy row, with an unknown seal mode).
        self._ignored_finalized = 0
        # Envelope-format start lines carry the OS account (``shell_user``), which the
        # ``connections`` table has no column for. Held here between the start line
        # and the promoting chunk so envelope recordings keep it (secondary detail;
        # lost on restart). Bounded like ``_sealed``.
        self._pending_shell_user: dict[str, str] = {}

    @property
    def active_count(self) -> int:
        """Number of sessions currently in progress (provisional, buffering)."""
        return len(self._buffers)

    async def handle(
        self, event: RecordingChunk | SessionStart | SessionEnd | ApiRequest
    ) -> None:
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
            case ApiRequest():
                await self._on_api(event)

    async def _on_start(self, event: SessionStart) -> None:
        """Record an authenticated connection as a *pending* connection.

        Writes only the ``connections`` row (identity, cluster, start time); no
        ``sessions`` row is created, so an API-only connection never appears as a
        recording. If a chunk already arrived for this ``conn_id`` (start line
        delivered late), the in-progress buffer is annotated and its provisional row
        refreshed as before.
        """
        async with self._lock:
            if event.conn_id in self._sealed:
                # Already sealed (terminal or reopenable). A bare start carries no
                # recording data, so there is nothing to reopen for — ignore it.
                self._ignored_finalized += 1
                log.debug("assembler.ignore_sealed", phase="start")
                return
            await self._activity.upsert_connection_start(
                conn_id=event.conn_id,
                user_id=event.user_id,
                username=event.username,
                resource_address=event.resource_address,
                started_at=event.ts,
            )
            buf = self._buffers.get(event.conn_id)
            if buf is None:
                # Pending connection only. A chunk promotes it; an audit line marks
                # it ``api``; neither within the backstop expires it to ``error``.
                if event.shell_user is not None:
                    self._remember_shell_user(event.conn_id, event.shell_user)
                return
            # A chunk arrived before the start line: the connection is already
            # recording. Keep its state there (the upsert above never changes state,
            # but a row inserted just now would be ``pending``).
            await self._activity.set_state(event.conn_id, "recording")
            if event.resource_address is not None:
                buf.resource_address = event.resource_address
            if event.username is not None:
                buf.username = event.username
            if event.shell_user is not None:
                buf.shell_user = event.shell_user
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
        """Store a chunk, persist the growing plaintext ``.cast``, and scan live.

        A chunk with no in-memory buffer is resolved first. The ``_sealed`` cache
        answers when it has an entry (terminal → ignore, reopenable → reopen);
        otherwise :meth:`_resolve_unbuffered` decides from the session row, which
        covers a restart and a cache eviction alike. The first chunk of a new
        connection promotes it (``pending``, ``api``, ``error``, or not yet seen) to
        ``recording`` and creates the ``provisional`` session row.

        Invariant: :meth:`_persist` — and so ``CastStore.write_plaintext`` — is
        reached only for a buffer created by promote, adopt, or reopen. A sealed
        ``.cast`` is therefore never rewritten without its full text as the buffer's
        baseline. Chunk content is never logged.
        """
        async with self._lock:
            conn_id = event.conn_id
            buf = self._buffers.get(conn_id)
            if buf is None:
                sealed_reopenable = self._sealed.get(conn_id)
                if sealed_reopenable is False:
                    # Terminally ended ("session finished"/close): a late/redelivered
                    # chunk must not reopen or clobber the file. Never log content.
                    self._ignored_finalized += 1
                    log.debug("assembler.ignore_sealed", phase="chunk", source="cache")
                    return
                if sealed_reopenable is True:
                    buf = await self._reopen_sealed(conn_id, source="cache")
                else:
                    action = await self._resolve_unbuffered(conn_id)
                    if action == "ignore":
                        return
                    if action == "reopen":
                        buf = await self._reopen_sealed(conn_id, source="db")
                    elif action == "adopt":
                        buf = await self._adopt_provisional(conn_id, self._clock())
                        log.info("assembler.adopt", conn_id=conn_id)
                    else:
                        buf = await self._promote(conn_id)
                self._buffers[conn_id] = buf

            buf.chunks[event.seq] = event.asciicast  # last write wins → dup-safe
            if event.request_id is not None and buf.request_id is None:
                buf.request_id = event.request_id
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

    async def _promote(self, conn_id: str) -> InProgress:
        """Promote a connection to ``recording`` on its first chunk; return its buffer.

        Seeds the new buffer (identity, cluster, start time) from the connection's
        start line, recovers a backstop ``error`` row if there is one (a late chunk
        reverts it to ``provisional``), creates/refreshes the ``provisional`` session
        row, and marks the connection ``recording`` (``has_api`` is kept). A chunk
        with no start line seen inserts a minimal ``recording`` connection, so a
        start line arriving later never leaves it ``pending``. Caller holds the lock.

        Only for a connection with no recording yet: no row, a ``provisional`` row
        with no ``.cast`` on disk, or a failed connection (``error``, no
        ``cast_path``). A sealed row never reaches here — :meth:`_resolve_unbuffered`
        ignores or reopens it — because the buffer this returns starts empty, and
        the next :meth:`_persist` would replace the sealed file with the new chunks
        alone.
        """
        conn = await self._activity.get_connection(conn_id)
        buf = InProgress(conn_id=conn_id)
        if conn is not None:
            buf.username = conn.username
            buf.resource_address = conn.resource_address
            buf.first_ts = conn.started_at
        buf.shell_user = self._pending_shell_user.pop(conn_id, None)
        # A connection the backstop had expired (started but never recorded) has a
        # visible 'error' row; revert it first so the upsert below can refresh it.
        # No-op for a fresh connection.
        await self._repo.revert_error_to_provisional(conn_id)
        await self._repo.upsert_start(
            conn_id=conn_id,
            username=buf.username,
            resource_address=buf.resource_address,
            started_at=buf.first_ts,
        )
        await self._activity.set_state(conn_id, "recording")
        log.info(
            "assembler.promote",
            conn_id=conn_id,
            from_state=conn.state if conn is not None else None,
        )
        return buf

    async def _resolve_unbuffered(self, conn_id: str) -> UnbufferedAction:
        """Decide what a chunk with no buffer and no ``_sealed`` entry may do.

        The session row is authoritative (one primary-key lookup per buffer miss,
        i.e. once per session, not per chunk):

        * no row, no ``.cast`` → ``promote`` (a new connection's first chunk);
        * no row, a non-empty ``.cast`` → ``ignore``: an orphan file whose row is
          gone is never overwritten;
        * ``provisional`` with a non-empty ``.cast`` → ``adopt`` its text as the
          baseline (as :meth:`sweep_startup` does); without one → ``promote``;
        * ``error`` with no ``cast_path`` (a failed connection) → ``promote``, which
          recovers it through ``revert_error_to_provisional``;
        * sealed (``complete``, or ``error`` with a ``cast_path``) whose ``.cast`` is
          missing → ``ignore`` with a warning; nothing is written;
        * sealed reopenably (``sealed_terminal`` 0) → ``reopen``;
        * sealed terminally (1) or before the column existed (``NULL``) →
          ``ignore``, counted and re-cached as terminal. Legacy ``NULL`` is treated
          as terminal because the likely trigger is a shipper redelivering its
          buffer, and reopening would append those chunks as duplicate events.

        Caller holds the lock. Logs carry ``conn_id`` and phase/source only, never
        chunk content.

        Args:
            conn_id: The connection id of the unbuffered chunk.

        Returns:
            The action for :meth:`_on_chunk` to take.
        """
        row = await self._repo.get(conn_id)
        path = self._casts.path_for(conn_id)
        if row is None:
            if self._has_nonempty_file(path):
                log.warning("assembler.orphan_cast_skip", conn_id=conn_id)
                return "ignore"
            return "promote"
        if row.status == "provisional":
            return "adopt" if self._has_nonempty_file(path) else "promote"
        if row.status == "error" and row.cast_path is None:
            return "promote"
        if row.status in ("complete", "error"):
            if not path.is_file():
                log.warning("assembler.sealed_cast_missing", conn_id=conn_id)
                return "ignore"
            if row.sealed_terminal is False:
                return "reopen"
            self._ignored_finalized += 1
            log.debug("assembler.ignore_sealed", phase="chunk", source="db")
            self._mark_sealed(conn_id, False)
            return "ignore"
        # Defensive: an unknown status is never written over.
        log.warning("assembler.unknown_status_skip", conn_id=conn_id)
        return "ignore"

    async def _reopen_sealed(self, conn_id: str, *, source: str) -> InProgress:
        """Reopen a reopenably-sealed session and return its buffer.

        Decrypts the sealed file back to plaintext (``CastStore.reopen``), reverts
        the row to ``provisional`` (``SessionRepository.reopen``, which also clears
        ``sealed_terminal``), and seeds the buffer with the full prior text as its
        baseline so appends extend it. Caller holds the lock.

        Args:
            conn_id: The connection id to reopen.
            source: ``"cache"`` (from ``_sealed``) or ``"db"`` (from the session
                row); logged for diagnostics.

        Returns:
            The new in-progress buffer.
        """
        baseline = await self._casts.reopen(conn_id)
        await self._repo.reopen(conn_id)
        self._sealed.pop(conn_id, None)
        log.info("assembler.reopen", conn_id=conn_id, source=source)
        return InProgress(conn_id=conn_id, baseline=baseline)

    async def _adopt_provisional(self, conn_id: str, now: float) -> InProgress:
        """Build a buffer for a ``provisional`` row from its on-disk plaintext ``.cast``.

        In-progress files are plaintext (only sealed rows are encrypted), so the file
        text becomes the buffer's baseline and continuation chunks append after it.
        Used by :meth:`sweep_startup` and by :meth:`_on_chunk` on a buffer miss.
        Caller holds the lock and has checked the file is non-empty.

        Args:
            conn_id: The connection id to adopt.
            now: Monotonic time to stamp as the buffer's last activity.

        Returns:
            The adopted in-progress buffer (not yet registered in ``_buffers``).
        """
        baseline = await self._casts.read_plaintext(self._casts.path_for(conn_id))
        return InProgress(conn_id=conn_id, baseline=baseline, last_activity=now)

    async def _on_api(self, event: ApiRequest) -> None:
        """Store one API audit line and advance its connection's state.

        Deduplicated by ``request_id``: a redelivered line is a no-op (no second
        row, no duplicate findings, no state change). The API rules run on the
        method + path first (pure and cheap, only when detection is enabled); the
        request — with the connection's cluster, ``NULL`` until the start line
        backfills it — and its findings are then stored in one transaction, so a
        crash or DB error between them can never leave a request whose findings a
        redelivery would skip as a duplicate. If detection itself raises, the
        request is still stored (without findings) and the exception type is
        logged. The connection then moves to ``api`` — or stays ``recording`` if it
        carries a recording (e.g. an exec's status-101 line). A connection the
        backstop had expired to ``error`` loses its phantom start-only error row:
        it was API-only after all. Never logs the URL, header values, or the raw
        line.
        """
        async with self._lock:
            conn_id = event.conn_id
            findings: list[Finding] = []
            if self._detection_enabled:
                try:
                    findings = list(detect_api(event.method, event.url))
                except Exception as exc:
                    # Detection failure forfeits only the findings; the request is
                    # still stored below. Exception type only (rule 5).
                    findings = []
                    log.warning(
                        "assembler.api_detect_error",
                        conn_id=conn_id,
                        error=type(exc).__name__,
                    )

            conn = await self._activity.get_connection(conn_id)
            resource_address = conn.resource_address if conn is not None else None
            inserted = await self._activity.insert_request_with_findings(
                event, resource_address, findings
            )
            if not inserted:
                log.debug("assembler.api_duplicate", conn_id=conn_id)
                return
            finding_count = len(findings)

            is_recording = (
                conn_id in self._buffers
                or conn_id in self._sealed
                or (conn is not None and conn.state == "recording")
            )
            if is_recording:
                await self._activity.set_state(conn_id, "recording", has_api=True)
            else:
                if conn is not None and conn.state == "error":
                    # A late audit (e.g. a long `get -w`) on an expired connection.
                    await self._repo.delete_start_only_error(conn_id)
                await self._activity.set_state(conn_id, "api", has_api=True)
                self._pending_shell_user.pop(conn_id, None)
            log.debug(
                "assembler.api_request",
                conn_id=conn_id,
                findings=finding_count,
                recording=is_recording,
            )

    async def finalize(self, conn_id: str) -> None:
        """Seal a connection terminally (end signal / close). Idempotent no-op if unknown."""
        async with self._lock:
            buf = self._buffers.pop(conn_id, None)
            if buf is None:
                return
            await self._seal(buf, reopenable=False)

    async def finalize_idle(self) -> None:
        """Idle backstop sweep. Intended to run on an APScheduler interval.

        Resolves anything silent for at least ``session_max_idle`` — normally the
        Gateway's ``"session finished"`` flush ends a session long before this, so
        reaching the backstop means that signal never came:

          * **Recording with data** → seal *reopenably* (encrypt if enabled, mark
            ``complete``). The on-disk recording is preserved; a still-later chunk
            reopens and extends it, so nothing is lost.
          * **Pending connection** (authenticated, but no chunk and no API audit
            line) → ``expire_pending`` flips it to ``error`` and a visible ``error``
            session row is created for it. The connection never delivered a single
            valid recording chunk within the window — a failed recording (most often
            the transport mangled/dropped every chunk; see the journald ``LineMax``
            note in INGESTION_RECIPES §2.1). A genuinely-late chunk still recovers it
            (``_promote`` reverts ``error`` → ``provisional``); a late API audit
            deletes the row instead (``_on_api``). Aged on SQLite wall-clock
            ``last_seen_at``, so it is correct across restarts. ``api`` connections
            are never expired: they have no visible row to resolve.

        The backstop must exceed the Gateway's flush interval: a quiet-but-active
        session is *expected* to be chunkless until its first flush, so
        ``session_max_idle`` has to be long enough that a real session always flushes
        at least once before it is judged a failed recording.
        """
        now = self._clock()
        async with self._lock:
            stale = [
                conn_id
                for conn_id, buf in self._buffers.items()
                if now - buf.last_activity >= self._max_idle
            ]
            for conn_id in stale:
                buf = self._buffers.pop(conn_id)
                if buf.has_data:
                    log.info("assembler.backstop_seal", conn_id=conn_id)
                    await self._seal(buf, reopenable=True)
                else:
                    # Defensive: buffers are created only by a chunk or a re-adopted
                    # non-empty .cast, so one without data should not exist.
                    await self._repo.mark_error_if_provisional(conn_id)
                    log.warning("assembler.empty_error", conn_id=conn_id)
            await self._expire_pending_connections()

    async def _expire_pending_connections(self) -> None:
        """Turn pending connections past the backstop into visible ``error`` rows.

        Caller holds the lock. Each expired connection gets a session row built
        from its start line (``upsert_start``) and is then marked ``error``
        (``mark_error_if_provisional``) — the same visible row a start-only session
        produced before connections were tracked separately. Logged as a counter.
        """
        expired = await self._activity.expire_pending(self._max_idle)
        errored = 0
        for conn in expired:
            self._pending_shell_user.pop(conn.conn_id, None)
            if conn.conn_id in self._buffers or conn.conn_id in self._sealed:
                # Defensive: this conn_id is actually recording (e.g. a session
                # re-adopted at startup whose start line was redelivered). Never
                # error a live recording; restore its connection state instead.
                await self._activity.set_state(conn.conn_id, "recording")
                continue
            await self._repo.upsert_start(
                conn_id=conn.conn_id,
                username=conn.username,
                resource_address=conn.resource_address,
                started_at=conn.started_at,
            )
            await self._repo.mark_error_if_provisional(conn.conn_id)
            errored += 1
        if errored:
            log.warning("assembler.pending_expired", count=errored)

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
                if self._has_nonempty_file(self._casts.path_for(conn_id)):
                    self._buffers[conn_id] = await self._adopt_provisional(conn_id, now)
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
            conn_id=buf.conn_id,
            username=buf.username,
            started_at=buf.first_ts,
            request_id=buf.request_id,
        )
        await self._repo.update_progress(
            buf.conn_id,
            username=buf.username,
            # Header-derived shell user wins (legacy format); envelope headers
            # carry no user field, so fall back to the session_start's value.
            shell_user=meta.shell_user or buf.shell_user,
            started_at=meta.started_at,
            ended_at=buf.last_ts,
            duration_seconds=meta.duration_seconds,
            width=meta.width,
            height=meta.height,
            chunk_count=len(buf.chunks),
            size_bytes=size,
            cast_path=str(path),
            request_id=buf.request_id,
        )
        return cast_text

    async def _seal(self, buf: InProgress, *, reopenable: bool) -> None:
        """Seal an in-progress recording: final scan, encrypt, mark complete.

        Writes the search sidecar and runs a final detection pass over the plaintext,
        then encrypts the ``.cast`` (a no-op when encryption is disabled) and marks the
        row ``complete`` (or ``error`` if it never carried a valid header). The seal
        mode is persisted on the row (``sealed_terminal = not reopenable``) and cached
        in ``_sealed``, so a late chunk is either ignored (terminal) or reopens the
        session (backstop) — before or after a restart. Caller holds the lock and has
        already removed ``buf`` from the active map.
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
            shell_user=meta.shell_user or buf.shell_user,
            started_at=meta.started_at,
            ended_at=buf.last_ts,
            duration_seconds=meta.duration_seconds,
            width=meta.width,
            height=meta.height,
            chunk_count=len(buf.chunks),
            size_bytes=size,
            cast_path=str(path),
            status=status,
            sealed_terminal=not reopenable,
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

    def _remember_shell_user(self, conn_id: str, shell_user: str) -> None:
        """Hold a pending connection's envelope ``shell_user`` until it is promoted.

        Caller holds the lock. Bounded: cleared once it exceeds ``_FINALIZED_MAX``;
        forgetting an entry only drops secondary detail for an envelope recording.
        """
        if len(self._pending_shell_user) >= _FINALIZED_MAX:
            self._pending_shell_user.clear()
        self._pending_shell_user[conn_id] = shell_user

    def _mark_sealed(self, conn_id: str, reopenable: bool) -> None:
        """Cache a conn_id as sealed (``reopenable`` flag). Caller holds the lock.

        Bounded: clears the map once it exceeds ``_FINALIZED_MAX`` to keep memory flat.
        The map is a cache only — the seal mode is persisted on the session row — so
        a miss after eviction falls back to the session row
        (:meth:`_resolve_unbuffered`) and never re-buffers a sealed recording.
        """
        if len(self._sealed) >= _FINALIZED_MAX:
            self._sealed.clear()
        self._sealed[conn_id] = reopenable

    @staticmethod
    def _has_nonempty_file(path: Path) -> bool:
        """True if ``path`` is a regular file with at least one byte.

        A ``stat`` failure propagates rather than reading as "absent", so an
        unreadable file is never treated as free to overwrite.
        """
        return path.is_file() and path.stat().st_size > 0

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
