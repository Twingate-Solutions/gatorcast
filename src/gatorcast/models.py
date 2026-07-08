"""Shared data models.

Holds the persisted session shape plus the pipeline event models the classifier
emits and the assembler consumes. Recording payloads themselves are never modeled
here — they live in the .cast file on the volume (CLAUDE.md rule 9).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class Session(BaseModel):
    """A recorded session as stored in the metadata database.

    Mirrors the ``sessions`` table. Recording payloads live in the .cast file
    referenced by ``cast_path``; this model carries metadata only.
    """

    conn_id: str
    username: str | None = None
    resource_address: str | None = None
    shell_user: str | None = None
    started_at: str | None = None
    ended_at: str | None = None
    duration_seconds: float | None = None
    width: int | None = None
    height: int | None = None
    chunk_count: int = 0
    size_bytes: int = 0
    cast_path: str | None = None
    status: str = "provisional"
    finding_count: int = 0
    max_severity: str | None = None


class RecordingChunk(BaseModel):
    """One flushed asciicast fragment of a recording.

    Emitted by ``classify`` for a ``gateway.audit`` line that carries a non-null
    ``asciicast``. Fragments are demuxed by ``conn_id`` and ordered by ``seq``;
    the assembler concatenates them (in seq order) before parsing.
    """

    model_config = ConfigDict(frozen=True)

    conn_id: str
    seq: int
    asciicast: str
    username: str | None = None
    ts: str | None = None
    is_final: bool = False
    """True when this chunk is the Gateway's final flush for the connection.

    The Gateway emits its last flush with ``message == "session finished"`` (from
    the recorder's ``Stop()``). It is both the last data chunk and a reliable
    end-of-session signal, so the assembler finalizes immediately on receiving it
    rather than waiting for the idle backstop.
    """


class SessionStart(BaseModel):
    """An authenticated-connection event that pre-registers a session.

    Emitted by ``classify`` for a ``gateway`` ``"Authenticated connection"`` line.
    Carries the target ``resource_address`` (the UI "system") and the SSO identity.
    """

    model_config = ConfigDict(frozen=True)

    conn_id: str
    resource_address: str | None = None
    username: str | None = None
    ts: str | None = None


class SessionEnd(BaseModel):
    """A connection-close signal that finalizes a session immediately.

    Open Validation Item 2: the Gateway's close-event shape is not yet confirmed,
    so this is produced only for candidate close messages. The idle timeout remains
    the authoritative finalize path.
    """

    model_config = ConfigDict(frozen=True)

    conn_id: str
    ts: str | None = None
