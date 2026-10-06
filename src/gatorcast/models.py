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
    request_id: str | None = None
    """Gateway request UUID of a Kubernetes exec/attach recording (``None`` for SSH).

    Equals the ``request_id`` of the exec's status-101 API audit line, which is how
    kubectl activity links a command to this recording.
    """
    sealed_terminal: bool | None = None
    """How the row was last sealed: ``True`` terminally ("session finished" / close),
    ``False`` reopenably (idle backstop). ``None`` when not sealed, or sealed before
    this column existed (legacy; the assembler treats a sealed ``None`` as terminal).
    """


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
    request_id: str | None = None
    """Gateway request UUID carried by Kubernetes exec/attach chunk lines.

    Matches the ``request_id`` of the exec's status-101 API audit line, which is
    how an activity command links to its recording. SSH chunks carry none.
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
    user_id: str | None = None
    """Gateway user id (``user.id``). Set by the legacy log-line branch only."""
    shell_user: str | None = None
    """Resolved OS account, when the source carries it (envelope wire format only).

    Secondary detail — never identity (CLAUDE.md rule 4). Legacy log lines never
    set this; the legacy path derives shell_user from the asciicast header instead.
    """
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


class ApiRequest(BaseModel):
    """One stock Gateway API-request audit line (metadata only, allowlisted).

    Emitted by ``classify`` for a ``gateway.audit`` line with no ``asciicast``
    whose message is ``"API request completed"`` or ``"API request failed"``.
    Only allowlisted fields are modeled: no ``Authorization`` value, cookie, other
    request header, response header, ``remote_addr``, or ``panic`` text is ever
    carried (CLAUDE.md rule 2).
    """

    model_config = ConfigDict(frozen=True)

    conn_id: str
    request_id: str
    """Gateway UUID, or a synthesized ``"h:<hex>"`` id when the line carries none."""
    requested_at: str
    """Normalized UTC timestamp, ``YYYY-MM-DDTHH:MM:SS.mmmZ``."""
    user_id: str | None = None
    username: str | None = None
    """Envelope SSO identity (``user.username``); identity per CLAUDE.md rule 4."""
    method: str
    url: str
    """Sanitized by ``classify._store_url`` (exec/attach query stripped)."""
    status_code: int | None = None
    outcome: str = "completed"
    """``"completed"`` or ``"failed"``."""
    kubectl_command: str | None = None
    kubectl_session: str | None = None
    user_agent: str | None = None
