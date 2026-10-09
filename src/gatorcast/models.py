"""Shared data models.

Holds the persisted session shape plus the pipeline event models the classifier
emits and the assembler consumes. Recording payloads themselves are never modeled
here — they live in the .cast file on the volume (CLAUDE.md rule 9).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


RESOURCE_TYPE_INVALID = "invalid"
"""Stored ``connections.resource_type`` for a start line whose ``resource_type`` was
present but unusable (WEBAPP_SPEC 4.1). Lower case, so it can never equal a real
normalized value (those match ``[A-Z][A-Z0-9_]{0,31}``). It is a non-null,
non-``KUBERNETES`` type: its requests are stored under the web policy with no rules.
It is an internal marker: it is never copied to ``sessions.resource_type`` and is
never shown as a type label."""


class GwopsWebApp(BaseModel):
    """Validated ``gwops`` object from a ``WEB_APP`` start line (WEBAPP_SPEC 3.3, 4.1).

    Configured state as gwops read it when it shipped the line, not proof of a
    negotiated TLS mode. Constructed only by ``classify._classify_gwops`` from
    explicitly validated primitives; never built by ``model_validate`` on the raw
    object. Invariant (held by the constructor, not re-checked here): for
    ``match == "exact"`` the ``managed``, both TLS modes and both ports are non-null;
    for ``none`` / ``ambiguous`` every field after ``gateway_id`` is ``None``.
    """

    model_config = ConfigDict(frozen=True)

    match: Literal["exact", "none", "ambiguous"]
    gateway_id: str | None
    """Opaque Twingate gateway id; ``None`` in gwops Mode B before its first reconcile."""
    app: str | None = None
    """Display-only app name (``exact`` only); ``None`` when absent or when check 10 failed."""
    managed: bool | None = None
    downstream_tls: Literal["tls13", "none"] | None = None
    downstream_port: int | None = None
    upstream_tls: Literal["verify_full", "verify_ca", "insecure", "none"] | None = None
    upstream_port: int | None = None


class GwopsSnapshot(BaseModel):
    """The per-connection ``gwops``/TLS snapshot as stored on ``connections``.

    Mirrors the eight snapshot columns (WEBAPP_SPEC 3.3 "What is stored", 4.3).
    Fixed on the first processing of the connection's start line and never
    rewritten (first write wins). Configured state, not proof of a negotiated
    mode. Every field is ``None`` for a connection with no valid object (TLS
    unknown). Field types are plain strings and ints, not the contract ``Literal``
    types: this is a read model over stored values and must not raise on a row
    written by another version.

    Never log an instance: ``gwops_app`` and ``gwops_gateway_id`` are never logged
    (WEBAPP_SPEC 4.4).
    """

    model_config = ConfigDict(frozen=True)

    gwops_match: str | None = None
    gwops_gateway_id: str | None = Field(default=None, repr=False)
    gwops_app: str | None = Field(default=None, repr=False)
    gwops_managed: bool | None = None
    downstream_tls: str | None = None
    downstream_port: int | None = None
    upstream_tls: str | None = None
    upstream_port: int | None = None


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
    resource_type: str | None = None
    """Normalized Gateway ``resource_type`` copied from the connection at promote
    (for example ``SSH``, ``KUBERNETES``), or ``None`` when unknown. Display and CSV
    export detail only (WEBAPP_SPEC §8.7 column 16); never identity (CLAUDE.md rule 4).
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
    resource_type: str | None = None
    """Normalized Gateway ``resource_type`` (for example ``KUBERNETES``, ``WEB_APP``).

    The raw value stripped and upper-cased, kept only when it fullmatches
    ``[A-Z][A-Z0-9_]{0,31}``. ``None`` when the field is absent (treated as a
    pre-upgrade Kubernetes connection) and always ``None`` for envelope-format
    starts. :data:`RESOURCE_TYPE_INVALID` when the field is present but unusable
    (not a string, or it fails the pattern): that is fail-closed like any other
    non-Kubernetes type. Set by the legacy ``Authenticated connection`` branch only.
    """
    gwops: GwopsWebApp | None = None
    """Validated ``gwops`` object, read only when ``resource_type == "WEB_APP"``.

    ``None`` when the object is absent, rejected, or the connection is not a web app;
    the rest of the event is identical in every one of those cases (TLS unknown).
    """


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
    url_web: str
    """Web-policy storage form of the same raw URL (``webmask.store_web_url``).

    Normalized path, masked query values. Chosen over ``url`` by the assembler for
    ``WEB_APP`` (and any other non-Kubernetes) connections. Required: ``classify``
    always sets it, and a hand-built request must say which form it carries.
    """
    status_code: int | None = None
    outcome: str = "completed"
    """``"completed"`` or ``"failed"``."""
    kubectl_command: str | None = None
    kubectl_session: str | None = None
    user_agent: str | None = None
