"""Classify a normalized Gateway log object into a pipeline event (or drop it).

The single source of truth for "what is this line". Three event types matter
(CLAUDE.md rule 2, TECHNICAL_PLAN "Classification"):

  * **RecordingChunk** — ``logger == "gateway.audit"`` *and* a non-null ``asciicast``.
    The logger check alone is insufficient: ``gateway.audit`` also carries
    API-request audits with no recording, which must be dropped.
  * **SessionStart** — ``logger == "gateway"`` with ``message == "Authenticated
    connection"``. Carries the target ``resource_address``.
  * **SessionEnd** — a connection-close signal (Open Validation Item 2: shape not
    yet confirmed; idle timeout is the authoritative finalize path).

Everything else (operational noise, API audits) returns ``None`` and is dropped.

``conn_id`` is the demux key and is used to name the on-disk ``.cast`` file, so it
is validated against a strict pattern here — this is the single choke point that
prevents path traversal or odd keys from a forged line (CLAUDE.md rule 5).
"""

from __future__ import annotations

import re

from gatorcast.logging import get_logger
from gatorcast.models import RecordingChunk, SessionEnd, SessionStart

log = get_logger(__name__)

Event = RecordingChunk | SessionStart | SessionEnd

# conn_id is a Gateway-issued UUID. Constrain it to a safe token: it becomes the
# .cast filename, so reject anything that could escape the casts directory or be
# otherwise hostile. Real values match this; anything else is dropped.
_SAFE_CONN_ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")

# The Gateway's session recorder emits its final flush with this message (from
# recorder.Stop()). The line still carries the last asciicast chunk, so it is
# classified as a RecordingChunk with is_final=True: the assembler stores it and
# then finalizes the connection immediately. If the Gateway ever renames this,
# recordings still finalize via the idle backstop — this is an optimization, not
# a dependency. Kept as a single named constant so it is trivial to adjust.
_FINAL_RECORDING_MESSAGE = "session finished"

# Candidate connection-close messages on the plain "gateway" logger. The recorder's
# "session finished" (above) is the authoritative end signal; these remain wired as
# a defensive fallback for a close event that carries no asciicast payload.
_CLOSE_MESSAGES = frozenset({"Connection closed", "Closed connection"})


def _safe_conn_id(obj: dict) -> str | None:
    """Return ``obj['conn_id']`` if present and safe to use as a filename, else None."""
    conn_id = obj.get("conn_id")
    if isinstance(conn_id, str) and _SAFE_CONN_ID.match(conn_id):
        return conn_id
    return None


def _username(obj: dict) -> str | None:
    """Extract the envelope SSO identity (``user.username``) defensively."""
    user = obj.get("user")
    if isinstance(user, dict):
        username = user.get("username")
        if isinstance(username, str):
            return username
    return None


def classify(obj: dict) -> Event | None:
    """Classify one normalized log object into a pipeline event.

    Args:
        obj: A JSON object produced by ``normalize`` (or a parsed ``/ingest`` item).

    Returns:
        A ``RecordingChunk``, ``SessionStart``, or ``SessionEnd`` event, or
        ``None`` if the object is operational noise or cannot be safely keyed.
    """
    logger = obj.get("logger")

    # 1. Recording chunk: gateway.audit AND a non-null asciicast string.
    if logger == "gateway.audit" and obj.get("asciicast") is not None:
        asciicast = obj.get("asciicast")
        if not isinstance(asciicast, str):
            log.debug("classify.drop", reason="asciicast_not_string")
            return None
        conn_id = _safe_conn_id(obj)
        if conn_id is None:
            log.debug("classify.drop", reason="chunk_bad_conn_id")
            return None
        seq = obj.get("asciicast_sequence_num")
        # The ordering key is mandatory — without it chunks cannot be sequenced,
        # and a missing key cannot safely default (it would collide across flushes).
        if not isinstance(seq, int) or isinstance(seq, bool):
            log.debug("classify.drop", reason="chunk_bad_seq")
            return None
        return RecordingChunk(
            conn_id=conn_id,
            seq=seq,
            asciicast=asciicast,
            username=_username(obj),
            ts=obj.get("ts"),
            is_final=obj.get("message") == _FINAL_RECORDING_MESSAGE,
        )

    # 2. Session start: gateway "Authenticated connection".
    if logger == "gateway" and obj.get("message") == "Authenticated connection":
        conn_id = _safe_conn_id(obj)
        if conn_id is None:
            log.debug("classify.drop", reason="start_bad_conn_id")
            return None
        resource_address = obj.get("resource_address")
        return SessionStart(
            conn_id=conn_id,
            resource_address=(
                resource_address if isinstance(resource_address, str) else None
            ),
            username=_username(obj),
            ts=obj.get("ts"),
        )

    # 3. Session end (close-event hook — see _CLOSE_MESSAGES note).
    if logger == "gateway" and obj.get("message") in _CLOSE_MESSAGES:
        conn_id = _safe_conn_id(obj)
        if conn_id is not None:
            return SessionEnd(conn_id=conn_id, ts=obj.get("ts"))

    # Everything else is operational noise / API audits → drop.
    return None
