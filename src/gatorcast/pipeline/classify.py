"""Classify a normalized Gateway log object into a pipeline event (or drop it).

The single source of truth for "what is this line". Two wire formats are
recognized; both map onto the same three pipeline events.

**Legacy log-line format** (CLAUDE.md rule 2, TECHNICAL_PLAN "Classification"):

  * **RecordingChunk** — ``logger == "gateway.audit"`` *and* a non-null ``asciicast``.
    The logger check alone is insufficient: ``gateway.audit`` also carries
    API-request audits with no recording, which must be dropped.
  * **SessionStart** — ``logger == "gateway"`` with ``message == "Authenticated
    connection"``. Carries the target ``resource_address``.
  * **SessionEnd** — a connection-close signal (Open Validation Item 2: shape not
    yet confirmed; idle timeout is the authoritative finalize path).

**Envelope format** (gateway fork POC — recording sink POSTing NDJSON directly;
spec: the fork's ``claudedocs/envelope-wire-spec.md``): self-describing records
with a ``"type"`` discriminator and *no* ``"logger"`` field. Support is strictly
additive — these records previously matched nothing and were silently dropped;
legacy classification is untouched, so existing shipping recipes keep working.

Everything else (operational noise, API audits) returns ``None`` and is dropped.

``conn_id`` is the demux key and is used to name the on-disk ``.cast`` file, so it
is validated against a strict pattern here — this is the single choke point that
prevents path traversal or odd keys from a forged line (CLAUDE.md rule 5).
"""

from __future__ import annotations

import base64
import json
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

# Envelope-format record types (fork recording sink). The discriminator is the
# "type" field on a record that carries no "logger" — legacy log lines always
# carry "logger", so this can never divert one.
_ENVELOPE_TYPES = frozenset({"session_start", "recording_chunk", "session_end"})


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


def _envelope_chunk_text(obj: dict) -> str | None:
    """Synthesize legacy-shaped chunk text from an envelope ``recording_chunk``.

    The envelope carries the asciicast header as a JSON object (seq 1 only) and
    the event lines as a newline-terminated string under ``events``. The
    synthesized text — header line (when present) + events — is exactly what
    ``reassemble_asciicast`` already consumes (first object line = header, array
    lines = events), so the assembler needs no changes.

    Returns:
        The chunk text, or ``None`` when ``events`` is missing/invalid (drop).
    """
    events = obj.get("events")
    if not isinstance(events, str):
        return None
    encoding = obj.get("encoding", "utf-8")
    if encoding == "base64":
        # Reserved byte-exact mode (spec §1): not emitted by current builds, but
        # cheap to honor. A malformed payload drops the chunk rather than corrupt
        # the document.
        try:
            events = base64.b64decode(events, validate=True).decode(
                "utf-8", errors="replace"
            )
        except (ValueError, TypeError):
            return None
    elif encoding != "utf-8":
        # Unknown future encoding: store the raw string rather than lose data
        # (spec recommendation); reassembly drops non-JSON lines defensively.
        log.debug("classify.envelope", reason="unknown_encoding")
    header = obj.get("header")
    if isinstance(header, dict):
        return json.dumps(header, separators=(",", ":")) + "\n" + events
    return events


def _classify_envelope(obj: dict, etype: str) -> Event | None:
    """Classify one envelope-format record (fork recording sink) into an event.

    Field authority is the fork's ``claudedocs/envelope-wire-spec.md``. All
    optional fields are ``omitempty`` on the wire — tolerate absence everywhere.
    """
    conn_id = _safe_conn_id(obj)
    if conn_id is None:
        log.debug("classify.drop", reason="envelope_bad_conn_id")
        return None

    if etype == "session_start":
        # Identity mapping (spec §4): username ← sso_user (SSO email; absent on
        # the SSH path in current fork builds), shell_user ← shell_user (resolved
        # OS account — secondary detail, never identity per CLAUDE.md rule 4).
        resource = obj.get("resource")
        address = resource.get("address") if isinstance(resource, dict) else None
        sso_user = obj.get("sso_user")
        shell_user = obj.get("shell_user")
        started_at = obj.get("started_at")
        return SessionStart(
            conn_id=conn_id,
            resource_address=address if isinstance(address, str) else None,
            username=sso_user if isinstance(sso_user, str) else None,
            shell_user=shell_user if isinstance(shell_user, str) else None,
            ts=started_at if isinstance(started_at, str) else None,
        )

    if etype == "recording_chunk":
        seq = obj.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            log.debug("classify.drop", reason="envelope_bad_seq")
            return None
        text = _envelope_chunk_text(obj)
        if text is None:
            log.debug("classify.drop", reason="envelope_bad_events")
            return None
        # The chunk-level "final" flag is advisory and frequently absent — the
        # authoritative terminator is the session_end record (spec §5). Honoring
        # it when present just seals a beat earlier; finalize is idempotent.
        return RecordingChunk(
            conn_id=conn_id,
            seq=seq,
            asciicast=text,
            is_final=obj.get("final") is True,
        )

    # session_end: control-only record (spec §5) — never carries events, so it
    # maps directly onto the existing terminal-finalize event. Its sha256 /
    # total_bytes integrity fields are not yet consumed.
    return SessionEnd(conn_id=conn_id)


def classify(obj: dict) -> Event | None:
    """Classify one normalized log object into a pipeline event.

    Args:
        obj: A JSON object produced by ``normalize`` (or a parsed ``/ingest`` item).

    Returns:
        A ``RecordingChunk``, ``SessionStart``, or ``SessionEnd`` event, or
        ``None`` if the object is operational noise or cannot be safely keyed.
    """
    logger = obj.get("logger")

    # 0. Envelope wire format (fork recording sink): a "type" discriminator and
    # no "logger". Checked first, but can never divert a legacy line — every
    # legacy Gateway line carries "logger". Unknown envelope types fall through
    # to the legacy checks below and (matching nothing) are dropped as noise.
    etype = obj.get("type")
    if logger is None and isinstance(etype, str) and etype in _ENVELOPE_TYPES:
        return _classify_envelope(obj, etype)

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
