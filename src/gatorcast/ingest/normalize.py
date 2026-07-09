"""Normalize a raw inbound line into a JSON object (dict) or None.

Both front doors (HTTP and syslog TCP) reduce a raw line to a candidate JSON
object via this single step. It must be defensive: a malformed or unrecognized
line is dropped (returns None and bumps a debug counter), never raised.

Handled wrappers, in order:
  1. A syslog envelope (``<PRI>VERSION TS HOST APP ... {json}`` or the BSD
     ``<PRI>TS HOST TAG: {json}`` form) is stripped to its JSON payload.
  2. A collector envelope (e.g. Docker's ``{"log":"...","stream":"stdout"}``)
     is unwrapped to the inner log line, which is then re-normalized.
  3. The result is parsed with ``json.loads``; on failure the line is dropped.
"""

from __future__ import annotations

import json

from gatorcast.logging import get_logger

log = get_logger(__name__)


def _try_json(text: str) -> object | None:
    """Parse ``text`` as JSON, returning the value or None on failure."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def unwrap_collector(obj: dict) -> dict | None:
    """Unwrap a collector envelope around an already-parsed JSON object.

    Some shippers wrap each log line in a collector envelope (e.g. Docker's
    ``{"log": "<original line>", "stream": "stdout"}``). Such a wrapper carries
    the original line as a string under ``"log"`` and has no gateway ``"logger"``
    field of its own. This is the dict-aware half of :func:`normalize`, factored
    out so the HTTP ``application/json`` path can apply the same unwrap without
    re-serializing each object.

    Args:
        obj: An already-parsed JSON object (dict).

    Returns:
        The unwrapped inner object as a ``dict`` (recursing through nested
        wrappers), or ``None`` if the inner ``"log"`` payload does not reduce to
        a JSON object. A plain (non-wrapper) object is returned unchanged.
    """
    if "logger" not in obj and isinstance(obj.get("log"), str):
        return normalize(obj["log"])
    return obj


def normalize(line: str) -> dict | None:
    """Reduce a raw inbound line to a JSON object.

    Args:
        line: A single raw line from a front door (already de-framed by the
            transport — no syslog octet count, no trailing newline required).

    Returns:
        The parsed JSON object as a ``dict``, or ``None`` if the line is empty,
        unparseable, or does not reduce to a JSON object.
    """
    stripped = line.strip()
    if not stripped:
        return None

    parsed = _try_json(stripped)

    # If the whole line isn't JSON, it may carry a syslog header before the
    # payload. Recover the payload by parsing from the first '{'.
    if parsed is None:
        brace = stripped.find("{")
        if brace > 0:
            parsed = _try_json(stripped[brace:])

    if parsed is None:
        # WARNING, not debug: an unparseable line almost always means the transport
        # mangled it — most commonly systemd-journald's LineMax (default 48 KB)
        # splitting a large asciicast chunk into JSON fragments. We log the length
        # (a value at/near 49152 is the journald-split tell) but NEVER the content
        # (rule 5), so "recordings silently vanishing" is a one-glance signal.
        log.warning("normalize.drop", reason="unparseable", length=len(stripped))
        return None

    if not isinstance(parsed, dict):
        log.warning("normalize.drop", reason="not_an_object", length=len(stripped))
        return None

    # Unwrap a collector envelope (e.g. Docker's {"log": "...", "stream": ...}).
    return unwrap_collector(parsed)
