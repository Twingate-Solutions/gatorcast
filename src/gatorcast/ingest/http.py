"""HTTP ingestion front door: ``POST /ingest``.

The primary intake. A shipper (rsyslog omhttp, curl, etc.) POSTs Gateway log
lines here with a bearer token. Bodies may be NDJSON, a single JSON object, a
JSON array of objects, or newline-delimited text. Parsing is per-line tolerant:
one bad line never fails the batch. Accepted objects are enqueued onto the
shared ingest queue; the endpoint returns 200 with per-batch counts and never echoes
content back.
"""

from __future__ import annotations

import asyncio
import json
import secrets

from fastapi import APIRouter, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from gatorcast.ingest.counts import IntakeCounts
from gatorcast.ingest.normalize import normalize, unwrap_collector
from gatorcast.logging import get_logger

log = get_logger(__name__)

router = APIRouter()

# A large batch is processed in one request task; yield to the event loop this often
# so the UI, the syslog listener and the consumer are not starved while it runs.
_YIELD_EVERY = 256


def _require_auth(authorization: str | None, expected_token: str) -> None:
    """Enforce ``Authorization: Bearer <INGEST_TOKEN>``.

    Args:
        authorization: The raw Authorization header value, if present.
        expected_token: The configured ingest token.

    Raises:
        HTTPException: 401 if the header is missing, malformed, or mismatched.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    presented = authorization[len("Bearer ") :].strip()
    if not secrets.compare_digest(presented, expected_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )


def _parse_json_body(text: str) -> tuple[list[dict], int]:
    """Parse an ``application/json`` body into a list of objects.

    Args:
        text: The decoded request body.

    Returns:
        A ``(objects, dropped)`` tuple. ``objects`` holds the dict items;
        ``dropped`` counts non-object array entries or a wholly invalid body.
    """
    data = None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return [], 1

    if isinstance(data, list):
        objs = [item for item in data if isinstance(item, dict)]
        return objs, len(data) - len(objs)
    if isinstance(data, dict):
        return [data], 0
    return [], 1


@router.post("/ingest")
async def ingest(
    request: Request,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    """Accept a batch of Gateway log lines, classify them, and enqueue the events.

    Auth is a bearer token. The body is decoded and split by content type:
    ``application/json`` is parsed as one document (object or array); anything
    else is treated as newline-delimited and each line is run through
    ``normalize``. Every object is then classified here and the resulting event is
    put on the ingest queue; the consumer only hands events to the assembler.

    Returns:
        ``200`` with ``application/json`` once auth passes, however many lines were
        dropped. The body carries counts only, never content::

            {
              "accepted": 3,
              "dropped": 2,
              "accepted_by_kind": {"ApiRequest": 1, "RecordingChunk": 2},
              "dropped_by_reason": {"noise": 1, "not_json": 1},
              "noise_by_logger": {"other": 1}
            }

        ``accepted`` is the number of objects classified into an event and queued;
        ``accepted_by_kind`` is keyed by event type (``RecordingChunk``,
        ``SessionStart``, ``SessionEnd``, ``ApiRequest``). ``dropped`` is the number
        of non-blank inputs that produced no event; ``dropped_by_reason`` is keyed
        ``not_json`` (not a JSON object), ``noise`` (``classify`` returned nothing
        for a line that is not a known event type), ``rejected`` (``classify``
        returned nothing for a known event type, so the line was malformed),
        ``classify_error`` or ``normalize_error`` (``normalize`` raised on that one
        input). ``noise_by_logger`` breaks ``noise`` down by the line's
        ``logger`` value: ``gateway``, ``gateway.audit``, ``system``, ``audit``,
        ``session_recording``, ``missing`` (absent or not a string) or ``other``.
        The three maps list non-zero entries only. Blank lines are not counted. A
        batch whose ``accepted`` is 0 and ``dropped`` is not has delivered nothing.
        The same counts are logged as one ``ingest.http`` line.

        Auth failures keep their ``401`` response.
    """
    settings = request.app.state.settings
    _require_auth(authorization, settings.ingest_token)

    queue = request.app.state.ingest_queue

    body = await request.body()
    text = body.decode("utf-8", errors="replace")
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()

    counts = IntakeCounts()

    if content_type == "application/json":
        objs, bad = _parse_json_body(text)
        counts.drop_not_json(bad)
        # Apply the same collector-unwrap the NDJSON/text path gets via
        # normalize(), so Docker-wrapped {"log": ...} objects are not silently
        # dropped by classify. Per-item tolerant: one bad item never fails the
        # batch (the 200 response is unconditional below).
        for index, obj in enumerate(objs, 1):
            if index % _YIELD_EVERY == 0:
                await asyncio.sleep(0)
            try:
                unwrapped = unwrap_collector(obj)
            except Exception as exc:
                counts.drop_normalize_error(exc)
                continue
            if unwrapped is None:
                counts.drop_not_json()
                continue
            event = counts.triage(unwrapped)
            if event is not None:
                await queue.put(event)
    else:
        # NDJSON / x-ndjson / text/plain: one candidate per line. Split on "\n"
        # only: str.splitlines() also breaks on U+0085, U+2028,
        # U+2029, \v, \f and \x1c-\x1e, which can appear raw inside a JSON string
        # (terminal output in an asciicast chunk) and would tear the line into
        # unparseable fragments. One trailing "\r" is dropped so CRLF bodies work.
        for index, line in enumerate(text.split("\n"), 1):
            if index % _YIELD_EVERY == 0:
                await asyncio.sleep(0)
            line = line.removesuffix("\r")
            if not line.strip():
                continue
            try:
                obj = normalize(line)
            except Exception as exc:
                counts.drop_normalize_error(exc)
                continue
            if obj is None:
                counts.drop_not_json()
                continue
            event = counts.triage(obj)
            if event is not None:
                await queue.put(event)

    summary = counts.as_dict()
    log.info("ingest.http", **summary)
    return JSONResponse(summary, status_code=status.HTTP_200_OK)
