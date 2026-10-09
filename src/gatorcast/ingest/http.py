"""HTTP ingestion front door: ``POST /ingest``.

The primary intake. A shipper (rsyslog omhttp, curl, etc.) POSTs Gateway log
lines here with a bearer token. Bodies may be NDJSON, a single JSON object, a
JSON array of objects, or newline-delimited text. Parsing is per-line tolerant:
one bad line never fails the batch. Accepted objects are enqueued onto the
shared ingest queue; the endpoint returns 204 and never echoes content back.
"""

from __future__ import annotations

import json
import secrets

from fastapi import APIRouter, Header, HTTPException, Request, Response, status

from gatorcast.ingest.normalize import normalize, unwrap_collector
from gatorcast.logging import get_logger

log = get_logger(__name__)

router = APIRouter()


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
) -> Response:
    """Accept a batch of Gateway log lines and enqueue them for the pipeline.

    Auth is a bearer token. The body is decoded and split by content type:
    ``application/json`` is parsed as one document (object or array); anything
    else is treated as newline-delimited and each line is run through
    ``normalize``. Accepted objects are put on the ingest queue.

    Returns:
        ``204 No Content`` on accept (even if some lines were dropped).
    """
    settings = request.app.state.settings
    _require_auth(authorization, settings.ingest_token)

    queue = request.app.state.ingest_queue

    body = await request.body()
    text = body.decode("utf-8", errors="replace")
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()

    accepted = 0
    dropped = 0

    if content_type == "application/json":
        objs, bad = _parse_json_body(text)
        dropped += bad
        # Apply the same collector-unwrap the NDJSON/text path gets via
        # normalize(), so Docker-wrapped {"log": ...} objects are not silently
        # dropped by classify. Per-item tolerant: one bad item never fails the
        # batch (the 204 response is unconditional below).
        for obj in objs:
            unwrapped = unwrap_collector(obj)
            if unwrapped is None:
                dropped += 1
                continue
            await queue.put(unwrapped)
            accepted += 1
    else:
        # NDJSON / x-ndjson / text/plain: one candidate per line. Split on "\n"
        # only: str.splitlines() also breaks on U+0085, U+2028,
        # U+2029, \v, \f and \x1c-\x1e, which can appear raw inside a JSON string
        # (terminal output in an asciicast chunk) and would tear the line into
        # unparseable fragments. One trailing "\r" is dropped so CRLF bodies work.
        for line in text.split("\n"):
            line = line.removesuffix("\r")
            if not line.strip():
                continue
            obj = normalize(line)
            if obj is None:
                dropped += 1
                continue
            await queue.put(obj)
            accepted += 1

    log.info("ingest.http", accepted=accepted, dropped=dropped)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
