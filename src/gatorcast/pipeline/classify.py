"""Classify a normalized Gateway log object into a pipeline event (or drop it).

The single source of truth for "what is this line". Two wire formats are
recognized. Both map onto the recording events (``RecordingChunk``,
``SessionStart``, ``SessionEnd``); the legacy format also yields ``ApiRequest``.

**Legacy log-line format** (CLAUDE.md rule 2, TECHNICAL_PLAN "Classification"):

  * **RecordingChunk** — ``logger == "gateway.audit"`` *and* a non-null ``asciicast``.
    The logger check alone is insufficient: ``gateway.audit`` also carries
    API-request audits with no recording, which are never chunks. Kubernetes
    exec/attach chunk lines also carry a ``request_id``, which is kept (and
    nothing else new is read from them) so the recording can be linked to its
    API audit line.
  * **ApiRequest** — ``logger == "gateway.audit"`` with *no* ``asciicast`` and
    ``message`` of ``"API request completed"`` or ``"API request failed"``. One
    per HTTP request. Only allowlisted metadata is kept: method, sanitized URL,
    status, user identity, and the ``User-Agent`` / ``Kubectl-Command`` /
    ``Kubectl-Session`` request headers. ``Authorization``, cookies, every other
    request header, response headers, ``remote_addr`` and ``panic`` are never
    read. Every stored URL is normalized and passes a query-key allowlist with
    validated values (``command`` and every other non-allowlisted key is dropped);
    proxy URLs keep only their path up to ``proxy`` (see ``_store_url``). The same
    raw URL also yields ``url_web`` (web-app policy: normalized path, masked query
    values; ``webmask.store_web_url``); the assembler picks the form by resource
    type. Other ``gateway.audit`` messages are dropped.
  * **SessionStart** — ``logger == "gateway"`` with ``message == "Authenticated
    connection"``. Carries the target ``resource_address`` and the user identity;
    on a ``WEB_APP`` start also the validated ``gwops`` object (``_classify_gwops``;
    a rejected object leaves the rest of the event unchanged).
  * **SessionEnd** — a connection-close signal (Open Validation Item 2: shape not
    yet confirmed; idle timeout is the authoritative finalize path).

**Envelope format** (gateway fork POC — recording sink POSTing NDJSON directly;
spec: the fork's ``claudedocs/envelope-wire-spec.md``): self-describing records
with a ``"type"`` discriminator and *no* ``"logger"`` field. Support is strictly
additive — these records previously matched nothing and were silently dropped;
legacy classification is untouched, so existing shipping recipes keep working.

Everything else (operational noise) returns ``None`` and is dropped. Drops log
only a ``classify.drop`` reason — never the raw line, a URL, or a header value.

``conn_id`` is the demux key and is used to name the on-disk ``.cast`` file, so it
is validated against a strict pattern here — this is the single choke point that
prevents path traversal or odd keys from a forged line (CLAUDE.md rule 5).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import unicodedata
from datetime import UTC, datetime
from urllib.parse import parse_qsl, urlencode

from gatorcast.logging import get_logger
from gatorcast.models import (
    RESOURCE_TYPE_INVALID,
    ApiRequest,
    GwopsWebApp,
    RecordingChunk,
    SessionEnd,
    SessionStart,
)
from gatorcast.pipeline.urlnorm import normalize_url, replace_lone_surrogates
from gatorcast.pipeline.webmask import store_web_url

log = get_logger(__name__)

Event = RecordingChunk | SessionStart | SessionEnd | ApiRequest

# conn_id is a Gateway-issued UUID. Constrain it to a safe token: it becomes the
# .cast filename, so reject anything that could escape the casts directory or be
# otherwise hostile. Real values match this; anything else is dropped.
# Always applied with ``fullmatch`` (never ``match`` + ``$``, which accepts a
# trailing newline).
_SAFE_CONN_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}")

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

# Stock Gateway API-request audit messages (logger "gateway.audit", no asciicast).
_API_COMPLETED_MESSAGE = "API request completed"
_API_FAILED_MESSAGE = "API request failed"
_API_MESSAGES = frozenset({_API_COMPLETED_MESSAGE, _API_FAILED_MESSAGE})

# Accepts lowercase and WebDAV-style methods (WEBAPP_SPEC 5.6). The method is stored
# as received; downstream comparisons (detection, discovery, mutating) upper-case it.
_HTTP_METHOD = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,23}")

# Gateway ``resource_type`` after strip + upper-case (WEBAPP_SPEC 4.1).
_RESOURCE_TYPE = re.compile(r"[A-Z][A-Z0-9_]{0,31}")

# --- gwops object on WEB_APP start lines (WEBAPP_SPEC 3.3) ---
_GWOPS_SCHEMA = 1
_GWOPS_MATCHES = frozenset({"exact", "none", "ambiguous"})
_GWOPS_GATEWAY_ID = re.compile(r"[A-Za-z0-9+/=_-]{1,128}")
_GWOPS_DOWNSTREAM_TLS = frozenset({"tls13", "none"})
_GWOPS_UPSTREAM_TLS = frozenset({"verify_full", "verify_ca", "insecure", "none"})
_GWOPS_MAX_APP = 200
# Unicode categories refused in ``app``: controls, format (bidi etc.), line and
# paragraph separators, surrogates (a lone one cannot be encoded for SQLite),
# private use, and unassigned code points.
_GWOPS_APP_BAD_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn"})

# Request headers that may be stored, keyed by lowercase wire name. Everything
# else — Authorization above all, which is on every real request — is never read.
_HEADER_ALLOWLIST = frozenset({"user-agent", "kubectl-command", "kubectl-session"})
_MAX_HEADER_VALUE = 256
_MAX_URL = 4096

# --- Stored-URL sanitization (CLAUDE.md rule 2) ---
#
# Query keys that may be stored on any URL; every other key is dropped outright
# (the key is not kept with an empty value). Matching is case-sensitive, as the
# Kubernetes API is.
_QUERY_ALLOWLIST = frozenset(
    {
        "labelSelector",
        "fieldSelector",
        "limit",
        "continue",
        "watch",
        "timeout",
        "timeoutSeconds",
        "resourceVersion",
        "resourceVersionMatch",
        "allowWatchBookmarks",
        "propagationPolicy",
        "gracePeriodSeconds",
        "dryRun",
        "fieldManager",
        "fieldValidation",
        "force",
        "follow",
        "tailLines",
        "sinceSeconds",
        "previous",
        "timestamps",
        "pretty",
        "orphanDependents",
    }
)

# Exec/attach subresources carry their command in ``?command=`` (can hold secrets);
# they additionally allow these keys, each with a validated value.
_EXEC_ATTACH_PATH = re.compile(r"/pods/[^/]+/(?:exec|attach)\Z", re.IGNORECASE)
_EXEC_FLAG_KEYS = frozenset({"stdin", "stdout", "stderr", "tty"})
_EXEC_FLAG_VALUES = frozenset({"true", "false", "1", "0"})
_CONTAINER_NAME = re.compile(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?")
_MAX_QUERY_VALUE = 256

# A ``proxy`` path segment hands the rest of the URL to a backend (pod, service
# or node), so the remainder of the path and the whole query can carry anything.
_PROXY_SEGMENT = "proxy"
_NODE_PROXY_HEAD = re.compile(r".*/nodes/[^/]+/proxy", re.IGNORECASE)
# Node-proxy subresources that run or attach to a process. The segment is kept
# after ``/proxy`` so the ``kube-node-proxy-exec`` detection rule still sees it.
_NODE_PROXY_EXEC_SEGMENTS = frozenset({"exec", "run", "attach"})


def _clean(value: str) -> str:
    """Make a string safe to store: lone surrogates become U+FFFD.

    Every free-text string ``classify`` passes on (identity, address, header values,
    timestamps as received, recording text) goes through this, because a JSON
    ``\\ud800`` escape decodes to a lone surrogate that SQLite and the cast files
    cannot encode, which would drop the whole line. ``conn_id``, ``request_id``,
    ``method``, ``resource_type``, normalized timestamps, ``gwops`` fields and URLs
    are already constrained by a pattern or by ``normalize_url``.
    """
    return replace_lone_surrogates(value)


def _clean_opt(value: object) -> str | None:
    """``_clean`` for a field that must be a string: anything else becomes ``None``."""
    return _clean(value) if isinstance(value, str) else None


def _ts_field(obj: dict) -> object:
    """Return ``obj['ts']`` as received (cleaned when it is a string)."""
    value = obj.get("ts")
    return _clean(value) if isinstance(value, str) else value


def _safe_conn_id(obj: dict) -> str | None:
    """Return ``obj['conn_id']`` if present and safe to use as a filename, else None."""
    conn_id = obj.get("conn_id")
    if isinstance(conn_id, str) and _SAFE_CONN_ID.fullmatch(conn_id):
        return conn_id
    return None


def _safe_request_id(obj: dict) -> str | None:
    """Return ``obj['request_id']`` if it is a safe token (Gateway UUID), else None."""
    request_id = obj.get("request_id")
    if isinstance(request_id, str) and _SAFE_CONN_ID.fullmatch(request_id):
        return request_id
    return None


def _user_id(obj: dict) -> str | None:
    """Extract the Gateway user id (``user.id``) defensively."""
    user = obj.get("user")
    if isinstance(user, dict):
        user_id = user.get("id")
        if isinstance(user_id, str):
            return _clean(user_id)
    return None


def _norm_ts(value: object) -> str | None:
    """Normalize an ISO 8601 timestamp to ``YYYY-MM-DDTHH:MM:SS.mmmZ`` (UTC).

    Accepts the Gateway's RFC 3339 forms (any fractional precision, ``Z`` or a
    numeric offset); a value with no offset is taken as UTC. Sub-millisecond
    precision is truncated. Returns None for non-strings, unparseable values, and
    values whose UTC conversion falls outside the representable range (for example
    ``0001-01-01T00:00:00+01:00``).
    """
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
        parsed = parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    except (ValueError, OverflowError):
        return None
    return f"{parsed:%Y-%m-%dT%H:%M:%S}.{parsed.microsecond // 1000:03d}Z"


def _allowlisted_headers(headers: object) -> dict[str, str]:
    """Pick the allowlisted request headers out of ``request.headers``.

    ``headers`` maps title-case names to lists of strings (for example
    ``"Kubectl-Command": ["kubectl get"]``). Each key is compared
    case-insensitively against ``user-agent``, ``kubectl-command`` and
    ``kubectl-session``; any other key is never read, so ``Authorization`` and
    cookies cannot reach the result. The first element of a list is taken (a plain
    string is accepted defensively) and capped at 256 characters.

    Returns:
        A dict keyed by lowercase header name; only present, non-empty headers.
    """
    picked: dict[str, str] = {}
    if not isinstance(headers, dict):
        return picked
    for key in headers:
        if not isinstance(key, str):
            continue
        name = key.lower()
        if name not in _HEADER_ALLOWLIST or name in picked:
            continue
        value = headers[key]
        if isinstance(value, list):
            value = value[0] if value else None
        if isinstance(value, str) and value:
            picked[name] = _clean(value[:_MAX_HEADER_VALUE])
    return picked


def _has_control_char(value: str) -> bool:
    """True if ``value`` holds a C0/DEL/C1 control character."""
    return any(ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F for ch in value)


def _query_pair_allowed(key: str, value: str, *, exec_attach: bool) -> bool:
    """Decide whether one decoded query ``key=value`` pair may be stored.

    The key must be on the allowlist (the exec/attach extras only apply when
    ``exec_attach`` is true). The value must then pass its check: exec flags are
    ``true``/``false``/``1``/``0``, ``container`` is a DNS-label-style name, and
    every other allowlisted value must be at most 256 characters with no ``;``
    (a parameter-smuggling separator) and no control character. A blank value is
    kept for the general allowlist only.
    """
    if exec_attach and key in _EXEC_FLAG_KEYS:
        return value in _EXEC_FLAG_VALUES
    if exec_attach and key == "container":
        return _CONTAINER_NAME.fullmatch(value) is not None
    if key not in _QUERY_ALLOWLIST:
        return False
    return len(value) <= _MAX_QUERY_VALUE and ";" not in value and not _has_control_char(value)


def _truncate_proxy(path: str) -> tuple[str, bool]:
    """Cut a normalized path after its first ``proxy`` segment.

    Everything after ``…/proxy`` is forwarded to a backend and may carry
    arbitrary data, so it is dropped. The one exception is a node proxy
    (``…/nodes/<n>/proxy``) followed directly by ``exec``, ``run`` or ``attach``:
    that segment is kept so detection can flag it, and nothing after it is.

    Returns:
        ``(path, proxied)``; ``proxied`` is true when the path was a proxy path
        (the caller must then drop the query as well).
    """
    segments = path.split("/")
    for index, segment in enumerate(segments):
        if segment.lower() != _PROXY_SEGMENT:
            continue
        head = "/".join(segments[: index + 1])
        following = segments[index + 1] if index + 1 < len(segments) else ""
        if (
            _NODE_PROXY_HEAD.fullmatch(head)
            and following.lower() in _NODE_PROXY_EXEC_SEGMENTS
        ):
            head = f"{head}/{following}"
        return head, True
    return path, False


def _store_url(raw_url: str) -> str:
    """Return the URL as it may be stored (CLAUDE.md rule 2).

    The URL is first normalized by :func:`gatorcast.pipeline.urlnorm.normalize_url`
    (fragment dropped, path unquoted once, repeated ``/`` collapsed, trailing ``/``
    stripped); the normalized path is what is stored. Then:

    * A path with a ``proxy`` segment keeps its path up to and including
      ``proxy`` (plus ``exec``/``run``/``attach`` for ``/nodes/<n>/proxy``) and
      loses the whole query.
    * When normalization finds the URL ambiguous (the unquoted path held ``?`` or
      ``#``, or still holds ``%``) the query is dropped entirely.
    * Otherwise only allowlisted query keys survive, in their original order, and
      only when their value passes validation; every other key is dropped, not
      kept blank. Exec/attach paths (``…/pods/<name>/exec|attach``) additionally
      allow ``container``, ``stdin``, ``stdout``, ``stderr`` and ``tty``.
      ``command`` is never allowlisted.

    Nothing from the raw URL is logged.
    """
    normalized = normalize_url(raw_url)
    path, proxied = _truncate_proxy(normalized.path)
    if proxied or normalized.query is None:
        return path
    exec_attach = _EXEC_ATTACH_PATH.search(path) is not None
    kept = [
        (key, value)
        for key, value in parse_qsl(normalized.query, keep_blank_values=True)
        if _query_pair_allowed(key, value, exec_attach=exec_attach)
    ]
    return f"{path}?{urlencode(kept)}" if kept else path


def _synth_request_id(conn_id: str, requested_at: str, method: str, url: str) -> str:
    """Deterministic ``h:<hex>`` id for a line with no usable ``request_id``.

    Keeps ``request_id`` dedup working under at-least-once redelivery. The ``:``
    guarantees it can never collide with a Gateway-issued (safe-token) id.
    """
    digest = hashlib.sha256("\x00".join((conn_id, requested_at, method, url)).encode())
    return "h:" + digest.hexdigest()[:32]


def _classify_api_request(obj: dict) -> ApiRequest | None:
    """Classify a ``gateway.audit`` API-request line into an ``ApiRequest``.

    Reads only the allowlisted fields (see the module docstring). Returns None,
    logging just a ``classify.drop`` reason, when ``conn_id``, ``method``,
    ``url``/``path`` or the timestamp is missing or malformed.
    """
    conn_id = _safe_conn_id(obj)
    if conn_id is None:
        log.debug("classify.drop", reason="api_bad_conn_id")
        return None
    method = obj.get("method")
    if not isinstance(method, str) or not _HTTP_METHOD.fullmatch(method):
        log.debug("classify.drop", reason="api_bad_method")
        return None
    # "path" is the legacy fixture spelling of "url".
    raw_url = obj.get("url") or obj.get("path")
    if not isinstance(raw_url, str) or not raw_url.startswith("/"):
        log.debug("classify.drop", reason="api_bad_url")
        return None
    url = _store_url(raw_url)[:_MAX_URL]
    url_web = store_web_url(raw_url)
    requested_at = _norm_ts(obj.get("requested_at") or obj.get("ts"))
    if requested_at is None:
        log.debug("classify.drop", reason="api_bad_time")
        return None
    request_id = _safe_request_id(obj) or _synth_request_id(
        conn_id, requested_at, method, url
    )

    failed = obj.get("message") == _API_FAILED_MESSAGE
    status_code: int | None = None
    response = obj.get("response")
    if not failed and isinstance(response, dict):
        status = response.get("status_code")
        if isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599:
            status_code = status

    request = obj.get("request")
    headers = _allowlisted_headers(request.get("headers") if isinstance(request, dict) else None)
    return ApiRequest(
        conn_id=conn_id,
        request_id=request_id,
        requested_at=requested_at,
        user_id=_user_id(obj),
        username=_username(obj),
        method=method,
        url=url,
        url_web=url_web,
        status_code=status_code,
        outcome="failed" if failed else "completed",
        kubectl_command=headers.get("kubectl-command"),
        kubectl_session=headers.get("kubectl-session"),
        user_agent=headers.get("user-agent"),
    )


def _resource_type(obj: dict, conn_id: str) -> str | None:
    """Normalize ``obj['resource_type']``: strip, upper-case, validate.

    Absent and present-but-invalid are different (CLAUDE.md rule 2):

      * key missing, or JSON ``null`` (no information): ``None``, treated downstream
        as a pre-upgrade Kubernetes connection;
      * a string that fullmatches ``[A-Z][A-Z0-9_]{0,31}`` after strip and
        upper-casing (``kubernetes`` becomes ``KUBERNETES``): that value;
      * anything else (non-string, empty, wrong characters, too long):
        :data:`~gatorcast.models.RESOURCE_TYPE_INVALID`, so the connection is
        fail-closed (web URL form, no rules) rather than silently Kubernetes.
        One ``classify.resource_type_rejected`` warning is logged with the reason
        and ``conn_id`` only, never the value.

    Never raises and never drops the line.
    """
    value = obj.get("resource_type")
    if value is None:
        return None
    if not isinstance(value, str):
        log.warning("classify.resource_type_rejected", reason="not_a_string", conn_id=conn_id)
        return RESOURCE_TYPE_INVALID
    normalized = value.strip().upper()
    if _RESOURCE_TYPE.fullmatch(normalized) is None:
        log.warning("classify.resource_type_rejected", reason="bad_value", conn_id=conn_id)
        return RESOURCE_TYPE_INVALID
    return normalized


def _is_int(value: object) -> bool:
    """True for a real int (``bool`` is excluded; JSON ``true`` must not pass as 1)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _gwops_app_ok(app: object) -> bool:
    """Check 10: a non-empty string of at most 200 code points with no Cc/Cf/Zl/Zp/Cs/Co/Cn."""
    if not isinstance(app, str) or not app or len(app) > _GWOPS_MAX_APP:
        return False
    return not any(
        unicodedata.category(ch) in _GWOPS_APP_BAD_CATEGORIES for ch in app
    )


def _gwops_rejected(conn_id: str, reason: str) -> None:
    """Log the one ``classify.gwops_rejected`` warning (reason and conn_id only)."""
    log.warning("classify.gwops_rejected", reason=reason, conn_id=conn_id)


def _classify_gwops(obj: dict, conn_id: str) -> GwopsWebApp | None:
    """Parse the ``gwops`` object of a ``WEB_APP`` start line (WEBAPP_SPEC 3.3).

    Call only for a start line whose normalized ``resource_type`` is ``WEB_APP``;
    on every other type the key must not be read. The object is validated by hand
    in the spec's order, and the frozen model is built from the validated
    primitives: the raw object is never passed to Pydantic, so no validation error
    (which would embed input values) can exist to be logged. Unknown keys are never
    read. Nothing but a reason code and ``conn_id`` is ever logged.

    Returns:
        ``None`` when the key is absent (no log) or the object is rejected (one
        ``classify.gwops_rejected`` warning). A bad ``app`` on an ``exact`` object
        is not a rejection: the model is returned with ``app=None`` and one
        ``classify.gwops_field_ignored`` warning.
    """
    if "gwops" not in obj:
        return None
    raw = obj["gwops"]
    if not isinstance(raw, dict):
        _gwops_rejected(conn_id, "gwops_not_object")
        return None

    schema = raw.get("schema")
    if not _is_int(schema) or schema != _GWOPS_SCHEMA:
        _gwops_rejected(conn_id, "gwops_bad_schema")
        return None

    match = raw.get("match")
    if not isinstance(match, str) or match not in _GWOPS_MATCHES:
        _gwops_rejected(conn_id, "gwops_bad_match")
        return None

    # A missing key and an explicit null differ: ``gateway_id`` must be present.
    if "gateway_id" not in raw:
        _gwops_rejected(conn_id, "gwops_bad_gateway_id")
        return None
    gateway_id = raw["gateway_id"]
    if gateway_id is not None and not (
        isinstance(gateway_id, str) and _GWOPS_GATEWAY_ID.fullmatch(gateway_id)
    ):
        _gwops_rejected(conn_id, "gwops_bad_gateway_id")
        return None

    if match != "exact":
        # none / ambiguous: only match and gateway_id are read.
        return GwopsWebApp(match=match, gateway_id=gateway_id)  # type: ignore[arg-type]

    managed = raw.get("managed")
    if not isinstance(managed, bool):
        _gwops_rejected(conn_id, "gwops_bad_managed")
        return None

    downstream_tls = raw.get("downstream_tls")
    upstream_tls = raw.get("upstream_tls")
    if (
        not isinstance(downstream_tls, str)
        or downstream_tls not in _GWOPS_DOWNSTREAM_TLS
        or not isinstance(upstream_tls, str)
        or upstream_tls not in _GWOPS_UPSTREAM_TLS
    ):
        _gwops_rejected(conn_id, "gwops_bad_mode")
        return None

    downstream_port = raw.get("downstream_port")
    upstream_port = raw.get("upstream_port")
    if not (
        _is_int(downstream_port)
        and 1 <= downstream_port <= 65535
        and _is_int(upstream_port)
        and 1 <= upstream_port <= 65535
    ):
        _gwops_rejected(conn_id, "gwops_bad_port")
        return None

    app = raw.get("app")
    if not _gwops_app_ok(app):
        log.warning("classify.gwops_field_ignored", reason="gwops_bad_app", conn_id=conn_id)
        app = None

    return GwopsWebApp(
        match="exact",
        gateway_id=gateway_id,
        app=app,
        managed=managed,
        downstream_tls=downstream_tls,  # type: ignore[arg-type]
        downstream_port=downstream_port,
        upstream_tls=upstream_tls,  # type: ignore[arg-type]
        upstream_port=upstream_port,
    )


def _username(obj: dict) -> str | None:
    """Extract the envelope SSO identity (``user.username``) defensively."""
    user = obj.get("user")
    if isinstance(user, dict):
        username = user.get("username")
        if isinstance(username, str):
            return _clean(username)
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
        return _clean(json.dumps(header, separators=(",", ":")) + "\n" + events)
    return _clean(events)


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
            resource_address=_clean_opt(address),
            username=_clean_opt(sso_user),
            shell_user=_clean_opt(shell_user),
            ts=_clean_opt(started_at),
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
        A ``RecordingChunk``, ``SessionStart``, ``SessionEnd`` or ``ApiRequest``
        event, or ``None`` if the object is operational noise or cannot be safely
        keyed.
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
            asciicast=_clean(asciicast),
            username=_username(obj),
            ts=_ts_field(obj),
            is_final=obj.get("message") == _FINAL_RECORDING_MESSAGE,
            request_id=_safe_request_id(obj),
        )

    # 1b. API request audit: gateway.audit, NO asciicast, completed/failed message.
    # Any line carrying an asciicast string was already handled above as a chunk.
    if (
        logger == "gateway.audit"
        and obj.get("asciicast") is None
        and obj.get("message") in _API_MESSAGES
    ):
        return _classify_api_request(obj)

    # 2. Session start: gateway "Authenticated connection".
    if logger == "gateway" and obj.get("message") == "Authenticated connection":
        conn_id = _safe_conn_id(obj)
        if conn_id is None:
            log.debug("classify.drop", reason="start_bad_conn_id")
            return None
        resource_address = obj.get("resource_address")
        resource_type = _resource_type(obj, conn_id)
        # The gwops key is read only on web-app starts; on any other type it is
        # ignored entirely and nothing is logged about it.
        gwops = _classify_gwops(obj, conn_id) if resource_type == "WEB_APP" else None
        return SessionStart(
            conn_id=conn_id,
            resource_address=_clean_opt(resource_address),
            username=_username(obj),
            user_id=_user_id(obj),
            ts=_ts_field(obj),
            resource_type=resource_type,
            gwops=gwops,
        )

    # 3. Session end (close-event hook — see _CLOSE_MESSAGES note).
    if logger == "gateway" and obj.get("message") in _CLOSE_MESSAGES:
        conn_id = _safe_conn_id(obj)
        if conn_id is not None:
            return SessionEnd(conn_id=conn_id, ts=_ts_field(obj))

    # Everything else is operational noise (including other gateway.audit
    # messages) → drop.
    return None
