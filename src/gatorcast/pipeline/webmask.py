"""Storage form of a web-app (``WEB_APP``) request URL: normalized path, masked query.

Web traffic is not Kubernetes traffic, so the Kubernetes URL policy in
:mod:`gatorcast.pipeline.classify` (``proxy`` truncation, query-key allowlist) does
not apply. Instead the path is stored as normalized and the query values are
masked, per ``docs/WEBAPP_SPEC.md`` section 5.

Policy summary:

* The path is the :func:`gatorcast.pipeline.urlnorm.normalize_url` output and
  nothing more. There is no path masking and no ``proxy`` truncation
  (WEBAPP_SPEC 5.3, withdrawn; the residual risk is recorded in its section 10).
* Every query value is masked with :func:`mask_value`. Keys that look like plain
  identifiers stay readable; anything else is masked as well, so a secret placed
  in a key position is not stored.
* The stored string is capped at 4096 characters. The cap is applied after
  masking, so truncation can never expose an unmasked query value.

Security (CLAUDE.md rules 2 and 5): query values can carry tokens, one-time codes,
and other credentials. Nothing in this module logs a URL or any part of one.

Layering: this module imports only :mod:`gatorcast.pipeline.urlnorm`, which
imports nothing from the package, so :mod:`gatorcast.pipeline.classify` can use
it without an import cycle.
"""

from __future__ import annotations

import re
from urllib.parse import unquote_plus

from gatorcast.pipeline.urlnorm import normalize_url

# Upper bound on the stored URL, in characters (WEBAPP_SPEC 5.1 step 5).
_MAX_URL = 4096

# A revealed character outside this set becomes "*", so masked text can never
# contain "&", "=", "/", "?", "#", "%", whitespace, or control characters
# (WEBAPP_SPEC 5.2).
_SAFE_CHAR = re.compile(r"[A-Za-z0-9._~-]")

# Query keys matching this pattern are kept in plaintext (WEBAPP_SPEC 5.4).
_PLAIN_KEY = re.compile(r"[A-Za-z0-9_.\[\]-]{1,64}")

_ELLIPSIS = "…"  # U+2026 HORIZONTAL ELLIPSIS
_MAX_REVEALED = 4
_MAX_PREFIX = 2


def _sanitize_revealed(text: str) -> str:
    """Replace each character outside ``[A-Za-z0-9._~-]`` with ``*``.

    Args:
        text: The revealed prefix or suffix of a value being masked.

    Returns:
        ``text`` with every unsafe character replaced by ``*``.
    """
    return "".join(ch if _SAFE_CHAR.fullmatch(ch) else "*" for ch in text)


def mask_value(value: str) -> str:
    """Mask an already-decoded value with the quarter rule, appending its length.

    ``n`` is the length in code points. At most ``min(4, n // 4)`` characters are
    revealed: the first two (or fewer) as a prefix, any remainder as a suffix.

    ==========  ========  ======  ======
    ``n``       revealed  prefix  suffix
    ==========  ========  ======  ======
    1-3         0         0       0
    4-7         1         1       0
    8-11        2         2       0
    12-15       3         2       1
    16 or more  4         2       2
    ==========  ========  ======  ======

    Revealed characters outside ``[A-Za-z0-9._~-]`` are replaced by ``*``. The
    output is ``prefix + "…" + suffix + "(" + str(n) + ")"``, for example
    ``mask_value("abc123def456") == "ab…6(12)"``. An empty value returns ``""``.

    Args:
        value: The decoded value to mask.

    Returns:
        The masked representation, or ``""`` when ``value`` is empty.
    """
    n = len(value)
    if n == 0:
        return ""
    revealed = min(_MAX_REVEALED, n // 4)
    prefix_len = min(revealed, _MAX_PREFIX)
    suffix_len = revealed - prefix_len
    prefix = _sanitize_revealed(value[:prefix_len])
    suffix = _sanitize_revealed(value[n - suffix_len :]) if suffix_len else ""
    return f"{prefix}{_ELLIPSIS}{suffix}({n})"


def mask_query(query: str) -> str:
    """Mask a raw (still percent-encoded) query string.

    The query is split on ``&`` only and empty parts are dropped. For each part:

    * ``key=value`` (split at the first ``=``): key and value are each decoded once
      with ``unquote_plus``. The key stays in plaintext when it fully matches
      ``[A-Za-z0-9_.\\[\\]-]{1,64}`` and is masked otherwise. The value is always
      masked; an empty value stays empty (``key=``). Exception: when the decoded
      value is non-empty and made only of ``=`` (a padded base64 token such as
      ``dGVzdA==``), the whole decoded item is the token and is masked as a bare
      item.
    * A bare item (no ``=``): decoded once and masked whole, emitted without ``=``.

    Order and repeats are preserved; parts are rejoined with ``&``.

    Args:
        query: The raw query string, without the leading ``?``.

    Returns:
        The masked query string. Empty when no non-empty part survived.
    """
    parts: list[str] = []
    for item in query.split("&"):
        if not item:
            continue
        raw_key, sep, raw_value = item.partition("=")
        key = unquote_plus(raw_key)
        if not sep:
            parts.append(mask_value(key))
            continue
        value = unquote_plus(raw_value)
        if value and not value.strip("="):
            # A padded bare token (``?dGVzdA==``) splits as key ``dGVzdA`` and value
            # ``=``. The "key" is the token, so mask the whole decoded item.
            parts.append(mask_value(unquote_plus(item)))
            continue
        shown_key = key if _PLAIN_KEY.fullmatch(key) else mask_value(key)
        parts.append(f"{shown_key}={mask_value(value)}")
    return "&".join(parts)


def store_web_url(url: str) -> str:
    """Return the storage form of a web-app request URL.

    Steps (WEBAPP_SPEC 5.1):

    1. :func:`gatorcast.pipeline.urlnorm.normalize_url` (fragment dropped, path
       unquoted once, ``//`` collapsed, trailing ``/`` stripped, fail-closed on an
       encoded ``?``/``#`` or a leftover ``%``).
    2. Keep the normalized path as is: no path masking, no ``proxy`` truncation.
    3. Mask the query with :func:`mask_query` when one survived step 1.
    4. Join as ``path`` or ``path?query`` and cap at 4096 characters.

    Args:
        url: The raw request URL or path as logged by the Gateway.

    Returns:
        The string to store, display, search, and export.
    """
    normalized = normalize_url(url)
    masked = mask_query(normalized.query) if normalized.query else ""
    stored = f"{normalized.path}?{masked}" if masked else normalized.path
    return stored[:_MAX_URL]


def store_provisional_url(kubernetes_url: str) -> str:
    """Return the storage form for a request whose connection type is not yet known.

    A request stored before its start line (or whose start line never arrives)
    could belong to a Kubernetes connection or a web app, so its stored URL must be
    safe under both policies (CLAUDE.md rule 2, WEBAPP_SPEC 4.4): the stricter of
    the two forms.

    The input is the Kubernetes storage form (``classify._store_url``): its path is
    already cut after ``proxy``, its query is already dropped on proxy paths, and
    only allowlisted keys survive (``command`` never does). This function adds the
    web policy's value masking on top (:func:`mask_query`), so the result has the
    Kubernetes path and key policy and the web value policy. The raw URL is not
    needed and is not kept.

    The stricter form is final: a later ``WEB_APP`` start line converts the row's
    ``api_kind`` but cannot re-derive a fuller URL, so a web path with a ``proxy``
    segment stays cut at ``proxy``.

    Args:
        kubernetes_url: A URL already produced by the Kubernetes storage policy.

    Returns:
        ``path`` or ``path?masked-query``, capped at 4096 characters after masking.
    """
    path, _, query = kubernetes_url.partition("?")
    masked = mask_query(query) if query else ""
    stored = f"{path}?{masked}" if masked else path
    return stored[:_MAX_URL]
