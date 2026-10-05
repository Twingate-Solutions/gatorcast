"""Shared request-URL normalization for the classify and detect stages.

Both :mod:`gatorcast.pipeline.classify` (which decides what part of a request URL
may be stored) and :mod:`gatorcast.pipeline.detect` (which matches rules against
the path) must agree on what path a URL really names. Otherwise an encoded or
oddly-shaped variant of ``/pods/p/exec`` slips past the sanitizer, the rules, or
both. This module is the single place that normalization lives; it imports
nothing from the rest of the package, so either stage can use it without a
circular import.

Security (CLAUDE.md rule 2): nothing here logs a URL or any part of one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote

_QUERY_OR_FRAGMENT = re.compile(r"[?#]")
_REPEATED_SLASH = re.compile(r"/{2,}")


@dataclass(frozen=True, slots=True)
class NormalizedUrl:
    """A request URL split into a normalized path and a still-untrusted query.

    ``query`` is ``None`` when the URL had no query, or when the URL was
    ambiguous enough that the query must not be trusted (see
    :func:`normalize_url`). It is the raw, still percent-encoded query string
    otherwise.
    """

    path: str
    query: str | None


def _clean_path(path: str) -> str:
    """Collapse repeated ``/`` and strip one trailing ``/`` (never the root)."""
    path = _REPEATED_SLASH.sub("/", path)
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path


def normalize_url(raw_url: str) -> NormalizedUrl:
    """Normalize a request URL into a canonical path plus its raw query.

    Steps, in order:

    1. Drop the fragment (everything from the first ``#``).
    2. Split the query off at the first ``?``.
    3. ``unquote`` the path exactly once.
    4. Collapse runs of ``/`` and strip a trailing ``/`` (the root ``/`` stays).

    Fail closed: if the unquoted path contains ``?`` or ``#`` (an encoded
    ``%3F`` / ``%23``), the path is cut at that character, because everything
    after it is query or fragment material that must never be stored as path.
    In that case, and also when the unquoted path still contains ``%`` (double
    encoding), the query is discarded (``query`` is ``None``).

    Args:
        raw_url: A request URL or path, as logged by the Gateway.

    Returns:
        The normalized path and, when it can be trusted, the raw query string.
    """
    without_fragment = raw_url.partition("#")[0]
    path, sep, query = without_fragment.partition("?")
    path = unquote(path)
    trusted = True
    cut = _QUERY_OR_FRAGMENT.search(path)
    if cut is not None:
        path = path[: cut.start()]
        trusted = False
    elif "%" in path:
        trusted = False
    path = _clean_path(path)
    return NormalizedUrl(path=path, query=query if sep and query and trusted else None)


def match_path(url: str) -> str:
    """Return the lower-cased normalized path that detection rules match against.

    Applies :func:`normalize_url` (so ``%73ecrets``, ``exec/``, ``pods//x`` and
    ``#fragment`` variants all collapse to their canonical form) and lower-cases
    the result. The query is never part of it.

    Args:
        url: A raw or stored request URL.

    Returns:
        The normalized, lower-cased path.
    """
    return normalize_url(url).path.lower()
