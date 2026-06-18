"""HTTP Basic authentication for the web UI and cast routes.

The UI surfaces secret-grade recordings (CLAUDE.md rule 5), so every UI route —
including the ``.cast`` byte stream — is gated behind this dependency. This is a
*separate* auth mechanism from ingestion: ``POST /ingest`` uses its own bearer
token (``INGEST_TOKEN``) and is unaffected by anything here.

Credentials are checked against ``ui_auth_username`` / ``ui_auth_password`` from
configuration using ``secrets.compare_digest`` to avoid timing side channels. On
failure the dependency returns ``401`` with a ``WWW-Authenticate: Basic`` header
so browsers present a login prompt.
"""

from __future__ import annotations

import secrets

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

# auto_error=False so a missing header yields our own 401 (with the
# WWW-Authenticate challenge) instead of FastAPI's default 403.
_basic = HTTPBasic(auto_error=False)

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Authentication required",
    headers={"WWW-Authenticate": "Basic"},
)


def require_ui_auth(
    request: Request,
    credentials: HTTPBasicCredentials | None = Depends(_basic),
) -> str:
    """FastAPI dependency enforcing HTTP Basic auth on UI routes.

    Compares the presented username and password against the configured UI
    credentials with constant-time comparisons. Both checks always run so the
    response time does not reveal which field was wrong.

    Args:
        request: The incoming request (used to read settings from app state).
        credentials: Decoded Basic credentials, or ``None`` if the header was
            absent or malformed.

    Returns:
        The authenticated username (useful for logging / later use).

    Raises:
        HTTPException: ``401`` with ``WWW-Authenticate: Basic`` when credentials
            are missing or do not match.
    """
    if credentials is None:
        raise _UNAUTHORIZED

    settings = request.app.state.settings
    expected_user = settings.ui_auth_username
    expected_pass = settings.ui_auth_password

    user_ok = secrets.compare_digest(
        credentials.username.encode("utf-8"), expected_user.encode("utf-8")
    )
    pass_ok = secrets.compare_digest(
        credentials.password.encode("utf-8"), expected_pass.encode("utf-8")
    )
    if not (user_ok and pass_ok):
        raise _UNAUTHORIZED

    return credentials.username
