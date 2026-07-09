"""Application configuration via environment variables (pydantic-settings).

Secrets (INGEST_TOKEN, UI_AUTH_*) come from the environment / .env file.
Operational settings have safe defaults and are normally set in docker-compose.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Placeholder secret defaults. These keep tests and local runs working out of the
# box, but a startup guard (see gatorcast.main.create_app) warns loudly whenever a
# deployed value is still equal to one of these. Never log the value itself.
DEFAULT_INGEST_TOKEN = "change-me-long-random"
DEFAULT_UI_AUTH_PASSWORD = "change-me"


class Settings(BaseSettings):
    """Runtime configuration. All values overridable via environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    # --- Network ---
    http_port: int = 8080
    """FastAPI HTTP port serving the UI and POST /ingest."""

    syslog_tcp_port: int = 6514
    """Syslog TCP listener port. 0 disables the listener."""

    # --- Storage ---
    data_dir: Path = Path("/data")
    """Volume root holding the SQLite database and .cast files."""

    # --- Assembly / retention ---
    idle_timeout_seconds: int = 120
    """Idle-sweep granularity and startup-sweep cutoff — NOT a finalize trigger.

    Sets how often the idle backstop sweep runs, and on restart the age past which a
    provisional row with no ``.cast`` is treated as an abandoned start and removed.
    Normal sessions finalize on the Gateway's ``"session finished"`` flush; see
    ``session_max_idle_seconds`` for the backstop.
    """

    session_max_idle_seconds: int = 3600
    """Idle backstop for a session that never got its ``"session finished"`` flush.

    After this much silence: a recording that has data is sealed (reopenably — a
    later chunk still extends it), and a session that started but never recorded a
    valid chunk is marked ``error`` (a failed recording — commonly the transport
    dropped its chunks; see the journald note in INGESTION_RECIPES §2.1). **Must
    exceed the Gateway's flush interval** — a quiet-but-active session is chunkless
    until its first flush, so too low a value would wrongly error live sessions.
    Under encryption it also bounds how long a recording stays plaintext at rest.
    """

    retention_days: int = 90
    """Purge sessions older than this many days. 0 keeps forever."""

    retention_max_gb: float = 0
    """Optional total .cast size cap in GB. 0 disables the size-based purge."""

    # --- Encryption at rest ---
    encryption_enabled: bool = False
    """Encrypt .cast files at rest with AES-256-GCM. Opt-in (fresh-start only).

    When true, GATORCAST_MASTER_KEY must be a valid base64 32-byte key or the app
    refuses to boot (fail-closed). The metadata DB stays plaintext regardless.
    """

    master_key: str | None = Field(default=None, validation_alias="GATORCAST_MASTER_KEY")
    """Base64-encoded 32-byte master key (env GATORCAST_MASTER_KEY).

    HKDF-derived into the AES content key. Generate: ``openssl rand -base64 32``.
    Losing this key makes encrypted .cast files unrecoverable. Never logged.
    """

    # --- Secrets ---
    ingest_token: str = DEFAULT_INGEST_TOKEN
    """Shared bearer token the shipper presents to POST /ingest."""

    ui_auth_username: str = "admin"
    """Username for UI basic auth."""

    ui_auth_password: str = DEFAULT_UI_AUTH_PASSWORD
    """Password for UI basic auth."""

    # --- Detection / search ---
    detection_enabled: bool = True
    """Run the rule-based detector at finalize and store findings."""

    backfill_on_startup: bool = True
    """On boot, build sidecars + findings for existing sessions that lack them."""

    search_page_size: int = 50
    """Default number of results returned per search/listing page."""

    search_regex_max_candidates: int = 2000
    """Cap on sidecars scanned per content search (ReDoS / resource bound)."""

    # --- Logging ---
    log_level: str = "info"
    """structlog level (debug, info, warning, error)."""

    @property
    def db_path(self) -> Path:
        """Filesystem path to the SQLite database."""
        return self.data_dir / "gatorcast.db"

    @property
    def casts_dir(self) -> Path:
        """Directory holding per-connection .cast files."""
        return self.data_dir / "casts"


def get_settings() -> Settings:
    """Return a fresh Settings instance loaded from the environment."""
    return Settings()
