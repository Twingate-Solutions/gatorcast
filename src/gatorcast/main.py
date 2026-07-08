"""FastAPI application entrypoint: app construction, lifespan, scheduler wiring.

This is the single process that hosts ingestion, assembly, storage, the
scheduler, and (later) the web UI. The lifespan opens the database, starts the
ingest consumer (classify → assembler), schedules the idle-finalize job, and
starts the syslog listener.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

import uvicorn
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from gatorcast.config import (
    DEFAULT_INGEST_TOKEN,
    DEFAULT_UI_AUTH_PASSWORD,
    Settings,
    get_settings,
)
from gatorcast.crypto import SIDECAR_HKDF_INFO, Cryptor
from gatorcast.db import init_db
from gatorcast.ingest.http import router as ingest_router
from gatorcast.ingest.syslog_tcp import SyslogTCPServer
from gatorcast.logging import configure_logging, get_logger
from gatorcast.pipeline.assembler import Assembler
from gatorcast.pipeline.backfill import run_backfill
from gatorcast.pipeline.classify import classify
from gatorcast.pipeline.retention import RetentionPurger
from gatorcast.store.casts import CastStore
from gatorcast.store.search import SearchStore
from gatorcast.store.sessions import SessionRepository
from gatorcast.web.routes import router as web_router

log = get_logger(__name__)


async def _consume_queue(app: FastAPI) -> None:
    """Drain the ingest queue through the pipeline: classify → assembler.

    One bad object must never kill the consumer, so processing is wrapped and
    failures are logged as a counter only (never the object's content — it may
    carry recording payloads, CLAUDE.md rule 5).
    """
    queue: asyncio.Queue[dict] = app.state.ingest_queue
    assembler: Assembler = app.state.assembler
    while True:
        obj = await queue.get()
        try:
            event = classify(obj)
            if event is not None:
                await assembler.handle(event)
        except Exception as exc:
            # Log only the exception type, never the object/content (it may carry
            # recording payloads, CLAUDE.md rule 5). asyncio.CancelledError is a
            # BaseException in 3.12, so it is NOT caught here and still propagates
            # to cancel the consumer on shutdown.
            log.warning("pipeline.error", error=type(exc).__name__)
        finally:
            queue.task_done()


def _warn_insecure_defaults(settings: Settings) -> None:
    """Warn loudly for each secret still equal to its placeholder default.

    Warn-only: the service still boots so tests and local runs keep working. The
    secret value itself is never logged (CLAUDE.md rule 5) — only the field name.
    """
    if settings.ingest_token == DEFAULT_INGEST_TOKEN:
        log.warning(
            "config.insecure_default",
            field="ingest_token",
            detail="INGEST_TOKEN is the placeholder default; set a strong value.",
        )
    if settings.ui_auth_password == DEFAULT_UI_AUTH_PASSWORD:
        log.warning(
            "config.insecure_default",
            field="ui_auth_password",
            detail="UI_AUTH_PASSWORD is the placeholder default; set a strong value.",
        )
    if settings.ui_auth_username == "admin":
        log.warning(
            "config.insecure_default",
            field="ui_auth_username",
            detail="UI_AUTH_USERNAME is still 'admin'; consider changing it.",
        )


def _build_cryptor(settings: Settings) -> Cryptor | None:
    """Build the at-rest Cryptor, failing closed when encryption is misconfigured.

    Returns ``None`` when encryption is disabled (the default), leaving ``.cast``
    files as plaintext. When ``encryption_enabled`` is true, a valid base64 32-byte
    ``GATORCAST_MASTER_KEY`` is mandatory: a missing or invalid key raises so the
    app refuses to boot rather than silently storing recordings in the clear
    (CLAUDE.md rule 5). The key value is never logged.

    Raises:
        RuntimeError: If encryption is enabled but the master key is absent or
            invalid (fail-closed).
    """
    if not settings.encryption_enabled:
        return None
    if not settings.master_key:
        log.error(
            "config.encryption_no_key",
            detail="ENCRYPTION_ENABLED=true but GATORCAST_MASTER_KEY is unset.",
        )
        raise RuntimeError(
            "Encryption enabled but GATORCAST_MASTER_KEY is not set (fail-closed)."
        )
    try:
        cryptor = Cryptor(settings.master_key)
    except ValueError as exc:
        # Do not include the key or the underlying value in the log (rule 5).
        log.error("config.encryption_bad_key", detail=str(exc))
        raise RuntimeError(
            "Encryption enabled but GATORCAST_MASTER_KEY is invalid (fail-closed)."
        ) from exc
    log.info("config.encryption_enabled")
    return cryptor


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage startup/shutdown of durable resources and background tasks."""
    settings: Settings = app.state.settings

    app.state.db = await init_db(settings.db_path)

    # Persistence: SQLite metadata repository + on-volume .cast file store.
    # The cryptor (or None) was built and validated in create_app (fail-closed). The
    # sidecar cryptor (distinct HKDF info) encrypts the search/detection plaintext
    # sidecars when encryption is enabled; None leaves them plaintext.
    repo = SessionRepository(app.state.db)
    casts = CastStore(
        settings.casts_dir,
        cryptor=app.state.cryptor,
        sidecar_cryptor=app.state.sidecar_cryptor,
    )
    # Search/detection store: findings persistence + scan-on-demand over sidecars.
    search = SearchStore(app.state.db, casts)
    app.state.repo = repo
    app.state.casts = casts
    app.state.search = search

    assembler = Assembler(
        repo=repo,
        casts=casts,
        idle_timeout_seconds=settings.idle_timeout_seconds,
        session_max_idle_seconds=settings.session_max_idle_seconds,
        search=search,
        detection_enabled=settings.detection_enabled,
    )
    app.state.assembler = assembler
    # Reconcile provisional rows orphaned by a prior crash/restart before intake.
    await assembler.sweep_startup()

    # Backfill: index + detect existing finalized sessions that lack a sidecar
    # (e.g. recordings stored before this feature, or recovered by the sweep).
    # Background + throttled + idempotent; gated by config.
    backfill_task: asyncio.Task | None = None
    if settings.backfill_on_startup and settings.detection_enabled:
        backfill_task = asyncio.create_task(run_backfill(repo, casts, search))
    app.state.backfill_task = backfill_task

    # Decouple intake from processing: front doors put objects on this queue,
    # the consumer drains it. Never let ingestion block the pipeline.
    app.state.ingest_queue = asyncio.Queue()
    consumer = asyncio.create_task(_consume_queue(app))

    scheduler = AsyncIOScheduler()
    # Idle sweep: drops abandoned chunkless sessions past IDLE_TIMEOUT_SECONDS and
    # applies the SESSION_MAX_IDLE_SECONDS crash backstop. Normal sessions finalize
    # on the Gateway's "session finished" flush, not here. Check at a bounded
    # fraction of the idle timeout so the empty-drop is reasonably prompt.
    idle_interval = max(5, min(settings.idle_timeout_seconds, 30))
    scheduler.add_job(
        assembler.finalize_idle,
        trigger="interval",
        seconds=idle_interval,
        id="idle_finalize",
        max_instances=1,
        coalesce=True,
    )
    # Retention purge: delete aged-out / over-cap recordings (row + .cast file).
    purger = RetentionPurger(
        repo=repo,
        casts=casts,
        retention_days=settings.retention_days,
        retention_max_gb=settings.retention_max_gb,
        search=search,
    )
    app.state.purger = purger
    scheduler.add_job(
        purger.run,
        trigger="interval",
        hours=24,
        id="retention_purge",
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    app.state.scheduler = scheduler

    # Syslog TCP front door (port 0 disables it).
    syslog_server: SyslogTCPServer | None = None
    if settings.syslog_tcp_port:
        syslog_server = SyslogTCPServer(
            host="0.0.0.0",
            port=settings.syslog_tcp_port,
            queue=app.state.ingest_queue,
        )
        await syslog_server.start()
    app.state.syslog_server = syslog_server

    log.info(
        "app.startup",
        http_port=settings.http_port,
        syslog_tcp_port=settings.syslog_tcp_port,
        data_dir=str(settings.data_dir),
        idle_timeout_seconds=settings.idle_timeout_seconds,
    )

    try:
        yield
    finally:
        if syslog_server is not None:
            await syslog_server.stop()
        if backfill_task is not None:
            backfill_task.cancel()
            try:
                await backfill_task
            except asyncio.CancelledError:
                pass
        consumer.cancel()
        try:
            await consumer
        except asyncio.CancelledError:
            pass
        scheduler.shutdown(wait=False)
        await app.state.db.close()
        log.info("app.shutdown")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build and return the FastAPI application.

    Args:
        settings: Optional settings override (used by tests). Defaults to
            configuration loaded from the environment.
    """
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    # Flag any secret still equal to its insecure placeholder default (warn-only).
    _warn_insecure_defaults(settings)

    # Build the at-rest cryptor up front so a misconfigured encryption setup fails
    # closed at construction — before the app starts serving (CLAUDE.md rule 5).
    cryptor = _build_cryptor(settings)
    # The sidecar cryptor derives an independent key (distinct HKDF info) from the
    # same validated master key, so it can only be built once the cast cryptor has
    # succeeded (which already proved the key is present and valid, fail-closed).
    sidecar_cryptor = (
        Cryptor(settings.master_key, info=SIDECAR_HKDF_INFO)
        if cryptor is not None
        else None
    )

    app = FastAPI(title="Gatorcast", version="0.3.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.cryptor = cryptor
    app.state.sidecar_cryptor = sidecar_cryptor

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        """Liveness probe. Returns a static OK payload."""
        return {"status": "ok"}

    # Ingestion front door (its own bearer-token auth) and the UI router (its own
    # HTTP Basic auth). The session repository and cast store the UI router reads
    # from app.state are wired in the lifespan handler above.
    app.include_router(ingest_router)
    app.include_router(web_router)

    # Vendored frontend assets, served locally — no CDN at runtime (rule 8).
    static_dir = Path(__file__).parent / "web" / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    return app


app = create_app()


def main() -> None:
    """Run the application under uvicorn (container entrypoint)."""
    settings = get_settings()
    uvicorn.run(
        "gatorcast.main:app",
        host="0.0.0.0",
        port=settings.http_port,
        log_config=None,
    )


if __name__ == "__main__":
    main()
