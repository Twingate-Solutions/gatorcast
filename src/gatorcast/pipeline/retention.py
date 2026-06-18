"""Retention purge: delete aged-out and over-cap recordings (row + ``.cast`` file).

Driven by an APScheduler job (default daily). Two independent policies, applied in
order:

  * **Age:** delete sessions whose ``started_at`` is older than ``RETENTION_DAYS``
    (``0`` keeps forever).
  * **Size:** if ``RETENTION_MAX_GB > 0``, delete the oldest *complete* sessions
    until the total ``.cast`` size is under the cap.

Deleting the metadata row, its ``.cast`` file, its plaintext sidecar, and its
findings is one logical operation; a file that is already gone is tolerated
(CLAUDE.md / "Retention"). Only counters are logged — never recording content
(CLAUDE.md rule 5).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from gatorcast.logging import get_logger
from gatorcast.store.casts import CastStore
from gatorcast.store.search import SearchStore
from gatorcast.store.sessions import PurgedSession, SessionRepository

log = get_logger(__name__)

_GB_IN_BYTES = 1024 * 1024 * 1024


class RetentionPurger:
    """Applies age- and size-based retention against the repository and cast store."""

    def __init__(
        self,
        repo: SessionRepository,
        casts: CastStore,
        retention_days: int,
        retention_max_gb: float,
        *,
        search: SearchStore | None = None,
    ) -> None:
        """Initialize the purger.

        Args:
            repo: Session metadata repository.
            casts: Cast file store (for deleting ``.cast`` files and sidecars).
            retention_days: Age cap in days; ``0`` disables age-based purge.
            retention_max_gb: Total ``.cast`` size cap in GB; ``0`` disables it.
            search: Optional search store; when provided, a purged session's
                findings are deleted alongside its row, file, and sidecar.
        """
        self._repo = repo
        self._casts = casts
        self._retention_days = retention_days
        self._retention_max_gb = retention_max_gb
        self._search = search

    async def run(self) -> None:
        """Run both retention policies and log a counters-only summary.

        Intended as the APScheduler job target. Safe to run repeatedly; a no-op when
        both policies are disabled or nothing exceeds the limits.
        """
        purged_age = await self._purge_by_age()
        purged_size = await self._purge_by_size()
        if purged_age or purged_size:
            log.info(
                "retention.purge",
                purged_age=purged_age,
                purged_size=purged_size,
            )

    async def _purge_by_age(self) -> int:
        """Delete sessions older than the configured age cap. Returns the count."""
        if self._retention_days <= 0:
            return 0
        cutoff = datetime.now(tz=timezone.utc) - timedelta(days=self._retention_days)
        iso_cutoff = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
        purged = await self._repo.purge_before(iso_cutoff)
        await self._delete_files(purged)
        return len(purged)

    async def _purge_by_size(self) -> int:
        """Delete oldest complete sessions until under the size cap. Returns count."""
        if self._retention_max_gb <= 0:
            return 0
        max_bytes = int(self._retention_max_gb * _GB_IN_BYTES)
        purged = await self._repo.purge_over_bytes(max_bytes)
        await self._delete_files(purged)
        return len(purged)

    async def _delete_files(self, purged: list[PurgedSession]) -> None:
        """Remove side artifacts for deleted rows: ``.cast`` file, sidecar, findings.

        Row deletion already happened in the repository; this cleans up everything
        that lives outside the ``sessions`` table so a purge leaves no orphans. A
        missing file or sidecar is tolerated (CLAUDE.md / "Retention"); findings are
        only deleted when a search store was supplied.
        """
        for item in purged:
            if item.cast_path:
                await self._casts.delete_cast(item.cast_path)
            # CastStore is always present; delete_sidecar tolerates a missing file.
            await self._casts.delete_sidecar(item.conn_id)
            if self._search is not None:
                await self._search.delete_findings(item.conn_id)
