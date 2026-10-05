"""Retention purge: delete aged-out and over-cap recordings and kubectl activity.

Driven by an APScheduler job (default daily). Two independent policies, applied in
order:

  * **Age:** delete sessions whose ``started_at`` is older than ``RETENTION_DAYS``
    (``0`` keeps forever). When an :class:`ActivityStore` is supplied, the same
    cutoff also deletes ``api_requests`` (with their ``api_findings``) and
    ``connections`` — API activity has no separate retention setting (kubectl
    activity design §11 / §14 item 4).
  * **Size:** if ``RETENTION_MAX_GB > 0``, delete the oldest *complete* sessions
    until the total ``.cast`` size is under the cap. The cap counts ``.cast`` bytes
    only and never touches API rows or connections.

Deleting the metadata row, its ``.cast`` file, its plaintext sidecar, and its
findings is one logical operation; a file that is already gone is tolerated
(CLAUDE.md / "Retention"). Only counters are logged — never recording content,
URLs, or header values (CLAUDE.md rules 2 and 5).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from gatorcast.logging import get_logger
from gatorcast.store.activity import ActivityStore
from gatorcast.store.casts import CastStore
from gatorcast.store.search import SearchStore
from gatorcast.store.sessions import PurgedSession, SessionRepository

log = get_logger(__name__)

_GB_IN_BYTES = 1024 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class AgePurgeCounts:
    """Rows removed by one age-based purge pass (all zero when the policy is off)."""

    sessions: int = 0
    api_requests: int = 0
    connections: int = 0


class RetentionPurger:
    """Applies age- and size-based retention to recordings and kubectl activity."""

    def __init__(
        self,
        repo: SessionRepository,
        casts: CastStore,
        retention_days: int,
        retention_max_gb: float,
        *,
        search: SearchStore | None = None,
        activity: ActivityStore | None = None,
    ) -> None:
        """Initialize the purger.

        Args:
            repo: Session metadata repository.
            casts: Cast file store (for deleting ``.cast`` files and sidecars).
            retention_days: Age cap in days for sessions *and* API activity;
                ``0`` disables age-based purge for both.
            retention_max_gb: Total ``.cast`` size cap in GB; ``0`` disables it.
            search: Optional search store; when provided, a purged session's
                findings are deleted alongside its row, file, and sidecar.
            activity: Optional kubectl activity store; when provided, the age purge
                also deletes ``api_requests`` (and their ``api_findings``) and
                ``connections`` older than the same cutoff.
        """
        self._repo = repo
        self._casts = casts
        self._retention_days = retention_days
        self._retention_max_gb = retention_max_gb
        self._search = search
        self._activity = activity

    async def run(self) -> None:
        """Run both retention policies and log a counters-only summary.

        Intended as the APScheduler job target. Safe to run repeatedly; a no-op when
        both policies are disabled or nothing exceeds the limits. The summary is
        logged only when at least one row was purged.
        """
        age = await self._purge_by_age()
        purged_size = await self._purge_by_size()
        if age.sessions or purged_size or age.api_requests or age.connections:
            log.info(
                "retention.purge",
                purged_age=age.sessions,
                purged_size=purged_size,
                purged_api_requests=age.api_requests,
                purged_connections=age.connections,
            )

    async def _purge_by_age(self) -> AgePurgeCounts:
        """Delete sessions and API activity older than the configured age cap.

        One cutoff, ``now - RETENTION_DAYS``, is computed and used for both the
        sessions purge and the activity purge, so the two windows never drift.

        Returns:
            The per-table deletion counts.
        """
        if self._retention_days <= 0:
            return AgePurgeCounts()
        cutoff = datetime.now(tz=timezone.utc) - timedelta(days=self._retention_days)
        iso_cutoff = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
        purged = await self._repo.purge_before(iso_cutoff)
        await self._delete_files(purged)
        api_requests = connections = 0
        if self._activity is not None:
            api_requests, connections = await self._activity.purge_before(iso_cutoff)
        return AgePurgeCounts(
            sessions=len(purged),
            api_requests=api_requests,
            connections=connections,
        )

    async def _purge_by_size(self) -> int:
        """Delete oldest complete sessions until under the size cap. Returns count.

        Counts ``.cast`` bytes only; API rows and connections are never touched.
        """
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
