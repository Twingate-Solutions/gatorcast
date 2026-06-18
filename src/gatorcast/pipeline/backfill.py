"""Startup backfill: index + detect already-finalized recordings lacking a sidecar.

When detection/search is added to a deployment that already holds recordings, those
sessions have a ``.cast`` file but no plaintext sidecar and no findings. This pass
walks every ``complete``/``error`` session, and for each one missing its ``.txt.enc``
sidecar it reads the recording, extracts plaintext to the sidecar, runs the detector,
and stores the findings plus the denormalized risk summary.

It is idempotent (a session with a sidecar is skipped, so a second run does nothing),
resilient (a single bad recording is logged and skipped, never aborting the pass),
and throttled (it yields to the event loop so it does not monopolize startup). Only
counters are logged — never recorded or extracted content (CLAUDE.md rule 5).
"""

from __future__ import annotations

import asyncio

from gatorcast.logging import get_logger
from gatorcast.pipeline.detect import detect, load_rules, max_severity
from gatorcast.pipeline.extract import extract_plaintext
from gatorcast.store.casts import CastStore
from gatorcast.store.search import SearchStore
from gatorcast.store.sessions import SessionRepository

log = get_logger(__name__)


async def run_backfill(
    repo: SessionRepository,
    casts: CastStore,
    search: SearchStore,
    *,
    batch_size: int = 50,
) -> int:
    """Index + detect existing finalized sessions that have no sidecar yet.

    For each complete/error session lacking a ``.txt.enc`` sidecar: read the ``.cast``
    (decrypting if needed), extract plaintext to the sidecar, run detection, store
    findings + the risk summary. Throttled (yields to the loop) and idempotent — a
    second run processes nothing. Returns the number of sessions processed. Logs
    counters only; never recorded/extracted content (CLAUDE.md rule 5).

    Args:
        repo: Session metadata repository (finalized lookup + summary update).
        casts: Cast store (read recording, write sidecar, sidecar existence check).
        search: Search store (persist findings).
        batch_size: How many sessions to process between progress yields/logs.

    Returns:
        The number of sessions processed (sidecar written + findings stored).
    """
    candidates = await repo.find_finalized()
    pending = [conn_id for conn_id, _ in candidates if not casts.has_sidecar(conn_id)]

    processed = 0
    rules = load_rules()
    for index, conn_id in enumerate(pending, start=1):
        try:
            cast_text = await casts.read_cast(conn_id)
        except FileNotFoundError:
            # The recording is gone; nothing to index. Skip without raising.
            continue
        except Exception as exc:  # noqa: BLE001 - one bad recording must not abort.
            log.warning(
                "backfill.item_error", conn_id=conn_id, error=type(exc).__name__
            )
            continue

        try:
            extract = await asyncio.to_thread(extract_plaintext, cast_text)
            await casts.write_sidecar(conn_id, extract.text)
            findings = await asyncio.to_thread(detect, extract, rules)
            await search.replace_findings(conn_id, findings)
            await repo.update_finding_summary(
                conn_id, len(findings), max_severity(findings)
            )
            processed += 1
        except Exception as exc:  # noqa: BLE001 - one bad recording must not abort.
            log.warning(
                "backfill.item_error", conn_id=conn_id, error=type(exc).__name__
            )
            continue

        # Throttle: yield to the loop every item, and log progress per batch.
        await asyncio.sleep(0)
        if index % batch_size == 0:
            log.info("backfill.progress", processed=processed, scanned=index)

    log.info("backfill.done", processed=processed)
    return processed
