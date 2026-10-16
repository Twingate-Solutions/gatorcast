"""Per-batch intake counting shared by both front doors.

Each front door reduces input to JSON objects, classifies them here, and enqueues the
resulting events. Every object ends in exactly one outcome, and the outcome is counted:

* **accepted**, keyed by the event type name ``classify`` returned
  (``RecordingChunk``, ``SessionStart``, ``SessionEnd``, ``ApiRequest``);
* **dropped**, keyed by a reason:

  ``not_json``
      ``normalize`` could not reduce the line to a JSON object, a JSON body or array
      item was not an object, or a collector wrapper held no JSON object.
  ``noise``
      ``classify`` returned ``None``. This covers operational lines Gatorcast does not
      store as well as recognised event types ``classify`` rejected as malformed
      (bad ``conn_id``, bad sequence number, and similar); ``classify`` reports those
      only in its debug ``classify.drop`` log, not to the caller.
  ``classify_error``
      ``classify`` raised. The exception type is logged, never the object.

Blank lines are skipped and not counted.

Noise is also broken down by ``logger``. The value is attacker-controlled text, so only
names in ``KNOWN_LOGGERS`` are reported; an absent or non-string value is ``missing`` and
every other string is ``other``. No arbitrary input text reaches a count key, a response,
or a log line (CLAUDE.md rule 5).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from gatorcast.logging import get_logger
from gatorcast.pipeline.classify import Event, classify

log = get_logger(__name__)

# Logger names that may appear as keys in ``noise_by_logger``. Extend this set when the
# Gateway introduces a new logger name; anything not listed is bucketed as ``other``.
KNOWN_LOGGERS: frozenset[str] = frozenset(
    {"gateway", "gateway.audit", "system", "audit", "session_recording"}
)
LOGGER_MISSING = "missing"
LOGGER_OTHER = "other"

DROP_NOT_JSON = "not_json"
DROP_NOISE = "noise"
DROP_CLASSIFY_ERROR = "classify_error"


def logger_bucket(obj: dict) -> str:
    """Map an object's ``logger`` value onto a fixed, safe-to-report label.

    Args:
        obj: A normalized JSON object.

    Returns:
        The logger name when it is in ``KNOWN_LOGGERS``, ``missing`` when the key is
        absent or not a string, otherwise ``other``. Never the raw value of an unknown
        name.
    """
    value = obj.get("logger")
    if not isinstance(value, str):
        return LOGGER_MISSING
    return value if value in KNOWN_LOGGERS else LOGGER_OTHER


@dataclass
class IntakeCounts:
    """Outcome counts for one batch (HTTP request) or one syslog connection."""

    accepted_by_kind: Counter[str] = field(default_factory=Counter)
    dropped_by_reason: Counter[str] = field(default_factory=Counter)
    noise_by_logger: Counter[str] = field(default_factory=Counter)

    @property
    def accepted(self) -> int:
        """Total objects classified into an event."""
        return sum(self.accepted_by_kind.values())

    @property
    def dropped(self) -> int:
        """Total objects dropped for any reason."""
        return sum(self.dropped_by_reason.values())

    def drop_not_json(self, count: int = 1) -> None:
        """Record ``count`` inputs that did not reduce to a JSON object."""
        if count > 0:
            self.dropped_by_reason[DROP_NOT_JSON] += count

    def triage(self, obj: dict) -> Event | None:
        """Classify one normalized object and count the outcome.

        A ``classify`` exception is isolated here: it is counted as ``classify_error``,
        logged as ``pipeline.error`` with the exception type only, and ``None`` is
        returned, so one bad object never fails the batch or the connection.

        Args:
            obj: A normalized JSON object.

        Returns:
            The event to enqueue, or ``None`` when the object was dropped.
        """
        try:
            event = classify(obj)
        except Exception as exc:
            log.warning("pipeline.error", stage="classify", error=type(exc).__name__)
            self.dropped_by_reason[DROP_CLASSIFY_ERROR] += 1
            return None
        if event is None:
            self.dropped_by_reason[DROP_NOISE] += 1
            self.noise_by_logger[logger_bucket(obj)] += 1
            return None
        self.accepted_by_kind[type(event).__name__] += 1
        return event

    def as_dict(self) -> dict[str, Any]:
        """Render the counts as the ``/ingest`` response body and ``ingest.http`` log fields.

        Returns:
            ``accepted`` and ``dropped`` totals plus the three breakdown maps. The maps
            list only non-zero entries, sorted by key; every key is always present.
        """
        return {
            "accepted": self.accepted,
            "dropped": self.dropped,
            "accepted_by_kind": dict(sorted(self.accepted_by_kind.items())),
            "dropped_by_reason": dict(sorted(self.dropped_by_reason.items())),
            "noise_by_logger": dict(sorted(self.noise_by_logger.items())),
        }
