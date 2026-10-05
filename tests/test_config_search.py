"""Tests for the detection/search and kubectl-activity settings on ``Settings``.

Covers the detection/search fields' defaults, an override path, and their types,
plus the kubectl activity window settings and their ``0 < gap <= max`` validator.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from gatorcast.config import Settings


def test_detection_search_defaults() -> None:
    """The four detection/search fields carry their documented defaults."""
    s = Settings()
    assert s.detection_enabled is True
    assert s.backfill_on_startup is True
    assert s.search_page_size == 50
    assert s.search_regex_max_candidates == 2000


def test_detection_search_override() -> None:
    """Explicit constructor overrides win over defaults."""
    s = Settings(
        detection_enabled=False,
        backfill_on_startup=False,
        search_page_size=10,
        search_regex_max_candidates=100,
    )
    assert s.detection_enabled is False
    assert s.backfill_on_startup is False
    assert s.search_page_size == 10
    assert s.search_regex_max_candidates == 100


def test_detection_search_types() -> None:
    """The new fields have the expected Python types."""
    s = Settings()
    assert isinstance(s.detection_enabled, bool)
    assert isinstance(s.backfill_on_startup, bool)
    assert isinstance(s.search_page_size, int)
    assert isinstance(s.search_regex_max_candidates, int)


# --- kubectl activity window (spec §8) ------------------------------------------


def test_kubectl_activity_defaults() -> None:
    """The activity gap and max window carry their documented defaults."""
    s = Settings()
    assert s.kubectl_activity_gap_seconds == 900
    assert s.kubectl_activity_max_seconds == 14400


def test_kubectl_activity_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both settings load from their KUBECTL_ACTIVITY_* environment variables."""
    monkeypatch.setenv("KUBECTL_ACTIVITY_GAP_SECONDS", "60")
    monkeypatch.setenv("KUBECTL_ACTIVITY_MAX_SECONDS", "600")
    s = Settings()
    assert s.kubectl_activity_gap_seconds == 60
    assert s.kubectl_activity_max_seconds == 600


def test_kubectl_activity_gap_equal_to_max_allowed() -> None:
    """``gap == max`` is valid (the bound is inclusive)."""
    s = Settings(kubectl_activity_gap_seconds=300, kubectl_activity_max_seconds=300)
    assert s.kubectl_activity_gap_seconds == s.kubectl_activity_max_seconds == 300


def test_kubectl_activity_gap_greater_than_max_rejected() -> None:
    """``gap > max`` fails validation."""
    with pytest.raises(ValidationError, match="KUBECTL_ACTIVITY_GAP_SECONDS"):
        Settings(kubectl_activity_gap_seconds=1000, kubectl_activity_max_seconds=999)


@pytest.mark.parametrize("gap", [0, -1])
def test_kubectl_activity_non_positive_gap_rejected(gap: int) -> None:
    """A zero or negative gap fails validation."""
    with pytest.raises(ValidationError, match="KUBECTL_ACTIVITY_GAP_SECONDS"):
        Settings(kubectl_activity_gap_seconds=gap)


def test_kubectl_activity_gap_above_default_max_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A gap raised past the default max via env is rejected at load time."""
    monkeypatch.setenv("KUBECTL_ACTIVITY_GAP_SECONDS", "20000")
    with pytest.raises(ValidationError):
        Settings()
