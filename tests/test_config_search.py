"""Tests for the detection/search settings added to ``Settings``.

Covers the four new fields' defaults, an override path, and their types.
"""

from __future__ import annotations

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
