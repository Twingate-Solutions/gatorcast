"""Shared access to the real Gateway sample log lines used across tests."""

from __future__ import annotations

from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def sample_lines() -> list[str]:
    """The real Gateway sample log lines, one per list entry."""
    text = (FIXTURES / "sample_log_lines.ndjson").read_text(encoding="utf-8")
    return [line for line in text.splitlines() if line.strip()]
