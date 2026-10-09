"""Plaintext reconstruction of an asciicast for search + detection.

Extraction is the single hook at finalize that feeds both content search (the
encrypted ``.txt.enc`` sidecar) and the rule-based detector. Output-only ``"o"``
events are ANSI/control-stripped and concatenated; an offset index maps each
character position back to the recording timestamp so a finding/search hit can
seek the player.

Defensive by contract: malformed input never raises (best-effort text). This
module never logs recorded content (CLAUDE.md rule 5).
"""

from __future__ import annotations

import json
import re
from bisect import bisect_right
from dataclasses import dataclass, field

# CSI (ESC[ ... final byte), OSC (ESC] ... BEL/ST), and other 2-char escapes.
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")
# Control chars to drop; keep \t (09) and \n (0a). \r is removed in _clean.
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


@dataclass(slots=True)
class ExtractResult:
    """Reconstructed plaintext plus a char-position -> time-offset index."""

    text: str
    offsets: list[tuple[int, float]] = field(default_factory=list)


def _clean(s: str) -> str:
    """Strip ANSI/control sequences from one output event's data."""
    s = _ANSI.sub("", s)
    s = s.replace("\r", "")
    return _CTRL.sub("", s)


def extract_plaintext(cast_text: str) -> ExtractResult:
    """Reconstruct a plaintext rendering of an asciicast and a char->time index.

    Output-only ``"o"`` events are ANSI-stripped and concatenated. ``offsets`` maps
    the cumulative character position at each event boundary to that event's time
    offset, enabling seek-to-finding. Never raises.

    Args:
        cast_text: The reassembled asciicast v2 document.

    Returns:
        An :class:`ExtractResult` with the cleaned text and offset index.
    """
    parts: list[str] = []
    offsets: list[tuple[int, float]] = []
    pos = 0
    # Split on "\n" only: str.splitlines() also breaks on U+0085, U+2028, U+2029 and
    # \v, \f, \x1c-\x1e, which can sit raw inside an event's JSON string and would
    # drop that event from search and detection.
    for line in cast_text.split("\n"):
        line = line.removesuffix("\r").strip()
        if not line or not line.startswith("["):
            continue
        try:
            ev = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if (
            isinstance(ev, list)
            and len(ev) >= 3
            and ev[1] == "o"
            and isinstance(ev[0], (int, float))
            and not isinstance(ev[0], bool)
            and isinstance(ev[2], str)
        ):
            cleaned = _clean(ev[2])
            if cleaned:
                offsets.append((pos, float(ev[0])))
                parts.append(cleaned)
                pos += len(cleaned)
    return ExtractResult(text="".join(parts), offsets=offsets)


def offset_at(result: ExtractResult, char_pos: int) -> float | None:
    """Return the replay time (seconds) for a character position, or None.

    Args:
        result: The extraction result holding the offset index.
        char_pos: A character position into ``result.text``.

    Returns:
        The event time offset for the event covering ``char_pos``, or ``None`` if
        there are no offsets recorded.
    """
    if not result.offsets:
        return None
    keys = [p for p, _ in result.offsets]
    i = bisect_right(keys, char_pos) - 1
    return result.offsets[i][1] if i >= 0 else result.offsets[0][1]
