"""Tests for the syslog TCP front door: framing + end-to-end enqueue."""

from __future__ import annotations

import asyncio

import pytest
from tests.samples import sample_lines

from gatorcast.ingest.syslog_tcp import SyslogTCPServer, read_frame


async def _reader_for(data: bytes) -> asyncio.StreamReader:
    """A StreamReader pre-loaded with ``data`` and at EOF."""
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


@pytest.mark.asyncio
async def test_octet_counting_frame() -> None:
    """RFC 6587 ``<len> <msg>`` returns exactly len bytes of message."""
    payload = sample_lines()[0]
    raw = payload.encode("utf-8")
    reader = await _reader_for(f"{len(raw)} ".encode() + raw)
    assert await read_frame(reader) == payload


@pytest.mark.asyncio
async def test_newline_frame() -> None:
    """A newline-delimited (CRLF) line is returned without the terminator."""
    payload = sample_lines()[1]
    reader = await _reader_for(payload.encode("utf-8") + b"\r\n")
    assert await read_frame(reader) == payload


@pytest.mark.asyncio
async def test_multiple_octet_frames_in_sequence() -> None:
    """Back-to-back octet frames are read one at a time."""
    a = sample_lines()[0].encode("utf-8")
    b = sample_lines()[1].encode("utf-8")
    stream = f"{len(a)} ".encode() + a + f"{len(b)} ".encode() + b
    reader = await _reader_for(stream)
    assert await read_frame(reader) == sample_lines()[0]
    assert await read_frame(reader) == sample_lines()[1]


@pytest.mark.asyncio
async def test_eof_returns_none() -> None:
    """A closed stream with no data yields None."""
    reader = await _reader_for(b"")
    assert await read_frame(reader) is None


@pytest.mark.asyncio
async def test_server_enqueues_octet_framed_message() -> None:
    """End-to-end: a connected client's octet frame lands on the queue."""
    queue: asyncio.Queue = asyncio.Queue()
    server = SyslogTCPServer(host="127.0.0.1", port=0, queue=queue)
    await server.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        raw = sample_lines()[1].encode("utf-8")
        writer.write(f"{len(raw)} ".encode() + raw)
        await writer.drain()

        obj = await asyncio.wait_for(queue.get(), timeout=2.0)
        assert obj["logger"] == "gateway"
        assert obj["resource_address"] == "kubernetes.default.svc.cluster.local"

        writer.close()
        await writer.wait_closed()
    finally:
        await server.stop()


# --- defensive bounds: FrameError regression --------------------------------


@pytest.mark.asyncio
async def test_read_frame_raises_on_oversized_declared_length() -> None:
    """An octet-count prefix declaring > MAX_FRAME_BYTES raises FrameError.

    Regression: without the cap, a hostile sender could declare a 1 GiB frame
    and force ``readexactly`` to block waiting for data that never arrives (or
    exhaust memory if it does).  The guard must fire before any readexactly call.
    """
    from gatorcast.ingest.syslog_tcp import FrameError, MAX_FRAME_BYTES

    # Declare one byte over the cap, followed by a space (which triggers the check).
    oversized = MAX_FRAME_BYTES + 1
    data = f"{oversized} ".encode()  # length prefix + space; no payload bytes
    reader = await _reader_for(data)

    with pytest.raises(FrameError, match="exceeds cap"):
        await read_frame(reader)


@pytest.mark.asyncio
async def test_read_frame_raises_on_too_many_length_digits() -> None:
    """A length prefix with more than MAX_LENGTH_DIGITS digits raises FrameError.

    Regression: without the cap, a sender could stream an infinite run of digit
    bytes, spinning the digit-accumulation loop and consuming CPU forever.
    """
    from gatorcast.ingest.syslog_tcp import FrameError, MAX_LENGTH_DIGITS

    # Build a digit run exactly one longer than the allowed maximum.
    # Use all '1's so the numeric value itself is modest (avoids the size cap).
    too_long = "1" * (MAX_LENGTH_DIGITS + 1)
    data = too_long.encode()  # no trailing space — digit loop must reject first
    reader = await _reader_for(data)

    with pytest.raises(FrameError, match="length prefix too long"):
        await read_frame(reader)


@pytest.mark.asyncio
async def test_read_frame_accepts_frame_at_exact_cap() -> None:
    """A declared length equal to MAX_FRAME_BYTES is accepted (boundary check)."""
    from gatorcast.ingest.syslog_tcp import MAX_FRAME_BYTES

    # Declare exactly MAX_FRAME_BYTES but feed only a tiny payload followed by
    # EOF; readexactly will return exc.partial — that's fine for this test, we
    # just verify no FrameError is raised on the length check itself.
    tiny_payload = b"x"
    data = f"{MAX_FRAME_BYTES} ".encode() + tiny_payload
    reader = await _reader_for(data)

    # Should not raise FrameError (may return a short string due to partial read).
    result = await read_frame(reader)
    assert result is not None
