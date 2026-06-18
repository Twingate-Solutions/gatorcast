"""Syslog TCP ingestion front door (fallback intake).

An asyncio TCP server that accepts Gateway log lines forwarded by a syslog
shipper (Docker syslog driver, rsyslog omfwd, etc.). TCP only — asciicast lines
are multi-KB and must never be truncated, so UDP is never accepted.

Framing supported per connection, auto-detected per message:
  * RFC 6587 octet-counting: ``<len> <msg>`` (the digit count, a space, then
    exactly ``len`` bytes of message).
  * Newline-delimited (LF, optional CR): a fallback for shippers that don't
    octet-count.

Each de-framed message is handed to ``normalize`` (which strips any ``<PRI>``
syslog header) and, if it reduces to a JSON object, enqueued for the pipeline.
There is no per-message auth; rely on network position (bind internal-only).
"""

from __future__ import annotations

import asyncio

from gatorcast.ingest.normalize import normalize
from gatorcast.logging import get_logger

log = get_logger(__name__)

# Defensive bounds. asciicast lines are multi-KB but never anywhere near these,
# so legitimate traffic is untouched while a hostile peer cannot exhaust memory,
# spin on a giant length prefix, or hold a half-open connection open forever.
MAX_FRAME_BYTES = 16 * 1024 * 1024  # 16 MiB cap on a single octet-counted frame.
MAX_LENGTH_DIGITS = 10  # A frame-length prefix longer than this is hostile.
MAX_CONNECTIONS = 128  # Bound on concurrent syslog connections.
IDLE_READ_TIMEOUT_SECONDS = 300  # Reap a connection idle this long mid-read.


class FrameError(Exception):
    """A frame violated a defensive bound; the connection should be closed."""


async def read_frame(reader: asyncio.StreamReader) -> str | None:
    """Read one syslog message from the stream, handling both framings.

    Args:
        reader: The connection's stream reader.

    Returns:
        The de-framed message text, or ``None`` at end of stream.

    Raises:
        FrameError: If a declared octet-count exceeds ``MAX_FRAME_BYTES`` or the
            length-prefix digit run exceeds ``MAX_LENGTH_DIGITS`` (hostile input;
            the caller closes the connection rather than allocate).
    """
    first = await reader.read(1)
    if not first:
        return None

    # A leading run of digits followed by a space signals octet-counting.
    if first.isdigit():
        digits = bytearray(first)
        while True:
            b = await reader.read(1)
            if not b:
                # EOF mid-prefix: treat the accumulated digits as a stray line.
                text = digits.decode("utf-8", errors="replace").strip()
                return text or None
            if b == b" ":
                length = int(digits)
                if length > MAX_FRAME_BYTES:
                    # Refuse to allocate for an oversized declared frame.
                    raise FrameError(f"frame length {length} exceeds cap")
                try:
                    data = await reader.readexactly(length)
                except asyncio.IncompleteReadError as exc:
                    data = exc.partial
                return data.decode("utf-8", errors="replace")
            if b == b"\n":
                # Newline-framed line that happened to be all digits.
                return digits.rstrip(b"\r").decode("utf-8", errors="replace")
            if not b.isdigit():
                # Not octet-counting: a newline-delimited line starting w/ digits.
                rest = await reader.readline()
                return (
                    (bytes(digits) + b + rest)
                    .rstrip(b"\r\n")
                    .decode("utf-8", errors="replace")
                )
            digits += b
            if len(digits) > MAX_LENGTH_DIGITS:
                # An absurdly long length prefix is hostile; abort the connection
                # rather than keep reading digits forever.
                raise FrameError("length prefix too long")

    # Newline-delimited line not starting with a digit.
    rest = await reader.readline()
    return (first + rest).rstrip(b"\r\n").decode("utf-8", errors="replace")


class SyslogTCPServer:
    """An asyncio TCP server that normalizes and enqueues syslog messages."""

    def __init__(
        self,
        host: str,
        port: int,
        queue: asyncio.Queue[dict],
    ) -> None:
        """Initialize the server.

        Args:
            host: Bind address (use an internal interface in production).
            port: TCP port to listen on.
            queue: Shared ingest queue accepted objects are put onto.
        """
        self._host = host
        self._port = port
        self._queue = queue
        self._server: asyncio.AbstractServer | None = None
        # Bound concurrent connections so a flood of peers cannot exhaust tasks
        # or file descriptors. Excess connections are accepted then immediately
        # closed (see _handle_connection).
        self._conn_sem = asyncio.Semaphore(MAX_CONNECTIONS)

    @property
    def port(self) -> int:
        """The actual bound port (resolves an ephemeral port-0 bind)."""
        if self._server is not None and self._server.sockets:
            return self._server.sockets[0].getsockname()[1]
        return self._port

    async def start(self) -> None:
        """Begin listening for connections."""
        self._server = await asyncio.start_server(
            self._handle_connection, self._host, self._port
        )
        log.info("syslog.listening", host=self._host, port=self.port)

    async def stop(self) -> None:
        """Stop the server and wait for it to close."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            log.info("syslog.stopped")

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Read framed messages from one connection until it closes.

        Concurrency is bounded by a semaphore; over the cap the connection is
        closed immediately. Each frame read is wrapped in an idle-read timeout so
        a half-open / silent connection is reaped rather than held forever. A
        frame that violates a defensive bound closes the connection.
        """
        peer = writer.get_extra_info("peername")
        if self._conn_sem.locked():
            # At the concurrency cap: refuse without blocking the accept loop.
            log.warning("syslog.connection_rejected", peer=str(peer))
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            return

        async with self._conn_sem:
            try:
                while True:
                    message = await asyncio.wait_for(
                        read_frame(reader), timeout=IDLE_READ_TIMEOUT_SECONDS
                    )
                    if message is None:
                        break
                    obj = normalize(message)
                    if obj is not None:
                        await self._queue.put(obj)
            except FrameError as exc:
                # Hostile framing — never log content (rule 5), only the reason.
                log.warning("syslog.frame_rejected", peer=str(peer), reason=str(exc))
            except asyncio.TimeoutError:
                log.debug("syslog.idle_timeout", peer=str(peer))
            except (ConnectionError, asyncio.IncompleteReadError):
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass
                log.debug("syslog.disconnect", peer=str(peer))
