"""Read/write of ``.cast`` recording files on the data volume, plus size accounting.

Recording payloads live as ``<conn_id>.cast`` files on the named volume — never in
SQLite (CLAUDE.md rule 9). This module is the only place that touches those files:
the assembler writes them on finalize, the web layer reads them for replay, and the
retention job deletes them.

``conn_id`` path-safety is enforced upstream in ``classify`` (the single choke point
where rows/files originate, CLAUDE.md rule 5), so values reaching here are already
constrained to a safe token. Paths are still joined defensively against the casts
directory.

Recording file *contents* are never written to application logs (CLAUDE.md rule 5).

When a :class:`~gatorcast.crypto.Cryptor` is injected, ``.cast`` payloads are
encrypted with AES-256-GCM before the atomic write and decrypted on read (the
connection id is the AAD). The on-disk file is then ciphertext; size accounting
reflects that ciphertext. With no cryptor, behavior is byte-for-byte as before.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from gatorcast.crypto import Cryptor


class CastStore:
    """File-backed store for per-connection ``.cast`` recordings on the volume."""

    def __init__(
        self,
        casts_dir: Path,
        cryptor: Cryptor | None = None,
        sidecar_cryptor: Cryptor | None = None,
    ) -> None:
        """Initialize the cast store and ensure the casts directory exists.

        Args:
            casts_dir: Directory holding per-connection ``<conn_id>.cast`` files.
            cryptor: Optional encryptor for ``.cast`` payloads. When provided,
                recordings are encrypted at rest (AES-256-GCM, aad=conn_id); when
                ``None``, stored as plaintext.
            sidecar_cryptor: Optional encryptor for plaintext-extraction sidecars.
                Keyed independently from ``cryptor`` (a distinct HKDF ``info``) so a
                sidecar cannot be authenticated with the ``.cast`` key. When ``None``,
                sidecars are stored as plaintext bytes.
        """
        self._casts_dir = Path(casts_dir)
        self._casts_dir.mkdir(parents=True, exist_ok=True)
        self._cryptor = cryptor
        self._sidecar_cryptor = sidecar_cryptor

    @property
    def casts_dir(self) -> Path:
        """The directory holding ``.cast`` files."""
        return self._casts_dir

    @property
    def encryption_enabled(self) -> bool:
        """Whether stored ``.cast`` files are encrypted (a cryptor is present)."""
        return self._cryptor is not None

    def path_for(self, conn_id: str) -> Path:
        """Return the ``.cast`` path for a connection id.

        Args:
            conn_id: The connection id (already validated upstream in ``classify``).

        Returns:
            The filesystem path ``<casts_dir>/<conn_id>.cast``.
        """
        return self._casts_dir / f"{conn_id}.cast"

    async def write_cast(self, conn_id: str, text: str) -> tuple[Path, int]:
        """Write a recording atomically (temp + replace) off the event loop.

        Args:
            conn_id: The connection id naming the file.
            text: The fully reassembled asciicast document.

        Returns:
            A ``(path, size_bytes)`` tuple for the written file. ``size_bytes`` is
            the on-disk size — ciphertext size when encryption is enabled.
        """
        path = self.path_for(conn_id)
        data = text.encode("utf-8")
        if self._cryptor is not None:
            # Bind the file to its session via AAD (CLAUDE.md rule 5: secret-grade).
            data = self._cryptor.encrypt(data, conn_id.encode("utf-8"))
        size = await asyncio.to_thread(self._write_atomic, path, data)
        return path, size

    async def write_plaintext(self, conn_id: str, text: str) -> tuple[Path, int]:
        """Write a recording's current text to disk as PLAINTEXT (never encrypted).

        Used while a session is in progress (file-first model): the ``.cast`` is
        persisted on every append for durability, but stays plaintext so appends are
        cheap and no decrypt/re-encrypt is needed mid-session. It is encrypted later
        by :meth:`seal`. The write is atomic (temp + replace).

        Args:
            conn_id: The connection id naming the file.
            text: The reassembled asciicast document so far.

        Returns:
            A ``(path, size_bytes)`` tuple for the written (plaintext) file.
        """
        path = self.path_for(conn_id)
        data = text.encode("utf-8")
        size = await asyncio.to_thread(self._write_atomic, path, data)
        return path, size

    async def read_plaintext(self, conn_id_or_path: str | Path) -> str:
        """Read a recording file as PLAINTEXT (no decryption), off the event loop.

        Used to read an in-progress ``.cast`` (which is not yet encrypted) — for live
        detection, playback of an in-progress session, and to seed a reopen. Do not
        use on a sealed/encrypted file; use :meth:`read_cast` for those.

        Args:
            conn_id_or_path: A bare ``conn_id`` or a concrete ``.cast`` path.

        Returns:
            The file's UTF-8 text.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        path = self._resolve(conn_id_or_path)
        return await asyncio.to_thread(path.read_text, "utf-8")

    async def reopen(self, conn_id: str) -> str:
        """Revert a sealed (encrypted) ``.cast`` back to plaintext so it can grow again.

        Decrypts the sealed file (or reads it, when unencrypted) and rewrites it as
        plaintext. Returns the decrypted text so the caller can seed the in-memory
        reassembly baseline. Used only on the rare late chunk after a timeout-seal.

        Args:
            conn_id: The connection id to reopen.

        Returns:
            The recording's plaintext text (also now written back to disk plaintext).
        """
        text = await self.read_cast(conn_id)
        await self.write_plaintext(conn_id, text)
        return text

    async def read_cast(self, conn_id_or_path: str | Path) -> str:
        """Read a recording's text, off the event loop.

        Args:
            conn_id_or_path: Either a bare ``conn_id`` or a concrete ``.cast`` path
                (e.g. the stored ``cast_path``).

        Returns:
            The recording's text content (decrypted when encryption is enabled).

        Raises:
            FileNotFoundError: If the file does not exist.
            cryptography.exceptions.InvalidTag: If encryption is enabled and the
                file fails authentication (wrong key, tampered, or AAD mismatch).
            ValueError: If encryption is enabled and the file is not a valid
                encrypted blob (bad magic / truncated).
        """
        path = self._resolve(conn_id_or_path)
        if self._cryptor is None:
            return await asyncio.to_thread(path.read_text, "utf-8")
        blob = await asyncio.to_thread(path.read_bytes)
        # The file name stem is the conn_id, which is the AAD bound at encrypt time.
        aad = path.stem.encode("utf-8")
        plaintext = self._cryptor.decrypt(blob, aad)
        return plaintext.decode("utf-8")

    async def delete_cast(self, path: str | Path) -> bool:
        """Delete a ``.cast`` file, tolerating a missing file.

        Row-and-file deletion is one logical operation in the retention job; a file
        that is already gone is not an error (CLAUDE.md / "Retention").

        Args:
            path: The file path to remove (typically the stored ``cast_path``).

        Returns:
            ``True`` if a file was removed, ``False`` if it was already absent.
        """
        target = Path(path)
        return await asyncio.to_thread(self._unlink_missing_ok, target)

    async def total_size_bytes(self) -> int:
        """Return the total size in bytes of all ``.cast`` files in the directory.

        Used by the size-cap retention purge. Computed off the event loop.

        Returns:
            Sum of file sizes for ``*.cast`` files under the casts directory.
        """
        return await asyncio.to_thread(self._sum_sizes, self._casts_dir)

    def stat_size(self, path: str | Path) -> int:
        """Return a file's size in bytes, or 0 if it does not exist.

        Args:
            path: The file path to stat.

        Returns:
            The file size in bytes, or 0 when the file is missing.
        """
        target = Path(path)
        try:
            return target.stat().st_size
        except FileNotFoundError:
            return 0

    # --- plaintext-extraction sidecars -----------------------------------------

    def path_for_sidecar(self, conn_id: str) -> Path:
        """Return the encrypted-sidecar path ``<casts_dir>/<conn_id>.txt.enc``.

        Args:
            conn_id: The connection id (already validated upstream in ``classify``).

        Returns:
            The filesystem path ``<casts_dir>/<conn_id>.txt.enc``.
        """
        return self._casts_dir / f"{conn_id}.txt.enc"

    @property
    def sidecar_encryption_enabled(self) -> bool:
        """Whether stored sidecars are encrypted (a sidecar cryptor is present)."""
        return self._sidecar_cryptor is not None

    async def write_sidecar(self, conn_id: str, text: str) -> int:
        """Write the plaintext-extraction sidecar atomically, off the event loop.

        Encrypted with the sidecar cryptor (aad=conn_id) when present, else stored as
        plaintext bytes. The file name is always ``<conn_id>.txt.enc``, mirroring how
        ``.cast`` keeps its name whether or not encryption is on. Returns on-disk size.
        Sidecar CONTENT is secret-grade and never logged (CLAUDE.md rule 5).

        Args:
            conn_id: The connection id naming the file.
            text: The ANSI-stripped plaintext extracted from the recording.

        Returns:
            The on-disk size in bytes — ciphertext size when encryption is enabled.
        """
        path = self.path_for_sidecar(conn_id)
        data = text.encode("utf-8")
        if self._sidecar_cryptor is not None:
            # Bind the file to its session via AAD, same convention as ``.cast``.
            data = self._sidecar_cryptor.encrypt(data, conn_id.encode("utf-8"))
        return await asyncio.to_thread(self._write_atomic, path, data)

    async def read_sidecar(self, conn_id: str) -> str:
        """Read and decrypt the sidecar for a conn_id, off the event loop.

        Args:
            conn_id: The connection id whose sidecar to read.

        Returns:
            The sidecar's plaintext (decrypted when sidecar encryption is enabled).

        Raises:
            FileNotFoundError: If the sidecar file does not exist.
            cryptography.exceptions.InvalidTag: If sidecar encryption is enabled and
                the file fails authentication (wrong key, tampered, or AAD mismatch).
            ValueError: If sidecar encryption is enabled and the file is not a valid
                encrypted blob (bad magic / truncated).
        """
        path = self.path_for_sidecar(conn_id)
        if self._sidecar_cryptor is None:
            return await asyncio.to_thread(path.read_text, "utf-8")
        blob = await asyncio.to_thread(path.read_bytes)
        plaintext = self._sidecar_cryptor.decrypt(blob, conn_id.encode("utf-8"))
        return plaintext.decode("utf-8")

    async def delete_sidecar(self, conn_id: str) -> bool:
        """Delete the sidecar file, tolerating a missing file.

        Args:
            conn_id: The connection id whose sidecar to remove.

        Returns:
            ``True`` if a file was removed, ``False`` if it was already absent.
        """
        path = self.path_for_sidecar(conn_id)
        return await asyncio.to_thread(self._unlink_missing_ok, path)

    def has_sidecar(self, conn_id: str) -> bool:
        """Return True if a sidecar file exists for this conn_id (sync, for backfill).

        Args:
            conn_id: The connection id to check.

        Returns:
            ``True`` if ``<conn_id>.txt.enc`` exists on disk, else ``False``.
        """
        return self.path_for_sidecar(conn_id).is_file()

    # --- internals -------------------------------------------------------------

    def _resolve(self, conn_id_or_path: str | Path) -> Path:
        """Resolve a bare ``conn_id`` or a concrete path to a confined ``.cast`` path.

        Defense in depth (CLAUDE.md rule 5): the result is resolved and rejected
        if it escapes ``casts_dir``, mirroring the web route's confinement. Today
        the only inputs are assembler-written values, but a stored ``cast_path``
        is treated as untrusted regardless.

        Raises:
            FileNotFoundError: If the candidate resolves outside ``casts_dir``.
        """
        candidate = Path(conn_id_or_path)
        if candidate.suffix == ".cast" or candidate.parent != Path("."):
            resolved = candidate
        else:
            resolved = self.path_for(str(conn_id_or_path))

        resolved = resolved.resolve()
        base = self._casts_dir.resolve()
        if not resolved.is_relative_to(base):
            # Treat an out-of-bounds path as "not found" rather than serving it.
            raise FileNotFoundError(conn_id_or_path)
        return resolved

    @staticmethod
    def _write_atomic(path: Path, data: bytes) -> int:
        """Write bytes atomically (temp file + replace) and return the byte size.

        Writes raw bytes (not text) so newline translation never rewrites ``\\n``
        to ``\\r\\n`` on Windows — ``.cast`` byte-fidelity must be host-independent.
        The bytes are already either UTF-8 plaintext or an encrypted blob.
        """
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(path)
        return path.stat().st_size

    @staticmethod
    def _unlink_missing_ok(path: Path) -> bool:
        """Remove a file, returning whether it existed. Missing file is tolerated."""
        try:
            path.unlink()
            return True
        except FileNotFoundError:
            return False

    @staticmethod
    def _sum_sizes(casts_dir: Path) -> int:
        """Sum the sizes of all ``*.cast`` files under ``casts_dir``."""
        total = 0
        for entry in casts_dir.glob("*.cast"):
            try:
                total += entry.stat().st_size
            except FileNotFoundError:
                continue
        return total
