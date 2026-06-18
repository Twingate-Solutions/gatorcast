"""Authenticated encryption of recording payloads at rest (AES-256-GCM).

Gatorcast encrypts the sensitive bulk — the ``.cast`` recordings — on the data
volume. The metadata database stays plaintext (a documented PoC limitation; see
``docs/superpowers/specs/2026-06-18-encryption-at-rest-design.md``).

A single master key arrives from the environment (``GATORCAST_MASTER_KEY``,
base64-encoded 32 bytes). The raw env value is never used as the AES key directly:
an HKDF-SHA256 derivation produces the content key, isolating the on-disk key from
the env value and leaving room for future per-purpose subkeys (a distinct ``info``
will derive the sidecar key in Session 8).

On-disk blob format::

    MAGIC (6 bytes: b"GCST\\x01\\x00")  ||  nonce (12 bytes)  ||  ciphertext+tag

GCM is authenticated: a wrong key, a truncated file, or a single flipped byte fails
the tag check and raises. The connection id is bound in as AAD so a blob cannot be
silently relocated to a different session.

Security: this module never logs the master key, the derived key, or any plaintext
or ciphertext content (CLAUDE.md rule 5).
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# 6-byte magic prefix: 4 ASCII bytes + a 2-byte version (major, minor). Lets a
# read reject anything that is not a Gatorcast-encrypted blob before touching AEAD.
MAGIC = b"GCST\x01\x00"

# AES-256 requires a 32-byte key; GCM uses a 96-bit (12-byte) nonce by convention.
_KEY_LEN = 32
_NONCE_LEN = 12

# HKDF context binding the derived key to this purpose/version. A different `info`
# yields an independent key for a different artifact.
_HKDF_INFO = b"gatorcast/cast/v1"

# Sidecar HKDF context. Distinct from ``_HKDF_INFO`` so the plaintext-extraction
# sidecar is encrypted under a key derived independently from the ``.cast`` key:
# the same master key produces unrelated keys, and a blob cannot be authenticated
# across the two artifacts (a relocated/compromised file fails the GCM tag check).
SIDECAR_HKDF_INFO = b"gatorcast/sidecar/v1"


class Cryptor:
    """AES-256-GCM encryptor/decryptor keyed by an HKDF-derived content key.

    One instance is built at startup from the base64 master key and injected into
    the cast store. It is stateless beyond the derived key and safe to share.
    """

    def __init__(self, master_key_b64: str, info: bytes = _HKDF_INFO) -> None:
        """Validate the base64 master key and derive the AES-256 content key.

        Args:
            master_key_b64: Base64-encoded 32-byte master key, typically from
                ``GATORCAST_MASTER_KEY``. Generate with ``openssl rand -base64 32``.
            info: Optional HKDF context bound into the derivation. Defaults to the
                ``.cast`` context (:data:`_HKDF_INFO`), preserving existing behavior.
                Pass a distinct value (e.g. :data:`SIDECAR_HKDF_INFO`) to derive an
                independent key for a different artifact from the same master key.

        Raises:
            ValueError: If the value is not valid base64 or does not decode to
                exactly 32 bytes.
        """
        try:
            raw = base64.b64decode(master_key_b64, validate=True)
        except (ValueError, TypeError) as exc:
            # Do not include the offending value in the message (CLAUDE.md rule 5).
            raise ValueError("GATORCAST_MASTER_KEY is not valid base64") from exc
        if len(raw) != _KEY_LEN:
            raise ValueError(
                f"GATORCAST_MASTER_KEY must decode to {_KEY_LEN} bytes, "
                f"got {len(raw)}"
            )
        # Derive a purpose-bound content key rather than using the env value raw.
        # No salt: the master key is already high-entropy and the salt would have to
        # be stored alongside the ciphertext for a fixed deployment anyway.
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=_KEY_LEN,
            salt=None,
            info=info,
        ).derive(raw)
        self._aesgcm = AESGCM(derived)

    def encrypt(self, plaintext: bytes, aad: bytes) -> bytes:
        """Encrypt ``plaintext`` into a framed, authenticated blob.

        Args:
            plaintext: The bytes to encrypt (a reassembled ``.cast`` document).
            aad: Additional authenticated data bound to the ciphertext — the
                connection id. Not encrypted, but tamper-evident and required to
                match on decrypt.

        Returns:
            ``MAGIC || nonce || ciphertext+tag`` as a single ``bytes`` blob.
        """
        nonce = os.urandom(_NONCE_LEN)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, aad)
        return MAGIC + nonce + ciphertext

    def decrypt(self, blob: bytes, aad: bytes) -> bytes:
        """Verify framing and decrypt a blob produced by :meth:`encrypt`.

        Args:
            blob: The on-disk blob (``MAGIC || nonce || ciphertext+tag``).
            aad: The connection id that must match the value used at encrypt time.

        Returns:
            The original plaintext bytes.

        Raises:
            ValueError: If the magic prefix is wrong or the blob is too short to
                contain a nonce and ciphertext.
            cryptography.exceptions.InvalidTag: If the key, AAD, or any byte is
                wrong (authentication failure) — including a different master key
                or a mismatched connection id.
        """
        if len(blob) < len(MAGIC) + _NONCE_LEN:
            raise ValueError("encrypted blob is too short")
        if not blob.startswith(MAGIC):
            raise ValueError("encrypted blob has an unrecognized header")
        nonce = blob[len(MAGIC) : len(MAGIC) + _NONCE_LEN]
        ciphertext = blob[len(MAGIC) + _NONCE_LEN :]
        # AESGCM.decrypt raises InvalidTag on any authentication failure; let it
        # propagate so callers can count/handle it without ever logging content.
        return self._aesgcm.decrypt(nonce, ciphertext, aad)


__all__ = ["Cryptor", "MAGIC", "SIDECAR_HKDF_INFO", "InvalidTag"]
