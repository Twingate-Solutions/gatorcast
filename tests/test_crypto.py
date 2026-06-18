"""Tests for gatorcast.crypto (Cryptor: AES-256-GCM with HKDF-derived key).

Covers:
  - round-trip encrypt → decrypt returns the original plaintext
  - on-disk blob carries the GCST magic and not the plaintext
  - a tampered byte → InvalidTag
  - a different master key → InvalidTag
  - a mismatched AAD (conn_id) → InvalidTag
  - invalid base64 / wrong-length key → constructor ValueError
  - unrecognized / truncated blob → ValueError
"""

from __future__ import annotations

import base64
import os

import pytest

from gatorcast.crypto import MAGIC, SIDECAR_HKDF_INFO, Cryptor, InvalidTag


def _key() -> str:
    """A fresh, valid base64 32-byte master key."""
    return base64.b64encode(os.urandom(32)).decode("ascii")


PLAINTEXT = (
    b'{"version":2,"width":80,"height":24,"timestamp":1700000000}\n'
    b'[0.1,"o","secret-token-on-screen"]\n'
)
AAD = b"conn-1234-5678"


def test_round_trip_returns_original() -> None:
    c = Cryptor(_key())
    blob = c.encrypt(PLAINTEXT, AAD)
    assert c.decrypt(blob, AAD) == PLAINTEXT


def test_blob_is_ciphertext_with_magic_not_plaintext() -> None:
    c = Cryptor(_key())
    blob = c.encrypt(PLAINTEXT, AAD)
    assert blob.startswith(MAGIC)
    # The recording header/content must not appear in the ciphertext.
    assert b'{"version":2' not in blob
    assert b"secret-token-on-screen" not in blob


def test_nonce_is_per_call_unique() -> None:
    c = Cryptor(_key())
    assert c.encrypt(PLAINTEXT, AAD) != c.encrypt(PLAINTEXT, AAD)


def test_tampered_byte_fails() -> None:
    c = Cryptor(_key())
    blob = bytearray(c.encrypt(PLAINTEXT, AAD))
    blob[-1] ^= 0x01  # flip a bit in the GCM tag
    with pytest.raises(InvalidTag):
        c.decrypt(bytes(blob), AAD)


def test_wrong_key_fails() -> None:
    blob = Cryptor(_key()).encrypt(PLAINTEXT, AAD)
    with pytest.raises(InvalidTag):
        Cryptor(_key()).decrypt(blob, AAD)


def test_mismatched_aad_fails() -> None:
    c = Cryptor(_key())
    blob = c.encrypt(PLAINTEXT, AAD)
    with pytest.raises(InvalidTag):
        c.decrypt(blob, b"different-conn-id")


def test_invalid_base64_key_raises() -> None:
    with pytest.raises(ValueError):
        Cryptor("not valid base64 !!!")


def test_wrong_length_key_raises() -> None:
    short = base64.b64encode(os.urandom(16)).decode("ascii")
    with pytest.raises(ValueError):
        Cryptor(short)


def test_unrecognized_header_raises() -> None:
    c = Cryptor(_key())
    bad = b"XXXX\x01\x00" + os.urandom(12) + b"ciphertext"
    with pytest.raises(ValueError):
        c.decrypt(bad, AAD)


def test_truncated_blob_raises() -> None:
    c = Cryptor(_key())
    with pytest.raises(ValueError):
        c.decrypt(MAGIC + b"\x00\x00", AAD)


def test_distinct_info_derives_independent_keys() -> None:
    """The default (.cast) info and the sidecar info derive different keys.

    A blob encrypted under one info must fail authentication when decrypted under
    the other, proving the two artifacts have cryptographically independent keys
    (Session 8 distinct-info requirement).
    """
    key = base64.b64encode(b"0" * 32).decode("ascii")
    cast_cryptor = Cryptor(key)
    sidecar_cryptor = Cryptor(key, info=SIDECAR_HKDF_INFO)

    sidecar_blob = sidecar_cryptor.encrypt(PLAINTEXT, AAD)
    with pytest.raises(InvalidTag):
        cast_cryptor.decrypt(sidecar_blob, AAD)

    cast_blob = cast_cryptor.encrypt(PLAINTEXT, AAD)
    with pytest.raises(InvalidTag):
        sidecar_cryptor.decrypt(cast_blob, AAD)
