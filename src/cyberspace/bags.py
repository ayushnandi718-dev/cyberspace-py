"""Bags: content encrypted to a region (spec section 7.6).

A bag is one Nostr event whose payload is encrypted with the key of one
region at one height.  The ciphertext is public; the key is not, and cannot
be derived without doing the work of computing that region's Cantor root.

Cipher: AES-256-GCM, 12-byte nonce, 16-byte tag, no additional authenticated
data.  The wire format is ``nonce || ciphertext || tag``, base64 encoded.

A failed decryption means only that the reader does not hold this region's
key.  It is never an error in the bag.
"""

from __future__ import annotations

import base64
import os

from .constants import BAG_CIPHER, BAG_NONCE_BYTES, BAG_TAG_BYTES

__all__ = ["encrypt_payload", "decrypt_payload", "BagKeyError"]


class BagKeyError(Exception):
    """Raised when a payload cannot be opened with the supplied key."""


def _aesgcm(key: bytes):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise RuntimeError(
            "the 'cryptography' package is required for bag encryption"
        ) from exc
    if len(key) != 32:
        raise ValueError("an AES-256-GCM key must be 32 bytes")
    return AESGCM(key)


def encrypt_payload(plaintext: bytes, key: bytes) -> str:
    """Encrypt a bag payload, returning the base64 wire form.

    The nonce is fresh for every encryption.
    """
    nonce = os.urandom(BAG_NONCE_BYTES)
    sealed = _aesgcm(key).encrypt(nonce, plaintext, None)
    # cryptography appends the 16-byte tag, so sealed == ciphertext || tag.
    if len(sealed) < BAG_TAG_BYTES:
        raise ValueError("sealed payload is shorter than the GCM tag")
    blob = nonce + sealed
    return base64.b64encode(blob).decode("ascii")


def decrypt_payload(payload_b64: str, key: bytes) -> bytes:
    """Open a bag payload.

    Raises :class:`BagKeyError` when the key is wrong, which for a reader
    means "this region is not yours", not "this bag is broken".
    """
    try:
        blob = base64.b64decode(payload_b64, validate=True)
    except Exception as exc:
        raise BagKeyError("payload is not valid base64") from exc
    if len(blob) < BAG_NONCE_BYTES + BAG_TAG_BYTES:
        raise BagKeyError("payload is too short to be a bag")
    nonce = blob[:BAG_NONCE_BYTES]
    sealed = blob[BAG_NONCE_BYTES:]
    try:
        return _aesgcm(key).decrypt(nonce, sealed, None)
    except Exception as exc:
        raise BagKeyError(
            "payload does not open with this key: the region is not yours"
        ) from exc


def cipher_name() -> str:
    """The cipher identifier carried in the ``encrypted`` tag."""
    return BAG_CIPHER
