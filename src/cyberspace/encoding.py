"""Canonical integer encodings used throughout the protocol (spec section 5.5).

Several protocol operations hash large integers, and the exact byte encoding
is consensus-critical: two implementations that disagree on it compute
different proofs for the same movement.
"""

from __future__ import annotations

__all__ = ["int_to_bytes_be_min", "bytes_to_int", "hex_to_bytes", "bytes_to_hex"]


def int_to_bytes_be_min(n: int) -> bytes:
    """Encode a non-negative integer as minimal big-endian bytes.

    Zero encodes as a single zero byte rather than an empty string, so that
    every integer has at least one byte.  This is the normative encoding of
    spec section 5.5.
    """
    if n < 0:
        raise ValueError("expected non-negative")
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def bytes_to_int(data: bytes) -> int:
    """Big-endian unsigned integer from bytes."""
    return int.from_bytes(data, "big")


def hex_to_bytes(text: str) -> bytes:
    """Decode a hex string, tolerating whitespace, rejecting bad input."""
    cleaned = "".join(text.split())
    if len(cleaned) % 2:
        raise ValueError("hex string has an odd number of digits")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"invalid hex string: {exc}") from exc


def bytes_to_hex(data: bytes) -> str:
    """Lowercase hex encoding of bytes."""
    return data.hex()
