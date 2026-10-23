"""Bech32 encoding for Nostr keys (``npub``, ``nsec``, ``nprofile``).

Bech32 is the human-facing encoding Nostr uses for public and secret keys.
It is a checksummed base32 format: a wrong character or a wrong checksum is
rejected rather than silently producing a different key.
"""

from __future__ import annotations

__all__ = ["bech32_encode", "bech32_decode", "encode_npub", "encode_nsec", "decode_npub"]

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3


class Bech32Error(ValueError):
    """Raised when a bech32 string is malformed."""


def _polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _verify_checksum(hrp: str, data: list[int]) -> str:
    const = _polymod(_hrp_expand(hrp) + data)
    if const == BECH32_CONST:
        return "bech32"
    if const == BECH32M_CONST:
        return "bech32m"
    raise Bech32Error("invalid bech32 checksum")


def bech32_encode(hrp: str, data: bytes, constant: int = BECH32_CONST) -> str:
    """Encode raw bytes under a human-readable prefix."""
    values = [0] * 8
    acc = 0
    bits = 0
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            values.append((acc >> bits) & 31)
    if bits:
        values.append((acc << (5 - bits)) & 31)
    checksum_const = BECH32_CONST if constant == BECH32_CONST else BECH32M_CONST
    values.extend([0] * 6)
    polymod = _polymod(_hrp_expand(hrp) + values) ^ checksum_const
    values.extend((polymod >> 5 * (5 - i)) & 31 for i in range(6))
    return hrp + "1" + "".join(CHARSET[d] for d in values)


def bech32_decode(text: str) -> tuple[str, bytes]:
    """Decode a bech32 string into its prefix and raw bytes."""
    if any(ord(c) < 33 or ord(c) > 126 for c in text):
        raise Bech32Error("bech32 string has out-of-range characters")
    lowered = text.lower()
    if text != lowered and text != text.upper():
        raise Bech32Error("bech32 string has mixed case")
    pos = lowered.rfind("1")
    if pos < 1 or pos + 7 > len(lowered):
        raise Bech32Error("bech32 string has a malformed separator")
    hrp = lowered[:pos]
    data = []
    for char in lowered[pos + 1 :]:
        index = CHARSET.find(char)
        if index < 0:
            raise Bech32Error(f"invalid bech32 character: {char!r}")
        data.append(index)
    _verify_checksum(hrp, data)
    payload = data[:-6]
    acc = 0
    bits = 0
    out = bytearray()
    for value in payload:
        acc = (acc << 5) | value
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits >= 5 or ((acc << (8 - bits)) & 0xFF):
        raise Bech32Error("bech32 string has invalid padding")
    return hrp, bytes(out)


def encode_npub(pubkey: bytes) -> str:
    """Encode a 32-byte public key as ``npub1...``."""
    return bech32_encode("npub", pubkey)


def encode_nsec(secret: bytes) -> str:
    """Encode a 32-byte secret key as ``nsec1...``."""
    return bech32_encode("nsec", secret)


def decode_npub(text: str) -> bytes:
    """Decode an ``npub1...`` string into a 32-byte public key."""
    hrp, data = bech32_decode(text)
    if hrp != "npub":
        raise Bech32Error(f"expected an npub, got {hrp!r}")
    if len(data) != 32:
        raise Bech32Error("an npub must carry 32 bytes")
    return data
