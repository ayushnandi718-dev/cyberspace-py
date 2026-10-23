"""MD4, for the NTLM hashes that turn up in Windows audits.

NTLM is MD4 over the password in UTF-16LE, with no salt and no iteration.
OpenSSL 3 dropped MD4 from the default provider, and Python's ``hashlib``
cannot always reach it, so it is implemented here.

The implementation follows RFC 1320 and is checked against the test vectors
of that document.
"""

from __future__ import annotations

import struct

__all__ = ["md4", "ntlm_hash"]

_MASK = 0xFFFFFFFF


def _rotl(value: int, count: int) -> int:
    value &= _MASK
    return ((value << count) | (value >> (32 - count))) & _MASK


def _f(x: int, y: int, z: int) -> int:
    return (x & y) | (~x & z)


def _g(x: int, y: int, z: int) -> int:
    return (x & y) | (x & z) | (y & z)


def _h(x: int, y: int, z: int) -> int:
    return x ^ y ^ z


def md4(data: bytes) -> bytes:
    """The MD4 digest of ``data`` (RFC 1320)."""
    original_length = len(data)
    data = data + b"\x80"
    data += b"\x00" * ((56 - len(data) % 64) % 64)
    data += struct.pack("<Q", original_length * 8)

    a = 0x67452301
    b = 0xEFCDAB89
    c = 0x98BADCFE
    d = 0x10325476

    for offset in range(0, len(data), 64):
        block = struct.unpack("<16I", data[offset : offset + 64])
        x = [value & _MASK for value in block]
        aa, bb, cc, dd = a, b, c, d

        # Round 1
        for k in range(16):
            shift = (3, 7, 11, 19)[k % 4]
            if k % 4 == 0:
                a = _rotl((a + _f(b, c, d) + x[k]) & _MASK, shift)
            elif k % 4 == 1:
                d = _rotl((d + _f(a, b, c) + x[k]) & _MASK, shift)
            elif k % 4 == 2:
                c = _rotl((c + _f(d, a, b) + x[k]) & _MASK, shift)
            else:
                b = _rotl((b + _f(c, d, a) + x[k]) & _MASK, shift)

        # Round 2
        order2 = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
        for k in range(16):
            shift = (3, 5, 9, 13)[k % 4]
            if k % 4 == 0:
                a = _rotl((a + _g(b, c, d) + x[order2[k]] + 0x5A827999) & _MASK, shift)
            elif k % 4 == 1:
                d = _rotl((d + _g(a, b, c) + x[order2[k]] + 0x5A827999) & _MASK, shift)
            elif k % 4 == 2:
                c = _rotl((c + _g(d, a, b) + x[order2[k]] + 0x5A827999) & _MASK, shift)
            else:
                b = _rotl((b + _g(c, d, a) + x[order2[k]] + 0x5A827999) & _MASK, shift)

        # Round 3
        order3 = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        for k in range(16):
            shift = (3, 9, 11, 15)[k % 4]
            if k % 4 == 0:
                a = _rotl((a + _h(b, c, d) + x[order3[k]] + 0x6ED9EBA1) & _MASK, shift)
            elif k % 4 == 1:
                d = _rotl((d + _h(a, b, c) + x[order3[k]] + 0x6ED9EBA1) & _MASK, shift)
            elif k % 4 == 2:
                c = _rotl((c + _h(d, a, b) + x[order3[k]] + 0x6ED9EBA1) & _MASK, shift)
            else:
                b = _rotl((b + _h(c, d, a) + x[order3[k]] + 0x6ED9EBA1) & _MASK, shift)

        a = (a + aa) & _MASK
        b = (b + bb) & _MASK
        c = (c + cc) & _MASK
        d = (d + dd) & _MASK

    return struct.pack("<4I", a, b, c, d)


def ntlm_hash(password: str) -> str:
    """The NTLM hash of a password: MD4 over UTF-16LE, as 32 hex characters."""
    return md4(password.encode("utf-16-le")).hex()
