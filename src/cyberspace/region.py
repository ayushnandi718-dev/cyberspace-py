"""Location-based encryption and discovery (spec section 7).

A **region** is an aligned cube of space.  Its Cantor root is a stable
identifier: two parties standing in the same region derive the same number
without ever communicating, because the math decides it.

A **bag** is content encrypted to the key of one region at one height.  The
ciphertext is public, so anyone can fetch it; only someone who has done the
work of computing that region's key can open it.  That is the whole idea:
content you can read only by being there.

Two layers of hashing separate the two uses of a region:

* ``location_decryption_key`` - the AES key.  Requires the region preimage.
* ``lookup_id`` - a public handle.  Safe to publish, useless for decrypting.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass

from .cantor import cantor_pair, compute_subtree_cantor
from .constants import AXIS_BITS
from .coordinates import aligned_base
from .encoding import int_to_bytes_be_min

__all__ = [
    "region_key",
    "region_lookup_id",
    "region_integer_at",
    "region_key_at",
    "region_lookup_id_at",
    "discover",
    "RegionCache",
    "RegionScan",
]


def region_key(region_n: int) -> bytes:
    """The location decryption key of a region (spec section 7.2)."""
    return hashlib.sha256(int_to_bytes_be_min(region_n)).digest()


def region_lookup_id(region_n: int) -> bytes:
    """The public lookup id of a region (spec section 7.2).

    A hash of the region key, so seeing it does not reveal the key.
    """
    return hashlib.sha256(region_key(region_n)).digest()


def region_integer_at(x: int, y: int, z: int, height: int) -> int:
    """The region integer of the aligned cube of side ``2**height`` at a point.

    The height must be at least 1 for a region to be addressable: at height 0
    a root is just a position, and the root alone does not identify its
    height (spec section 4.6).
    """
    if height < 1:
        raise ValueError("a region's height must be at least 1")
    if height > AXIS_BITS:
        raise ValueError(f"height must be <= {AXIS_BITS}")
    bx = aligned_base(x, height)
    by = aligned_base(y, height)
    bz = aligned_base(z, height)
    rx = compute_subtree_cantor(bx, height)
    ry = compute_subtree_cantor(by, height)
    rz = compute_subtree_cantor(bz, height)
    return cantor_pair(cantor_pair(rx, ry), rz)


def region_key_at(x: int, y: int, z: int, height: int) -> bytes:
    """The location decryption key of the region at a point."""
    return region_key(region_integer_at(x, y, z, height))


def region_lookup_id_at(x: int, y: int, z: int, height: int) -> bytes:
    """The lookup id of the region at a point."""
    return region_lookup_id(region_integer_at(x, y, z, height))


@dataclass(frozen=True)
class RegionScan:
    """One region found by a discovery scan."""

    height: int
    base: tuple[int, int, int]
    region_n: int
    lookup_id: bytes
    key: bytes


def discover(
    x: int, y: int, z: int, max_height: int, min_height: int = 1
) -> Iterator[RegionScan]:
    """Scan the regions around a point, one height at a time (spec section 7.4).

    Yields the regions of height ``min_height`` to ``max_height`` that contain
    the point.  The work is the same whether you travelled there or not:
    looking and walking cost the same.
    """
    if min_height < 1:
        raise ValueError("discovery starts at height 1")
    for height in range(min_height, max_height + 1):
        base = (
            aligned_base(x, height),
            aligned_base(y, height),
            aligned_base(z, height),
        )
        region = region_integer_at(x, y, z, height)
        yield RegionScan(
            height=height,
            base=base,
            region_n=region,
            lookup_id=region_lookup_id(region),
            key=region_key(region),
        )


class RegionCache:
    """A cache of region keys that survives movement (spec section 7.5).

    An aligned subtree of height ``h`` only changes when a boundary at that
    height is crossed, so after a small move most cached entries are still
    valid and no tree has to be rebuilt.
    """

    def __init__(self) -> None:
        self._entries: dict[int, tuple[tuple[int, int, int], bytes, bytes]] = {}

    def key_at(self, x: int, y: int, z: int, height: int) -> bytes:
        """The region key at a point, reusing a cached value when possible."""
        base = (
            aligned_base(x, height),
            aligned_base(y, height),
            aligned_base(z, height),
        )
        cached = self._entries.get(height)
        if cached is not None and cached[0] == base:
            return cached[1]
        region = region_integer_at(x, y, z, height)
        key = region_key(region)
        self._entries[height] = (base, key, region_lookup_id(region))
        return key

    def lookup_id_at(self, x: int, y: int, z: int, height: int) -> bytes:
        """The lookup id at a point, reusing a cached value when possible."""
        base = (
            aligned_base(x, height),
            aligned_base(y, height),
            aligned_base(z, height),
        )
        cached = self._entries.get(height)
        if cached is not None and cached[0] == base:
            return cached[2]
        region = region_integer_at(x, y, z, height)
        lookup = region_lookup_id(region)
        self._entries[height] = (base, region_key(region), lookup)
        return lookup

    def invalidate(self, height: int | None = None) -> None:
        """Drop cached entries, for one height or all of them."""
        if height is None:
            self._entries.clear()
        else:
            self._entries.pop(height, None)
