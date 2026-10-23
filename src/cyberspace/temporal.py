"""The temporal axis: every hop costs fresh work (spec section 5).

A spatial Cantor root is a *stable region identifier*: the same region always
produces the same root.  That stability is what makes location-based
encryption work, but it also means a mover could cache a root and reuse it
for unbounded further movement.

The temporal axis closes that hole.  Every hop adds a fourth Cantor
computation whose height ``K`` is derived from the *destination terrain* and
whose seed is derived from the previous event's id.  Because the event id
commits to the previous proof, the seed is unknown until the previous hop is
finished, so the work cannot be precomputed, cached or replayed.

This module implements:

* the terrain function that yields the temporal height ``K`` (spec 5.2),
* the temporal axis seed and root (spec 5.3),
* the 4D hop preimage and the movement proof hash (spec 5.4 to 5.6).
"""

from __future__ import annotations

import hashlib

from .cantor import cantor_pair, compute_subtree_cantor
from .constants import AXIS_BITS, TERRAIN_CELL_BITS, TERRAIN_DOMAIN_V2
from .coordinates import xyz_to_coord
from .encoding import int_to_bytes_be_min

__all__ = [
    "terrain_height",
    "terrain_word",
    "temporal_seed",
    "temporal_root",
    "hop_preimage",
    "movement_proof_hash",
]


def terrain_word(x: int, y: int, z: int, plane: int) -> int:
    """The 16-bit terrain word at a destination (spec section 5.2).

    Four nibbles are taken from hashes of the destination aligned to cells of
    width 2**3, 2**7, 2**9 and 2**11, so nearby destinations share a terrain
    value and the landscape has "hills and valleys" in it.
    """
    nibbles: list[int] = []
    for bits in TERRAIN_CELL_BITS:
        bx = (x >> bits) << bits
        by = (y >> bits) << bits
        bz = (z >> bits) << bits
        cell_coord = xyz_to_coord(bx, by, bz, plane)
        digest = hashlib.sha256(
            TERRAIN_DOMAIN_V2 + bytes([bits]) + cell_coord.to_bytes(32, "big")
        ).digest()
        nibbles.append(digest[0] & 0x0F)
    return (nibbles[0] << 12) | (nibbles[1] << 8) | (nibbles[2] << 4) | nibbles[3]


def terrain_height(x: int, y: int, z: int, plane: int) -> int:
    """The temporal height ``K`` at a destination: the popcount of its word.

    ``K`` lies in ``[0, 16]``, so the temporal axis is always affordable:
    at most 65,536 Cantor pairs, roughly 100 ms.
    """
    return bin(terrain_word(x, y, z, plane)).count("1")


def temporal_seed(previous_event_id: bytes) -> int:
    """Reduce a previous event id into the u85 temporal axis (spec 5.3)."""
    if len(previous_event_id) != 32:
        raise ValueError("previous_event_id must be 32 raw bytes")
    return int.from_bytes(previous_event_id, "big") % (1 << AXIS_BITS)


def temporal_root(previous_event_id: bytes, height: int) -> int:
    """Cantor root of the aligned temporal subtree at the given height."""
    if not 0 <= height <= 16:
        raise ValueError("temporal height must be within [0, 16]")
    seed = temporal_seed(previous_event_id)
    base = (seed >> height) << height
    return compute_subtree_cantor(base, height)


def hop_preimage(
    region_n: int,
    previous_event_id: bytes,
    destination: tuple[int, int, int, int],
) -> int:
    """The 4D hop preimage ``pi(region_n, cantor_t)`` (spec section 5.4).

    ``destination`` is the ``(x, y, z, plane)`` of the hop's target, which
    determines the terrain height ``K``.
    """
    x, y, z, plane = destination
    height = terrain_height(x, y, z, plane)
    cantor_t = temporal_root(previous_event_id, height)
    return cantor_pair(region_n, cantor_t)


def movement_proof_hash(preimage: int) -> bytes:
    """The movement proof hash: double SHA-256 of the preimage (spec 5.6)."""
    key = hashlib.sha256(int_to_bytes_be_min(preimage)).digest()
    return hashlib.sha256(key).digest()
