"""The proof of a movement (spec section 8.7).

A movement between two positions is paid for by the mathematics of the
region it crosses.  The proof of a hop is therefore the double SHA-256 of the
Cantor root of that region, bound to the event that moved and the position
it moved to.

The work a hop costs is exponential in the height of the region it crosses,
so the helpers here are for movements that are short enough to be worth
making: a hop across the lowest boundary of an axis costs one leaf.
"""

from __future__ import annotations

from .cantor import axis_root, cantor_pair
from .coordinates import Coordinate, coord_to_xyz
from .temporal import hop_preimage, movement_proof_hash

__all__ = [
    "hop_proof",
    "movement_region",
    "movement_tags",
]


def movement_region(source: Coordinate, target: Coordinate) -> int:
    """The Cantor number of the region a movement crosses.

    The region is the smallest aligned subtree that holds both positions on
    every axis, paired into a single number by the Cantor pairing.
    """
    x1, y1, z1, _p1 = coord_to_xyz(source.coord)
    x2, y2, z2, _p2 = coord_to_xyz(target.coord)
    return cantor_pair(
        cantor_pair(axis_root(x1, x2), axis_root(y1, y2)), axis_root(z1, z2)
    )


def hop_proof(previous_event_id: bytes, source: Coordinate, target: Coordinate) -> str:
    """The proof tag of a hop from one position to another (spec 8.7.1)."""
    region = movement_region(source, target)
    x2, y2, z2, p2 = coord_to_xyz(target.coord)
    preimage = hop_preimage(region, previous_event_id, (x2, y2, z2, p2))
    return movement_proof_hash(preimage).hex()


def movement_tags(
    action: str,
    genesis: str,
    previous: str,
    source: Coordinate,
    target: Coordinate,
    proof: str,
) -> list[list[str]]:
    """The tags of a movement event, as the specification lays them out."""
    from .coordinates import sector_tags

    sectors = sector_tags(target.x, target.y, target.z)
    return [
        ["A", action],
        ["e", genesis, "", "genesis"],
        ["e", previous, "", "previous"],
        ["c", source.hex],
        ["C", target.hex],
        ["proof", proof],
        ["X", sectors["X"]],
        ["Y", sectors["Y"]],
        ["Z", sectors["Z"]],
        ["S", sectors["S"]],
    ]
