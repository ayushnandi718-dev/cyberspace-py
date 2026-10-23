"""Probing a position: what it costs to be there, and to get elsewhere.

A movement in cyberspace is paid for in Cantor work, and the price is
determined by the highest boundary a movement crosses.  This module computes
that price, so that a step can be quoted before it is taken, and it derives
the region keys of a position, so that what a reader can open at that
position is known.

The work of a real movement is exponential in its height, so the price is
computed from the heights alone and the roots are only computed when they
are cheap enough to be worth the time.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..cantor import axis_geometry
from ..constants import AXIS_BITS
from ..coordinates import Coordinate, coord_to_xyz, sector_tags
from ..region import region_integer_at, region_key, region_lookup_id

__all__ = [
    "MovementCost",
    "Probe",
    "movement_cost",
    "probe",
    "region_keys_at",
]

MAX_COMPUTABLE_HEIGHT = 20
"""The highest height whose Cantor root is worth computing in pure Python.

A tree of height ``h`` has ``2**h`` leaves, and the reference timings in
the deck put height 16 at about a tenth of a second and height 22 far out
of reach.  Above this height a tool quotes the work instead of doing it.
"""


@dataclass
class MovementCost:
    """The price of one movement between two positions."""

    source: tuple[int, int, int]
    destination: tuple[int, int, int]
    bases: tuple[int, int, int]
    heights: tuple[int, int, int]

    @property
    def max_height(self) -> int:
        """The highest boundary the movement crosses."""
        return max(self.heights)

    @property
    def leaves(self) -> int:
        """The number of Cantor pairs the movement's work costs, at the top."""
        return 1 << self.max_height

    @property
    def feasible(self) -> bool:
        """Whether the movement's roots can be computed in reasonable time."""
        return self.max_height <= MAX_COMPUTABLE_HEIGHT

    def describe(self) -> str:
        """A one-line description of the price."""
        return (
            f"heights x={self.heights[0]} y={self.heights[1]} z={self.heights[2]} "
            f"max={self.max_height} work=2**{self.max_height} "
            f"({'computable' if self.feasible else 'too expensive to compute here'})"
        )


@dataclass
class Probe:
    """What is known about one position without moving."""

    coordinate: Coordinate
    sectors: dict[str, str]
    region_keys: list[tuple[int, bytes, bytes]] = field(default_factory=list)
    skipped_heights: list[int] = field(default_factory=list)

    def key_at(self, height: int) -> bytes | None:
        """The region key at a height, when it was computed."""
        for level, key, _lookup in self.region_keys:
            if level == height:
                return key
        return None

    def lookup_at(self, height: int) -> bytes | None:
        """The region lookup id at a height, when it was computed."""
        for level, _key, lookup in self.region_keys:
            if level == height:
                return lookup
        return None


def movement_cost(
    source: Coordinate, destination: Coordinate
) -> MovementCost:
    """Price the movement from one position to another."""
    bases: list[int] = []
    heights: list[int] = []
    for a, b in (
        (source.x, destination.x),
        (source.y, destination.y),
        (source.z, destination.z),
    ):
        base, height = axis_geometry(a, b)
        bases.append(base)
        heights.append(height)
    return MovementCost(
        source=(source.x, source.y, source.z),
        destination=(destination.x, destination.y, destination.z),
        bases=(bases[0], bases[1], bases[2]),
        heights=(heights[0], heights[1], heights[2]),
    )


def region_keys_at(
    coordinate: Coordinate, heights: range | list[int]
) -> tuple[list[tuple[int, bytes, bytes]], list[int]]:
    """Derive the region keys of a position at a set of heights.

    Returns the keys and lookup ids that were computed, and the heights
    that were left out because their trees are too large to compute.
    """
    keys: list[tuple[int, bytes, bytes]] = []
    skipped: list[int] = []
    for height in heights:
        if height < 1 or height > AXIS_BITS:
            raise ValueError(f"height must be between 1 and {AXIS_BITS}")
        if height > MAX_COMPUTABLE_HEIGHT:
            skipped.append(height)
            continue
        region = region_integer_at(
            coordinate.x, coordinate.y, coordinate.z, height
        )
        keys.append((height, region_key(region), region_lookup_id(region)))
    return keys, skipped


def probe(
    coordinate: Coordinate,
    min_height: int = 1,
    max_height: int = 12,
) -> Probe:
    """Look at one position: its sectors and the region keys around it."""
    keys, skipped = region_keys_at(
        coordinate, range(min_height, max_height + 1)
    )
    return Probe(
        coordinate=coordinate,
        sectors=sector_tags(coordinate.x, coordinate.y, coordinate.z),
        region_keys=keys,
        skipped_heights=skipped,
    )


def distance_between(source: Coordinate, destination: Coordinate) -> int:
    """The protocol's own distance between two positions."""
    x1, y1, z1, _p1 = coord_to_xyz(source.coord)
    x2, y2, z2, _p2 = coord_to_xyz(destination.coord)
    from ..hyperspace import distance

    return distance(source.coord, destination.coord)
