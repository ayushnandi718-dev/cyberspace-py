"""Hints: the hider's coarse statement of where a bag can be found (spec 7.7).

A bag's lookup id is a hash of a hash, so a discovery scan finds it only by
scanning the right neighbourhood.  A **hint** is the hider's optional,
public, as-coarse-as-they-like statement of where to look: an aligned box,
one height per axis, on one plane.

The seeker sweeps the box.  The number of candidates is
``2**((Hx - h) + (Hy - h) + (Hz - h))`` for a bag at height ``h``, which is
the price the hider sets when publishing the hint.

A malformed hint is treated as *absent*, never as a reason to reject the bag:
hints are advisory metadata, and the bag's validity is decided by its cipher
and its region alone.
"""

from __future__ import annotations

from dataclasses import dataclass

from .constants import AXIS_BITS, SECTOR_SHIFT
from .coordinates import aligned_base, coord_to_hex, coord_to_xyz, xyz_to_coord

__all__ = [
    "Hint",
    "hint_tags",
    "parse_hint",
    "hint_contains",
    "sweep_candidates",
]

HINT_TAG = "hint"


@dataclass(frozen=True)
class Hint:
    """A well-formed hinted box."""

    x: int
    y: int
    z: int
    plane: int
    heights: tuple[int, int, int]

    @property
    def base(self) -> tuple[int, int, int]:
        return (self.x, self.y, self.z)

    def contains(self, x: int, y: int, z: int, plane: int, bag_height: int) -> bool:
        """Whether a region of the given height at a point lies in this box."""
        if plane != self.plane:
            return False
        hx, hy, hz = self.heights
        if min(hx, hy, hz) < bag_height:
            return False
        return (
            aligned_base(x, hx) == self.x
            and aligned_base(y, hy) == self.y
            and aligned_base(z, hz) == self.z
        )


def hint_tags(
    x: int, y: int, z: int, plane: int, heights: tuple[int, int, int]
) -> list[list[str]]:
    """The tags a hider adds to a bag: the hint plus its sector tags.

    Any point inside the box may be passed; the hint carries the aligned
    base, so every hider who hints the same box publishes the same tag.
    """
    hx, hy, hz = heights
    if not all(0 <= h <= AXIS_BITS for h in heights):
        raise ValueError(f"hint heights must lie within [0, {AXIS_BITS}]")
    bx = aligned_base(x, hx)
    by = aligned_base(y, hy)
    bz = aligned_base(z, hz)
    tags: list[list[str]] = [
        [HINT_TAG, coord_to_hex(xyz_to_coord(bx, by, bz, plane)), str(hx), str(hy), str(hz)]
    ]
    known: dict[str, str] = {}
    for name, base, h in (("X", bx, hx), ("Y", by, hy), ("Z", bz, hz)):
        if h <= SECTOR_SHIFT:
            known[name] = str(base >> SECTOR_SHIFT)
            tags.append([name, known[name]])
    if len(known) == 3:
        tags.append(["S", f"{known['X']}-{known['Y']}-{known['Z']}"])
    return tags


def parse_hint(tags: list[list[str]], bag_height: int) -> Hint | None:
    """The hinted box of a bag, or ``None`` when there is no well-formed hint.

    A malformed hint is absent, not an error: wrong arity, bad hex, a base
    that is not aligned, a height outside ``[0, 85]``, a non-canonical
    integer, or a height below the bag's own height.
    """
    hint = next((t for t in tags if t and t[0] == HINT_TAG), None)
    if hint is None or len(hint) != 5:
        return None
    try:
        if len(hint[1]) != 64 or hint[1] != hint[1].lower():
            return None
        coord = int(hint[1], 16)
        heights = tuple(int(h) for h in hint[2:5])
    except ValueError:
        return None
    if any(str(h) != s for h, s in zip(heights, hint[2:5], strict=True)):
        return None
    if any(h < bag_height or h > AXIS_BITS for h in heights):
        return None
    if coord >> 256:
        return None
    x, y, z, plane = coord_to_xyz(coord)
    for value, h in zip((x, y, z), heights, strict=True):
        if h < AXIS_BITS and value & ((1 << h) - 1):
            return None
        if h == AXIS_BITS and value:
            return None
    return Hint(x=x, y=y, z=z, plane=plane, heights=heights)  # type: ignore[arg-type]


def hint_contains(
    hint: Hint, x: int, y: int, z: int, plane: int, bag_height: int
) -> bool:
    """Whether a bag's region lies inside a hinted box."""
    return hint.contains(x, y, z, plane, bag_height)


def sweep_candidates(bag_height: int, heights: tuple[int, int, int]) -> int:
    """How many region keys a seeker must derive to sweep a hinted box."""
    if any(h < bag_height for h in heights):
        raise ValueError("a hint height below the bag height cannot contain it")
    return 1 << sum(h - bag_height for h in heights)
