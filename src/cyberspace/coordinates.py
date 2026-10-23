"""The 256-bit coordinate system (spec section 2).

A coordinate packs three 85-bit spatial axes and one plane bit into a single
256-bit integer.  The axes are *interleaved* rather than packed, so that
neighbouring coordinates share bit prefixes and nearby positions fall into the
same aligned Cantor subtrees.

Bit layout (spec section 2.2)::

    bit  0        : plane (0 = dataspace, 1 = ideaspace)
    bits 3, 6, 9  : X axis, least significant bit first
    bits 2, 5, 8  : Y axis, least significant bit first
    bits 1, 4, 7  : Z axis, least significant bit first
"""

from __future__ import annotations

from dataclasses import dataclass

from .constants import (
    AXIS_BITS,
    AXIS_MAX,
    COORD_BITS,
    PLANE_DATASPACE,
    PLANE_IDEASPACE,
    PLANE_NAMES,
    SECTOR_SHIFT,
)

__all__ = [
    "Coordinate",
    "xyz_to_coord",
    "coord_to_xyz",
    "coord_to_hex",
    "hex_to_coord",
    "is_valid_coord_hex",
    "aligned_base",
    "sector_tags",
]


@dataclass(frozen=True, order=True)
class Coordinate:
    """A position in Cyberspace.

    ``x``, ``y`` and ``z`` are unsigned 85-bit axis values; ``plane`` selects
    dataspace (0) or ideaspace (1).
    """

    x: int
    y: int
    z: int
    plane: int = PLANE_DATASPACE

    def __post_init__(self) -> None:
        for name in ("x", "y", "z"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"{name} must be an int, got {type(value).__name__}")
            if not 0 <= value <= AXIS_MAX:
                raise ValueError(f"{name}={value} is outside the 85-bit axis range")
        if self.plane not in (PLANE_DATASPACE, PLANE_IDEASPACE):
            raise ValueError(f"plane must be 0 or 1, got {self.plane!r}")

    @property
    def coord(self) -> int:
        """The packed 256-bit integer form of this coordinate."""
        return xyz_to_coord(self.x, self.y, self.z, self.plane)

    @property
    def hex(self) -> str:
        """The 32-byte lowercase hex form used in Nostr tags."""
        return coord_to_hex(self.coord)

    @property
    def plane_name(self) -> str:
        return PLANE_NAMES[self.plane]

    def offset(self, dx: int = 0, dy: int = 0, dz: int = 0) -> Coordinate:
        """Return this coordinate moved by the given axis offsets."""
        return Coordinate(self.x + dx, self.y + dy, self.z + dz, self.plane)

    def sectors(self) -> dict[str, str]:
        """The sector tag values for this coordinate (spec section 10)."""
        return sector_tags(self.x, self.y, self.z)

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.hex} ({self.plane_name})"


def xyz_to_coord(x: int, y: int, z: int, plane: int = PLANE_DATASPACE) -> int:
    """Pack three axis values and a plane bit into a 256-bit coordinate.

    This is the normative construction of spec section 2.3, transcribed.
    """
    if not 0 <= x <= AXIS_MAX:
        raise ValueError(f"x={x} is outside the 85-bit axis range")
    if not 0 <= y <= AXIS_MAX:
        raise ValueError(f"y={y} is outside the 85-bit axis range")
    if not 0 <= z <= AXIS_MAX:
        raise ValueError(f"z={z} is outside the 85-bit axis range")
    if plane not in (PLANE_DATASPACE, PLANE_IDEASPACE):
        raise ValueError(f"plane must be 0 or 1, got {plane!r}")

    coord = plane & 1
    for i in range(AXIS_BITS):
        coord |= ((z >> i) & 1) << (1 + i * 3)
        coord |= ((y >> i) & 1) << (2 + i * 3)
        coord |= ((x >> i) & 1) << (3 + i * 3)
    return coord


def coord_to_xyz(coord: int) -> tuple[int, int, int, int]:
    """Unpack a 256-bit coordinate into ``(x, y, z, plane)``."""
    if not 0 <= coord < (1 << COORD_BITS):
        raise ValueError(f"coord must fit in 256 bits, got {coord}")
    plane = coord & 1
    x = y = z = 0
    for i in range(AXIS_BITS):
        z |= ((coord >> (1 + i * 3)) & 1) << i
        y |= ((coord >> (2 + i * 3)) & 1) << i
        x |= ((coord >> (3 + i * 3)) & 1) << i
    return (x, y, z, plane)


def coord_to_hex(coord: int) -> str:
    """Encode a 256-bit coordinate as 64 lowercase hex characters."""
    return format(coord, "064x")


def hex_to_coord(text: str) -> int:
    """Decode a 64-character lowercase hex coordinate.

    Strict on purpose: the spec requires coordinates in tags to be 32-byte
    lowercase hex with no ``0x`` prefix, and a reader that accepts other
    spellings disagrees with readers that do not.
    """
    if not isinstance(text, str):
        raise TypeError("coordinate hex must be a string")
    if len(text) != 64:
        raise ValueError(f"coordinate hex must be 64 characters, got {len(text)}")
    if text != text.lower():
        raise ValueError("coordinate hex must be lowercase")
    if any(c not in "0123456789abcdef" for c in text):
        raise ValueError("coordinate hex must contain only hex digits")
    return int(text, 16)


def is_valid_coord_hex(text: str) -> bool:
    """True when ``text`` is a well-formed coordinate hex string."""
    try:
        hex_to_coord(text)
    except (TypeError, ValueError):
        return False
    return True


def aligned_base(value: int, height: int) -> int:
    """The base of the aligned region of side ``2**height`` containing ``value``.

    Spec section 4.5: an aligned subtree of height ``h`` starts at a multiple
    of ``2**h`` and covers exactly ``2**h`` consecutive leaves.
    """
    if height < 0:
        raise ValueError("height must be >= 0")
    if height > AXIS_BITS:
        raise ValueError(f"height must be <= {AXIS_BITS}")
    return (value >> height) << height


def sector_tags(x: int, y: int, z: int) -> dict[str, str]:
    """The four sector tag values for a position (spec section 10).

    Returns the values for the ``X``, ``Y``, ``Z`` and ``S`` tags.  Sector
    indices are 55 bits wide, so they must not be stored in 32-bit integers.
    """
    sx = x >> SECTOR_SHIFT
    sy = y >> SECTOR_SHIFT
    sz = z >> SECTOR_SHIFT
    return {
        "X": str(sx),
        "Y": str(sy),
        "Z": str(sz),
        "S": f"{sx}-{sy}-{sz}",
    }
