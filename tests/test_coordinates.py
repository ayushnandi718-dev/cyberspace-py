"""Tests for the coordinate system of spec section 2."""

from __future__ import annotations

import pytest

from cyberspace.constants import AXIS_MAX
from cyberspace.coordinates import (
    Coordinate,
    aligned_base,
    coord_to_hex,
    coord_to_xyz,
    hex_to_coord,
    is_valid_coord_hex,
    sector_tags,
    xyz_to_coord,
)


def test_round_trip_of_every_axis() -> None:
    for x, y, z in ((0, 0, 0), (1, 2, 3), (AXIS_MAX, AXIS_MAX, AXIS_MAX)):
        for plane in (0, 1):
            coord = xyz_to_coord(x, y, z, plane)
            assert coord_to_xyz(coord) == (x, y, z, plane)


def test_axes_are_interleaved() -> None:
    """The x axis sits on bits 3, 6, 9 and so on (spec 2.2)."""
    coord = xyz_to_coord(1, 0, 0, 0)
    assert coord == 1 << 3
    coord = xyz_to_coord(0, 1, 0, 0)
    assert coord == 1 << 2
    coord = xyz_to_coord(0, 0, 1, 0)
    assert coord == 1 << 1
    assert xyz_to_coord(0, 0, 0, 1) == 1


def test_neighbours_share_bit_prefixes() -> None:
    """Nearby coordinates agree on their high bits, which is what makes a
    short movement cheap."""
    base = 1 << 84
    left = xyz_to_coord(base, base, base, 0)
    right = xyz_to_coord(base + 1, base, base, 0)
    assert left ^ right == 1 << 3


def test_hex_is_strict() -> None:
    text = coord_to_hex(xyz_to_coord(1, 2, 3, 0))
    assert len(text) == 64
    assert hex_to_coord(text) == xyz_to_coord(1, 2, 3, 0)
    with pytest.raises(ValueError):
        hex_to_coord(text.upper())
    with pytest.raises(ValueError):
        hex_to_coord(text[:-1])
    with pytest.raises(ValueError):
        hex_to_coord("0x" + text[2:])
    assert is_valid_coord_hex(text)
    assert not is_valid_coord_hex("nope")


def test_axes_are_bounded() -> None:
    with pytest.raises(ValueError):
        xyz_to_coord(AXIS_MAX + 1, 0, 0, 0)
    with pytest.raises(ValueError):
        xyz_to_coord(0, 0, 0, 2)
    with pytest.raises(TypeError):
        Coordinate(True, 0, 0, 0)


def test_aligned_base_covers_the_subtree() -> None:
    base = aligned_base(13, 3)
    assert base == 8
    assert base % 8 == 0
    assert base <= 13 < base + 8


def test_sector_tags_are_strings() -> None:
    """Sector indices are 55 bits wide and must not be truncated."""
    sectors = sector_tags(AXIS_MAX, AXIS_MAX, AXIS_MAX)
    assert sectors["X"] == str(AXIS_MAX >> 30)
    assert sectors["S"] == f"{sectors['X']}-{sectors['Y']}-{sectors['Z']}"
