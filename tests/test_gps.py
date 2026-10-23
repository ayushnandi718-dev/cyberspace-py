"""Tests for the GPS mapping of spec section 9."""

from __future__ import annotations

from decimal import Decimal

from cyberspace.constants import UNITS_PER_KM
from cyberspace.coordinates import coord_to_xyz, xyz_to_coord
from cyberspace.gps import coord_to_gps, gps_to_axes, gps_to_coord
from cyberspace.redteam.vectors import GPS_VECTORS


def test_the_golden_vectors_of_the_specification_match() -> None:
    for name, latitude, longitude, expected in GPS_VECTORS:
        assert f"{gps_to_coord(latitude, longitude):064x}" == expected, name


def test_the_earth_is_centred_in_the_cube() -> None:
    """The Earth sits at the centre of the cube: the axis values are measured
    from the middle, not from a corner."""
    centre = 1 << 84
    x, y, z = gps_to_axes(0, 0)
    # A surface point is one Earth radius from the centre of the cube.
    radius_km = (x - centre) / UNITS_PER_KM
    assert 6300 < radius_km < 6400
    assert y == centre
    assert z == centre


def test_the_equator_and_the_prime_meridian_are_the_axes() -> None:
    """The mapping swaps the Earth axes into the dataspace ones (spec 9.4)."""
    x, y, z = gps_to_axes(0, 0)
    centre = 1 << 84
    assert y == centre
    assert z == centre
    assert x != centre


def test_a_position_south_of_the_equator_is_below_the_centre() -> None:
    north = gps_to_axes(45, 0)[1]
    south = gps_to_axes(-45, 0)[1]
    centre = 1 << 84
    assert north > centre > south


def test_a_position_east_of_the_meridian_is_to_one_side() -> None:
    """The longitude runs along the third dataspace axis."""
    east = gps_to_axes(0, 45)[2]
    west = gps_to_axes(0, -45)[2]
    assert east > west


def test_a_position_can_be_read_back() -> None:
    latitude, longitude = coord_to_gps(gps_to_coord(51.5074, -0.1278))
    assert abs(float(latitude) - 51.5074) < 0.01
    assert abs(float(longitude) + 0.1278) < 0.01


def test_a_latitude_beyond_the_pole_is_clamped() -> None:
    assert gps_to_axes(120, 0) == gps_to_axes(90, 0)
    assert gps_to_axes(-120, 0) == gps_to_axes(-90, 0)


def test_a_longitude_is_wrapped() -> None:
    assert gps_to_axes(0, 190) == gps_to_axes(0, -170)
    assert gps_to_axes(0, 180) == gps_to_axes(0, -180)


def test_the_altitude_is_ignored_on_the_surface() -> None:
    assert gps_to_axes(0, 0, 1000) == gps_to_axes(0, 0, 0)
    assert gps_to_axes(0, 0, 1000, clamp_to_surface=False) != gps_to_axes(0, 0, 0)


def test_a_coordinate_is_a_whole_number_of_gibsons() -> None:
    coord = gps_to_coord(51.5074, -0.1278)
    x, y, z, plane = coord_to_xyz(coord)
    assert plane == 0
    assert xyz_to_coord(x, y, z, plane) == coord
    assert all(isinstance(value, int) for value in (x, y, z))


def test_the_mapping_is_deterministic() -> None:
    first = gps_to_coord(51.5074, "-0.1278")
    second = gps_to_coord(Decimal("51.5074"), Decimal("-0.1278"))
    assert first == second
