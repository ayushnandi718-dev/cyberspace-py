"""The GPS-to-dataspace mapping (spec section 9).

Dataspace coordinates correspond to real places on and around Earth.  The
mapping is **consensus-critical**: two clients that disagree about where a
latitude and longitude are do not merely render differently, they disagree
about where a place is.

To keep it deterministic, the whole computation runs in decimal arithmetic
with a fixed precision, a fixed pi constant, and a fixed Taylor-series
trigonometry, rather than the platform's floating-point library.

The calibration is the Cantor Height 34 scale: 2**34 Gibsons is 2 metres, so
one Gibson is 2**-33 metres and Earth is centred at exactly 2**84 on every
axis.
"""

from __future__ import annotations

from decimal import ROUND_HALF_EVEN, Decimal, localcontext

from .constants import (
    AXIS_MAX,
    CANONICAL_GPS_TO_DATASPACE_SPEC_VERSION,
    GPS_PRECISION,
    GPS_TRIG_MAX_ITER,
    UNITS_PER_KM,
)
from .coordinates import xyz_to_coord

__all__ = [
    "gps_to_coord",
    "gps_to_axes",
    "coord_to_gps",
    "CANONICAL_GPS_TO_DATASPACE_SPEC_VERSION",
]

WGS84_A = Decimal("6378137.0")
"""Semi-major axis of the WGS84 ellipsoid, in metres."""

WGS84_F = Decimal(1) / Decimal("298.257223563")
"""Flattening of the WGS84 ellipsoid."""

_EPS = Decimal("1e-88")
_MAX_ITER = GPS_TRIG_MAX_ITER


def _pi() -> Decimal:
    return Decimal(
        "3.141592653589793238462643383279502884197169399375105820974944592307"
        "8164062862089986280348253421170679"
    )


def _sin(x: Decimal) -> Decimal:
    """Deterministic sine: range reduction then a Taylor series."""
    pi = _pi()
    two_pi = pi * 2
    half_pi = pi / 2
    quarters = int((x / two_pi).to_integral_value(rounding=ROUND_HALF_EVEN))
    r = x - Decimal(quarters) * two_pi
    if r > half_pi:
        r = pi - r
    elif r < -half_pi:
        r = -pi - r
    term = r
    total = r
    n = 1
    while n < _MAX_ITER:
        term = -term * r * r / (Decimal(2 * n) * Decimal(2 * n + 1))
        total += term
        if abs(term) < _EPS:
            break
        n += 1
    return total


def _cos(x: Decimal) -> Decimal:
    """Deterministic cosine, as ``sin(x + pi/2)``."""
    return _sin(x + _pi() / 2)


def _to_radians(degrees: Decimal) -> Decimal:
    return degrees * _pi() / 180


def _decimal(value) -> Decimal:
    if isinstance(value, Decimal):
        return value
    return Decimal(str(value))


def _clamp_latitude(lat: Decimal) -> Decimal:
    if lat < -90:
        return Decimal(-90)
    if lat > 90:
        return Decimal(90)
    return lat


def _wrap_longitude(lon: Decimal) -> Decimal:
    """Wrap a longitude into ``[-180, 180)``."""
    if lon < -180:
        lon = lon + 360
    elif lon >= 180:
        lon = lon - 360
    if lon < -180 or lon >= 180:
        return _wrap_longitude(lon)
    return lon


def _ecef(lat: Decimal, lon: Decimal, altitude_m: Decimal) -> tuple[Decimal, Decimal, Decimal]:
    """WGS84 geodetic coordinates to Earth-centred Earth-fixed metres."""
    phi = _to_radians(lat)
    lam = _to_radians(lon)
    sin_phi = _sin(phi)
    cos_phi = _cos(phi)
    sin_lam = _sin(lam)
    cos_lam = _cos(lam)
    e2 = WGS84_F * (2 - WGS84_F)
    n = WGS84_A / (1 - e2 * sin_phi * sin_phi).sqrt()
    x = (n + altitude_m) * cos_phi * cos_lam
    y = (n + altitude_m) * cos_phi * sin_lam
    z = (n * (1 - e2) + altitude_m) * sin_phi
    return (x, y, z)


def _axis_value(km: Decimal) -> int:
    """Kilometres from the centre of the cube to a u85 axis value."""
    units = km * Decimal(UNITS_PER_KM) + Decimal(1 << 84)
    rounded = units.quantize(Decimal(1), rounding=ROUND_HALF_EVEN)
    value = int(rounded)
    if value < 0:
        return 0
    if value > AXIS_MAX:
        return AXIS_MAX
    return value


def gps_to_axes(
    latitude: float | str | Decimal,
    longitude: float | str | Decimal,
    altitude_m: float | str | Decimal | None = None,
    clamp_to_surface: bool = True,
) -> tuple[int, int, int]:
    """The dataspace axis values for a WGS84 position.

    Returns ``(x, y, z)`` in u85.  Altitude defaults to 0 and, with
    ``clamp_to_surface`` enabled, is forced to 0.
    """
    lat = _clamp_latitude(_decimal(latitude))
    lon = _wrap_longitude(_decimal(longitude))
    if altitude_m is None:
        altitude = Decimal(0)
    else:
        altitude = _decimal(altitude_m)
        if clamp_to_surface:
            altitude = Decimal(0)

    with localcontext() as ctx:
        ctx.prec = GPS_PRECISION
        ctx.rounding = ROUND_HALF_EVEN
        x_ecef, y_ecef, z_ecef = _ecef(lat, lon, altitude)
        x_cs = _axis_value(x_ecef / 1000)
        y_cs = _axis_value(z_ecef / 1000)
        z_cs = _axis_value(y_ecef / 1000)
    return (x_cs, y_cs, z_cs)


def gps_to_coord(
    latitude: float | str | Decimal,
    longitude: float | str | Decimal,
    altitude_m: float | str | Decimal | None = None,
    clamp_to_surface: bool = True,
) -> int:
    """The 256-bit dataspace coordinate of a WGS84 position."""
    x, y, z = gps_to_axes(latitude, longitude, altitude_m, clamp_to_surface)
    return xyz_to_coord(x, y, z, 0)


def coord_to_gps(coord: int) -> tuple[Decimal, Decimal]:
    """Approximate the WGS84 position of a dataspace coordinate.

    The inverse of the mapping, useful for showing a user where they are.
    """
    from .coordinates import coord_to_xyz

    with localcontext() as ctx:
        ctx.prec = GPS_PRECISION
        x, y, z, _plane = coord_to_xyz(coord)
        x_ecef_m = (Decimal(x) - Decimal(1 << 84)) / Decimal(UNITS_PER_KM) * 1000
        z_ecef_m = (Decimal(y) - Decimal(1 << 84)) / Decimal(UNITS_PER_KM) * 1000
        y_ecef_m = (Decimal(z) - Decimal(1 << 84)) / Decimal(UNITS_PER_KM) * 1000

        e2 = WGS84_F * (2 - WGS84_F)
        lon = _atan2(y_ecef_m, x_ecef_m)
        p = (x_ecef_m**2 + y_ecef_m**2).sqrt()
        if p == 0:
            # Exactly on the polar axis: the latitude is the pole itself.
            lat = _pi() / 2 if z_ecef_m >= 0 else -_pi() / 2
        else:
            # Bowring's iteration, refined until the latitude stops moving.
            lat = _atan2(z_ecef_m, p * (1 - e2))
            for _ in range(12):
                sin_lat = _sin(lat)
                n = WGS84_A / (1 - e2 * sin_lat * sin_lat).sqrt()
                cos_lat = _cos(lat)
                if cos_lat == 0:
                    break
                h = p / cos_lat - n
                new_lat = _atan2(z_ecef_m, p * (1 - e2 * n / (n + h)))
                if new_lat == lat:
                    break
                lat = new_lat
        return (
            lat * 180 / _pi(),
            lon * 180 / _pi(),
        )


def _atan2(y: Decimal, x: Decimal) -> Decimal:
    """The arctangent of a point, by argument reduction into the Taylor range."""
    pi = _pi()
    half_pi = pi / 2
    if x == 0 and y == 0:
        return Decimal(0)
    if x == 0:
        return half_pi if y > 0 else -half_pi
    ratio = y / x
    if ratio > 1:
        angle = half_pi - _atan_small(Decimal(1) / ratio)
    elif ratio < -1:
        angle = -(half_pi - _atan_small(Decimal(-1) / ratio))
    else:
        angle = _atan_small(ratio)
    if x < 0:
        angle += pi if y >= 0 else -pi
    return angle


def _atan_small(x: Decimal) -> Decimal:
    """Arctangent of a value in ``[-1, 1]`` by its Taylor series."""
    total = Decimal(0)
    term = x
    x_sq = x * x
    n = 0
    while n < _MAX_ITER:
        total += term / Decimal(2 * n + 1)
        if abs(term) < _EPS:
            break
        term = -term * x_sq
        n += 1
    return total
