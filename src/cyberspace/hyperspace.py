"""Hyperspace: the Bitcoin block transit line (DECK-0001).

Cyberspace is a cube of 2**85 Gibsons per axis, and the cube is mostly
empty.  Hyperspace is a one-dimensional line threaded through it: every
Bitcoin block is a **stop** on the line, and the stop's merkle root decides
what kind of stop it is.

* A root whose plane bit is 1 is a **port**: its coordinate is the root
  itself, a point in ideaspace.
* A root whose plane bit is 0 has **landed** on Earth: its coordinate is a
  point on the WGS84 ellipsoid chosen by the block hash, which no miner can
  steer without discarding valid blocks.

An identity boards the line from wherever it stands.  It does not choose
where it appears: it appears at its **station**, the stop nearest to it in
the protocol's own metric.  From the station it rides to any other stop by
publishing a ``hyperjump`` whose proof carries fresh, seeded work for every
block passed.  It leaves by publishing an ordinary hop or sidestep from the
stop's coordinate.

This module implements the line, the stops, the station lookup and the two
proofs: the temporal-axis entry proof of section 3.2 and the sampled ride
proof of section 5.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal, localcontext

from .cantor import compute_subtree_cantor, find_lca_height
from .constants import (
    AXIS_MAX,
    GPS_PI_STR,
    GPS_PRECISION,
    GPS_TRIG_EPS,
    GPS_TRIG_MAX_ITER,
    UNITS_PER_KM,
)
from .coordinates import coord_to_xyz, xyz_to_coord
from .encoding import int_to_bytes_be_min
from .temporal import movement_proof_hash, temporal_root, terrain_height

__all__ = [
    "Block",
    "Line",
    "K_LINE",
    "SAMPLES",
    "GRIND_HEIGHT",
    "PAD_LEAF",
    "LANDFALL_DOMAIN",
    "HYPERSPACE_TERRAIN_DOMAIN",
    "HYPERSPACE_SEED_DOMAIN",
    "HYPERSPACE_LEAF_DOMAIN",
    "HYPERSPACE_GRIND_DOMAIN",
    "HYPERSPACE_SAMPLE_DOMAIN",
    "line_terrain_k",
    "ride_leaf",
    "merkle_levels",
    "merkle_root",
    "path_of",
    "verify_path",
    "attempts_required",
    "grind_attempt",
    "meets_price",
    "sample_indices",
    "find_nonce",
    "prove_ride",
    "verify_ride",
    "landfall_coord",
    "enter_proof",
    "stop_coordinate",
    "distance",
]

K_LINE = 6
"""Height added to a block's terrain popcount to give the ride's tree height."""

SAMPLES = 32
"""Number of sampled openings published for a ride."""

HYPERSPACE_SAMPLES = SAMPLES
"""Alias, for readers that prefer the namespaced spelling."""

GRIND_HEIGHT = 16
"""Height of the Cantor tree one re-roll attempt costs."""

PAD_LEAF = bytes(32)
"""The padding leaf appended until the leaf count is a power of two."""

LANDFALL_DOMAIN = b"CYBERSPACE_LANDFALL_V1"
"""Domain separator for the landfall derivation (section 1.2)."""

HYPERSPACE_TERRAIN_DOMAIN = b"CYBERSPACE_HYPERSPACE_TERRAIN_V1"
"""Domain separator for a block's terrain word."""

HYPERSPACE_SEED_DOMAIN = b"CYBERSPACE_HYPERSPACE_SEED_V1"
"""Domain separator for a block's seeded temporal value."""

HYPERSPACE_LEAF_DOMAIN = b"CYBERSPACE_HYPERSPACE_LEAF_V1"
"""Domain separator for a ride leaf."""

HYPERSPACE_GRIND_DOMAIN = b"CYBERSPACE_HYPERSPACE_GRIND_V1"
"""Domain separator for the re-roll price."""

HYPERSPACE_SAMPLE_DOMAIN = b"CYBERSPACE_HYPERSPACE_SAMPLE_V2"
"""Domain separator for the sampled opening indices."""


def _be64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _be32(value: int) -> bytes:
    return value.to_bytes(4, "big")


# --- The line (section 1) --------------------------------------------------------


@dataclass(frozen=True)
class Block:
    """One Bitcoin block, as a stop on the line."""

    height: int
    block_hash: bytes
    merkle_root: bytes

    def __post_init__(self) -> None:
        if len(self.block_hash) != 32 or len(self.merkle_root) != 32:
            raise ValueError("a block's hash and merkle root are 32 bytes each")

    @property
    def merkle_root_int(self) -> int:
        """The merkle root read as a 256-bit big-endian integer."""
        return int.from_bytes(self.merkle_root, "big")

    @property
    def plane(self) -> int:
        """The plane the stop sits on: the root's lowest bit."""
        return self.merkle_root_int & 1

    @property
    def coord(self) -> int:
        """The coordinate of the stop."""
        return stop_coordinate(self)


def stop_coordinate(block: Block) -> int:
    """The coordinate of a stop (section 1.1 and 1.2).

    A port sits exactly at its merkle root.  A landfall sits on the WGS84
    surface at a point derived from the block hash.
    """
    if block.plane == 1:
        return block.merkle_root_int
    return landfall_coord(block.block_hash)


def distance(p: int, q: int) -> int:
    """The distance between two coordinates in the protocol's own metric.

    The distance is the height of the smallest aligned cube containing both
    points, which is exactly the boundary a direct hop between them would
    have to cross.  Plane bits are ignored.
    """
    x1, y1, z1, _p1 = coord_to_xyz(p)
    x2, y2, z2, _p2 = coord_to_xyz(q)
    return max(
        find_lca_height(x1, x2),
        find_lca_height(y1, y2),
        find_lca_height(z1, z2),
    )


class Line:
    """The line of stops, indexed by height.

    A verifier needs the whole line to answer one question: where is the
    station?  The station is the stop nearest to a coordinate among the
    stops below a declared bound, and the answer is a fact the chain
    commits to, so every reader must be able to recompute it.
    """

    def __init__(self, blocks: list[Block]) -> None:
        self._blocks: dict[int, Block] = {}
        for block in blocks:
            self._blocks[block.height] = block
        self._sorted: list[Block] = sorted(
            self._blocks.values(), key=lambda block: block.height
        )
        self._coords: dict[int, int] = {}

    @classmethod
    def from_json(cls, data: dict) -> Line:
        """Build a line from the chain-rules fixture's ``line`` object."""
        return cls(
            [
                Block(
                    height=int(entry["height"]),
                    block_hash=bytes.fromhex(entry["block_hash"]),
                    merkle_root=bytes.fromhex(entry["merkle_root"]),
                )
                for entry in data["blocks"]
            ]
        )

    def __len__(self) -> int:
        return len(self._blocks)

    def __contains__(self, height: int) -> bool:
        return height in self._blocks

    @property
    def heights(self) -> list[int]:
        """Every height on the line, ascending."""
        return [block.height for block in self._sorted]

    def block(self, height: int) -> Block | None:
        """The block at a height, or ``None``."""
        return self._blocks.get(height)

    def coord(self, height: int) -> int | None:
        """The coordinate of the stop at a height, or ``None``."""
        if height not in self._blocks:
            return None
        if height not in self._coords:
            self._coords[height] = stop_coordinate(self._blocks[height])
        return self._coords[height]

    def station(self, coord: int, bound: int) -> int | None:
        """The station of an identity at a coordinate, given a set bound.

        The station is the stop nearest to ``coord`` among the stops at or
        below ``bound``; ties go to the lowest height.  Returns the height of
        the station, or ``None`` when the bound excludes every stop.
        """
        best_height: int | None = None
        best_distance: int | None = None
        for block in self._sorted:
            if block.height > bound:
                break
            d = distance(coord, stop_coordinate(block))
            if best_distance is None or d < best_distance:
                best_distance = d
                best_height = block.height
        return best_height


# --- Landfall derivation (section 1.2) ------------------------------------------


def _sin_cos(x: Decimal) -> tuple[Decimal, Decimal]:
    """Deterministic sine and cosine, as the DECK's reference computes them.

    Range reduction into ``[-pi, pi]``, then the Taylor series, with the
    sign of the cosine folded in by mirroring the argument.
    """
    pi = Decimal(GPS_PI_STR)
    two_pi = pi * 2
    half_pi = pi / 2
    eps = Decimal(GPS_TRIG_EPS)
    max_iter = GPS_TRIG_MAX_ITER

    x = x % two_pi
    if x > pi:
        x -= two_pi
    cos_sign = Decimal(1)
    if x > half_pi:
        x = pi - x
        cos_sign = Decimal(-1)
    elif x < -half_pi:
        x = -pi - x
        cos_sign = Decimal(-1)

    x2 = x * x
    sin_sum = sin_term = x
    for k in range(1, max_iter + 1):
        sin_term = -sin_term * x2 / Decimal((2 * k) * (2 * k + 1))
        sin_sum += sin_term
        if abs(sin_term) < eps:
            break
    else:
        raise ValueError("sin() did not converge")

    cos_sum = cos_term = Decimal(1)
    for k in range(1, max_iter + 1):
        cos_term = -cos_term * x2 / Decimal((2 * k - 1) * (2 * k))
        cos_sum += cos_term
        if abs(cos_term) < eps:
            break
    else:
        raise ValueError("cos() did not converge")

    return sin_sum, cos_sum * cos_sign


def _km_to_axis_u(km: Decimal) -> int:
    """Kilometres from the centre of the cube to a u85 axis value."""
    units = km * Decimal(UNITS_PER_KM) + Decimal(1 << 84)
    value = int(units.to_integral_value(rounding=ROUND_HALF_EVEN))
    if value < 0:
        return 0
    if value > AXIS_MAX:
        return AXIS_MAX
    return value


def landfall_coord(block_hash: bytes) -> int:
    """The coordinate of a landfall: a point on the WGS84 surface (section 1.2).

    The block hash is turned into a uniform direction on the sphere, the
    direction is intersected with the ellipsoid, and the resulting point is
    permuted into Cyberspace axes.  A miner cannot steer it: choosing a
    position means discarding valid blocks.
    """
    if len(block_hash) != 32:
        raise ValueError("a block hash is 32 bytes")
    seed = hashlib.sha256(LANDFALL_DOMAIN + block_hash).digest()
    with localcontext() as ctx:
        ctx.prec = GPS_PRECISION
        ctx.rounding = ROUND_HALF_EVEN
        pi = Decimal(GPS_PI_STR)
        u1 = Decimal(int.from_bytes(seed[0:16], "big")) / Decimal(1 << 128)
        u2 = Decimal(int.from_bytes(seed[16:32], "big")) / Decimal(1 << 128)
        lon = (Decimal(2) * u1 - 1) * pi
        z = Decimal(2) * u2 - 1
        rxy = (Decimal(1) - z * z).sqrt()
        sin_lon, cos_lon = _sin_cos(lon)
        dx, dy, dz = rxy * cos_lon, rxy * sin_lon, z
        a = Decimal("6378137")
        b = a * (Decimal(1) - Decimal(1) / Decimal("298.257223563"))
        inv = (
            (dx * dx + dy * dy) / (a * a) + (dz * dz) / (b * b)
        ).sqrt()
        r = Decimal(1) / inv
        km = Decimal(1000)
        # Axis permutation per spec section 9.4: X_cs = X, Y_cs = Z, Z_cs = Y.
        x = _km_to_axis_u(r * dx / km)
        y = _km_to_axis_u(r * dz / km)
        z_cs = _km_to_axis_u(r * dy / km)
        return xyz_to_coord(x, y, z_cs, 0)


# --- The entry proof (section 3.2) ------------------------------------------------


def enter_proof(previous_event_id: bytes, coord: int) -> bytes:
    """The entry proof of an ``enter-hyperspace`` action.

    It is the base protocol's temporal axis at the boarding coordinate, with
    no spatial component: the boarding is bound to the identity's chain
    position and cannot be precomputed before the previous event exists.
    """
    x, y, z, plane = coord_to_xyz(coord)
    height = terrain_height(x, y, z, plane)
    cantor_t = temporal_root(previous_event_id, height)
    from .cantor import cantor_pair

    enter_n = cantor_pair(0, cantor_t)
    return movement_proof_hash(enter_n)


# --- The ride proof (sections 5.3 to 5.5) ----------------------------------------


def line_terrain_k(block_hash: bytes) -> int:
    """The terrain popcount of a block: the height of its ride tree."""
    digest = hashlib.sha256(HYPERSPACE_TERRAIN_DOMAIN + block_hash).digest()
    return bin((digest[0] << 8) | digest[1]).count("1")


def ride_leaf(previous_event_id: bytes, height: int, block_hash: bytes) -> bytes:
    """The leaf of one block of a ride (section 5.3).

    The leaf depends on the previous event's id, so no leaf can be computed
    before the preceding event exists, and none can be reused across
    identities or chain positions.  The height depends on the block, so the
    line has hills: some stretches cost more to pass than others.
    """
    h = line_terrain_k(block_hash) + K_LINE
    seed = int.from_bytes(
        hashlib.sha256(HYPERSPACE_SEED_DOMAIN + previous_event_id + _be64(height)).digest(),
        "big",
    ) % (1 << 85)
    base = (seed >> h) << h
    cantor = compute_subtree_cantor(base, h)
    return hashlib.sha256(
        HYPERSPACE_LEAF_DOMAIN + _be64(height) + int_to_bytes_be_min(cantor)
    ).digest()


def merkle_levels(leaves: list[bytes]) -> list[list[bytes]]:
    """The levels of a ride's Merkle tree, padded to a power of two."""
    width = 1
    while width < len(leaves):
        width *= 2
    level = list(leaves) + [PAD_LEAF] * (width - len(leaves))
    out = [level]
    while len(level) > 1:
        level = [
            hashlib.sha256(level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)
        ]
        out.append(level)
    return out


def merkle_root(leaves: list[bytes]) -> bytes:
    """The root of a ride's Merkle tree."""
    if not leaves:
        return PAD_LEAF
    return merkle_levels(leaves)[-1][0]


def path_of(levels: list[list[bytes]], index: int) -> list[bytes]:
    """The inclusion path of a leaf: the sibling at each level."""
    out: list[bytes] = []
    i = index
    for level in levels[:-1]:
        out.append(level[i ^ 1])
        i //= 2
    return out


def verify_path(leaf: bytes, index: int, path: list[bytes], root: bytes) -> bool:
    """Whether an inclusion path reaches the root."""
    current = leaf
    i = index
    for sibling in path:
        current = (
            hashlib.sha256(current + sibling).digest()
            if i % 2 == 0
            else hashlib.sha256(sibling + current).digest()
        )
        i //= 2
    return current == root


def attempts_required(length: int) -> int:
    """How many re-roll attempts a ride of this length needs on average."""
    return max(1, -(-length // SAMPLES))


def grind_attempt(previous_event_id: bytes, root: bytes, nonce: int) -> bytes:
    """One re-roll attempt: one Cantor tree at the grind height.

    Returns ``G``, the value the sampled indices are drawn from.  Each
    attempt costs about as much as one block of the ride.
    """
    seed = hashlib.sha256(
        HYPERSPACE_GRIND_DOMAIN + previous_event_id + root + _be64(nonce)
    ).digest()
    g_base = ((int.from_bytes(seed, "big") % (1 << 85)) >> GRIND_HEIGHT) << GRIND_HEIGHT
    cantor = compute_subtree_cantor(g_base, GRIND_HEIGHT)
    return hashlib.sha256(
        HYPERSPACE_GRIND_DOMAIN + seed + int_to_bytes_be_min(cantor)
    ).digest()


def meets_price(g_value: bytes, attempts: int) -> bool:
    """Whether a drawn ``G`` meets the re-roll price."""
    return int.from_bytes(g_value, "big") * attempts < (1 << 256)


def sample_indices(g_value: bytes, length: int) -> list[int]:
    """The sampled leaf positions of a ride, drawn from ``G``."""
    return [
        int.from_bytes(
            hashlib.sha256(HYPERSPACE_SAMPLE_DOMAIN + g_value + _be32(i)).digest(),
            "big",
        )
        % length
        for i in range(SAMPLES)
    ]


def find_nonce(
    previous_event_id: bytes,
    root: bytes,
    length: int,
    start: int = 0,
    accept=None,
) -> tuple[int, bytes, int]:
    """The first nonce at or after ``start`` that meets the price.

    ``accept`` is an optional predicate on ``G``, used by a prover that wants
    the samples to avoid a particular leaf.
    """
    attempts = attempts_required(length)
    nonce = start
    spent = 0
    while True:
        g_value = grind_attempt(previous_event_id, root, nonce)
        spent += 1
        if meets_price(g_value, attempts) and (accept is None or accept(g_value)):
            return nonce, g_value, spent
        nonce += 1


def prove_ride(
    previous_event_id: bytes,
    low: int,
    high: int,
    block_hash,
) -> tuple[bytes, int, list[list[bytes]]]:
    """Build a ride's proof: the root, the nonce and the sampled paths.

    ``block_hash`` is a callable taking a height and returning that block's
    hash.  The ride passes the blocks ``low + 1 .. high``.
    """
    length = high - low
    if length <= 0:
        return PAD_LEAF, 0, []
    leaves = [
        ride_leaf(previous_event_id, b, block_hash(b)) for b in range(low + 1, high + 1)
    ]
    levels = merkle_levels(leaves)
    root = levels[-1][0]
    nonce, g_value, _spent = find_nonce(previous_event_id, root, length)
    return root, nonce, [path_of(levels, i) for i in sample_indices(g_value, length)]


def verify_ride(
    previous_event_id: bytes,
    low: int,
    high: int,
    block_hash,
    root: bytes,
    nonce: int,
    openings: list[list[bytes]],
) -> bool:
    """Level 1 verification of a ride (section 5.5).

    The price is checked first, then every sampled leaf is recomputed from
    the block hashes and its inclusion path checked against the root.
    """
    length = high - low
    if length <= 0:
        return root == PAD_LEAF and nonce == 0 and not openings
    g_value = grind_attempt(previous_event_id, root, nonce)
    if not meets_price(g_value, attempts_required(length)):
        return False
    if len(openings) != SAMPLES:
        return False
    depth = len(merkle_levels([PAD_LEAF] * length)) - 1
    cache: dict[int, bytes] = {}
    for index, path in zip(
        sample_indices(g_value, length), openings, strict=True
    ):
        if len(path) != depth:
            return False
        height = low + 1 + index
        if height not in cache:
            cache[height] = ride_leaf(previous_event_id, height, block_hash(height))
        if not verify_path(cache[height], index, path, root):
            return False
    return True
