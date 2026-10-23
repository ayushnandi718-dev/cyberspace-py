"""The sidestep: crossing a wall with a Merkle hash tree (spec section 6).

A Cantor hop computes a region root, but the intermediate values of a Cantor
tree grow exponentially in width, so beyond roughly h25 the computation no
longer fits in storage.  Those high boundaries are walls.

A **sidestep** crosses a wall using a Merkle hash tree over SHA-256 hashes of
the leaf coordinates instead.  SHA-256 is fixed-size, so there is no storage
bottleneck: the cost is pure time.

Three properties make the construction sound:

* **Seeding.**  The tree is seeded by the mover's chain position, so a
  published root is worth nothing to anybody else.  Crossing a boundary is a
  toll paid in full by every traveller.
* **Axis separation.**  The seed includes an axis byte, so identical subtrees
  on different axes produce different roots.
* **Sampled openings.**  A destination inclusion path alone does not prove
  the tree was built over the aligned subtree.  The prover must also publish
  eight sampled inclusion paths, and the sample positions cost a re-roll
  price, so skipping work and retrying never pays.

This module implements proving and verifying, at Level 1 (sampled openings)
and Level 2 (full root recomputation).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .cantor import find_lca_height
from .constants import (
    AXIS_BYTES,
    AXIS_X,
    AXIS_Y,
    AXIS_Z,
    SEED_PAD,
    SIDESTEP_DOMAIN,
    SIDESTEP_GRIND_DOMAIN,
    SIDESTEP_SAMPLE_DOMAIN,
    SIDESTEP_SAMPLES,
)
from .encoding import int_to_bytes_be_min

__all__ = [
    "SidestepProof",
    "seed_prefix",
    "leaf_hash",
    "merkle_root_streaming",
    "merkle_levels",
    "inclusion_path",
    "verify_path",
    "axis_geometry",
    "crossing_geometry_ok",
    "reroll_attempts",
    "grind_hash",
    "meets_price",
    "find_nonce",
    "sample_indices",
    "prove_sidestep",
    "verify_sidestep",
    "verify_sidestep_level2",
    "encode_roots_tag",
    "decode_roots_tag",
    "encode_openings_tag",
    "decode_openings_tag",
]


def seed_prefix(previous_event_id: bytes, axis_byte: int) -> bytes:
    """The 64-byte seed prefix for one axis (spec section 6.4).

    Exactly one SHA-256 block, so seeding costs no extra compression per
    leaf and the midstate can be reused for the whole tree.
    """
    if len(previous_event_id) != 32:
        raise ValueError("previous_event_id must be 32 raw bytes")
    prefix = SIDESTEP_DOMAIN + previous_event_id + bytes([axis_byte]) + SEED_PAD
    if len(prefix) != 64:
        raise ValueError("seed prefix must be exactly one SHA-256 block")
    return prefix


def leaf_hash(prefix: bytes, value: int) -> bytes:
    """Hash of one leaf coordinate under a seed prefix."""
    return hashlib.sha256(prefix + int_to_bytes_be_min(value)).digest()


def merkle_root_streaming(prefix: bytes, base: int, height: int) -> bytes:
    """Merkle root over an aligned subtree, in O(height) memory (spec 6.5).

    Leaves are enumerated in ascending order from ``base``.  Total work is
    ``2**(height+1) - 1`` hashes.
    """
    if height == 0:
        return leaf_hash(prefix, base)
    stack: list[tuple[bytes, int]] = []
    for i in range(1 << height):
        current = leaf_hash(prefix, base + i)
        level = 0
        while stack and stack[-1][1] == level:
            left = stack.pop()[0]
            current = hashlib.sha256(left + current).digest()
            level += 1
        stack.append((current, level))
    return stack[0][0]


def merkle_levels(prefix: bytes, base: int, height: int) -> list[list[bytes]]:
    """All levels of the tree, leaves first.  Only for small heights."""
    level = [leaf_hash(prefix, base + i) for i in range(1 << height)]
    out = [level]
    while len(level) > 1:
        level = [
            hashlib.sha256(level[j] + level[j + 1]).digest()
            for j in range(0, len(level), 2)
        ]
        out.append(level)
    return out


def inclusion_path(prefix: bytes, base: int, height: int, index: int) -> list[bytes]:
    """Sibling hashes from leaf to root for the leaf at ``index``."""
    if not 0 <= index < (1 << height):
        raise ValueError("leaf index out of range for this subtree")
    levels = merkle_levels(prefix, base, height)
    out: list[bytes] = []
    i = index
    for depth in range(height):
        out.append(levels[depth][i ^ 1])
        i //= 2
    return out


def verify_path(leaf: bytes, index: int, siblings: list[bytes], root: bytes) -> bool:
    """Check an inclusion path against a root."""
    current = leaf
    i = index
    for sibling in siblings:
        current = (
            hashlib.sha256(current + sibling).digest()
            if i % 2 == 0
            else hashlib.sha256(sibling + current).digest()
        )
        i //= 2
    return current == root


def axis_geometry(v1: int, v2: int) -> tuple[int, int]:
    """``(base, height)`` of the covering aligned subtree for an axis."""
    height = find_lca_height(v1, v2)
    return ((v1 >> height) << height, height)


def crossing_geometry_ok(v1: int, v2: int) -> bool:
    """Whether a 1-Gibson step on one axis is a valid wall crossing (spec 6.3).

    The source must be the leaf touching the wall on its own side and the
    destination must be the neighbouring leaf on the other side.
    """
    if v1 == v2:
        return True
    if abs(v2 - v1) != 1:
        return False
    height = find_lca_height(v1, v2)
    base = (v1 >> height) << height
    half = 1 << (height - 1)
    if v2 > v1:
        return v1 == base + half - 1
    return v1 == base + half


def reroll_attempts(heights: list[int] | tuple[int, ...]) -> int:
    """Expected re-roll attempts ``A = ceil(L / SIDESTEP_SAMPLES)``.

    ``L`` is the total number of leaves over the axes that move.  One attempt
    costs one leaf's share of the tree, so the price is one eighth of the
    crossing: the smallest price at which trying again never pays.
    """
    leaves = sum(1 << h for h in heights if h > 0)
    return max(1, -(-leaves // SIDESTEP_SAMPLES))


def grind_hash(previous_event_id: bytes, roots: tuple[bytes, bytes, bytes], nonce: int) -> bytes:
    """The re-roll price hash ``G`` (spec section 6.10).

    The preimage is 164 bytes, which SHA-256 treats as three blocks, and the
    nonce sits in the first, so no midstate survives from one attempt to the
    next and every attempt costs three compressions.
    """
    if len(previous_event_id) != 32:
        raise ValueError("previous_event_id must be 32 raw bytes")
    return hashlib.sha256(
        SIDESTEP_GRIND_DOMAIN
        + nonce.to_bytes(8, "big")
        + previous_event_id
        + roots[0]
        + roots[1]
        + roots[2]
    ).digest()


def meets_price(g: bytes, attempts: int) -> bool:
    """Whether ``G`` satisfies the re-roll price ``G * A < 2**256``."""
    return int.from_bytes(g, "big") * attempts < (1 << 256)


def find_nonce(
    previous_event_id: bytes,
    roots: tuple[bytes, bytes, bytes],
    attempts: int,
    start: int = 0,
) -> tuple[int, bytes]:
    """Grind a nonce that meets the re-roll price."""
    nonce = start
    while True:
        g = grind_hash(previous_event_id, roots, nonce)
        if meets_price(g, attempts):
            return nonce, g
        nonce += 1


def sample_indices(g: bytes, axis_byte: int, height: int) -> list[int]:
    """The sampled opening indices for one axis (spec section 6.10).

    Indices are positions within the aligned subtree.  They may collide and
    MUST NOT be deduplicated, so that the opening count stays fixed-width.
    """
    modulus = 1 << height
    return [
        int.from_bytes(
            hashlib.sha256(
                SIDESTEP_SAMPLE_DOMAIN
                + g
                + bytes([axis_byte])
                + i.to_bytes(4, "big")
            ).digest(),
            "big",
        )
        % modulus
        for i in range(SIDESTEP_SAMPLES)
    ]


@dataclass
class SidestepProof:
    """A complete sidestep proof: roots, nonce and sampled openings."""

    roots: tuple[bytes, bytes, bytes]
    nonce: int
    openings: list[list[list[bytes]]]
    heights: tuple[int, int, int]
    grind: bytes = b""

    @property
    def roots_tag(self) -> str:
        return encode_roots_tag(self.roots)

    @property
    def openings_tag(self) -> str:
        return encode_openings_tag(self.openings, self.heights)

    @property
    def nonce_tag(self) -> str:
        return format(self.nonce, "016x")


def prove_sidestep(
    previous_event_id: bytes,
    source: tuple[int, int, int],
    destination: tuple[int, int, int],
) -> SidestepProof:
    """Produce a sidestep proof for a wall crossing.

    ``source`` and ``destination`` are ``(x, y, z)``.  Every axis that moves
    must be a valid one-Gibson wall crossing (spec section 6.3).
    """
    geometry = [axis_geometry(a, b) for a, b in zip(source, destination, strict=True)]
    for v1, v2 in zip(source, destination, strict=True):
        if not crossing_geometry_ok(v1, v2):
            raise ValueError(
                f"axis movement {v1}->{v2} is not a valid one-Gibson wall crossing"
            )

    prefixes = [seed_prefix(previous_event_id, axis) for axis in AXIS_BYTES]
    roots = tuple(
        merkle_root_streaming(prefix, base, height)
        for prefix, (base, height) in zip(prefixes, geometry, strict=True)
    )
    heights = tuple(height for _, height in geometry)
    attempts = reroll_attempts(heights)
    nonce, g = find_nonce(previous_event_id, roots, attempts)  # type: ignore[arg-type]

    openings: list[list[list[bytes]]] = []
    for axis, prefix, (base, height), v2 in zip(
        AXIS_BYTES, prefixes, geometry, destination, strict=True
    ):
        if height == 0:
            openings.append([])
            continue
        paths = [inclusion_path(prefix, base, height, v2 - base)]
        paths += [
            inclusion_path(prefix, base, height, index)
            for index in sample_indices(g, axis, height)
        ]
        openings.append(paths)

    return SidestepProof(
        roots=roots,  # type: ignore[arg-type]
        nonce=nonce,
        openings=openings,
        heights=heights,  # type: ignore[arg-type]
        grind=g,
    )


def verify_sidestep(
    previous_event_id: bytes,
    source: tuple[int, int, int],
    destination: tuple[int, int, int],
    roots: tuple[bytes, bytes, bytes],
    nonce: int,
    openings: list[list[list[bytes]]],
) -> bool:
    """Level 1 verification: price, destination path, sampled paths (spec 6.11)."""
    if len(roots) != 3 or len(openings) != 3:
        return False
    geometry = [axis_geometry(a, b) for a, b in zip(source, destination, strict=True)]
    for v1, v2 in zip(source, destination, strict=True):
        if not crossing_geometry_ok(v1, v2):
            return False

    heights = [height for _, height in geometry]
    attempts = reroll_attempts(heights)
    g = grind_hash(previous_event_id, roots, nonce)
    if not meets_price(g, attempts):
        return False

    for axis, (base, height), v2, root, paths in zip(
        AXIS_BYTES, geometry, destination, roots, openings, strict=True
    ):
        prefix = seed_prefix(previous_event_id, axis)
        if height == 0:
            if root != leaf_hash(prefix, v2) or paths:
                return False
            continue
        if len(paths) != SIDESTEP_SAMPLES + 1:
            return False
        if any(len(path) != height for path in paths):
            return False
        if not verify_path(leaf_hash(prefix, v2), v2 - base, paths[0], root):
            return False
        for path, index in zip(
            paths[1:], sample_indices(g, axis, height), strict=True
        ):
            if not verify_path(leaf_hash(prefix, base + index), index, path, root):
                return False
    return True


def verify_sidestep_level2(
    previous_event_id: bytes,
    source: tuple[int, int, int],
    destination: tuple[int, int, int],
    roots: tuple[bytes, bytes, bytes],
) -> bool:
    """Level 2 verification: rebuild every tree from scratch and compare.

    This is the audit path.  It costs the same order of work as the original
    proof, and it catches a fabricated subtree that Level 1 can miss.
    """
    geometry = [axis_geometry(a, b) for a, b in zip(source, destination, strict=True)]
    for axis, (base, height), root in zip(AXIS_BYTES, geometry, roots, strict=True):
        prefix = seed_prefix(previous_event_id, axis)
        if merkle_root_streaming(prefix, base, height) != root:
            return False
    return True


def encode_roots_tag(roots: tuple[bytes, bytes, bytes]) -> str:
    """Encode the ``mr`` tag: three Merkle roots, colon separated."""
    return ":".join(root.hex() for root in roots)


def decode_roots_tag(text: str) -> tuple[bytes, bytes, bytes]:
    """Decode the ``mr`` tag."""
    parts = text.split(":")
    if len(parts) != 3:
        raise ValueError("mr tag must have three colon-separated roots")
    roots = []
    for part in parts:
        if len(part) != 64:
            raise ValueError("each mr root must be 64 hex characters")
        roots.append(bytes.fromhex(part))
    return (roots[0], roots[1], roots[2])


def encode_openings_tag(
    openings: list[list[list[bytes]]], heights: tuple[int, int, int]
) -> str:
    """Encode the ``mp`` tag.

    Each axis segment is the concatenation of ``SIDESTEP_SAMPLES + 1``
    inclusion proofs, each of ``height`` sibling hashes, hex encoded.  A
    trivial axis contributes an empty segment.
    """
    segments = []
    for paths, height in zip(openings, heights, strict=True):
        if height == 0:
            segments.append("")
            continue
        parts = []
        for path in paths:
            parts.append("".join(sibling.hex() for sibling in path))
        segments.append("".join(parts))
    return ":".join(segments)


def decode_openings_tag(
    text: str, heights: tuple[int, int, int]
) -> list[list[list[bytes]]]:
    """Decode the ``mp`` tag.

    A segment whose length is not an exact multiple of ``64 * height`` is
    malformed and the event must be rejected.  A segment of exactly
    ``64 * height`` characters is a version 1 proof and is rejected too.
    """
    segments = text.split(":")
    if len(segments) != 3:
        raise ValueError("mp tag must have three colon-separated segments")
    out: list[list[list[bytes]]] = []
    for segment, height in zip(segments, heights, strict=True):
        if height == 0:
            if segment != "":
                raise ValueError("a trivial axis must have an empty opening segment")
            out.append([])
            continue
        if len(segment) % (64 * height) != 0:
            raise ValueError("opening segment is not a multiple of 64 * height")
        count = len(segment) // (64 * height)
        if count != SIDESTEP_SAMPLES + 1:
            raise ValueError(
                f"expected {SIDESTEP_SAMPLES + 1} openings per axis, got {count}"
            )
        paths: list[list[bytes]] = []
        for i in range(count):
            chunk = segment[i * 64 * height : (i + 1) * 64 * height]
            paths.append(
                [
                    bytes.fromhex(chunk[j * 64 : (j + 1) * 64])
                    for j in range(height)
                ]
            )
        out.append(paths)
    return out


# Axis byte constants are re-exported for callers building proofs by hand.
AXIS_BYTES_EXPORT = (AXIS_X, AXIS_Y, AXIS_Z)
