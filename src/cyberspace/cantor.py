"""Cantor pairing trees: the spatial fabric of Cyberspace (spec section 4).

Movement is priced by computing the mathematical structure that lies between
two coordinates.  Each axis has its own independent binary tree of *aligned*
subtrees; a movement proof is the Cantor root of the smallest aligned subtree
covering both endpoints on each axis, combined across the three axes.

The properties that make this work:

* The Cantor pairing function is a bijection, so a root names exactly one
  region and can be reversed.
* Aligned subtree bases are powers-of-two aligned, so two parties standing in
  the same region compute the same root without communicating.
* The cost of a movement is the height of the covering subtree, so crossing a
  power-of-two boundary is expensive even for a one-Gibson step.

This module also implements the *low-bit window* of spec section 4.9: the low
``k`` bits of a root can be computed without materialising the root, because
carries only propagate upward.  That makes verification of a disclosed root
cheap, while producing the root stays expensive.
"""

from __future__ import annotations

from .constants import AXIS_BITS
from .encoding import int_to_bytes_be_min

__all__ = [
    "cantor_pair",
    "cantor_unpair",
    "find_lca_height",
    "aligned_base",
    "compute_subtree_cantor",
    "compute_subtree_cantor_low",
    "axis_root",
    "axis_geometry",
    "region_roots",
    "region_n",
    "decomposition_max_height",
]


def cantor_pair(a: int, b: int) -> int:
    """The Cantor pairing function ``pi(a, b) = (a+b)(a+b+1)/2 + b``.

    A bijection from pairs of naturals onto the naturals, so every integer
    names exactly one pair and every pair exactly one integer.
    """
    if a < 0 or b < 0:
        raise ValueError("cantor_pair expects non-negative inputs")
    s = a + b
    return (s * (s + 1)) // 2 + b


def cantor_unpair(n: int) -> tuple[int, int]:
    """Invert the Cantor pairing function."""
    if n < 0:
        raise ValueError("cantor_unpair expects a non-negative input")
    # w = floor((sqrt(8n+1) - 1) / 2) is the largest w with w(w+1)/2 <= n.
    w = (isqrt(8 * n + 1) - 1) // 2
    t = w * (w + 1) // 2
    b = n - t
    a = w - b
    return (a, b)


def isqrt(n: int) -> int:
    """Integer square root (Python 3.8+ has math.isqrt, kept local for clarity)."""
    import math

    return math.isqrt(n)


def find_lca_height(v1: int, v2: int) -> int:
    """Height of the lowest common ancestor of two axis values.

    The LCA height is the level of the binary boundary that separates the two
    values: the number of trailing bits in which they differ.  It is not a
    measure of distance in Gibsons, but of *which boundary* is crossed.
    """
    if v1 == v2:
        return 0
    return (v1 ^ v2).bit_length()


def aligned_base(value: int, height: int) -> int:
    """Base of the aligned subtree of side ``2**height`` that contains ``value``."""
    if height < 0:
        raise ValueError("height must be >= 0")
    if height > AXIS_BITS:
        raise ValueError(f"height must be <= {AXIS_BITS}")
    return (value >> height) << height


def compute_subtree_cantor(base: int, height: int) -> int:
    """Cantor root of the aligned subtree at ``base`` of the given height.

    Leaves are ``base .. base + 2**height - 1`` and are paired bottom-up,
    adjacent pairs first, until a single value remains.  The result is the
    region's identifier.

    The intermediate values grow with the height, so this is memory-bound
    above roughly h25 and is not the right tool for high boundaries; use a
    sidestep (spec section 6) for those.
    """
    if height < 0:
        raise ValueError("height must be >= 0")
    if height > AXIS_BITS:
        raise ValueError(f"height must be <= {AXIS_BITS}")
    if height == 0:
        return base

    values = list(range(base, base + (1 << height)))
    for _ in range(height):
        values = [
            cantor_pair(values[i], values[i + 1]) for i in range(0, len(values), 2)
        ]
    return values[0]


def compute_subtree_cantor_low(base: int, height: int, bits: int) -> int:
    """The low ``bits`` bits of a subtree root, without building the root.

    Carries propagate upward only, so a window of ``bits + height`` low bits
    through the same pairings reproduces the true root's low ``bits`` bits
    exactly.  This turns an ``O(2**height)``-wide computation into one that
    touches a few machine words.

    The result is a *prefix*, not a root: it cannot be used to derive a region
    key or to forge a proof.  It is good for detecting mistakes and for
    checking that a disclosed root belongs to the region you asked about.
    """
    if height < 0:
        raise ValueError("height must be >= 0")
    if bits < 0:
        raise ValueError("bits must be >= 0")
    if height > AXIS_BITS:
        raise ValueError(f"height must be <= {AXIS_BITS}")
    if bits == 0:
        return 0

    window = bits + height
    mask = (1 << window) - 1
    values = [(base + i) & mask for i in range(1 << height)]
    for level in range(height):
        level_mask = (1 << (window - level)) - 1
        values = [
            (cantor_pair(values[i], values[i + 1])) & level_mask
            for i in range(0, len(values), 2)
        ]
    return values[0] & ((1 << bits) - 1)


def axis_root(v1: int, v2: int) -> int:
    """Cantor root of the smallest aligned subtree covering ``v1`` and ``v2``."""
    height = find_lca_height(v1, v2)
    base = aligned_base(v1, height)
    return compute_subtree_cantor(base, height)


def axis_geometry(v1: int, v2: int) -> tuple[int, int]:
    """Return ``(base, height)`` of the covering aligned subtree."""
    height = find_lca_height(v1, v2)
    return (aligned_base(v1, height), height)


def region_roots(
    x1: int, y1: int, z1: int, x2: int, y2: int, z2: int
) -> tuple[tuple[int, int, int], tuple[int, int, int]]:
    """Per-axis Cantor roots and heights for a movement.

    Returns ``((root_x, root_y, root_z), (height_x, height_y, height_z))``.
    An axis that did not move has height 0 and its root is the position
    itself, which is ordinary: the three heights are computed independently.
    """
    rx = axis_root(x1, x2)
    ry = axis_root(y1, y2)
    rz = axis_root(z1, z2)
    heights = (
        find_lca_height(x1, x2),
        find_lca_height(y1, y2),
        find_lca_height(z1, z2),
    )
    return ((rx, ry, rz), heights)


def region_n(
    x1: int, y1: int, z1: int, x2: int, y2: int, z2: int
) -> int:
    """The stable spatial region integer for a movement (spec section 4.7).

    ``region_n = pi(pi(cantor_x, cantor_y), cantor_z)``.  It identifies the
    3D region implied by the movement and is stable: the same region always
    produces the same value, independent of who computed it or when.
    """
    (rx, ry, rz), _heights = region_roots(x1, y1, z1, x2, y2, z2)
    return cantor_pair(cantor_pair(rx, ry), rz)


def decomposition_max_height(v1: int, v2: int) -> int:
    """The largest unit-step LCA height between ``v1`` and ``v2``.

    Spec section 4.8 proves that this equals ``find_lca_height(v1, v2)``: a
    movement cannot be made cheaper by decomposing it into small steps.  This
    helper computes the left-hand side by brute force, for small ranges, so
    that the theorem can be checked rather than trusted.
    """
    if v1 > v2:
        v1, v2 = v2, v1
    if v1 == v2:
        return 0
    return max(find_lca_height(i, i + 1) for i in range(v1, v2))


def subtree_cantor_bytes(base: int, height: int) -> bytes:
    """The canonical byte encoding of a subtree root, for hashing."""
    return int_to_bytes_be_min(compute_subtree_cantor(base, height))
