"""Tests for the Cantor pairing trees of spec section 4."""

from __future__ import annotations

import pytest

from cyberspace.cantor import (
    axis_geometry,
    axis_root,
    cantor_pair,
    cantor_unpair,
    compute_subtree_cantor,
    find_lca_height,
    region_n,
)


def test_cantor_pair_is_the_specified_function() -> None:
    """π(a, b) = (a + b)(a + b + 1)/2 + b (spec 4.2)."""
    for a, b in ((0, 1), (2, 3), (7, 11), (1 << 20, 1 << 21)):
        s = a + b
        assert cantor_pair(a, b) == (s * (s + 1)) // 2 + b


def test_cantor_pair_is_a_bijection() -> None:
    for a, b in ((0, 0), (1, 2), (300, 7000), (1 << 40, 1 << 41)):
        assert cantor_unpair(cantor_pair(a, b)) == (a, b)


def test_lca_height_follows_the_bit_pattern() -> None:
    """The height is the number of bits in which the two values differ."""
    assert find_lca_height(4, 5) == 1
    assert find_lca_height(7, 8) == 4
    assert find_lca_height(0, 5) == 3
    assert find_lca_height(4, 7) == 2
    assert find_lca_height(9, 9) == 0
    assert find_lca_height((1 << 34) - 1, 1 << 34) == 35


def test_subtree_roots_match_the_worked_examples() -> None:
    """The examples the specification works through (spec 4.5, 4.6)."""
    assert compute_subtree_cantor(0, 1) == 2
    assert compute_subtree_cantor(2, 1) == 18
    assert compute_subtree_cantor(18, 0) == 18
    assert compute_subtree_cantor(0, 2) == 228
    assert compute_subtree_cantor(0, 3) == 64450752


def test_axis_root_covers_both_endpoints() -> None:
    """The covering aligned subtree holds both ends of the movement."""
    for v1, v2 in ((0, 5), (4, 7), (1, 2), (100, 250)):
        height = find_lca_height(v1, v2)
        base = (v1 >> height) << height
        assert base <= min(v1, v2)
        assert max(v1, v2) < base + (1 << height)


def test_neighbours_share_a_root() -> None:
    """Positions inside one aligned subtree see the same region."""
    assert axis_root(0, 3) == axis_root(1, 2) == axis_root(0, 2)


def test_geometry_gives_the_base_and_the_height() -> None:
    base, height = axis_geometry(4, 7)
    assert height == 2
    assert base == 4
    base, height = axis_geometry(7, 7)
    assert height == 0
    assert base == 7


def test_region_n_combines_the_axes() -> None:
    x_root = axis_root(0, 3)
    y_root = axis_root(0, 3)
    z_root = axis_root(0, 3)
    expected = cantor_pair(cantor_pair(x_root, y_root), z_root)
    assert region_n(0, 0, 0, 3, 3, 3) == expected


def test_subtree_root_rejects_a_negative_height() -> None:
    with pytest.raises(ValueError):
        compute_subtree_cantor(0, -1)
