"""Tests for the temporal axis of spec section 5.

The specification works through one movement in full (spec 5.7), so the
numbers it gives are used here as the reference.
"""

from __future__ import annotations

import hashlib

from cyberspace.cantor import cantor_pair, compute_subtree_cantor
from cyberspace.coordinates import xyz_to_coord
from cyberspace.temporal import (
    TERRAIN_CELL_BITS,
    TERRAIN_DOMAIN_V2,
    hop_preimage,
    int_to_bytes_be_min,
    movement_proof_hash,
    temporal_root,
    terrain_height,
    terrain_word,
)


def test_integer_encoding_is_minimal_big_endian() -> None:
    """int_to_bytes_be_min (spec 5.5)."""
    assert int_to_bytes_be_min(0) == b"\x00"
    assert int_to_bytes_be_min(1) == b"\x01"
    assert int_to_bytes_be_min(255) == b"\xff"
    assert int_to_bytes_be_min(256) == b"\x01\x00"
    encoded = int_to_bytes_be_min(1 << 200)
    assert len(encoded) == 26
    assert encoded[0] == 0x01


def test_terrain_height_is_the_popcount_of_the_word() -> None:
    """K is the popcount of a 16-bit word (spec 5.2)."""
    word = terrain_word(4104, 0, 0, 0)
    assert 0 <= word < (1 << 16)
    assert terrain_height(4104, 0, 0, 0) == bin(word).count("1")
    assert terrain_height(4104, 0, 0, 0) == 11


def test_terrain_height_is_bounded() -> None:
    for value in (0, 1, 4104, 1 << 40, (1 << 84) - 1):
        assert 0 <= terrain_height(value, value, value, 0) <= 16


def test_terrain_uses_the_stated_constants() -> None:
    assert TERRAIN_DOMAIN_V2 == b"CYBERSPACE_TERRAIN_K_V2"
    assert tuple(TERRAIN_CELL_BITS) == (3, 7, 9, 11)


def test_terrain_cell_alignment() -> None:
    """The terrain is sampled from aligned cells, so neighbours agree at the
    coarse scales."""
    low = terrain_word(4096, 0, 0, 0)
    high = terrain_word(4104, 0, 0, 0)
    # The two differ only in the nibble of the finest cell, 2**3, which is
    # the high nibble of the word.
    assert (low & 0x0FFF) == (high & 0x0FFF)
    assert (low >> 12) != (high >> 12)


def test_temporal_root_follows_the_seed() -> None:
    """The seed is the previous event id reduced into the axis (spec 5.3)."""
    previous = bytes(32)
    assert temporal_root(previous, 11) == compute_subtree_cantor(0, 11)
    # Only the low 85 bits of the id reach the axis.
    other = bytes.fromhex("00" * 31 + "01")
    assert temporal_root(other, 11) == compute_subtree_cantor(0, 11)
    # Seeds inside one aligned subtree share its root, so the root only
    # changes when the seed crosses a boundary.
    third = bytes.fromhex("00" * 30 + "3000")
    assert temporal_root(third, 11) == compute_subtree_cantor(12288, 11)


def test_temporal_root_ignores_the_high_bits_of_the_id() -> None:
    """The id is reduced into 85 bits, so the top bits do not reach the axis."""
    low = bytes.fromhex("00" * 31 + "01")
    high = bytes.fromhex("ff" + "00" * 30 + "01")
    assert temporal_root(low, 8) == temporal_root(high, 8)


def test_worked_example_from_the_specification() -> None:
    """The movement (0, 0, 0) → (4104, 0, 0) of spec 5.7."""
    x_root = compute_subtree_cantor(0, 13)
    region = cantor_pair(cantor_pair(x_root, 0), 0)

    lookup = hashlib.sha256(hashlib.sha256(int_to_bytes_be_min(region)).digest()).digest()
    assert lookup.hex() == (
        "8d2463eb22301d97a1f7e33b90e473ba2eec69079f418a72609c3e4d2981669b"
    )

    height = terrain_height(4104, 0, 0, 0)
    assert height == 11
    cantor_t = compute_subtree_cantor(0, 11)
    proof = movement_proof_hash(cantor_pair(region, cantor_t))
    assert proof.hex() == (
        "ed9d09ca697b2da29c9d042207ac8ef7aab40f6dde550e6467452aa0e2e8cac6"
    )


def test_hop_preimage_binds_the_chain_context() -> None:
    """Two different parents give two different proofs for one move."""
    region = 12345
    first = movement_proof_hash(hop_preimage(region, bytes(32), (4104, 0, 0, 0)))
    second = movement_proof_hash(
        hop_preimage(region, bytes.fromhex("00" * 30 + "3000"), (4104, 0, 0, 0))
    )
    assert first != second


def test_terrain_word_uses_the_aligned_cell() -> None:
    """The word is built from nibbles of the cell digests (spec 5.2)."""
    bits = TERRAIN_CELL_BITS[0]
    bx = (4104 >> bits) << bits
    cell = xyz_to_coord(bx, 0, 0, 0)
    digest = hashlib.sha256(
        TERRAIN_DOMAIN_V2 + bytes([bits]) + cell.to_bytes(32, "big")
    ).digest()
    # The finest cell is the high nibble of the word.
    assert (terrain_word(4104, 0, 0, 0) >> 12) & 0x0F == digest[0] & 0x0F
