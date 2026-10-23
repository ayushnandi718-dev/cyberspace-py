"""Tests for location-based encryption and discovery (spec section 7)."""

from __future__ import annotations

import hashlib

import pytest

from cyberspace.bags import BagKeyError, decrypt_payload, encrypt_payload
from cyberspace.cantor import cantor_pair, compute_subtree_cantor
from cyberspace.encoding import int_to_bytes_be_min
from cyberspace.region import (
    RegionCache,
    discover,
    region_integer_at,
    region_key,
    region_key_at,
    region_lookup_id,
    region_lookup_id_at,
)


def test_key_derivation_follows_the_specification() -> None:
    """location_decryption_key = sha256(region_bytes), lookup = sha256(key)."""
    region = 123456789
    key = hashlib.sha256(int_to_bytes_be_min(region)).digest()
    assert region_key(region) == key
    assert region_lookup_id(region) == hashlib.sha256(key).digest()


def test_the_worked_example_of_the_specification() -> None:
    """The lookup id of the region of spec 5.7."""
    x_root = compute_subtree_cantor(0, 13)
    region = cantor_pair(cantor_pair(x_root, 0), 0)
    assert region_lookup_id(region).hex() == (
        "8d2463eb22301d97a1f7e33b90e473ba2eec69079f418a72609c3e4d2981669b"
    )


def test_a_region_has_a_height_of_at_least_one() -> None:
    with pytest.raises(ValueError):
        region_integer_at(0, 0, 0, 0)


def test_positions_in_one_region_share_its_key() -> None:
    """Two readers in the same region derive the same key (spec 7.1)."""
    base = 1 << 80
    first = region_key_at(base, base, base, 4)
    second = region_key_at(base + 15, base + 15, base + 15, 4)
    assert first == second


def test_positions_in_different_regions_do_not() -> None:
    base = 1 << 80
    assert region_key_at(base, base, base, 4) != region_key_at(base + 16, base, base, 4)


def test_the_region_of_a_point_is_its_own_cube() -> None:
    """The region integer of a point is built from the aligned bases."""
    x, y, z, height = 4096, 0, 0, 3
    expected = cantor_pair(
        cantor_pair(
            compute_subtree_cantor(4096, 3),
            compute_subtree_cantor(0, 3),
        ),
        compute_subtree_cantor(0, 3),
    )
    assert region_integer_at(x, y, z, height) == expected


def test_discovery_scans_one_height_at_a_time() -> None:
    scans = list(discover(1024, 1024, 1024, 6))
    assert [scan.height for scan in scans] == [1, 2, 3, 4, 5, 6]
    assert all(len(scan.lookup_id) == 32 for scan in scans)
    assert all(len(scan.key) == 32 for scan in scans)


def test_discovery_starts_at_height_one() -> None:
    with pytest.raises(ValueError):
        list(discover(0, 0, 0, 4, min_height=0))


def test_a_bag_opens_with_the_region_key() -> None:
    key = region_key_at(1024, 1024, 1024, 4)
    payload = encrypt_payload(b"a note left here", key)
    assert decrypt_payload(payload, key) == b"a note left here"


def test_a_bag_does_not_open_with_another_key() -> None:
    key = region_key_at(1024, 1024, 1024, 4)
    other = region_key_at(2048, 1024, 1024, 4)
    payload = encrypt_payload(b"a note left here", key)
    with pytest.raises(BagKeyError):
        decrypt_payload(payload, other)


def test_every_encryption_uses_a_fresh_nonce() -> None:
    key = region_key_at(1024, 1024, 1024, 4)
    first = encrypt_payload(b"same text", key)
    second = encrypt_payload(b"same text", key)
    assert first != second
    assert decrypt_payload(first, key) == decrypt_payload(second, key)


def test_the_cache_survives_a_small_move() -> None:
    """An aligned subtree only changes when a boundary is crossed (spec 7.5)."""
    cache = RegionCache()
    base = 1 << 80
    first = cache.key_at(base, base, base, 8)
    assert cache.key_at(base + 1, base, base, 8) == first
    moved = cache.key_at(base + 256, base, base, 8)
    assert moved != first


def test_lookup_ids_match_at_the_same_point() -> None:
    assert region_lookup_id_at(1024, 1024, 1024, 4) == region_lookup_id(
        region_integer_at(1024, 1024, 1024, 4)
    )
