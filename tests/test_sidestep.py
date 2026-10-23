"""Tests for the sidestep of spec section 6.

The numbers locked here are the golden vectors of the specification's own
reference construction, so a port that agrees with them agrees with every
other port on what a sidestep costs.
"""

from __future__ import annotations

import hashlib

from cyberspace.sidestep import (
    SIDESTEP_GRIND_DOMAIN,
    SIDESTEP_SAMPLES,
    decode_openings_tag,
    decode_roots_tag,
    encode_openings_tag,
    encode_roots_tag,
    find_nonce,
    grind_hash,
    leaf_hash,
    meets_price,
    merkle_root_streaming,
    prove_sidestep,
    reroll_attempts,
    sample_indices,
    seed_prefix,
    verify_path,
    verify_sidestep,
)

HEIGHT = 12
BASE = (0x1234567 >> HEIGHT) << HEIGHT
SOURCE = (5, 7, BASE + (1 << (HEIGHT - 1)) - 1)
DESTINATION = (5, 7, BASE + (1 << (HEIGHT - 1)))
ZERO = bytes(32)
ALICE = bytes(range(32))
BOB = bytes(range(32, 64))


def test_golden_axis_roots() -> None:
    """The axis roots the reference construction publishes."""
    assert merkle_root_streaming(seed_prefix(ZERO, 0), 0, 0).hex() == (
        "803e23af5b006f6542e43cb30a70e0229916586105eb230e5d8796984d5b0901"
    )
    assert merkle_root_streaming(seed_prefix(ZERO, 2), BASE, 5).hex() == (
        "202ede33045254297d335033c68b2fa05e6a47be1756abe7fee8caeedd89dcd6"
    )
    assert merkle_root_streaming(seed_prefix(ALICE, 1), 1 << 40, 9).hex() == (
        "badf31e4bf617b2cddaa7f5b560ead66ed34198523a2b8ae4f45b624103cda92"
    )


def test_golden_crossing() -> None:
    """The crossing the reference construction publishes."""
    proof = prove_sidestep(ZERO, SOURCE, DESTINATION)
    assert reroll_attempts([0, 0, HEIGHT]) == 512
    assert proof.nonce == 175
    grind = grind_hash(ZERO, proof.roots, proof.nonce)
    assert grind.hex() == (
        "0067d4a60e171a3f6007da903f999c0eb441115369fa2d07f9424af4dd5f985a"
    )
    assert sample_indices(grind, 2, HEIGHT)[0] == 2113


def test_roots_differ_across_movers() -> None:
    """The tree is seeded by the mover's chain position, so it is a toll."""
    alice = prove_sidestep(ALICE, SOURCE, DESTINATION)
    bob = prove_sidestep(BOB, SOURCE, DESTINATION)
    assert alice.roots[2] != bob.roots[2]


def test_a_copied_proof_fails_under_the_copiers_seed() -> None:
    alice = prove_sidestep(ALICE, SOURCE, DESTINATION)
    assert not verify_sidestep(
        BOB, SOURCE, DESTINATION, alice.roots, alice.nonce, alice.openings
    )


def test_an_honest_proof_verifies() -> None:
    alice = prove_sidestep(ALICE, SOURCE, DESTINATION)
    assert verify_sidestep(
        ALICE, SOURCE, DESTINATION, alice.roots, alice.nonce, alice.openings
    )


def test_the_axis_byte_separates_identical_subtrees() -> None:
    assert merkle_root_streaming(seed_prefix(ALICE, 0), BASE, HEIGHT) != (
        merkle_root_streaming(seed_prefix(ALICE, 2), BASE, HEIGHT)
    )


def test_a_fabricated_tree_fails_the_sampled_openings() -> None:
    """The attack of spec 6.11: a destination-only check is not enough."""
    alice = prove_sidestep(ALICE, SOURCE, DESTINATION)
    prefix = seed_prefix(ALICE, 2)
    siblings = [hashlib.sha256(b"forge" + bytes([index])).digest() for index in range(HEIGHT)]
    current = leaf_hash(prefix, DESTINATION[2])
    index = DESTINATION[2] - BASE
    for sibling in siblings:
        if index % 2 == 0:
            current = hashlib.sha256(current + sibling).digest()
        else:
            current = hashlib.sha256(sibling + current).digest()
        index //= 2
    roots = (alice.roots[0], alice.roots[1], current)
    nonce, _ = find_nonce(ALICE, roots, reroll_attempts([0, 0, HEIGHT]))
    assert not verify_sidestep(
        ALICE,
        SOURCE,
        DESTINATION,
        roots,
        nonce,
        [[], [], [siblings] * (SIDESTEP_SAMPLES + 1)],
    )


def test_a_trivial_axis_root_is_the_single_seeded_leaf() -> None:
    alice = prove_sidestep(ALICE, SOURCE, DESTINATION)
    assert alice.roots[0] == leaf_hash(seed_prefix(ALICE, 0), SOURCE[0])


def test_the_seed_prefix_is_one_block() -> None:
    assert len(seed_prefix(ALICE, 0)) == 64


def test_a_nonce_that_misses_the_price_is_rejected() -> None:
    alice = prove_sidestep(ALICE, SOURCE, DESTINATION)
    attempts = reroll_attempts([0, 0, HEIGHT])
    bad_nonce = next(
        nonce
        for nonce in range(100000)
        if not meets_price(grind_hash(ALICE, alice.roots, nonce), attempts)
    )
    assert not verify_sidestep(
        ALICE, SOURCE, DESTINATION, alice.roots, bad_nonce, alice.openings
    )


def test_the_grind_domain_is_the_stated_one() -> None:
    assert SIDESTEP_GRIND_DOMAIN == b"CYBERSPACE_SIDESTEP_GRIND_V1"


def test_paths_verify() -> None:
    prefix = seed_prefix(ALICE, 2)
    root = merkle_root_streaming(prefix, BASE, 4)
    leaf = leaf_hash(prefix, BASE + 5)
    siblings: list[bytes] = []
    index = 5
    levels = [[leaf_hash(prefix, BASE + i) for i in range(16)]]
    while len(levels[-1]) > 1:
        level = levels[-1]
        levels.append(
            [
                hashlib.sha256(level[j] + level[j + 1]).digest()
                for j in range(0, len(level), 2)
            ]
        )
    for depth in range(4):
        siblings.append(levels[depth][index ^ 1])
        index //= 2
    assert verify_path(leaf, 5, siblings, root)
    assert not verify_path(leaf, 5, siblings, bytes(32))


def test_tags_round_trip() -> None:
    alice = prove_sidestep(ALICE, SOURCE, DESTINATION)
    roots = decode_roots_tag(encode_roots_tag(alice.roots))
    assert roots == alice.roots
    openings = decode_openings_tag(
        encode_openings_tag(alice.openings, alice.heights), alice.heights
    )
    assert openings == alice.openings
