"""Tests for the Nostr layer of spec section 8.2."""

from __future__ import annotations

import hashlib
import json

from cyberspace.nostr.event import Event, event_id, new_event, serialize_event
from cyberspace.nostr.schnorr import (
    N,
    generate_keypair,
    pubkey_from_secret,
    sign,
    verify,
)


def _keypair() -> tuple[int, str]:
    secret, pubkey = generate_keypair()
    return secret, pubkey.hex()


def test_a_signed_event_verifies() -> None:
    secret, pubkey = _keypair()
    event = new_event(secret, pubkey, 3333, [["A", "spawn"]], "", 1700000000)
    assert event.verify()
    assert event.is_wellformed()
    assert event.verify_id()


def test_the_canonical_id_is_the_hash_of_the_serialisation() -> None:
    secret, pubkey = _keypair()
    event = new_event(secret, pubkey, 3333, [["A", "spawn"]], "hello", 1700000000)
    expected = hashlib.sha256(
        json.dumps(
            [0, pubkey, 1700000000, 3333, [["A", "spawn"]], "hello"],
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    assert event.id == expected
    assert event.id == event_id(pubkey, 1700000000, 3333, [["A", "spawn"]], "hello")


def test_the_serialisation_has_no_whitespace() -> None:
    _secret, pubkey = _keypair()
    assert serialize_event(pubkey, 1700000000, 1, [], "a note") == (
        f'[0,"{pubkey}",1700000000,1,[],"a note"]'.encode()
    )


def test_changing_the_content_breaks_the_id() -> None:
    secret, pubkey = _keypair()
    event = new_event(secret, pubkey, 1, [], "a note", 1700000000)
    event.content = "another note"
    assert not event.verify_id()
    assert not event.verify()


def test_a_forged_signature_fails() -> None:
    secret, pubkey = _keypair()
    event = new_event(secret, pubkey, 1, [], "a note", 1700000000)
    event.sig = "00" * 64
    assert event.verify_id()
    assert not event.verify()


def test_an_event_of_the_wrong_shape_is_not_authentic() -> None:
    """A relay can deliver anything; the reader must judge it."""
    secret, pubkey = _keypair()
    event = new_event(secret, pubkey, 1, [], "a note", 1700000000)
    broken = Event.from_dict(event.to_dict())
    broken.pubkey = "not hex"
    assert not broken.verify()
    broken = Event.from_dict(event.to_dict())
    broken.kind = "1"
    assert not broken.verify()
    broken = Event.from_dict(event.to_dict())
    broken.created_at = True
    assert not broken.verify()
    broken = Event.from_dict(event.to_dict())
    broken.tags = [["A", 1]]
    assert not broken.verify()


def test_a_lone_surrogate_is_discarded_rather_than_crashing() -> None:
    secret, pubkey = _keypair()
    event = new_event(secret, pubkey, 1, [], "a note", 1700000000)
    broken = Event.from_dict(event.to_dict())
    broken.content = "\ud800"
    assert not broken.verify()
    assert not broken.verify_id()


def test_a_tag_helper_finds_the_marked_tag() -> None:
    secret, pubkey = _keypair()
    event = new_event(
        secret,
        pubkey,
        3333,
        [["A", "hop"], ["e", "aa" * 32, "", "genesis"], ["e", "bb" * 32, "", "previous"]],
        "",
        1700000000,
    )
    assert event.marked_tag("e", "previous") == ["e", "bb" * 32, "", "previous"]
    assert event.marked_tag("e", "genesis") == ["e", "aa" * 32, "", "genesis"]
    assert event.marked_tag("e", "root") is None
    assert event.action() == "hop"
    assert event.previous_event_id() == bytes.fromhex("bb" * 32)


def test_the_schnorr_signature_verifies() -> None:
    secret, pubkey = _keypair()
    message = bytes(range(32))
    signature = sign(message, secret)
    assert verify(message, bytes.fromhex(pubkey), signature)


def test_a_signature_over_another_message_fails() -> None:
    secret, pubkey = _keypair()
    signature = sign(bytes(32), secret)
    assert not verify(bytes(31) + b"\x01", bytes.fromhex(pubkey), signature)


def test_the_public_key_is_the_even_y_representative() -> None:
    """BIP-340: a public key is an x coordinate, and the point is the even
    one."""
    for _ in range(8):
        secret, pubkey = generate_keypair()
        assert pubkey_from_secret(secret) == pubkey


def test_the_secret_is_flipped_for_an_odd_point() -> None:
    """A secret whose point has an odd y is used with its sign flipped."""
    secret, pubkey = generate_keypair()
    flipped = N - secret
    assert pubkey_from_secret(flipped) == pubkey
    message = bytes(range(32))
    assert verify(message, pubkey, sign(message, flipped))


def test_a_signature_from_another_key_fails() -> None:
    secret, pubkey = _keypair()
    other_secret, _other_pubkey = _keypair()
    message = bytes(range(32))
    signature = sign(message, other_secret)
    assert not verify(message, bytes.fromhex(pubkey), signature)


def test_a_malformed_signature_is_rejected() -> None:
    secret, pubkey = _keypair()
    assert not verify(bytes(32), bytes.fromhex(pubkey), b"\x00" * 63)
    assert not verify(bytes(32), b"\x00" * 32, b"\x00" * 64)
