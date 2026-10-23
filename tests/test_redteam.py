"""Tests for the red-team tooling: auditing, probing and the vector runners."""

from __future__ import annotations

import pytest
from fixture_paths import visualization_path

from cyberspace.chain import resolve_chain
from cyberspace.coordinates import Coordinate, coord_to_xyz, sector_tags
from cyberspace.movement import hop_proof, movement_tags
from cyberspace.nostr.event import new_event
from cyberspace.nostr.schnorr import generate_keypair
from cyberspace.redteam.audit import audit, find_forks, format_report
from cyberspace.redteam.probe import movement_cost, probe, region_keys_at
from cyberspace.redteam.vectors import (
    run_gps_vectors,
    run_visualization_vectors,
)


def _keypair() -> tuple[int, str]:
    secret, pubkey = generate_keypair()
    return secret, pubkey.hex()


def _spawn(secret: int, pubkey: str, created_at: int):
    """A spawn event, whose coordinate is its own public key."""
    x, y, z, _plane = coord_to_xyz(int(pubkey, 16))
    sectors = sector_tags(x, y, z)
    return new_event(
        secret,
        pubkey,
        3333,
        [
            ["A", "spawn"],
            ["C", pubkey],
            ["X", sectors["X"]],
            ["Y", sectors["Y"]],
            ["Z", sectors["Z"]],
            ["S", sectors["S"]],
        ],
        "",
        created_at,
    )


def _hop(secret: int, pubkey: str, spawn, created_at: int):
    """A hop one Gibson along the x axis, with a genuine proof."""
    source = Coordinate(*coord_to_xyz(int(pubkey, 16)))
    step = 1 if source.x % 2 == 0 else -1
    target = source.offset(dx=step)
    proof = hop_proof(bytes.fromhex(spawn.id), source, target)
    tags = movement_tags(
        "hop", spawn.id, spawn.id, source, target, proof
    )
    return new_event(secret, pubkey, 3333, tags, "", created_at)


def test_the_price_of_a_movement_is_the_highest_boundary_it_crosses() -> None:
    source = Coordinate(0, 0, 0)
    destination = Coordinate(2, 0, 0)
    cost = movement_cost(source, destination)
    assert cost.heights == (2, 0, 0)
    assert cost.max_height == 2
    assert cost.leaves == 4
    assert cost.feasible
    assert "max=2" in cost.describe()


def test_a_one_gibson_step_across_the_lowest_boundary_is_cheap() -> None:
    cost = movement_cost(Coordinate(0, 0, 0), Coordinate(1, 0, 0))
    assert cost.heights == (1, 0, 0)
    assert cost.leaves == 2


def test_a_movement_over_a_high_boundary_is_priced_but_not_computed() -> None:
    cost = movement_cost(Coordinate(0, 0, 0), Coordinate(1 << 30, 0, 0))
    assert cost.max_height == 31
    assert not cost.feasible
    assert "too expensive" in cost.describe()


def test_a_probe_reports_sectors_and_region_keys() -> None:
    result = probe(Coordinate(1024, 1024, 1024), max_height=6)
    assert set(result.sectors) == {"X", "Y", "Z", "S"}
    assert result.key_at(1) is not None
    assert result.lookup_at(1) is not None
    assert result.key_at(2) != result.key_at(1)
    assert result.skipped_heights == []


def test_a_probe_leaves_out_trees_it_cannot_afford() -> None:
    keys, skipped = region_keys_at(Coordinate(0, 0, 0), [1, 25])
    assert [level for level, _key, _lookup in keys] == [1]
    assert skipped == [25]


def test_a_valid_chain_audits_clean() -> None:
    secret, pubkey = _keypair()
    spawn = _spawn(secret, pubkey, 1700000000)
    hop = _hop(secret, pubkey, spawn, 1700000001)
    report = audit([spawn, hop], pubkey)
    assert report.valid
    assert len(report.authentic) == 2
    assert report.forged == []
    assert report.forks == []
    assert report.position_hex is not None


def test_an_audit_names_a_forged_event() -> None:
    """A forgery is discarded before resolution, so it cannot end a chain."""
    secret, pubkey = _keypair()
    spawn = _spawn(secret, pubkey, 1700000000)
    forged = _spawn(secret, pubkey, 1700000002)
    forged.content = "not what was signed"
    report = audit([spawn, forged], pubkey)
    assert report.valid
    assert [event.id for event in report.forged] == [forged.id]
    assert [event.id for event in report.authentic] == [spawn.id]


def test_an_audit_reports_events_of_another_identity() -> None:
    secret, pubkey = _keypair()
    other_secret, other_pubkey = _keypair()
    spawn = _spawn(secret, pubkey, 1700000000)
    foreign = _spawn(other_secret, other_pubkey, 1700000001)
    report = audit([spawn, foreign], pubkey)
    assert [event.id for event in report.foreign] == [foreign.id]


def test_a_fork_is_reported_and_is_fatal() -> None:
    secret, pubkey = _keypair()
    spawn = _spawn(secret, pubkey, 1700000000)
    first = _hop(secret, pubkey, spawn, 1700000001)
    second = _hop(secret, pubkey, spawn, 1700000002)
    forks = find_forks([spawn, first, second])
    assert len(forks) == 1
    assert forks[0][0] == spawn.id
    assert sorted(forks[0][1]) == sorted([first.id, second.id])
    verdict = resolve_chain([spawn, first, second], pubkey)
    assert not verdict.valid
    assert verdict.reason == "fork"


def test_the_report_renders_as_text() -> None:
    secret, pubkey = _keypair()
    spawn = _spawn(secret, pubkey, 1700000000)
    report = audit([spawn], pubkey)
    text = format_report(report)
    assert "pubkey" in text
    assert "valid     true" in text
    assert "position" in text


def test_the_gps_vectors_of_the_specification_pass() -> None:
    report = run_gps_vectors()
    assert report.ok, report.failures
    assert report.total == 6


def test_the_visualisation_vectors_of_the_specification_pass() -> None:
    path = visualization_path()
    if path is None:  # pragma: no cover - fixture is external
        pytest.skip("the visualisation fixture is not available")
    report = run_visualization_vectors(path)
    assert report.ok, report.failures
    assert report.total == 14
