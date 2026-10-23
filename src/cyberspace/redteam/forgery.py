"""What a forged event can and cannot do.

The chain rules make strong claims: a forged event is discarded, a fork
kills the chain, a moved coordinate breaks continuity.  This module builds
a real chain, breaks it in each of the ways an attacker would try, and
records what the chain rules say about the result.

Every case here is a *local* experiment: a key pair is generated, events
are signed with it, and the events are handed to the resolver.  Nothing is
published and no key is reused between cases.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..chain import ChainVerdict, resolve_chain
from ..constants import KIND_MOVEMENT
from ..coordinates import Coordinate, coord_to_xyz, sector_tags
from ..movement import hop_proof
from ..nostr.event import Event, new_event
from ..nostr.schnorr import generate_keypair

__all__ = [
    "ForgeryCase",
    "ForgeryResult",
    "forgery_cases",
    "hop_proof",
    "run_forgery_cases",
]


@dataclass
class ForgeryCase:
    """One experiment: a set of events and what the rules should say."""

    name: str
    description: str
    events: list[Event]
    pubkey: str
    expect_valid: bool
    expect_reason: str | None = None
    expect_chain: list[str] | None = None


@dataclass
class ForgeryResult:
    """The outcome of one experiment."""

    case: ForgeryCase
    verdict: ChainVerdict
    passed: bool
    detail: str

    def __str__(self) -> str:  # pragma: no cover - display only
        mark = "ok  " if self.passed else "FAIL"
        return f"{mark} {self.case.name}: {self.detail}"


def _movement_tags(
    action: str,
    genesis: str,
    previous: str,
    previous_coord: Coordinate,
    target: Coordinate,
    proof: str,
) -> list[list[str]]:
    """The tags of a movement event, as the spec lays them out."""
    sectors = sector_tags(target.x, target.y, target.z)
    return [
        ["A", action],
        ["e", genesis, "", "genesis"],
        ["e", previous, "", "previous"],
        ["c", f"{previous_coord.coord:064x}"],
        ["C", f"{target.coord:064x}"],
        ["proof", proof],
        ["X", sectors["X"]],
        ["Y", sectors["Y"]],
        ["Z", sectors["Z"]],
        ["S", sectors["S"]],
    ]


def _spawn_tags(target: Coordinate) -> list[list[str]]:
    """The tags of a spawn event."""
    sectors = sector_tags(target.x, target.y, target.z)
    return [
        ["A", "spawn"],
        ["C", f"{target.coord:064x}"],
        ["X", sectors["X"]],
        ["Y", sectors["Y"]],
        ["Z", sectors["Z"]],
        ["S", sectors["S"]],
    ]


def _nudge(value: int) -> int:
    """A value one step away, differing in the lowest bit only.

    A movement across the lowest boundary of an axis costs one leaf of
    work, which keeps these experiments fast.
    """
    if value & 1:
        return value - 1
    return value + 1


def forgery_cases() -> list[ForgeryCase]:
    """Build the standard set of forgery experiments."""
    secret, pubkey_bytes = generate_keypair()
    pubkey = pubkey_bytes.hex()

    # The spawn of an identity is its own public key read as a coordinate.
    spawn_position = Coordinate(*coord_to_xyz(int(pubkey, 16)))
    target_position = Coordinate(
        _nudge(spawn_position.x), spawn_position.y, spawn_position.z, spawn_position.plane
    )
    far_position = Coordinate(
        _nudge(_nudge(spawn_position.x)),
        spawn_position.y,
        spawn_position.z,
        spawn_position.plane,
    )

    spawn = new_event(
        secret, pubkey, KIND_MOVEMENT, _spawn_tags(spawn_position), "", 1700000000
    )

    def make_hop(
        target: Coordinate = target_position,
        previous: Event = spawn,
        previous_position: Coordinate = spawn_position,
        created_at: int = 1700000001,
        action: str = "hop",
    ) -> Event:
        proof = hop_proof(
            bytes.fromhex(previous.id), previous_position, target
        )
        return new_event(
            secret,
            pubkey,
            KIND_MOVEMENT,
            _movement_tags(
                action,
                spawn.id,
                previous.id,
                previous_position,
                target,
                proof,
            ),
            "",
            created_at,
        )

    hop = make_hop()

    # 1. A copy of the hop whose content was changed and whose id was
    #    recomputed to match, but whose signature was not.
    altered = Event.from_dict(hop.to_dict())
    altered.content = "altered by someone else"
    altered.id = altered.compute_id()

    # 2. A copy of the hop with a corrupted signature.
    forged_signature = Event.from_dict(hop.to_dict())
    forged_signature.sig = "00" * 64

    # 3. An authentic hop whose proof does not match its destination.
    tags = [list(tag) for tag in make_hop(target=far_position).tags]
    for tag in tags:
        if tag[0] == "proof":
            tag[1] = "11" * 32
    wrong_proof = new_event(secret, pubkey, KIND_MOVEMENT, tags, "", 1700000002)

    # 4. An authentic hop whose sector tags do not match its coordinate.
    tags = [list(tag) for tag in make_hop().tags]
    for tag in tags:
        if tag[0] == "S":
            tag[1] = "1-1-1"
    wrong_sector = new_event(secret, pubkey, KIND_MOVEMENT, tags, "", 1700000003)

    # 5. An authentic hop whose continuity tag points elsewhere.
    tags = [list(tag) for tag in make_hop().tags]
    for tag in tags:
        if tag[0] == "c":
            tag[1] = f"{Coordinate(9, 9, 9, 0).coord:064x}"
    broken_c = new_event(secret, pubkey, KIND_MOVEMENT, tags, "", 1700000004)

    # 6. An authentic hop carrying its coordinate tag twice.
    tags = [list(tag) for tag in make_hop().tags]
    tags.append(["C", f"{target_position.coord:064x}"])
    twice = new_event(secret, pubkey, KIND_MOVEMENT, tags, "", 1700000005)

    # 7. Two authentic hops from the same parent: a fork.
    fork_a = make_hop(created_at=1700000006)
    fork_b = make_hop(target=far_position, created_at=1700000007)

    # 8. An authentic event whose action nobody knows: it is skipped.
    unknown = make_hop(action="dance", created_at=1700000008)

    # 9. An authentic spawn whose coordinate is not its public key.
    bad_spawn = new_event(
        secret,
        pubkey,
        KIND_MOVEMENT,
        _spawn_tags(Coordinate(5, 5, 5, 0)),
        "",
        1700000009,
    )

    # 10. A newer spawn: it ends the old chain and starts a new one.
    respawn = new_event(
        secret,
        pubkey,
        KIND_MOVEMENT,
        _spawn_tags(spawn_position),
        "",
        1700000010,
    )

    return [
        ForgeryCase(
            name="baseline",
            description="a spawn and one honest hop",
            events=[spawn, hop],
            pubkey=pubkey,
            expect_valid=True,
            expect_chain=[spawn.id, hop.id],
        ),
        ForgeryCase(
            name="altered-content",
            description="a copy of the hop with its content changed",
            events=[spawn, hop, altered],
            pubkey=pubkey,
            expect_valid=True,
            expect_chain=[spawn.id, hop.id],
        ),
        ForgeryCase(
            name="forged-signature",
            description="a copy of the hop with a corrupted signature",
            events=[spawn, hop, forged_signature],
            pubkey=pubkey,
            expect_valid=True,
            expect_chain=[spawn.id, hop.id],
        ),
        ForgeryCase(
            name="signed-wrong-proof",
            description="an authentic hop whose proof does not verify",
            events=[spawn, wrong_proof],
            pubkey=pubkey,
            expect_valid=False,
            expect_reason="hop-proof",
        ),
        ForgeryCase(
            name="wrong-sector-tag",
            description="an authentic hop whose sector tags do not match",
            events=[spawn, wrong_sector],
            pubkey=pubkey,
            expect_valid=False,
            expect_reason="sector-tags",
        ),
        ForgeryCase(
            name="broken-continuity",
            description="an authentic hop whose c tag points elsewhere",
            events=[spawn, broken_c],
            pubkey=pubkey,
            expect_valid=False,
            expect_reason="c-mismatch",
        ),
        ForgeryCase(
            name="repeated-tag",
            description="an authentic hop that carries its coordinate twice",
            events=[spawn, twice],
            pubkey=pubkey,
            expect_valid=False,
            expect_reason="malformed",
        ),
        ForgeryCase(
            name="fork",
            description="two authentic hops from the same parent",
            events=[spawn, fork_a, fork_b],
            pubkey=pubkey,
            expect_valid=False,
            expect_reason="fork",
        ),
        ForgeryCase(
            name="unknown-action",
            description="an authentic event whose action nobody knows",
            events=[spawn, unknown],
            pubkey=pubkey,
            expect_valid=True,
        ),
        ForgeryCase(
            name="no-spawn",
            description="a chain with no spawn at all",
            events=[hop],
            pubkey=pubkey,
            expect_valid=False,
            expect_reason="no-spawn",
        ),
        ForgeryCase(
            name="spawn-wrong-coordinate",
            description="a spawn whose coordinate is not its public key",
            events=[bad_spawn],
            pubkey=pubkey,
            expect_valid=False,
            expect_reason="spawn-coordinate",
        ),
        ForgeryCase(
            name="respawn",
            description="a newer spawn, which starts a new chain",
            events=[spawn, hop, respawn],
            pubkey=pubkey,
            expect_valid=True,
        ),
    ]


def run_forgery_cases(cases: list[ForgeryCase] | None = None) -> list[ForgeryResult]:
    """Run the experiments and compare the verdicts with the expectations."""
    if cases is None:
        cases = forgery_cases()
    results: list[ForgeryResult] = []
    for case in cases:
        verdict = resolve_chain(case.events, case.pubkey)
        problems: list[str] = []
        if verdict.valid != case.expect_valid:
            problems.append(
                f"valid={verdict.valid} expected {case.expect_valid}"
            )
        if case.expect_reason is not None and verdict.reason != case.expect_reason:
            problems.append(
                f"reason={verdict.reason!r} expected {case.expect_reason!r}"
            )
        if case.expect_chain is not None and verdict.chain != case.expect_chain:
            problems.append(f"chain={verdict.chain} expected {case.expect_chain}")
        detail = verdict.reason or "valid"
        if problems:
            detail = "; ".join(problems)
        results.append(
            ForgeryResult(
                case=case, verdict=verdict, passed=not problems, detail=detail
            )
        )
    return results
