"""Resolving and validating movement chains (spec sections 8.2, 8.7-8.12).

A movement chain is a per-identity line of signed Nostr events.  Resolving it
is a two-stage process, and the order matters:

**Resolution comes first.**  The active chain is chosen from authentic events
by their links, their ``created_at`` and their ids alone, without checking a
single proof.  Every reader therefore agrees on where the identity is, and can
disagree only about whether the chain is valid, which each settles by checking
the proofs.

**Validity comes second.**  The chosen chain is then checked event by event
from the spawn forward.  The first invalid event makes the chain invalid from
there: the event and everything after it count for nothing, and the identity is
frozen at its last valid position until it respawns.

Two rules deserve their own note.

*Forks are fatal.*  When two distinct events name the same event as their
previous, the chain is dead from the spawn and the identity stands at its
spawn coordinate.  There is no "branch signed first wins" rule: any rewrite
of published history ends the chain.

*Forged events are discarded before resolution.*  Otherwise anyone could end
another identity's chain by posting a forged event under its pubkey.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .cantor import axis_root, cantor_pair, find_lca_height
from .constants import (
    ACTION_ENTER_HYPERSPACE,
    ACTION_ENTER_VIRTUAL,
    ACTION_EXIT_VIRTUAL,
    ACTION_HOP,
    ACTION_HYPERJUMP,
    ACTION_SIDESTEP,
    ACTION_SPAWN,
    AXIS_BITS,
    CHAIN_RULES_REVISION,
    KIND_MOVEMENT,
    RESERVED_ACTIONS,
)
from .coordinates import coord_to_xyz, sector_tags
from .grandfathered import is_grandfathered_hyperjump, is_grandfathered_sidestep
from .hyperspace import (
    HYPERSPACE_SAMPLES,
    Line,
    attempts_required,
    enter_proof,
    grind_attempt,
    meets_price,
    verify_ride,
)
from .nostr.event import Event
from .sidestep import (
    crossing_geometry_ok,
    decode_openings_tag,
    decode_roots_tag,
    verify_sidestep,
)
from .temporal import hop_preimage, movement_proof_hash, temporal_root, terrain_height

__all__ = [
    "ChainVerdict",
    "resolve_chain",
    "CHAIN_RULES_REVISION",
    "REASONS",
    "REASON_NO_SPAWN",
    "REASON_FORK",
    "REASON_A_TAG",
    "REASON_MALFORMED",
    "REASON_SECTOR_TAGS",
    "REASON_SPAWN_COORDINATE",
    "REASON_C_MISMATCH",
    "REASON_HOP_PROOF",
    "REASON_SIDESTEP_PROOF",
    "REASON_ENTER_HYPERSPACE_MOVED",
    "REASON_ENTER_HYPERSPACE_PROOF",
    "REASON_HYPERJUMP_PREDECESSOR",
    "REASON_HYPERJUMP_ZERO_LENGTH",
    "REASON_HYPERJUMP_AS_OF",
    "REASON_HYPERJUMP_STATION",
    "REASON_HYPERJUMP_FROM_HEIGHT",
    "REASON_HYPERJUMP_STOP",
    "REASON_HYPERJUMP_PROOF",
    "REASON_ENTER_VIRTUAL_MOVED",
    "REASON_REGION",
    "REASON_GAME_TAG",
    "REASON_BASE_ACTION_IN_BRACKET",
    "REASON_EXIT_WITHOUT_BRACKET",
    "REASON_EXIT_WRONG_ENTRY",
    "REASON_EXIT_POSITION",
]

# --- Reason codes (the vocabulary the spec's golden vectors use) --------------

REASON_NO_SPAWN = "no-spawn"
REASON_FORK = "fork"
REASON_A_TAG = "a-tag"
REASON_MALFORMED = "malformed"
REASON_SECTOR_TAGS = "sector-tags"
REASON_SPAWN_COORDINATE = "spawn-coordinate"
REASON_C_MISMATCH = "c-mismatch"
REASON_HOP_PROOF = "hop-proof"
REASON_SIDESTEP_PROOF = "sidestep-proof"
REASON_ENTER_HYPERSPACE_MOVED = "enter-hyperspace-moved"
REASON_ENTER_HYPERSPACE_PROOF = "enter-hyperspace-proof"
REASON_HYPERJUMP_PREDECESSOR = "hyperjump-predecessor"
REASON_HYPERJUMP_ZERO_LENGTH = "hyperjump-zero-length"
REASON_HYPERJUMP_AS_OF = "hyperjump-as-of"
REASON_HYPERJUMP_STATION = "hyperjump-station"
REASON_HYPERJUMP_FROM_HEIGHT = "hyperjump-from-height"
REASON_HYPERJUMP_STOP = "hyperjump-stop"
REASON_HYPERJUMP_PROOF = "hyperjump-proof"
REASON_ENTER_VIRTUAL_MOVED = "enter-virtual-moved"
REASON_REGION = "region"
REASON_GAME_TAG = "game-tag"
REASON_BASE_ACTION_IN_BRACKET = "base-action-in-bracket"
REASON_EXIT_WITHOUT_BRACKET = "exit-without-bracket"
REASON_EXIT_WRONG_ENTRY = "exit-wrong-entry"
REASON_EXIT_POSITION = "exit-position"

REASONS = (
    REASON_NO_SPAWN,
    REASON_FORK,
    REASON_A_TAG,
    REASON_MALFORMED,
    REASON_SECTOR_TAGS,
    REASON_SPAWN_COORDINATE,
    REASON_C_MISMATCH,
    REASON_HOP_PROOF,
    REASON_SIDESTEP_PROOF,
    REASON_ENTER_HYPERSPACE_MOVED,
    REASON_ENTER_HYPERSPACE_PROOF,
    REASON_HYPERJUMP_PREDECESSOR,
    REASON_HYPERJUMP_ZERO_LENGTH,
    REASON_HYPERJUMP_AS_OF,
    REASON_HYPERJUMP_STATION,
    REASON_HYPERJUMP_FROM_HEIGHT,
    REASON_HYPERJUMP_STOP,
    REASON_HYPERJUMP_PROOF,
    REASON_ENTER_VIRTUAL_MOVED,
    REASON_REGION,
    REASON_GAME_TAG,
    REASON_BASE_ACTION_IN_BRACKET,
    REASON_EXIT_WITHOUT_BRACKET,
    REASON_EXIT_WRONG_ENTRY,
    REASON_EXIT_POSITION,
)

_HEX32 = re.compile(r"\A[0-9a-f]{64}\Z")
_HEX16 = re.compile(r"\A[0-9a-f]{16}\Z")
_DECIMAL = re.compile(r"\A(?:0|[1-9][0-9]*)\Z")


def _is_hex32(value: object) -> bool:
    """Whether a value is a 32-byte lowercase hex string."""
    return isinstance(value, str) and _HEX32.match(value) is not None


def _is_hex16(value: object) -> bool:
    """Whether a value is a 16-character lowercase hex string."""
    return isinstance(value, str) and _HEX16.match(value) is not None


def _is_decimal(value: object) -> bool:
    """Whether a value is a canonical base-10 integer string."""
    return isinstance(value, str) and _DECIMAL.match(value) is not None


def _tags_named(event: Event, name: str) -> list[list[str]]:
    """Every tag with the given name, in the order they appear."""
    return [t for t in event.tags if isinstance(t, list) and t and t[0] == name]


def _tags_marked(event: Event, name: str, marker: str) -> list[list[str]]:
    """Every tag with the given name whose fourth element is the marker."""
    return [
        t
        for t in event.tags
        if isinstance(t, list) and t and t[0] == name and len(t) >= 4 and t[3] == marker
    ]


def _tag_value(tag: list[str]) -> str | None:
    """The value of a tag, or ``None`` when it has none."""
    if len(tag) >= 2 and isinstance(tag[1], str):
        return tag[1]
    return None


def _first_marked_value(event: Event, name: str, marker: str) -> str | None:
    """The value of the *first* tag with the given name and marker.

    Resolution reads the first copy of each link and checks no form, so that
    two readers holding the same events resolve the same chain.
    """
    tags = _tags_marked(event, name, marker)
    if not tags:
        return None
    return _tag_value(tags[0])


def _exactly_one_hex32(event: Event, name: str, marker: str | None = None) -> str | None:
    """The value of a tag that must appear exactly once and be well formed.

    Returns ``None`` when the tag is missing, repeated, valueless or ill
    formed: any of those makes the event invalid.
    """
    tags = _tags_marked(event, name, marker) if marker else _tags_named(event, name)
    if len(tags) != 1:
        return None
    value = _tag_value(tags[0])
    if not _is_hex32(value):
        return None
    return value


def _exactly_one_decimal(event: Event, name: str) -> str | None:
    """The value of a tag that must appear exactly once and be a decimal."""
    tags = _tags_named(event, name)
    if len(tags) != 1:
        return None
    value = _tag_value(tags[0])
    if not _is_decimal(value):
        return None
    return value


def _exactly_one_text(event: Event, name: str) -> str | None:
    """The value of a tag that must appear exactly once, with any value."""
    tags = _tags_named(event, name)
    if len(tags) != 1:
        return None
    return _tag_value(tags[0])


def _action_tag(event: Event) -> str | None:
    """The value of the event's single ``A`` tag.

    Returns ``None`` when the event carries no ``A`` tag, more than one, or
    one with no value: a bare ``["A"]`` counts as an ``A`` tag, and a
    malformed one.
    """
    tags = _tags_named(event, "A")
    if len(tags) != 1:
        return None
    value = _tag_value(tags[0])
    if not value:
        return None
    return value


def _is_spawn(event: Event) -> bool:
    """Whether any ``A`` tag of the event names ``spawn``."""
    return any(
        isinstance(t, list) and t and t[0] == "A" and len(t) >= 2 and t[1] == ACTION_SPAWN
        for t in event.tags
    )


def _sector_tags_ok(event: Event, coord_hex: str) -> bool:
    """Whether the four sector tags of an event match its coordinate.

    Each tag must appear exactly once, with the value computed from the
    coordinate, written as a canonical base-10 integer.
    """
    x, y, z, _plane = coord_to_xyz(int(coord_hex, 16))
    expected = sector_tags(x, y, z)
    for name in ("X", "Y", "Z", "S"):
        tags = _tags_named(event, name)
        if len(tags) != 1:
            return False
        if _tag_value(tags[0]) != expected[name]:
            return False
    return True


def _region_ok(tag: list[str]) -> bool:
    """Whether a ``region`` tag is well formed (spec section 8.11.1).

    The tag carries the coordinate of the region's aligned base and its
    height ``H``.  Only the form is checked: the base position need not lie
    inside the region, and the region may be on another plane.
    """
    if len(tag) != 3:
        return False
    coord_hex = _tag_value(tag)
    height = tag[2] if len(tag) >= 3 and isinstance(tag[2], str) else None
    if not _is_hex32(coord_hex) or not _is_decimal(height):
        return False
    height_int = int(height)
    if height_int > AXIS_BITS:
        return False
    x, y, z, _plane = coord_to_xyz(int(coord_hex, 16))
    mask = (1 << height_int) - 1
    return not (x & mask) and not (y & mask) and not (z & mask)


@dataclass
class _Bracket:
    """An open virtual bracket."""

    entry_id: str
    base_hex: str
    saved_prev: _Recognized | None = None
    """The action the bracket stands in front of, restored when it closes."""


@dataclass
class _Recognized:
    """A recognized action, as the rules that look back see it.

    A skipped action is not recognized, so the chain walks straight over it.
    An ``exit-virtual`` stands for the action before its ``enter-virtual``,
    so a rule that looks back through a bracket sees what was there before
    the game started.
    """

    action: str
    coord: int
    event_id: str
    height: int | None = None
    """The destination height of a ``hyperjump``."""


@dataclass
class _State:
    """The verifier's state as it walks the active chain."""

    pubkey: str
    position: int
    last_recognized: int | None = None
    prev: _Recognized | None = None
    bracket: _Bracket | None = None
    skipped: list[str] = field(default_factory=list)


@dataclass
class ChainVerdict:
    """The result of resolving and validating one identity's chain."""

    valid: bool = False
    chain: list[str] = field(default_factory=list)
    position: int | None = None
    head: str | None = None
    open_bracket: str | None = None
    skipped: list[str] | None = None
    reason: str | None = None
    invalid_at: str | None = None
    invalid_index: int | None = None
    revision: str = CHAIN_RULES_REVISION

    @property
    def position_hex(self) -> str | None:
        """The position as the 32-byte lowercase hex used in tags."""
        if self.position is None:
            return None
        return format(self.position, "064x")

    def to_dict(self) -> dict:
        """The verdict in the shape the spec's golden vectors use."""
        out: dict = {
            "valid": self.valid,
            "chain": list(self.chain),
            "position": self.position_hex,
        }
        if self.valid:
            out["head"] = self.head
            out["open_bracket"] = self.open_bracket
            out["skipped"] = list(self.skipped or [])
        else:
            out["reason"] = self.reason
            out["invalid_at"] = self.invalid_at
            out["invalid_index"] = self.invalid_index
        return out


def _authentic_chain_events(events: list[Event], pubkey: str) -> list[Event]:
    """The authentic kind-3333 events of one identity, deduplicated by id.

    An event is authentic when its id is the hash of its canonical
    serialisation, its signature verifies over that id, and its pubkey is the
    identity's own.  Everything else is discarded before resolution.
    """
    by_id: dict[str, Event] = {}
    for event in events:
        if event.kind != KIND_MOVEMENT:
            continue
        if event.pubkey != pubkey:
            continue
        if event.id in by_id:
            continue
        if not event.verify():
            continue
        by_id[event.id] = event
    return list(by_id.values())


def resolve_chain(
    events: list[Event], pubkey: str, line: Line | None = None
) -> ChainVerdict:
    """Resolve and validate the active movement chain of an identity.

    ``events`` may hold any events at all: they are filtered to the
    identity's authentic chain events first.

    ``line`` is the Bitcoin line, needed to check hyperspace rides
    (DECK-0001).  Without it a ride cannot be confirmed and the chain is
    invalid from that ride.
    """
    authentic = _authentic_chain_events(events, pubkey)

    spawns = [event for event in authentic if _is_spawn(event)]
    if not spawns:
        return ChainVerdict(
            valid=False, chain=[], position=None, reason=REASON_NO_SPAWN
        )
    spawn = max(spawns, key=lambda event: (event.created_at, event.id))

    children: dict[str, list[Event]] = {}
    for event in authentic:
        if _is_spawn(event):
            # A spawn is never a link, whatever e tags it carries.
            continue
        genesis = _first_marked_value(event, "e", "genesis")
        previous = _first_marked_value(event, "e", "previous")
        if genesis is None or previous is None:
            continue
        if genesis != spawn.id:
            # It belongs to an older chain and is ignored here.
            continue
        children.setdefault(previous, []).append(event)

    chain_events: list[Event] = [spawn]
    current = spawn
    visited = {spawn.id}
    while True:
        candidates = children.get(current.id, [])
        if len(candidates) > 1:
            return ChainVerdict(
                valid=False,
                chain=[event.id for event in chain_events],
                position=int(pubkey, 16),
                reason=REASON_FORK,
                invalid_at=spawn.id,
                invalid_index=0,
            )
        if not candidates:
            break
        current = candidates[0]
        if current.id in visited:
            break
        visited.add(current.id)
        chain_events.append(current)

    chain_ids = [event.id for event in chain_events]
    state = _State(pubkey=pubkey, position=int(pubkey, 16))

    reason = _validate_spawn(spawn, pubkey)
    if reason is not None:
        return ChainVerdict(
            valid=False,
            chain=chain_ids,
            position=int(pubkey, 16),
            reason=reason,
            invalid_at=spawn.id,
            invalid_index=0,
        )
    state.position = int(_exactly_one_hex32(spawn, "C"), 16)
    state.last_recognized = state.position
    state.prev = _Recognized(ACTION_SPAWN, state.position, spawn.id)

    for index, event in enumerate(chain_events[1:], start=1):
        reason = _validate_event(event, state, line)
        if reason is not None:
            return ChainVerdict(
                valid=False,
                chain=chain_ids,
                position=state.position,
                reason=reason,
                invalid_at=event.id,
                invalid_index=index,
            )

    return ChainVerdict(
        valid=True,
        chain=chain_ids,
        position=state.position,
        head=chain_ids[-1],
        open_bracket=state.bracket.entry_id if state.bracket else None,
        skipped=list(state.skipped),
    )


def _validate_spawn(event: Event, pubkey: str) -> str | None:
    """Check a spawn event and return a reason code, or ``None``."""
    if _action_tag(event) is None:
        return REASON_A_TAG
    coord_hex = _exactly_one_hex32(event, "C")
    if coord_hex is None:
        return REASON_MALFORMED
    if not _sector_tags_ok(event, coord_hex):
        return REASON_SECTOR_TAGS
    if coord_hex != pubkey:
        return REASON_SPAWN_COORDINATE
    return None


def _validate_event(event: Event, state: _State, line: Line | None) -> str | None:
    """Check one event of the active chain and return a reason code."""
    action = _action_tag(event)
    if action is None:
        return REASON_A_TAG

    genesis = _exactly_one_hex32(event, "e", "genesis")
    previous = _exactly_one_hex32(event, "e", "previous")
    if genesis is None or previous is None:
        return REASON_MALFORMED

    if state.bracket is not None:
        if action in RESERVED_ACTIONS:
            return REASON_BASE_ACTION_IN_BRACKET
        if action == ACTION_EXIT_VIRTUAL:
            return _validate_exit(event, state)
        # A virtual action: links, the A tag and the reserved names are all
        # that the base protocol reads inside a bracket.
        return None

    if action == ACTION_EXIT_VIRTUAL:
        return _validate_exit(event, state)
    if action == ACTION_ENTER_VIRTUAL:
        return _validate_enter_virtual(event, state)
    if action == ACTION_HOP:
        return _validate_hop(event, state, previous)
    if action == ACTION_SIDESTEP:
        return _validate_sidestep(event, state, previous)
    if action == ACTION_ENTER_HYPERSPACE:
        return _validate_enter_hyperspace(event, state, previous)
    if action == ACTION_HYPERJUMP:
        return _validate_hyperjump(event, state, previous, line)

    # An action this verifier does not recognize is skipped: the chain goes
    # on through it, and the position it may have moved is not carried.
    state.skipped.append(event.id)
    return None


def _validate_exit(event: Event, state: _State) -> str | None:
    """Check an ``exit-virtual`` action."""
    entry = _exactly_one_hex32(event, "e", "entry")
    if entry is None:
        return REASON_MALFORMED
    coord_hex = _exactly_one_hex32(event, "C")
    if coord_hex is None:
        return REASON_MALFORMED
    if not _sector_tags_ok(event, coord_hex):
        return REASON_SECTOR_TAGS
    if state.bracket is None:
        return REASON_EXIT_WITHOUT_BRACKET
    if entry != state.bracket.entry_id:
        return REASON_EXIT_WRONG_ENTRY
    if coord_hex != state.bracket.base_hex:
        return REASON_EXIT_POSITION
    # The exit stands for the action before its enter-virtual, so a rule
    # that looks back sees straight through the bracket.
    state.prev = state.bracket.saved_prev
    state.bracket = None
    state.position = int(coord_hex, 16)
    state.last_recognized = state.position
    return None


def _validate_enter_virtual(event: Event, state: _State) -> str | None:
    """Check an ``enter-virtual`` action and open its bracket."""
    prev_hex = _exactly_one_hex32(event, "c")
    if prev_hex is None:
        return REASON_MALFORMED
    coord_hex = _exactly_one_hex32(event, "C")
    if coord_hex is None:
        return REASON_MALFORMED
    if not _sector_tags_ok(event, coord_hex):
        return REASON_SECTOR_TAGS
    if state.last_recognized is not None and int(prev_hex, 16) != state.last_recognized:
        return REASON_C_MISMATCH
    if coord_hex != prev_hex:
        return REASON_ENTER_VIRTUAL_MOVED
    region_tags = _tags_named(event, "region")
    if len(region_tags) != 1 or not _region_ok(region_tags[0]):
        return REASON_REGION
    game_tags = _tags_marked(event, "p", "game")
    if len(game_tags) != 1 or not _is_hex32(_tag_value(game_tags[0])):
        return REASON_GAME_TAG
    state.bracket = _Bracket(
        entry_id=event.id, base_hex=prev_hex, saved_prev=state.prev
    )
    state.position = int(coord_hex, 16)
    state.last_recognized = state.position
    state.prev = _Recognized(ACTION_ENTER_VIRTUAL, state.position, event.id)
    return None


def _validate_hop(event: Event, state: _State, previous_event_id: str) -> str | None:
    """Check a ``hop`` action."""
    prev_hex = _exactly_one_hex32(event, "c")
    if prev_hex is None:
        return REASON_MALFORMED
    coord_hex = _exactly_one_hex32(event, "C")
    if coord_hex is None:
        return REASON_MALFORMED
    proof = _exactly_one_hex32(event, "proof")
    if proof is None:
        return REASON_MALFORMED
    if not _sector_tags_ok(event, coord_hex):
        return REASON_SECTOR_TAGS
    prev_coord = int(prev_hex, 16)
    if state.last_recognized is not None and prev_coord != state.last_recognized:
        return REASON_C_MISMATCH
    if not _hop_proof_ok(
        bytes.fromhex(previous_event_id), prev_coord, int(coord_hex, 16), proof
    ):
        return REASON_HOP_PROOF
    state.position = int(coord_hex, 16)
    state.last_recognized = state.position
    state.prev = _Recognized(ACTION_HOP, state.position, event.id)
    return None


def _validate_sidestep(event: Event, state: _State, previous_event_id: str) -> str | None:
    """Check a ``sidestep`` action."""
    prev_hex = _exactly_one_hex32(event, "c")
    if prev_hex is None:
        return REASON_MALFORMED
    coord_hex = _exactly_one_hex32(event, "C")
    if coord_hex is None:
        return REASON_MALFORMED
    proof = _exactly_one_hex32(event, "proof")
    if proof is None:
        return REASON_MALFORMED
    roots_text = _exactly_one_text(event, "mr")
    if roots_text is None:
        return REASON_MALFORMED
    openings_text = _exactly_one_text(event, "mp")
    if openings_text is None:
        return REASON_MALFORMED
    heights = []
    for name in ("hx", "hy", "hz"):
        value = _exactly_one_decimal(event, name)
        if value is None or int(value) > AXIS_BITS:
            return REASON_MALFORMED
        heights.append(int(value))
    nonce_tags = _tags_named(event, "mn")
    if len(nonce_tags) > 1:
        return REASON_MALFORMED
    if nonce_tags:
        nonce_text = _tag_value(nonce_tags[0])
        if not _is_hex16(nonce_text):
            return REASON_MALFORMED

    if not _sector_tags_ok(event, coord_hex):
        return REASON_SECTOR_TAGS
    prev_coord = int(prev_hex, 16)
    if state.last_recognized is not None and prev_coord != state.last_recognized:
        return REASON_C_MISMATCH

    try:
        roots = decode_roots_tag(roots_text)
        openings = decode_openings_tag(openings_text, (heights[0], heights[1], heights[2]))
    except ValueError:
        return REASON_MALFORMED

    if not nonce_tags:
        # A version 2 proof.  It may only be accepted when it is listed in
        # the grandfathered file, which waives only the re-check of the
        # roots and the openings.
        if not is_grandfathered_sidestep(event.id):
            return REASON_SIDESTEP_PROOF
    else:
        nonce = int(_tag_value(nonce_tags[0]), 16)
        if not _sidestep_proof_ok(
            bytes.fromhex(previous_event_id),
            prev_coord,
            int(coord_hex, 16),
            roots,
            nonce,
            openings,
            (heights[0], heights[1], heights[2]),
            proof,
        ):
            return REASON_SIDESTEP_PROOF
    state.position = int(coord_hex, 16)
    state.last_recognized = state.position
    state.prev = _Recognized(ACTION_SIDESTEP, state.position, event.id)
    return None


def _validate_enter_hyperspace(
    event: Event, state: _State, previous_event_id: str
) -> str | None:
    """Check an ``enter-hyperspace`` action (DECK-0001 section 3).

    Boarding does not move the identity: it marks the chain position from
    which the first ride departs.
    """
    prev_hex = _exactly_one_hex32(event, "c")
    if prev_hex is None:
        return REASON_MALFORMED
    coord_hex = _exactly_one_hex32(event, "C")
    if coord_hex is None:
        return REASON_MALFORMED
    proof = _exactly_one_hex32(event, "proof")
    if proof is None:
        return REASON_MALFORMED
    if not _sector_tags_ok(event, coord_hex):
        return REASON_SECTOR_TAGS
    prev_coord = int(prev_hex, 16)
    if state.last_recognized is not None and prev_coord != state.last_recognized:
        return REASON_C_MISMATCH
    if coord_hex != prev_hex:
        return REASON_ENTER_HYPERSPACE_MOVED
    if enter_proof(bytes.fromhex(previous_event_id), prev_coord).hex() != proof:
        return REASON_ENTER_HYPERSPACE_PROOF
    state.position = prev_coord
    state.last_recognized = state.position
    state.prev = _Recognized(ACTION_ENTER_HYPERSPACE, state.position, event.id)
    return None


def _validate_hyperjump(
    event: Event, state: _State, previous_event_id: str, line: Line | None
) -> str | None:
    """Check a ``hyperjump`` action (DECK-0001 sections 4 and 5).

    The order of the checks is the deck's: the shape of the event first,
    then the continuity of ``c``, then the rule that there is no zero-length
    ride, then the sector tags, then the rule of section 4.3, then the stop
    of section 5.5 step 2, and last the proof of steps 3 to 6.
    """
    prev_hex = _exactly_one_hex32(event, "c")
    if prev_hex is None:
        return REASON_MALFORMED
    coord_hex = _exactly_one_hex32(event, "C")
    if coord_hex is None:
        return REASON_MALFORMED
    proof = _exactly_one_hex32(event, "proof")
    if proof is None:
        return REASON_MALFORMED
    from_height_text = _exactly_one_decimal(event, "from_height")
    if from_height_text is None:
        return REASON_MALFORMED
    destination_text = _exactly_one_decimal(event, "B")
    if destination_text is None:
        return REASON_MALFORMED
    nonce_tags = _tags_named(event, "mn")
    if len(nonce_tags) > 1:
        return REASON_MALFORMED
    nonce_text = None
    if nonce_tags:
        nonce_text = _tag_value(nonce_tags[0])
        if not _is_hex16(nonce_text):
            return REASON_MALFORMED

    # The as_of tag is read only by the first ride after a boarding, so only
    # that ride is bound by its shape (DECK-0001 section 8).
    previous = state.prev
    first_ride = previous is not None and previous.action == ACTION_ENTER_HYPERSPACE
    as_of_text = None
    if first_ride:
        as_of_tags = _tags_named(event, "as_of")
        if len(as_of_tags) > 1:
            return REASON_MALFORMED
        if as_of_tags:
            as_of_text = _tag_value(as_of_tags[0])
            if not _is_decimal(as_of_text):
                return REASON_MALFORMED

    prev_coord = int(prev_hex, 16)
    if state.last_recognized is not None and prev_coord != state.last_recognized:
        return REASON_C_MISMATCH

    from_height = int(from_height_text)
    destination = int(destination_text)
    if destination == from_height:
        # There is no zero-length ride: it would carry no work and prove
        # nothing (DECK-0001 section 5.6).
        return REASON_HYPERJUMP_ZERO_LENGTH

    if not _sector_tags_ok(event, coord_hex):
        return REASON_SECTOR_TAGS

    if previous is None or previous.action not in (
        ACTION_ENTER_HYPERSPACE,
        ACTION_HYPERJUMP,
    ):
        return REASON_HYPERJUMP_PREDECESSOR

    if first_ride:
        if as_of_text is None:
            return REASON_HYPERJUMP_AS_OF
        as_of = int(as_of_text)
        if line is None or as_of not in line:
            return REASON_HYPERJUMP_AS_OF
        if as_of < destination:
            return REASON_HYPERJUMP_AS_OF
        station = line.station(previous.coord, as_of)
        if station is None or station != from_height:
            return REASON_HYPERJUMP_STATION
    else:
        if previous.height is None or previous.height != from_height:
            return REASON_HYPERJUMP_FROM_HEIGHT

    if line is None or destination not in line:
        return REASON_HYPERJUMP_STOP
    if line.coord(destination) != int(coord_hex, 16):
        return REASON_HYPERJUMP_STOP

    # The openings are read only with the proof, so that a ride the deck
    # rejects before that point is reported for its own reason.
    openings_text = _exactly_one_text(event, "mp")
    if openings_text is None or not openings_text:
        return REASON_MALFORMED

    if nonce_text is None:
        # A version 1 ride.  Only a listed ride may lack the nonce, and
        # the list waives only the re-check of the root and the openings.
        if not is_grandfathered_hyperjump(event.id):
            return REASON_HYPERJUMP_PROOF
    elif not _hyperjump_proof_ok(
        event,
        line,
        previous_event_id,
        from_height,
        destination,
        proof,
        nonce_text,
        openings_text,
    ):
        return REASON_HYPERJUMP_PROOF

    state.position = int(coord_hex, 16)
    state.last_recognized = state.position
    state.prev = _Recognized(
        ACTION_HYPERJUMP, state.position, event.id, height=destination
    )
    return None


def _hyperjump_proof_ok(
    event: Event,
    line: Line,
    previous_event_id: str,
    from_height: int,
    destination: int,
    proof: str,
    nonce_text: str,
    openings_text: str,
) -> bool:
    """Whether a ride's proof verifies at Level 1 (DECK-0001 section 5.5)."""
    low = min(from_height, destination)
    high = max(from_height, destination)
    length = high - low
    root = bytes.fromhex(proof)
    nonce = int(nonce_text, 16)

    g_value = grind_attempt(bytes.fromhex(previous_event_id), root, nonce)
    if not meets_price(g_value, attempts_required(length)):
        return False

    depth = max(0, (length - 1).bit_length())
    parts = openings_text.split(":")
    if len(parts) != HYPERSPACE_SAMPLES:
        return False
    paths: list[list[bytes]] = []
    for part in parts:
        if len(part) != 64 * depth:
            return False
        try:
            paths.append(
                [bytes.fromhex(part[i : i + 64]) for i in range(0, len(part), 64)]
            )
        except ValueError:
            return False

    def block_hash(height: int) -> bytes:
        block = line.block(height)
        return block.block_hash if block is not None else b""

    return verify_ride(
        bytes.fromhex(previous_event_id), low, high, block_hash, root, nonce, paths
    )


def _hop_proof_ok(
    previous_event_id: bytes, prev_coord: int, cur_coord: int, proof: str
) -> bool:
    """Whether a hop's proof tag verifies (spec section 8.7.1)."""
    x1, y1, z1, _p1 = coord_to_xyz(prev_coord)
    x2, y2, z2, p2 = coord_to_xyz(cur_coord)
    region = cantor_pair(
        cantor_pair(axis_root(x1, x2), axis_root(y1, y2)), axis_root(z1, z2)
    )
    preimage = hop_preimage(region, previous_event_id, (x2, y2, z2, p2))
    return movement_proof_hash(preimage).hex() == proof


def _sidestep_proof_ok(
    previous_event_id: bytes,
    prev_coord: int,
    cur_coord: int,
    roots: tuple[bytes, bytes, bytes],
    nonce: int,
    openings: list[list[list[bytes]]],
    heights: tuple[int, int, int],
    proof: str,
) -> bool:
    """Whether a sidestep's proof tag verifies (spec section 8.7.2)."""
    x1, y1, z1, _p1 = coord_to_xyz(prev_coord)
    x2, y2, z2, p2 = coord_to_xyz(cur_coord)
    for v1, v2 in ((x1, x2), (y1, y2), (z1, z2)):
        if not crossing_geometry_ok(v1, v2):
            return False
    computed = (
        find_lca_height(x1, x2),
        find_lca_height(y1, y2),
        find_lca_height(z1, z2),
    )
    if computed != heights:
        return False
    if not verify_sidestep(
        previous_event_id, (x1, y1, z1), (x2, y2, z2), roots, nonce, openings
    ):
        return False
    region_m = cantor_pair(
        cantor_pair(
            int.from_bytes(roots[0], "big"), int.from_bytes(roots[1], "big")
        ),
        int.from_bytes(roots[2], "big"),
    )
    cantor_t = temporal_root(previous_event_id, terrain_height(x2, y2, z2, p2))
    preimage = cantor_pair(region_m, cantor_t)
    return movement_proof_hash(preimage).hex() == proof
