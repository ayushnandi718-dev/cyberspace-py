"""Avatars: the shape an identity is drawn as (spec section 8.10).

An avatar lands on other people's screens whether they asked for it or not,
so its size and detail are paid for in work, on the event that publishes it.
A client draws nothing it cannot verify has paid.

The price has two terms:

* **Reach**, the farthest any vertex lies from the build origin, priced at two
  bits per doubling of distance.
* **Detail**, the number of vertices plus faces beyond a free allowance of
  thirty-two, priced at three bits per doubling.

Both terms are floored so that a modest shape costs minutes on a phone and a
sector-sized one is out of reach of any hash power.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

__all__ = [
    "AVATAR_FLOOR_BITS",
    "AVATAR_SIZE_BITS",
    "AVATAR_DETAIL_BITS",
    "AVATAR_DETAIL_FREE",
    "Vertex",
    "AvatarPayload",
    "avatar_work",
    "leading_zero_bits",
    "avatar_is_paid",
]

AVATAR_FLOOR_BITS = 16
"""Every avatar pays at least this many bits of work."""

AVATAR_SIZE_BITS = 2
"""Bits of work per doubling of reach."""

AVATAR_DETAIL_BITS = 3
"""Bits of work per doubling of detail beyond the free allowance."""

AVATAR_DETAIL_FREE = 32
"""Vertices plus faces that are free of charge."""


@dataclass(frozen=True)
class Vertex:
    """One vertex of an avatar model.

    The tick offset ``t`` is in 120ths of a unit and may be negative, which
    stands for ``-N`` zero triples in the packed representation.
    """

    x: float = 0.0
    y: float = 0.0
    z: float = 0.0
    t: int = 0

    def offset(self) -> float:
        """The coordinate with its tick offset applied."""
        return self.t / 120.0


@dataclass
class AvatarPayload:
    """The parsed content of an avatar event."""

    unit: int = 0
    vertices: list[Vertex] = field(default_factory=list)
    faces: list = field(default_factory=list)


def avatar_work(payload: AvatarPayload) -> int:
    """The number of bits of work an avatar's content has to pay.

    ``ceil`` of the sum, so the price is a whole number of bits and two
    avatars of the same size cost the same.
    """
    reach = 1.0
    for vertex in payload.vertices:
        reach = max(
            reach,
            abs(vertex.x + vertex.offset()),
            abs(vertex.y + vertex.offset()),
            abs(vertex.z + vertex.offset()),
        )
    reach *= 2 ** payload.unit
    detail = max(AVATAR_DETAIL_FREE, len(payload.vertices) + len(payload.faces))
    work = (
        AVATAR_FLOOR_BITS
        + AVATAR_SIZE_BITS * math.log2(reach)
        + AVATAR_DETAIL_BITS * math.log2(detail / AVATAR_DETAIL_FREE)
    )
    return math.ceil(work)


def leading_zero_bits(value: bytes) -> int:
    """The number of leading zero bits in a digest."""
    count = 0
    for byte in value:
        if byte == 0:
            count += 8
            continue
        count += 8 - byte.bit_length()
        break
    return count


def avatar_is_paid(payload: AvatarPayload, event_id: str, target: int) -> bool:
    """Whether an avatar event has paid for itself.

    Both conditions are required: the committed target must be at least the
    work the content implies, and the event id must carry at least the target
    number of leading zero bits.
    """
    if target < avatar_work(payload):
        return False
    return leading_zero_bits(bytes.fromhex(event_id)) >= target
