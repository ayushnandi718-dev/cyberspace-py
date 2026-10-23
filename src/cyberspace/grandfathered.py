"""The grandfathered lists of section 6.16 and DECK-0001 section 5.8.

Two constructions changed their openings after they had been published, and
the events published under the old construction were audited one by one and
listed.  A listed event keeps its proof: the list waives only the re-check
of the root and the openings, and every other rule still applies to it.

The lists are event ids, and event ids cannot be forged, so the list cannot
be joined after the fact by backdating a ``created_at``.
"""

from __future__ import annotations

import functools
import pathlib

__all__ = [
    "GRANDFATHERED_SIDESTEPS",
    "GRANDFATHERED_HYPERJUMPS",
    "is_grandfathered_sidestep",
    "is_grandfathered_hyperjump",
]

_DATA = pathlib.Path(__file__).with_name("data")

GRANDFATHERED_SIDESTEPS = "grandfathered-v2-sidesteps.txt"
"""The file listing the version 2 sidesteps exempt under section 6.16."""

GRANDFATHERED_HYPERJUMPS = "grandfathered-v1-hyperjumps.txt"
"""The file listing the version 1 rides exempt under DECK-0001 section 5.8."""


def _read(path: pathlib.Path) -> frozenset[str]:
    """The event ids a list file names.

    Each non-empty line that does not begin with ``#`` starts with a 64
    character lowercase hex event id; anything after it is commentary.
    """
    ids: set[str] = set()
    if not path.exists():
        return frozenset()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        event_id = line.split()[0]
        if len(event_id) == 64:
            ids.add(event_id)
    return frozenset(ids)


@functools.cache
def _sidesteps() -> frozenset[str]:
    return _read(_DATA / GRANDFATHERED_SIDESTEPS)


@functools.cache
def _hyperjumps() -> frozenset[str]:
    return _read(_DATA / GRANDFATHERED_HYPERJUMPS)


def is_grandfathered_sidestep(event_id: str) -> bool:
    """Whether a sidestep is on the version 2 list."""
    return event_id in _sidesteps()


def is_grandfathered_hyperjump(event_id: str) -> bool:
    """Whether a ride is on the version 1 list."""
    return event_id in _hyperjumps()
