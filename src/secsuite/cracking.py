"""Recovering a password from a hash you already hold.

This is the offline half of a password audit: the hash is in hand, and the
question is which candidate produced it.  The tool never reaches out to a
network, never guesses credentials against a service, and stops as soon as
it is told to, so that it stays inside the boundary of an audit of one's own
material.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field

from .hash import identify_hash, verify_hash

__all__ = ["CrackResult", "recover"]


@dataclass
class CrackResult:
    """What a recovery attempt found."""

    hash: str
    kind: str
    found: bool = False
    plaintext: str = ""
    tested: int = 0
    elapsed: float = 0.0
    stopped_early: bool = False
    candidates: list[str] = field(default_factory=list)

    @property
    def rate(self) -> float:
        """Candidates tried per second."""
        if self.elapsed <= 0:
            return 0.0
        return self.tested / self.elapsed

    def as_dict(self) -> dict:
        """Return a plain, JSON-serialisable representation."""
        data = asdict(self)
        data["rate"] = round(self.rate, 1)
        return data

    def __str__(self) -> str:  # pragma: no cover - display only
        if self.found:
            return f"recovered {self.plaintext!r} after {self.tested} candidate(s)"
        return f"not recovered after {self.tested} candidate(s)"


def recover(
    value: str,
    candidates,
    kind: str | None = None,
    limit: int | None = None,
    timeout: float | None = None,
) -> CrackResult:
    """Try candidates against a hash until one matches.

    ``kind`` narrows the guess made by :func:`secsuite.hash.identify_hash`
    when several formats share the same shape.  ``limit`` and ``timeout``
    bound the attempt, and the result says whether the bound was reached.
    """
    text = value.strip()
    identified = ""
    if kind is None:
        identifications = identify_hash(text)
        identified = identifications[0].kind if identifications else "unknown"

    result = CrackResult(hash=text, kind=kind or identified)
    started = time.monotonic()
    for candidate in candidates:
        if limit is not None and result.tested >= limit:
            result.stopped_early = True
            break
        if timeout is not None and (time.monotonic() - started) >= timeout:
            result.stopped_early = True
            break
        result.tested += 1
        if verify_hash(text, candidate, kind=kind):
            result.found = True
            result.plaintext = candidate
            break
    result.elapsed = time.monotonic() - started
    return result
