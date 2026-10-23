"""Auditing a chain from the outside.

A reader of cyberspace sees a pile of events from a relay.  The chain rules
say which of them form an identity's chain and where that chain stands.
This module applies those rules to a pile of events and reports what it
found, including the parts a client would rather not show: the events that
were discarded, and the events that would have forked the chain.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field

from ..chain import ChainVerdict, resolve_chain
from ..hyperspace import Line
from ..nostr.event import Event

__all__ = [
    "AuditReport",
    "audit",
    "find_forks",
    "format_report",
    "load_events",
]


@dataclass
class AuditReport:
    """What an audit of one identity's events found."""

    pubkey: str
    verdict: ChainVerdict
    authentic: list[Event] = field(default_factory=list)
    forged: list[Event] = field(default_factory=list)
    foreign: list[Event] = field(default_factory=list)
    forks: list[tuple[str, list[str]]] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        """Whether the chain is valid."""
        return self.verdict.valid

    @property
    def position_hex(self) -> str | None:
        """The coordinate the chain stands at, in hex."""
        if self.verdict.position is None:
            return None
        return f"{self.verdict.position:064x}"


def load_events(path: str | pathlib.Path) -> list[Event]:
    """Load events from a JSON file.

    The file may hold a list of event objects, or an object with an
    ``events`` list, which is what the upstream fixtures use.
    """
    data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        raw = data.get("events", [])
    else:
        raw = data
    return [Event.from_dict(entry) for entry in raw]


def find_forks(events: list[Event]) -> list[tuple[str, list[str]]]:
    """Find the points where two events name the same previous event.

    A fork is fatal: the chain is invalid from the spawn, whatever the
    forking events are.  Reporting the pairs is how an operator finds the
    identity that signed both, or the relay that served a copy.
    """
    by_previous: dict[str, list[str]] = {}
    for event in events:
        tag = event.marked_tag("e", "previous")
        if tag is None or len(tag) < 2:
            continue
        by_previous.setdefault(tag[1], []).append(event.id)
    return [
        (previous, sorted(ids))
        for previous, ids in sorted(by_previous.items())
        if len(ids) > 1
    ]


def audit(
    events: list[Event], pubkey: str, line: Line | None = None
) -> AuditReport:
    """Audit one identity's events and report the verdict and the discards."""
    authentic: list[Event] = []
    forged: list[Event] = []
    foreign: list[Event] = []
    for event in events:
        if event.pubkey != pubkey:
            foreign.append(event)
            continue
        if event.kind != 3333:
            continue
        if event.verify():
            authentic.append(event)
        else:
            forged.append(event)

    verdict = resolve_chain(events, pubkey, line)
    return AuditReport(
        pubkey=pubkey,
        verdict=verdict,
        authentic=authentic,
        forged=forged,
        foreign=foreign,
        forks=find_forks(events),
    )


def format_report(report: AuditReport) -> str:
    """Render an audit report as text."""
    verdict = report.verdict
    lines = [
        f"pubkey    {report.pubkey}",
        f"valid     {str(verdict.valid).lower()}",
    ]
    if verdict.reason:
        lines.append(f"reason    {verdict.reason}")
    if verdict.invalid_at:
        lines.append(f"invalid   {verdict.invalid_at} (index {verdict.invalid_index})")
    lines.append(f"chain     {len(verdict.chain)} event(s)")
    for index, event_id in enumerate(verdict.chain):
        lines.append(f"  [{index}] {event_id}")
    lines.append(f"position  {report.position_hex or 'none'}")
    if verdict.head:
        lines.append(f"head      {verdict.head}")
    if verdict.open_bracket:
        lines.append(f"bracket   {verdict.open_bracket}")
    if verdict.skipped:
        lines.append(f"skipped   {len(verdict.skipped)} event(s)")
        for event_id in verdict.skipped:
            lines.append(f"  {event_id}")
    lines.append(f"authentic {len(report.authentic)} event(s)")
    lines.append(f"forged    {len(report.forged)} event(s)")
    for event in report.forged:
        lines.append(f"  {event.id} created_at={event.created_at}")
    if report.forks:
        lines.append(f"forks     {len(report.forks)} point(s)")
        for previous, ids in report.forks:
            lines.append(f"  {previous}")
            for event_id in ids:
                lines.append(f"    {event_id}")
    return "\n".join(lines)
