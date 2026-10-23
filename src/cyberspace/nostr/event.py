"""NIP-01 events (spec section 8.2).

An event's identity is the SHA-256 of its canonical serialisation, and its
authenticity is a BIP-340 signature over that id.  The chain rules discard
any event that fails either check, so a reader must be able to make both
judgements itself.

Canonical serialisation is the JSON array
``[0, pubkey, created_at, kind, tags, content]`` with no whitespace.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field

from . import schnorr

__all__ = ["Event", "event_id", "serialize_event"]

_HEX32 = re.compile(r"\A[0-9a-f]{64}\Z")
_HEX64 = re.compile(r"\A[0-9a-f]{128}\Z")


def serialize_event(
    pubkey: str, created_at: int, kind: int, tags: list[list[str]], content: str
) -> bytes:
    """The NIP-01 canonical serialisation of an event."""
    payload = [0, pubkey, created_at, kind, tags, content]
    return json.dumps(
        payload, separators=(",", ":"), ensure_ascii=False, sort_keys=False
    ).encode("utf-8")


def event_id(
    pubkey: str, created_at: int, kind: int, tags: list[list[str]], content: str
) -> str:
    """The canonical event id: SHA-256 of the serialisation, lowercase hex."""
    return hashlib.sha256(
        serialize_event(pubkey, created_at, kind, tags, content)
    ).hexdigest()


@dataclass
class Event:
    """A Nostr event."""

    pubkey: str
    created_at: int
    kind: int
    tags: list[list[str]] = field(default_factory=list)
    content: str = ""
    id: str = ""
    sig: str = ""

    def serialize(self) -> bytes:
        """The canonical serialisation, ignoring the id and signature."""
        return serialize_event(
            self.pubkey, self.created_at, self.kind, self.tags, self.content
        )

    def compute_id(self) -> str:
        """The canonical id of this event."""
        return event_id(
            self.pubkey, self.created_at, self.kind, self.tags, self.content
        )

    def sign(self, secret: int) -> Event:
        """Sign this event in place and return it."""
        self.id = self.compute_id()
        signature = schnorr.sign(bytes.fromhex(self.id), secret)
        self.sig = signature.hex()
        return self

    def verify_id(self) -> bool:
        """Whether the id matches the canonical serialisation.

        An event whose content cannot be serialised, such as one holding a
        lone surrogate, has no canonical serialisation and so no id.
        """
        try:
            computed = self.compute_id()
        except (UnicodeEncodeError, TypeError, ValueError):
            return False
        return self.id == computed

    def verify(self) -> bool:
        """Whether the event is a NIP-01 event that is authentic."""
        if not self.is_wellformed():
            return False
        if not self.verify_id():
            return False
        try:
            return schnorr.verify(
                bytes.fromhex(self.id), bytes.fromhex(self.pubkey), bytes.fromhex(self.sig)
            )
        except ValueError:
            return False

    def is_authentic(self) -> bool:
        """Whether the event is a valid NIP-01 event signed by its pubkey."""
        return self.verify()

    def to_dict(self) -> dict:
        """The event as a plain dict, in NIP-01 field order."""
        return {
            "id": self.id,
            "pubkey": self.pubkey,
            "created_at": self.created_at,
            "kind": self.kind,
            "tags": self.tags,
            "content": self.content,
            "sig": self.sig,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Event:
        """Build an event from a dict, as a relay would deliver it.

        The shape of the event is not judged here.  An event that is not a
        NIP-01 event at all is still built, so that a reader can recognise
        it as such and discard it, rather than stopping on it.
        """
        tags = data.get("tags", [])
        if isinstance(tags, list):
            tags = [list(tag) if isinstance(tag, list) else tag for tag in tags]
        return cls(
            pubkey=data.get("pubkey", ""),
            created_at=data.get("created_at", 0),
            kind=data.get("kind", 0),
            tags=tags,
            content=data.get("content", ""),
            id=data.get("id", ""),
            sig=data.get("sig", ""),
        )

    def is_wellformed(self) -> bool:
        """Whether the event has the shape NIP-01 requires.

        A NIP-01 event carries a 32-byte lowercase hex pubkey, id and
        64-byte lowercase hex signature, an integer kind and created_at, a
        string content and a list of lists of strings as its tags.  An event
        that does not is not a NIP-01 event, whatever its signature says.
        """
        if not isinstance(self.pubkey, str) or not _HEX32.match(self.pubkey):
            return False
        if not isinstance(self.id, str) or not _HEX32.match(self.id):
            return False
        if not isinstance(self.sig, str) or not _HEX64.match(self.sig):
            return False
        if not isinstance(self.kind, int) or isinstance(self.kind, bool):
            return False
        if not isinstance(self.created_at, int) or isinstance(self.created_at, bool):
            return False
        if not isinstance(self.content, str):
            return False
        if not isinstance(self.tags, list):
            return False
        for tag in self.tags:
            if not isinstance(tag, list):
                return False
            for item in tag:
                if not isinstance(item, str):
                    return False
        return True

    def tag_values(self, name: str) -> list[list[str]]:
        """Every tag with the given name, in the order they appear."""
        return [t for t in self.tags if t and t[0] == name]

    def first_tag(self, name: str) -> list[str] | None:
        """The first tag with the given name, or ``None``."""
        found = self.tag_values(name)
        return found[0] if found else None

    def marked_tag(self, name: str, marker: str) -> list[str] | None:
        """The first tag with the given name and fourth-element marker.

        For ``e`` and ``p`` tags the marker is the fourth element, as in
        ``["e", "<id>", "", "previous"]``.
        """
        for tag in self.tags:
            if len(tag) >= 4 and tag[0] == name and tag[3] == marker:
                return tag
        return None

    def action(self) -> str | None:
        """The value of the ``A`` tag, or ``None`` when there is no such tag."""
        tag = self.first_tag("A")
        return tag[1] if tag and len(tag) > 1 else None

    def has_spawn_tag(self) -> bool:
        """Whether any ``A`` tag names ``spawn``."""
        return any(len(t) >= 2 and t[0] == "A" and t[1] == "spawn" for t in self.tags)

    def coordinate(self) -> int | None:
        """The value of the ``C`` tag as a 256-bit coordinate."""
        tag = self.first_tag("C")
        if not tag or len(tag) < 2 or len(tag[1]) != 64:
            return None
        try:
            return int(tag[1], 16)
        except ValueError:
            return None

    def previous_coord(self) -> int | None:
        """The value of the ``c`` tag as a 256-bit coordinate."""
        tag = self.first_tag("c")
        if not tag or len(tag) < 2 or len(tag[1]) != 64:
            return None
        try:
            return int(tag[1], 16)
        except ValueError:
            return None

    def previous_event_id(self) -> bytes | None:
        """The raw bytes of the ``e`` tag marked ``previous``."""
        tag = self.marked_tag("e", "previous")
        if not tag or len(tag) < 2 or len(tag[1]) != 64:
            return None
        try:
            return bytes.fromhex(tag[1])
        except ValueError:
            return None

    def genesis_event_id(self) -> str | None:
        """The id named by the ``e`` tag marked ``genesis``."""
        tag = self.marked_tag("e", "genesis")
        if not tag or len(tag) < 2 or len(tag[1]) != 64:
            return None
        return tag[1]


def new_event(
    secret: int,
    pubkey: str,
    kind: int,
    tags: list[list[str]],
    content: str = "",
    created_at: int | None = None,
) -> Event:
    """Build, sign and return a fresh event."""
    event = Event(
        pubkey=pubkey,
        created_at=created_at if created_at is not None else int(time.time()),
        kind=kind,
        tags=tags,
        content=content,
    )
    return event.sign(secret)
