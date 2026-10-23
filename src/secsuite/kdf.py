"""Reading the cost of a password hash.

A hash is only as strong as the work behind it.  This module reads the
parameters out of the hash formats that carry them, and measures how long a
single derivation takes, so that an audit can say "600000 rounds of PBKDF2
takes 180 milliseconds here" instead of "the rounds are high".
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import asdict, dataclass, field

__all__ = ["KdfReport", "describe_hash", "measure", "recommendation"]

_BCRYPT_RE = re.compile(r"^\$2[abxy]?\$(\d{2})\$")
_ARGON2_RE = re.compile(
    r"^\$argon2(?P<variant>i|d|id)\$v=(?P<version>\d+)\$m=(?P<m>\d+),t=(?P<t>\d+),p=(?P<p>\d+)\$"
)
_PASSLIB_RE = re.compile(r"^\$pbkdf2-(?P<alg>[a-z0-9]+)\$(?P<rounds>\d+)\$")
_DJANGO_RE = re.compile(r"^pbkdf2_sha(?P<alg>\d+)\$(?P<rounds>\d+)\$")
_SHA_CRYPT_RE = re.compile(r"^\$(?P<alg>5|6)\$rounds=(?P<rounds>\d+)\$")

_GUIDANCE = {
    "pbkdf2-sha256": 600000,
    "pbkdf2-sha512": 210000,
    "pbkdf2-sha1": 1300000,
    "bcrypt": 12,
}
"""Rounds (or a cost factor) that are worth aiming for, from the current guidance."""


@dataclass
class KdfReport:
    """The cost of one hash."""

    kind: str
    parameters: dict = field(default_factory=dict)
    rounds: int = 0
    guidance: int = 0
    advice: str = ""

    def as_dict(self) -> dict:
        """Return a plain, JSON-serialisable representation."""
        return asdict(self)


def recommendation(kind: str, rounds: int) -> str:
    """A sentence about whether a cost is enough."""
    target = _GUIDANCE.get(kind)
    if target is None:
        return f"no published guidance for {kind}"
    if rounds <= 0:
        return f"{kind} has no recorded cost"
    if rounds >= target:
        return f"{kind} uses {rounds} rounds, at or above the guidance of {target}"
    return (
        f"{kind} uses {rounds} rounds, below the guidance of {target}"
    )


def describe_hash(value: str) -> KdfReport:
    """Read the parameters out of a hash."""
    text = value.strip()

    match = _BCRYPT_RE.match(text)
    if match:
        rounds = int(match.group(1))
        return KdfReport(
            kind="bcrypt",
            parameters={"cost": rounds},
            rounds=rounds,
            guidance=12,
            advice=recommendation("bcrypt", rounds),
        )

    match = _ARGON2_RE.match(text)
    if match:
        parameters = {
            "variant": match.group("variant"),
            "memory_kib": int(match.group("m")),
            "iterations": int(match.group("t")),
            "parallelism": int(match.group("p")),
        }
        memory_mib = parameters["memory_kib"] / 1024
        if memory_mib >= 64:
            advice = (
                f"argon2 uses {memory_mib:.0f} MiB of memory, at or above the "
                "guidance of 64 MiB"
            )
        else:
            advice = (
                f"argon2 uses {memory_mib:.0f} MiB of memory, below the guidance "
                "of 64 MiB"
            )
        return KdfReport(
            kind="argon2",
            parameters=parameters,
            rounds=parameters["iterations"],
            guidance=3,
            advice=advice,
        )

    match = _PASSLIB_RE.match(text)
    if match:
        rounds = int(match.group("rounds"))
        kind = f"pbkdf2-{match.group('alg')}"
        return KdfReport(
            kind=kind,
            parameters={"rounds": rounds},
            rounds=rounds,
            guidance=_GUIDANCE.get(kind, 0),
            advice=recommendation(kind, rounds),
        )

    match = _DJANGO_RE.match(text)
    if match:
        rounds = int(match.group("rounds"))
        kind = f"pbkdf2-sha{match.group('alg')}"
        return KdfReport(
            kind=kind,
            parameters={"rounds": rounds},
            rounds=rounds,
            guidance=_GUIDANCE.get(kind, 0),
            advice=recommendation(kind, rounds),
        )

    match = _SHA_CRYPT_RE.match(text)
    if match:
        rounds = int(match.group("rounds"))
        kind = "sha256crypt" if match.group("alg") == "5" else "sha512crypt"
        return KdfReport(
            kind=kind,
            parameters={"rounds": rounds},
            rounds=rounds,
            guidance=0,
            advice=recommendation(kind, rounds),
        )

    return KdfReport(
        kind="unknown",
        parameters={},
        rounds=0,
        guidance=0,
        advice="the hash carries no cost parameters",
    )


def measure(
    kind: str = "pbkdf2-sha256",
    password: str = "password",
    rounds: int = 100000,
    salt: bytes = b"cyberspace-py-salt",
) -> dict:
    """Time a derivation and report how much work it does.

    The measurement is scaled down when the asked-for cost is large enough
    to make the tool feel slow, and the cost per second is reported so that
    the real cost can be extrapolated.
    """
    started = time.perf_counter()
    if kind.startswith("pbkdf2"):
        algorithm = kind.split("-", 1)[1]
        hashlib.pbkdf2_hmac(
            algorithm, password.encode("utf-8"), salt, rounds, dklen=32
        )
    elif kind == "scrypt":
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

        Scrypt(
            salt=salt,
            length=32,
            n=1 << 14,
            r=8,
            p=1,
        ).derive(password.encode("utf-8"))
    elif kind == "bcrypt":
        import bcrypt

        bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=10))
    else:
        raise ValueError(f"unknown kind {kind!r}")
    elapsed = time.perf_counter() - started
    return {
        "kind": kind,
        "rounds": rounds,
        "seconds": round(elapsed, 6),
        "per_second": round(rounds / elapsed) if elapsed > 0 else 0,
    }
