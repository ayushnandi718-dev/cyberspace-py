"""Hash identification and verification.

When an audit turns up a string of hex or a modular crypt format, the first
question is what it is.  This module answers that question from the shape of
the string, and then offers the small set of tools needed to confirm the
answer: hash a candidate and compare, or verify a candidate against a hash
that uses a format with its own verification step.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import asdict, dataclass, field

__all__ = [
    "BackendMissing",
    "HASH_ALGORITHMS",
    "HashIdentification",
    "HashResult",
    "identify_hash",
    "hash_bytes",
    "hash_text",
    "is_supported_hash",
    "verify_hash",
]

class BackendMissing(RuntimeError):
    """A hash format needs an optional dependency that is not installed.

    A verifier that silently returns "no match" when its backend is absent
    would make a missing package look like a wrong password, so verification
    raises this instead.
    """


HASH_ALGORITHMS: tuple[str, ...] = (
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3_256",
    "sha3_512",
    "blake2b",
    "blake2s",
)
"""The plain hash functions this module can compute."""


@dataclass
class HashResult:
    """A computed hash."""

    algorithm: str
    hex: str
    length: int

    def as_dict(self) -> dict:
        """Return a plain, JSON-serialisable representation."""
        return asdict(self)


@dataclass
class HashIdentification:
    """A guess at what a hash is."""

    kind: str
    confidence: str
    detail: str = ""
    candidates: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        """Return a plain, JSON-serialisable representation."""
        return asdict(self)


_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BCRYPT_RE = re.compile(r"^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$")
_ARGON2_RE = re.compile(r"^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$")
_PBKDF2_PASSLIB_RE = re.compile(r"^\$pbkdf2-(?P<alg>[a-z0-9]+)\$(?P<rounds>\d+)\$")
_SHA_CRYPT_RE = re.compile(r"^\$[56]\$rounds=\d+\$")
_PHPSS_RE = re.compile(r"^\$[PH]\$")
_DJANGO_RE = re.compile(r"^pbkdf2_sha(?P<alg>\d+)\$(?P<rounds>\d+)\$")
_MYSQL_RE = re.compile(r"^\*[0-9A-F]{40}$")
_NTLM_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_BCRYPT_ROUNDS_RE = re.compile(r"^\$2[abxy]?\$(\d{2})\$")

_DIGEST_LENGTHS = {name: hashlib.new(name).digest_size for name in HASH_ALGORITHMS}
"""The digest size of every plain hash function this module can compute."""

_PLAIN_KINDS = {
    "md5": ("md5",),
    "sha1": ("sha1",),
    "sha224": ("sha224",),
    "sha256": ("sha256",),
    "sha384": ("sha384",),
    "sha512": ("sha512",),
    "sha3_256": ("sha3_256",),
    "sha3_512": ("sha3_512",),
    "blake2b": ("blake2b",),
    "blake2s": ("blake2s",),
}
"""The plain hash functions each identified kind stands for."""


def hash_bytes(data: bytes, algorithm: str = "sha256") -> HashResult:
    """Hash bytes with one of the supported algorithms."""
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError(
            f"unsupported algorithm {algorithm!r}; "
            f"choose one of {', '.join(HASH_ALGORITHMS)}"
        )
    digest = hashlib.new(algorithm, data).digest()
    return HashResult(
        algorithm=algorithm, hex=digest.hex(), length=len(digest)
    )


def hash_text(text: str, algorithm: str = "sha256") -> HashResult:
    """Hash a string with one of the supported algorithms."""
    return hash_bytes(text.encode("utf-8"), algorithm)


def is_supported_hash(value: str) -> bool:
    """True when the value looks like a hash this module can check."""
    return any(identification.kind != "unknown" for identification in identify_hash(value))


def identify_hash(value: str) -> list[HashIdentification]:
    """Guess what a hash is from its shape.

    Several kinds share a shape, so the result is a list, most likely first.
    A 32 character hex string is both an MD5 digest and an NTLM hash, and
    only the context of the audit can say which one it is.
    """
    if not isinstance(value, str):
        raise TypeError("hash must be a string")
    text = value.strip()
    if not text:
        return [HashIdentification(kind="unknown", confidence="none", detail="empty value")]

    results: list[HashIdentification] = []

    if _BCRYPT_RE.match(text):
        rounds = _BCRYPT_ROUNDS_RE.match(text)
        cost = rounds.group(1) if rounds else "?"
        results.append(
            HashIdentification(
                kind="bcrypt",
                confidence="high",
                detail=f"modular crypt format with a cost factor of {cost}",
            )
        )
    if _ARGON2_RE.match(text):
        results.append(
            HashIdentification(
                kind="argon2",
                confidence="high",
                detail="argon2 password hash",
            )
        )
    if _PBKDF2_PASSLIB_RE.match(text):
        match = _PBKDF2_PASSLIB_RE.match(text)
        results.append(
            HashIdentification(
                kind="pbkdf2",
                confidence="high",
                detail=(
                    f"passlib pbkdf2-{match.group('alg')} with "
                    f"{match.group('rounds')} rounds"
                    if match
                    else "passlib pbkdf2"
                ),
            )
        )
    if _SHA_CRYPT_RE.match(text):
        results.append(
            HashIdentification(
                kind="sha-crypt",
                confidence="high",
                detail="sha256crypt or sha512crypt",
            )
        )
    if _PHPSS_RE.match(text):
        results.append(
            HashIdentification(
                kind="phpass",
                confidence="medium",
                detail="phpass portable hash",
            )
        )
    if _DJANGO_RE.match(text):
        match = _DJANGO_RE.match(text)
        results.append(
            HashIdentification(
                kind="django",
                confidence="high",
                detail=(
                    f"django pbkdf2 with {match.group('rounds')} rounds"
                    if match
                    else "django pbkdf2"
                ),
            )
        )
    if _MYSQL_RE.match(text):
        results.append(
            HashIdentification(
                kind="mysql",
                confidence="high",
                detail="mysql user table hash",
            )
        )

    if _HEX_RE.match(text):
        length = len(text)
        lengths = {
            32: ("md5", "ntlm"),
            40: ("sha1",),
            64: ("sha256", "sha3_256", "blake2s"),
            96: ("sha384",),
            128: ("sha512", "sha3_512", "blake2b"),
        }
        kinds = lengths.get(length)
        if kinds:
            confidence = "low" if len(kinds) > 1 else "medium"
            results.append(
                HashIdentification(
                    kind=kinds[0],
                    confidence=confidence,
                    detail=f"{length} hex characters",
                    candidates=list(kinds),
                )
            )
            if "ntlm" in kinds:
                results.append(
                    HashIdentification(
                        kind="ntlm",
                        confidence="low",
                        detail="16 byte hex digest, as stored in an nt hash",
                    )
                )
        else:
            results.append(
                HashIdentification(
                    kind="unknown",
                    confidence="none",
                    detail=f"{length} hex characters, which matches no known digest size",
                )
            )
    elif not any(r.kind != "unknown" for r in results):
        results.append(
            HashIdentification(
                kind="unknown",
                confidence="none",
                detail="does not match any known hash format",
            )
        )

    return results


def _bcrypt_verify(value: str, password: str) -> bool | None:
    """Check a password against a bcrypt hash, when bcrypt is installed."""
    try:
        import bcrypt
    except ImportError:  # pragma: no cover - depends on the environment
        return None
    try:
        return bcrypt.checkpw(password.encode("utf-8"), value.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def _passlib_verify(value: str, password: str) -> bool | None:
    """Check a password against a passlib hash, when passlib is installed."""
    try:
        from passlib.hash import django_pbkdf2, pbkdf2_sha256
    except ImportError:  # pragma: no cover - depends on the environment
        return None
    for scheme in (pbkdf2_sha256, django_pbkdf2):
        try:
            if scheme.verify(password, value):
                return True
        except (ValueError, TypeError):
            continue
    return False


def _argon2_verify(value: str, password: str) -> bool | None:
    """Check a password against an argon2 hash, when argon2-cffi is installed."""
    try:
        from argon2 import PasswordHasher
        from argon2.exceptions import VerifyMismatchError
    except ImportError:  # pragma: no cover - depends on the environment
        return None
    try:
        return bool(PasswordHasher().verify(value, password))
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def _ntlm_verify(value: str, password: str) -> bool:
    """Check a password against an NTLM hash: MD4 over UTF-16LE."""
    from .md4 import ntlm_hash

    if not _NTLM_RE.match(value):
        return False
    return hmac.compare_digest(ntlm_hash(password).lower(), value.lower())


def _require(result: bool | None, kind: str) -> bool:
    """Turn a verifier's "backend unavailable" into a clear error."""
    if result is None:
        raise BackendMissing(
            f"{kind} verification needs an optional dependency that is not "
            "installed; install the hashing extra (or argon2-cffi)"
        )
    return result


def verify_hash(value: str, password: str, kind: str | None = None) -> bool:
    """Check a password against a hash.

    Hashes with their own verification step (bcrypt, argon2, the passlib
    formats) are checked with that step.  Plain digests are checked against
    every algorithm whose length matches, so that a 64 character hex string
    is tried as sha256, sha3-256 and blake2s.

    ``kind`` narrows the guess to one format, which is what an audit wants
    when the context already says what the hash is: ``"ntlm"`` checks the
    NTLM hash and nothing else.

    Raises :class:`BackendMissing` when the format needs an optional package
    that is not installed, so that an unavailable verifier can never be
    mistaken for a wrong password.
    """
    text = value.strip()
    if kind is None:
        candidates: list[str] = []
        for identification in identify_hash(text):
            if identification.candidates:
                candidates.extend(identification.candidates)
            else:
                candidates.append(identification.kind)
        candidates = list(dict.fromkeys(candidates))
    else:
        candidates = [kind.strip().lower()]

    for candidate in candidates:
        if candidate == "bcrypt":
            if _require(_bcrypt_verify(text, password), "bcrypt"):
                return True
        elif candidate in ("pbkdf2", "django"):
            if _require(_passlib_verify(text, password), "passlib"):
                return True
        elif candidate == "argon2":
            if _require(_argon2_verify(text, password), "argon2"):
                return True
        elif candidate == "ntlm":
            if _ntlm_verify(text, password):
                return True
        elif candidate in _PLAIN_KINDS:
            for algorithm in _PLAIN_KINDS[candidate]:
                if len(text) != _DIGEST_LENGTHS[algorithm] * 2:
                    continue
                if not _HEX_RE.match(text):
                    continue
                computed = hash_text(password, algorithm).hex
                if hmac.compare_digest(computed.lower(), text.lower()):
                    return True
    return False
