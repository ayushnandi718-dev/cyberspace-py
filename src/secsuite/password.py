"""Password strength analysis.

The number of bits a password is worth is not the length times the size of
its alphabet: a password made of a dictionary word and a year is far weaker
than that formula suggests.  This module estimates the entropy of a password
and says why the estimate came out where it did, so that an audit can point
at the weakness rather than at the number.
"""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import asdict, dataclass, field

__all__ = [
    "COMMON_PASSWORDS",
    "PasswordReport",
    "analyse",
    "estimate_entropy",
    "verdict_for",
]

COMMON_PASSWORDS: tuple[str, ...] = (
    "123456",
    "123456789",
    "12345678",
    "12345",
    "qwerty",
    "qwerty123",
    "password",
    "password1",
    "123123",
    "111111",
    "1234567890",
    "letmein",
    "admin",
    "welcome",
    "monkey",
    "dragon",
    "iloveyou",
    "abc123",
    "football",
    "baseball",
    "master",
    "sunshine",
    "princess",
    "login",
    "passw0rd",
    "starwars",
    "trustno1",
    "whatever",
    "zaq12wsx",
    "changeme",
    "secret",
)
"""The passwords that open the most accounts, used to catch the worst cases."""

_COMMON_WORDS: tuple[str, ...] = (
    "admin",
    "alice",
    "android",
    "awesome",
    "batman",
    "charlie",
    "company",
    "computer",
    "dragon",
    "flower",
    "football",
    "freedom",
    "hello",
    "iloveyou",
    "letmein",
    "love",
    "michael",
    "monkey",
    "mustang",
    "nicole",
    "password",
    "princess",
    "qwerty",
    "shadow",
    "summer",
    "sunshine",
    "superman",
    "trustno1",
    "welcome",
    "winter",
)

_LOWERCASE = set("abcdefghijklmnopqrstuvwxyz")
_UPPERCASE = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
_DIGITS = set("0123456789")
_SYMBOLS = set("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ")

_SEQUENCE_RE = re.compile(
    r"(0123|1234|2345|3456|4567|5678|6789|89ab|9abc|abcd|bcde|cdef|defg|"
    r"efgh|fghi|ghij|hijk|ijkl|jklm|klmn|lmno|mnop|nopq|opqr|pqrs|qrst|"
    r"rstu|stuv|tuvw|uvwx|vwxy|wxyz|abcd|aaaa|qqqq)",
    re.IGNORECASE,
)
_REPEATED_RE = re.compile(r"(.)\1{2,}")
_YEAR_RE = re.compile(r"(19|20)\d{2}")
_KEYBOARD_RE = re.compile(
    r"(qwerty|asdfgh|zxcvbn|1qaz2wsx|qazwsx|!@#$%^|qwertyuiop)",
    re.IGNORECASE,
)

_ENTROPY_FLOOR = 28.0
_ENTROPY_CEILINGS = (
    (20.0, "very weak"),
    (36.0, "weak"),
    (60.0, "fair"),
    (80.0, "strong"),
    (float("inf"), "very strong"),
)
"""The bands an entropy estimate falls into, from the weakest upwards."""


@dataclass
class PasswordReport:
    """What an audit found about one password."""

    length: int
    classes: list[str] = field(default_factory=list)
    entropy: float = 0.0
    verdict: str = ""
    weaknesses: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        """Return a plain, JSON-serialisable representation."""
        return asdict(self)


def _charset_size(classes: list[str]) -> int:
    """The size of the alphabet a password draws from."""
    size = 0
    if "lower" in classes:
        size += 26
    if "upper" in classes:
        size += 26
    if "digit" in classes:
        size += 10
    if "symbol" in classes:
        size += len(_SYMBOLS)
    if "non-ascii" in classes:
        size += 100
    return size or 1


def _classes_of(password: str) -> list[str]:
    """The character classes a password uses."""
    classes: list[str] = []
    if any(character in _LOWERCASE for character in password):
        classes.append("lower")
    if any(character in _UPPERCASE for character in password):
        classes.append("upper")
    if any(character in _DIGITS for character in password):
        classes.append("digit")
    if any(character in _SYMBOLS for character in password):
        classes.append("symbol")
    if any(ord(character) > 127 for character in password):
        classes.append("non-ascii")
    return classes


def _dictionary_words(password: str) -> list[str]:
    """The dictionary words a password contains."""
    lowered = password.lower()
    found: list[str] = []
    for word in _COMMON_WORDS:
        if word in lowered:
            found.append(word)
    return found


def estimate_entropy(password: str) -> float:
    """Estimate the number of bits a password is worth.

    The estimate starts from the length and the alphabet, then takes away for
    the things that make a password predictable.
    """
    if not password:
        return 0.0
    classes = _classes_of(password)
    pool = _charset_size(classes)
    entropy = len(password) * math.log2(pool)

    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        entropy = min(entropy, 4.0)

    for word in _dictionary_words(password):
        entropy -= 8.0 * len(word) - math.log2(pool) * len(word)

    if _REPEATED_RE.search(password):
        entropy -= 4.0
    if _SEQUENCE_RE.search(password):
        entropy -= 4.0
    if _KEYBOARD_RE.search(password):
        entropy -= 6.0
    if _YEAR_RE.search(password):
        entropy -= 6.0
    if len(set(password)) <= max(2, len(password) // 4):
        entropy -= 8.0

    return max(0.0, entropy)


def verdict_for(entropy: float) -> str:
    """The verdict that goes with an entropy estimate."""
    for ceiling, label in _ENTROPY_CEILINGS:
        if entropy < ceiling:
            return label
    return "very strong"


def analyse(password: str) -> PasswordReport:
    """Analyse a password and report its strength and its weaknesses."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    classes = _classes_of(password)
    entropy = estimate_entropy(password)
    lowered = password.lower()

    weaknesses: list[str] = []
    suggestions: list[str] = []

    if not password:
        weaknesses.append("the password is empty")
    if len(password) < 8:
        weaknesses.append("the password is shorter than 8 characters")
        suggestions.append("use at least 12 characters")
    if lowered in COMMON_PASSWORDS:
        weaknesses.append("the password is one of the most common passwords in the world")
        suggestions.append("replace it with a passphrase that is not in any wordlist")
    words = _dictionary_words(password)
    if words and lowered not in COMMON_PASSWORDS:
        weaknesses.append(
            "the password contains the dictionary word " + ", ".join(repr(word) for word in words)
        )
        suggestions.append("avoid dictionary words inside the password")
    if _REPEATED_RE.search(password):
        weaknesses.append("the password repeats a character three or more times")
    if _SEQUENCE_RE.search(password):
        weaknesses.append("the password contains a run of consecutive characters")
    if _KEYBOARD_RE.search(password):
        weaknesses.append("the password follows a keyboard pattern")
    if _YEAR_RE.search(password):
        weaknesses.append("the password contains a year")
    if len(set(password)) <= max(2, len(password) // 4):
        weaknesses.append("the password uses very few distinct characters")
    if len(classes) == 1 and password:
        weaknesses.append("the password uses only one character class")
        suggestions.append("mix character classes, or use a longer passphrase")

    return PasswordReport(
        length=len(password),
        classes=classes,
        entropy=round(entropy, 1),
        verdict=verdict_for(entropy),
        weaknesses=weaknesses,
        suggestions=suggestions,
    )


def normalise(password: str) -> str:
    """Fold a password for dictionary lookups: case, accents and spacing."""
    folded = unicodedata.normalize("NFKD", password)
    return "".join(
        character for character in folded if not unicodedata.combining(character)
    ).lower()
