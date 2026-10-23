"""Building the candidate lists an audit uses.

When a service account has a password that nobody chose well, the words that
make up the candidates come from the service itself: the host name, the
account name, the words of the banner, and the year it was set up.  This
module turns such material into a candidate list and applies the mutations
that password reuse actually shows.
"""

from __future__ import annotations

import itertools
import pathlib
import re
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass

__all__ = [
    "RULES",
    "Rule",
    "apply_rule",
    "dedupe",
    "generate",
    "per_target_words",
    "read_wordlist",
    "write_wordlist",
]

_YEARS = tuple(str(year) for year in range(2015, 2026))
_LEET = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}


@dataclass
class Rule:
    """One mutation applied to a base word."""

    name: str
    description: str
    suffixes: tuple[str, ...] = ()
    prefixes: tuple[str, ...] = ()
    transform: str = ""

    def as_dict(self) -> dict:
        """Return a plain, JSON-serialisable representation."""
        return asdict(self)


RULES: tuple[Rule, ...] = (
    Rule(name="lower", description="the word as it stands, in lower case"),
    Rule(name="capitalise", description="the word with its first letter raised"),
    Rule(name="upper", description="the word in upper case"),
    Rule(name="leet", description="common letters replaced by lookalike digits"),
    Rule(name="append-digit", description="the word with a single digit appended"),
    Rule(name="append-symbol", description="the word with a single symbol appended"),
    Rule(name="append-year", description="the word with a year appended", suffixes=_YEARS),
    Rule(
        name="append-suffix",
        description="the word with a common suffix",
        suffixes=("!", "1", "123", "2024", "@"),
    ),
    Rule(name="prepend", description="the word with a prefix", prefixes=("!", "@")),
    Rule(name="double", description="the word repeated"),
)
"""The mutations a candidate list is built from."""


def _capitalise(word: str) -> str:
    return word[:1].upper() + word[1:]


def _leet(word: str) -> str:
    return "".join(_LEET.get(character, character) for character in word)


def apply_rule(word: str, rule: Rule) -> list[str]:
    """Apply one mutation to a word and return the results."""
    if rule.name == "lower":
        return [word.lower()]
    if rule.name == "capitalise":
        return [_capitalise(word.lower())]
    if rule.name == "upper":
        return [word.upper()]
    if rule.name == "leet":
        return [_leet(word.lower())]
    if rule.name == "append-digit":
        return [f"{word}{digit}" for digit in "0123456789"]
    if rule.name == "append-symbol":
        return [f"{word}{symbol}" for symbol in "!@#$%&*"]
    if rule.name == "append-year":
        return [f"{word}{year}" for year in rule.suffixes]
    if rule.name == "append-suffix":
        return [f"{word}{suffix}" for suffix in rule.suffixes]
    if rule.name == "prepend":
        return [f"{prefix}{word}" for prefix in rule.prefixes]
    if rule.name == "double":
        return [word * 2]
    raise ValueError(f"unknown rule {rule.name!r}")


def rule_by_name(name: str) -> Rule:
    """Look a rule up by name."""
    for rule in RULES:
        if rule.name == name:
            return rule
    raise KeyError(name)


def generate(
    base_words: Iterable[str],
    rules: Iterable[Rule] | None = None,
) -> Iterator[str]:
    """Build a candidate list from base words and mutations.

    The base words are yielded first, because the weakest password in an
    audit is very often the plain word itself.
    """
    selected = tuple(rules) if rules is not None else RULES
    seen: set[str] = set()
    for word in base_words:
        cleaned = word.strip()
        if not cleaned:
            continue
        if cleaned not in seen:
            seen.add(cleaned)
            yield cleaned
        for rule in selected:
            for candidate in apply_rule(cleaned, rule):
                if candidate and candidate not in seen:
                    seen.add(candidate)
                    yield candidate


def dedupe(words: Iterable[str]) -> list[str]:
    """Remove duplicates while keeping the order."""
    seen: set[str] = set()
    result: list[str] = []
    for word in words:
        if word not in seen:
            seen.add(word)
            result.append(word)
    return result


def per_target_words(host: str, usernames: Iterable[str] = ()) -> list[str]:
    """The words a target's own name suggests."""
    words: list[str] = []
    for part in re.split(r"[^A-Za-z0-9]+", host):
        if part:
            words.append(part)
            words.append(part.lower())
    words.append(host)
    words.append(host.lower())
    for username in usernames:
        words.append(username)
        words.append(username.lower())
    return dedupe(words)


def read_wordlist(path: str | pathlib.Path) -> list[str]:
    """Read a wordlist, one candidate per line."""
    text = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    return dedupe(line.strip() for line in text.splitlines() if line.strip())


def write_wordlist(path: str | pathlib.Path, words: Iterable[str]) -> int:
    """Write a wordlist, one candidate per line.  Returns the number of lines."""
    unique = dedupe(words)
    pathlib.Path(path).write_text(
        "\n".join(unique) + ("\n" if unique else ""), encoding="utf-8"
    )
    return len(unique)


def combinatorial(
    words: Iterable[str], separators: Iterable[str] = ("", "-", "_")
) -> Iterator[str]:
    """Join pairs of words with a separator."""
    for first, second in itertools.product(words, repeat=2):
        if first == second:
            continue
        for separator in separators:
            yield f"{first}{separator}{second}"
