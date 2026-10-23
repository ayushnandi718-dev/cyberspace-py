"""Where the specification's own vector files are looked for.

The vectors are the normative numbers of the protocol: the chain rules of
section 8.12, the visualisation conventions of section 9.7 and the GPS
mapping of section 9.8.  They are kept in ``tests/fixtures`` so that the
suite runs anywhere, and an environment variable may point the suite at
another copy.
"""

from __future__ import annotations

import os
import pathlib

__all__ = ["FIXTURE_DIR", "chain_rules_path", "visualization_path"]

FIXTURE_DIR = pathlib.Path(__file__).resolve().parent / "fixtures"

_ENVIRONMENT = "CYBERSPACE_FIXTURES"


def _candidate_paths(name: str) -> list[pathlib.Path]:
    """Every place a vector file may live, most preferred first."""
    paths: list[pathlib.Path] = []
    override = os.environ.get(_ENVIRONMENT)
    if override:
        directory = pathlib.Path(override)
        paths.append(directory / name)
        paths.append(directory / "chain-rules-2026-09-28-virtual-brackets.json")
    paths.append(FIXTURE_DIR / name)
    return paths


def _find(name: str) -> pathlib.Path | None:
    """The first copy of a vector file that exists."""
    for path in _candidate_paths(name):
        if path.exists():
            return path
    return None


def chain_rules_path() -> pathlib.Path | None:
    """The path of the chain-rule vectors, when they are available."""
    return _find("chain-rules-2026-09-28-virtual-brackets.json")


def visualization_path() -> pathlib.Path | None:
    """The path of the visualisation vectors, when they are available."""
    return _find("visualization_vectors.json")
