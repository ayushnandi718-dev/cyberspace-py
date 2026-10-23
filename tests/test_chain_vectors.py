"""Run the spec's chain-rules golden vectors against this implementation.

The fixture at ``chain-rules-2026-09-28-virtual-brackets.json`` is normative:
a conforming verifier MUST reach every vector's verdict, its position and,
for an invalid vector, its ``invalid_at``.
"""

from __future__ import annotations

import json

import pytest
from fixture_paths import chain_rules_path

from cyberspace.chain import resolve_chain
from cyberspace.hyperspace import Line
from cyberspace.nostr.event import Event

FIXTURE = chain_rules_path()

if FIXTURE is None:  # pragma: no cover - fixture is external
    pytest.skip("the chain-rules fixture is not available", allow_module_level=True)

DATA = json.loads(FIXTURE.read_text(encoding="utf-8"))
VECTORS = DATA["vectors"]
PUBKEY = DATA["test_key"]["pubkey"]
LINE = Line.from_json(DATA["line"])


def _events(vector: dict) -> list[Event]:
    return [Event.from_dict(raw) for raw in vector["events"]]


def _check(vector: dict) -> None:
    expected = vector["expected"]
    verdict = resolve_chain(_events(vector), PUBKEY, LINE)

    assert verdict.valid == expected["valid"], (
        f"{vector['name']}: valid {verdict.valid} != {expected['valid']} "
        f"(reason {verdict.reason!r})"
    )
    assert verdict.chain == expected["chain"], f"{vector['name']}: chain mismatch"
    assert verdict.position_hex == expected["position"], (
        f"{vector['name']}: position {verdict.position_hex} != {expected['position']}"
    )
    if expected["valid"]:
        assert verdict.head == expected["head"], f"{vector['name']}: head mismatch"
        assert verdict.open_bracket == expected["open_bracket"], (
            f"{vector['name']}: open_bracket mismatch"
        )
        assert verdict.skipped == expected["skipped"], (
            f"{vector['name']}: skipped mismatch"
        )
    else:
        assert verdict.reason == expected["reason"], (
            f"{vector['name']}: reason {verdict.reason!r} != {expected['reason']!r}"
        )
        assert verdict.invalid_at == expected["invalid_at"], (
            f"{vector['name']}: invalid_at mismatch"
        )
        assert verdict.invalid_index == expected["invalid_index"], (
            f"{vector['name']}: invalid_index mismatch"
        )


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_chain_vector(vector: dict) -> None:
    _check(vector)
