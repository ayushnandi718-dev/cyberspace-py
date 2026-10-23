"""Running the protocol's own golden vectors.

The specification locks three sets of numbers that two implementations must
agree on: the chain rules of section 8.12, the GPS mapping of section 9.8
and the visualisation conventions of section 9.7.  A port that agrees with
the spec on these agrees with every other port on where things are.

This module runs them and reports what did not match.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field

from ..chain import resolve_chain
from ..coordinates import xyz_to_coord
from ..gps import gps_to_coord
from ..hyperspace import Line
from ..nostr.event import Event

__all__ = [
    "VectorReport",
    "load_vector_file",
    "run_chain_rules",
    "run_gps_vectors",
    "run_visualization_vectors",
]

GPS_VECTORS = (
    (
        "origin_equator_prime",
        0,
        0,
        "e000000000000000000001200041040208048040000000000000000000000000",
    ),
    (
        "equator_east_90",
        0,
        90,
        "e000000000000000000000480010410082012010000000000000000000000000",
    ),
    (
        "equator_west_90",
        0,
        -90,
        "c492492492492492492492012482082410480490000000000000000000000000",
    ),
    (
        "north_pole",
        90,
        0,
        "e000000000000000000000900004924920020000820000920100824920800020",
    ),
    (
        "london",
        51.5074,
        -0.1278,
        "c492492492492492492492edf5bee7267451c787d95ba4d7840c76d1e33c9940",
    ),
    (
        "nyc",
        40.7128,
        -74.0060,
        "c4924924924924924924921f79235dae293ada913e78294253a235239a332854",
    ),
)
"""The golden vectors of spec section 9.8."""


@dataclass
class VectorReport:
    """What one run of a vector set found."""

    name: str
    total: int = 0
    passed: int = 0
    failures: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Whether every vector matched."""
        return self.total == self.passed

    def __str__(self) -> str:  # pragma: no cover - display only
        mark = "ok  " if self.ok else "FAIL"
        return f"{mark} {self.name}: {self.passed}/{self.total} vectors"


def load_vector_file(path: str | pathlib.Path) -> dict:
    """Read a vector file."""
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def run_chain_rules(path: str | pathlib.Path) -> VectorReport:
    """Run the chain-rule vectors of section 8.12."""
    data = load_vector_file(path)
    report = VectorReport(name="chain-rules")
    line = Line.from_json(data["line"])
    pubkey = data["test_key"]["pubkey"]
    for vector in data["vectors"]:
        report.total += 1
        expected = vector["expected"]
        events = [Event.from_dict(raw) for raw in vector["events"]]
        verdict = resolve_chain(events, pubkey, line)
        problems: list[str] = []
        if verdict.valid != expected["valid"]:
            problems.append(
                f"valid={verdict.valid} expected {expected['valid']}"
            )
        if "reason" in expected and verdict.reason != expected["reason"]:
            problems.append(
                f"reason={verdict.reason!r} expected {expected['reason']!r}"
            )
        if "invalid_at" in expected and verdict.invalid_at != expected["invalid_at"]:
            problems.append(
                f"invalid_at={verdict.invalid_at!r} expected {expected['invalid_at']!r}"
            )
        if "invalid_index" in expected and verdict.invalid_index != expected[
            "invalid_index"
        ]:
            problems.append(
                f"invalid_index={verdict.invalid_index} "
                f"expected {expected['invalid_index']}"
            )
        if "chain" in expected and verdict.chain != expected["chain"]:
            problems.append("chain differs")
        if "position" in expected:
            position = (
                None if verdict.position is None else f"{verdict.position:064x}"
            )
            if position != expected["position"]:
                problems.append(
                    f"position={position!r} expected {expected['position']!r}"
                )
        if problems:
            report.failures.append(f"{vector['name']}: {'; '.join(problems)}")
        else:
            report.passed += 1
    return report


def run_gps_vectors() -> VectorReport:
    """Run the GPS golden vectors of section 9.8."""
    report = VectorReport(name="gps")
    for name, latitude, longitude, expected in GPS_VECTORS:
        report.total += 1
        actual = f"{gps_to_coord(latitude, longitude):064x}"
        if actual == expected:
            report.passed += 1
        else:
            report.failures.append(
                f"{name}: got {actual} expected {expected}"
            )
    return report


def run_visualization_vectors(path: str | pathlib.Path) -> VectorReport:
    """Run the visualisation vectors of section 9.7."""
    data = load_vector_file(path)
    report = VectorReport(name="visualization")
    units_per_km = int(data["scale"]["units_per_km"])
    center = 1 << 84
    for vector in data["vectors"]:
        report.total += 1
        problems: list[str] = []
        x = int(vector["x_u85"])
        y = int(vector["y_u85"])
        z = int(vector["z_u85"])
        plane = int(vector["plane"])
        coord = f"{xyz_to_coord(x, y, z, plane):064x}"
        if coord != vector["coord_hex"]:
            problems.append(f"coord {coord} expected {vector['coord_hex']}")
        for axis, value in (("x", x), ("y", y), ("z", z)):
            km = (value - center) / units_per_km
            expected_km = vector.get(f"{axis}_km_from_center")
            if expected_km is None:
                continue
            if abs(km - expected_km) > 1e-6:
                problems.append(
                    f"{axis} km {km} expected {expected_km}"
                )
        if problems:
            report.failures.append(f"{vector['name']}: {'; '.join(problems)}")
        else:
            report.passed += 1
    return report
