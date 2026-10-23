"""The ``cs`` command line tool.

A thin front end over the library: it audits chains, runs the protocol's
golden vectors, prices a movement before it is paid for, and probes a
position for what a reader could open there.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from .coordinates import Coordinate, coord_to_hex, coord_to_xyz, hex_to_coord
from .gps import gps_to_coord
from .redteam.audit import audit, format_report, load_events
from .redteam.forgery import run_forgery_cases
from .redteam.probe import movement_cost, probe
from .redteam.vectors import (
    run_chain_rules,
    run_gps_vectors,
    run_visualization_vectors,
)

__all__ = ["main"]


def _coordinate(text: str) -> Coordinate:
    """Read a coordinate from 64 hex characters."""
    return Coordinate(*coord_to_xyz(hex_to_coord(text)))


def _cmd_audit(args: argparse.Namespace) -> int:
    events = load_events(args.events)
    line = None
    if args.line:
        line_data = json.loads(pathlib.Path(args.line).read_text(encoding="utf-8"))
        from .hyperspace import Line

        line = Line.from_json(line_data)
    report = audit(events, args.pubkey, line)
    print(format_report(report))
    return 0 if report.valid else 1


def _cmd_vectors(args: argparse.Namespace) -> int:
    reports = []
    if args.fixture_dir:
        directory = pathlib.Path(args.fixture_dir)
        chain_file = directory / "chain-rules-2026-09-28-virtual-brackets.json"
        if chain_file.exists():
            reports.append(run_chain_rules(chain_file))
        viz_file = directory / "visualization_vectors.json"
        if viz_file.exists():
            reports.append(run_visualization_vectors(viz_file))
    reports.append(run_gps_vectors())
    failed = 0
    for report in reports:
        print(report)
        for failure in report.failures:
            print(f"  {failure}")
        if not report.ok:
            failed += 1
    return 1 if failed else 0


def _cmd_forgery(args: argparse.Namespace) -> int:
    failed = 0
    for result in run_forgery_cases():
        print(result)
        if not result.passed:
            failed += 1
    print(f"{failed} case(s) failed")
    return 1 if failed else 0


def _cmd_probe(args: argparse.Namespace) -> int:
    coordinate = _coordinate(args.coordinate)
    result = probe(coordinate, args.min_height, args.max_height)
    print(f"coordinate  {coord_to_hex(coordinate.coord)}")
    print(f"plane       {coordinate.plane_name}")
    print(f"axes        x={coordinate.x} y={coordinate.y} z={coordinate.z}")
    print(f"sectors     {result.sectors['S']}")
    for height, key, lookup in result.region_keys:
        print(f"region h{height:<3} key={key.hex()} lookup={lookup.hex()}")
    if result.skipped_heights:
        print(
            "not computed at heights "
            + ", ".join(str(height) for height in result.skipped_heights)
        )
    return 0


def _cmd_price(args: argparse.Namespace) -> int:
    source = _coordinate(args.source)
    destination = _coordinate(args.destination)
    cost = movement_cost(source, destination)
    print(f"from       {coord_to_hex(source.coord)}")
    print(f"to         {coord_to_hex(destination.coord)}")
    print(cost.describe())
    return 0


def _cmd_decode(args: argparse.Namespace) -> int:
    coord = hex_to_coord(args.coordinate)
    x, y, z, plane = coord_to_xyz(coord)
    print(f"hex    {coord_to_hex(coord)}")
    print(f"plane  {plane}")
    print(f"x      {x}")
    print(f"y      {y}")
    print(f"z      {z}")
    return 0


def _cmd_gps(args: argparse.Namespace) -> int:
    coord = gps_to_coord(args.latitude, args.longitude)
    print(f"hex    {coord_to_hex(coord)}")
    x, y, z, plane = coord_to_xyz(coord)
    print(f"x      {x}")
    print(f"y      {y}")
    print(f"z      {z}")
    print(f"plane  {plane}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="cs", description="tools for the Cyberspace v2 protocol"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit_parser = subparsers.add_parser(
        "audit", help="audit an identity's chain from a file of events"
    )
    audit_parser.add_argument("events", help="a JSON file of Nostr events")
    audit_parser.add_argument("--pubkey", required=True, help="the identity's public key")
    audit_parser.add_argument(
        "--line", help="a JSON file holding the hyperspace line, for rides"
    )
    audit_parser.set_defaults(handler=_cmd_audit)

    vectors_parser = subparsers.add_parser(
        "vectors", help="run the protocol's golden vectors"
    )
    vectors_parser.add_argument(
        "--fixture-dir",
        help="a directory holding the upstream vector files",
    )
    vectors_parser.set_defaults(handler=_cmd_vectors)

    forgery_parser = subparsers.add_parser(
        "forgery", help="run the forgery experiments against the chain rules"
    )
    forgery_parser.set_defaults(handler=_cmd_forgery)

    probe_parser = subparsers.add_parser(
        "probe", help="look at one position and the regions around it"
    )
    probe_parser.add_argument("coordinate", help="64 hex characters")
    probe_parser.add_argument("--min-height", type=int, default=1)
    probe_parser.add_argument("--max-height", type=int, default=12)
    probe_parser.set_defaults(handler=_cmd_probe)

    price_parser = subparsers.add_parser(
        "price", help="price a movement between two positions"
    )
    price_parser.add_argument("source", help="64 hex characters")
    price_parser.add_argument("destination", help="64 hex characters")
    price_parser.set_defaults(handler=_cmd_price)

    decode_parser = subparsers.add_parser(
        "decode", help="decode a coordinate into its axes"
    )
    decode_parser.add_argument("coordinate", help="64 hex characters")
    decode_parser.set_defaults(handler=_cmd_decode)

    gps_parser = subparsers.add_parser(
        "gps", help="turn a latitude and longitude into a coordinate"
    )
    gps_parser.add_argument("latitude")
    gps_parser.add_argument("longitude")
    gps_parser.set_defaults(handler=_cmd_gps)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the command line tool."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":  # pragma: no cover - script entry point
    sys.exit(main())
