"""The ``secsuite`` command line tool.

A front end over the static analysis helpers: identify a hash, judge a
password, build a candidate list, read the cost of a hash, and run the
network and Android checks.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from .cracking import recover
from .hash import (
    HASH_ALGORITHMS,
    BackendMissing,
    hash_bytes,
    hash_text,
    identify_hash,
)
from .kdf import describe_hash, measure
from .password import analyse
from .wordlist import RULES, generate, per_target_words, read_wordlist, write_wordlist

__all__ = ["main"]


def _cmd_identify(args: argparse.Namespace) -> int:
    value = args.value
    if args.file:
        value = pathlib.Path(args.file).read_text(encoding="utf-8").strip()
    for identification in identify_hash(value):
        print(f"{identification.confidence:<7} {identification.kind:<12} {identification.detail}")
        if identification.candidates:
            print(f"        also could be: {', '.join(identification.candidates)}")
    return 0


def _cmd_hash(args: argparse.Namespace) -> int:
    if args.file:
        # The file is hashed as bytes: a binary file is not text.
        result = hash_bytes(pathlib.Path(args.file).read_bytes(), args.algorithm)
    else:
        result = hash_text(args.text, args.algorithm)
    print(f"{result.algorithm}  {result.hex}")
    return 0


def _cmd_password(args: argparse.Namespace) -> int:
    password = args.password
    if args.file:
        password = pathlib.Path(args.file).read_text(encoding="utf-8").rstrip("\r\n")
    report = analyse(password)
    print(f"length   {report.length}")
    print(f"classes  {', '.join(report.classes) or 'none'}")
    print(f"entropy  {report.entropy} bits")
    print(f"verdict  {report.verdict}")
    for weakness in report.weaknesses:
        print(f"  ! {weakness}")
    for suggestion in report.suggestions:
        print(f"  > {suggestion}")
    return 0


def _cmd_wordlist(args: argparse.Namespace) -> int:
    if args.host:
        base = per_target_words(args.host, args.usernames or ())
    elif args.file:
        base = read_wordlist(args.file)
    else:
        base = list(args.words or [])
    if not base:
        print("nothing to work from: give a host, a file or some words")
        return 2
    rules = [rule for rule in RULES if rule.name in args.rules] if args.rules else None
    candidates = generate(base, rules)
    if args.output:
        written = write_wordlist(args.output, candidates)
        print(f"wrote {written} candidate(s) to {args.output}")
        return 0
    count = 0
    for candidate in candidates:
        print(candidate)
        count += 1
        if args.limit and count >= args.limit:
            break
    return 0


def _cmd_kdf(args: argparse.Namespace) -> int:
    if args.hash:
        report = describe_hash(args.hash)
        print(f"kind        {report.kind}")
        print(f"parameters  {json.dumps(report.parameters)}")
        print(f"advice      {report.advice}")
        return 0
    result = measure(args.kind, "password", args.rounds)
    print(json.dumps(result, indent=2))
    return 0


def _cmd_recover(args: argparse.Namespace) -> int:
    if args.file:
        candidates = read_wordlist(args.file)
    else:
        candidates = list(args.candidates or [])
    if not candidates:
        print("no candidates given")
        return 2
    try:
        result = recover(args.hash, candidates, args.kind, args.limit, args.timeout)
    except BackendMissing as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result.as_dict(), indent=2))
    return 0 if result.found else 1


def _cmd_tls(args: argparse.Namespace) -> int:
    from .net.tls import inspect_tls

    report = inspect_tls(args.host, args.port, args.timeout, args.sni)
    print(json.dumps(report.as_dict(), indent=2))
    return 0 if not report.findings else 1


def _cmd_http(args: argparse.Namespace) -> int:
    from .net.http import audit_headers, fetch

    status, headers, _body, final_url = fetch(args.url, timeout=args.timeout)
    findings = audit_headers(headers, is_https=final_url.startswith("https://"))
    print(json.dumps({"status": status, "url": final_url, "headers": headers}, indent=2))
    for finding in findings:
        print(f"{finding.severity:<8} {finding.name:<28} {finding.title}")
    return 0 if not findings else 1


def _cmd_scan(args: argparse.Namespace) -> int:
    from .net.scan import tcp_scan

    ports = [int(port) for port in args.ports.split(",") if port.strip()]
    results = tcp_scan(args.host, ports, timeout=args.timeout)
    print(json.dumps([result.as_dict() for result in results], indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="secsuite", description="static analysis helpers for security auditing"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    identify_parser = subparsers.add_parser(
        "identify", help="guess what a hash is"
    )
    identify_parser.add_argument("value", nargs="?", default="")
    identify_parser.add_argument("--file", help="read the hash from a file")
    identify_parser.set_defaults(handler=_cmd_identify)

    hash_parser = subparsers.add_parser("hash", help="hash a text or a file")
    hash_parser.add_argument("text", nargs="?", default="")
    hash_parser.add_argument("--file", help="hash the contents of a file")
    hash_parser.add_argument("--algorithm", default="sha256", choices=list(HASH_ALGORITHMS))
    hash_parser.set_defaults(handler=_cmd_hash)

    password_parser = subparsers.add_parser(
        "password", help="judge the strength of a password"
    )
    password_parser.add_argument("password", nargs="?", default="")
    password_parser.add_argument("--file", help="read the password from a file")
    password_parser.set_defaults(handler=_cmd_password)

    wordlist_parser = subparsers.add_parser(
        "wordlist", help="build a candidate list"
    )
    wordlist_parser.add_argument("words", nargs="*", help="base words")
    wordlist_parser.add_argument("--host", help="take the base words from a host name")
    wordlist_parser.add_argument("--usernames", nargs="*", help="account names to include")
    wordlist_parser.add_argument("--file", help="take the base words from a file")
    wordlist_parser.add_argument(
        "--rules", nargs="*", help="only these mutations", choices=[rule.name for rule in RULES]
    )
    wordlist_parser.add_argument("--output", help="write the list to a file")
    wordlist_parser.add_argument("--limit", type=int, help="stop after this many lines")
    wordlist_parser.set_defaults(handler=_cmd_wordlist)

    kdf_parser = subparsers.add_parser(
        "kdf", help="read the cost of a hash, or time a derivation"
    )
    kdf_parser.add_argument("--hash", help="a hash whose cost should be read")
    kdf_parser.add_argument(
        "--kind", default="pbkdf2-sha256", help="the kind of derivation to time"
    )
    kdf_parser.add_argument("--rounds", type=int, default=100000)
    kdf_parser.set_defaults(handler=_cmd_kdf)

    recover_parser = subparsers.add_parser(
        "recover", help="try candidates against a hash you hold"
    )
    recover_parser.add_argument("hash")
    recover_parser.add_argument("candidates", nargs="*")
    recover_parser.add_argument("--file", help="read the candidates from a file")
    recover_parser.add_argument("--kind", help="the kind of hash, when it is ambiguous")
    recover_parser.add_argument("--limit", type=int, help="try at most this many candidates")
    recover_parser.add_argument("--timeout", type=float, help="give up after this many seconds")
    recover_parser.set_defaults(handler=_cmd_recover)

    tls_parser = subparsers.add_parser("tls", help="inspect a TLS endpoint")
    tls_parser.add_argument("host")
    tls_parser.add_argument("--port", type=int, default=443)
    tls_parser.add_argument("--timeout", type=float, default=5.0)
    tls_parser.add_argument("--sni", help="the name to send in the handshake")
    tls_parser.set_defaults(handler=_cmd_tls)

    http_parser = subparsers.add_parser("http", help="audit the headers of a response")
    http_parser.add_argument("url")
    http_parser.add_argument("--timeout", type=float, default=10.0)
    http_parser.set_defaults(handler=_cmd_http)

    scan_parser = subparsers.add_parser("scan", help="scan a few ports on a host")
    scan_parser.add_argument("host")
    scan_parser.add_argument("--ports", default="22,80,443")
    scan_parser.add_argument("--timeout", type=float, default=1.0)
    scan_parser.set_defaults(handler=_cmd_scan)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the command line tool."""
    parser = build_parser()
    args, extra = parser.parse_known_args(argv)
    if extra:
        candidates = getattr(args, "candidates", None)
        if candidates is None:
            parser.error(f"unrecognized arguments: {' '.join(extra)}")
        args.candidates = [*candidates, *extra]
    return args.handler(args)


if __name__ == "__main__":  # pragma: no cover - script entry point
    sys.exit(main())
