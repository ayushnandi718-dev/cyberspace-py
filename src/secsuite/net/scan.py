"""Network probing: TCP port scanning, DNS lookups and service banners."""

from __future__ import annotations

import importlib.util
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass

__all__ = ["PortResult", "tcp_scan", "dns_records", "service_banner"]

_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")


@dataclass
class PortResult:
    """The outcome of a single TCP connect attempt."""

    port: int
    state: str
    banner: str = ""

    def as_dict(self) -> dict:
        """Return a plain, JSON-serialisable representation of the result."""
        return asdict(self)


def tcp_scan(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    workers: int = 64,
    grab_banner: bool = True,
) -> list[PortResult]:
    """TCP connect scan using a thread pool. Returns results sorted by port.

    'open' when the connect succeeds, 'closed' when refused (ConnectionRefusedError),
    'filtered' on timeout or any other error.
    """
    if not ports:
        return []

    def probe(port: int) -> PortResult:
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                banner = ""
                if grab_banner:
                    sock.settimeout(timeout)
                    try:
                        chunk = sock.recv(256)
                    except (TimeoutError, OSError):
                        chunk = b""
                    banner = chunk.decode("utf-8", "replace")
                return PortResult(port=port, state="open", banner=banner)
        except ConnectionRefusedError:
            return PortResult(port=port, state="closed")
        except TimeoutError:
            return PortResult(port=port, state="filtered")
        except OSError:
            return PortResult(port=port, state="filtered")

    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        results = list(executor.map(probe, ports))
    return sorted(results, key=lambda result: result.port)


def _records_with_dnspython(host: str, timeout: float) -> dict[str, list[str]]:
    """Resolve the record types with dnspython when it is installed."""
    records: dict[str, list[str]] = {name: [] for name in _RECORD_TYPES}
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    errors: list[str] = []
    for record_type in _RECORD_TYPES:
        try:
            answers = resolver.resolve(host, record_type)
        except dns.resolver.NXDOMAIN:
            errors.append(f"NXDOMAIN for {record_type}")
            continue
        except (dns.exception.DNSException, ValueError, OSError) as exc:
            errors.append(f"{record_type}: {exc}")
            continue
        records[record_type] = [str(answer) for answer in answers]
    if not any(records.values()) and errors:
        records["error"] = errors[0]
    return records


def _records_with_resolver(host: str) -> dict[str, list[str]]:
    """Fall back to the stdlib resolver, which only yields addresses."""
    records: dict[str, list[str]] = {name: [] for name in _RECORD_TYPES}
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError) as exc:
        records["error"] = f"{type(exc).__name__}: {exc}"
        return records
    for family, _type, _proto, _canon, sockaddr in infos:
        address = sockaddr[0]
        if family == socket.AF_INET and address not in records["A"]:
            records["A"].append(address)
        elif family == socket.AF_INET6 and address not in records["AAAA"]:
            records["AAAA"].append(address)
    return records


def _dnspython_available() -> bool:
    """True when the dnspython resolver can be imported."""
    try:
        return importlib.util.find_spec("dns.resolver") is not None
    except (ImportError, ValueError):
        return False


def dns_records(host: str, timeout: float = 5.0) -> dict[str, list[str]]:
    """Query A, AAAA, MX, NS, TXT and CNAME records for a host.

    Uses dnspython if importable, else falls back to the stdlib socket
    resolver (getaddrinfo) for A/AAAA and returns empty lists for the rest.
    Never raises; on failure returns a dict with empty lists and the key
    "error" mapped to a message string.
    """
    if not _dnspython_available():
        return _records_with_resolver(host)
    try:
        return _records_with_dnspython(host, timeout)
    except Exception as exc:  # dnspython raises a wide range of errors
        records: dict[str, list[str]] = {name: [] for name in _RECORD_TYPES}
        records["error"] = f"{type(exc).__name__}: {exc}"
        return records


def service_banner(
    host: str,
    port: int,
    timeout: float = 2.0,
    probe: bytes = b"",
) -> str:
    """Connect, optionally send a probe, read up to 256 bytes and return it
    decoded lossy. Returns "" on any failure.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            if probe:
                sock.sendall(probe)
            sock.settimeout(timeout)
            try:
                data = sock.recv(256)
            except (TimeoutError, OSError):
                data = b""
            return data.decode("utf-8", "replace")
    except (OSError, ValueError):
        return ""
