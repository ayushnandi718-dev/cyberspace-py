"""TLS endpoint auditing.

The handshake is performed with certificate verification disabled on
purpose: a scanner must be able to inspect expired, self-signed or otherwise
broken certificates, and a rejected handshake hides exactly the material the
audit is looking for.  Because ``getpeercert(False)`` returns an empty mapping
when verification is off, the peer certificate is read as raw DER and decoded
by a small X.509 parser implemented in this module.
"""

from __future__ import annotations

import datetime as dt
import re
import socket
import ssl
from dataclasses import asdict, dataclass, field

from .common import Finding, sort_findings

__all__ = ["TlsReport", "inspect_tls"]

_UTC = dt.timezone.utc

_RSA_OID = "1.2.840.113549.1.1.1"
_EC_OID = "1.2.840.10045.2.1"
_SAN_OID = "2.5.29.17"
_BASIC_CONSTRAINTS_OID = "2.5.29.19"

_ATTRIBUTE_NAMES: dict[str, str] = {
    "2.5.4.3": "CN",
    "2.5.4.4": "SN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "STREET",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.12": "title",
    "2.5.4.42": "GN",
    "0.9.2342.19200300.100.1.1": "UID",
    "0.9.2342.19200300.100.1.25": "DC",
    "1.2.840.113549.1.9.1": "emailAddress",
}

_WEAK_CIPHER_TOKENS: tuple[str, ...] = (
    "RC4",
    "DES",
    "3DES",
    "NULL",
    "EXPORT",
    "MD5",
    "ANON",
)

_PROTOCOL_FINDINGS: dict[str, tuple[str, str, str]] = {
    "TLSV1.3": ("info", "tls-1.3", "Modern protocol version negotiated"),
    "TLSV1.2": ("low", "tls-1.2", "TLS 1.2 negotiated; TLS 1.3 preferred"),
    "TLSV1.1": ("high", "weak-tls-version", "Obsolete protocol version negotiated"),
    "TLSV1": ("high", "weak-tls-version", "Obsolete protocol version negotiated"),
    "SSLV3": ("high", "weak-tls-version", "Broken protocol version negotiated"),
    "SSLV2": ("high", "weak-tls-version", "Broken protocol version negotiated"),
}

_UTC_TIME_RE = re.compile(
    r"^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{4})?$"
)
_GENERALIZED_TIME_RE = re.compile(
    r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{4})?$"
)


@dataclass
class TlsReport:
    """The result of inspecting a single TLS endpoint."""

    host: str
    port: int
    connected: bool = False
    error: str = ""
    protocol: str = ""
    cipher: str = ""
    key_bits: int = 0
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    not_before: str = ""
    not_after: str = ""
    days_remaining: int | None = None
    subject_alt_names: list[str] = field(default_factory=list)
    self_signed: bool = False
    findings: list[Finding] = field(default_factory=list)

    def as_dict(self) -> dict:
        """Return a plain, JSON-serialisable representation of the report."""
        return asdict(self)


@dataclass
class _DerNode:
    """A decoded DER tag-length-value triple."""

    tag: int
    number: int
    content: bytes
    encoded: bytes
    constructed: bool

    @property
    def is_context(self) -> bool:
        """True when the node carries a context-specific tag."""
        return self.tag & 0xC0 == 0x80


@dataclass
class _CertificateInfo:
    """Fields decoded from an X.509 certificate."""

    subject: str = ""
    issuer: str = ""
    serial: str = ""
    not_before: dt.datetime | None = None
    not_after: dt.datetime | None = None
    key_bits: int = 0
    key_algorithm: str = ""
    subject_alt_names: list[str] = field(default_factory=list)
    is_ca: bool = False
    self_signed: bool = False


def _parse_node(data: bytes, offset: int) -> tuple[_DerNode, int]:
    """Decode one DER TLV starting at ``offset``.

    Returns the node and the offset of the next element.
    """
    if offset >= len(data):
        raise ValueError("unexpected end of DER data")
    start = offset
    tag = data[offset]
    offset += 1
    number = tag & 0x1F
    if number == 0x1F:
        number = 0
        while True:
            if offset >= len(data):
                raise ValueError("truncated DER tag")
            byte = data[offset]
            offset += 1
            number = (number << 7) | (byte & 0x7F)
            if not byte & 0x80:
                break
    if offset >= len(data):
        raise ValueError("truncated DER length")
    first = data[offset]
    offset += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0:
            raise ValueError("indefinite length encoding is not valid DER")
        if offset + count > len(data):
            raise ValueError("truncated DER length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    else:
        length = first
    end = offset + length
    if end > len(data):
        raise ValueError("truncated DER content")
    return (
        _DerNode(
            tag=tag,
            number=number,
            content=data[offset:end],
            encoded=data[start:end],
            constructed=bool(tag & 0x20),
        ),
        end,
    )


def _children(node: _DerNode) -> list[_DerNode]:
    """Decode the children of a constructed node.

    Decoding is best effort: a node whose content is not a well formed
    sequence of TLVs yields the children that could be decoded.
    """
    if not node.constructed:
        return []
    nodes: list[_DerNode] = []
    offset = 0
    while offset < len(node.content):
        try:
            child, offset = _parse_node(node.content, offset)
        except ValueError:
            return nodes
        nodes.append(child)
    return nodes


def _decode_oid(content: bytes) -> str:
    """Decode the contents octets of an OBJECT IDENTIFIER into dotted form."""
    if not content:
        return ""
    first = content[0]
    if first < 40:
        head = (0, first)
    elif first < 80:
        head = (1, first - 40)
    else:
        head = (2, first - 80)
    parts = [str(head[0]), str(head[1])]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _decode_text(node: _DerNode) -> str:
    """Decode a string-typed node into text."""
    if node.tag == 0x0C:
        return node.content.decode("utf-8", "replace")
    if node.tag == 0x1E:
        return node.content.decode("utf-16-be", "replace")
    if node.tag == 0x1C:
        return node.content.decode("utf-32-be", "replace")
    return node.content.decode("latin-1", "replace")


def _format_name(node: _DerNode) -> str:
    """Render a Name (RDNSequence) as an RFC4514-ish string.

    The attribute order of the encoding is preserved, so the result reads
    like ``"CN=example.com, O=Acme"``.
    """
    parts: list[str] = []
    for rdn in _children(node):
        attributes: list[str] = []
        for entry in _children(rdn):
            pair = _children(entry)
            if len(pair) < 2:
                continue
            oid = _decode_oid(pair[0].content)
            label = _ATTRIBUTE_NAMES.get(oid, oid)
            attributes.append(f"{label}={_decode_text(pair[1])}")
        if attributes:
            parts.append("+".join(attributes))
    return ", ".join(parts)


def _parse_time(node: _DerNode) -> dt.datetime | None:
    """Decode a UTCTime or GeneralizedTime node into an aware datetime."""
    raw = node.content.decode("ascii", "replace").strip()
    if node.tag == 0x17:
        match = _UTC_TIME_RE.match(raw)
        if match is None:
            return None
        year = int(match.group(1))
        year += 2000 if year < 50 else 1900
    elif node.tag == 0x18:
        match = _GENERALIZED_TIME_RE.match(raw)
        if match is None:
            return None
        year = int(match.group(1))
    else:
        return None
    groups = (year,) + tuple(int(value) for value in match.groups()[1:5])
    seconds = int(match.group(6)) if match.group(6) else 0
    offset = match.group(7)
    month, day, hour, minute = groups[1], groups[2], groups[3], groups[4]
    try:
        stamp = dt.datetime(year, month, day, hour, minute, seconds, tzinfo=_UTC)
    except ValueError:
        return None
    if offset and offset not in ("Z", "z"):
        sign = 1 if offset[0] == "+" else -1
        delta = dt.timedelta(hours=int(offset[1:3]), minutes=int(offset[3:5]))
        stamp -= sign * delta
    return stamp


def _parse_subject_alt_names(content: bytes) -> list[str]:
    """Extract the dNSName entries from a GeneralNames structure."""
    names: list[str] = []
    try:
        general_names, _ = _parse_node(content, 0)
    except ValueError:
        return names
    for entry in _children(general_names):
        if entry.tag == 0x82:
            value = entry.content.decode("ascii", "replace").strip()
            if value:
                names.append(value)
    return names


def _parse_basic_constraints(content: bytes) -> bool:
    """Return True when the BasicConstraints extension marks the cert as a CA."""
    try:
        constraints, _ = _parse_node(content, 0)
    except ValueError:
        return False
    for child in _children(constraints):
        if child.tag == 0x01 and child.content.strip(b"\x00"):
            return True
    return False


def _parse_public_key(spki: _DerNode) -> tuple[int, str]:
    """Return the modulus size in bits and the algorithm name of a public key."""
    parts = _children(spki)
    if len(parts) < 2:
        return 0, ""
    algorithm = _children(parts[0])
    oid = _decode_oid(algorithm[0].content) if algorithm else ""
    if oid == _RSA_OID:
        key_bytes = parts[1].content[1:]
        try:
            rsa_key, _ = _parse_node(key_bytes, 0)
        except ValueError:
            return 0, "RSA"
        numbers = _children(rsa_key)
        if not numbers:
            return 0, "RSA"
        modulus = int.from_bytes(numbers[0].content, "big")
        return modulus.bit_length(), "RSA"
    if oid == _EC_OID:
        return 0, "EC"
    return 0, "unknown"


def _parse_certificate(der: bytes) -> _CertificateInfo:
    """Decode the interesting fields of an X.509 certificate from DER bytes."""
    root, _ = _parse_node(der, 0)
    top = _children(root)
    if not top:
        raise ValueError("certificate does not contain a tbsCertificate")
    fields = _children(top[0])
    index = 0
    if fields and fields[0].is_context and fields[0].number == 0:
        index = 1
    if len(fields) < index + 6:
        raise ValueError("tbsCertificate is missing required fields")

    serial_node = fields[index]
    issuer_node = fields[index + 2]
    validity_node = fields[index + 3]
    subject_node = fields[index + 4]
    spki_node = fields[index + 5]

    info = _CertificateInfo()
    serial_bytes = serial_node.content
    if len(serial_bytes) > 1 and serial_bytes[0] == 0:
        serial_bytes = serial_bytes[1:]
    info.serial = format(int.from_bytes(serial_bytes, "big"), "X")
    info.subject = _format_name(subject_node)
    info.issuer = _format_name(issuer_node)
    info.self_signed = issuer_node.encoded == subject_node.encoded

    times = _children(validity_node)
    if len(times) >= 1:
        info.not_before = _parse_time(times[0])
    if len(times) >= 2:
        info.not_after = _parse_time(times[1])

    info.key_bits, info.key_algorithm = _parse_public_key(spki_node)

    for extra in fields[index + 6 :]:
        if not extra.is_context or extra.number != 3:
            continue
        wrapper = _children(extra)
        if not wrapper:
            continue
        for extension in _children(wrapper[0]):
            parts = _children(extension)
            if len(parts) < 2:
                continue
            oid = _decode_oid(parts[0].content)
            value = parts[-1]
            if oid == _SAN_OID:
                info.subject_alt_names.extend(_parse_subject_alt_names(value.content))
            elif oid == _BASIC_CONSTRAINTS_OID:
                info.is_ca = _parse_basic_constraints(value.content)

    return info


def _san_matches(hostname: str, names: list[str]) -> bool:
    """True when ``hostname`` is covered by one of the SAN dNSName entries."""
    target = hostname.strip().rstrip(".").lower()
    if not target:
        return False
    for entry in names:
        candidate = entry.strip().rstrip(".").lower()
        if not candidate:
            continue
        if candidate == target:
            return True
        if candidate.startswith("*.") and not target.startswith("*."):
            suffix = candidate[1:]
            if target.endswith(suffix) and target.count(".") == candidate.count("."):
                return True
    return False


def _close_quietly(sock: socket.socket | None) -> None:
    """Close a socket, ignoring any error raised while doing so."""
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        return


def _widen_version_range(context: ssl.SSLContext) -> ssl.SSLContext:
    """Allow legacy protocol versions so that weak endpoints can be detected."""
    try:
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
    except (ValueError, AttributeError, OSError):
        return context
    return context


def _insecure_context() -> ssl.SSLContext:
    """A client context that accepts any certificate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return _widen_version_range(context)


def _verifying_context() -> ssl.SSLContext:
    """A client context that validates the chain but not the hostname."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def _chain_error(host: str, port: int, timeout: float, server_hostname: str) -> str | None:
    """Verify the server chain; return an error message when it does not validate."""
    try:
        context = _verifying_context()
    except ssl.SSLError:
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=server_hostname):
                return None
    except ssl.SSLCertVerificationError as exc:
        return str(exc)
    except (ssl.SSLError, OSError, ValueError):
        return None


def _build_findings(
    report: TlsReport,
    info: _CertificateInfo | None,
    chain_error: str | None,
    sni: str | None,
) -> list[Finding]:
    """Assemble the audit findings for a completed inspection."""
    findings: list[Finding] = []
    now = dt.datetime.now(_UTC)

    if info is not None and info.not_after is not None:
        remaining = info.not_after - now
        if remaining.total_seconds() <= 0:
            findings.append(
                Finding(
                    severity="critical",
                    name="expired-certificate",
                    title="Certificate has expired",
                    detail=(
                        f"notAfter {info.not_after.isoformat()} passed "
                        f"{abs(int(remaining.total_seconds() // 86400))} day(s) ago"
                    ),
                )
            )
        elif remaining.days <= 7:
            findings.append(
                Finding(
                    severity="high",
                    name="certificate-expiring-soon",
                    title="Certificate expires within 7 days",
                    detail=f"notAfter {info.not_after.isoformat()}, {remaining.days} day(s) left",
                )
            )
        elif remaining.days <= 30:
            findings.append(
                Finding(
                    severity="medium",
                    name="certificate-expiring",
                    title="Certificate expires within 30 days",
                    detail=f"notAfter {info.not_after.isoformat()}, {remaining.days} day(s) left",
                )
            )

    if info is not None and info.self_signed:
        findings.append(
            Finding(
                severity="high",
                name="self-signed-certificate",
                title="Certificate is self-signed",
                detail=f"subject and issuer are identical: {info.subject or '<empty>'}",
            )
        )

    if 0 < report.key_bits < 2048:
        findings.append(
            Finding(
                severity="high",
                name="weak-public-key",
                title="Public key is shorter than 2048 bits",
                detail=f"certificate public key is {report.key_bits} bits",
            )
        )

    protocol_entry = _PROTOCOL_FINDINGS.get(report.protocol.upper())
    if protocol_entry is not None:
        severity, name, title = protocol_entry
        findings.append(
            Finding(
                severity=severity,
                name=name,
                title=title,
                detail=(
                    f"negotiated {report.protocol or 'unknown'} with "
                    f"{report.cipher or 'unknown cipher'}"
                ),
            )
        )

    cipher_upper = report.cipher.upper()
    if cipher_upper:
        weak = [token for token in _WEAK_CIPHER_TOKENS if token in cipher_upper]
        if weak:
            findings.append(
                Finding(
                    severity="high",
                    name="weak-cipher",
                    title="Negotiated cipher is considered weak",
                    detail=f"cipher {report.cipher} matches {', '.join(weak)}",
                )
            )

    if info is not None:
        if not info.subject_alt_names:
            findings.append(
                Finding(
                    severity="medium",
                    name="missing-subject-alt-name",
                    title="Certificate has no subjectAltName extension",
                    detail="modern clients require subjectAltName; the commonName is deprecated",
                )
            )
        elif sni and not _san_matches(sni, info.subject_alt_names):
            findings.append(
                Finding(
                    severity="medium",
                    name="hostname-not-in-san",
                    title="Requested hostname is not listed in subjectAltName",
                    detail=f"'{sni}' is absent from {', '.join(info.subject_alt_names)}",
                )
            )

    if chain_error:
        findings.append(
            Finding(
                severity="medium",
                name="untrusted-chain",
                title="Certificate chain is not trusted",
                detail=chain_error,
            )
        )

    return sort_findings(findings)


def inspect_tls(
    host: str,
    port: int = 443,
    timeout: float = 5.0,
    sni: str | None = None,
) -> TlsReport:
    """Connect, handshake, and audit the certificate and negotiated parameters.

    Never raises for network problems: on failure returns a report with
    connected=False and error set.
    """
    report = TlsReport(host=host, port=port)
    server_hostname = sni or host
    context = _insecure_context()
    info: _CertificateInfo | None = None
    parse_error = ""

    raw_sock: socket.socket | None = None
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        with context.wrap_socket(raw_sock, server_hostname=server_hostname) as tls_sock:
            raw_sock = None
            cipher = tls_sock.cipher()
            if cipher:
                report.cipher = cipher[0] or ""
                report.protocol = tls_sock.version() or cipher[1] or ""
            else:
                report.protocol = tls_sock.version() or ""
            der = tls_sock.getpeercert(binary_form=True)
            if der:
                try:
                    info = _parse_certificate(der)
                except (ValueError, IndexError) as exc:
                    parse_error = f"{type(exc).__name__}: {exc}"
            report.connected = True
    except (ssl.SSLError, OSError, ValueError) as exc:
        report.connected = False
        report.error = f"{type(exc).__name__}: {exc}"
        _close_quietly(raw_sock)
        return report

    if info is not None:
        report.subject = info.subject
        report.issuer = info.issuer
        report.serial = info.serial
        report.not_before = info.not_before.isoformat() if info.not_before else ""
        report.not_after = info.not_after.isoformat() if info.not_after else ""
        if info.not_after is not None:
            report.days_remaining = (info.not_after - dt.datetime.now(_UTC)).days
        report.subject_alt_names = list(info.subject_alt_names)
        report.self_signed = info.self_signed
        report.key_bits = info.key_bits
    elif parse_error:
        report.findings.append(
            Finding(
                severity="low",
                name="certificate-parse-failed",
                title="Certificate could not be decoded",
                detail=parse_error,
            )
        )

    chain_error = _chain_error(host, port, timeout, server_hostname)
    report.findings.extend(_build_findings(report, info, chain_error, sni))
    report.findings = sort_findings(report.findings)
    return report
