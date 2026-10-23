"""HTTP fetching and header auditing.

The helpers here are deliberately tolerant: they talk to hosts that are
misconfigured on purpose, so network problems are reported as empty results
rather than exceptions.
"""

from __future__ import annotations

import http.client
import re
import ssl
from urllib.parse import urljoin, urlsplit

from .common import Finding

__all__ = ["fetch", "audit_headers", "audit_cors", "audit_redirects"]

_USER_AGENT = "secsuite-audit/1.0"
_MAX_REDIRECTS = 10
_MAX_REDIRECT_CHAIN = 10
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)

_SET_COOKIE_SPLIT = re.compile(r",\s*(?=[^\s,;=]+=)")
_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)
_VERSION_RE = re.compile(r"\d+\.\d+")
_UNSAFE_METHODS = frozenset({"PUT", "DELETE", "PATCH"})


def _insecure_ssl_context() -> ssl.SSLContext:
    """A TLS context that accepts any certificate.

    Headers must remain readable on hosts with expired or self-signed
    certificates, otherwise the audit of such a host would stop before it
    starts.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _lookup(headers: dict[str, str], name: str) -> str:
    """Case-insensitive header lookup."""
    if not headers:
        return ""
    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() == wanted:
            return value if isinstance(value, str) else str(value)
    return ""


def _collapse_headers(raw_headers: list[tuple[str, str]]) -> dict[str, str]:
    """Fold raw header pairs into a lowercased mapping."""
    folded: dict[str, str] = {}
    for key, value in raw_headers:
        name = key.lower()
        if name in folded:
            folded[name] = f"{folded[name]}, {value}"
        else:
            folded[name] = value
    return folded


def _split_set_cookie(value: str) -> list[str]:
    """Split a joined ``Set-Cookie`` value back into individual cookies.

    The separator is a comma, but a comma also appears inside the ``Expires``
    attribute, so a split only happens where a cookie name/value pair follows.
    """
    if not value:
        return []
    return [part.strip() for part in _SET_COOKIE_SPLIT.split(value) if part.strip()]


def _request(
    url: str,
    timeout: float,
    method: str,
    max_bytes: int,
) -> tuple[int, dict[str, str], bytes, str]:
    """Perform a single HTTP request.

    Returns ``(status, headers, body, location)``; ``status`` is 0 when the
    request could not be completed.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return 0, {}, b"", ""
    target = parts.path or "/"
    if parts.query:
        target = f"{target}?{parts.query}"
    request_headers = {
        "User-Agent": _USER_AGENT,
        "Accept": "*/*",
        "Connection": "close",
    }
    try:
        if parts.scheme == "https":
            connection = http.client.HTTPSConnection(
                parts.hostname,
                parts.port or 443,
                timeout=timeout,
                context=_insecure_ssl_context(),
            )
        else:
            connection = http.client.HTTPConnection(
                parts.hostname,
                parts.port or 80,
                timeout=timeout,
            )
        try:
            connection.request(method, target, headers=request_headers)
            response = connection.getresponse()
            status = response.status
            raw_headers = response.getheaders()
            location = response.getheader("Location") or ""
            body = response.read(max_bytes) if max_bytes > 0 else b""
        finally:
            connection.close()
    except (http.client.HTTPException, OSError, ValueError):
        return 0, {}, b"", ""
    return status, _collapse_headers(raw_headers), body, location


def fetch(
    url: str,
    timeout: float = 8.0,
    method: str = "GET",
    follow_redirects: bool = True,
    max_bytes: int = 262144,
) -> tuple[int, dict[str, str], bytes, str]:
    """Fetch a URL.

    Returns (status, headers_lowercased, body_bytes, final_url).
    Never raises for network errors: on failure returns (0, {}, b"", url).
    Only http:// and https:// are permitted.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return 0, {}, b"", url

    current = url
    current_method = method
    status, headers, body = 0, {}, b""
    for _ in range(_MAX_REDIRECTS + 1):
        status, headers, body, location = _request(
            current, timeout, current_method, max_bytes
        )
        if status == 0:
            return 0, {}, b"", url
        if not follow_redirects or status not in _REDIRECT_STATUSES or not location:
            return status, headers, body, current
        target = urljoin(current, location)
        if urlsplit(target).scheme not in ("http", "https"):
            return status, headers, body, current
        if status == 303 or (status in (301, 302) and current_method not in ("GET", "HEAD")):
            current_method = "GET"
        current = target
    return status, headers, body, current


def audit_headers(headers: dict[str, str], *, is_https: bool = True) -> list[Finding]:
    """Audit a response's headers for common security misconfigurations.

    headers keys are case-insensitive; accept them lowercased.
    """
    findings: list[Finding] = []
    if headers is None:
        return findings

    csp = _lookup(headers, "content-security-policy")
    if not csp:
        findings.append(
            Finding(
                severity="medium",
                name="missing-csp",
                title="Missing Content-Security-Policy header",
                detail="No CSP is sent, so the browser applies no script or object restrictions.",
            )
        )
    else:
        directives = set()
        for chunk in csp.split(";"):
            name = chunk.strip().split()[0].lower() if chunk.strip() else ""
            if name:
                directives.add(name)
        missing = [
            directive
            for directive in ("default-src", "object-src")
            if directive not in directives
        ]
        if missing:
            findings.append(
                Finding(
                    severity="low",
                    name="incomplete-csp",
                    title="Content-Security-Policy is missing key directives",
                    detail=f"missing: {', '.join(missing)}",
                )
            )
        lowered_csp = csp.lower()
        if "unsafe-inline" in lowered_csp:
            findings.append(
                Finding(
                    severity="medium",
                    name="csp-unsafe-inline",
                    title="Content-Security-Policy permits unsafe-inline",
                    detail="Inline scripts or styles bypass the policy's script controls.",
                )
            )
        if "unsafe-eval" in lowered_csp:
            findings.append(
                Finding(
                    severity="medium",
                    name="csp-unsafe-eval",
                    title="Content-Security-Policy permits unsafe-eval",
                    detail="eval() style execution defeats the policy's script controls.",
                )
            )

    hsts = _lookup(headers, "strict-transport-security")
    if is_https:
        if not hsts:
            findings.append(
                Finding(
                    severity="medium",
                    name="missing-hsts",
                    title="Missing Strict-Transport-Security header",
                    detail="HTTPS is not enforced for this host on subsequent visits.",
                )
            )
        else:
            max_age = _MAX_AGE_RE.search(hsts)
            if max_age is None:
                findings.append(
                    Finding(
                        severity="low",
                        name="weak-hsts-max-age",
                        title="Strict-Transport-Security has no usable max-age",
                        detail=f"header value: {hsts}",
                    )
                )
            elif int(max_age.group(1)) < 15552000:
                findings.append(
                    Finding(
                        severity="low",
                        name="weak-hsts-max-age",
                        title="Strict-Transport-Security max-age is below 180 days",
                        detail=f"max-age={max_age.group(1)}, 15552000 recommended",
                    )
                )
            if "includesubdomains" not in hsts.lower():
                findings.append(
                    Finding(
                        severity="low",
                        name="hsts-no-includesubdomains",
                        title="Strict-Transport-Security omits includeSubDomains",
                        detail="Sub-domains are not covered by the policy.",
                    )
                )

    nosniff = _lookup(headers, "x-content-type-options")
    if not nosniff:
        findings.append(
            Finding(
                severity="low",
                name="missing-x-content-type-options",
                title="Missing X-Content-Type-Options header",
                detail="MIME type sniffing may turn user supplied content into active content.",
            )
        )
    elif nosniff.strip().lower() != "nosniff":
        findings.append(
            Finding(
                severity="medium",
                name="x-content-type-options-not-nosniff",
                title="X-Content-Type-Options is not set to nosniff",
                detail=f"header value: {nosniff}",
            )
        )

    frame_options = _lookup(headers, "x-frame-options")
    if not frame_options and "frame-ancestors" not in csp.lower():
        findings.append(
            Finding(
                severity="low",
                name="no-clickjacking-protection",
                title="No clickjacking protection is configured",
                detail="Neither X-Frame-Options nor CSP frame-ancestors is present.",
            )
        )

    if not _lookup(headers, "referrer-policy"):
        findings.append(
            Finding(
                severity="low",
                name="missing-referrer-policy",
                title="Missing Referrer-Policy header",
                detail="Full referrers may leak sensitive URLs to third parties.",
            )
        )

    if not _lookup(headers, "permissions-policy"):
        findings.append(
            Finding(
                severity="info",
                name="missing-permissions-policy",
                title="Missing Permissions-Policy header",
                detail="Browser features such as camera or microphone are not restricted.",
            )
        )

    for cookie in _split_set_cookie(_lookup(headers, "set-cookie")):
        attributes = {
            attribute.split("=", 1)[0].strip().lower()
            for attribute in cookie.split(";")[1:]
        }
        name = cookie.split("=", 1)[0].strip()
        if "secure" not in attributes:
            findings.append(
                Finding(
                    severity="high",
                    name="cookie-missing-secure",
                    title="Cookie is not marked Secure",
                    detail=f"cookie '{name}' may be sent over plaintext HTTP.",
                )
            )
        if "httponly" not in attributes:
            findings.append(
                Finding(
                    severity="medium",
                    name="cookie-missing-httponly",
                    title="Cookie is not marked HttpOnly",
                    detail=f"cookie '{name}' is readable from JavaScript.",
                )
            )
        if "samesite" not in attributes:
            findings.append(
                Finding(
                    severity="medium",
                    name="cookie-missing-samesite",
                    title="Cookie is missing the SameSite attribute",
                    detail=f"cookie '{name}' may be sent on cross-site requests.",
                )
            )

    server = _lookup(headers, "server")
    if server and _VERSION_RE.search(server):
        findings.append(
            Finding(
                severity="info",
                name="server-version-disclosure",
                title="Server header discloses a version number",
                detail=f"Server: {server}",
            )
        )

    if _lookup(headers, "x-powered-by"):
        findings.append(
            Finding(
                severity="info",
                name="x-powered-by-disclosure",
                title="X-Powered-By header discloses the technology stack",
                detail=f"X-Powered-By: {_lookup(headers, 'x-powered-by')}",
            )
        )

    return findings


def audit_cors(
    response_headers: dict[str, str],
    request_origin: str,
    request_method: str = "GET",
) -> list[Finding]:
    """Audit CORS configuration for a request made with the given Origin.

    Detect: wildcard origin with credentials allowed (critical),
    origin reflection (Access-Control-Allow-Origin echoing an arbitrary
    Origin) combined with Allow-Credentials: true (high),
    missing/incorrect Access-Control-Allow-Origin when a specific origin was
    sent (medium), null origin reflected (high), and
    Access-Control-Allow-Methods containing unsafe methods with
    Allow-Credentials true (medium).
    """
    findings: list[Finding] = []
    if response_headers is None:
        return findings

    allow_origin = _lookup(response_headers, "access-control-allow-origin").strip()
    allow_credentials = (
        _lookup(response_headers, "access-control-allow-credentials").strip().lower()
        == "true"
    )
    allow_methods = _lookup(response_headers, "access-control-allow-methods")
    origin = (request_origin or "").strip()
    specific_origin = bool(origin) and origin != "*"

    if allow_origin == "*":
        if allow_credentials:
            findings.append(
                Finding(
                    severity="critical",
                    name="cors-wildcard-with-credentials",
                    title="Wildcard CORS origin combined with credentials",
                    detail=(
                        "Access-Control-Allow-Origin: * with "
                        "Access-Control-Allow-Credentials: true lets any site "
                        "read authenticated responses."
                    ),
                )
            )
    elif allow_origin.lower() == "null":
        findings.append(
            Finding(
                severity="high",
                name="cors-null-origin-reflected",
                title="CORS allows the null origin",
                detail=(
                    "Access-Control-Allow-Origin: null accepts requests from "
                    "sandboxed frames and data: URLs."
                ),
            )
        )
    elif specific_origin:
        if not allow_origin:
            findings.append(
                Finding(
                    severity="medium",
                    name="cors-missing-allow-origin",
                    title="Response omits Access-Control-Allow-Origin",
                    detail=(
                        f"Origin: {origin} was sent but the response carries no "
                        "Access-Control-Allow-Origin header."
                    ),
                )
            )
        elif allow_origin.lower() != origin.lower():
            findings.append(
                Finding(
                    severity="medium",
                    name="cors-origin-not-allowed",
                    title="Access-Control-Allow-Origin does not match the request origin",
                    detail=(
                        f"requested origin '{origin}' but allowed origin is "
                        f"'{allow_origin}'."
                    ),
                )
            )
        elif allow_credentials:
            findings.append(
                Finding(
                    severity="high",
                    name="cors-origin-reflection-with-credentials",
                    title="CORS reflects the request origin and allows credentials",
                    detail=(
                        f"Access-Control-Allow-Origin echoes '{origin}' while "
                        "Access-Control-Allow-Credentials is true."
                    ),
                )
            )

    methods = {
        method.strip().upper() for method in allow_methods.split(",") if method.strip()
    }
    unsafe = sorted(methods & _UNSAFE_METHODS)
    if allow_credentials and unsafe:
        findings.append(
            Finding(
                severity="medium",
                name="cors-unsafe-methods-with-credentials",
                title="CORS allows state changing methods with credentials",
                detail=(
                    f"Access-Control-Allow-Methods contains {', '.join(unsafe)} "
                    "while Access-Control-Allow-Credentials is true."
                ),
            )
        )

    return findings


def audit_redirects(url: str, timeout: float = 8.0) -> list[Finding]:
    """Follow redirects manually and report https->http downgrades, redirects
    to non-http(s) schemes, and excessive redirect chains. Returns findings;
    returns a single 'info' finding describing the chain if no issue found.
    """
    findings: list[Finding] = []
    chain = [url]
    current = url

    for _ in range(_MAX_REDIRECT_CHAIN):
        status, headers, _body, location = _request(current, timeout, "HEAD", 0)
        if status in (400, 403, 404, 405, 501):
            status, headers, _body, location = _request(current, timeout, "GET", 4096)
        if status == 0:
            findings.append(
                Finding(
                    severity="info",
                    name="redirect-chain",
                    title="Redirect chain could not be followed",
                    detail=" -> ".join(chain),
                )
            )
            return findings
        if status not in _REDIRECT_STATUSES or not location:
            break
        target = urljoin(current, location)
        chain.append(target)
        target_scheme = urlsplit(target).scheme.lower()
        current_scheme = urlsplit(current).scheme.lower()
        if target_scheme not in ("http", "https"):
            findings.append(
                Finding(
                    severity="high",
                    name="redirect-to-non-http-scheme",
                    title="Redirect points at a non-HTTP(S) scheme",
                    detail=f"{current} redirects to '{target}'.",
                )
            )
            return findings
        if current_scheme == "https" and target_scheme == "http":
            findings.append(
                Finding(
                    severity="high",
                    name="https-downgrade",
                    title="Redirect downgrades HTTPS to HTTP",
                    detail=f"{current} redirects to {target}.",
                )
            )
        current = target
    else:
        findings.append(
            Finding(
                severity="medium",
                name="excessive-redirects",
                title="Redirect chain is excessively long",
                detail=f"{len(chain)} hops: " + " -> ".join(chain),
            )
        )
        return findings

    if not findings:
        findings.append(
            Finding(
                severity="info",
                name="redirect-chain",
                title="No redirect issues detected",
                detail=" -> ".join(chain),
            )
        )
    return findings
