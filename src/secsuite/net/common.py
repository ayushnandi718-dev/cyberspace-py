"""Shared result primitives for the network audit modules.

Every audit in this package reports problems as :class:`Finding` records so
that TLS, HTTP and service-level checks can be aggregated, deduplicated and
rendered by a caller in a single, uniform way.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

__all__ = ["Finding", "SEVERITIES", "sort_findings"]

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
"""Severity labels ordered from most to least urgent."""

_SEVERITY_RANK: dict[str, int] = {name: index for index, name in enumerate(SEVERITIES)}


@dataclass
class Finding:
    """A single security observation.

    Attributes:
        severity: One of ``critical``, ``high``, ``medium``, ``low`` or ``info``.
        name: Short machine-friendly identifier such as ``"missing-hsts"``.
        title: One-line human readable summary.
        detail: Optional longer explanation or supporting evidence.
    """

    severity: str
    name: str
    title: str
    detail: str = ""

    def as_dict(self) -> dict:
        """Return a plain, JSON-serialisable representation of the finding."""
        return asdict(self)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort by severity (critical first), then by name.

    Findings with an unrecognised severity are placed after the known ones
    rather than dropped.
    """
    return sorted(
        findings,
        key=lambda finding: (
            _SEVERITY_RANK.get(finding.severity, len(SEVERITIES)),
            finding.name,
        ),
    )
