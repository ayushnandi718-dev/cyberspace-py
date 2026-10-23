"""Adversarial and analytical tools for the Cyberspace protocol.

The chain rules in :mod:`cyberspace.chain` are written to be obeyed.  This
package is written to *test* them: to look at a chain the way an attacker
would, to ask what a forged event can and cannot do, to price a movement
before it is paid for, and to run the protocol's own golden vectors.

Everything here is analysis of a protocol that is public.  It reads events,
it computes proofs, and it reports what it finds; it never touches a
network, a key or a relay.
"""

from __future__ import annotations

from .audit import (
    AuditReport,
    audit,
    find_forks,
    format_report,
    load_events,
)
from .forgery import (
    ForgeryCase,
    forgery_cases,
    run_forgery_cases,
)
from .probe import (
    MovementCost,
    Probe,
    movement_cost,
    probe,
    region_keys_at,
)
from .vectors import (
    VectorReport,
    load_vector_file,
    run_chain_rules,
    run_gps_vectors,
    run_visualization_vectors,
)

__all__ = [
    "AuditReport",
    "audit",
    "find_forks",
    "format_report",
    "load_events",
    "ForgeryCase",
    "forgery_cases",
    "run_forgery_cases",
    "MovementCost",
    "Probe",
    "movement_cost",
    "probe",
    "region_keys_at",
    "VectorReport",
    "load_vector_file",
    "run_chain_rules",
    "run_gps_vectors",
    "run_visualization_vectors",
]
