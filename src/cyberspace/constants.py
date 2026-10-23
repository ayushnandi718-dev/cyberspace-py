"""Protocol constants for Cyberspace v2.

Every value here is fixed by the normative specification.  Changing any of
them is a protocol change, not a refactor: a different domain string or a
different bit width produces a different network.  The spec requires that any
change to a domain string bumps its version rather than silently reusing it,
so treat these as frozen.

References are to sections of ``CYBERSPACE_V2.md`` (spec version
``2026-10-08``).
"""

from __future__ import annotations

# --- Coordinate system (spec section 2) ----------------------------------------

AXIS_BITS = 85
"""Bits per spatial axis.  Each of X, Y and Z is an unsigned 85-bit integer."""

AXIS_MAX = (1 << AXIS_BITS) - 1
"""Largest value an axis can hold: 2**85 - 1."""

COORD_BITS = 256
"""Total width of a coordinate: 3 * 85 axis bits plus one plane bit."""

PLANE_DATASPACE = 0
"""Plane bit 0: coordinates map to physical reality through the GPS mapping."""

PLANE_IDEASPACE = 1
"""Plane bit 1: coordinates have no physical counterpart."""

PLANE_NAMES = {PLANE_DATASPACE: "dataspace", PLANE_IDEASPACE: "ideaspace"}

# --- Movement events (spec sections 8.1 to 8.6) --------------------------------

KIND_MOVEMENT = 3333
"""Movement chain event kind: spawn, hop, sidestep, bracket actions."""

KIND_BAG = 33330
"""Encrypted content event kind (a "bag", spec section 8.6)."""

KIND_AVATAR = 11333
"""Replaceable avatar event kind (spec section 8.10)."""

ACTION_SPAWN = "spawn"
ACTION_HOP = "hop"
ACTION_SIDESTEP = "sidestep"
ACTION_ENTER_VIRTUAL = "enter-virtual"
ACTION_EXIT_VIRTUAL = "exit-virtual"
ACTION_ENTER_HYPERSPACE = "enter-hyperspace"
ACTION_HYPERJUMP = "hyperjump"

BASE_ACTIONS = (
    ACTION_SPAWN,
    ACTION_HOP,
    ACTION_SIDESTEP,
    ACTION_ENTER_VIRTUAL,
    ACTION_EXIT_VIRTUAL,
)
"""Action names the base protocol defines (spec section 8.8)."""

DECK_0001_ACTIONS = (
    ACTION_ENTER_HYPERSPACE,
    ACTION_HYPERJUMP,
)
"""Action names DECK-0001 defines, the mandatory hyperspace deck."""

RESERVED_ACTIONS = (
    ACTION_HOP,
    ACTION_SIDESTEP,
    ACTION_ENTER_HYPERSPACE,
    ACTION_HYPERJUMP,
    ACTION_ENTER_VIRTUAL,
)
"""Action names a game may not reuse inside a virtual bracket (spec section 8.11.4)."""

CHAIN_RULES_REVISION = "2026-09-28-virtual-brackets"
"""The chain rules revision this implementation targets (spec section 8.12)."""

# --- Terrain / temporal axis (spec section 5.2) --------------------------------

TERRAIN_DOMAIN_V2 = b"CYBERSPACE_TERRAIN_K_V2"
"""Domain separator for the terrain height function."""

TERRAIN_CELL_BITS = (3, 7, 9, 11)
"""The four cell widths whose nibbles compose the 16-bit terrain word."""

TERRAIN_MAX_K = 16
"""K is a popcount of a 16-bit word, so it lies in [0, 16]."""

# --- Sidestep (spec sections 6.4, 6.10) ----------------------------------------

SIDESTEP_DOMAIN = b"CYBERSPACE_SIDESTEP_V2"
"""Domain separator for sidestep leaf hashes (version 2 of the construction)."""

SEED_PAD = b"\x00" * 9
"""Padding that brings a sidestep seed prefix to exactly one SHA-256 block."""

SIDESTEP_GRIND_DOMAIN = b"CYBERSPACE_SIDESTEP_GRIND_V1"
"""Domain separator for the re-roll price hash G."""

SIDESTEP_SAMPLE_DOMAIN = b"CYBERSPACE_SIDESTEP_SAMPLE_V2"
"""Domain separator for deriving sampled opening indices from G."""

SIDESTEP_SAMPLES = 8
"""Number of sampled openings published per non-trivial axis."""

AXIS_X, AXIS_Y, AXIS_Z = 0x00, 0x01, 0x02
"""Axis byte values used in the sidestep seed prefix."""

AXIS_BYTES = (AXIS_X, AXIS_Y, AXIS_Z)
AXIS_NAMES = {AXIS_X: "x", AXIS_Y: "y", AXIS_Z: "z"}

SIDESTEP_VERSION = 3
"""The sidestep construction this implementation builds and verifies."""

# --- Hyperspace (DECK-0001) ----------------------------------------------------

HYPERSPACE_K_LINE = 6
"""Height added to a block's terrain popcount to give the height of its tree."""

HYPERSPACE_SAMPLES = 32
"""Number of sampled openings published for a ride."""

HYPERSPACE_GRIND_HEIGHT = 16
"""Height of the Cantor tree that one re-roll attempt costs."""

# --- Sectors (spec section 10) -------------------------------------------------

SECTOR_SHIFT = 30
"""A sector is 2**30 Gibsons per axis."""

SECTOR_BITS = AXIS_BITS - SECTOR_SHIFT
"""A sector index needs 55 bits per axis, not 32.  Use 64-bit integers."""

# --- GPS mapping (spec section 9.5) --------------------------------------------

CANONICAL_GPS_TO_DATASPACE_SPEC_VERSION = "2026-03-16-h34-corrected"
"""Version string of the canonical GPS-to-dataspace mapping."""

GPS_PRECISION = 96
"""Decimal precision used throughout the GPS mapping."""

GPS_PI_STR = (
    "3.141592653589793238462643383279502884197169399375105820974944592307"
    "8164062862089986280348253421170679"
)
"""Exact truncated decimal string for pi.  Do not use the platform libm."""

GPS_TRIG_EPS = "1e-88"
"""Termination epsilon for the deterministic Taylor-series trigonometry."""

GPS_TRIG_MAX_ITER = 256
"""Maximum iterations for the deterministic trigonometry."""

UNITS_PER_KM = 1000 * (1 << 33)
"""Gibsons per kilometre at the Cantor Height 34 calibration."""

GIBSONS_PER_METER = 1 / (1 << 33)
"""Metres per Gibson at the Cantor Height 34 calibration."""

# --- Bag cipher (spec section 7.6) ---------------------------------------------

BAG_CIPHER = "aes-256-gcm"
BAG_NONCE_BYTES = 12
BAG_TAG_BYTES = 16

# --- Versioning ----------------------------------------------------------------

__all__ = [name for name in dir() if not name.startswith("_")]
