"""A from-scratch implementation of the Cyberspace v2 protocol.

The protocol turns a signed Nostr event chain into a place: every event is a
move, every move is priced by the mathematics of the space it crosses, and
the price is what makes the space real.

Modules:

* :mod:`cyberspace.coordinates` - the 256-bit coordinate system (spec 2).
* :mod:`cyberspace.cantor` - Cantor pairing trees and region roots (spec 4).
* :mod:`cyberspace.temporal` - the terrain-derived temporal axis (spec 5).
* :mod:`cyberspace.sidestep` - Merkle-tree wall crossings (spec 6).
* :mod:`cyberspace.region` - region keys, lookup ids and discovery (spec 7).
* :mod:`cyberspace.bags` - content encrypted to a region (spec 7.6).
* :mod:`cyberspace.hints` - the hider's coarse statement of where to look.
* :mod:`cyberspace.nostr` - NIP-01 events and BIP-340 signatures.
* :mod:`cyberspace.chain` - resolving and validating movement chains (spec 8).
* :mod:`cyberspace.gps` - the mapping from WGS84 to dataspace (spec 9).
* :mod:`cyberspace.avatar` - the work an avatar has to pay (spec 8.10).
* :mod:`cyberspace.redteam` - adversarial tests of the verifier itself.
"""

from __future__ import annotations

from .avatar import AvatarPayload, Vertex, avatar_is_paid, avatar_work
from .bags import BagKeyError, decrypt_payload, encrypt_payload
from .cantor import (
    axis_root,
    cantor_pair,
    cantor_unpair,
    compute_subtree_cantor,
    find_lca_height,
    region_n,
)
from .chain import ChainVerdict, resolve_chain
from .constants import (
    CHAIN_RULES_REVISION,
    KIND_AVATAR,
    KIND_BAG,
    KIND_MOVEMENT,
)
from .coordinates import (
    Coordinate,
    coord_to_hex,
    coord_to_xyz,
    hex_to_coord,
    sector_tags,
    xyz_to_coord,
)
from .gps import gps_to_coord
from .hints import Hint, hint_tags, parse_hint
from .movement import hop_proof, movement_region, movement_tags
from .nostr import Event, generate_keypair, new_event
from .region import (
    RegionCache,
    discover,
    region_key,
    region_key_at,
    region_lookup_id,
    region_lookup_id_at,
)
from .sidestep import (
    SidestepProof,
    prove_sidestep,
    verify_sidestep,
    verify_sidestep_level2,
)
from .temporal import hop_preimage, movement_proof_hash, temporal_root, terrain_height

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "CHAIN_RULES_REVISION",
    "KIND_MOVEMENT",
    "KIND_BAG",
    "KIND_AVATAR",
    "Coordinate",
    "xyz_to_coord",
    "coord_to_xyz",
    "coord_to_hex",
    "hex_to_coord",
    "sector_tags",
    "cantor_pair",
    "cantor_unpair",
    "compute_subtree_cantor",
    "find_lca_height",
    "axis_root",
    "region_n",
    "terrain_height",
    "temporal_root",
    "hop_preimage",
    "movement_proof_hash",
    "prove_sidestep",
    "verify_sidestep",
    "verify_sidestep_level2",
    "SidestepProof",
    "region_key",
    "region_lookup_id",
    "region_key_at",
    "region_lookup_id_at",
    "discover",
    "RegionCache",
    "encrypt_payload",
    "decrypt_payload",
    "BagKeyError",
    "Hint",
    "hint_tags",
    "parse_hint",
    "Event",
    "new_event",
    "generate_keypair",
    "resolve_chain",
    "ChainVerdict",
    "gps_to_coord",
    "hop_proof",
    "movement_region",
    "movement_tags",
    "AvatarPayload",
    "Vertex",
    "avatar_work",
    "avatar_is_paid",
]
