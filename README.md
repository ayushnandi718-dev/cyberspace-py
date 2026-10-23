# cyberspace-py

A from-scratch Python implementation of the [Cyberspace v2 protocol][spec], the
thermodynamic spatial protocol that prices movement in the mathematics of the
space it crosses.

The repository holds two packages:

* **`cyberspace`** — the protocol itself: the coordinate system, the Cantor
  pairing trees that price a movement, the temporal and sidestep machinery, the
  region keys that hide and reveal content, the Nostr event layer, and the
  movement-chain rules that decide where an identity stands.
* **`secsuite`** — the security auditing toolkit: hash identification, password
  strength, candidate-list building, offline hash recovery, key-derivation cost
  measurement, and the network and Android checks.

Everything here is written from the specification text. Nothing is ported from
another implementation, and the two numbers that the specification locks down —
the chain rules of section 8.12 and the GPS mapping of section 9.8 — are
reproduced exactly.

[spec]: https://github.com/arkin0x/cyberspace

## Install

```bash
pip install .
```

The core protocol needs nothing but the standard library. The optional extras
pull in what the auditing tools use:

```bash
pip install ".[tls]"      # the TLS inspector
pip install ".[hashing]"  # bcrypt and passlib verification
pip install ".[dev]"      # everything, plus pytest
```

## The library

An identity is a key pair. A place is a 256-bit coordinate. A chain is the
sequence of signed events that carries an identity from one place to another.

```python
from cyberspace import (
    Coordinate,
    coord_to_xyz,
    generate_keypair,
    hop_proof,
    new_event,
    resolve_chain,
    sector_tags,
)

secret, pubkey_bytes = generate_keypair()
pubkey = pubkey_bytes.hex()

# An identity's first position is its own public key, read as a coordinate.
here = Coordinate(*coord_to_xyz(int(pubkey, 16)))
# One step along the x axis crosses the lowest boundary and so costs almost nothing.
there = Coordinate(
    here.x + 1 if here.x % 2 == 0 else here.x - 1, here.y, here.z, here.plane
)

sectors = sector_tags(here.x, here.y, here.z)
spawn = new_event(
    secret,
    pubkey,
    3333,
    [["A", "spawn"], ["C", here.hex]]
    + [[tag, sectors[tag]] for tag in ("X", "Y", "Z", "S")],
    "",
    1700000000,
)

proof = hop_proof(bytes.fromhex(spawn.id), here, there)
sectors = sector_tags(there.x, there.y, there.z)
hop = new_event(
    secret,
    pubkey,
    3333,
    [
        ["A", "hop"],
        ["e", spawn.id, "", "genesis"],
        ["e", spawn.id, "", "previous"],
        ["c", here.hex],
        ["C", there.hex],
        ["proof", proof],
    ]
    + [[tag, sectors[tag]] for tag in ("X", "Y", "Z", "S")],
    "",
    1700000001,
)

verdict = resolve_chain([spawn, hop], pubkey)
print(verdict.valid, verdict.reason)
```

The chain rules are strict on purpose. An event that does not carry the tags
its action requires, that names a parent it does not descend from, that
disagrees with its own sector tags, or that forks the chain is rejected with a
reason that says which rule it broke.

### Coordinates

```python
from cyberspace import Coordinate, coord_to_xyz, gps_to_coord, hex_to_coord, xyz_to_coord

coord = xyz_to_coord(19342813113834066795298816, 0, 0, 0)
assert coord_to_xyz(coord)[0] == 19342813113834066795298816

# A place on the earth, in the dataspace plane.
place = gps_to_coord(51.5074, -0.1278)
```

A coordinate is 256 bits: three 85-bit axes interleaved, and one plane bit.
Neighbouring coordinates share bit prefixes, which is what makes a movement
across a short distance cheap and a movement across a long one dear.

### Regions, bags and hints

Content is encrypted to a region, so that only a reader who has done the work
of being there can open it:

```python
from cyberspace import decrypt_payload, encrypt_payload, region_key_at

key = region_key_at(x, y, z, height)
ciphertext = encrypt_payload(b"a note", key)
assert decrypt_payload(ciphertext, key) == b"a note"
```

### Movement proofs

A movement is proven by the mathematics of the region it crossed. The proof
of a hop is the double SHA-256 of the Cantor root of the movement's region:

```python
from cyberspace import hop_preimage, movement_proof_hash, terrain_height

height = terrain_height(x, y, z, 0)
preimage = hop_preimage(region_n, previous_event_id_bytes, (x, y, z, 0))
proof = movement_proof_hash(preimage)
```

## The `cs` command

```bash
cs decode 0000000000000000000000000000000000000000000000000000000000000001
cs gps 51.5074 -0.1278
cs price <from-hex> <to-hex>            # how dear a movement is
cs probe <hex> --max-height 12          # what a reader could open from here
cs audit events.json --pubkey <hex>     # resolve and explain a chain
cs forgery                             # the forgery experiments
cs vectors --fixture-dir <dir>          # the specification's own vectors
```

`cs audit` reports the verdict, the events that were discarded, and the points
at which the chain forked.

## The `secsuite` command

```bash
secsuite identify 5f4dcc3b5aa765d61d8327deb882cf99   # what is this hash?
secsuite password 'Tr0ub4dor&3'                      # how strong is it?
secsuite wordlist --host intranet.example.com --rules capitalise append-year
secsuite kdf --hash '$2b$12$...'                      # what does the hash cost?
secsuite recover <hash> candidate1 candidate2         # offline, hash in hand
secsuite tls example.com --port 443
secsuite http https://example.com/
secsuite scan example.com --ports 22,80,443
```

The recovery tool is the offline half of a password audit: the hash is already
in hand and the question is which candidate produced it. It never touches a
network and never guesses credentials against a service.

## Conformance

The specification locks three sets of numbers that two implementations must
agree on. This one agrees with all of them:

```bash
cs vectors --fixture-dir <the upstream directory>
```

```
ok   chain-rules: 140/140 vectors
ok   visualization: 14/14 vectors
ok   gps: 6/6 vectors
```

## Red team

`cyberspace.redteam` attacks the verifier rather than the protocol: it builds
forged events, broken proofs, wrong sector tags, forks and respawns, and
checks that the rules reject each one for the right reason.

```bash
cs forgery
```

```
ok   baseline: valid
ok   altered-content: valid
ok   forged-signature: valid
ok   signed-wrong-proof: hop-proof
ok   wrong-sector-tag: sector-tags
ok   broken-continuity: c-mismatch
ok   repeated-tag: malformed
ok   fork: fork
ok   unknown-action: valid
ok   no-spawn: no-spawn
ok   spawn-wrong-coordinate: spawn-coordinate
ok   respawn: valid
```

## Tests

```bash
pip install -e ".[dev]"
pytest
```

The suite runs the specification's chain-rule vectors, the GPS and
visualisation vectors, the forgery experiments, and unit tests for the
coordinates, the Cantor trees, the temporal axis, the sidestep proofs, the
region keys, the bags, the hints, the event layer, and the auditing toolkit.

## Licence

The code in this repository is under the MIT licence; see [LICENSE](LICENSE).

The protocol specification itself is not part of this repository and stays
under its own terms. This is an independent implementation of it, written from
the specification text, and the specification is © arkin0x under
[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/legalcode). See
[NOTICE](NOTICE).
