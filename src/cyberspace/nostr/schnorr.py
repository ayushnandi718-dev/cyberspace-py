"""BIP-340 Schnorr signatures over secp256k1, in pure Python.

Nostr uses BIP-340 for event signatures, and the Cyberspace chain rules
require that a reader verify a signature itself: relays commonly verify
signatures, but a reader cannot know which relays did, so it checks.

No third-party dependency: the curve arithmetic is about eighty lines and
runs fast enough for a handful of events per second.

The arithmetic is Jacobian, so a scalar multiplication costs one modular
inversion instead of one per addition.  That matters: a chain check verifies
a signature per event, and an affine implementation spends all its time in
Fermat's little theorem.
"""

from __future__ import annotations

import hashlib
import secrets

__all__ = [
    "P",
    "N",
    "G",
    "generate_keypair",
    "sign",
    "verify",
    "pubkey_from_secret",
    "point_add",
    "point_mul",
    "point_neg",
    "lift_x",
    "tagged_hash",
]

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
"""The secp256k1 field prime."""

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
"""The secp256k1 group order."""

G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
"""The base point."""

Point = tuple[int, int] | None
"""An affine curve point, or ``None`` for the point at infinity."""

# A Jacobian point (X, Y, Z) stands for the affine point (X/Z^2, Y/Z^3).
_Jacobian = tuple[int, int, int]


def tagged_hash(tag: str, message: bytes) -> bytes:
    """BIP-340 tagged hash: ``SHA256(SHA256(tag) || SHA256(tag) || msg)``."""
    tag_hash = hashlib.sha256(tag.encode("utf-8")).digest()
    return hashlib.sha256(tag_hash + tag_hash + message).digest()


def _inv(value: int) -> int:
    return pow(value, P - 2, P)


def _jac_from_affine(point: Point) -> _Jacobian | None:
    if point is None:
        return None
    return (point[0], point[1], 1)


def _jac_to_affine(point: _Jacobian | None) -> Point:
    if point is None:
        return None
    x, y, z = point
    if z == 0:
        return None
    z_inv = _inv(z)
    z_inv2 = z_inv * z_inv % P
    return (x * z_inv2 % P, y * z_inv2 % P * z_inv % P)


def _jac_double(point: _Jacobian | None) -> _Jacobian | None:
    """Double a Jacobian point (curve parameter a = 0)."""
    if point is None:
        return None
    x, y, z = point
    if y == 0 or z == 0:
        return None
    xx = x * x % P
    yy = y * y % P
    yyyy = yy * yy % P
    zz = z * z % P
    s = 2 * ((x + yy) * (x + yy) - xx - yyyy) % P
    m = 3 * xx % P
    t = (m * m - 2 * s) % P
    y3 = (m * (s - t) - 8 * yyyy) % P
    z3 = ((y + z) * (y + z) - yy - zz) % P
    return (t, y3, z3)


def _jac_add(p1: _Jacobian | None, p2: _Jacobian | None) -> _Jacobian | None:
    """Add two Jacobian points."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    z1z1 = z1 * z1 % P
    z2z2 = z2 * z2 % P
    u1 = x1 * z2z2 % P
    u2 = x2 * z1z1 % P
    s1 = y1 * z2 % P * z2z2 % P
    s2 = y2 * z1 % P * z1z1 % P
    if u1 == u2:
        if s1 != s2:
            return None
        return _jac_double(p1)
    h = (u2 - u1) % P
    i = (2 * h) % P
    i = i * i % P
    j = h * i % P
    r = 2 * (s2 - s1) % P
    v = u1 * i % P
    x3 = (r * r - j - 2 * v) % P
    y3 = (r * (v - x3) - 2 * s1 * j) % P
    z3 = ((z1 + z2) * (z1 + z2) - z1z1 - z2z2) % P
    z3 = z3 * h % P
    return (x3, y3, z3)



def _jac_mul(scalar: int, point: _Jacobian | None) -> _Jacobian | None:
    """Multiply a Jacobian point by a scalar, double-and-add."""
    if point is None or scalar % N == 0:
        return None
    scalar %= N
    result: _Jacobian | None = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _jac_add(result, addend)
        addend = _jac_double(addend)
        scalar >>= 1
    return result


def point_neg(point: Point) -> Point:
    """The point mirrored through the x axis."""
    if point is None:
        return None
    return (point[0], (-point[1]) % P)


def point_add(p1: Point, p2: Point) -> Point:
    """Add two curve points."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    return _jac_to_affine(_jac_add(_jac_from_affine(p1), _jac_from_affine(p2)))


def point_mul(scalar: int, point: Point = G) -> Point:
    """Multiply a curve point by a scalar."""
    if point is None:
        return None
    return _jac_to_affine(_jac_mul(scalar, _jac_from_affine(point)))


def lift_x(x: int) -> Point:
    """Recover the even-y curve point with the given x coordinate."""
    if x >= P:
        raise ValueError("x coordinate is out of range")
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        raise ValueError("x coordinate is not on the curve")
    if y & 1:
        y = P - y
    return (x, y)


def generate_keypair() -> tuple[int, bytes]:
    """A fresh secret key and its 32-byte compressed public key.

    The public key is the x coordinate of the point, so the point itself is
    the even-y representative: BIP-340 defines a public key that way, and
    a secret whose point has an odd y is used with its sign flipped.
    """
    while True:
        secret = secrets.randbelow(N)
        if secret == 0:
            continue
        point = point_mul(secret)
        if point is None:
            continue
        if point[1] & 1:
            secret = N - secret
            point = point_neg(point)
        return secret, point[0].to_bytes(32, "big")


def pubkey_from_secret(secret: int) -> bytes:
    """The compressed public key for a secret key."""
    point = point_mul(secret)
    if point is None:
        raise ValueError("secret key is out of range")
    if point[1] & 1:
        point = point_neg(point)
    return point[0].to_bytes(32, "big")


def sign(message: bytes, secret: int, aux: bytes = b"\x00" * 32) -> bytes:
    """Sign a 32-byte message hash with a BIP-340 Schnorr signature."""
    if not 0 < secret < N:
        raise ValueError("secret key is out of range")
    point = point_mul(secret)
    if point is None:
        raise ValueError("secret key is out of range")
    if point[1] & 1:
        # The public key is x only, so the point it names is the even-y
        # one, which the negated secret produces.
        secret = N - secret
        point = point_neg(point)
    pubkey = point[0].to_bytes(32, "big")

    t = secret ^ int.from_bytes(tagged_hash("BIP0340/aux", aux), "big")
    rand = tagged_hash(
        "BIP0340/nonce",
        t.to_bytes(32, "big") + pubkey + message,
    )
    k = int.from_bytes(rand, "big") % N
    if k == 0:
        raise ValueError("degenerate nonce")
    r_point = point_mul(k)
    if r_point is None:
        raise ValueError("degenerate nonce")
    if r_point[1] & 1:
        # BIP-340 uses the even-y representative of R.
        k = N - k
        r_point = point_neg(r_point)
    r_bytes = r_point[0].to_bytes(32, "big")

    challenge = int.from_bytes(
        tagged_hash("BIP0340/challenge", r_bytes + pubkey + message), "big"
    ) % N
    s = (k + challenge * secret) % N
    return r_bytes + s.to_bytes(32, "big")


def verify(message: bytes, pubkey: bytes, signature: bytes) -> bool:
    """Verify a BIP-340 Schnorr signature over a 32-byte message hash."""
    if len(pubkey) != 32 or len(signature) != 64:
        return False
    try:
        p_point = lift_x(int.from_bytes(pubkey, "big"))
    except ValueError:
        return False

    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if r >= P or s >= N:
        return False

    challenge = int.from_bytes(
        tagged_hash("BIP0340/challenge", signature[:32] + pubkey + message), "big"
    ) % N

    # R = s*G - e*P, computed in Jacobian coordinates.
    p_jac = _jac_from_affine(p_point)
    neg_p = (p_jac[0], (-p_jac[1]) % P, p_jac[2])  # type: ignore[index]
    result = _jac_add(_jac_mul(s, _jac_from_affine(G)), _jac_mul(challenge, neg_p))
    affine = _jac_to_affine(result)
    if affine is None:
        return False
    if affine[1] & 1:
        return False
    return affine[0] == r
