"""Independent vectors for XEdDSA over Curve25519 (xeddsa.rs).

Written from Signal's specification, "The XEdDSA and VXEdDSA Signature
Schemes", revision 1, 2016-10-20 (https://signal.org/docs/specifications/xeddsa/),
sections 2.3, 2.5 and 3.3, with the Ed25519 arithmetic of RFC 8032 §5.1 in
plain Python integers:

    calculate_key_pair(k):  E = kB;  A.y = E.y, A.s = 0;  a = -k (mod q) if E.s else k (mod q)
    xeddsa_sign(k, M, Z):   r = hash1(a || M || Z) (mod q);  R = rB;  h = hash(R || A || M) (mod q)
                            s = r + h*a (mod q);  signature = R || s
    xeddsa_verify(u, M, R || s):  u < p, s < q;  A = convert_mont(u) (y = (u - 1)/(u + 1), sign 0)
                            accept iff R == sB - hA

hash is SHA-512 and hash1(X) = SHA-512(0xFE || 0xFF*31 || X). k is the
X25519 private key after the usual clamping, as X25519 itself uses it.

Independent of the Rust code and of this file's own arithmetic, OpenSSL
(through Python's `cryptography`) checks every case twice:

- the X25519 public key `u` that OpenSSL derives from the private key is
  the Montgomery form of this script's `A` (or of `-A`);
- each signature verifies as a standard Ed25519 signature under the
  converted key `A`, which is what the specification promises.

Z is fixed per case, so a rerun prints the same file:

    python -X utf8 tests/vectors/xeddsa.py > tests/vectors/xeddsa.json
"""

import hashlib
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

P = 2**255 - 19
Q = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, -1, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
HASH1_PREFIX = b"\xfe" + b"\xff" * 31

# The device-dh message of a device list entry (diseno-vinculacion.md §3.1),
# so one case signs exactly the shape `dh_sig` signs.
DEVICE_DH_DOMAIN = b"trino/device-dh/v1\x00"


# ---- Ed25519 arithmetic (RFC 8032 §5.1, extended coordinates) ---------------

def point_add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def point_mul(n, pt):
    acc = (0, 1, 1, 0)
    while n > 0:
        if n & 1:
            acc = point_add(acc, pt)
        pt = point_add(pt, pt)
        n >>= 1
    return acc


def point_neg(pt):
    x, y, z, t = pt
    return (-x % P, y, z, -t % P)


def point_equal(p1, p2):
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


IDENTITY = (0, 1, 1, 0)


def recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, -1, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


def compress(pt):
    x, y, z, _ = pt
    zi = pow(z, -1, P)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def decompress(b):
    n = int.from_bytes(b, "little")
    sign = n >> 255
    y = n & ((1 << 255) - 1)
    x = recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


G_Y = 4 * pow(5, -1, P) % P
BASE = (recover_x(G_Y, 0), G_Y, 1, recover_x(G_Y, 0) * G_Y % P)


# ---- XEdDSA (the specification) -------------------------------------------

def clamp(k):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def calculate_key_pair(k_bytes):
    k = clamp(k_bytes)
    e = compress(point_mul(k, BASE))
    e_sign = e[31] >> 7
    a_pub = e[:31] + bytes([e[31] & 0x7F])
    a = (-k) % Q if e_sign else k % Q
    return a_pub, a, e_sign


def sha512_int(data):
    return int.from_bytes(hashlib.sha512(data).digest(), "little")


def xeddsa_sign(k_bytes, msg, z):
    a_pub, a, _ = calculate_key_pair(k_bytes)
    r = sha512_int(HASH1_PREFIX + a.to_bytes(32, "little") + msg + z) % Q
    big_r = compress(point_mul(r, BASE))
    h = sha512_int(big_r + a_pub + msg) % Q
    s_ = (r + h * a) % Q
    return big_r + s_.to_bytes(32, "little")


def convert_mont(u_bytes):
    u = int.from_bytes(u_bytes, "little")
    if u >= P or (u + 1) % P == 0:
        return None
    y = (u - 1) * pow(u + 1, -1, P) % P
    return y.to_bytes(32, "little")  # sign bit 0


def xeddsa_verify(u_bytes, msg, sig):
    a_bytes = convert_mont(u_bytes)
    if a_bytes is None:
        return False
    a_pt = decompress(a_bytes)
    if a_pt is None:
        return False
    # A must be in the prime-order subgroup (an honest one always is).
    if point_equal(point_mul(8, a_pt), IDENTITY) or not point_equal(point_mul(Q, a_pt), IDENTITY):
        return False
    s_ = int.from_bytes(sig[32:], "little")
    if s_ >= Q:
        return False
    h = sha512_int(sig[:32] + a_bytes + msg) % Q
    r_check = point_add(point_mul(s_, BASE), point_neg(point_mul(h, a_pt)))
    return compress(r_check) == sig[:32]


def mont_u_of_edwards(a_bytes):
    y = int.from_bytes(a_bytes, "little") & ((1 << 255) - 1)
    return ((1 + y) * pow(1 - y, -1, P) % P).to_bytes(32, "little")


# ---- Cases --------------------------------------------------------------------

def label(text, n=32):
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(f"{text}/{i}".encode()).digest()
        i += 1
    return out[:n]


def openssl_x25519_public(k_bytes):
    return x25519.X25519PrivateKey.from_private_bytes(k_bytes).public_key().public_bytes(
        s.Encoding.Raw, s.PublicFormat.Raw
    )


def openssl_ed25519_verifies(a_pub, msg, sig):
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(a_pub).verify(sig, msg)
        return True
    except InvalidSignature:
        return False


def case(k, msg, z):
    u = openssl_x25519_public(k)
    a_pub, _, e_sign = calculate_key_pair(k)
    assert mont_u_of_edwards(a_pub) == u, "OpenSSL's X25519 key is not A's Montgomery form"
    assert convert_mont(u) == a_pub
    sig = xeddsa_sign(k, msg, z)
    assert xeddsa_verify(u, msg, sig)
    assert openssl_ed25519_verifies(a_pub, msg, sig), "OpenSSL rejects the signature as Ed25519"
    return {
        "k": k.hex(),
        "u": u.hex(),
        "ed_public": a_pub.hex(),
        "e_sign": e_sign,
        "msg": msg.hex(),
        "z": z.hex(),
        "sig": sig.hex(),
    }


def main():
    cases = []
    seen_signs = set()
    msgs = [
        b"",
        b"\x01",
        label("trino/xeddsa/msg/32"),
        bytes(200),
        DEVICE_DH_DOMAIN + label("trino/xeddsa/A") + (7).to_bytes(4, "big") + label("trino/xeddsa/dev_sign"),
        label("trino/xeddsa/msg/1000", 1000),
    ]
    i = 0
    # Enough keys that both Edwards sign bits appear, so the negation of the
    # private scalar is exercised.
    while len(cases) < 8 or len(seen_signs) < 2:
        k = label(f"trino/xeddsa/k/{i}")
        msg = msgs[i % len(msgs)]
        z = label(f"trino/xeddsa/z/{i}", 64)
        c = case(k, msg, z)
        seen_signs.add(c["e_sign"])
        cases.append(c)
        i += 1
    out = {
        "generator": "tests/vectors/xeddsa.py",
        "spec": "https://signal.org/docs/specifications/xeddsa/ (revision 1, 2016-10-20)",
        "cases": cases,
    }
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
