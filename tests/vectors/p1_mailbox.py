"""Independent P1 mailbox vectors for trino-core's p1/mailbox.rs.

Computes the derivations of design P1 §3.2-§3.4 (with the device keys of
diseno-vinculacion.md §4.1) with Python's `cryptography` package (OpenSSL),
which shares no code with the Rust implementation:

    S_intro   = HKDF(ikm = X25519(dh_a, dh_b), salt = "trino/p1/v1/intro" || lo || hi, info = "seed")
    s_e       = HKDF(ikm = S, salt = "", info = "epoch" || e u32 BE)
    s_e+1     = HKDF(ikm = s_e, salt = "", info = "next")
    S_ses     = HKDF(ikm = master_secret, salt = "trino/p1/v1/session", info = AD)
    sk_mbox   = HKDF(ikm = s, salt = "", info = "mbox" || d || gen || ctr), as a secp256k1 scalar
    mailbox   = x-only(sk_mbox * G)
    k_mac     = HKDF(ikm = s, salt = "", info = "mac" || d || gen)
    k_dedup   = HKDF(ikm = s, salt = "", info = "dedup")

Every HKDF is HKDF-SHA256 with a 32-byte output. An empty salt is the
RFC 5869 default (32 zero bytes).

    python -X utf8 tests/vectors/p1_mailbox.py > tests/vectors/p1_mailbox.json
"""

import hashlib
import json
import struct
import sys

import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, salt if salt else None, info).derive(ikm)


def x25519_pair(label: str):
    sk = x25519.X25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())
    from cryptography.hazmat.primitives import serialization as s

    pub = sk.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
    priv = sk.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
    return sk, priv, pub


def intro_seed(sk, my_pub: bytes, their_pub: bytes) -> bytes:
    dh = sk.exchange(x25519.X25519PublicKey.from_public_bytes(their_pub))
    lo, hi = sorted([my_pub, their_pub])
    return hkdf(dh, b"trino/p1/v1/intro" + lo + hi, b"seed")


def epoch_secret(seed: bytes, e: int) -> bytes:
    return hkdf(seed, b"", b"epoch" + struct.pack(">I", e))


def next_epoch(s: bytes) -> bytes:
    return hkdf(s, b"", b"next")


def mailbox(s: bytes, d: int, gen: int):
    for ctr in range(256):
        k = int.from_bytes(hkdf(s, b"", b"mbox" + bytes([d, gen, ctr])), "big")
        if 0 < k < N:
            pub = ec.derive_private_key(k, ec.SECP256K1()).public_key()
            return {
                "ctr": ctr,
                "sk": k.to_bytes(32, "big").hex(),
                "mailbox": pub.public_numbers().x.to_bytes(32, "big").hex(),
                "k_mac": hkdf(s, b"", b"mac" + bytes([d, gen])).hex(),
            }
    raise AssertionError("no scalar in 256 tries")


def main():
    out = {
        "generator": "tests/vectors/p1_mailbox.py",
        "cryptography": cryptography.__version__,
        "intro": [],
        "session": [],
        "mailboxes": [],
        "low_order": [],
    }
    for i in range(4):
        sa, priv_a, pub_a = x25519_pair(f"trino/p1-mailbox/a/{i}")
        sb, priv_b, pub_b = x25519_pair(f"trino/p1-mailbox/b/{i}")
        seed = intro_seed(sa, pub_a, pub_b)
        assert seed == intro_seed(sb, pub_b, pub_a)
        e = 20_388 + i  # days since 1970: late October 2025 onwards
        s_e = epoch_secret(seed, e)
        out["intro"].append(
            {
                "priv_a": priv_a.hex(),
                "pub_a": pub_a.hex(),
                "priv_b": priv_b.hex(),
                "pub_b": pub_b.hex(),
                "intro_seed": seed.hex(),
                "epoch": e,
                "epoch_secret": s_e.hex(),
                "k_dedup": hkdf(s_e, b"", b"dedup").hex(),
            }
        )
    for i in range(3):
        master = hashlib.sha256(f"trino/p1-mailbox/master/{i}".encode()).digest()
        ad = hashlib.sha256(f"trino/p1-mailbox/ad/{i}".encode()).digest() * (i + 1)
        s_ses = hkdf(master, b"trino/p1/v1/session", ad)
        e0 = 20_400 + i
        chain = [epoch_secret(s_ses, e0)]
        for _ in range(3):
            chain.append(next_epoch(chain[-1]))
        out["session"].append(
            {
                "master_secret": master.hex(),
                "ad": ad.hex(),
                "session_seed": s_ses.hex(),
                "e0": e0,
                "chain": [c.hex() for c in chain],
            }
        )
    for i in range(3):
        s = hashlib.sha256(f"trino/p1-mailbox/s/{i}".encode()).digest()
        for d in (0, 1):
            for gen in (0, 1):
                out["mailboxes"].append({"s": s.hex(), "d": d, "gen": gen, **mailbox(s, d, gen)})
    # Low-order X25519 points: OpenSSL refuses the all-zero shared secret.
    sa, _, _ = x25519_pair("trino/p1-mailbox/a/0")
    for u in [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ]:
        try:
            sa.exchange(x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(u)))
            raise AssertionError(f"OpenSSL accepted low-order point {u}")
        except ValueError:
            out["low_order"].append(u)
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
