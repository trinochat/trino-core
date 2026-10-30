"""Independent vectors for the device list (device/list.rs).

diseno-vinculacion.md §3.1 with the §21.4 header (all integers big-endian):

    list  = "trino/devices/v1\\0" 17 || sig_suite u8 || A 32 || gen u32 || seq u64
          || issued u64 || expires u64 || prev 32 || next 32 || rot 32 || rot_key 32
          || rot_pqh 32 || n u8 (1..=5) || entries[n] || sig 64 || rot_sig 64
    entry = id u32 || flags u8 (bit0 primary, bit1 groups) || dev_sign 32 || dev_dh 32
          || since (gen u32, seq u64) 12 || d_sig 64 || dh_sig 64                  -> 209 bytes
    d_sig   = Ed25519(dev_sign, "trino/device/v1\\0" || A || id || dev_dh)
    dh_sig  = XEdDSA(dev_dh, "trino/device-dh/v1\\0" || A || id || dev_sign)
    sig     = Ed25519(A, everything before sig)
    rot_sig = Ed25519(rot_key, the same bytes) in a rotation; zeros otherwise

A list is 367 + 209*n bytes. OpenSSL (through Python's `cryptography`)
makes the Ed25519 keys and signatures, which are deterministic, and the
X25519 keys; `dh_sig` comes from `xeddsa.py` (this directory) with a fixed
Z, and OpenSSL checks it as Ed25519 under the converted key. Rerunning the
script prints the same file:

    python -X utf8 tests/vectors/device_list.py > tests/vectors/device_list.json
"""

import hashlib
import json
import struct
import sys

from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import ed25519

import xeddsa

LIST_DOMAIN = b"trino/devices/v1\x00"
ENTRY_DOMAIN = b"trino/device/v1\x00"
DH_DOMAIN = b"trino/device-dh/v1\x00"
RESERVE_DOMAIN = b"trino/reserve/v2\x00"
DAY = 86400


def seed(text):
    return hashlib.sha256(text.encode()).digest()


def ed_key(text):
    k = ed25519.Ed25519PrivateKey.from_private_bytes(seed(text))
    return k, k.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)


def entry(account, dev_id, flags, since, name):
    dev_sign, dev_sign_pub = ed_key(f"trino/device-list/dev_sign/{name}")
    dh_priv = seed(f"trino/device-list/dev_dh/{name}")
    dev_dh = xeddsa.openssl_x25519_public(dh_priv)
    d_sig = dev_sign.sign(ENTRY_DOMAIN + account + struct.pack(">I", dev_id) + dev_dh)
    dh_msg = DH_DOMAIN + account + struct.pack(">I", dev_id) + dev_sign_pub
    z = hashlib.sha512(f"trino/device-list/z/{name}".encode()).digest()
    dh_sig = xeddsa.xeddsa_sign(dh_priv, dh_msg, z)
    assert xeddsa.openssl_ed25519_verifies(xeddsa.convert_mont(dev_dh), dh_msg, dh_sig)
    raw = (
        struct.pack(">IB", dev_id, flags)
        + dev_sign_pub
        + dev_dh
        + struct.pack(">IQ", *since)
        + d_sig
        + dh_sig
    )
    assert len(raw) == 209
    return raw, {
        "dev_sign_seed": seed(f"trino/device-list/dev_sign/{name}").hex(),
        "dev_dh_priv": dh_priv.hex(),
    }


def build(name, account_key, gen, seq, issued, expires, prev, nxt, devices, rotation=None):
    account = account_key.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
    rot = rot_key = rot_pqh = bytes(32)
    if rotation is not None:
        old_account, reserve_key, rot_pqh = rotation
        rot = old_account
        rot_key = reserve_key.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
    entries = []
    secrets = []
    for dev_id, flags, since, dev_name in devices:
        raw, sec = entry(account, dev_id, flags, since, dev_name)
        entries.append(raw)
        secrets.append(sec)
    body = (
        LIST_DOMAIN
        + bytes([0x01])
        + account
        + struct.pack(">IQQQ", gen, seq, issued, expires)
        + prev
        + nxt
        + rot
        + rot_key
        + rot_pqh
        + bytes([len(entries)])
        + b"".join(entries)
    )
    sig = account_key.sign(body)
    rot_sig = reserve_key.sign(body) if rotation is not None else bytes(64)
    raw = body + sig + rot_sig
    assert len(raw) == 367 + 209 * len(entries)
    return raw, {
        "name": name,
        "account_seed": account_key.private_bytes(
            s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption()
        ).hex(),
        "devices": secrets,
        "list": raw.hex(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def commitment(b_ed_pub, pq_hash):
    return hashlib.sha256(RESERVE_DOMAIN + b_ed_pub + pq_hash).digest()


def main():
    a_key, _ = ed_key("trino/device-list/A")
    t0 = 1_793_000_000

    # The first list of a migrated account: one primary device, no reserve.
    first, c_first = build("first", a_key, 1, 1, t0, t0 + 90 * DAY, bytes(32), bytes(32), [(0x1A2B3C4D, 0x01, (1, 1), "pc")])

    # Five devices, the primary with groups, a reserve commitment, prev set.
    b_key, b_pub = ed_key("trino/device-list/B")
    pq_hash = hashlib.sha256(b"trino/device-list/B_pq_pub").digest()
    nxt = commitment(b_pub, pq_hash)
    five, c_five = build(
        "five",
        a_key,
        1,
        2,
        t0 + DAY,
        t0 + 91 * DAY,
        hashlib.sha256(first).digest(),
        nxt,
        [
            (0x1A2B3C4D, 0x03, (1, 1), "pc"),
            (7, 0x00, (1, 2), "phone"),
            (8, 0x02, (1, 2), "tablet"),
            (0xFFFFFFFF, 0x00, (1, 2), "laptop"),
            (0, 0x00, (1, 2), "old-phone"),
        ],
    )

    # A rotation: generation 2, signed by the new A* and by the reserve key B.
    a_star, _ = ed_key("trino/device-list/A*")
    b2_key, b2_pub = ed_key("trino/device-list/B'")
    nxt2 = commitment(b2_pub, hashlib.sha256(b"trino/device-list/B'_pq_pub").digest())
    a_pub = a_key.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
    rotation, c_rot = build(
        "rotation",
        a_star,
        2,
        1,
        t0 + 10 * DAY,
        t0 + 100 * DAY,
        hashlib.sha256(five).digest(),
        nxt2,
        [(7, 0x01, (2, 1), "phone")],
        rotation=(a_pub, b_key, pq_hash),
    )
    c_rot["reserve_seed"] = seed("trino/device-list/B").hex()
    c_rot["reserve_pq_hash"] = pq_hash.hex()

    out = {"generator": "tests/vectors/device_list.py", "cases": [c_first, c_five, c_rot]}
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
