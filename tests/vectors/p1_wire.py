"""Independent P1 inner-frame vectors for trino-core's p1/wire.rs.

Builds inner frames (design P1 §2.2, with the hybrid types of
diseno-vinculacion.md §21.4 and §21.8) byte by byte with Python's standard
library, and finds a 24-bit proof of work for a type 3, so the Rust code is
checked against bytes it did not produce:

    inner = ver 1 || type u8 || ts u64 BE || len u32 BE || body || zeros || mac 32   (exactly E bytes)
    mac   = HMAC-SHA256(k_mac, "trino/p1/v1/inner" || inner[..E-32])                 (types 1, 2, 4)
    mac   = 32 zero bytes                                                            (type 3)
    pow   = SHA-256("trino/p1/v2/pow" || R || SHA-256(type 3 body after pow_nonce) || pow_nonce u64 BE)

    python -X utf8 tests/vectors/p1_wire.py > tests/vectors/p1_wire.json

Inputs come from fixed labels, so a rerun prints the same file (the proof of
work search takes a few seconds).
"""

import hashlib
import hmac
import json
import struct
import sys


def det(label: str, n: int) -> bytes:
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(f"{label}/{i}".encode()).digest()
        i += 1
    return out[:n]


def inner(ver: int, typ: int, ts: int, body: bytes, step: int, k_mac) -> bytes:
    head = bytes([ver, typ]) + struct.pack(">QI", ts, len(body)) + body
    head += b"\x00" * (step - 32 - len(head))
    assert len(head) == step - 32
    if k_mac is None:
        return head + b"\x00" * 32
    mac = hmac.new(k_mac, b"trino/p1/v1/inner" + head, hashlib.sha256).digest()
    return head + mac


def type1(label: str, ct_len: int) -> bytes:
    return (
        det(label + "/dh", 32)
        + struct.pack(">II", 3, 7)
        + det(label + "/nonce", 12)
        + det(label + "/ct", ct_len)
    )


def leading_zero_bits(h: bytes) -> int:
    n = 0
    for b in h:
        if b == 0:
            n += 8
            continue
        n += 8 - b.bit_length()
        break
    return n


def find_pow(r: bytes, rest: bytes, bits: int) -> int:
    h = hashlib.sha256(rest).digest()
    prefix = hashlib.sha256(b"trino/p1/v2/pow" + r + h)
    nonce = 0
    while True:
        d = prefix.copy()
        d.update(struct.pack(">Q", nonce))
        if leading_zero_bits(d.digest()) >= bits:
            return nonce
        nonce += 1


def entry(name, typ, step, ts, body, k_mac, frame):
    return {
        "name": name,
        "type": typ,
        "step": step,
        "ts": ts,
        "body": body.hex(),
        "k_mac": k_mac.hex() if k_mac else None,
        "inner_sha256": hashlib.sha256(frame).hexdigest(),
        "mac": frame[-32:].hex(),
    }


def main():
    k_mac = det("trino/p1-wire/k_mac", 32)
    ts = 1_793_102_400
    out = {"generator": "tests/vectors/p1_wire.py", "frames": [], "pow": []}

    # Type 1 at each step; an empty-capacity-adjacent body at 1 KiB.
    for step, ct_len in [(1024, 100), (1024, 1024 - 46 - 52), (4096, 2000), (16384, 3000), (40960, 3000)]:
        body = type1(f"trino/p1-wire/t1/{step}/{ct_len}", ct_len)
        out["frames"].append(entry(f"type1-{step}-{ct_len}", 1, step, ts, body, k_mac, inner(1, 1, ts, body, step, k_mac)))

    # Type 2: suite 1, pq_spk_id, ct 1088, dev_dh, ek, spk_id, opk_id none, then a type 1 body.
    t2 = (
        b"\x01"
        + struct.pack(">I", 0x01020304)
        + det("trino/p1-wire/t2/ct", 1088)
        + det("trino/p1-wire/t2/dev_dh", 32)
        + det("trino/p1-wire/t2/ek", 32)
        + struct.pack(">II", 42, 0xFFFFFFFF)
        + type1("trino/p1-wire/t2/msg", 500)
    )
    out["frames"].append(entry("type2-4096", 2, 4096, ts, t2, k_mac, inner(1, 2, ts, t2, 4096, k_mac)))

    # Type 4: ct 1088, then a type 1 body.
    t4 = det("trino/p1-wire/t4/ct", 1088) + type1("trino/p1-wire/t4/msg", 300)
    out["frames"].append(entry("type4-4096", 4, 4096, ts, t4, k_mac, inner(1, 4, ts, t4, 4096, k_mac)))

    # Type 3: pow_nonce, suite, con_kem, e, dev_dh, [ct_R], sealed part.
    r = det("trino/p1-wire/t3/R", 32)
    for con_kem, sealed_len in [(0, 1500), (1, 2500)]:
        rest = (
            b"\x01"
            + bytes([con_kem])
            + det("trino/p1-wire/t3/e", 32)
            + det("trino/p1-wire/t3/dev_dh", 32)
            + (det("trino/p1-wire/t3/ct_R", 1088) if con_kem else b"")
            + det(f"trino/p1-wire/t3/sealed/{con_kem}", sealed_len)
        )
        nonce = find_pow(r, rest, 24)
        body = struct.pack(">Q", nonce) + rest
        h = hashlib.sha256(b"trino/p1/v2/pow" + r + hashlib.sha256(rest).digest() + struct.pack(">Q", nonce)).digest()
        out["frames"].append(entry(f"type3-kem{con_kem}", 3, 16384, ts, body, None, inner(1, 3, ts, body, 16384, None)))
        out["pow"].append(
            {
                "R": r.hex(),
                "body": body.hex(),
                "nonce": nonce,
                "hash": h.hex(),
                "zero_bits": leading_zero_bits(h),
            }
        )
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
