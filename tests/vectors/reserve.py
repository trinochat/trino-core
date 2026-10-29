"""Independent vectors for the hybrid reserve key (src/reserve.rs).

diseno-vinculacion.md §21.9:

    B         = (B_ed: Ed25519, B_pq: ML-DSA-65 generated from a 32-byte seed xi)
    rot_pqh   = SHA-256(B_pq_pub)
    next      = SHA-256("trino/reserve/v2\\0" || B_ed_pub || rot_pqh)
    blob      = nonce 12 || AES-256-GCM(k_reserva, B_ed_priv || xi,
                                        aad = "trino/reserve/v2\\0" || next)   -> 92 bytes

OpenSSL (through Python's `cryptography`) computes the Ed25519 and ML-DSA-65
public keys from their seeds and seals the blob. The vault's `kit` field
then holds

    record = version 1 || h_check 32 || next 32 || blob 92                  -> 157 bytes

The first case seals with the `k_reserva` of the all-zero kit in kit.json.

    python -I -X utf8 tests/vectors/reserve.py > tests/vectors/reserve.json
"""

import hashlib
import json
import sys

from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DOMAIN = b"trino/reserve/v2\x00"
# k_reserva and h_check of the all-zero kit (kit.json, "keys"[0]).
ZERO_KIT_K_RESERVA = bytes.fromhex("ffface18ab495683f40a46f4c79a6e94e0c001fc1fd8da698fbbc7474d72b87e")
ZERO_KIT_H_CHECK = bytes.fromhex("928876abb08ef013d53b7ec42d13fe51af3895dd4053b943a009997839ead7fe")


def h(label):
    return hashlib.sha256(label.encode()).digest()


def main():
    out = {"generator": "tests/vectors/reserve.py", "cases": []}
    for i in range(4):
        ed_seed = h(f"trino/reserve/vector/ed/{i}")
        xi = h(f"trino/reserve/vector/xi/{i}")
        k_reserva = ZERO_KIT_K_RESERVA if i == 0 else h(f"trino/reserve/vector/k/{i}")
        h_check = ZERO_KIT_H_CHECK if i == 0 else h(f"trino/reserve/vector/h/{i}")
        nonce = h(f"trino/reserve/vector/nonce/{i}")[:12]
        ed_pub = ed25519.Ed25519PrivateKey.from_private_bytes(ed_seed).public_key().public_bytes(
            s.Encoding.Raw, s.PublicFormat.Raw
        )
        pq_pub = mldsa.MLDSA65PrivateKey.from_seed_bytes(xi).public_key().public_bytes(
            s.Encoding.Raw, s.PublicFormat.Raw
        )
        assert len(pq_pub) == 1952
        rot_pqh = hashlib.sha256(pq_pub).digest()
        nxt = hashlib.sha256(DOMAIN + ed_pub + rot_pqh).digest()
        blob = nonce + AESGCM(k_reserva).encrypt(nonce, ed_seed + xi, DOMAIN + nxt)
        assert len(blob) == 92
        record = bytes([1]) + h_check + nxt + blob
        assert len(record) == 157
        out["cases"].append(
            {
                "ed_seed": ed_seed.hex(),
                "xi": xi.hex(),
                "k_reserva": k_reserva.hex(),
                "h_check": h_check.hex(),
                "nonce": nonce.hex(),
                "ed_pub": ed_pub.hex(),
                "pq_pub_sha256": rot_pqh.hex(),
                "next": nxt.hex(),
                "blob": blob.hex(),
                "record": record.hex(),
            }
        )
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
