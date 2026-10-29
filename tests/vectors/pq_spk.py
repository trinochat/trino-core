"""Independent vectors for the signed post-quantum prekey (pq_spk.rs).

diseno-vinculacion.md §21.3:

    pq_spk     = id u32 BE || ek 1184
    pq_spk_sig = Ed25519(dev_sign, "trino/pqspk/v1\\0" || id || ek)     -> 1252 bytes in all

OpenSSL (through Python's `cryptography`) derives the ML-KEM-768 key from a
seed and signs with Ed25519, which is deterministic (RFC 8032), so the Rust
side must produce the very same bytes.

    python -X utf8 tests/vectors/pq_spk.py > tests/vectors/pq_spk.json
"""

import hashlib
import json
import struct
import sys

from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import ed25519, mlkem

DOMAIN = b"trino/pqspk/v1\x00"


def main():
    out = {"generator": "tests/vectors/pq_spk.py", "cases": []}
    for i, pq_id in enumerate([1, 2, 0x7FFFFFFF, 0xFFFFFFFE]):
        sign_seed = hashlib.sha256(f"trino/pq-spk/dev_sign/{i}".encode()).digest()
        kem_seed = hashlib.sha256(f"trino/pq-spk/kem/{i}".encode()).digest() * 2
        dev_sign = ed25519.Ed25519PrivateKey.from_private_bytes(sign_seed)
        dev_pub = dev_sign.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
        ek = mlkem.MLKEM768PrivateKey.from_seed_bytes(kem_seed).public_key().public_bytes(
            s.Encoding.Raw, s.PublicFormat.Raw
        )
        body = struct.pack(">I", pq_id) + ek
        sig = dev_sign.sign(DOMAIN + body)
        signed = body + sig
        assert len(signed) == 1252
        out["cases"].append(
            {
                "dev_sign_priv": sign_seed.hex(),
                "dev_sign_pub": dev_pub.hex(),
                "kem_seed": kem_seed.hex(),
                "id": pq_id,
                "signed_sha256": hashlib.sha256(signed).hexdigest(),
                "sig": sig.hex(),
            }
        )
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
