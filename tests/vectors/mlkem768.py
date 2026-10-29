"""Independent ML-KEM-768 vectors for trino-core's kem.rs.

OpenSSL (through Python's `cryptography`) makes each key pair from a 64-byte
seed (d || z, FIPS 203), encapsulates with its own randomness, and
decapsulates a ciphertext with one bit flipped (implicit rejection). The
Rust side checks that libcrux, from the same seed, gives the same public key
and recovers the same shared secrets. Neither side made the other's bytes.

    python -X utf8 tests/vectors/mlkem768.py > tests/vectors/mlkem768.json

Encapsulation is randomized inside OpenSSL, so a rerun prints different
ciphertexts; the file in the repository is the one the tests read.
"""

import hashlib
import json
import sys

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import mlkem


def main():
    out = {
        "generator": "tests/vectors/mlkem768.py",
        "cryptography": cryptography.__version__,
        "openssl": backend.openssl_version_text(),
        "cases": [],
    }
    for i in range(6):
        seed = hashlib.sha256(f"trino/mlkem768/seed/{i}".encode()).digest() + hashlib.sha256(
            f"trino/mlkem768/seed2/{i}".encode()
        ).digest()
        sk = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)
        ek = sk.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
        ss, ct = sk.public_key().encapsulate()
        assert sk.decapsulate(ct) == ss
        bad = bytearray(ct)
        bad[(97 * i + 5) % len(bad)] ^= 1 << (i % 8)
        rejected = sk.decapsulate(bytes(bad))
        assert rejected != ss
        out["cases"].append(
            {
                "seed": seed.hex(),
                "ek_sha256": hashlib.sha256(ek).hexdigest(),
                "ek": ek.hex() if i == 0 else None,
                "ct": ct.hex(),
                "ss": ss.hex(),
                "bad_ct": bytes(bad).hex(),
                "rejected_ss": rejected.hex(),
            }
        )
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
