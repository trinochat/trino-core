"""Independent vectors for the hybrid handshake combiner (pqxdh.rs).

diseno-vinculacion.md §21.2 (PQ-01, PQ-02, PQ-04):

    DH1  = X25519(dev_dh_ini, SPK_resp)   DH2 = X25519(ek, dev_dh_resp)   DH3 = X25519(ek, SPK_resp)
    (SS, ct) = ML-KEM-768.Encaps(pq_ek_resp)
    IKM  = 0xFF * 32 || DH1 || DH2 || DH3 || SS
    info = "trino/pqxdh/v1" || suite || SHA-256(pq_ek_resp) || SHA-256(ct) || pq_spk_id u32 BE
    SK   = HKDF-SHA256(salt = 32 zero bytes, IKM, info, 32)
    AD   = "trino/x3dh/v2\\0" || suite || A_ini || dev_dh_ini || A_resp || dev_dh_resp
    spk_sig = Ed25519(dev_sign_resp, "trino/spk/v2\\0" || spk_id u32 BE || SPK_resp)   (§2.1)

Everything is computed with OpenSSL through Python's `cryptography`:
X25519, ML-KEM-768 (key from a seed, randomized encapsulation) and HKDF.
The Rust side decapsulates OpenSSL's ciphertext with libcrux and must reach
the same SK.

    python -X utf8 tests/vectors/pqxdh.py > tests/vectors/pqxdh.json

Encapsulation is randomized inside OpenSSL, so a rerun prints other
ciphertexts and keys; the tests read the committed file.
"""

import hashlib
import json
import struct
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import ed25519, mlkem, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SUITE = 1


def x_pair(label):
    priv = hashlib.sha256(label.encode()).digest()
    k = x25519.X25519PrivateKey.from_private_bytes(priv)
    pub = k.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
    return k, priv, pub


def dh(k, pub):
    return k.exchange(x25519.X25519PublicKey.from_public_bytes(pub))


def main():
    out = {"generator": "tests/vectors/pqxdh.py", "cases": []}
    for i in range(4):
        dev_ini, dev_ini_priv, dev_ini_pub = x_pair(f"trino/pqxdh/dev_ini/{i}")
        ek, ek_priv, ek_pub = x_pair(f"trino/pqxdh/ek/{i}")
        dev_resp, dev_resp_priv, dev_resp_pub = x_pair(f"trino/pqxdh/dev_resp/{i}")
        spk, spk_priv, spk_pub = x_pair(f"trino/pqxdh/spk/{i}")
        a_ini = hashlib.sha256(f"trino/pqxdh/A_ini/{i}".encode()).digest()
        a_resp = hashlib.sha256(f"trino/pqxdh/A_resp/{i}".encode()).digest()
        pq_seed = hashlib.sha256(f"trino/pqxdh/pq/{i}".encode()).digest() * 2
        pq = mlkem.MLKEM768PrivateKey.from_seed_bytes(pq_seed)
        pq_ek = pq.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
        ss, ct = pq.public_key().encapsulate()
        pq_spk_id = 7 + i * 1000
        dh1, dh2, dh3 = dh(dev_ini, spk_pub), dh(ek, dev_resp_pub), dh(ek, spk_pub)
        # The responder's side of the same three exchanges.
        assert (dh1, dh2, dh3) == (dh(spk, dev_ini_pub), dh(dev_resp, ek_pub), dh(spk, ek_pub))
        ikm = b"\xff" * 32 + dh1 + dh2 + dh3 + ss
        info = (
            b"trino/pqxdh/v1"
            + bytes([SUITE])
            + hashlib.sha256(pq_ek).digest()
            + hashlib.sha256(ct).digest()
            + struct.pack(">I", pq_spk_id)
        )
        sk = HKDF(hashes.SHA256(), 32, b"\x00" * 32, info).derive(ikm)
        ad = b"trino/x3dh/v2\x00" + bytes([SUITE]) + a_ini + dev_ini_pub + a_resp + dev_resp_pub
        dev_sign_priv = hashlib.sha256(f"trino/pqxdh/dev_sign/{i}".encode()).digest()
        dev_sign = ed25519.Ed25519PrivateKey.from_private_bytes(dev_sign_priv)
        spk_id = 100 + i
        spk_sig = dev_sign.sign(b"trino/spk/v2\x00" + struct.pack(">I", spk_id) + spk_pub)
        out["cases"].append(
            {
                "dev_sign_resp_priv": dev_sign_priv.hex(),
                "spk_id": spk_id,
                "spk_sig": spk_sig.hex(),
                "dev_dh_ini_priv": dev_ini_priv.hex(),
                "ek_priv": ek_priv.hex(),
                "dev_dh_resp_priv": dev_resp_priv.hex(),
                "spk_priv": spk_priv.hex(),
                "a_ini": a_ini.hex(),
                "a_resp": a_resp.hex(),
                "pq_seed": pq_seed.hex(),
                "pq_spk_id": pq_spk_id,
                "dh1": dh1.hex(),
                "dh2": dh2.hex(),
                "dh3": dh3.hex(),
                "ct": ct.hex(),
                "ss": ss.hex(),
                "sk": sk.hex(),
                "ad": ad.hex(),
            }
        )
    # PQ-11 (§21.6): the initiator brings an ephemeral ML-KEM key; SK0 has no
    # KEM secret, and the responder's ciphertext moves the root to root1.
    #   SK0   = HKDF(salt = 32 zeros, 0xFF*32 || DH1 || DH2 || DH3,
    #              info = "trino/pqxdh/v1/pq11" || suite || SHA-256(pq_ek_eph))
    #   root1 = HKDF(salt = SK0, ikm = SS, info = "trino/pq11/v1" || SHA-256(ct))
    out["pq11"] = []
    for i in range(3):
        dev_ini, dev_ini_priv, dev_ini_pub = x_pair(f"trino/pq11/dev_ini/{i}")
        ek, ek_priv, ek_pub = x_pair(f"trino/pq11/ek/{i}")
        dev_resp, dev_resp_priv, dev_resp_pub = x_pair(f"trino/pq11/dev_resp/{i}")
        spk, spk_priv, spk_pub = x_pair(f"trino/pq11/spk/{i}")
        eph_seed = hashlib.sha256(f"trino/pq11/eph/{i}".encode()).digest() * 2
        eph = mlkem.MLKEM768PrivateKey.from_seed_bytes(eph_seed)
        pq_ek = eph.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
        dh1, dh2, dh3 = dh(dev_ini, spk_pub), dh(ek, dev_resp_pub), dh(ek, spk_pub)
        sk0 = HKDF(
            hashes.SHA256(),
            32,
            b"\x00" * 32,
            b"trino/pqxdh/v1/pq11" + bytes([SUITE]) + hashlib.sha256(pq_ek).digest(),
        ).derive(b"\xff" * 32 + dh1 + dh2 + dh3)
        ss, ct = eph.public_key().encapsulate()
        root1 = HKDF(hashes.SHA256(), 32, sk0, b"trino/pq11/v1" + hashlib.sha256(ct).digest()).derive(ss)
        out["pq11"].append(
            {
                "dev_dh_ini_priv": dev_ini_priv.hex(),
                "ek_priv": ek_priv.hex(),
                "dev_dh_resp_priv": dev_resp_priv.hex(),
                "spk_priv": spk_priv.hex(),
                "eph_seed": eph_seed.hex(),
                "sk0": sk0.hex(),
                "ct": ct.hex(),
                "ss": ss.hex(),
                "root1": root1.hex(),
            }
        )
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
