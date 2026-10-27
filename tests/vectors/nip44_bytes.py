"""Independent NIP-44 v2 vectors over raw bytes, for trino-core's nip44.rs.

Trino puts binary P1 frames inside NIP-44 v2, so it needs vectors whose
plaintext is not UTF-8 and whose lengths are the P1 size steps. This script
computes them with Python's `cryptography` package (OpenSSL), an
implementation that shares no code with the Rust one it checks.

    python -X utf8 tests/vectors/nip44_bytes.py > tests/vectors/nip44_bytes.json

Every input is derived from fixed labels, so a rerun prints the same file.
"""

import base64
import hashlib
import hmac
import json
import sys

import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def scalar(label: str) -> int:
    k = int.from_bytes(hashlib.sha256(label.encode()).digest(), "big") % N
    assert k != 0
    return k


def xonly(sk: int) -> bytes:
    pub = ec.derive_private_key(sk, ec.SECP256K1()).public_key()
    return pub.public_numbers().x.to_bytes(32, "big")


def conversation_key(sk: int, pub_x: bytes) -> bytes:
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), b"\x02" + pub_x)
    shared_x = ec.derive_private_key(sk, ec.SECP256K1()).exchange(ec.ECDH(), peer)
    return hmac.new(b"nip44-v2", shared_x, hashlib.sha256).digest()


def message_keys(conv: bytes, nonce: bytes):
    okm = HKDFExpand(hashes.SHA256(), 76, nonce).derive(conv)
    return okm[:32], okm[32:44], okm[44:76]


def calc_padded_len(n: int) -> int:
    if n <= 32:
        return 32
    next_power = 1 << ((n - 1).bit_length())
    chunk = 32 if next_power <= 256 else next_power // 8
    return chunk * ((n - 1) // chunk + 1)


def encrypt(conv: bytes, nonce: bytes, plaintext: bytes) -> str:
    assert 1 <= len(plaintext) <= 65535
    key, chacha_nonce, hmac_key = message_keys(conv, nonce)
    padded = len(plaintext).to_bytes(2, "big") + plaintext
    padded += b"\x00" * (2 + calc_padded_len(len(plaintext)) - len(padded))
    # cryptography's ChaCha20 takes a 16-byte nonce: 32-bit LE counter || 96-bit nonce.
    enc = Cipher(algorithms.ChaCha20(key, b"\x00" * 4 + chacha_nonce), mode=None).encryptor()
    ct = enc.update(padded) + enc.finalize()
    mac = hmac.new(hmac_key, nonce + ct, hashlib.sha256).digest()
    return base64.b64encode(b"\x02" + nonce + ct + mac).decode()


def pattern(n: int) -> bytes:
    """The plaintext of the long cases: byte i is (7 * i + 3) mod 256."""
    return bytes((7 * i + 3) & 0xFF for i in range(n))


def main():
    out = {
        "generator": "tests/vectors/nip44_bytes.py",
        "cryptography": cryptography.__version__,
        "note": "Independent NIP-44 v2 vectors over raw bytes (OpenSSL via Python cryptography).",
        "conversation_keys": [],
        "message_keys": [],
        "short": [],
        "long": [],
    }
    for i in range(8):
        sk1, sk2 = scalar(f"trino/nip44-bytes/sk1/{i}"), scalar(f"trino/nip44-bytes/sk2/{i}")
        out["conversation_keys"].append(
            {
                "sec1": sk1.to_bytes(32, "big").hex(),
                "pub2": xonly(sk2).hex(),
                "conversation_key": conversation_key(sk1, xonly(sk2)).hex(),
            }
        )
    for i in range(4):
        conv = hashlib.sha256(f"trino/nip44-bytes/conv/{i}".encode()).digest()
        nonce = hashlib.sha256(f"trino/nip44-bytes/mk-nonce/{i}".encode()).digest()
        k, n, h = message_keys(conv, nonce)
        out["message_keys"].append(
            {
                "conversation_key": conv.hex(),
                "nonce": nonce.hex(),
                "chacha_key": k.hex(),
                "chacha_nonce": n.hex(),
                "hmac_key": h.hex(),
            }
        )
    sk1, sk2 = scalar("trino/nip44-bytes/msg/sk1"), scalar("trino/nip44-bytes/msg/sk2")
    conv = conversation_key(sk1, xonly(sk2))
    assert conv == conversation_key(sk2, xonly(sk1))
    shorts = [
        b"\x00",
        b"\xff\xfe\x00\x80",  # not UTF-8
        bytes(range(31)),
        bytes(range(32)),
        bytes(range(33)),
        b"\xc3\x28" * 50,  # invalid UTF-8, 100 bytes
    ]
    for i, pt in enumerate(shorts):
        nonce = hashlib.sha256(f"trino/nip44-bytes/short-nonce/{i}".encode()).digest()
        out["short"].append(
            {
                "sec1": sk1.to_bytes(32, "big").hex(),
                "sec2": sk2.to_bytes(32, "big").hex(),
                "conversation_key": conv.hex(),
                "nonce": nonce.hex(),
                "plaintext": pt.hex(),
                "payload": encrypt(conv, nonce, pt),
            }
        )
    # The P1 size steps (1, 4, 16 and 40 KiB) and the NIP-44 maximum.
    for i, n in enumerate([1024, 4096, 16384, 40960, 65535]):
        nonce = hashlib.sha256(f"trino/nip44-bytes/long-nonce/{i}".encode()).digest()
        payload = encrypt(conv, nonce, pattern(n))
        out["long"].append(
            {
                "conversation_key": conv.hex(),
                "nonce": nonce.hex(),
                "plaintext_len": n,
                "padded_len": calc_padded_len(n),
                "payload_len": len(payload),
                "payload_sha256": hashlib.sha256(payload.encode()).hexdigest(),
            }
        )
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
