"""Independent vectors for the outer layer of P1, the Nostr event (p1/event.rs).

diseno.md §2.1:

    {"kind": 1059 (21059 for calls), "pubkey": <one-time key>,
     "created_at": <1059: now - U(0, 300 s); 21059: now>,
     "tags": [["p", <mailbox>], ["expiration", <1059: created_at + U(6 d, 8 d);
                                                 21059: created_at + U(1 h, 2 h)>]],
     "content": <NIP-44 v2 from the one-time key to the mailbox>,
     "sig": <BIP-340 by the one-time key, with auxiliary randomness>}

The id is NIP-01's: SHA-256 of the compact JSON
[0, pubkey, created_at, kind, tags, content]. Python's `json` serializes it,
OpenSSL (through `cryptography`) does the secp256k1 scalar multiplications
and the NIP-44 primitives, and BIP-340 signing is written here from the
specification (https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki),
so none of it shares code with libsecp256k1, which the Rust side uses.

    python -I -X utf8 tests/vectors/p1_event.py > tests/vectors/p1_event.json

Every input comes from fixed labels, so a rerun prints the same file.
"""

import base64
import hashlib
import hmac
import json
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def h(label):
    return hashlib.sha256(label.encode()).digest()


def scalar(label):
    k = int.from_bytes(h(label), "big") % N
    assert k != 0
    return k


def point(k):
    """k·G through OpenSSL, as (x, y)."""
    nums = ec.derive_private_key(k, ec.SECP256K1()).public_key().public_numbers()
    return nums.x, nums.y


def tagged_hash(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def bip340_sign(msg, d0, aux):
    """BIP-340 'Default Signing', step by step."""
    px, py = point(d0)
    d = d0 if py % 2 == 0 else N - d0
    t = bytes(a ^ b for a, b in zip(d.to_bytes(32, "big"), tagged_hash("BIP0340/aux", aux)))
    k0 = int.from_bytes(tagged_hash("BIP0340/nonce", t + px.to_bytes(32, "big") + msg), "big") % N
    assert k0 != 0
    rx, ry = point(k0)
    k = k0 if ry % 2 == 0 else N - k0
    e = int.from_bytes(
        tagged_hash("BIP0340/challenge", rx.to_bytes(32, "big") + px.to_bytes(32, "big") + msg), "big"
    ) % N
    return rx.to_bytes(32, "big") + ((k + e * d) % N).to_bytes(32, "big")


def xonly(k):
    return point(k)[0].to_bytes(32, "big")


def conversation_key(sk, pub_x):
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), b"\x02" + pub_x)
    shared_x = ec.derive_private_key(sk, ec.SECP256K1()).exchange(ec.ECDH(), peer)
    return hmac.new(b"nip44-v2", shared_x, hashlib.sha256).digest()


def calc_padded_len(n):
    if n <= 32:
        return 32
    next_power = 1 << ((n - 1).bit_length())
    chunk = 32 if next_power <= 256 else next_power // 8
    return chunk * ((n - 1) // chunk + 1)


def nip44_encrypt(conv, nonce, plaintext):
    okm = HKDFExpand(hashes.SHA256(), 76, nonce).derive(conv)
    key, chacha_nonce, hmac_key = okm[:32], okm[32:44], okm[44:76]
    padded = len(plaintext).to_bytes(2, "big") + plaintext
    padded += b"\x00" * (2 + calc_padded_len(len(plaintext)) - len(padded))
    enc = Cipher(algorithms.ChaCha20(key, b"\x00" * 4 + chacha_nonce), mode=None).encryptor()
    ct = enc.update(padded) + enc.finalize()
    mac = hmac.new(hmac_key, nonce + ct, hashlib.sha256).digest()
    return base64.b64encode(b"\x02" + nonce + ct + mac).decode()


def main():
    # BIP-340's test vector 0: secret key 3, auxiliary randomness and message all zeros.
    assert bip340_sign(bytes(32), 3, bytes(32)).hex().upper() == (
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
    )
    out = {"generator": "tests/vectors/p1_event.py", "cases": []}
    for i, (kind, inner_len, created_at, expiration) in enumerate(
        [
            (1059, 1024, 1_793_000_000, 1_793_000_000 + 6 * 86400),
            (1059, 16384, 1_793_086_399, 1_793_086_399 + 8 * 86400),
            # diseno-vinculacion.md §23.8: a call signal expires too, 1 to 2 hours out.
            (21059, 4096, 1_793_100_000, 1_793_100_000 + 3600),
            (21059, 16384, 1_793_100_123, 1_793_100_123 + 7200),
        ]
    ):
        one_time = scalar(f"trino/p1-event/one-time/{i}")
        mailbox_sk = scalar(f"trino/p1-event/mailbox/{i}")
        mailbox = xonly(mailbox_sk)
        inner = bytes((5 * j + i) & 0xFF for j in range(inner_len))
        nonce = h(f"trino/p1-event/nip44-nonce/{i}")
        aux = h(f"trino/p1-event/aux/{i}")
        pubkey = xonly(one_time).hex()
        content = nip44_encrypt(conversation_key(one_time, mailbox), nonce, inner)
        assert content == nip44_encrypt(conversation_key(mailbox_sk, bytes.fromhex(pubkey)), nonce, inner)
        tags = [["p", mailbox.hex()], ["expiration", str(expiration)]]
        serial = json.dumps([0, pubkey, created_at, kind, tags, content], separators=(",", ":"), ensure_ascii=False)
        event_id = hashlib.sha256(serial.encode()).digest()
        sig = bip340_sign(event_id, one_time, aux)
        out["cases"].append(
            {
                "one_time_sk": one_time.to_bytes(32, "big").hex(),
                "mailbox_sk": mailbox_sk.to_bytes(32, "big").hex(),
                "nip44_nonce": nonce.hex(),
                "aux": aux.hex(),
                "inner_sha256": hashlib.sha256(inner).hexdigest(),
                "inner_len": inner_len,
                "inner_seed": i,
                "event": {
                    "id": event_id.hex(),
                    "pubkey": pubkey,
                    "created_at": created_at,
                    "kind": kind,
                    "tags": tags,
                    "content": content,
                    "sig": sig.hex(),
                },
            }
        )
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
