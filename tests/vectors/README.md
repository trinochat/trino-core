# Test vectors

| File | What | Where it comes from |
| --- | --- | --- |
| `nip44.vectors.json` | NIP-44 v2: conversation keys, message keys, padded lengths, payloads, long messages, invalid inputs | The official file of the specification, downloaded unchanged (see "Downloads"). |
| `nip44_bytes.json` | NIP-44 v2 over raw bytes and at the P1 size steps | Computed by `nip44_bytes.py` with Python's `cryptography` (OpenSSL). Rerunning the script prints the same file. |
| `p1_mailbox.json` | P1 mailboxes: `S_intro`, `S_ses`, epoch secrets and chain, mailbox keys, `k_mac`, `k_dedup`, low-order X25519 keys | Computed by `p1_mailbox.py` with Python's `cryptography` (OpenSSL). Rerunning the script prints the same file. |
| `p1_wire.json` | P1 inner frames of types 1 to 4 at their steps, their MACs, and two type 3 bodies with a real 24-bit proof of work | Built byte by byte by `p1_wire.py` with Python's standard library (`hmac`, `hashlib`). Rerunning the script prints the same file (the proof of work search takes about a minute). |
| `mlkem768.json` | ML-KEM-768: public keys from seeds, ciphertexts and shared secrets, and the implicit rejection of a flipped ciphertext | Made by OpenSSL 4.0.2 through `mlkem768.py` (Python's `cryptography` 50.0.1). Encapsulation is randomized there, so a rerun prints other ciphertexts; the tests read the committed file. |
| `pq_spk.json` | Signed post-quantum prekeys: the ML-KEM-768 key from a seed and its deterministic Ed25519 signature | OpenSSL through `pq_spk.py`. Rerunning the script prints the same file. |
| `pqxdh.json` | The hybrid handshake: the three X25519 results, an ML-KEM-768 ciphertext and secret, SK, AD and the `dev_sign` signature of the SPK | OpenSSL through `pqxdh.py` (X25519, ML-KEM-768, HKDF, Ed25519). Encapsulation is randomized there, so a rerun prints other ciphertexts and keys; the tests read the committed file. |

## Downloads

Downloaded unchanged on 29 Oct 2026. Nothing in them is executed; the tests only read them.

| File | URL | Source commit | SHA-256 |
| --- | --- | --- | --- |
| `nip44.vectors.json` | https://raw.githubusercontent.com/paulmillr/nip44/671a1f04bcfacaf125b0db68adc45bc9ce0e763b/nip44.vectors.json | `paulmillr/nip44` @ `671a1f04bcfacaf125b0db68adc45bc9ce0e763b` | `269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040`, the same checksum NIP-44 publishes |

## History

- Until 29 Oct 2026 `nip44.vectors.json` was the shorter copy in the `nip44` crate 0.3.2 (SHA-256 `cedc7f554d62d700977eaced5e2656db52d9485826ab1024977ab8ca777eba57`). Its `encrypt_decrypt_long_msg` entry paired the keys `sec1 = n-2`, `pub2 = 0x02` with the conversation key `7a1ccf5c…` and an empty checksum. The official file has no such entry, and gives `8b6392db…` for that pair, as the crate's own `get_conversation_key` did: the entry was stale. The tests never used it.
