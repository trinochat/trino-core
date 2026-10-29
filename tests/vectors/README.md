# Test vectors

| File | What | Where it comes from |
| --- | --- | --- |
| `nip44.vectors.json` | NIP-44 v2: conversation keys, padded lengths, payloads, invalid inputs | Copied unchanged from the `nip44` crate 0.3.2 on crates.io (MIT, Michael Dilger; `src/nip44.vectors.json`, git `d3301d4`), which says it copies Paul Miller's vectors. SHA-256 `cedc7f554d62d700977eaced5e2656db52d9485826ab1024977ab8ca777eba57`. |
| `nip44_bytes.json` | NIP-44 v2 over raw bytes and at the P1 size steps | Computed by `nip44_bytes.py` with Python's `cryptography` (OpenSSL). Rerunning the script prints the same file. |
| `p1_mailbox.json` | P1 mailboxes: `S_intro`, `S_ses`, epoch secrets and chain, mailbox keys, `k_mac`, `k_dedup`, low-order X25519 keys | Computed by `p1_mailbox.py` with Python's `cryptography` (OpenSSL). Rerunning the script prints the same file. |
| `p1_wire.json` | P1 inner frames of types 1 to 4 at their steps, their MACs, and two type 3 bodies with a real 24-bit proof of work | Built byte by byte by `p1_wire.py` with Python's standard library (`hmac`, `hashlib`). Rerunning the script prints the same file (the proof of work search takes about a minute). |
| `mlkem768.json` | ML-KEM-768: public keys from seeds, ciphertexts and shared secrets, and the implicit rejection of a flipped ciphertext | Made by OpenSSL 4.0.2 through `mlkem768.py` (Python's `cryptography` 50.0.1). Encapsulation is randomized there, so a rerun prints other ciphertexts; the tests read the committed file. |

## Caveats

- `nip44.vectors.json` is **not** the official, full file from `paulmillr/nip44`: it is shorter and its SHA-256 has not been compared with the one the NIP publishes. Replacing it with the official file is pending.
- Its `encrypt_decrypt_long_msg` entry contradicts the same file: it pairs the keys of `get_conversation_key[1]` with a different conversation key, and its checksum is empty. The tests do not use it. `nip44_bytes.py` agrees with every other valid entry.
