# Cryptographic primitives

Thin wrappers over the RustCrypto crates that every other module builds on.

Every key Trino derives and every byte it encrypts goes through this module. Its tests check official vectors (RFC 5869, RFC 7914 and NIST's GCM examples), not only round trips, so a wrong parameter cannot hide behind a test that agrees with itself.

| Item | Section |
| --- | --- |
| `random_bytes`, `random_array` | [Random bytes](#random) |
| `sha256` | [SHA-256](#sha256) |
| `hkdf_expand` | [HKDF-SHA256](#hkdf) |
| `aes_gcm_encrypt`, `aes_gcm_decrypt`, `KEY_SIZE`, `NONCE_SIZE`, `TAG_SIZE` | [AES-256-GCM](#aes-gcm) |
| `pbkdf2_sha256` | [PBKDF2-HMAC-SHA256](#pbkdf2) |
| `concat` | [Concatenation](#concat) |
| `to_hex`, `from_hex` | [Hex](#hex) |
| `CryptoError` | [Errors](#errors) |
| Wiping derived keys | [Zeroization](#zeroize) |

## <a id="random"></a>Random bytes: `random_bytes`, `random_array`

**What.** `random_bytes(n)` returns `n` random bytes in a `Vec`. `random_array::<N>()` returns them as a `[u8; N]`. Both read `rand::thread_rng()`.

**Why.** In rand 0.8, `thread_rng()` is a ChaCha12 generator seeded from the operating system (`OsRng`). It reseeds itself every 64 KiB of output and after a `fork` on Unix. It is a cryptographically secure generator, so nothing here needs seeding by hand.

**Invariants.**

- If the operating system cannot seed the generator, rand panics. These functions never fall back to predictable bytes.
- Every call returns fresh bytes. Nothing caches randomness.

**Used by.**

- `identity`: X25519 private keys, Nostr (secp256k1) private keys, and the fallback in `x25519_derive_shared`.
- `vault`: the 16-byte PBKDF2 salt, drawn again on every seal.
- `aes_gcm_encrypt`: the 12-byte nonce of every encryption.
- `totp`: the 20-byte TOTP secret, the 160 bits RFC 4226 recommends.
- `group`: the 32 random bytes behind every group id.
- The app: one fresh key per attachment, and group ids.

Ed25519 keys come from `ed25519_dalek::SigningKey::generate`, fed by the same `thread_rng()`.

## <a id="sha256"></a>SHA-256: `sha256`

**What.** The SHA-256 digest (FIPS 180-4) of `data`, from the `sha2` crate.

**Why.** The formats Trino speaks fix it: a Nostr event id (NIP-01) and a Blossom blob address are SHA-256 digests.

**Invariants.** It is a digest, not a MAC and not a KDF. Keys come from [HKDF](#hkdf) and passphrases go through [PBKDF2](#pbkdf2), never through a bare hash.

**Used by.** The app: Nostr event ids, the address of an encrypted attachment on a Blossom server, and short identifiers. The protocol core does not call it.

**Tested** against the standard `"abc"` example.

## <a id="hkdf"></a>HKDF-SHA256: `hkdf_expand`

**What.** HKDF (RFC 5869) with SHA-256. It extracts a pseudorandom key from `ikm`, keyed by `salt`, then expands it to `length` bytes bound to `info`. The bytes come back in a `Zeroizing<Vec<u8>>`.

**Why.** HKDF is the standard extract-then-expand key derivation, and the one the Signal X3DH and Double Ratchet specifications build on. A distinct `info` label per purpose gives each derived key its own domain, so the same input never yields the same key for two jobs.

**Invariants.**

- `length` is at most 255 × 32 = 8160 bytes; anything longer fails with `CryptoError::Hkdf`. Trino only asks for 32 or 64.
- An empty `salt`, a `salt` of 32 zero bytes and an absent salt give the same output. RFC 5869 §2.2 defines an absent salt as HashLen zero bytes, and HMAC pads a short key with zeros. The A.3 test checks all three.
- Every label ends in `-v1`. Changing a label or a salt changes every key derived from it, so existing sessions and files would stop decrypting.

**Used by.**

- X3DH master secret (`x3dh`): IKM is DH1 ‖ DH2 ‖ DH3, plus DH4 when the initial message names a one-time prekey. Salt: 32 zero bytes. Info: `trino-x3dh-v1`. 32 bytes.
- Double Ratchet root step (`ratchet`, `kdf_rk`): IKM is the new DH output. Salt: the current root key. Info: `trino-ratchet-rk-v1`. 64 bytes, split into the next root key and a chain key.
- Double Ratchet chain step (`ratchet`, `kdf_ck`): IKM is the chain key. Salt: 32 zero bytes. Info: `trino-ratchet-ck-chain-v1` for the next chain key and `trino-ratchet-ck-msg-v1` for the message key. 32 bytes each.
- History key (the app): IKM is the identity's Ed25519 signing private key. Salt: 32 zero bytes. Info: `trino-history-key-v1`. 32 bytes. It encrypts `history.bin` and `ratchets.bin`.

**Tested** against RFC 5869, Appendix A, test cases A.1 to A.3.

## <a id="aes-gcm"></a>AES-256-GCM: `aes_gcm_encrypt`, `aes_gcm_decrypt`

**What.** Authenticated encryption with AES-256 in Galois/Counter Mode (NIST SP 800-38D). `aes_gcm_encrypt` draws a random nonce, encrypts, and returns the ciphertext with the tag appended, together with the nonce. The caller stores the nonce next to the ciphertext. `aes_gcm_decrypt` checks the tag over the associated data and the ciphertext, and returns the plaintext only if it matches.

**Why these parameters.**

- `KEY_SIZE` is 32: AES-256.
- `NONCE_SIZE` is 12: the 96-bit IV that SP 800-38D recommends for interoperability and efficiency.
- `TAG_SIZE` is 16: the full 128-bit tag. Shorter tags only make forgeries easier.

**Random nonces and the NIST limits.** A nonce must never repeat under one key. A repeat leaks the XOR of the two plaintexts and lets an attacker forge tags. Trino draws every nonce at random, the RBG-based construction of SP 800-38D §8.2.2. For that construction, §8.3 allows at most 2^32 encryptions per key, which keeps the chance of any repeated nonce below 2^-32. That is far beyond how Trino uses a key:

- A ratchet message key encrypts exactly one message.
- The vault key is new on every seal, because every seal draws a fresh PBKDF2 salt.
- An attachment key (in the app) is random per file.
- The history key (in the app) is the one long-lived key. It re-encrypts `history.bin` or `ratchets.bin` with a fresh nonce on every save. At one save per second, 2^32 saves take about 136 years.

A version that takes the nonce from the caller exists only to check NIST's vectors, and it is private.

**Invariants.**

- The key must be 32 bytes, and on decryption the nonce must be 12 bytes. Anything else fails with `InvalidKeyLength` or `InvalidNonceLength`.
- The ciphertext is always 16 bytes longer than the plaintext.
- `None` as associated data is the same as empty associated data. NIST examples #1 and #2 go through `None`.
- Once the lengths are right, every decryption failure is `CryptoError::Aead`. A wrong key, a wrong nonce, wrong associated data and tampering all look the same to the caller.
- SP 800-38D caps one plaintext at 2^39 − 256 bits, just under 64 GiB, and the `aes-gcm` crate returns an error past 2^36 bytes.

**Used by.**

- `vault`: the sealed identity, under the PBKDF2 key, with no associated data.
- `ratchet`: every message, under its own message key. The associated data is the X3DH associated data followed by the encoded message header.
- The app: attachments sent through Blossom, and `history.bin` and `ratchets.bin` under the history key. Each file stores the nonce in front of the ciphertext.

**Tested** against NIST's GCM-AES256 examples #1 to #5 (the ones with a 128-bit tag), in both directions, and with round-trip, wrong associated data, tampering and wrong key length.

## <a id="pbkdf2"></a>PBKDF2-HMAC-SHA256: `pbkdf2_sha256`

**What.** PBKDF2 (RFC 8018) with HMAC-SHA256. It turns the passphrase and the vault's salt into the vault's 32-byte AES-256 key, returned in a `Zeroizing<[u8; 32]>`.

**Why these parameters.**

- 600 000 iterations (`PBKDF2_ITERATIONS` in `vault`): the work factor the OWASP Password Storage Cheat Sheet recommends for PBKDF2-HMAC-SHA256.
- A random 16-byte salt on every seal: SP 800-132 asks for at least 128 random bits, and a fresh salt means a fresh key every time.
- 32 bytes of output: exactly one HMAC-SHA256 block. Each extra block would cost the full iteration count again, and an attacker able to check a guess against one block would not pay for the others.

PBKDF2 is not memory-hard. GPUs speed up guessing it far more than they speed up Argon2id or scrypt, which OWASP lists first. The iteration count is its only defence, and the strength of the passphrase does the rest.

**Invariants.**

- Deterministic: the same passphrase, salt and iteration count always give the same key.
- The vault header does not store the iteration count, so the format version fixes it. Changing it needs a new `VAULT_VERSION`, or existing vaults would no longer open.
- The 32 bytes are the first 32 bytes of any longer PBKDF2 output with the same inputs, which is how the tests compare them with the 64-byte RFC 7914 vectors.

**Used by.** `seal_vault` and `unseal_vault` in `vault`.

**Tested** against RFC 7914 §11, with 1 and with 80 000 iterations.

## <a id="concat"></a>Concatenation: `concat`

**What.** Joins byte slices with no separators and no length prefixes.

**Why it is unambiguous where Trino uses it.** In general, plain concatenation is ambiguous: `"ab"` + `"c"` and `"a"` + `"bc"` give the same bytes. Trino only concatenates parts whose lengths are fixed, so every boundary is known:

- X3DH associated data (`x3dh`): the initiator's identity DH public key, then the responder's. 32 bytes each.
- Message associated data (`ratchet`): the X3DH associated data, then the encoded header. The header is always 40 bytes (the 32-byte DH public key, then `pn` and `n` as big-endian `u32`) and comes last, so the split would stay fixed even if the first part's length changed.

GCM itself adds no ambiguity: its tag covers the lengths of the associated data and of the ciphertext.

**Invariant.** Only use it for parts of fixed length, with at most one part of variable length. Anything else needs length prefixes.

**Used by.** `x3dh` and `ratchet`, as above.

## <a id="hex"></a>Hex: `to_hex`, `from_hex`

**What.** Hex encoding and decoding, from the `hex` crate.

**Invariants.**

- `to_hex` always writes lowercase.
- `from_hex` accepts either case and rejects odd lengths and non-hex characters. It does not check the length: callers that expect a key or a signature check it, as `decode_array_32` and `decode_array_64` in `identity` do.
- Both cases decode to the same bytes, so code that compares keys as strings must insist on one case. Group rosters require lowercase.
- The strings are ordinary `String` values and are not wiped.

**Used by.** `identity`, for public bundles and for decoding fixed-size keys and signatures, including the private keys read from the decrypted vault payload.

## <a id="errors"></a>Errors: `CryptoError`

- `InvalidKeyLength` and `InvalidNonceLength`: the input has the wrong size. Both report the expected and the actual length.
- `Aead`: encryption failed, or decryption could not authenticate the input. It says nothing about why, on purpose.
- `Hkdf`: `hkdf_expand` was asked for more than 8160 bytes.

## <a id="zeroize"></a>Zeroization

`hkdf_expand` and `pbkdf2_sha256` return their output in `zeroize::Zeroizing`, which overwrites the buffer with zeros when it is dropped. A caller that copies the bytes out owns that copy. `x3dh` and `ratchet` copy them into fixed-size arrays: `RatchetState` wipes the keys it holds when it is dropped, but the X3DH results and short-lived local copies are not wiped.

What this module does not wipe:

- the plaintext returned by `aes_gcm_decrypt`;
- the internal state of the RustCrypto types: the AES key schedule and the HMAC states inside HKDF and PBKDF2. The `aes-gcm` crate is built without its optional `zeroize` feature.

## <a id="references"></a>References

- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869): HKDF. Appendix A holds the test vectors.
- [RFC 7914, Section 11](https://www.rfc-editor.org/rfc/rfc7914#section-11): PBKDF2-HMAC-SHA256 test vectors.
- [RFC 8018](https://www.rfc-editor.org/rfc/rfc8018): PKCS #5 v2.1, which defines PBKDF2.
- [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final): GCM. §5.2.1.1 covers input lengths, §8 nonce uniqueness, §8.2.2 random nonces and §8.3 the 2^32 limit.
- [NIST example values for GCM](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf): the GCM-AES256 examples used in the tests.
- [NIST SP 800-132](https://csrc.nist.gov/pubs/sp/800/132/final): password-based key derivation and salt length.
- [OWASP Password Storage Cheat Sheet, PBKDF2](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2): the 600 000 iteration work factor.
- [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf): SHA-256.
- [RFC 4226, Section 4](https://www.rfc-editor.org/rfc/rfc4226#section-4): shared-secret length for HOTP and TOTP.
- [The X3DH key agreement protocol](https://signal.org/docs/specifications/x3dh/) and [the Double Ratchet algorithm](https://signal.org/docs/specifications/doubleratchet/): the Signal specifications the protocol follows.
- [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md): Nostr event ids.
