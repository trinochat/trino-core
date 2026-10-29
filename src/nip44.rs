//! NIP-44 version 2 encryption over raw bytes.
//!
//! P1 seals every event's content with NIP-44 v2 between a one-time author
//! key and a mailbox key (`diseno.md` §2.1, decision D1), so a P1 event looks
//! like any other gift wrap and a relay that guards kind 1059 behind AUTH
//! still serves it.
//!
//! The cryptography is the specification's, unchanged:
//!
//! ```text
//! conversation_key = HKDF-extract(salt = "nip44-v2", ikm = ECDH_x(sk, pk))
//! (key 32 ‖ nonce 12 ‖ hmac_key 32) = HKDF-expand(conversation_key, info = nonce 32, 76)
//! padded  = u16 BE length ‖ plaintext ‖ zeros up to 2 + calc_padded_len(length)
//! payload = base64( 0x02 ‖ nonce 32 ‖ ChaCha20(key, nonce, padded) ‖ HMAC-SHA256(hmac_key, nonce ‖ ciphertext) )
//! ```
//!
//! **One conscious deviation.** NIP-44 defines the plaintext as UTF-8; Trino
//! puts binary P1 frames inside. Nothing else ever decrypts these events, and
//! the bytes on the wire are what the specification produces for the same
//! plaintext bytes, so `decrypt` hands back bytes and never checks UTF-8.
//!
//! Every P1 size step `E` (1, 4, 16 and 40 KiB) is its own padded length,
//! `calc_padded_len(E) = E`, so NIP-44 adds no step of its own on top of P1's.
//!
//! The tests check the official vectors of the specification (Paul Miller's
//! `nip44.vectors.json`, whose SHA-256 the NIP publishes) and independent
//! byte vectors computed with OpenSSL (`tests/vectors/nip44_bytes.py`); see
//! `tests/vectors/README.md`.

use crate::crypto::random_array;
use base64::Engine;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use secp256k1::{ecdh, Parity, SecretKey, XOnlyPublicKey};
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// The version byte of NIP-44 v2.
pub const VERSION: u8 = 2;
/// Shortest plaintext NIP-44 accepts.
pub const MIN_PLAINTEXT: usize = 1;
/// Longest plaintext NIP-44 accepts.
pub const MAX_PLAINTEXT: usize = 65_535;
/// Length of the per-message nonce.
pub const NONCE_LEN: usize = 32;
/// Length of the HMAC-SHA256 tag.
pub const MAC_LEN: usize = 32;

const SALT: &[u8] = b"nip44-v2";
// Decoded payload: version 1, nonce 32, at least 2 + 32 padded bytes, mac 32.
const MIN_PAYLOAD: usize = 1 + NONCE_LEN + 2 + 32 + MAC_LEN;
// Version 1, nonce 32, 2 + 65536 padded bytes, mac 32.
const MAX_PAYLOAD: usize = 1 + NONCE_LEN + 2 + 65_536 + MAC_LEN;
// Base64 lengths of the two bounds above.
const MIN_PAYLOAD_B64: usize = 132;
const MAX_PAYLOAD_B64: usize = 87_472;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Nip44Error {
    #[error("secret key is zero or not below the curve order")]
    InvalidSecretKey,
    #[error("public key is not the x coordinate of a curve point")]
    InvalidPublicKey,
    #[error("plaintext must be 1 to 65535 bytes, got {0}")]
    PlaintextLength(usize),
    #[error("payload length is out of range")]
    PayloadLength,
    #[error("unknown encryption version")]
    UnknownVersion,
    #[error("payload is not valid base64")]
    InvalidBase64,
    #[error("invalid MAC")]
    InvalidMac,
    #[error("invalid padding")]
    InvalidPadding,
}

/// The per-message keys NIP-44 expands from the conversation key and nonce.
pub struct MessageKeys {
    pub chacha_key: Zeroizing<[u8; 32]>,
    pub chacha_nonce: [u8; 12],
    pub hmac_key: Zeroizing<[u8; 32]>,
}

/// The conversation key between secret key `sk` and the x-only public key
/// `pk` (taken with an even y, as NIP-44 and BIP-340 do). It is symmetric:
/// `conversation_key(a, B) == conversation_key(b, A)`.
pub fn conversation_key(sk: &[u8; 32], pk: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Nip44Error> {
    let sk = SecretKey::from_slice(sk).map_err(|_| Nip44Error::InvalidSecretKey)?;
    let pk = XOnlyPublicKey::from_slice(pk)
        .map_err(|_| Nip44Error::InvalidPublicKey)?
        .public_key(Parity::Even);
    // The unhashed x coordinate of sk·P, as NIP-44 specifies.
    let mut point = ecdh::shared_secret_point(&pk, &sk);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(SALT), &point[..32]);
    point.zeroize();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&prk);
    Ok(out)
}

/// HKDF-expand of the conversation key with the nonce as `info`.
pub fn message_keys(conversation_key: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> MessageKeys {
    let hk = Hkdf::<Sha256>::from_prk(conversation_key).expect("32 bytes is a valid PRK length");
    let mut okm = Zeroizing::new([0u8; 76]);
    hk.expand(nonce, &mut okm[..])
        .expect("76 bytes is a valid HKDF-SHA256 length");
    let mut keys = MessageKeys {
        chacha_key: Zeroizing::new([0u8; 32]),
        chacha_nonce: [0u8; 12],
        hmac_key: Zeroizing::new([0u8; 32]),
    };
    keys.chacha_key.copy_from_slice(&okm[..32]);
    keys.chacha_nonce.copy_from_slice(&okm[32..44]);
    keys.hmac_key.copy_from_slice(&okm[44..]);
    keys
}

/// The padded length (without the 2-byte length prefix) of a plaintext of
/// `len` bytes. It does not check `len`: [`encrypt`] and [`decrypt`] do.
pub fn calc_padded_len(len: usize) -> usize {
    if len <= 32 {
        return 32;
    }
    // 1 << (floor(log2(len - 1)) + 1), as the specification writes it.
    let next_power = 1usize << (usize::BITS - (len - 1).leading_zeros());
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    chunk * ((len - 1) / chunk + 1)
}

fn mac(hmac_key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Hmac<Sha256> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(hmac_key).expect("HMAC takes any key length");
    mac.update(nonce);
    mac.update(ciphertext);
    mac
}

/// Encrypts `plaintext` under a fresh random nonce and returns the base64
/// payload.
pub fn encrypt(conversation_key: &[u8; 32], plaintext: &[u8]) -> Result<String, Nip44Error> {
    let nonce: [u8; NONCE_LEN] = random_array();
    encrypt_with_nonce(conversation_key, plaintext, &nonce)
}

/// Encrypts under a caller-chosen nonce. Crate-private: a nonce reused under
/// one conversation key repeats the ChaCha20 keystream.
pub(crate) fn encrypt_with_nonce(
    conversation_key: &[u8; 32],
    plaintext: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<String, Nip44Error> {
    if !(MIN_PLAINTEXT..=MAX_PLAINTEXT).contains(&plaintext.len()) {
        return Err(Nip44Error::PlaintextLength(plaintext.len()));
    }
    let padded_len = calc_padded_len(plaintext.len());
    let keys = message_keys(conversation_key, nonce);
    let mut out = Vec::with_capacity(1 + NONCE_LEN + 2 + padded_len + MAC_LEN);
    out.push(VERSION);
    out.extend_from_slice(nonce);
    let start = out.len();
    out.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());
    out.extend_from_slice(plaintext);
    out.resize(start + 2 + padded_len, 0);
    ChaCha20::new(keys.chacha_key.as_ref().into(), &keys.chacha_nonce.into())
        .apply_keystream(&mut out[start..]);
    let tag = mac(&keys.hmac_key, nonce, &out[start..])
        .finalize()
        .into_bytes();
    out.extend_from_slice(&tag);
    Ok(base64::engine::general_purpose::STANDARD.encode(out))
}

/// Checks and decrypts a base64 payload; returns the plaintext bytes.
pub fn decrypt(
    conversation_key: &[u8; 32],
    payload: &str,
) -> Result<Zeroizing<Vec<u8>>, Nip44Error> {
    // A leading '#' marks a payload that is not base64 at all (a future,
    // non-base64 version); the specification rejects it before decoding.
    if payload.starts_with('#') {
        return Err(Nip44Error::UnknownVersion);
    }
    if !(MIN_PAYLOAD_B64..=MAX_PAYLOAD_B64).contains(&payload.len()) {
        return Err(Nip44Error::PayloadLength);
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(payload)
        .map_err(|_| Nip44Error::InvalidBase64)?;
    if !(MIN_PAYLOAD..=MAX_PAYLOAD).contains(&raw.len()) {
        return Err(Nip44Error::PayloadLength);
    }
    if raw[0] != VERSION {
        return Err(Nip44Error::UnknownVersion);
    }
    let nonce: [u8; NONCE_LEN] = raw[1..1 + NONCE_LEN].try_into().expect("length checked");
    let (ciphertext, tag) = raw[1 + NONCE_LEN..].split_at(raw.len() - 1 - NONCE_LEN - MAC_LEN);
    let keys = message_keys(conversation_key, &nonce);
    // Constant-time comparison, before anything is decrypted.
    mac(&keys.hmac_key, &nonce, ciphertext)
        .verify_slice(tag)
        .map_err(|_| Nip44Error::InvalidMac)?;
    let mut padded = Zeroizing::new(ciphertext.to_vec());
    ChaCha20::new(keys.chacha_key.as_ref().into(), &keys.chacha_nonce.into())
        .apply_keystream(&mut padded);
    let len = usize::from(u16::from_be_bytes([padded[0], padded[1]]));
    if len < MIN_PLAINTEXT || padded.len() != 2 + calc_padded_len(len) {
        return Err(Nip44Error::InvalidPadding);
    }
    Ok(Zeroizing::new(padded[2..2 + len].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const THIRD_PARTY: &str = include_str!("../tests/vectors/nip44.vectors.json");
    const BYTES: &str = include_str!("../tests/vectors/nip44_bytes.json");

    fn v2() -> Value {
        serde_json::from_str::<Value>(THIRD_PARTY).unwrap()["v2"].clone()
    }

    fn h32(s: &Value) -> [u8; 32] {
        hex::decode(s.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn xonly_of(sk: &[u8; 32]) -> [u8; 32] {
        let sk = SecretKey::from_slice(sk).unwrap();
        sk.x_only_public_key(secp256k1::SECP256K1).0.serialize()
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (7 * i + 3) as u8).collect()
    }

    #[test]
    fn third_party_conversation_keys() {
        for c in v2()["valid"]["get_conversation_key"].as_array().unwrap() {
            let got = conversation_key(&h32(&c["sec1"]), &h32(&c["pub2"])).unwrap();
            assert_eq!(*got, h32(&c["conversation_key"]), "{}", c["note"]);
        }
    }

    #[test]
    fn third_party_invalid_conversation_keys() {
        for c in v2()["invalid"]["get_conversation_key"].as_array().unwrap() {
            assert!(
                conversation_key(&h32(&c["sec1"]), &h32(&c["pub2"])).is_err(),
                "{}",
                c["note"]
            );
        }
    }

    #[test]
    fn third_party_padded_lengths() {
        for p in v2()["valid"]["calc_padded_len"].as_array().unwrap() {
            let (len, padded) = (p[0].as_u64().unwrap(), p[1].as_u64().unwrap());
            assert_eq!(calc_padded_len(len as usize), padded as usize, "{len}");
        }
    }

    #[test]
    fn third_party_encrypt_decrypt() {
        for c in v2()["valid"]["encrypt_decrypt"].as_array().unwrap() {
            let (sec1, sec2) = (h32(&c["sec1"]), h32(&c["sec2"]));
            let conv = conversation_key(&sec1, &xonly_of(&sec2)).unwrap();
            assert_eq!(*conv, h32(&c["conversation_key"]));
            assert_eq!(*conversation_key(&sec2, &xonly_of(&sec1)).unwrap(), *conv);
            let plaintext = c["plaintext"].as_str().unwrap().as_bytes();
            let payload = encrypt_with_nonce(&conv, plaintext, &h32(&c["nonce"])).unwrap();
            assert_eq!(payload, c["payload"].as_str().unwrap());
            assert_eq!(&decrypt(&conv, &payload).unwrap()[..], plaintext);
        }
    }

    #[test]
    fn third_party_message_keys() {
        let set = &v2()["valid"]["get_message_keys"];
        let conv = h32(&set["conversation_key"]);
        for k in set["keys"].as_array().unwrap() {
            let keys = message_keys(&conv, &h32(&k["nonce"]));
            assert_eq!(*keys.chacha_key, h32(&k["chacha_key"]));
            assert_eq!(
                hex::encode(keys.chacha_nonce),
                k["chacha_nonce"].as_str().unwrap()
            );
            assert_eq!(*keys.hmac_key, h32(&k["hmac_key"]));
        }
    }

    #[test]
    fn third_party_long_messages() {
        use sha2::Digest;
        for c in v2()["valid"]["encrypt_decrypt_long_msg"]
            .as_array()
            .unwrap()
        {
            let conv = h32(&c["conversation_key"]);
            let repeat = c["repeat"].as_u64().unwrap() as usize;
            let plaintext = c["pattern"].as_str().unwrap().repeat(repeat);
            assert_eq!(
                Sha256::digest(plaintext.as_bytes())[..],
                h32(&c["plaintext_sha256"])
            );
            let payload =
                encrypt_with_nonce(&conv, plaintext.as_bytes(), &h32(&c["nonce"])).unwrap();
            assert_eq!(
                Sha256::digest(payload.as_bytes())[..],
                h32(&c["payload_sha256"])
            );
            assert_eq!(&decrypt(&conv, &payload).unwrap()[..], plaintext.as_bytes());
        }
    }

    #[test]
    fn third_party_invalid_payloads() {
        for c in v2()["invalid"]["decrypt"].as_array().unwrap() {
            let conv = h32(&c["conversation_key"]);
            let note = c["note"].as_str().unwrap();
            // The file names the reason; each one maps to its own error.
            let want = if note.starts_with("unknown encryption version") {
                Nip44Error::UnknownVersion
            } else if note.starts_with("invalid base64") {
                Nip44Error::InvalidBase64
            } else if note.starts_with("invalid MAC") {
                Nip44Error::InvalidMac
            } else if note.starts_with("invalid padding") {
                Nip44Error::InvalidPadding
            } else if note.starts_with("invalid payload length") {
                Nip44Error::PayloadLength
            } else {
                panic!("unexpected note {note}")
            };
            assert_eq!(
                decrypt(&conv, c["payload"].as_str().unwrap()).err(),
                Some(want),
                "{note}"
            );
        }
    }

    #[test]
    fn third_party_plaintext_lengths() {
        let conv = [1u8; 32];
        for len in v2()["invalid"]["encrypt_msg_lengths"].as_array().unwrap() {
            let len = len.as_u64().unwrap() as usize;
            // 10 000 000 would only allocate to fail; any length past the
            // maximum takes the same branch.
            let len = len.min(MAX_PLAINTEXT + 1);
            assert_eq!(
                encrypt(&conv, &vec![b'a'; len]),
                Err(Nip44Error::PlaintextLength(len))
            );
        }
    }

    #[test]
    fn third_party_payload_lengths() {
        let conv = [1u8; 32];
        // The `nip44` crate's copy of the vectors listed these decoded
        // lengths; the official file covers them through the "invalid
        // payload length" entries of `invalid.decrypt`.
        for n in [0usize, 1, 2, 5, 10, 20, 32, 48, 64] {
            let as_text = "a".repeat(n);
            let as_bytes = base64::engine::general_purpose::STANDARD.encode(vec![2u8; n]);
            assert!(decrypt(&conv, &as_text).is_err(), "{n} characters");
            assert!(decrypt(&conv, &as_bytes).is_err(), "{n} bytes");
        }
    }

    #[test]
    fn independent_conversation_keys() {
        let v: Value = serde_json::from_str(BYTES).unwrap();
        for c in v["conversation_keys"].as_array().unwrap() {
            let got = conversation_key(&h32(&c["sec1"]), &h32(&c["pub2"])).unwrap();
            assert_eq!(*got, h32(&c["conversation_key"]));
        }
    }

    #[test]
    fn independent_message_keys() {
        let v: Value = serde_json::from_str(BYTES).unwrap();
        for c in v["message_keys"].as_array().unwrap() {
            let keys = message_keys(&h32(&c["conversation_key"]), &h32(&c["nonce"]));
            assert_eq!(*keys.chacha_key, h32(&c["chacha_key"]));
            assert_eq!(
                hex::encode(keys.chacha_nonce),
                c["chacha_nonce"].as_str().unwrap()
            );
            assert_eq!(*keys.hmac_key, h32(&c["hmac_key"]));
        }
    }

    #[test]
    fn independent_short_byte_payloads() {
        let v: Value = serde_json::from_str(BYTES).unwrap();
        for c in v["short"].as_array().unwrap() {
            let (sec1, sec2) = (h32(&c["sec1"]), h32(&c["sec2"]));
            let conv = conversation_key(&sec1, &xonly_of(&sec2)).unwrap();
            assert_eq!(*conv, h32(&c["conversation_key"]));
            let plaintext = hex::decode(c["plaintext"].as_str().unwrap()).unwrap();
            let payload = encrypt_with_nonce(&conv, &plaintext, &h32(&c["nonce"])).unwrap();
            assert_eq!(payload, c["payload"].as_str().unwrap());
            assert_eq!(&decrypt(&conv, &payload).unwrap()[..], &plaintext[..]);
        }
    }

    #[test]
    fn independent_long_byte_payloads_at_the_p1_steps() {
        let v: Value = serde_json::from_str(BYTES).unwrap();
        for c in v["long"].as_array().unwrap() {
            let conv = h32(&c["conversation_key"]);
            let n = c["plaintext_len"].as_u64().unwrap() as usize;
            assert_eq!(calc_padded_len(n) as u64, c["padded_len"].as_u64().unwrap());
            let payload = encrypt_with_nonce(&conv, &pattern(n), &h32(&c["nonce"])).unwrap();
            assert_eq!(payload.len() as u64, c["payload_len"].as_u64().unwrap());
            assert_eq!(
                hex::encode(crate::crypto::sha256(payload.as_bytes())),
                c["payload_sha256"].as_str().unwrap()
            );
            assert_eq!(&decrypt(&conv, &payload).unwrap()[..], &pattern(n)[..]);
        }
    }

    #[test]
    fn every_p1_step_is_its_own_padded_length() {
        for e in [1024, 4096, 16384, 40960] {
            assert_eq!(calc_padded_len(e), e);
        }
    }

    #[test]
    fn padding_hides_the_length_within_a_chunk() {
        // NIP-44's own steps are coarse (here 128 bytes): every plaintext of
        // 897 to 1024 bytes gives the same payload length. P1 does not rely on
        // them; its inner frame always measures exactly its step (wire.rs).
        let conv = [9u8; 32];
        let lens: Vec<usize> = (897..=1024)
            .map(|n| encrypt(&conv, &vec![1u8; n]).unwrap().len())
            .collect();
        assert!(lens.iter().all(|&l| l == 1456), "{lens:?}");
        assert_ne!(encrypt(&conv, &[1u8; 896]).unwrap().len(), 1456);
    }

    #[test]
    fn a_flipped_bit_anywhere_fails() {
        let conv = [4u8; 32];
        let payload = encrypt(&conv, b"hola").unwrap();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&payload)
            .unwrap();
        for i in 0..raw.len() {
            let mut bad = raw.clone();
            bad[i] ^= 0x01;
            let bad = base64::engine::general_purpose::STANDARD.encode(bad);
            assert!(decrypt(&conv, &bad).is_err(), "byte {i}");
        }
    }

    #[test]
    fn the_wrong_conversation_key_fails_on_the_mac() {
        let payload = encrypt(&[4u8; 32], b"hola").unwrap();
        assert_eq!(
            decrypt(&[5u8; 32], &payload).unwrap_err(),
            Nip44Error::InvalidMac
        );
    }

    #[test]
    fn two_encryptions_never_share_a_nonce() {
        let conv = [6u8; 32];
        assert_ne!(encrypt(&conv, b"x").unwrap(), encrypt(&conv, b"x").unwrap());
    }
}
