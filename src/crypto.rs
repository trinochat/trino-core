#![doc = include_str!("../docs/crypto.md")]

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

/// AES-256-GCM key length in bytes.
///
/// Details: docs/crypto.md#aes-gcm
pub const KEY_SIZE: usize = 32;
/// AES-GCM nonce length in bytes (96 bits).
///
/// Details: docs/crypto.md#aes-gcm
pub const NONCE_SIZE: usize = 12;
/// AES-GCM tag length in bytes, appended to every ciphertext.
///
/// Details: docs/crypto.md#aes-gcm
pub const TAG_SIZE: usize = 16;

/// Errors from the primitives in this module.
///
/// Details: docs/crypto.md#errors
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    #[error("invalid nonce length: expected {expected}, got {got}")]
    InvalidNonceLength { expected: usize, got: usize },
    #[error("AEAD operation failed (likely tampering)")]
    Aead,
    #[error("HKDF expansion failed")]
    Hkdf,
}

/// Returns `n` bytes from the thread-local CSPRNG.
///
/// Details: docs/crypto.md#random
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// Returns `N` bytes from the thread-local CSPRNG as an array.
///
/// Details: docs/crypto.md#random
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// SHA-256 digest of `data`.
///
/// Details: docs/crypto.md#sha256
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Derives `length` bytes from `ikm` with HKDF-SHA256; the output is wiped on drop.
///
/// Details: docs/crypto.md#hkdf
pub fn hkdf_expand(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new(vec![0u8; length]);
    hk.expand(info, &mut okm).map_err(|_| CryptoError::Hkdf)?;
    Ok(okm)
}

/// Encrypts with AES-256-GCM under a fresh random nonce; returns ciphertext and tag, and the nonce.
///
/// Details: docs/crypto.md#aes-gcm
pub fn aes_gcm_encrypt(
    key: &[u8],
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<(Vec<u8>, [u8; NONCE_SIZE]), CryptoError> {
    let nonce: [u8; NONCE_SIZE] = random_array();
    let ciphertext = aes_gcm_encrypt_with_nonce(key, &nonce, plaintext, associated_data)?;
    Ok((ciphertext, nonce))
}

/// Encrypts under a caller-chosen nonce. Private: a nonce reused under one key breaks GCM.
pub(crate) fn aes_gcm_encrypt_with_nonce(
    key: &[u8],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != KEY_SIZE {
        return Err(CryptoError::InvalidKeyLength {
            expected: KEY_SIZE,
            got: key.len(),
        });
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::Aead)?;
    let payload = match associated_data {
        Some(aad) => Payload {
            msg: plaintext,
            aad,
        },
        None => Payload::from(plaintext),
    };
    cipher
        .encrypt(Nonce::from_slice(nonce), payload)
        .map_err(|_| CryptoError::Aead)
}

/// Authenticates and decrypts AES-256-GCM output; any mismatch is `CryptoError::Aead`.
///
/// Details: docs/crypto.md#aes-gcm
pub fn aes_gcm_decrypt(
    key: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != KEY_SIZE {
        return Err(CryptoError::InvalidKeyLength {
            expected: KEY_SIZE,
            got: key.len(),
        });
    }
    if nonce.len() != NONCE_SIZE {
        return Err(CryptoError::InvalidNonceLength {
            expected: NONCE_SIZE,
            got: nonce.len(),
        });
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::Aead)?;
    let nonce = Nonce::from_slice(nonce);
    let payload = match associated_data {
        Some(aad) => Payload {
            msg: ciphertext,
            aad,
        },
        None => Payload::from(ciphertext),
    };
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::Aead)
}

/// Derives a 32-byte key from a passphrase with PBKDF2-HMAC-SHA256; the key is wiped on drop.
///
/// Details: docs/crypto.md#pbkdf2
pub fn pbkdf2_sha256(passphrase: &[u8], salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase, salt, iterations, &mut out[..]);
    out
}

/// Joins byte slices with no separators: only for parts of fixed length.
///
/// Details: docs/crypto.md#concat
pub fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut out = Vec::with_capacity(total);
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

/// Lowercase hex encoding of `bytes`.
///
/// Details: docs/crypto.md#hex
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Decodes hex in either case; does not check the length.
///
/// Details: docs/crypto.md#hex
pub fn from_hex(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_keys_come_back_in_zeroizing_buffers() {
        let key: Zeroizing<[u8; 32]> = pbkdf2_sha256(b"passwd", b"salt", 1);
        let okm: Zeroizing<Vec<u8>> = hkdf_expand(b"ikm", &[], b"info", 32).unwrap();
        assert_eq!(key.len(), KEY_SIZE);
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn sha256_known_vector() {
        let h = sha256(b"abc");
        assert_eq!(
            to_hex(&h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn aes_gcm_roundtrip() {
        let key = random_array::<32>();
        let (ct, nonce) = aes_gcm_encrypt(&key, b"hello world", None).unwrap();
        let pt = aes_gcm_decrypt(&key, &ct, &nonce, None).unwrap();
        assert_eq!(&pt, b"hello world");
    }

    #[test]
    fn aes_gcm_aad_required_match() {
        let key = random_array::<32>();
        let (ct, nonce) = aes_gcm_encrypt(&key, b"msg", Some(b"ad")).unwrap();
        assert!(aes_gcm_decrypt(&key, &ct, &nonce, Some(b"other-ad")).is_err());
        assert!(aes_gcm_decrypt(&key, &ct, &nonce, Some(b"ad")).is_ok());
    }

    #[test]
    fn aes_gcm_tamper_detected() {
        let key = random_array::<32>();
        let (mut ct, nonce) = aes_gcm_encrypt(&key, b"important data", None).unwrap();
        ct[0] ^= 0xff;
        assert!(aes_gcm_decrypt(&key, &ct, &nonce, None).is_err());
    }

    #[test]
    fn aes_gcm_rejects_a_key_of_the_wrong_length() {
        assert!(matches!(
            aes_gcm_encrypt(&[0u8; 16], b"msg", None),
            Err(CryptoError::InvalidKeyLength {
                expected: 32,
                got: 16
            })
        ));
        assert!(matches!(
            aes_gcm_decrypt(&[0u8; 16], &[0u8; 32], &[0u8; NONCE_SIZE], None),
            Err(CryptoError::InvalidKeyLength {
                expected: 32,
                got: 16
            })
        ));
    }

    #[test]
    fn hkdf_outputs_length() {
        let ikm = b"input keying material";
        let salt = [0u8; 32];
        let out = hkdf_expand(ikm, &salt, b"info", 48).unwrap();
        assert_eq!(out.len(), 48);
    }

    // concat builds the associated data of the ratchet and of X3DH: dropping or
    // reordering a part would unbind a header or an identity key.
    #[test]
    fn concat_joins_every_part_in_order() {
        assert_eq!(concat(&[&b"ab"[..], b"", b"cde", b"f"]), b"abcdef");
        assert_eq!(concat(&[&b"cde"[..], b"ab"]), b"cdeab");
        assert!(concat(&[]).is_empty());
    }

    #[test]
    fn pbkdf2_deterministic() {
        let a = pbkdf2_sha256(b"pass", b"salt", 1000);
        let b = pbkdf2_sha256(b"pass", b"salt", 1000);
        assert_eq!(a, b);
    }

    fn unhex(s: &str) -> Vec<u8> {
        from_hex(s).expect("test vector is valid hex")
    }

    // RFC 5869, Appendix A, test cases A.1-A.3: https://www.rfc-editor.org/rfc/rfc5869#appendix-A
    #[test]
    fn hkdf_matches_rfc5869_a1_basic() {
        let okm = hkdf_expand(
            &unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            &unhex("000102030405060708090a0b0c"),
            &unhex("f0f1f2f3f4f5f6f7f8f9"),
            42,
        )
        .unwrap();
        assert_eq!(
            to_hex(&okm),
            concat!(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
                "34007208d5b887185865"
            )
        );
    }

    #[test]
    fn hkdf_matches_rfc5869_a2_long_inputs() {
        let ikm: Vec<u8> = (0x00..=0x4f).collect();
        let salt: Vec<u8> = (0x60..=0xaf).collect();
        let info: Vec<u8> = (0xb0..=0xff).collect();
        let okm = hkdf_expand(&ikm, &salt, &info, 82).unwrap();
        assert_eq!(
            to_hex(&okm),
            concat!(
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c",
                "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71",
                "cc30c58179ec3e87c14c01d5c1f3434f1d87"
            )
        );
    }

    #[test]
    fn hkdf_matches_rfc5869_a3_empty_salt_as_absent_salt() {
        let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let expected = concat!(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d",
            "9d201395faa4b61a96c8"
        );
        // An absent salt is HashLen zero bytes (RFC 5869 §2.2); HMAC zero-pads
        // short keys, so the empty salt and Trino's 32-byte zero salt match it.
        let mut absent = [0u8; 42];
        Hkdf::<Sha256>::new(None, &ikm)
            .expand(&[], &mut absent)
            .unwrap();
        assert_eq!(to_hex(&absent), expected);
        assert_eq!(to_hex(&hkdf_expand(&ikm, &[], &[], 42).unwrap()), expected);
        assert_eq!(
            to_hex(&hkdf_expand(&ikm, &[0u8; 32], &[], 42).unwrap()),
            expected
        );
    }

    // NIST CSRC example values, AES_GCM.pdf, GCM-AES256 Examples #1-#5: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf
    const NIST_KEY: &str = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
    const NIST_IV: &str = "cafebabefacedbaddecaf888";
    const NIST_AAD: &str = concat!(
        "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf",
        "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4"
    );
    const NIST_PT: &str = concat!(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
    );
    const NIST_CT: &str = concat!(
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
    );

    #[test]
    fn aes_gcm_matches_nist_gcm_aes256_examples() {
        let key = unhex(NIST_KEY);
        let nonce: [u8; NONCE_SIZE] = unhex(NIST_IV).try_into().unwrap();
        // (AAD, plaintext, ciphertext, tag); #5 uses 20 bytes of AAD and 60 of plaintext.
        let examples = [
            ("", "", "", "fd2caa16a5832e76aa132c1453eeda7e"),
            ("", NIST_PT, NIST_CT, "b094dac5d93471bdec1a502270e3cc6c"),
            (NIST_AAD, "", "", "de34b6dcd4cee2fdbec3cea01af1ee44"),
            (
                NIST_AAD,
                NIST_PT,
                NIST_CT,
                "c06d76f31930fef37acae23ed465ae62",
            ),
            (
                &NIST_AAD[..40],
                &NIST_PT[..120],
                &NIST_CT[..120],
                "e097195f4532da895fb917a5a55c6aa0",
            ),
        ];
        for (n, (aad_hex, pt_hex, ct_hex, tag_hex)) in examples.into_iter().enumerate() {
            let (aad_bytes, pt) = (unhex(aad_hex), unhex(pt_hex));
            let aad = (!aad_bytes.is_empty()).then_some(aad_bytes.as_slice());
            let sealed = aes_gcm_encrypt_with_nonce(&key, &nonce, &pt, aad).unwrap();
            assert_eq!(
                to_hex(&sealed),
                format!("{ct_hex}{tag_hex}"),
                "example #{}",
                n + 1
            );
            let opened = aes_gcm_decrypt(&key, &sealed, &nonce, aad).unwrap();
            assert_eq!(opened, pt, "example #{}", n + 1);
        }
    }

    #[test]
    fn aes_gcm_encrypt_is_the_explicit_nonce_form_with_a_fresh_nonce() {
        let key = random_array::<32>();
        let (first, nonce) = aes_gcm_encrypt(&key, b"msg", Some(b"ad")).unwrap();
        let (_, other_nonce) = aes_gcm_encrypt(&key, b"msg", Some(b"ad")).unwrap();
        assert_ne!(nonce, other_nonce);
        assert_eq!(
            first,
            aes_gcm_encrypt_with_nonce(&key, &nonce, b"msg", Some(b"ad")).unwrap()
        );
    }

    // RFC 7914, Section 11, first 32 of the 64 output bytes: https://www.rfc-editor.org/rfc/rfc7914#section-11
    #[test]
    fn pbkdf2_matches_rfc7914_one_iteration() {
        let dk = pbkdf2_sha256(b"passwd", b"salt", 1);
        assert_eq!(
            to_hex(&dk[..]),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
    }

    #[test]
    fn pbkdf2_matches_rfc7914_80000_iterations() {
        let dk = pbkdf2_sha256(b"Password", b"NaCl", 80_000);
        assert_eq!(
            to_hex(&dk[..]),
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
        );
    }
}
