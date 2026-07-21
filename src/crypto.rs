use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

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

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

pub fn random_array<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn hkdf_expand(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm).map_err(|_| CryptoError::Hkdf)?;
    Ok(okm)
}

pub fn aes_gcm_encrypt(
    key: &[u8],
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<(Vec<u8>, [u8; NONCE_SIZE]), CryptoError> {
    if key.len() != KEY_SIZE {
        return Err(CryptoError::InvalidKeyLength {
            expected: KEY_SIZE,
            got: key.len(),
        });
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::Aead)?;
    let nonce_bytes: [u8; NONCE_SIZE] = random_array();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = match associated_data {
        Some(aad) => Payload {
            msg: plaintext,
            aad,
        },
        None => Payload::from(plaintext),
    };
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| CryptoError::Aead)?;
    Ok((ciphertext, nonce_bytes))
}

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

pub fn pbkdf2_sha256(passphrase: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase, salt, iterations, &mut out);
    out
}

pub fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut out = Vec::with_capacity(total);
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn from_hex(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(s)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn hkdf_outputs_length() {
        let ikm = b"input keying material";
        let salt = [0u8; 32];
        let out = hkdf_expand(ikm, &salt, b"info", 48).unwrap();
        assert_eq!(out.len(), 48);
    }

    #[test]
    fn pbkdf2_deterministic() {
        let a = pbkdf2_sha256(b"pass", b"salt", 1000);
        let b = pbkdf2_sha256(b"pass", b"salt", 1000);
        assert_eq!(a, b);
    }
}
