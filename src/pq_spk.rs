//! The signed post-quantum prekey of each device, `pq_spk`
//! (`diseno-vinculacion.md` §21.3; PQ-05, PQ-06, DN-06).
//!
//! ```text
//! pq_spk     = id u32 BE ‖ ek 1184                                   (ML-KEM-768)
//! pq_spk_sig = Ed25519(dev_sign, "trino/pqspk/v1\0" ‖ id ‖ ek)        → 1252 bytes signed
//! ```
//!
//! - **Only the 64-byte seed is stored**, never the 2400-byte private key.
//! - **Rotates every 30 days** (with the device list) and a retired key is
//!   kept **45 days** (30 of rotation, 7 of trickle and a margin), so the
//!   vault holds at most 3 seeds (192 bytes).
//! - **The signature is checked strictly** (`verify_strict`: no small-order
//!   keys, no malleable signatures), and the public key must pass the
//!   FIPS 203 check: a prekey that fails either is refused before any
//!   encapsulation (§21.2).
//!
//! The tests check signatures made by OpenSSL (`tests/vectors/pq_spk.py`).

use crate::identity::ed25519_sign;
use crate::identity::KeyPair;
use crate::kem::{validate_public_key, KemSecret, EK_LEN};
use ed25519_dalek::{Signature, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

/// How often the current prekey is replaced.
pub const PQ_SPK_ROTATION_SECS: i64 = 30 * 24 * 60 * 60;
/// How long a retired prekey still opens handshakes.
pub const PQ_SPK_RETENTION_SECS: i64 = 45 * 24 * 60 * 60;
/// The most seeds a device ever holds: the current one and two retired.
pub const MAX_PQ_SPK_SEEDS: usize = 3;
/// `id ‖ ek ‖ sig`.
pub const SIGNED_PQ_SPK_LEN: usize = 4 + EK_LEN + 64;

const DOMAIN: &[u8] = b"trino/pqspk/v1\0";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PqSpkError {
    #[error("a signed pq_spk is 1252 bytes")]
    Length,
    #[error("pq_spk signature does not verify")]
    Signature,
    #[error("pq_spk public key is malformed")]
    Key,
}

/// One of this device's post-quantum prekeys.
pub struct PqPrekey {
    pub id: u32,
    pub secret: KemSecret,
    pub created_at: i64,
}

/// A prekey that is no longer current but still opens handshakes.
pub struct RetiredPqPrekey {
    pub prekey: PqPrekey,
    pub retired_at: i64,
}

/// The current prekey and the retired ones still held.
pub struct PqPrekeys {
    pub current: PqPrekey,
    pub retired: Vec<RetiredPqPrekey>,
}

/// A signed prekey as it travels in the full `DeviceList`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPqPrekey {
    pub id: u32,
    pub ek: Box<[u8; EK_LEN]>,
    pub sig: [u8; 64],
}

impl PqPrekeys {
    /// A first prekey, id 1, created at `now`.
    pub fn new_with_rng<R: RngCore + CryptoRng>(now: i64, rng: &mut R) -> Self {
        PqPrekeys {
            current: PqPrekey {
                id: 1,
                secret: KemSecret::generate_with_rng(rng),
                created_at: now,
            },
            retired: Vec::new(),
        }
    }

    /// Rotates when due and drops retired keys past retention; true if
    /// anything changed.
    pub fn rotate_if_due_with_rng<R: RngCore + CryptoRng>(
        &mut self,
        now: i64,
        rng: &mut R,
    ) -> bool {
        let mut changed = false;
        if now - self.current.created_at >= PQ_SPK_ROTATION_SECS {
            let fresh = PqPrekey {
                id: self.current.id.wrapping_add(1),
                secret: KemSecret::generate_with_rng(rng),
                created_at: now,
            };
            let outgoing = std::mem::replace(&mut self.current, fresh);
            self.retired.push(RetiredPqPrekey {
                prekey: outgoing,
                retired_at: now,
            });
            changed = true;
        }
        let before = self.retired.len();
        self.retired
            .retain(|r| now - r.retired_at < PQ_SPK_RETENTION_SECS);
        // A clock that jumps forward can retire keys faster than retention
        // drops them; the vault never holds more than three seeds.
        let excess = (1 + self.retired.len()).saturating_sub(MAX_PQ_SPK_SEEDS);
        self.retired.drain(..excess);
        changed || self.retired.len() != before
    }

    /// The key a handshake names, current or retired.
    pub fn by_id(&self, id: u32) -> Option<&KemSecret> {
        std::iter::once(&self.current)
            .chain(self.retired.iter().map(|r| &r.prekey))
            .find(|p| p.id == id)
            .map(|p| &p.secret)
    }

    /// The current prekey, signed by this device's `dev_sign`.
    pub fn signed_current(&self, dev_sign: &KeyPair) -> SignedPqPrekey {
        SignedPqPrekey::sign(dev_sign, self.current.id, &self.current.secret.public_key())
    }
}

impl SignedPqPrekey {
    /// Signs `ek` under `id` with `dev_sign`.
    pub fn sign(dev_sign: &KeyPair, id: u32, ek: &[u8; EK_LEN]) -> Self {
        SignedPqPrekey {
            id,
            ek: Box::new(*ek),
            sig: ed25519_sign(dev_sign, &signed_message(id, ek)),
        }
    }

    /// Checks the signature against `dev_sign_pub` and the key itself.
    pub fn verify(&self, dev_sign_pub: &[u8; 32]) -> Result<(), PqSpkError> {
        let key = VerifyingKey::from_bytes(dev_sign_pub).map_err(|_| PqSpkError::Signature)?;
        key.verify_strict(
            &signed_message(self.id, &self.ek),
            &Signature::from_bytes(&self.sig),
        )
        .map_err(|_| PqSpkError::Signature)?;
        if !validate_public_key(&self.ek) {
            return Err(PqSpkError::Key);
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGNED_PQ_SPK_LEN);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.ek[..]);
        out.extend_from_slice(&self.sig);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, PqSpkError> {
        if b.len() != SIGNED_PQ_SPK_LEN {
            return Err(PqSpkError::Length);
        }
        let (id, rest) = b.split_at(4);
        let (ek, sig) = rest.split_at(EK_LEN);
        Ok(SignedPqPrekey {
            id: u32::from_be_bytes(id.try_into().expect("4 bytes")),
            ek: Box::new(ek.try_into().expect("EK_LEN bytes")),
            sig: sig.try_into().expect("64 bytes"),
        })
    }
}

fn signed_message(id: u32, ek: &[u8; EK_LEN]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN.len() + 4 + EK_LEN);
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(ek);
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha256;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../tests/vectors/pq_spk.json");
    const DAY: i64 = 24 * 60 * 60;

    fn hx<const N: usize>(v: &Value) -> [u8; N] {
        hex::decode(v.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn keypair(priv_bytes: [u8; 32]) -> KeyPair {
        let pub_bytes = ed25519_dalek::SigningKey::from_bytes(&priv_bytes)
            .verifying_key()
            .to_bytes();
        KeyPair {
            priv_bytes,
            pub_bytes,
        }
    }

    #[test]
    fn signatures_match_openssl() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        for c in v["cases"].as_array().unwrap() {
            let dev = keypair(hx(&c["dev_sign_priv"]));
            assert_eq!(dev.pub_bytes, hx::<32>(&c["dev_sign_pub"]));
            let ek = KemSecret::from_seed(&hx(&c["kem_seed"])).public_key();
            let id = c["id"].as_u64().unwrap() as u32;
            let signed = SignedPqPrekey::sign(&dev, id, &ek);
            assert_eq!(signed.sig, hx::<64>(&c["sig"]));
            let enc = signed.encode();
            assert_eq!(enc.len(), SIGNED_PQ_SPK_LEN);
            assert_eq!(SIGNED_PQ_SPK_LEN, 1252, "§21.3");
            assert_eq!(
                hex::encode(sha256(&enc)),
                c["signed_sha256"].as_str().unwrap()
            );
            let back = SignedPqPrekey::decode(&enc).unwrap();
            assert_eq!(back, signed);
            assert_eq!(back.verify(&dev.pub_bytes), Ok(()));
        }
    }

    #[test]
    fn a_wrong_key_or_any_flipped_byte_is_refused() {
        let mut rng = ChaCha20Rng::from_seed([1; 32]);
        let dev = keypair([5; 32]);
        let keys = PqPrekeys::new_with_rng(0, &mut rng);
        let enc = keys.signed_current(&dev).encode();
        assert_eq!(
            SignedPqPrekey::decode(&enc)
                .unwrap()
                .verify(&keypair([6; 32]).pub_bytes),
            Err(PqSpkError::Signature)
        );
        for i in (0..enc.len())
            .step_by(97)
            .chain([0, 3, 4, 1187, 1188, 1251])
        {
            let mut bad = enc.clone();
            bad[i] ^= 0x20;
            assert!(
                SignedPqPrekey::decode(&bad)
                    .unwrap()
                    .verify(&dev.pub_bytes)
                    .is_err(),
                "byte {i}"
            );
        }
        assert_eq!(
            SignedPqPrekey::decode(&enc[..1251]).unwrap_err(),
            PqSpkError::Length
        );
    }

    #[test]
    fn a_signed_but_malformed_key_is_refused() {
        let dev = keypair([5; 32]);
        let mut ek = KemSecret::from_seed(&[3; 64]).public_key();
        ek[0] = 0xFF;
        ek[1] |= 0x0F;
        let signed = SignedPqPrekey::sign(&dev, 1, &ek);
        assert_eq!(signed.verify(&dev.pub_bytes), Err(PqSpkError::Key));
    }

    #[test]
    fn rotation_every_30_days_and_retention_of_45() {
        let mut rng = ChaCha20Rng::from_seed([2; 32]);
        let mut keys = PqPrekeys::new_with_rng(0, &mut rng);
        assert_eq!(keys.current.id, 1);
        let first_ek = keys.current.secret.public_key();
        assert!(!keys.rotate_if_due_with_rng(30 * DAY - 1, &mut rng));
        assert!(keys.rotate_if_due_with_rng(30 * DAY, &mut rng));
        assert_eq!(keys.current.id, 2);
        assert_ne!(keys.current.secret.public_key(), first_ek);
        // The retired key still opens what was made against it.
        assert_eq!(keys.by_id(1).unwrap().public_key(), first_ek);
        assert!(keys.rotate_if_due_with_rng(60 * DAY, &mut rng));
        assert_eq!(1 + keys.retired.len(), MAX_PQ_SPK_SEEDS);
        // Key 1 retired at day 30: gone at day 75, not a second before.
        assert!(!keys.rotate_if_due_with_rng(75 * DAY - 1, &mut rng));
        assert!(keys.by_id(1).is_some());
        assert!(keys.rotate_if_due_with_rng(75 * DAY, &mut rng));
        assert!(keys.by_id(1).is_none());
        assert!(keys.by_id(2).is_some() && keys.by_id(3).is_some());
        assert!(keys.by_id(4).is_none());
    }

    #[test]
    fn never_more_than_three_seeds() {
        // Even with a clock that jumps by exactly the rotation period, or a
        // device that rotates many times in a row, at most 3 seeds remain.
        let mut rng = ChaCha20Rng::from_seed([3; 32]);
        let mut keys = PqPrekeys::new_with_rng(0, &mut rng);
        for k in 1..20 {
            keys.rotate_if_due_with_rng(k * 30 * DAY, &mut rng);
            assert!(
                keys.retired.len() < MAX_PQ_SPK_SEEDS,
                "current plus retired"
            );
        }
        let ids: Vec<u32> = keys.retired.iter().map(|r| r.prekey.id).collect();
        assert_eq!((keys.current.id, ids), (20, vec![18, 19]));
    }

    #[test]
    fn the_current_prekey_signs_and_verifies() {
        let mut rng = ChaCha20Rng::from_seed([4; 32]);
        let dev = keypair([9; 32]);
        let keys = PqPrekeys::new_with_rng(100, &mut rng);
        let signed = keys.signed_current(&dev);
        assert_eq!(signed.id, keys.current.id);
        assert_eq!(*signed.ek, *keys.current.secret.public_key());
        assert_eq!(signed.verify(&dev.pub_bytes), Ok(()));
    }
}
