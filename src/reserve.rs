//! The reserve key `B` and its blob (`diseno-vinculacion.md` §2.3 and
//! §21.9, PQ-13).
//!
//! `B` is the only key that can rotate the account without the primary
//! device (§8.3). It signs nothing while all is well; every device list
//! carries a commitment to it, and the 12-word kit wraps it:
//!
//! ```text
//! B       = (B_ed: Ed25519, B_pq: ML-DSA-65 generated from a 32-byte seed ξ)
//! rot_pqh = SHA-256(B_pq_pub)
//! next    = SHA-256("trino/reserve/v2\0" ‖ B_ed_pub ‖ rot_pqh)
//! blob    = nonce 12 ‖ AES-256-GCM(k_reserva, B_ed_priv ‖ ξ,
//!                                  aad = "trino/reserve/v2\0" ‖ next)   = 92 bytes
//! ```
//!
//! Only the hash of the ML-DSA key goes into `next`, so a classic rotation
//! does not grow by 1952 bytes; the whole key travels only the day of a
//! post-quantum rotation (`sig_suite` 0x02). The blob keeps the seed ξ, not
//! the key, so another implementation can regenerate it (`crate::mldsa`).
//!
//! The blob is bound to its `next` through the AAD, and opening it checks
//! that what comes out commits to that `next`.
//!
//! The rotation list that `B` signs is built by
//! `device::ListBody::sign_rotation` and accepted by `device::Chain` (VI-1).
//! What is not here yet (VI-5): the account mailbox.

use crate::crypto::{aes_gcm_decrypt, aes_gcm_encrypt_with_nonce};
use crate::mldsa;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

/// Length of the sealed blob.
pub const BLOB_LEN: usize = 92;

const DOMAIN: &[u8] = b"trino/reserve/v2\0";
const NONCE_LEN: usize = 12;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReserveError {
    /// The blob does not open: other words, another `next`, or a damaged
    /// blob.
    #[error("the reserve blob does not open with these words")]
    Blob,
    /// The blob opened but its key does not commit to `next`.
    #[error("the reserve key does not match its commitment")]
    Commitment,
}

/// The reserve key: its Ed25519 half and the seed of its ML-DSA-65 half.
pub struct ReserveKey {
    ed: SigningKey,
    xi: Zeroizing<[u8; mldsa::SEED_LEN]>,
    pq_hash: [u8; 32],
}

impl fmt::Debug for ReserveKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReserveKey(..)")
    }
}

/// `next`, the commitment to a reserve key that a device list carries.
pub fn commitment(ed_public: &[u8; 32], pq_hash: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(ed_public)
        .chain_update(pq_hash)
        .finalize()
        .into()
}

impl ReserveKey {
    /// A new reserve key from the system's generator.
    pub fn generate() -> ReserveKey {
        ReserveKey::generate_with_rng(&mut OsRng)
    }

    /// A new reserve key from `rng`.
    pub fn generate_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> ReserveKey {
        let mut ed_seed = Zeroizing::new([0u8; 32]);
        let mut xi = Zeroizing::new([0u8; mldsa::SEED_LEN]);
        rng.fill_bytes(&mut ed_seed[..]);
        rng.fill_bytes(&mut xi[..]);
        ReserveKey::from_seeds(&ed_seed, &xi)
    }

    /// The key made of these two seeds.
    pub(crate) fn from_seeds(ed_seed: &[u8; 32], xi: &[u8; mldsa::SEED_LEN]) -> ReserveKey {
        let pq_hash = Sha256::digest(mldsa::public_key_from_seed(xi)).into();
        ReserveKey {
            ed: SigningKey::from_bytes(ed_seed),
            xi: Zeroizing::new(*xi),
            pq_hash,
        }
    }

    /// `B_ed_pub`, which a rotation names as `rot_key`.
    pub fn ed_public(&self) -> [u8; 32] {
        self.ed.verifying_key().to_bytes()
    }

    /// `B_pq_pub`, which only a post-quantum rotation carries.
    pub fn pq_public(&self) -> [u8; mldsa::PUBLIC_LEN] {
        mldsa::public_key_from_seed(&self.xi)
    }

    /// `rot_pqh = SHA-256(B_pq_pub)`.
    pub fn pq_hash(&self) -> [u8; 32] {
        self.pq_hash
    }

    /// Signs a rotation list (`rot_sig`, §3.1). Crate-only: `B` signs
    /// nothing else.
    pub(crate) fn sign_rotation(&self, list_bytes: &[u8]) -> [u8; 64] {
        self.ed.sign(list_bytes).to_bytes()
    }

    /// `next` for this key.
    pub fn next(&self) -> [u8; 32] {
        commitment(&self.ed_public(), &self.pq_hash)
    }

    /// The blob that wraps this key under `k_reserva`.
    pub fn seal(&self, k_reserva: &[u8; 32]) -> [u8; BLOB_LEN] {
        self.seal_with_rng(k_reserva, &mut OsRng)
    }

    /// [`ReserveKey::seal`] with the nonce from `rng`.
    pub fn seal_with_rng<R: RngCore + CryptoRng>(
        &self,
        k_reserva: &[u8; 32],
        rng: &mut R,
    ) -> [u8; BLOB_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let mut plain = Zeroizing::new([0u8; 64]);
        plain[..32].copy_from_slice(self.ed.as_bytes());
        plain[32..].copy_from_slice(&self.xi[..]);
        let sealed =
            aes_gcm_encrypt_with_nonce(k_reserva, &nonce, &plain[..], Some(&aad(&self.next())))
                .expect("a 32-byte key and 64 bytes always seal");
        let mut blob = [0u8; BLOB_LEN];
        blob[..NONCE_LEN].copy_from_slice(&nonce);
        blob[NONCE_LEN..].copy_from_slice(&sealed);
        blob
    }

    /// Opens a blob with `k_reserva` and checks it against `next`.
    pub fn open(
        k_reserva: &[u8; 32],
        blob: &[u8; BLOB_LEN],
        next: &[u8; 32],
    ) -> Result<ReserveKey, ReserveError> {
        let (nonce, sealed) = blob.split_at(NONCE_LEN);
        let plain = Zeroizing::new(
            aes_gcm_decrypt(k_reserva, sealed, nonce, Some(&aad(next)))
                .map_err(|_| ReserveError::Blob)?,
        );
        let ed_seed: &[u8; 32] = plain[..32].try_into().expect("64 bytes inside");
        let xi: &[u8; 32] = plain[32..].try_into().expect("64 bytes inside");
        let key = ReserveKey::from_seeds(ed_seed, xi);
        if key.next() != *next {
            return Err(ReserveError::Commitment);
        }
        Ok(key)
    }
}

/// The AAD of a blob: the domain and the `next` it is bound to.
fn aad(next: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN.len() + 32);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(next);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../tests/vectors/reserve.json");

    fn cases() -> Vec<Value> {
        serde_json::from_str::<Value>(VECTORS).unwrap()["cases"]
            .as_array()
            .unwrap()
            .clone()
    }

    fn h<const N: usize>(v: &Value) -> [u8; N] {
        hex::decode(v.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    /// An RNG that hands out the vector's nonce.
    struct Fixed(Vec<u8>);
    impl RngCore for Fixed {
        fn next_u32(&mut self) -> u32 {
            unimplemented!()
        }
        fn next_u64(&mut self) -> u64 {
            unimplemented!()
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let n = dest.len();
            dest.copy_from_slice(&self.0[..n]);
            self.0.drain(..n);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for Fixed {}

    #[test]
    fn the_key_and_commitment_match_the_independent_vectors() {
        for c in cases() {
            let key = ReserveKey::from_seeds(&h(&c["ed_seed"]), &h(&c["xi"]));
            assert_eq!(key.ed_public(), h::<32>(&c["ed_pub"]));
            assert_eq!(key.pq_hash(), h::<32>(&c["pq_pub_sha256"]));
            assert_eq!(Sha256::digest(key.pq_public())[..], key.pq_hash());
            assert_eq!(key.next(), h::<32>(&c["next"]));
            assert_eq!(commitment(&key.ed_public(), &key.pq_hash()), key.next());
        }
    }

    #[test]
    fn the_blob_matches_the_independent_vectors() {
        for c in cases() {
            let key = ReserveKey::from_seeds(&h(&c["ed_seed"]), &h(&c["xi"]));
            let nonce: [u8; NONCE_LEN] = h(&c["nonce"]);
            let blob = key.seal_with_rng(&h(&c["k_reserva"]), &mut Fixed(nonce.to_vec()));
            assert_eq!(blob, h::<BLOB_LEN>(&c["blob"]));
        }
    }

    #[test]
    fn an_openssl_blob_opens_to_the_same_key() {
        for c in cases() {
            let key =
                ReserveKey::open(&h(&c["k_reserva"]), &h(&c["blob"]), &h(&c["next"])).unwrap();
            assert_eq!(key.ed_public(), h::<32>(&c["ed_pub"]));
            assert_eq!(key.next(), h::<32>(&c["next"]));
        }
    }

    #[test]
    fn other_words_or_another_next_do_not_open_the_blob() {
        let c = &cases()[0];
        let (k, blob, next): ([u8; 32], [u8; BLOB_LEN], [u8; 32]) =
            (h(&c["k_reserva"]), h(&c["blob"]), h(&c["next"]));
        let mut other_k = k;
        other_k[0] ^= 1;
        assert_eq!(
            ReserveKey::open(&other_k, &blob, &next).unwrap_err(),
            ReserveError::Blob
        );
        let mut other_next = next;
        other_next[31] ^= 1;
        assert_eq!(
            ReserveKey::open(&k, &blob, &other_next).unwrap_err(),
            ReserveError::Blob
        );
        for i in [0, 12, 50, BLOB_LEN - 1] {
            let mut damaged = blob;
            damaged[i] ^= 0x80;
            assert_eq!(
                ReserveKey::open(&k, &damaged, &next).unwrap_err(),
                ReserveError::Blob
            );
        }
    }

    #[test]
    fn a_blob_whose_key_does_not_commit_to_next_is_refused() {
        // Whoever has k_reserva could seal any key under any next: opening
        // still checks the commitment.
        let c = &cases()[1];
        let (k, next): ([u8; 32], [u8; 32]) = (h(&c["k_reserva"]), h(&c["next"]));
        let other = ReserveKey::from_seeds(&[9; 32], &[9; 32]);
        let mut aad = DOMAIN.to_vec();
        aad.extend_from_slice(&next);
        let mut plain = [9u8; 64];
        let nonce = [3u8; NONCE_LEN];
        let sealed = aes_gcm_encrypt_with_nonce(&k, &nonce, &plain, Some(&aad)).unwrap();
        plain.fill(0);
        let mut blob = [0u8; BLOB_LEN];
        blob[..NONCE_LEN].copy_from_slice(&nonce);
        blob[NONCE_LEN..].copy_from_slice(&sealed);
        assert_ne!(other.next(), next);
        assert_eq!(
            ReserveKey::open(&k, &blob, &next).unwrap_err(),
            ReserveError::Commitment
        );
    }

    #[test]
    fn a_new_key_seals_and_opens() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([4; 32]);
        let key = ReserveKey::generate_with_rng(&mut rng);
        let k = [7u8; 32];
        let blob = key.seal_with_rng(&k, &mut rng);
        let back = ReserveKey::open(&k, &blob, &key.next()).unwrap();
        assert_eq!(
            (back.ed_public(), back.pq_hash()),
            (key.ed_public(), key.pq_hash())
        );
        // Two seals of one key never share a nonce.
        assert_ne!(key.seal(&k)[..NONCE_LEN], key.seal(&k)[..NONCE_LEN]);
        assert_ne!(ReserveKey::generate().next(), ReserveKey::generate().next());
    }

    #[test]
    fn the_debug_form_hides_the_key() {
        let key = ReserveKey::from_seeds(&[1; 32], &[2; 32]);
        assert_eq!(format!("{key:?}"), "ReserveKey(..)");
    }
}
