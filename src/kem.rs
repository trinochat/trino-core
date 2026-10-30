//! ML-KEM-768 (FIPS 203) for the hybrid handshake (PQ-01, PQ-02, PQ-03).
//!
//! A thin wrapper over `libcrux-ml-kem`, pinned to an exact version in
//! `Cargo.toml` (`=0.0.11`, Apache-2.0): pure Rust, the primitive Signal's
//! SPQR uses. Spike S-PQ checked it against RustCrypto's `ml-kem` and the
//! IETF LAMPS examples; the tests here check it again against RustCrypto
//! and against OpenSSL (`tests/vectors/mlkem768.py`).
//!
//! - **Only the 64-byte seed is kept** (`d ‖ z` of FIPS 203, §21.3): the
//!   2400-byte private key is rebuilt from it for each decapsulation.
//! - **Randomness is injectable** (`*_with_rng`): the callers pass a
//!   `ChaCha20Rng` seeded from the operating system ([`drbg`]), as the
//!   libcrux README recommends over reading `OsRng` directly, and tests pass
//!   a seeded one to get fixed vectors.
//! - **The public key is validated before encapsulating** (the FIPS 203
//!   modulus check), so a malformed prekey is refused, not used.
//! - **Wiping is best effort.** libcrux's key types do not wipe themselves;
//!   every private key and shared secret is moved back into a `Zeroizing`
//!   buffer right after use. Copies the compiler makes on the way are out of
//!   reach, as everywhere in Rust.

use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use thiserror::Error;
use zeroize::Zeroizing;

/// An ML-KEM-768 encapsulation (public) key.
pub const EK_LEN: usize = 1184;
/// An ML-KEM-768 ciphertext.
pub const CT_LEN: usize = 1088;
/// The shared secret.
pub const SS_LEN: usize = 32;
/// The key generation seed, `d ‖ z`.
pub const SEED_LEN: usize = 64;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KemError {
    #[error("ML-KEM-768 public key is malformed")]
    InvalidKey,
}

/// A decapsulation key, kept as its seed.
#[derive(Clone)]
pub struct KemSecret {
    seed: Zeroizing<[u8; SEED_LEN]>,
}

/// A deterministic random bit generator seeded from the operating system.
pub fn drbg() -> ChaCha20Rng {
    ChaCha20Rng::from_entropy()
}

impl KemSecret {
    /// The key of a stored seed.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        KemSecret {
            seed: Zeroizing::new(*seed),
        }
    }

    /// A new key from `rng`.
    pub fn generate_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        rng.fill_bytes(&mut seed[..]);
        KemSecret { seed }
    }

    /// The libcrux key pair of the seed: the public key and the private key
    /// moved into a wiped buffer.
    fn expand(&self) -> (Box<[u8; EK_LEN]>, Zeroizing<[u8; 2400]>) {
        let (sk, pk) = mlkem768::generate_key_pair(*self.seed).into_parts();
        (Box::new(pk.into()), Zeroizing::new(sk.into()))
    }

    /// The seed, the only thing to store.
    pub fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// The encapsulation key to publish.
    pub fn public_key(&self) -> Box<[u8; EK_LEN]> {
        self.expand().0
    }

    /// The shared secret of a ciphertext. A ciphertext that was not made for
    /// this key gives an unrelated secret (implicit rejection), never an
    /// error: the handshake fails later, on its AEAD.
    pub fn decapsulate(&self, ct: &[u8; CT_LEN]) -> Zeroizing<[u8; SS_LEN]> {
        let (_, sk_bytes) = self.expand();
        let sk = MlKem768PrivateKey::from(&*sk_bytes);
        let ss = Zeroizing::new(mlkem768::decapsulate(&sk, &MlKem768Ciphertext::from(ct)));
        // Back into a buffer that wipes itself.
        let _wiped = Zeroizing::new(<[u8; 2400]>::from(sk));
        ss
    }
}

/// A ciphertext and the shared secret it carries.
pub type Encapsulated = (Box<[u8; CT_LEN]>, Zeroizing<[u8; SS_LEN]>);

/// Encapsulates to `ek` with 32 bytes from `rng`.
pub fn encapsulate_with_rng<R: RngCore + CryptoRng>(
    ek: &[u8; EK_LEN],
    rng: &mut R,
) -> Result<Encapsulated, KemError> {
    let pk = MlKem768PublicKey::from(ek);
    if !mlkem768::validate_public_key(&pk) {
        return Err(KemError::InvalidKey);
    }
    let mut m = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut m[..]);
    let (ct, ss) = mlkem768::encapsulate(&pk, *m);
    Ok((Box::new(ct.into()), Zeroizing::new(ss)))
}

/// Whether `ek` passes the FIPS 203 encapsulation key check.
pub fn validate_public_key(ek: &[u8; EK_LEN]) -> bool {
    mlkem768::validate_public_key(&MlKem768PublicKey::from(ek))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const OPENSSL: &str = include_str!("../tests/vectors/mlkem768.json");

    fn hx<const N: usize>(v: &Value) -> [u8; N] {
        hex::decode(v.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn the_lamps_example_key() {
        // IETF LAMPS kyber-certificates example: seed 00 01 .. 3f. Its public
        // key hash was computed by RustCrypto, OpenSSL and libcrux in spike
        // S-PQ, and all three agreed.
        let seed: [u8; 64] = core::array::from_fn(|i| i as u8);
        let ek = KemSecret::from_seed(&seed).public_key();
        assert_eq!(
            hex::encode(crate::crypto::sha256(&ek[..])),
            "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9"
        );
    }

    #[test]
    fn openssl_ciphertexts_open_to_openssl_secrets() {
        let v: Value = serde_json::from_str(OPENSSL).unwrap();
        for c in v["cases"].as_array().unwrap() {
            let key = KemSecret::from_seed(&hx(&c["seed"]));
            let ek = key.public_key();
            assert_eq!(
                hex::encode(crate::crypto::sha256(&ek[..])),
                c["ek_sha256"].as_str().unwrap()
            );
            if let Some(full) = c["ek"].as_str() {
                assert_eq!(hex::encode(&ek[..]), full);
            }
            assert_eq!(*key.decapsulate(&hx(&c["ct"])), hx::<32>(&c["ss"]));
            assert_eq!(
                *key.decapsulate(&hx(&c["bad_ct"])),
                hx::<32>(&c["rejected_ss"])
            );
        }
    }

    #[test]
    fn libcrux_and_rustcrypto_agree() {
        use ml_kem::{Decapsulate, KeyExport};
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        for _ in 0..50 {
            let mut seed = [0u8; 64];
            rng.fill_bytes(&mut seed);
            let ours = KemSecret::from_seed(&seed);
            let theirs = ml_kem::DecapsulationKey768::from_seed(seed.into());
            let ek = ours.public_key();
            assert_eq!(&ek[..], theirs.encapsulation_key().to_bytes().as_slice());
            // Same 32 bytes of randomness on both sides.
            let mut m = [0u8; 32];
            rng.fill_bytes(&mut m);
            let (ct, ss) = encapsulate_with_rng(&ek, &mut ChaCha20Rng::from_seed(m)).unwrap();
            let mut m2 = [0u8; 32];
            ChaCha20Rng::from_seed(m).fill_bytes(&mut m2);
            let ek_rc = ml_kem::EncapsulationKey768::new(ek.as_ref().into()).unwrap();
            let (ct_rc, ss_rc) = ek_rc.encapsulate_deterministic(&m2.into());
            assert_eq!(&ct[..], ct_rc.as_slice());
            assert_eq!(&ss[..], ss_rc.as_slice());
            assert_eq!(theirs.decapsulate(&ct_rc).as_slice(), &ss[..]);
        }
    }

    #[test]
    fn a_round_trip_agrees_and_a_wrong_key_does_not() {
        let mut rng = ChaCha20Rng::from_seed([1; 32]);
        let bob = KemSecret::generate_with_rng(&mut rng);
        let eve = KemSecret::generate_with_rng(&mut rng);
        let (ct, ss) = encapsulate_with_rng(&bob.public_key(), &mut rng).unwrap();
        assert_eq!(*bob.decapsulate(&ct), *ss);
        assert_ne!(*eve.decapsulate(&ct), *ss);
        assert_eq!(*KemSecret::from_seed(bob.seed()).decapsulate(&ct), *ss);
    }

    #[test]
    fn a_seeded_generator_gives_fixed_keys() {
        let a = KemSecret::generate_with_rng(&mut ChaCha20Rng::from_seed([2; 32]));
        let b = KemSecret::generate_with_rng(&mut ChaCha20Rng::from_seed([2; 32]));
        assert_eq!(a.seed(), b.seed());
        assert_ne!(
            KemSecret::generate_with_rng(&mut drbg()).seed(),
            KemSecret::generate_with_rng(&mut drbg()).seed()
        );
    }

    #[test]
    fn a_malformed_public_key_is_refused() {
        let mut ek = KemSecret::from_seed(&[3; 64]).public_key();
        assert!(validate_public_key(&ek));
        // The first 12-bit coefficient set to 4095, above q = 3329.
        ek[0] = 0xFF;
        ek[1] |= 0x0F;
        assert!(!validate_public_key(&ek));
        assert_eq!(
            encapsulate_with_rng(&ek, &mut ChaCha20Rng::from_seed([4; 32])).unwrap_err(),
            KemError::InvalidKey
        );
    }
}
