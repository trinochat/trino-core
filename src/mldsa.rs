//! ML-DSA-65 key generation (FIPS 204), for the post-quantum half of the
//! reserve key (`diseno-vinculacion.md` §21.9, PQ-13).
//!
//! Only `ML-DSA.KeyGen_internal` from a 32-byte seed `ξ`: nothing is signed
//! with it until a post-quantum rotation (`sig_suite` 0x02) exists. A bug
//! here would only show the day of that rotation, so the tests check NIST's
//! ACVP `keyGen` vectors for ML-DSA-65 (`tests/vectors/README.md`), and the
//! reserve keeps the seed, not the key, so another implementation can
//! regenerate it.
//!
//! The crate is RustCrypto's `ml-dsa` 0.1.1 (DN-05) with its `zeroize`
//! feature, so the signing key it expands is wiped when dropped.

use ml_dsa::signature::Keypair;
use ml_dsa::{MlDsa65, SigningKey};

/// Length of the seed `ξ`.
pub const SEED_LEN: usize = 32;
/// Length of an encoded ML-DSA-65 public key.
pub const PUBLIC_LEN: usize = 1952;

/// The ML-DSA-65 public key that `ξ` generates.
pub fn public_key_from_seed(xi: &[u8; SEED_LEN]) -> [u8; PUBLIC_LEN] {
    // The signing key (and its copy of the seed) is wiped when it drops.
    let key = SigningKey::<MlDsa65>::from_seed(&(*xi).into());
    key.verifying_key()
        .encode()
        .as_slice()
        .try_into()
        .expect("an ML-DSA-65 public key is 1952 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const ACVP: &str = include_str!("../tests/vectors/acvp_mldsa_keygen.json");

    /// The ML-DSA-65 cases of the ACVP keyGen file: (seed, pk, sk).
    fn cases() -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let v: Value = serde_json::from_str(ACVP).unwrap();
        assert_eq!(v["algorithm"], "ML-DSA");
        assert_eq!(v["mode"], "keyGen");
        assert_eq!(v["revision"], "FIPS204");
        let groups: Vec<&Value> = v["testGroups"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|g| g["parameterSet"] == "ML-DSA-65")
            .collect();
        assert_eq!(groups.len(), 1);
        let h = |t: &Value, k: &str| hex::decode(t[k].as_str().unwrap()).unwrap();
        groups[0]["tests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| (h(t, "seed"), h(t, "pk"), h(t, "sk")))
            .collect()
    }

    #[test]
    fn the_acvp_keygen_vectors_give_the_public_key() {
        let cases = cases();
        assert_eq!(cases.len(), 25);
        for (seed, pk, _) in cases {
            let xi: [u8; SEED_LEN] = seed.try_into().unwrap();
            assert_eq!(public_key_from_seed(&xi).to_vec(), pk);
        }
    }

    #[test]
    fn the_acvp_keygen_vectors_give_the_signing_key_too() {
        // The expanded signing key is never stored (the reserve keeps the
        // seed), but checking it confirms the whole of KeyGen_internal.
        for (seed, _, sk) in cases() {
            let key = SigningKey::<MlDsa65>::from_seed(&seed.as_slice().try_into().unwrap());
            #[allow(deprecated)]
            let expanded = key.expanded_key().to_expanded();
            assert_eq!(expanded.as_slice(), sk.as_slice());
        }
    }

    #[test]
    fn different_seeds_give_different_keys() {
        assert_ne!(
            public_key_from_seed(&[1; SEED_LEN])[..],
            public_key_from_seed(&[2; SEED_LEN])[..]
        );
    }
}
