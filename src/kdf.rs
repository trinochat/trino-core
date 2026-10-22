//! Argon2id, the passphrase KDF of the version 3 vault.
//!
//! RFC 9106 §4, second recommended option for when 2 GiB is not available:
//! Argon2id, version 0x13, `m = 64 MiB, t = 3, p = 4`, a 128-bit salt and a
//! 256-bit tag (`KdfParams::PRODUCTION`). The parameters travel in the vault
//! header, so a vault can be opened by a later Trino with stronger defaults.
//! Because anyone can write that header, `KdfParams::check` bounds them
//! before any derivation: a planted vault asking for 1 TiB must not take
//! Trino down.
//!
//! The crate is RustCrypto's `argon2` 0.5.3 with its `zeroize` feature. That
//! feature wipes the crate's own temporaries (the initial hash, the final
//! block) but **not** the memory matrix that `Argon2::hash_password_into`
//! allocates and drops as is. The matrix is enough to recompute the key
//! (the tag is BLAKE2b of the last block of each lane), so this module hands
//! the crate its own matrix inside `Zeroizing`, which wipes all of it on
//! drop. RFC 9106 §4 asks implementations to wipe that memory.

use argon2::{Algorithm, Argon2, AssociatedData, Block, ParamsBuilder, Version};
use thiserror::Error;
use zeroize::Zeroizing;

/// Length of every key this module derives.
pub const KEY_LEN: usize = 32;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KdfError {
    /// The parameters fall outside `KdfParams::check`'s bounds.
    #[error("argon2id parameters out of bounds")]
    ParamsOutOfBounds,
    #[error("argon2id failed")]
    Failed,
}

/// Argon2id costs: memory in KiB, passes and lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u8,
}

impl KdfParams {
    /// RFC 9106's second option (decision CE-D1, 15 Oct 2026).
    pub const PRODUCTION: KdfParams = KdfParams {
        m_kib: 64 * 1024,
        t: 3,
        p: 4,
    };

    /// OWASP's floor, 19 MiB (`m = 19 MiB, t = 2, p = 1`).
    pub const MIN_M_KIB: u32 = 19 * 1024;
    /// 1 GiB: a vault cannot ask for more memory than this.
    pub const MAX_M_KIB: u32 = 1024 * 1024;
    pub const MIN_T: u32 = 1;
    pub const MAX_T: u32 = 10;
    pub const MIN_P: u8 = 1;
    pub const MAX_P: u8 = 8;

    /// Whether these parameters are within the bounds a vault may ask for.
    pub fn check(&self) -> Result<(), KdfError> {
        let in_bounds = (Self::MIN_M_KIB..=Self::MAX_M_KIB).contains(&self.m_kib)
            && (Self::MIN_T..=Self::MAX_T).contains(&self.t)
            && (Self::MIN_P..=Self::MAX_P).contains(&self.p);
        if in_bounds {
            Ok(())
        } else {
            Err(KdfError::ParamsOutOfBounds)
        }
    }
}

/// Argon2id of `passphrase` under `salt` and `params`, after `check`.
pub fn argon2id(
    passphrase: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, KdfError> {
    params.check()?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2id_raw(passphrase, salt, &[], &[], params, &mut key[..])?;
    Ok(key)
}

/// Argon2id with every input RFC 9106 has, and no bounds: for the vectors.
fn argon2id_raw(
    passphrase: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    params: &KdfParams,
    out: &mut [u8],
) -> Result<(), KdfError> {
    let mut builder = ParamsBuilder::new();
    builder
        .m_cost(params.m_kib)
        .t_cost(params.t)
        .p_cost(u32::from(params.p))
        .output_len(out.len());
    if !associated_data.is_empty() {
        builder.data(AssociatedData::new(associated_data).map_err(|_| KdfError::Failed)?);
    }
    let argon2_params = builder.build().map_err(|_| KdfError::Failed)?;
    let argon2 = if secret.is_empty() {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params)
    } else {
        Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, argon2_params)
            .map_err(|_| KdfError::Failed)?
    };
    // Our own matrix, wiped on drop, instead of the one
    // `hash_password_into` would allocate and drop without wiping.
    let mut memory = Zeroizing::new(vec![Block::default(); argon2.params().block_count()]);
    argon2
        .hash_password_into_with_memory(passphrase, salt, out, &mut memory[..])
        .map_err(|_| KdfError::Failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s.split_whitespace().collect::<String>()).unwrap()
    }

    /// RFC 9106 §5.3, the Argon2id test vector.
    #[test]
    fn the_argon2id_vector_of_rfc_9106_passes() {
        let params = KdfParams {
            m_kib: 32,
            t: 3,
            p: 4,
        };
        let mut tag = [0u8; 32];
        argon2id_raw(
            &[0x01; 32],
            &[0x02; 16],
            &[0x03; 8],
            &[0x04; 12],
            &params,
            &mut tag,
        )
        .unwrap();
        assert_eq!(
            tag.to_vec(),
            hex("0d 64 0d f5 8d 78 76 6c 08 c0 37 a3 4a 8b 53 c9
                 d0 1e f0 45 2d 75 b6 5e b5 25 20 e9 6b 01 e6 59")
        );
    }

    /// The reference implementation's Argon2id vectors (phc-winner-argon2,
    /// `src/test.c`), which use neither a secret nor associated data, as the
    /// vault does.
    #[test]
    fn the_reference_argon2id_vectors_without_secret_pass() {
        for (p, expected) in [
            (
                1,
                "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe",
            ),
            (
                2,
                "6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037",
            ),
        ] {
            let params = KdfParams {
                m_kib: 256,
                t: 2,
                p,
            };
            let mut tag = [0u8; 32];
            argon2id_raw(b"password", b"somesalt", &[], &[], &params, &mut tag).unwrap();
            assert_eq!(hex::encode(tag), expected, "p = {p}");
        }
    }

    #[test]
    fn production_parameters_are_rfc_9106_second_option() {
        assert_eq!(
            KdfParams::PRODUCTION,
            KdfParams {
                m_kib: 65536,
                t: 3,
                p: 4
            }
        );
        assert_eq!(KdfParams::PRODUCTION.check(), Ok(()));
    }

    #[test]
    fn parameters_out_of_bounds_are_refused() {
        let ok = KdfParams::PRODUCTION;
        for bad in [
            KdfParams {
                m_kib: KdfParams::MIN_M_KIB - 1,
                ..ok
            },
            KdfParams {
                m_kib: KdfParams::MAX_M_KIB + 1,
                ..ok
            },
            KdfParams { m_kib: 0, ..ok },
            KdfParams {
                m_kib: u32::MAX,
                ..ok
            },
            KdfParams { t: 0, ..ok },
            KdfParams { t: 11, ..ok },
            KdfParams { p: 0, ..ok },
            KdfParams { p: 9, ..ok },
        ] {
            assert_eq!(bad.check(), Err(KdfError::ParamsOutOfBounds), "{bad:?}");
            assert_eq!(
                argon2id(b"pass", &[0; 16], &bad).err(),
                Some(KdfError::ParamsOutOfBounds),
                "{bad:?}"
            );
        }
        for edge in [
            KdfParams {
                m_kib: KdfParams::MIN_M_KIB,
                t: 1,
                p: 1,
            },
            KdfParams {
                m_kib: KdfParams::MAX_M_KIB,
                t: 10,
                p: 8,
            },
        ] {
            assert_eq!(edge.check(), Ok(()), "{edge:?}");
        }
    }

    /// Times `KdfParams::PRODUCTION` on this machine. Ignored, so as not to
    /// load the computer on every run:
    /// `cargo test --release kdf::tests::time_production -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn time_production_parameters() {
        let runs = 10;
        let mut times = Vec::with_capacity(runs);
        for i in 0..runs {
            let start = std::time::Instant::now();
            let key = argon2id(b"timing", &[i as u8; 16], &KdfParams::PRODUCTION).unwrap();
            times.push(start.elapsed());
            assert_ne!(*key, [0u8; 32]);
        }
        times.sort();
        println!(
            "argon2id m=64 MiB t=3 p=4: min {:?}, median {:?}, max {:?} over {runs} runs",
            times[0],
            times[runs / 2],
            times[runs - 1]
        );
    }

    /// The bounded entry point is the same Argon2id as the raw one.
    #[test]
    fn argon2id_matches_the_raw_derivation_at_the_minimum() {
        let params = KdfParams {
            m_kib: KdfParams::MIN_M_KIB,
            t: 1,
            p: 1,
        };
        let key = argon2id(b"pass", &[7; 16], &params).unwrap();
        let mut raw = [0u8; 32];
        argon2id_raw(b"pass", &[7; 16], &[], &[], &params, &mut raw).unwrap();
        assert_eq!(*key, raw);
        assert_ne!(raw, [0u8; 32]);
        let other = argon2id(b"pasS", &[7; 16], &params).unwrap();
        assert_ne!(*key, *other);
    }
}
