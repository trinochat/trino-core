//! The redirect of CE-D12 (design §3.8): after the emergency path, the real
//! passphrase opens the empty account too.
//!
//! Every passphrase's KEK gives an X25519 key pair, `r` and `R`, through its
//! own HKDF domain that does not depend on `id_vault` (the emergency path
//! changes it). The shared block of every vault carries the `R` of the
//! current real passphrase. The emergency path, which reads the shared
//! block, seals the new MK to that `R` in the slot position it would
//! otherwise fill with random bytes. Unlocking derives `r` from the KEK it
//! already has, so the real passphrase opens that slot with no second
//! derivation.

use crate::crypto::hkdf_expand;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const KEY_INFO: &[u8] = b"trino/vault/v3/redirect-key";

/// `r`, the private redirect key of the passphrase whose KEK this is.
pub(super) fn secret_key(kek: &[u8; 32]) -> StaticSecret {
    let okm = hkdf_expand(kek, &[], KEY_INFO, 32).expect("32 bytes is a valid HKDF length");
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&okm);
    StaticSecret::from(*bytes)
}

/// `R`, the public redirect key of the passphrase whose KEK this is.
pub(super) fn public_key(kek: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&secret_key(kek)).to_bytes()
}
