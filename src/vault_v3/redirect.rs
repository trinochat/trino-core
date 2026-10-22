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

use super::format::{
    open_slot_uncounted, seal_slot_with_lead, SlotBytes, SLOT_LEAD_LEN, SLOT_REDIRECT,
};
use crate::crypto::{hkdf_expand, random_array};
use crate::vault::VaultError;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const KEY_INFO: &[u8] = b"trino/vault/v3/redirect-key";
const MASK_INFO: &[u8] = b"trino/vault/v3/redirect-mask";
const SEAL_INFO: &[u8] = b"trino/vault/v3/redirect";

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

/// The mask over the ephemeral key of a redirect slot.
///
/// An X25519 public key does not look like random bytes: its top bit is
/// always 0 and it is always a point of the curve, never of its twist.
/// Masked with a value only the holders of `R` can compute, the lead of a
/// redirect slot is as random as any other slot's.
pub(super) fn mask(r_pub: &[u8; 32], id_vault: &[u8; 16], position: u8) -> [u8; 32] {
    let info = [MASK_INFO, &[position]].concat();
    let okm = hkdf_expand(r_pub, id_vault, &info, 32).expect("32 bytes is a valid HKDF length");
    okm[..].try_into().expect("32 bytes")
}

/// The AEAD key of a redirect slot, from the X25519 output, bound to both
/// public keys and to the vault.
pub(super) fn seal_key(
    shared_secret: &[u8; 32],
    ephemeral_pub: &[u8; 32],
    r_pub: &[u8; 32],
    id_vault: &[u8; 16],
) -> Zeroizing<[u8; 32]> {
    let info = [SEAL_INFO, ephemeral_pub, r_pub].concat();
    let okm =
        hkdf_expand(shared_secret, id_vault, &info, 32).expect("32 bytes is a valid HKDF length");
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&okm);
    key
}

/// The redirect slot: `mk` sealed to `r_pub` with a fresh ephemeral key,
/// for position `position` of the vault named `id_vault`.
///
/// Fails with `BadPayload` if `r_pub` is a low-order point, which no
/// passphrase gives: the shared block that carried it was not written by
/// Trino.
pub(super) fn seal(
    r_pub: &[u8; 32],
    id_vault: &[u8; 16],
    position: u8,
    mk: &[u8; 32],
) -> Result<SlotBytes, VaultError> {
    let ephemeral = StaticSecret::from(random_array::<32>());
    let ephemeral_pub = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*r_pub));
    if !shared.was_contributory() {
        return Err(VaultError::BadPayload);
    }
    let key = seal_key(shared.as_bytes(), &ephemeral_pub, r_pub, id_vault);
    let mask = mask(r_pub, id_vault, position);
    let lead: [u8; SLOT_LEAD_LEN] = std::array::from_fn(|i| ephemeral_pub[i] ^ mask[i]);
    Ok(seal_slot_with_lead(
        &key,
        lead,
        id_vault,
        position,
        SLOT_REDIRECT,
        mk,
    ))
}

/// Opens a redirect slot with `r`: the MK it carries, or `None`. The same
/// work whatever the slot holds; a low-order ephemeral key opens nothing.
pub(super) fn open(
    r: &StaticSecret,
    r_pub: &[u8; 32],
    id_vault: &[u8; 16],
    position: u8,
    slot: &[u8],
) -> Option<Zeroizing<[u8; 32]>> {
    #[cfg(test)]
    super::tests::count_redirect_try();
    let mask = mask(r_pub, id_vault, position);
    let ephemeral_pub: [u8; 32] = std::array::from_fn(|i| slot[i] ^ mask[i]);
    let shared = r.diffie_hellman(&PublicKey::from(ephemeral_pub));
    let contributory = shared.was_contributory();
    let key = seal_key(shared.as_bytes(), &ephemeral_pub, r_pub, id_vault);
    match open_slot_uncounted(&key, id_vault, position, slot) {
        Some((SLOT_REDIRECT, mk)) if contributory => Some(mk),
        _ => None,
    }
}
