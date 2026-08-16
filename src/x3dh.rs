use crate::crypto::{concat, hkdf_expand, CryptoError};
use crate::identity::{
    consume_one_time_prekey, decode_array_32, generate_x25519, signed_prekey_by_id, verify_bundle,
    x25519_derive_shared, Identity, IdentityError, PublicBundle,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const HKDF_SALT: [u8; 32] = [0u8; 32];
const HKDF_INFO: &[u8] = b"trino-x3dh-v1";

#[derive(Debug, Error)]
pub enum X3dhError {
    #[error("bundle signature invalid")]
    InvalidBundle,
    #[error("unknown SPK id: {0}")]
    UnknownSpk(u32),
    #[error("OPK {0} already consumed or unknown")]
    UnknownOpk(u32),
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitialMessage {
    #[serde(rename = "ikDhPub")]
    pub ik_dh_pub: String,
    #[serde(rename = "ekPub")]
    pub ek_pub: String,
    #[serde(rename = "spkId")]
    pub spk_id: u32,
    #[serde(rename = "opkId")]
    pub opk_id: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct InitiatorResult {
    pub master_secret: [u8; 32],
    pub message: InitialMessage,
    pub associated_data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ResponderResult {
    pub master_secret: [u8; 32],
    pub associated_data: Vec<u8>,
}

pub fn initiate(ours: &Identity, theirs: &PublicBundle) -> Result<InitiatorResult, X3dhError> {
    if !verify_bundle(theirs) {
        return Err(X3dhError::InvalidBundle);
    }
    let their_ik_dh_pub = decode_array_32(&theirs.ik_dh_pub)?;
    let their_spk_pub = decode_array_32(&theirs.spk_pub)?;

    let ek = generate_x25519();

    let dh1 = x25519_derive_shared(&ours.ik_dh.priv_bytes, &their_spk_pub);
    let dh2 = x25519_derive_shared(&ek.priv_bytes, &their_ik_dh_pub);
    let dh3 = x25519_derive_shared(&ek.priv_bytes, &their_spk_pub);

    let mut dh_inputs: Vec<u8> = Vec::with_capacity(96);
    dh_inputs.extend_from_slice(&dh1);
    dh_inputs.extend_from_slice(&dh2);
    dh_inputs.extend_from_slice(&dh3);

    let okm = hkdf_expand(&dh_inputs, &HKDF_SALT, HKDF_INFO, 32)?;
    let mut master_secret = [0u8; 32];
    master_secret.copy_from_slice(&okm);

    let associated_data = concat(&[&ours.ik_dh.pub_bytes, &their_ik_dh_pub]);

    Ok(InitiatorResult {
        master_secret,
        message: InitialMessage {
            ik_dh_pub: hex::encode(ours.ik_dh.pub_bytes),
            ek_pub: hex::encode(ek.pub_bytes),
            spk_id: theirs.spk_id,
            opk_id: None,
        },
        associated_data,
    })
}

pub fn respond(ours: &mut Identity, msg: &InitialMessage) -> Result<ResponderResult, X3dhError> {
    // Accept the current signed prekey OR one we rotated away from but still
    // retain. Peers cache our bundle out-of-band, so after a rotation they will
    // legitimately keep presenting the older id — including on every auto-heal
    // re-handshake. Rejecting those would strand the peer permanently.
    let spk_priv = signed_prekey_by_id(ours, msg.spk_id)
        .ok_or(X3dhError::UnknownSpk(msg.spk_id))?
        .keypair
        .priv_bytes;

    let their_ik_dh_pub = decode_array_32(&msg.ik_dh_pub)?;
    let their_ek_pub = decode_array_32(&msg.ek_pub)?;

    let dh1 = x25519_derive_shared(&spk_priv, &their_ik_dh_pub);
    let dh2 = x25519_derive_shared(&ours.ik_dh.priv_bytes, &their_ek_pub);
    let dh3 = x25519_derive_shared(&spk_priv, &their_ek_pub);

    let mut dh_inputs: Vec<u8> = Vec::with_capacity(128);
    dh_inputs.extend_from_slice(&dh1);
    dh_inputs.extend_from_slice(&dh2);
    dh_inputs.extend_from_slice(&dh3);

    if let Some(opk_id) = msg.opk_id {
        let opk = consume_one_time_prekey(ours, opk_id).ok_or(X3dhError::UnknownOpk(opk_id))?;
        let dh4 = x25519_derive_shared(&opk.keypair.priv_bytes, &their_ek_pub);
        dh_inputs.extend_from_slice(&dh4);
    }

    let okm = hkdf_expand(&dh_inputs, &HKDF_SALT, HKDF_INFO, 32)?;
    let mut master_secret = [0u8; 32];
    master_secret.copy_from_slice(&okm);

    let associated_data = concat(&[&their_ik_dh_pub, &ours.ik_dh.pub_bytes]);

    Ok(ResponderResult {
        master_secret,
        associated_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{create_identity, public_bundle_for};

    #[test]
    fn alice_and_bob_derive_same_master() {
        let alice = create_identity();
        let mut bob = create_identity();
        let bob_bundle = public_bundle_for(&bob);
        let init = initiate(&alice, &bob_bundle).unwrap();
        let resp = respond(&mut bob, &init.message).unwrap();
        assert_eq!(init.master_secret, resp.master_secret);
    }

    #[test]
    fn associated_data_symmetric() {
        let alice = create_identity();
        let mut bob = create_identity();
        let bob_bundle = public_bundle_for(&bob);
        let init = initiate(&alice, &bob_bundle).unwrap();
        let resp = respond(&mut bob, &init.message).unwrap();
        assert_eq!(init.associated_data, resp.associated_data);
    }

    #[test]
    fn respond_idempotent_without_opk() {
        // OPK-based replay protection removed in zero-server design.
        // Replays now yield the same master (tolerated, not exploited).
        let alice = create_identity();
        let mut bob = create_identity();
        let bob_bundle = public_bundle_for(&bob);
        let init = initiate(&alice, &bob_bundle).unwrap();
        let first = respond(&mut bob, &init.message).unwrap();
        let second = respond(&mut bob, &init.message).unwrap();
        assert_eq!(first.master_secret, second.master_secret);
    }

    #[test]
    fn peer_with_cached_bundle_still_works_after_rotation() {
        // The whole point of retention: Bob rotates his signed prekey, but
        // Alice is still holding the bundle she pasted days ago. She must keep
        // being able to hand shake — otherwise every rotation would strand
        // every peer, including on auto-heal re-handshakes.
        use crate::identity::rotate_signed_prekey_if_due;

        let alice = create_identity();
        let mut bob = create_identity();
        let old_bundle = public_bundle_for(&bob); // Alice caches this

        let far_future = bob.signed_prekey.created_at + crate::identity::SPK_ROTATION_SECS + 1;
        assert!(rotate_signed_prekey_if_due(&mut bob, far_future));
        assert_ne!(
            bob.signed_prekey.id, old_bundle.spk_id,
            "should have rotated"
        );

        let init = initiate(&alice, &old_bundle).unwrap();
        let resp = respond(&mut bob, &init.message).expect("retired SPK must still resolve");
        assert_eq!(init.master_secret, resp.master_secret);
    }

    #[test]
    fn retired_spk_stops_working_once_expired() {
        // Forward secrecy only actually improves when the retired private key
        // is gone, so expiry must genuinely drop it.
        use crate::identity::{rotate_signed_prekey_if_due, SPK_RETENTION_SECS, SPK_ROTATION_SECS};

        let alice = create_identity();
        let mut bob = create_identity();
        let old_bundle = public_bundle_for(&bob);
        let init = initiate(&alice, &old_bundle).unwrap();

        let t0 = bob.signed_prekey.created_at;
        rotate_signed_prekey_if_due(&mut bob, t0 + SPK_ROTATION_SECS + 1);
        rotate_signed_prekey_if_due(&mut bob, t0 + SPK_RETENTION_SECS + 1);

        assert!(
            bob.retired_signed_prekeys.is_empty(),
            "retired key must be dropped"
        );
        assert!(respond(&mut bob, &init.message).is_err());
    }

    #[test]
    fn rotation_is_not_due_before_its_time() {
        use crate::identity::rotate_signed_prekey_if_due;
        let mut bob = create_identity();
        let id_before = bob.signed_prekey.id;
        let just_after_creation = bob.signed_prekey.created_at + 60;
        assert!(!rotate_signed_prekey_if_due(&mut bob, just_after_creation));
        assert_eq!(bob.signed_prekey.id, id_before);
    }

    #[test]
    fn invalid_bundle_signature_rejected() {
        let alice = create_identity();
        let bob = create_identity();
        let mut bundle = public_bundle_for(&bob);
        bundle.spk_sig = hex::encode([0u8; 64]);
        assert!(initiate(&alice, &bundle).is_err());
    }
}
