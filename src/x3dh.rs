use crate::crypto::{concat, hkdf_expand, CryptoError};
use crate::identity::{
    consume_one_time_prekey, decode_array_32, generate_x25519, verify_bundle, x25519_derive_shared,
    Identity, IdentityError, PublicBundle,
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
    if msg.spk_id != ours.signed_prekey.id {
        return Err(X3dhError::UnknownSpk(msg.spk_id));
    }
    let their_ik_dh_pub = decode_array_32(&msg.ik_dh_pub)?;
    let their_ek_pub = decode_array_32(&msg.ek_pub)?;

    let spk_priv = ours.signed_prekey.keypair.priv_bytes;

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
    fn invalid_bundle_signature_rejected() {
        let alice = create_identity();
        let bob = create_identity();
        let mut bundle = public_bundle_for(&bob);
        bundle.spk_sig = hex::encode([0u8; 64]);
        assert!(initiate(&alice, &bundle).is_err());
    }
}
