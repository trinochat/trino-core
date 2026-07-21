use crate::crypto::{from_hex, random_array, to_hex, CryptoError};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use secp256k1::{Keypair, Secp256k1};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XSecret};
use zeroize::ZeroizeOnDrop;

pub const OPK_COUNT: usize = 50;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid byte length")]
    InvalidLength,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("hex decode failed")]
    HexDecode,
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

#[derive(Clone, ZeroizeOnDrop, serde::Serialize, serde::Deserialize)]
pub struct KeyPair {
    pub priv_bytes: [u8; 32],
    #[zeroize(skip)]
    pub pub_bytes: [u8; 32],
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyPair {{ pub: {} }}", to_hex(&self.pub_bytes))
    }
}

#[derive(Clone, Debug)]
pub struct SignedPreKey {
    pub id: u32,
    pub keypair: KeyPair,
    pub signature: [u8; 64],
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct OneTimePreKey {
    pub id: u32,
    pub keypair: KeyPair,
}

#[derive(Clone, Debug)]
pub struct Identity {
    pub ik_sign: KeyPair,
    pub ik_dh: KeyPair,
    pub nostr: KeyPair,
    pub signed_prekey: SignedPreKey,
    pub one_time_prekeys: Vec<OneTimePreKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicBundle {
    #[serde(rename = "ikSignPub")]
    pub ik_sign_pub: String,
    #[serde(rename = "ikDhPub")]
    pub ik_dh_pub: String,
    #[serde(rename = "nostrPub")]
    pub nostr_pub: String,
    #[serde(rename = "spkId")]
    pub spk_id: u32,
    #[serde(rename = "spkPub")]
    pub spk_pub: String,
    #[serde(rename = "spkSig")]
    pub spk_sig: String,
    #[serde(rename = "opkId")]
    pub opk_id: Option<u32>,
    #[serde(rename = "opkPub")]
    pub opk_pub: Option<String>,
    /// ik_sign signature over (ik_dh_pub || nostr_pub). Binds the DH and Nostr
    /// keys to the identity key so a MITM can't swap them. Empty on legacy
    /// bundles (rejected by verify_bundle). See identity_signing_bytes.
    #[serde(rename = "idSig", default)]
    pub id_sig: String,
}

/// Bytes signed by ik_sign to bind ik_dh_pub + nostr_pub into the bundle.
fn identity_signing_bytes(ik_dh_pub: &[u8; 32], nostr_pub: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(ik_dh_pub);
    v.extend_from_slice(nostr_pub);
    v
}

pub fn generate_ed25519() -> KeyPair {
    let mut rng = rand::thread_rng();
    let signing = SigningKey::generate(&mut rng);
    let priv_bytes = signing.to_bytes();
    let pub_bytes = signing.verifying_key().to_bytes();
    KeyPair {
        priv_bytes,
        pub_bytes,
    }
}

pub fn generate_x25519() -> KeyPair {
    let priv_bytes: [u8; 32] = random_array();
    let secret = XSecret::from(priv_bytes);
    let pub_key = XPublicKey::from(&secret);
    KeyPair {
        priv_bytes: secret.to_bytes(),
        pub_bytes: pub_key.to_bytes(),
    }
}

pub fn generate_nostr_keypair() -> KeyPair {
    // BIP340 / Nostr key via libsecp256k1 (interoperates with @noble/curves and relays).
    let secp = Secp256k1::new();
    loop {
        let priv_bytes: [u8; 32] = random_array();
        if let Ok(kp) = Keypair::from_seckey_slice(&secp, &priv_bytes) {
            let (xonly, _parity) = kp.x_only_public_key();
            return KeyPair {
                priv_bytes,
                pub_bytes: xonly.serialize(),
            };
        }
    }
}

pub fn ed25519_sign(kp: &KeyPair, msg: &[u8]) -> [u8; 64] {
    let signing = SigningKey::from_bytes(&kp.priv_bytes);
    let sig: Signature = signing.sign(msg);
    sig.to_bytes()
}

pub fn ed25519_verify(pub_bytes: &[u8; 32], msg: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(verifying) = VerifyingKey::from_bytes(pub_bytes) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    verifying.verify(msg, &sig).is_ok()
}

pub fn x25519_derive_shared(our_priv: &[u8; 32], peer_pub: &[u8; 32]) -> [u8; 32] {
    let secret = XSecret::from(*our_priv);
    let peer = XPublicKey::from(*peer_pub);
    let shared = secret.diffie_hellman(&peer);
    // Defense in depth: a low-order / non-contributory peer key forces a
    // predictable (attacker-known) shared secret. Reject it by returning random
    // bytes — the derived session then fails to agree instead of leaking a known
    // key. The honest path is always contributory, so this never affects it.
    if !shared.was_contributory() {
        return random_array();
    }
    shared.to_bytes()
}

pub fn create_signed_prekey(ik_sign: &KeyPair, id: u32) -> SignedPreKey {
    let keypair = generate_x25519();
    let signature = ed25519_sign(ik_sign, &keypair.pub_bytes);
    SignedPreKey {
        id,
        keypair,
        signature,
        created_at: chrono::Utc::now().timestamp(),
    }
}

pub fn create_one_time_prekeys(start_id: u32, count: usize) -> Vec<OneTimePreKey> {
    (0..count)
        .map(|i| OneTimePreKey {
            id: start_id + i as u32,
            keypair: generate_x25519(),
        })
        .collect()
}

pub fn create_identity() -> Identity {
    let ik_sign = generate_ed25519();
    let ik_dh = generate_x25519();
    let nostr = generate_nostr_keypair();
    let signed_prekey = create_signed_prekey(&ik_sign, 1);
    let one_time_prekeys = create_one_time_prekeys(1, OPK_COUNT);

    Identity {
        ik_sign,
        ik_dh,
        nostr,
        signed_prekey,
        one_time_prekeys,
    }
}

pub fn public_bundle_for(identity: &Identity) -> PublicBundle {
    let id_sig = ed25519_sign(
        &identity.ik_sign,
        &identity_signing_bytes(&identity.ik_dh.pub_bytes, &identity.nostr.pub_bytes),
    );
    PublicBundle {
        ik_sign_pub: to_hex(&identity.ik_sign.pub_bytes),
        ik_dh_pub: to_hex(&identity.ik_dh.pub_bytes),
        nostr_pub: to_hex(&identity.nostr.pub_bytes),
        spk_id: identity.signed_prekey.id,
        spk_pub: to_hex(&identity.signed_prekey.keypair.pub_bytes),
        spk_sig: to_hex(&identity.signed_prekey.signature),
        opk_id: None,
        opk_pub: None,
        id_sig: to_hex(&id_sig),
    }
}

pub fn verify_bundle(bundle: &PublicBundle) -> bool {
    let Ok(ik_sign_pub) = decode_array_32(&bundle.ik_sign_pub) else {
        return false;
    };
    let Ok(spk_pub) = decode_array_32(&bundle.spk_pub) else {
        return false;
    };
    let Ok(sig) = decode_array_64(&bundle.spk_sig) else {
        return false;
    };
    // The signed prekey must be signed by the identity key.
    ed25519_verify(&ik_sign_pub, &spk_pub, &sig)
}

/// Stricter check for DIRECT contact adds (pasted/scanned bundle): also require
/// that ik_dh_pub + nostr_pub are signed by ik_sign. Without this a MITM could
/// swap the DH key at first contact and the fingerprint wouldn't catch it.
/// (Group members are vouched for by the signed roster instead, so the normal
/// verify_bundle is enough there.)
pub fn verify_bundle_binding(bundle: &PublicBundle) -> bool {
    if !verify_bundle(bundle) {
        return false;
    }
    let (Ok(ik_sign_pub), Ok(ik_dh_pub), Ok(nostr_pub), Ok(id_sig)) = (
        decode_array_32(&bundle.ik_sign_pub),
        decode_array_32(&bundle.ik_dh_pub),
        decode_array_32(&bundle.nostr_pub),
        decode_array_64(&bundle.id_sig),
    ) else {
        return false;
    };
    ed25519_verify(
        &ik_sign_pub,
        &identity_signing_bytes(&ik_dh_pub, &nostr_pub),
        &id_sig,
    )
}

pub fn consume_one_time_prekey(identity: &mut Identity, opk_id: u32) -> Option<OneTimePreKey> {
    let idx = identity
        .one_time_prekeys
        .iter()
        .position(|o| o.id == opk_id)?;
    Some(identity.one_time_prekeys.remove(idx))
}

pub fn decode_array_32(s: &str) -> Result<[u8; 32], IdentityError> {
    let v = from_hex(s).map_err(|_| IdentityError::HexDecode)?;
    if v.len() != 32 {
        return Err(IdentityError::InvalidLength);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&v);
    Ok(arr)
}

pub fn decode_array_64(s: &str) -> Result<[u8; 64], IdentityError> {
    let v = from_hex(s).map_err(|_| IdentityError::HexDecode)?;
    if v.len() != 64 {
        return Err(IdentityError::InvalidLength);
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&v);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_has_3_keypairs() {
        let id = create_identity();
        assert_eq!(id.ik_sign.priv_bytes.len(), 32);
        assert_eq!(id.ik_dh.pub_bytes.len(), 32);
        assert_eq!(id.nostr.pub_bytes.len(), 32);
        assert_eq!(id.one_time_prekeys.len(), OPK_COUNT);
    }

    #[test]
    fn bundle_signature_verifies() {
        let id = create_identity();
        let bundle = public_bundle_for(&id);
        assert!(verify_bundle(&bundle));
    }

    #[test]
    fn tampered_bundle_rejected() {
        let id = create_identity();
        let mut bundle = public_bundle_for(&id);
        bundle.spk_pub = to_hex(&[0u8; 32]);
        assert!(!verify_bundle(&bundle));
    }

    #[test]
    fn opk_consumed_once() {
        let mut id = create_identity();
        let first_id = id.one_time_prekeys[0].id;
        assert!(consume_one_time_prekey(&mut id, first_id).is_some());
        assert!(consume_one_time_prekey(&mut id, first_id).is_none());
    }

    #[test]
    fn x25519_shared_matches_both_sides() {
        let alice = generate_x25519();
        let bob = generate_x25519();
        let s1 = x25519_derive_shared(&alice.priv_bytes, &bob.pub_bytes);
        let s2 = x25519_derive_shared(&bob.priv_bytes, &alice.pub_bytes);
        assert_eq!(s1, s2);
    }
}
