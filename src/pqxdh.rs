//! The hybrid handshake: X3DH plus ML-KEM-768, combined the way PQXDH does
//! (`diseno-vinculacion.md` §21.2; PQ-01, PQ-02, PQ-04).
//!
//! Between the initiating device (`ini`) and the responding one (`resp`):
//!
//! ```text
//! DH1  = X25519(dev_dh_ini, SPK_resp)   DH2 = X25519(ek, dev_dh_resp)   DH3 = X25519(ek, SPK_resp)
//! (SS, ct) = ML-KEM-768.Encaps(pq_ek_resp)
//! IKM  = 0xFF×32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ SS            (X3DH's F prefix; no DH4, there are no OPKs)
//! info = "trino/pqxdh/v1" ‖ suite ‖ SHA-256(pq_ek_resp) ‖ SHA-256(ct) ‖ pq_spk_id u32
//! SK   = HKDF-SHA256(salt = 32 zero bytes, IKM, info, 32)      → the ratchet's master secret
//! AD   = "trino/x3dh/v2\0" ‖ suite ‖ A_ini ‖ dev_dh_ini ‖ A_resp ‖ dev_dh_resp
//! ```
//!
//! - **`SHA-256(pq_ek) ‖ SHA-256(ct)` in `info`:** the lesson of the KEM
//!   re-encapsulation attack on PQXDH (Bhargavan et al., USENIX 2024): the
//!   mistake is in how the secret is bound. ML-KEM already binds its public
//!   key; binding it again costs nothing on the wire.
//! - **No classical mode exists** (PQ-01): a handshake without a KEM
//!   ciphertext cannot be expressed, and any suite but `0x01` is refused.
//! - **Every prekey signature is checked before encapsulating**: the
//!   classical SPK, signed by `dev_sign` as `"trino/spk/v2\0" ‖ spk_id ‖
//!   spk` (§2.1), and the `pq_spk` ([`crate::pq_spk`]). Either failing
//!   aborts the handshake.
//! - **Non-contributory X25519 results are refused**, not replaced by
//!   random bytes as `identity::x25519_derive_shared` does.
//! - **Randomness is injectable**: `initiate_with_rng` draws 32 bytes for
//!   the ephemeral key, then 32 for the encapsulation.
//!
//! **PQ-11 mode** (§21.6), when the initiator has no `pq_spk` of the other
//! device (a group member who is not a contact, a contact whose full
//! `DeviceList` has not arrived, a direct `trino3:` code):
//!
//! ```text
//! type 5 = suite ‖ pq_ek_eph ‖ dev_dh ‖ ek ‖ spk_id ‖ opk_id ‖ message 0 (no user text)
//! SK₀    = HKDF(salt = 32 zero bytes, 0xFF×32 ‖ DH1 ‖ DH2 ‖ DH3,
//!               info = "trino/pqxdh/v1/pq11" ‖ suite ‖ SHA-256(pq_ek_eph))
//! type 4 = ct ‖ first reply,  with (SS, ct) = Encaps(pq_ek_eph)
//! root'  = HKDF(salt = SK₀, ikm = SS, info = "trino/pq11/v1" ‖ SHA-256(ct))
//! ```
//!
//! "The root" of §21.6 is taken to be `SK₀`, and both ratchets restart
//! from `root'`: the responder as the ratchet's initiator, against the
//! ratchet key in message 0's header; the initiator as its responder, with
//! the key pair it used for message 0. Only message 0, which carries no
//! user text, stays under `SK₀`; the reply is already hybrid. `S_ses` comes
//! from `root'`, so the type 4 travels on the introduction mailbox: the
//! initiator cannot compute the session one before opening it.
//!
//! Not here yet: that `dev_dh_ini` belongs to `A_ini`'s device list (§5.1,
//! RV-06) is checked by the device list code (VI-1).
//!
//! **`S_ses`** (design P1 §3.3) comes out with the secret on both sides:
//! from `SK` and `AD` in the normal mode, from `root'` and `AD` in PQ-11,
//! never from `SK₀`. The caller hands it to `RatchetState::attach_session`
//! and lets it drop, which wipes it.
//!
//! The tests check SK, AD and the SPK signature against OpenSSL
//! (`tests/vectors/pqxdh.py`), with OpenSSL's ciphertexts opened by libcrux.

use crate::crypto::{hkdf_expand, sha256};
use crate::identity::{ed25519_sign, KeyPair};
use crate::kem::{encapsulate_with_rng, KemError, KemSecret, CT_LEN, EK_LEN};
use crate::p1::mailbox::session_seed;
use crate::p1::wire::{HandshakeBody, HandshakePq11Body, MessageBody, SUITE_X25519_MLKEM768};
use crate::pq_spk::{PqSpkError, SignedPqPrekey};
use ed25519_dalek::{Signature, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroizing;

/// The only suite: X25519 + ML-KEM-768 + HKDF-SHA-256 + AES-256-GCM.
pub const SUITE: u8 = SUITE_X25519_MLKEM768;
/// A signed classical prekey: `id ‖ spk ‖ sig`.
pub const SIGNED_SPK_LEN: usize = 4 + 32 + 64;

const SPK_DOMAIN: &[u8] = b"trino/spk/v2\0";
const AD_LABEL: &[u8] = b"trino/x3dh/v2\0";
const INFO_LABEL: &[u8] = b"trino/pqxdh/v1";
const PQ11_INFO_LABEL: &[u8] = b"trino/pqxdh/v1/pq11";
const PQ11_ROOT_LABEL: &[u8] = b"trino/pq11/v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PqxdhError {
    #[error("unknown suite {0}")]
    Suite(u8),
    #[error("signed prekey signature does not verify")]
    Spk,
    #[error("post-quantum prekey: {0}")]
    PqSpk(#[from] PqSpkError),
    #[error("ML-KEM: {0}")]
    Kem(#[from] KemError),
    #[error("an X25519 exchange is not contributory")]
    NonContributory,
    #[error("one-time prekeys are not used")]
    OneTimePrekey,
    #[error("a signed prekey is 100 bytes")]
    Length,
}

/// A device's classical signed prekey, signed by its `dev_sign` (§2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedSpk {
    pub id: u32,
    pub public: [u8; 32],
    pub sig: [u8; 64],
}

/// What the initiator holds of the responding device.
pub struct PeerPrekeys {
    /// The responder's account key `A`.
    pub account: [u8; 32],
    pub dev_sign: [u8; 32],
    pub dev_dh: [u8; 32],
    pub spk: SignedSpk,
    pub pq_spk: SignedPqPrekey,
}

/// The initiator's result: the secret, the AD, and the handshake fields.
pub struct Initiation {
    pub sk: Zeroizing<[u8; 32]>,
    /// `S_ses` (design P1 §3.3) from this SK and AD.
    pub s_ses: Zeroizing<[u8; 32]>,
    pub ad: Vec<u8>,
    pub pq_spk_id: u32,
    pub ct: Box<[u8; CT_LEN]>,
    pub dev_dh: [u8; 32],
    pub ek: [u8; 32],
    pub spk_id: u32,
}

/// The responding device's keys for this handshake, already looked up by
/// the ids the handshake names.
pub struct ResponderKeys<'a> {
    pub account: [u8; 32],
    pub dev_dh: &'a KeyPair,
    pub spk: &'a KeyPair,
    pub pq: &'a KemSecret,
}

/// The responder's result.
pub struct Response {
    pub sk: Zeroizing<[u8; 32]>,
    /// `S_ses` (design P1 §3.3) from this SK and AD.
    pub s_ses: Zeroizing<[u8; 32]>,
    pub ad: Vec<u8>,
}

impl SignedSpk {
    /// Signs `public` under `id` with `dev_sign`.
    pub fn sign(dev_sign: &KeyPair, id: u32, public: &[u8; 32]) -> Self {
        SignedSpk {
            id,
            public: *public,
            sig: ed25519_sign(dev_sign, &spk_message(id, public)),
        }
    }

    /// Checks the signature strictly against `dev_sign_pub`.
    pub fn verify(&self, dev_sign_pub: &[u8; 32]) -> Result<(), PqxdhError> {
        VerifyingKey::from_bytes(dev_sign_pub)
            .map_err(|_| PqxdhError::Spk)?
            .verify_strict(
                &spk_message(self.id, &self.public),
                &Signature::from_bytes(&self.sig),
            )
            .map_err(|_| PqxdhError::Spk)
    }

    pub fn encode(&self) -> [u8; SIGNED_SPK_LEN] {
        let mut out = [0u8; SIGNED_SPK_LEN];
        out[..4].copy_from_slice(&self.id.to_be_bytes());
        out[4..36].copy_from_slice(&self.public);
        out[36..].copy_from_slice(&self.sig);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, PqxdhError> {
        if b.len() != SIGNED_SPK_LEN {
            return Err(PqxdhError::Length);
        }
        Ok(SignedSpk {
            id: u32::from_be_bytes(b[..4].try_into().expect("4 bytes")),
            public: b[4..36].try_into().expect("32 bytes"),
            sig: b[36..].try_into().expect("64 bytes"),
        })
    }
}

impl Initiation {
    /// The type 2 body that carries this handshake and its first message.
    pub fn handshake(&self, message: MessageBody) -> HandshakeBody {
        HandshakeBody {
            suite: SUITE,
            pq_spk_id: self.pq_spk_id,
            ct: self.ct.clone(),
            dev_dh: self.dev_dh,
            ek: self.ek,
            spk_id: self.spk_id,
            opk_id: None,
            message,
        }
    }
}

/// `SK` from the three Diffie-Hellman results and the KEM's.
pub fn combine(
    dh: [&[u8; 32]; 3],
    ss: &[u8; 32],
    pq_ek: &[u8],
    ct: &[u8; CT_LEN],
    pq_spk_id: u32,
) -> Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(INFO_LABEL.len() + 1 + 32 + 32 + 4);
    info.extend_from_slice(INFO_LABEL);
    info.push(SUITE);
    info.extend_from_slice(&sha256(pq_ek));
    info.extend_from_slice(&sha256(ct));
    info.extend_from_slice(&pq_spk_id.to_be_bytes());
    hkdf32(&ikm_of(dh, Some(ss)), &[0u8; 32], &info)
}

/// `AD`: the suite, both accounts and both device keys.
pub fn associated_data(
    a_ini: &[u8; 32],
    dev_dh_ini: &[u8; 32],
    a_resp: &[u8; 32],
    dev_dh_resp: &[u8; 32],
) -> Vec<u8> {
    let mut ad = Vec::with_capacity(AD_LABEL.len() + 1 + 4 * 32);
    ad.extend_from_slice(AD_LABEL);
    ad.push(SUITE);
    for part in [a_ini, dev_dh_ini, a_resp, dev_dh_resp] {
        ad.extend_from_slice(part);
    }
    ad
}

/// Starts a handshake with a device whose prekeys are `peer`.
pub fn initiate_with_rng<R: RngCore + CryptoRng>(
    my_account: &[u8; 32],
    my_dev_dh: &KeyPair,
    peer: &PeerPrekeys,
    rng: &mut R,
) -> Result<Initiation, PqxdhError> {
    // Every prekey signature first: nothing is encapsulated to an
    // unauthenticated key (§21.2).
    peer.spk.verify(&peer.dev_sign)?;
    peer.pq_spk.verify(&peer.dev_sign)?;

    let (ek, [dh1, dh2, dh3]) = initiator_dh(my_dev_dh, &peer.dev_dh, &peer.spk.public, rng)?;
    let (ct, ss) = encapsulate_with_rng(&peer.pq_spk.ek, rng)?;
    let sk = combine(
        [&dh1, &dh2, &dh3],
        &ss,
        &peer.pq_spk.ek[..],
        &ct,
        peer.pq_spk.id,
    );
    let ad = associated_data(
        my_account,
        &my_dev_dh.pub_bytes,
        &peer.account,
        &peer.dev_dh,
    );
    Ok(Initiation {
        s_ses: session_seed(&sk, &ad),
        sk,
        ad,
        pq_spk_id: peer.pq_spk.id,
        ct,
        dev_dh: my_dev_dh.pub_bytes,
        ek,
        spk_id: peer.spk.id,
    })
}

/// Answers a handshake from account `their_account`.
pub fn respond(
    me: &ResponderKeys,
    their_account: &[u8; 32],
    hs: &HandshakeBody,
) -> Result<Response, PqxdhError> {
    if hs.suite != SUITE {
        return Err(PqxdhError::Suite(hs.suite));
    }
    if hs.opk_id.is_some() {
        return Err(PqxdhError::OneTimePrekey);
    }
    let [dh1, dh2, dh3] = responder_dh(me.dev_dh, me.spk, &hs.dev_dh, &hs.ek)?;
    let ss = me.pq.decapsulate(&hs.ct);
    let sk = combine(
        [&dh1, &dh2, &dh3],
        &ss,
        &me.pq.public_key()[..],
        &hs.ct,
        hs.pq_spk_id,
    );
    let ad = associated_data(their_account, &hs.dev_dh, &me.account, &me.dev_dh.pub_bytes);
    Ok(Response {
        s_ses: session_seed(&sk, &ad),
        sk,
        ad,
    })
}

// ---------------------------------------------------------------- PQ-11

/// What the initiator holds of a device whose `pq_spk` it does not have:
/// a group member who is not a contact yet, or a contact whose full
/// `DeviceList` has not arrived (§21.6).
pub struct PeerClassical {
    pub account: [u8; 32],
    pub dev_sign: [u8; 32],
    pub dev_dh: [u8; 32],
    pub spk: SignedSpk,
}

/// The responding device's classical keys for a PQ-11 handshake.
pub struct ClassicalResponderKeys<'a> {
    pub account: [u8; 32],
    pub dev_dh: &'a KeyPair,
    pub spk: &'a KeyPair,
}

/// The initiator's side of a PQ-11 handshake. It keeps the ephemeral KEM
/// key until the type 4 reply arrives, then [`Pq11Initiation::finish`].
pub struct Pq11Initiation {
    /// `SK₀`: protects only message 0, which carries no user text.
    pub sk0: Zeroizing<[u8; 32]>,
    pub ad: Vec<u8>,
    pub kem: KemSecret,
    pub pq_ek: Box<[u8; EK_LEN]>,
    pub dev_dh: [u8; 32],
    pub ek: [u8; 32],
    pub spk_id: u32,
}

/// `raíz'` of a PQ-11 session and the `S_ses` that comes from it.
pub struct Pq11Root {
    pub root: Zeroizing<[u8; 32]>,
    pub s_ses: Zeroizing<[u8; 32]>,
}

/// The ciphertext for the type 4 body and the new root.
pub type Pq11Reply = (Box<[u8; CT_LEN]>, Pq11Root);

/// The responder's side of a PQ-11 handshake.
pub struct Pq11Response {
    pub sk0: Zeroizing<[u8; 32]>,
    pub ad: Vec<u8>,
    pq_ek: Box<[u8; EK_LEN]>,
}

/// `SK₀` of PQ-11: the three Diffie-Hellman results only, bound to the
/// initiator's ephemeral KEM key.
pub fn combine_pq11(dh: [&[u8; 32]; 3], pq_ek: &[u8; EK_LEN]) -> Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(PQ11_INFO_LABEL.len() + 1 + 32);
    info.extend_from_slice(PQ11_INFO_LABEL);
    info.push(SUITE);
    info.extend_from_slice(&sha256(pq_ek));
    hkdf32(&ikm_of(dh, None), &[0u8; 32], &info)
}

/// `raíz' = HKDF(salt = SK₀, ikm = SS, info = "trino/pq11/v1" ‖ SHA-256(ct))`.
pub fn pq11_root(sk0: &[u8; 32], ss: &[u8; 32], ct: &[u8; CT_LEN]) -> Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(PQ11_ROOT_LABEL.len() + 32);
    info.extend_from_slice(PQ11_ROOT_LABEL);
    info.extend_from_slice(&sha256(ct));
    hkdf32(ss, sk0, &info)
}

/// Starts a PQ-11 handshake. Draws 32 bytes for the X25519 ephemeral key,
/// then 64 for the ML-KEM one.
pub fn initiate_pq11_with_rng<R: RngCore + CryptoRng>(
    my_account: &[u8; 32],
    my_dev_dh: &KeyPair,
    peer: &PeerClassical,
    rng: &mut R,
) -> Result<Pq11Initiation, PqxdhError> {
    peer.spk.verify(&peer.dev_sign)?;
    let (ek, [dh1, dh2, dh3]) = initiator_dh(my_dev_dh, &peer.dev_dh, &peer.spk.public, rng)?;
    let kem = KemSecret::generate_with_rng(rng);
    let pq_ek = kem.public_key();
    Ok(Pq11Initiation {
        sk0: combine_pq11([&dh1, &dh2, &dh3], &pq_ek),
        ad: associated_data(
            my_account,
            &my_dev_dh.pub_bytes,
            &peer.account,
            &peer.dev_dh,
        ),
        kem,
        pq_ek,
        dev_dh: my_dev_dh.pub_bytes,
        ek,
        spk_id: peer.spk.id,
    })
}

/// Answers a PQ-11 handshake from account `their_account`.
pub fn respond_pq11(
    me: &ClassicalResponderKeys,
    their_account: &[u8; 32],
    hs: &HandshakePq11Body,
) -> Result<Pq11Response, PqxdhError> {
    if hs.suite != SUITE {
        return Err(PqxdhError::Suite(hs.suite));
    }
    if hs.opk_id.is_some() {
        return Err(PqxdhError::OneTimePrekey);
    }
    let [dh1, dh2, dh3] = responder_dh(me.dev_dh, me.spk, &hs.dev_dh, &hs.ek)?;
    Ok(Pq11Response {
        sk0: combine_pq11([&dh1, &dh2, &dh3], &hs.pq_ek),
        ad: associated_data(their_account, &hs.dev_dh, &me.account, &me.dev_dh.pub_bytes),
        pq_ek: hs.pq_ek.clone(),
    })
}

impl Pq11Initiation {
    /// The type 5 body. `message` must carry no user text (§21.6).
    pub fn handshake(&self, message: MessageBody) -> HandshakePq11Body {
        HandshakePq11Body {
            suite: SUITE,
            pq_ek: self.pq_ek.clone(),
            dev_dh: self.dev_dh,
            ek: self.ek,
            spk_id: self.spk_id,
            opk_id: None,
            message,
        }
    }

    /// `raíz'` from the responder's ciphertext (the type 4 body).
    pub fn finish(&self, ct: &[u8; CT_LEN]) -> Pq11Root {
        let root = pq11_root(&self.sk0, &self.kem.decapsulate(ct), ct);
        Pq11Root {
            s_ses: session_seed(&root, &self.ad),
            root,
        }
    }
}

impl Pq11Response {
    /// Encapsulates to the initiator's key and returns the ciphertext for
    /// the type 4 body and `raíz'`, mixed in before anything is encrypted.
    pub fn reply_with_rng<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<Pq11Reply, PqxdhError> {
        let (ct, ss) = encapsulate_with_rng(&self.pq_ek, rng)?;
        let root = pq11_root(&self.sk0, &ss, &ct);
        Ok((
            ct,
            Pq11Root {
                s_ses: session_seed(&root, &self.ad),
                root,
            },
        ))
    }
}

/// The ephemeral key and the three X25519 results of the initiator.
type InitiatorDh = ([u8; 32], [Zeroizing<[u8; 32]>; 3]);

/// The initiator's half: a fresh X25519 ephemeral key from 32 bytes of
/// `rng`, then DH1, DH2 and DH3.
fn initiator_dh<R: RngCore + CryptoRng>(
    my_dev_dh: &KeyPair,
    their_dev_dh: &[u8; 32],
    their_spk: &[u8; 32],
    rng: &mut R,
) -> Result<InitiatorDh, PqxdhError> {
    let mut ek_priv = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut ek_priv[..]);
    // StaticSecret wipes itself on drop.
    let ek = StaticSecret::from(*ek_priv);
    let dh1 = x25519(&StaticSecret::from(my_dev_dh.priv_bytes), their_spk)?;
    let dh2 = x25519(&ek, their_dev_dh)?;
    let dh3 = x25519(&ek, their_spk)?;
    Ok((XPublicKey::from(&ek).to_bytes(), [dh1, dh2, dh3]))
}

/// The responder's half of the same three exchanges.
fn responder_dh(
    my_dev_dh: &KeyPair,
    my_spk: &KeyPair,
    their_dev_dh: &[u8; 32],
    their_ek: &[u8; 32],
) -> Result<[Zeroizing<[u8; 32]>; 3], PqxdhError> {
    let spk = StaticSecret::from(my_spk.priv_bytes);
    Ok([
        x25519(&spk, their_dev_dh)?,
        x25519(&StaticSecret::from(my_dev_dh.priv_bytes), their_ek)?,
        x25519(&spk, their_ek)?,
    ])
}

fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let okm = hkdf_expand(ikm, salt, info, 32).expect("32 bytes is a valid HKDF length");
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&okm);
    out
}

fn ikm_of(dh: [&[u8; 32]; 3], ss: Option<&[u8; 32]>) -> Zeroizing<Vec<u8>> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 * 5));
    ikm.extend_from_slice(&[0xFF; 32]);
    for d in dh {
        ikm.extend_from_slice(d);
    }
    if let Some(ss) = ss {
        ikm.extend_from_slice(ss);
    }
    ikm
}

fn spk_message(id: u32, public: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SPK_DOMAIN.len() + 4 + 32);
    m.extend_from_slice(SPK_DOMAIN);
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(public);
    m
}

fn x25519(mine: &StaticSecret, their_pub: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, PqxdhError> {
    let shared = mine.diffie_hellman(&XPublicKey::from(*their_pub));
    if !shared.was_contributory() {
        return Err(PqxdhError::NonContributory);
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::KemSecret;
    use crate::pq_spk::PqPrekeys;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../tests/vectors/pqxdh.json");

    fn hx<const N: usize>(v: &Value) -> [u8; N] {
        hex::decode(v.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn x_pair(priv_bytes: [u8; 32]) -> KeyPair {
        let s = x25519_dalek::StaticSecret::from(priv_bytes);
        KeyPair {
            priv_bytes: s.to_bytes(),
            pub_bytes: x25519_dalek::PublicKey::from(&s).to_bytes(),
        }
    }

    fn ed_pair(priv_bytes: [u8; 32]) -> KeyPair {
        let pub_bytes = ed25519_dalek::SigningKey::from_bytes(&priv_bytes)
            .verifying_key()
            .to_bytes();
        KeyPair {
            priv_bytes,
            pub_bytes,
        }
    }

    fn sample_message() -> MessageBody {
        MessageBody {
            dh: [1; 32],
            pn: 0,
            n: 0,
            nonce: [2; 12],
            ciphertext: vec![3; 40],
        }
    }

    struct Bob {
        account: [u8; 32],
        dev_sign: KeyPair,
        dev_dh: KeyPair,
        spk: KeyPair,
        pq: PqPrekeys,
    }

    impl Bob {
        fn new(rng: &mut ChaCha20Rng) -> Self {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            let account = b;
            rng.fill_bytes(&mut b);
            let dev_sign = ed_pair(b);
            rng.fill_bytes(&mut b);
            let dev_dh = x_pair(b);
            rng.fill_bytes(&mut b);
            let spk = x_pair(b);
            Bob {
                account,
                dev_sign,
                dev_dh,
                spk,
                pq: PqPrekeys::new_with_rng(0, rng),
            }
        }

        fn prekeys(&self) -> PeerPrekeys {
            PeerPrekeys {
                account: self.account,
                dev_sign: self.dev_sign.pub_bytes,
                dev_dh: self.dev_dh.pub_bytes,
                spk: SignedSpk::sign(&self.dev_sign, 5, &self.spk.pub_bytes),
                pq_spk: self.pq.signed_current(&self.dev_sign),
            }
        }

        fn keys(&self) -> ResponderKeys<'_> {
            ResponderKeys {
                account: self.account,
                dev_dh: &self.dev_dh,
                spk: &self.spk,
                pq: self.pq.by_id(self.pq.current.id).unwrap(),
            }
        }
    }

    #[test]
    fn combine_and_ad_match_openssl() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        for c in v["cases"].as_array().unwrap() {
            let pq_ek = KemSecret::from_seed(&hx(&c["pq_seed"])).public_key();
            let sk = combine(
                [&hx(&c["dh1"]), &hx(&c["dh2"]), &hx(&c["dh3"])],
                &hx(&c["ss"]),
                &pq_ek[..],
                &hx(&c["ct"]),
                c["pq_spk_id"].as_u64().unwrap() as u32,
            );
            assert_eq!(*sk, hx::<32>(&c["sk"]));
            let ad = associated_data(
                &hx(&c["a_ini"]),
                &x_pair(hx(&c["dev_dh_ini_priv"])).pub_bytes,
                &hx(&c["a_resp"]),
                &x_pair(hx(&c["dev_dh_resp_priv"])).pub_bytes,
            );
            assert_eq!(hex::encode(ad), c["ad"].as_str().unwrap());
        }
    }

    #[test]
    fn respond_opens_openssl_handshakes() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        for c in v["cases"].as_array().unwrap() {
            let dev_dh = x_pair(hx(&c["dev_dh_resp_priv"]));
            let spk = x_pair(hx(&c["spk_priv"]));
            let pq = KemSecret::from_seed(&hx(&c["pq_seed"]));
            let me = ResponderKeys {
                account: hx(&c["a_resp"]),
                dev_dh: &dev_dh,
                spk: &spk,
                pq: &pq,
            };
            let hs = HandshakeBody {
                suite: SUITE,
                pq_spk_id: c["pq_spk_id"].as_u64().unwrap() as u32,
                ct: Box::new(hx(&c["ct"])),
                dev_dh: x_pair(hx(&c["dev_dh_ini_priv"])).pub_bytes,
                ek: x_pair(hx(&c["ek_priv"])).pub_bytes,
                spk_id: c["spk_id"].as_u64().unwrap() as u32,
                opk_id: None,
                message: sample_message(),
            };
            let r = respond(&me, &hx(&c["a_ini"]), &hs).unwrap();
            assert_eq!(*r.sk, hx::<32>(&c["sk"]));
            assert_eq!(hex::encode(&r.ad), c["ad"].as_str().unwrap());
        }
    }

    #[test]
    fn spk_signatures_match_openssl() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        for c in v["cases"].as_array().unwrap() {
            let dev_sign = ed_pair(hx(&c["dev_sign_resp_priv"]));
            let spk = x_pair(hx(&c["spk_priv"]));
            let id = c["spk_id"].as_u64().unwrap() as u32;
            let signed = SignedSpk::sign(&dev_sign, id, &spk.pub_bytes);
            assert_eq!(signed.sig, hx::<64>(&c["spk_sig"]));
            assert_eq!(SignedSpk::decode(&signed.encode()).unwrap(), signed);
            assert_eq!(signed.verify(&dev_sign.pub_bytes), Ok(()));
        }
    }

    #[test]
    fn both_sides_reach_the_same_secret_through_the_wire() {
        use crate::p1::wire::{open_inner, seal_inner, InnerType, Step};
        let mut rng = ChaCha20Rng::from_seed([1; 32]);
        let bob = Bob::new(&mut rng);
        let alice_account = [9u8; 32];
        let alice_dh = x_pair([8; 32]);
        let init = initiate_with_rng(&alice_account, &alice_dh, &bob.prekeys(), &mut rng).unwrap();
        let k_mac = [7u8; 32];
        let frame = seal_inner(
            InnerType::Handshake,
            1,
            &init.handshake(sample_message()).encode(),
            Step::K4,
            &k_mac,
        )
        .unwrap();
        let hs = HandshakeBody::decode(&open_inner(&frame, &k_mac).unwrap().body).unwrap();
        let resp = respond(&bob.keys(), &alice_account, &hs).unwrap();
        assert_eq!(*resp.sk, *init.sk);
        assert_eq!(resp.ad, init.ad);
        assert_eq!(hs.spk_id, 5);
        assert_eq!(hs.pq_spk_id, bob.pq.current.id);
    }

    #[test]
    fn the_first_ratchet_message_opens_with_the_hybrid_secret() {
        use crate::ratchet::{init_initiator, init_responder, ratchet_decrypt, ratchet_encrypt};
        let mut rng = ChaCha20Rng::from_seed([2; 32]);
        let bob = Bob::new(&mut rng);
        let alice_dh = x_pair([8; 32]);
        let init = initiate_with_rng(&[9; 32], &alice_dh, &bob.prekeys(), &mut rng).unwrap();
        let mut a = init_initiator(*init.sk, bob.spk.pub_bytes).unwrap();
        let sent = ratchet_encrypt(&mut a, b"hola", &init.ad).unwrap();
        let hs = init.handshake(MessageBody::from_ratchet(&sent).unwrap());
        let resp = respond(&bob.keys(), &[9; 32], &hs).unwrap();
        let mut b = init_responder(*resp.sk, bob.spk.clone());
        let plain = ratchet_decrypt(&mut b, &hs.message.to_ratchet(), &resp.ad).unwrap();
        assert_eq!(plain, b"hola");
    }

    #[test]
    fn a_seeded_generator_gives_a_fixed_handshake() {
        let bob = Bob::new(&mut ChaCha20Rng::from_seed([3; 32]));
        let alice_dh = x_pair([8; 32]);
        let run = |seed| {
            initiate_with_rng(
                &[9; 32],
                &alice_dh,
                &bob.prekeys(),
                &mut ChaCha20Rng::from_seed(seed),
            )
            .unwrap()
        };
        let (x, y, z) = (run([4; 32]), run([4; 32]), run([5; 32]));
        assert_eq!((*x.sk, x.ek, &x.ct[..]), (*y.sk, y.ek, &y.ct[..]));
        assert_ne!(*x.sk, *z.sk);
        assert_ne!(x.ek, z.ek);
    }

    #[test]
    fn a_bad_prekey_signature_aborts_before_encapsulating() {
        let mut rng = ChaCha20Rng::from_seed([6; 32]);
        let bob = Bob::new(&mut rng);
        let me = x_pair([8; 32]);
        let mut p = bob.prekeys();
        p.spk.sig[0] ^= 1;
        assert_eq!(
            initiate_with_rng(&[9; 32], &me, &p, &mut rng).err(),
            Some(PqxdhError::Spk)
        );
        let mut p = bob.prekeys();
        p.pq_spk.sig[0] ^= 1;
        assert_eq!(
            initiate_with_rng(&[9; 32], &me, &p, &mut rng).err(),
            Some(PqxdhError::PqSpk(PqSpkError::Signature))
        );
        let mut p = bob.prekeys();
        p.dev_sign = ed_pair([0x42; 32]).pub_bytes;
        assert_eq!(
            initiate_with_rng(&[9; 32], &me, &p, &mut rng).err(),
            Some(PqxdhError::Spk)
        );
    }

    #[test]
    fn everything_bound_into_the_secret_changes_it() {
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        let bob = Bob::new(&mut rng);
        let init = initiate_with_rng(&[9; 32], &x_pair([8; 32]), &bob.prekeys(), &mut rng).unwrap();
        let hs = init.handshake(sample_message());
        let good = respond(&bob.keys(), &[9; 32], &hs).unwrap();
        // A flipped ciphertext bit: implicit rejection, another secret.
        let mut bad = hs.clone();
        bad.ct[10] ^= 1;
        assert_ne!(*respond(&bob.keys(), &[9; 32], &bad).unwrap().sk, *good.sk);
        // Another prekey id in `info`.
        let mut bad = hs.clone();
        bad.pq_spk_id ^= 1;
        assert_ne!(*respond(&bob.keys(), &[9; 32], &bad).unwrap().sk, *good.sk);
        // Another account: same secret, another AD, so the ratchet fails.
        assert_ne!(respond(&bob.keys(), &[8; 32], &hs).unwrap().ad, good.ad);
        // Another suite or a one-time prekey: refused.
        let mut bad = hs.clone();
        bad.suite = 0;
        assert_eq!(
            respond(&bob.keys(), &[9; 32], &bad).err(),
            Some(PqxdhError::Suite(0))
        );
        let mut bad = hs.clone();
        bad.opk_id = Some(1);
        assert_eq!(
            respond(&bob.keys(), &[9; 32], &bad).err(),
            Some(PqxdhError::OneTimePrekey)
        );
    }

    #[test]
    fn a_low_order_key_is_refused() {
        let mut rng = ChaCha20Rng::from_seed([8; 32]);
        let bob = Bob::new(&mut rng);
        let mut hs = initiate_with_rng(&[9; 32], &x_pair([8; 32]), &bob.prekeys(), &mut rng)
            .unwrap()
            .handshake(sample_message());
        hs.dev_dh = [0; 32];
        assert_eq!(
            respond(&bob.keys(), &[9; 32], &hs).err(),
            Some(PqxdhError::NonContributory)
        );
        let mut p = bob.prekeys();
        p.dev_dh = [0; 32];
        assert_eq!(
            initiate_with_rng(&[9; 32], &x_pair([8; 32]), &p, &mut rng).err(),
            Some(PqxdhError::NonContributory)
        );
    }

    // ------------------------------------------------------------ PQ-11

    fn classical(bob: &Bob) -> PeerClassical {
        PeerClassical {
            account: bob.account,
            dev_sign: bob.dev_sign.pub_bytes,
            dev_dh: bob.dev_dh.pub_bytes,
            spk: SignedSpk::sign(&bob.dev_sign, 5, &bob.spk.pub_bytes),
        }
    }

    fn classical_keys(bob: &Bob) -> ClassicalResponderKeys<'_> {
        ClassicalResponderKeys {
            account: bob.account,
            dev_dh: &bob.dev_dh,
            spk: &bob.spk,
        }
    }

    #[test]
    fn pq11_sk0_and_root_match_openssl() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        for c in v["pq11"].as_array().unwrap() {
            let ini = x_pair(hx(&c["dev_dh_ini_priv"]));
            let ek = x_pair(hx(&c["ek_priv"]));
            let resp = x_pair(hx(&c["dev_dh_resp_priv"]));
            let spk = x_pair(hx(&c["spk_priv"]));
            let eph = KemSecret::from_seed(&hx(&c["eph_seed"]));
            let pq_ek = eph.public_key();
            // The responder computes SK0 from the type 5 fields.
            let hs = HandshakePq11Body {
                suite: SUITE,
                pq_ek: pq_ek.clone(),
                dev_dh: ini.pub_bytes,
                ek: ek.pub_bytes,
                spk_id: 5,
                opk_id: None,
                message: sample_message(),
            };
            let me = ClassicalResponderKeys {
                account: [1; 32],
                dev_dh: &resp,
                spk: &spk,
            };
            let r = respond_pq11(&me, &[2; 32], &hs).unwrap();
            assert_eq!(*r.sk0, hx::<32>(&c["sk0"]));
            // The initiator opens OpenSSL's ciphertext and reaches root1.
            let ct: [u8; CT_LEN] = hx(&c["ct"]);
            let ss = eph.decapsulate(&ct);
            assert_eq!(*ss, hx::<32>(&c["ss"]));
            assert_eq!(*pq11_root(&r.sk0, &ss, &ct), hx::<32>(&c["root1"]));
        }
    }

    #[test]
    fn a_pq11_session_runs_both_ways_after_the_reply() {
        use crate::p1::wire::KemReplyBody;
        use crate::ratchet::{init_initiator, init_responder, ratchet_decrypt, ratchet_encrypt};
        let mut rng = ChaCha20Rng::from_seed([11; 32]);
        let bob = Bob::new(&mut rng);
        let alice_account = [9u8; 32];
        let alice_dh = x_pair([8; 32]);

        // Alice: type 5 with message 0 under SK0 (no user text in it).
        let init =
            initiate_pq11_with_rng(&alice_account, &alice_dh, &classical(&bob), &mut rng).unwrap();
        let mut a0 = init_initiator(*init.sk0, bob.spk.pub_bytes).unwrap();
        let m0 = ratchet_encrypt(&mut a0, b"device list only", &init.ad).unwrap();
        let hs = HandshakePq11Body::decode(
            &init
                .handshake(MessageBody::from_ratchet(&m0).unwrap())
                .encode(),
        )
        .unwrap();

        // Bob: opens message 0, then mixes the KEM before replying.
        let resp = respond_pq11(&classical_keys(&bob), &alice_account, &hs).unwrap();
        let mut b0 = init_responder(*resp.sk0, bob.spk.clone());
        assert_eq!(
            ratchet_decrypt(&mut b0, &hs.message.to_ratchet(), &resp.ad).unwrap(),
            b"device list only"
        );
        let (ct, root1) = resp.reply_with_rng(&mut rng).unwrap();
        let mut b1 = init_initiator(*root1.root, hs.message.dh).unwrap();
        let r = ratchet_encrypt(&mut b1, b"hola", &resp.ad).unwrap();
        let reply = KemReplyBody::decode(
            &KemReplyBody {
                ct,
                message: MessageBody::from_ratchet(&r).unwrap(),
            }
            .encode(),
        )
        .unwrap();

        // Alice: the ciphertext gives the same root; her ratchet restarts
        // from it with the DH key she used in message 0.
        let root1_a = init.finish(&reply.ct);
        assert_eq!(*root1_a.root, *root1.root);
        let mut a1 = init_responder(*root1_a.root, a0.dhs.clone());
        assert_eq!(
            ratchet_decrypt(&mut a1, &reply.message.to_ratchet(), &init.ad).unwrap(),
            b"hola"
        );
        let back = ratchet_encrypt(&mut a1, b"que tal", &init.ad).unwrap();
        assert_eq!(
            ratchet_decrypt(&mut b1, &back, &resp.ad).unwrap(),
            b"que tal"
        );
        // SK0 alone does not give root1.
        assert_ne!(*init.sk0, *root1.root);
    }

    #[test]
    fn pq11_binds_the_ephemeral_key_and_the_ciphertext() {
        let mut rng = ChaCha20Rng::from_seed([12; 32]);
        let bob = Bob::new(&mut rng);
        let init =
            initiate_pq11_with_rng(&[9; 32], &x_pair([8; 32]), &classical(&bob), &mut rng).unwrap();
        let hs = init.handshake(sample_message());
        let good = respond_pq11(&classical_keys(&bob), &[9; 32], &hs).unwrap();
        assert_eq!(*good.sk0, *init.sk0);
        assert_eq!(good.ad, init.ad);
        // A swapped ephemeral key changes SK0.
        let mut other = hs.clone();
        other.pq_ek = KemSecret::from_seed(&[1; 64]).public_key();
        assert_ne!(
            *respond_pq11(&classical_keys(&bob), &[9; 32], &other)
                .unwrap()
                .sk0,
            *good.sk0
        );
        // A flipped ciphertext bit gives another root on the initiator.
        let (mut ct, root1) = good.reply_with_rng(&mut rng).unwrap();
        ct[3] ^= 1;
        assert_ne!(*init.finish(&ct).root, *root1.root);
        // Refused: another suite, a one-time prekey, a malformed ephemeral
        // key, a bad SPK signature.
        let mut bad = hs.clone();
        bad.suite = 2;
        assert_eq!(
            respond_pq11(&classical_keys(&bob), &[9; 32], &bad).err(),
            Some(PqxdhError::Suite(2))
        );
        let mut bad = hs.clone();
        bad.opk_id = Some(3);
        assert_eq!(
            respond_pq11(&classical_keys(&bob), &[9; 32], &bad).err(),
            Some(PqxdhError::OneTimePrekey)
        );
        let mut bad = hs.clone();
        bad.pq_ek[0] = 0xFF;
        bad.pq_ek[1] |= 0x0F;
        let r = respond_pq11(&classical_keys(&bob), &[9; 32], &bad).unwrap();
        assert_eq!(
            r.reply_with_rng(&mut rng).err(),
            Some(PqxdhError::Kem(KemError::InvalidKey))
        );
        let mut p = classical(&bob);
        p.spk.sig[1] ^= 1;
        assert_eq!(
            initiate_pq11_with_rng(&[9; 32], &x_pair([8; 32]), &p, &mut rng).err(),
            Some(PqxdhError::Spk)
        );
    }

    #[test]
    fn both_sides_get_the_same_session_seed_in_both_modes() {
        use crate::p1::mailbox::session_seed;
        let mut rng = ChaCha20Rng::from_seed([13; 32]);
        let bob = Bob::new(&mut rng);
        let alice_dh = x_pair([8; 32]);
        let init = initiate_with_rng(&[9; 32], &alice_dh, &bob.prekeys(), &mut rng).unwrap();
        let resp = respond(&bob.keys(), &[9; 32], &init.handshake(sample_message())).unwrap();
        assert_eq!(*init.s_ses, *resp.s_ses);
        assert_eq!(*init.s_ses, *session_seed(&init.sk, &init.ad));
        // PQ-11: S_ses comes from root', never from SK0.
        let init = initiate_pq11_with_rng(&[9; 32], &alice_dh, &classical(&bob), &mut rng).unwrap();
        let resp = respond_pq11(
            &classical_keys(&bob),
            &[9; 32],
            &init.handshake(sample_message()),
        )
        .unwrap();
        let (ct, theirs) = resp.reply_with_rng(&mut rng).unwrap();
        let ours = init.finish(&ct);
        assert_eq!(*ours.s_ses, *theirs.s_ses);
        assert_eq!(*ours.s_ses, *session_seed(&ours.root, &init.ad));
        assert_ne!(*ours.s_ses, *session_seed(&init.sk0, &init.ad));
    }

    #[test]
    fn pq11_and_the_normal_handshake_never_share_a_secret() {
        // Same DH inputs, but the labels differ: SK0 is not an SK.
        let dh = [&[1u8; 32], &[2u8; 32], &[3u8; 32]];
        let pq_ek = KemSecret::from_seed(&[4; 64]).public_key();
        let ct = [5u8; CT_LEN];
        assert_ne!(
            *combine_pq11(dh, &pq_ek),
            *combine(dh, &[0; 32], &pq_ek[..], &ct, 0)
        );
    }
}
