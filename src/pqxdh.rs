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
//! Not here yet: that `dev_dh_ini` belongs to `A_ini`'s device list (§5.1,
//! RV-06) is checked by the device list code (VI-1), and `S_ses` comes from
//! `SK` in P1-5.
//!
//! The tests check SK, AD and the SPK signature against OpenSSL
//! (`tests/vectors/pqxdh.py`), with OpenSSL's ciphertexts opened by libcrux.

use crate::crypto::{hkdf_expand, sha256};
use crate::identity::{ed25519_sign, KeyPair};
use crate::kem::{encapsulate_with_rng, KemError, KemSecret, CT_LEN};
use crate::p1::wire::{HandshakeBody, MessageBody, SUITE_X25519_MLKEM768};
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
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 * 5));
    ikm.extend_from_slice(&[0xFF; 32]);
    for d in dh {
        ikm.extend_from_slice(d);
    }
    ikm.extend_from_slice(ss);
    let mut info = Vec::with_capacity(INFO_LABEL.len() + 1 + 32 + 32 + 4);
    info.extend_from_slice(INFO_LABEL);
    info.push(SUITE);
    info.extend_from_slice(&sha256(pq_ek));
    info.extend_from_slice(&sha256(ct));
    info.extend_from_slice(&pq_spk_id.to_be_bytes());
    let okm = hkdf_expand(&ikm, &[0u8; 32], &info, 32).expect("32 bytes is a valid HKDF length");
    let mut sk = Zeroizing::new([0u8; 32]);
    sk.copy_from_slice(&okm);
    sk
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

    let mut ek_priv = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut ek_priv[..]);
    // StaticSecret wipes itself on drop.
    let ek = StaticSecret::from(*ek_priv);
    let dh1 = x25519(&StaticSecret::from(my_dev_dh.priv_bytes), &peer.spk.public)?;
    let dh2 = x25519(&ek, &peer.dev_dh)?;
    let dh3 = x25519(&ek, &peer.spk.public)?;
    let (ct, ss) = encapsulate_with_rng(&peer.pq_spk.ek, rng)?;
    let sk = combine(
        [&dh1, &dh2, &dh3],
        &ss,
        &peer.pq_spk.ek[..],
        &ct,
        peer.pq_spk.id,
    );
    Ok(Initiation {
        sk,
        ad: associated_data(
            my_account,
            &my_dev_dh.pub_bytes,
            &peer.account,
            &peer.dev_dh,
        ),
        pq_spk_id: peer.pq_spk.id,
        ct,
        dev_dh: my_dev_dh.pub_bytes,
        ek: XPublicKey::from(&ek).to_bytes(),
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
    let spk = StaticSecret::from(me.spk.priv_bytes);
    let dh1 = x25519(&spk, &hs.dev_dh)?;
    let dh2 = x25519(&StaticSecret::from(me.dev_dh.priv_bytes), &hs.ek)?;
    let dh3 = x25519(&spk, &hs.ek)?;
    let ss = me.pq.decapsulate(&hs.ct);
    let sk = combine(
        [&dh1, &dh2, &dh3],
        &ss,
        &me.pq.public_key()[..],
        &hs.ct,
        hs.pq_spk_id,
    );
    Ok(Response {
        sk,
        ad: associated_data(their_account, &hs.dev_dh, &me.account, &me.dev_dh.pub_bytes),
    })
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
}
