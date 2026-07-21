use crate::crypto::{aes_gcm_decrypt, aes_gcm_encrypt, concat, hkdf_expand, CryptoError};
use crate::identity::{generate_x25519, x25519_derive_shared, KeyPair};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use zeroize::Zeroize;

const KDF_RK_INFO: &[u8] = b"trino-ratchet-rk-v1";
const KDF_CK_INFO_CHAIN: &[u8] = b"trino-ratchet-ck-chain-v1";
const KDF_CK_INFO_MSG: &[u8] = b"trino-ratchet-ck-msg-v1";
const ZERO_SALT: [u8; 32] = [0u8; 32];

// Max messages we will skip (derive+store keys for) in one chain before refusing.
const MAX_SKIP: u32 = 1000;
const MAX_RETIRED_DH_KEYS: usize = 8;

#[derive(Debug, Error)]
pub enum RatchetError {
    #[error("no sending chain (waiting for peer message)")]
    NoSendingChain,
    #[error("no receiving chain")]
    NoReceivingChain,
    #[error("out-of-order message: expected n={expected} got n={got}")]
    OutOfOrder { expected: u32, got: u32 },
    #[error("too many skipped messages (gap > {0})")]
    TooManySkipped(u32),
    #[error("replayed or stale message n={n}")]
    Replay { n: u32 },
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetState {
    pub root_key: [u8; 32],
    pub dhs: KeyPair,
    pub dhr: Option<[u8; 32]>,
    pub sending_chain_key: Option<[u8; 32]>,
    pub receiving_chain_key: Option<[u8; 32]>,
    pub sending_msg_number: u32,
    pub receiving_msg_number: u32,
    pub previous_sending_chain_length: u32,
    // Derived-but-unused message keys for out-of-order delivery, keyed "dhPubHex:n".
    pub skipped_keys: HashMap<String, [u8; 32]>,
    // Recently retired peer DH keys classify stale old-chain ciphertext as a
    // replay instead of a new ratchet step.
    #[serde(default)]
    pub retired_peer_dh_keys: Vec<[u8; 32]>,
}

impl RatchetState {
    pub fn zeroize_secrets(&mut self) {
        self.root_key.zeroize();
        self.dhs.priv_bytes.zeroize();
        if let Some(key) = self.sending_chain_key.as_mut() {
            key.zeroize();
        }
        if let Some(key) = self.receiving_chain_key.as_mut() {
            key.zeroize();
        }
        for key in self.skipped_keys.values_mut() {
            key.zeroize();
        }
        self.sending_chain_key = None;
        self.receiving_chain_key = None;
        self.skipped_keys.clear();
    }
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageHeader {
    #[serde(rename = "dhPub")]
    pub dh_pub: String,
    pub pn: u32,
    pub n: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub header: MessageHeader,
    pub nonce: String,
    pub ciphertext: String,
}

pub fn init_initiator(
    master_secret: [u8; 32],
    their_spk_pub: [u8; 32],
) -> Result<RatchetState, RatchetError> {
    let dhs = generate_x25519();
    let dh_out = x25519_derive_shared(&dhs.priv_bytes, &their_spk_pub);
    let (root_key, chain_key) = kdf_rk(&master_secret, &dh_out)?;

    Ok(RatchetState {
        root_key,
        dhs,
        dhr: Some(their_spk_pub),
        sending_chain_key: Some(chain_key),
        receiving_chain_key: None,
        sending_msg_number: 0,
        receiving_msg_number: 0,
        previous_sending_chain_length: 0,
        skipped_keys: HashMap::new(),
        retired_peer_dh_keys: Vec::new(),
    })
}

pub fn init_responder(master_secret: [u8; 32], our_spk_keypair: KeyPair) -> RatchetState {
    RatchetState {
        root_key: master_secret,
        dhs: our_spk_keypair,
        dhr: None,
        sending_chain_key: None,
        receiving_chain_key: None,
        sending_msg_number: 0,
        receiving_msg_number: 0,
        previous_sending_chain_length: 0,
        skipped_keys: HashMap::new(),
        retired_peer_dh_keys: Vec::new(),
    }
}

pub fn ratchet_encrypt(
    state: &mut RatchetState,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<EncryptedMessage, RatchetError> {
    let sending_ck = state
        .sending_chain_key
        .ok_or(RatchetError::NoSendingChain)?;
    let (next_ck, message_key) = kdf_ck(&sending_ck)?;
    state.sending_chain_key = Some(next_ck);

    let header = MessageHeader {
        dh_pub: hex::encode(state.dhs.pub_bytes),
        pn: state.previous_sending_chain_length,
        n: state.sending_msg_number,
    };
    state.sending_msg_number += 1;

    let header_bytes = encode_header(&header)?;
    let ad = concat(&[associated_data, &header_bytes]);
    let (ciphertext, nonce) = aes_gcm_encrypt(&message_key, plaintext, Some(&ad))?;

    Ok(EncryptedMessage {
        header,
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
    })
}

pub fn ratchet_decrypt(
    state: &mut RatchetState,
    msg: &EncryptedMessage,
    associated_data: &[u8],
) -> Result<Vec<u8>, RatchetError> {
    // Transactional: roll back on any failure so a tampered, replayed or
    // undecryptable message can never corrupt the ratchet.
    let snapshot = state.clone();
    match ratchet_decrypt_inner(state, msg, associated_data) {
        Ok(pt) => Ok(pt),
        Err(e) => {
            *state = snapshot;
            Err(e)
        }
    }
}

fn ratchet_decrypt_inner(
    state: &mut RatchetState,
    msg: &EncryptedMessage,
    associated_data: &[u8],
) -> Result<Vec<u8>, RatchetError> {
    let header_dh = decode_32(&msg.header.dh_pub)?;

    // 1. A message we already derived a key for (arrived late / out of order).
    if let Some(pt) = try_skipped_message_key(state, msg, &header_dh, associated_data)? {
        return Ok(pt);
    }

    // A key from a completed chain, or an already-consumed message in the
    // current chain, is a replay. It must never trigger session auto-healing.
    if state
        .retired_peer_dh_keys
        .iter()
        .any(|retired| retired == &header_dh)
        || (state.dhr.as_ref() == Some(&header_dh) && msg.header.n < state.receiving_msg_number)
    {
        return Err(RatchetError::Replay { n: msg.header.n });
    }

    // 2. New DH ratchet key from the peer → bank the rest of the old chain, step.
    let is_new_dh = match &state.dhr {
        Some(prev) => prev != &header_dh,
        None => true,
    };
    if is_new_dh {
        skip_message_keys(state, msg.header.pn)?;
        dh_ratchet_step(state, header_dh)?;
    }

    // 3. Bank any keys between where we are and this message's number.
    skip_message_keys(state, msg.header.n)?;

    // 4. Derive this message's key and decrypt.
    let recv_ck = state
        .receiving_chain_key
        .ok_or(RatchetError::NoReceivingChain)?;
    let (next_ck, message_key) = kdf_ck(&recv_ck)?;
    state.receiving_chain_key = Some(next_ck);
    state.receiving_msg_number += 1;

    let header_bytes = encode_header(&msg.header)?;
    let ad = concat(&[associated_data, &header_bytes]);
    let ciphertext = decode_hex(&msg.ciphertext)?;
    let nonce = decode_hex(&msg.nonce)?;
    Ok(aes_gcm_decrypt(
        &message_key,
        &ciphertext,
        &nonce,
        Some(&ad),
    )?)
}

fn skipped_key_id(dh_pub: &[u8; 32], n: u32) -> String {
    format!("{}:{}", hex::encode(dh_pub), n)
}

fn try_skipped_message_key(
    state: &mut RatchetState,
    msg: &EncryptedMessage,
    header_dh: &[u8; 32],
    associated_data: &[u8],
) -> Result<Option<Vec<u8>>, RatchetError> {
    let id = skipped_key_id(header_dh, msg.header.n);
    let mk = match state.skipped_keys.get(&id) {
        Some(k) => *k,
        None => return Ok(None),
    };
    let header_bytes = encode_header(&msg.header)?;
    let ad = concat(&[associated_data, &header_bytes]);
    let ciphertext = decode_hex(&msg.ciphertext)?;
    let nonce = decode_hex(&msg.nonce)?;
    let pt = aes_gcm_decrypt(&mk, &ciphertext, &nonce, Some(&ad))?;
    state.skipped_keys.remove(&id);
    Ok(Some(pt))
}

fn skip_message_keys(state: &mut RatchetState, until: u32) -> Result<(), RatchetError> {
    let recv_ck = match state.receiving_chain_key {
        Some(ck) => ck,
        None => return Ok(()),
    };
    if state.receiving_msg_number.saturating_add(MAX_SKIP) < until {
        return Err(RatchetError::TooManySkipped(MAX_SKIP));
    }
    let dhr = match state.dhr {
        Some(d) => d,
        None => return Ok(()),
    };
    let mut ck = recv_ck;
    while state.receiving_msg_number < until {
        let (next_ck, mk) = kdf_ck(&ck)?;
        ck = next_ck;
        state
            .skipped_keys
            .insert(skipped_key_id(&dhr, state.receiving_msg_number), mk);
        state.receiving_msg_number += 1;
    }
    state.receiving_chain_key = Some(ck);
    Ok(())
}

fn dh_ratchet_step(state: &mut RatchetState, peer_dh_pub: [u8; 32]) -> Result<(), RatchetError> {
    state.previous_sending_chain_length = state.sending_msg_number;
    state.sending_msg_number = 0;
    state.receiving_msg_number = 0;
    if let Some(previous) = state.dhr {
        if previous != peer_dh_pub && !state.retired_peer_dh_keys.contains(&previous) {
            state.retired_peer_dh_keys.push(previous);
            if state.retired_peer_dh_keys.len() > MAX_RETIRED_DH_KEYS {
                state.retired_peer_dh_keys.remove(0);
            }
        }
    }
    state.dhr = Some(peer_dh_pub);

    let dh_out_recv = x25519_derive_shared(&state.dhs.priv_bytes, &peer_dh_pub);
    let (new_rk, recv_ck) = kdf_rk(&state.root_key, &dh_out_recv)?;
    state.root_key = new_rk;
    state.receiving_chain_key = Some(recv_ck);

    let new_dhs = generate_x25519();
    let dh_out_send = x25519_derive_shared(&new_dhs.priv_bytes, &peer_dh_pub);
    state.dhs = new_dhs;
    let (new_rk2, send_ck) = kdf_rk(&state.root_key, &dh_out_send)?;
    state.root_key = new_rk2;
    state.sending_chain_key = Some(send_ck);
    Ok(())
}

fn kdf_rk(rk: &[u8], dh_out: &[u8]) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let okm = hkdf_expand(dh_out, rk, KDF_RK_INFO, 64)?;
    let mut new_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    new_rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);
    Ok((new_rk, ck))
}

fn kdf_ck(ck: &[u8]) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let next_ck = hkdf_expand(ck, &ZERO_SALT, KDF_CK_INFO_CHAIN, 32)?;
    let mk = hkdf_expand(ck, &ZERO_SALT, KDF_CK_INFO_MSG, 32)?;
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&next_ck);
    b.copy_from_slice(&mk);
    Ok((a, b))
}

fn encode_header(h: &MessageHeader) -> Result<Vec<u8>, RatchetError> {
    let dh_bytes = decode_32(&h.dh_pub)?;
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&dh_bytes);
    out.extend_from_slice(&h.pn.to_be_bytes());
    out.extend_from_slice(&h.n.to_be_bytes());
    Ok(out)
}

fn decode_32(s: &str) -> Result<[u8; 32], RatchetError> {
    let v = hex::decode(s).map_err(|_| {
        RatchetError::Crypto(CryptoError::InvalidKeyLength {
            expected: 32,
            got: 0,
        })
    })?;
    if v.len() != 32 {
        return Err(RatchetError::Crypto(CryptoError::InvalidKeyLength {
            expected: 32,
            got: v.len(),
        }));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&v);
    Ok(arr)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, RatchetError> {
    hex::decode(s).map_err(|_| RatchetError::Crypto(CryptoError::Aead))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{create_identity, public_bundle_for};
    use crate::x3dh::{initiate, respond};

    #[test]
    fn single_message_alice_to_bob() {
        let alice = create_identity();
        let mut bob = create_identity();
        let bob_bundle = public_bundle_for(&bob);
        let init = initiate(&alice, &bob_bundle).unwrap();
        let resp = respond(&mut bob, &init.message).unwrap();

        let mut alice_state = init_initiator(
            init.master_secret,
            crate::identity::decode_array_32(&bob_bundle.spk_pub).unwrap(),
        )
        .unwrap();
        let mut bob_state = init_responder(resp.master_secret, bob.signed_prekey.keypair.clone());

        let ct = ratchet_encrypt(&mut alice_state, b"hola bob", &init.associated_data).unwrap();
        let pt = ratchet_decrypt(&mut bob_state, &ct, &resp.associated_data).unwrap();
        assert_eq!(&pt, b"hola bob");
    }

    #[test]
    fn full_conversation() {
        let alice = create_identity();
        let mut bob = create_identity();
        let bob_bundle = public_bundle_for(&bob);
        let init = initiate(&alice, &bob_bundle).unwrap();
        let resp = respond(&mut bob, &init.message).unwrap();
        let mut alice_state = init_initiator(
            init.master_secret,
            crate::identity::decode_array_32(&bob_bundle.spk_pub).unwrap(),
        )
        .unwrap();
        let mut bob_state = init_responder(resp.master_secret, bob.signed_prekey.keypair.clone());
        let ad = init.associated_data;

        let m1 = ratchet_encrypt(&mut alice_state, b"1: alice", &ad).unwrap();
        assert_eq!(
            ratchet_decrypt(&mut bob_state, &m1, &ad).unwrap(),
            b"1: alice"
        );
        let m2 = ratchet_encrypt(&mut bob_state, b"2: bob", &ad).unwrap();
        assert_eq!(
            ratchet_decrypt(&mut alice_state, &m2, &ad).unwrap(),
            b"2: bob"
        );
        let m3 = ratchet_encrypt(&mut alice_state, b"3: alice", &ad).unwrap();
        assert_eq!(
            ratchet_decrypt(&mut bob_state, &m3, &ad).unwrap(),
            b"3: alice"
        );
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let alice = create_identity();
        let mut bob = create_identity();
        let bob_bundle = public_bundle_for(&bob);
        let init = initiate(&alice, &bob_bundle).unwrap();
        let resp = respond(&mut bob, &init.message).unwrap();
        let mut alice_state = init_initiator(
            init.master_secret,
            crate::identity::decode_array_32(&bob_bundle.spk_pub).unwrap(),
        )
        .unwrap();
        let mut bob_state = init_responder(resp.master_secret, bob.signed_prekey.keypair.clone());

        let mut ct =
            ratchet_encrypt(&mut alice_state, b"important", &init.associated_data).unwrap();
        let mut ct_bytes = hex::decode(&ct.ciphertext).unwrap();
        ct_bytes[0] ^= 0xff;
        ct.ciphertext = hex::encode(&ct_bytes);
        assert!(ratchet_decrypt(&mut bob_state, &ct, &resp.associated_data).is_err());
    }

    fn pair() -> (RatchetState, RatchetState, Vec<u8>) {
        let alice = create_identity();
        let mut bob = create_identity();
        let bob_bundle = public_bundle_for(&bob);
        let init = initiate(&alice, &bob_bundle).unwrap();
        let resp = respond(&mut bob, &init.message).unwrap();
        let alice_state = init_initiator(
            init.master_secret,
            crate::identity::decode_array_32(&bob_bundle.spk_pub).unwrap(),
        )
        .unwrap();
        let bob_state = init_responder(resp.master_secret, bob.signed_prekey.keypair.clone());
        (alice_state, bob_state, init.associated_data)
    }

    #[test]
    fn out_of_order_messages_decrypt() {
        let (mut alice, mut bob, ad) = pair();
        let mut cts = vec![];
        for i in 0..5 {
            cts.push(ratchet_encrypt(&mut alice, format!("m{i}").as_bytes(), &ad).unwrap());
        }
        for &i in &[2usize, 4, 0, 3, 1] {
            let pt = ratchet_decrypt(&mut bob, &cts[i], &ad).unwrap();
            assert_eq!(pt, format!("m{i}").as_bytes());
        }
    }

    #[test]
    fn out_of_order_across_dh_step() {
        let (mut alice, mut bob, ad) = pair();
        let a0 = ratchet_encrypt(&mut alice, b"a0", &ad).unwrap();
        let a1 = ratchet_encrypt(&mut alice, b"a1", &ad).unwrap();
        ratchet_decrypt(&mut bob, &a0, &ad).unwrap();
        let b0 = ratchet_encrypt(&mut bob, b"b0", &ad).unwrap();
        ratchet_decrypt(&mut alice, &b0, &ad).unwrap();
        let a2 = ratchet_encrypt(&mut alice, b"a2", &ad).unwrap(); // new chain
        assert_eq!(ratchet_decrypt(&mut bob, &a2, &ad).unwrap(), b"a2");
        assert_eq!(ratchet_decrypt(&mut bob, &a1, &ad).unwrap(), b"a1"); // old-chain straggler
    }

    #[test]
    fn replay_does_not_corrupt() {
        let (mut alice, mut bob, ad) = pair();
        let m0 = ratchet_encrypt(&mut alice, b"m0", &ad).unwrap();
        let m1 = ratchet_encrypt(&mut alice, b"m1", &ad).unwrap();
        assert_eq!(ratchet_decrypt(&mut bob, &m0, &ad).unwrap(), b"m0");
        assert!(matches!(
            ratchet_decrypt(&mut bob, &m0, &ad),
            Err(RatchetError::Replay { n: 0 })
        ));
        assert_eq!(ratchet_decrypt(&mut bob, &m1, &ad).unwrap(), b"m1"); // still healthy
    }

    #[test]
    fn replay_is_classified_after_state_reload() {
        let (mut alice, mut bob, ad) = pair();
        let m0 = ratchet_encrypt(&mut alice, b"m0", &ad).unwrap();
        assert_eq!(ratchet_decrypt(&mut bob, &m0, &ad).unwrap(), b"m0");

        let saved = serde_json::to_vec(&bob).unwrap();
        let mut reloaded: RatchetState = serde_json::from_slice(&saved).unwrap();
        assert!(matches!(
            ratchet_decrypt(&mut reloaded, &m0, &ad),
            Err(RatchetError::Replay { n: 0 })
        ));
    }

    #[test]
    fn replay_from_retired_chain_is_classified() {
        let (mut alice, mut bob, ad) = pair();
        let old = ratchet_encrypt(&mut alice, b"old", &ad).unwrap();
        ratchet_decrypt(&mut bob, &old, &ad).unwrap();
        let reply = ratchet_encrypt(&mut bob, b"reply", &ad).unwrap();
        ratchet_decrypt(&mut alice, &reply, &ad).unwrap();
        let next_chain = ratchet_encrypt(&mut alice, b"next", &ad).unwrap();
        ratchet_decrypt(&mut bob, &next_chain, &ad).unwrap();

        assert!(matches!(
            ratchet_decrypt(&mut bob, &old, &ad),
            Err(RatchetError::Replay { n: 0 })
        ));
    }

    #[test]
    fn max_skip_guard_rejects_absurd_gap() {
        let (mut alice, mut bob, ad) = pair();
        let mut ct = ratchet_encrypt(&mut alice, b"x", &ad).unwrap();
        ct.header.n = 5000;
        assert!(matches!(
            ratchet_decrypt(&mut bob, &ct, &ad),
            Err(RatchetError::TooManySkipped(_))
        ));
    }
}
