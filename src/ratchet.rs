use crate::crypto::{aes_gcm_decrypt, aes_gcm_encrypt, concat, hkdf_expand, CryptoError};
use crate::identity::{generate_x25519, x25519_derive_shared, KeyPair};
use crate::p1::mailbox::{MailboxError, SessionChain};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use zeroize::Zeroize;

const KDF_RK_INFO: &[u8] = b"trino-ratchet-rk-v1";
const KDF_CK_INFO_CHAIN: &[u8] = b"trino-ratchet-ck-chain-v1";
const KDF_CK_INFO_MSG: &[u8] = b"trino-ratchet-ck-msg-v1";
const ZERO_SALT: [u8; 32] = [0u8; 32];

// Max messages we will skip (derive+store keys for) in one chain before refusing.
const MAX_SKIP: u32 = 1000;
const MAX_RETIRED_DH_KEYS: usize = 8;

// Ceiling on banked out-of-order keys across ALL chains. MAX_SKIP only bounds a
// single gap: without a global cap a peer can bank another 1000 keys on every DH
// step, forever, growing the state we persist into the vault without limit.
// Past the cap the oldest keys are dropped — those messages become permanently
// undecryptable, which is the correct trade against unbounded growth.
const MAX_SKIPPED_KEYS: usize = 2000;

/// The state version of a P1 session (hybrid handshake and mailboxes).
/// Version 0 is a session from before P1: the app drops it on load and
/// sends a delayed handshake (design P1 §9, R-01).
pub const STATE_VERSION: u32 = 2;

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
    #[error("ratchet state version {0} is newer than this code")]
    StateVersion(u32),
    #[error("ratchet state does not decode")]
    Decode,
    #[error("mailbox chain: {0}")]
    Mailbox(#[from] MailboxError),
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
    // Insertion order over `skipped_keys`, so the global cap can evict the
    // oldest first. Defaulted so sessions sealed before the cap existed load.
    #[serde(default)]
    pub skipped_key_order: Vec<String>,
    // Recently retired peer DH keys classify stale old-chain ciphertext as a
    // replay instead of a new ratchet step.
    #[serde(default)]
    pub retired_peer_dh_keys: Vec<[u8; 32]>,
    // P1 (design P1 §9, diseno-vinculacion.md §21.5). All defaulted, so a
    // session from before P1 loads as version 0 with no mailbox chain.
    #[serde(default)]
    pub version: u32,
    /// The handshake suite; 0 before P1.
    #[serde(default)]
    pub suite: u8,
    /// Today's and yesterday's session mailbox secrets.
    #[serde(default)]
    pub session: Option<SessionChain>,
    /// A PQ-11 session still waiting for the type 4 ciphertext (§21.6).
    #[serde(default)]
    pub awaiting_kem: bool,
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
        self.skipped_key_order.clear();
        // SessionChain wipes itself on drop.
        self.session = None;
    }

    /// Makes this a P1 session: records the suite and starts the mailbox
    /// chain from `S_ses` at `e0`, the epoch of the authenticated `ts` of
    /// the message that carried the handshake, walked to `today` (§3.3).
    pub fn attach_session(
        &mut self,
        suite: u8,
        s_ses: &[u8; 32],
        e0: u32,
        today: u32,
    ) -> Result<(), RatchetError> {
        self.session = Some(SessionChain::start(s_ses, e0, today)?);
        self.suite = suite;
        self.version = STATE_VERSION;
        Ok(())
    }

    /// Whether this session can run on P1. One that cannot is dropped on
    /// load; the contact stays and gets a delayed handshake.
    pub fn is_p1(&self) -> bool {
        self.version == STATE_VERSION && self.suite == crate::pqxdh::SUITE && self.session.is_some()
    }

    /// Decodes a stored state and refuses a version newer than this code.
    pub fn load(bytes: &[u8]) -> Result<RatchetState, RatchetError> {
        let state: RatchetState =
            serde_json::from_slice(bytes).map_err(|_| RatchetError::Decode)?;
        if state.version > STATE_VERSION {
            return Err(RatchetError::StateVersion(state.version));
        }
        Ok(state)
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
        skipped_key_order: Vec::new(),
        retired_peer_dh_keys: Vec::new(),
        version: 0,
        suite: 0,
        session: None,
        awaiting_kem: false,
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
        skipped_key_order: Vec::new(),
        retired_peer_dh_keys: Vec::new(),
        version: 0,
        suite: 0,
        session: None,
        awaiting_kem: false,
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
    state.skipped_key_order.retain(|k| k != &id);
    Ok(Some(pt))
}

/// Bank a derived-but-unused message key, enforcing the global ceiling.
fn bank_skipped_key(state: &mut RatchetState, id: String, mk: [u8; 32]) {
    match state.skipped_keys.insert(id.clone(), mk) {
        Some(mut replaced) => replaced.zeroize(),
        None => state.skipped_key_order.push(id),
    }
    evict_oldest_skipped_keys(state);
}

fn evict_oldest_skipped_keys(state: &mut RatchetState) {
    if state.skipped_keys.len() <= MAX_SKIPPED_KEYS {
        return;
    }
    adopt_unordered_skipped_keys(state);
    while state.skipped_keys.len() > MAX_SKIPPED_KEYS {
        if state.skipped_key_order.is_empty() {
            break;
        }
        let oldest = state.skipped_key_order.remove(0);
        if let Some(mut mk) = state.skipped_keys.remove(&oldest) {
            mk.zeroize();
        }
    }
}

/// A session sealed before `skipped_key_order` existed loads with a full map and
/// an empty order list. Adopt those keys — sorted, so eviction stays
/// deterministic — ahead of anything we do have an order for, since they are by
/// definition older.
fn adopt_unordered_skipped_keys(state: &mut RatchetState) {
    if state.skipped_key_order.len() == state.skipped_keys.len() {
        return;
    }
    let known: HashSet<String> = state.skipped_key_order.iter().cloned().collect();
    let mut adopted: Vec<String> = state
        .skipped_keys
        .keys()
        .filter(|k| !known.contains(*k))
        .cloned()
        .collect();
    adopted.sort();
    adopted.append(&mut state.skipped_key_order);
    state.skipped_key_order = adopted;
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
        bank_skipped_key(state, skipped_key_id(&dhr, state.receiving_msg_number), mk);
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

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(48))]

        /// Whatever order the network happens to deliver a burst in, every
        /// message must come out intact and exactly once. That is the entire
        /// promise of the skipped-key machinery, and it is the property the
        /// hand-written out-of-order tests can only sample.
        #[test]
        fn every_delivery_order_decrypts_every_message(
            weights in proptest::collection::vec(proptest::prelude::any::<u32>(), 8)
        ) {
            let (mut alice, mut bob, ad) = pair();
            let sent: Vec<_> = (0..8)
                .map(|i| ratchet_encrypt(&mut alice, format!("m{i}").as_bytes(), &ad).unwrap())
                .collect();

            let mut order: Vec<usize> = (0..8).collect();
            order.sort_by_key(|&i| weights[i]);

            for &i in &order {
                let plaintext = ratchet_decrypt(&mut bob, &sent[i], &ad).unwrap();
                proptest::prop_assert_eq!(plaintext, format!("m{i}").into_bytes());
            }
        }
    }

    #[test]
    fn banked_keys_stay_under_the_global_cap_across_dh_steps() {
        let (mut alice, mut bob, ad) = pair();
        // Each round banks ~900 keys. Three rounds would reach ~2700 without a
        // global ceiling — MAX_SKIP alone does not stop this.
        for _round in 0..3 {
            let mut cts = vec![];
            for i in 0..900 {
                cts.push(ratchet_encrypt(&mut alice, format!("m{i}").as_bytes(), &ad).unwrap());
            }
            // Only the newest arrives; everything before it gets banked.
            ratchet_decrypt(&mut bob, cts.last().unwrap(), &ad).unwrap();
            assert!(bob.skipped_keys.len() <= MAX_SKIPPED_KEYS);

            // Force a DH step so the next round banks under a fresh chain.
            let reply = ratchet_encrypt(&mut bob, b"reply", &ad).unwrap();
            ratchet_decrypt(&mut alice, &reply, &ad).unwrap();
        }
        assert_eq!(bob.skipped_keys.len(), MAX_SKIPPED_KEYS);
        assert_eq!(bob.skipped_key_order.len(), bob.skipped_keys.len());
    }

    #[test]
    fn consuming_a_banked_key_also_clears_its_order_entry() {
        let (mut alice, mut bob, ad) = pair();
        let m0 = ratchet_encrypt(&mut alice, b"m0", &ad).unwrap();
        let m1 = ratchet_encrypt(&mut alice, b"m1", &ad).unwrap();
        ratchet_decrypt(&mut bob, &m1, &ad).unwrap(); // banks m0's key
        assert_eq!(bob.skipped_keys.len(), 1);
        assert_eq!(bob.skipped_key_order.len(), 1);

        ratchet_decrypt(&mut bob, &m0, &ad).unwrap(); // consumes it
        assert!(bob.skipped_keys.is_empty());
        assert!(bob.skipped_key_order.is_empty());
    }

    #[test]
    fn legacy_banked_keys_without_an_order_list_are_evicted_to_the_cap() {
        let (_alice, mut bob, _ad) = pair();
        // A session sealed before the cap existed: banked keys, no order list.
        for n in 0..(MAX_SKIPPED_KEYS as u32 + 50) {
            bob.skipped_keys
                .insert(skipped_key_id(&[7u8; 32], n), [1u8; 32]);
        }
        assert!(bob.skipped_key_order.is_empty());

        evict_oldest_skipped_keys(&mut bob);

        assert_eq!(bob.skipped_keys.len(), MAX_SKIPPED_KEYS);
        assert_eq!(bob.skipped_key_order.len(), MAX_SKIPPED_KEYS);
    }

    #[test]
    fn session_sealed_before_the_cap_still_deserializes() {
        let (_alice, bob, _ad) = pair();
        let mut raw = serde_json::to_value(&bob).unwrap();
        raw.as_object_mut().unwrap().remove("skipped_key_order");
        let reloaded: RatchetState = serde_json::from_value(raw).unwrap();
        assert!(reloaded.skipped_key_order.is_empty());
    }

    // Known answers for the key schedule. The agreement tests above cannot see
    // a KDF that returns a constant, since both sides would agree on it. These
    // come from an independent HKDF-SHA256 (RFC 5869 over Python's hmac and
    // hashlib, self-checked against RFC 5869 test case 1), not from this crate.
    //
    // kdf_rk(rk = [1; 32], dh_out = [2; 32]): salt = rk, ikm = dh_out.
    const KAT_RK: &str = "353408393104ce34bf5bea3518ecb79bfc27e528b8e8ad3132df124bb5966a5e";
    const KAT_RK_CK: &str = "1f3bdc1f17629e2ace21db6155efdeaaad3d7bf8a608afa7db2e6eedf87eac9f";
    // kdf_ck(ck = [3; 32]), and kdf_ck of its next chain key.
    const KAT_CK_NEXT: &str = "ce601e9741de7516ca58df66f43441b3673acfd297690e0bf65696df0d142206";
    const KAT_CK_MK: &str = "b53c5bf1d4e78dbba078cb9119ea0e4629459a97532fef5e0eb3ecb1ff6ff716";
    const KAT_CK2_NEXT: &str = "b7517debc36130a945043905067ed5c5dea36840b91696772ac3d5c82b543f7a";
    const KAT_CK2_MK: &str = "e29116967bb9b9af98f4b4ab524f508473c74c87c8430a56a2e0b78ba41b4617";

    #[test]
    fn kdf_rk_matches_known_vector() {
        let (rk, ck) = kdf_rk(&[1; 32], &[2; 32]).unwrap();
        assert_eq!(hex::encode(rk), KAT_RK);
        assert_eq!(hex::encode(ck), KAT_RK_CK);
    }

    #[test]
    fn kdf_ck_matches_known_vectors() {
        let (next, mk) = kdf_ck(&[3; 32]).unwrap();
        assert_eq!(hex::encode(next), KAT_CK_NEXT);
        assert_eq!(hex::encode(mk), KAT_CK_MK);
        let (next2, mk2) = kdf_ck(&next).unwrap();
        assert_eq!(hex::encode(next2), KAT_CK2_NEXT);
        assert_eq!(hex::encode(mk2), KAT_CK2_MK);
    }

    #[test]
    fn header_encodes_as_dh_pub_then_pn_then_n_big_endian() {
        let dh: Vec<u8> = (0u8..32).collect();
        let header = MessageHeader {
            dh_pub: hex::encode(&dh),
            pn: 0x0102_0304,
            n: 0x0506_0708,
        };
        let mut expected = dh.clone();
        expected.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(encode_header(&header).unwrap(), expected);
    }

    /// Opens a message with nothing but the known message key and an AD built
    /// by hand (caller AD, then dh_pub || pn || n), so the ratchet's own KDF,
    /// header encoding and `concat` are all checked against outside values.
    fn open_with(mk_hex: &str, msg: &EncryptedMessage, ad: &[u8], dh_pub: &[u8; 32]) -> Vec<u8> {
        let mut full_ad = ad.to_vec();
        full_ad.extend_from_slice(dh_pub);
        full_ad.extend_from_slice(&msg.header.pn.to_be_bytes());
        full_ad.extend_from_slice(&msg.header.n.to_be_bytes());
        aes_gcm_decrypt(
            &hex::decode(mk_hex).unwrap(),
            &hex::decode(&msg.ciphertext).unwrap(),
            &hex::decode(&msg.nonce).unwrap(),
            Some(&full_ad),
        )
        .unwrap()
    }

    #[test]
    fn encrypt_uses_the_known_chain_and_binds_ad_and_header() {
        let (mut alice, _bob, ad) = pair();
        alice.sending_chain_key = Some([3; 32]);
        alice.previous_sending_chain_length = 7;
        let dh_pub = alice.dhs.pub_bytes;

        let m0 = ratchet_encrypt(&mut alice, b"first", &ad).unwrap();
        assert_eq!((m0.header.pn, m0.header.n), (7, 0));
        assert_eq!(hex::encode(alice.sending_chain_key.unwrap()), KAT_CK_NEXT);
        assert_eq!(open_with(KAT_CK_MK, &m0, &ad, &dh_pub), b"first");

        let m1 = ratchet_encrypt(&mut alice, b"second", &ad).unwrap();
        assert_eq!(m1.header.n, 1);
        assert_eq!(hex::encode(alice.sending_chain_key.unwrap()), KAT_CK2_NEXT);
        assert_eq!(open_with(KAT_CK2_MK, &m1, &ad, &dh_pub), b"second");
    }

    #[test]
    fn header_and_associated_data_are_authenticated() {
        let (mut alice, mut bob, ad) = pair();
        let m0 = ratchet_encrypt(&mut alice, b"0", &ad).unwrap();
        assert_eq!(ratchet_decrypt(&mut bob, &m0, &ad).unwrap(), b"0");

        // Same chain, so pn does not take part in deriving the key: only the
        // AD can tell the forged header apart.
        let m1 = ratchet_encrypt(&mut alice, b"x", &ad).unwrap();
        let mut other_pn = m1.clone();
        other_pn.header.pn += 1;
        assert!(ratchet_decrypt(&mut bob, &other_pn, &ad).is_err());
        assert!(ratchet_decrypt(&mut bob, &m1, b"another AD").is_err());
        assert_eq!(ratchet_decrypt(&mut bob, &m1, &ad).unwrap(), b"x");
    }

    #[test]
    fn chain_and_root_keys_move() {
        let (mut alice, mut bob, ad) = pair();
        let ck_before = alice.sending_chain_key.unwrap();
        let m0 = ratchet_encrypt(&mut alice, b"0", &ad).unwrap();
        let ck_after_one = alice.sending_chain_key.unwrap();
        ratchet_encrypt(&mut alice, b"1", &ad).unwrap();
        assert_ne!(ck_before, ck_after_one);
        assert_ne!(ck_after_one, alice.sending_chain_key.unwrap());

        // Bob's first message from Alice is a DH step: two kdf_rk calls.
        let rk_before = bob.root_key;
        ratchet_decrypt(&mut bob, &m0, &ad).unwrap();
        assert_ne!(bob.root_key, rk_before);
        assert_ne!(bob.sending_chain_key, bob.receiving_chain_key);
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

    // ------------------------------------------------------------ P1 state

    fn p1_pair() -> (RatchetState, RatchetState) {
        let bob_spk = generate_x25519();
        let a = init_initiator([1; 32], bob_spk.pub_bytes).unwrap();
        let b = init_responder([1; 32], bob_spk);
        (a, b)
    }

    #[test]
    fn a_state_from_before_p1_loads_as_version_0_without_a_session() {
        let (a, _) = p1_pair();
        let mut raw = serde_json::to_value(&a).unwrap();
        for k in ["version", "suite", "session", "awaiting_kem"] {
            raw.as_object_mut().unwrap().remove(k);
        }
        let loaded = RatchetState::load(&serde_json::to_vec(&raw).unwrap()).unwrap();
        assert_eq!((loaded.version, loaded.suite), (0, 0));
        assert!(loaded.session.is_none());
        assert!(!loaded.is_p1());
    }

    #[test]
    fn a_newer_state_version_is_refused() {
        let (mut a, _) = p1_pair();
        a.attach_session(1, &[2; 32], 10, 10).unwrap();
        a.version = STATE_VERSION + 1;
        let bytes = serde_json::to_vec(&a).unwrap();
        assert!(matches!(
            RatchetState::load(&bytes),
            Err(RatchetError::StateVersion(v)) if v == STATE_VERSION + 1
        ));
        assert!(matches!(
            RatchetState::load(b"{"),
            Err(RatchetError::Decode)
        ));
    }

    #[test]
    fn a_p1_session_round_trips_and_keeps_only_two_days() {
        let (mut a, _) = p1_pair();
        a.attach_session(1, &[2; 32], 10, 12).unwrap();
        assert!(a.is_p1());
        let loaded = RatchetState::load(&serde_json::to_vec(&a).unwrap()).unwrap();
        assert!(loaded.is_p1());
        let chain = loaded.session.as_ref().unwrap();
        assert_eq!(chain.epoch, 12);
        assert!(chain.secret(12).is_some() && chain.secret(11).is_some());
        assert!(chain.secret(10).is_none());
        // Another suite is not a P1 session.
        let (mut b, _) = p1_pair();
        b.attach_session(0, &[2; 32], 10, 10).unwrap();
        assert!(!b.is_p1());
    }

    #[test]
    fn wiping_the_state_drops_the_mailbox_chain() {
        let (mut a, _) = p1_pair();
        a.attach_session(1, &[2; 32], 10, 10).unwrap();
        a.zeroize_secrets();
        assert!(a.session.is_none());
    }
}
