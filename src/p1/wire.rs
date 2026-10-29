//! The P1 inner frame: what NIP-44 seals inside every P1 event (design P1
//! §2.2-§2.3, with the hybrid types of `diseno-vinculacion.md` §21.1, §21.4,
//! §21.6 and §21.8).
//!
//! ```text
//! inner = ver u8 (= 1) ‖ type u8 ‖ ts u64 BE ‖ len u32 BE ‖ body[len] ‖ zeros ‖ mac 32
//!         and it measures exactly its step E (1, 4, 16 or 40 KiB)
//! mac   = HMAC-SHA256(k_mac, "trino/p1/v1/inner" ‖ inner[0 .. E − 32])     (types 1, 2, 4)
//! mac   = 32 zero bytes                                                     (type 3)
//!
//! type 1, message:    dh 32 ‖ pn u32 ‖ n u32 ‖ nonce 12 ‖ AES-256-GCM ciphertext with its tag
//! type 2, handshake:  suite u8 ‖ pq_spk_id u32 ‖ ct 1088 ‖ dev_dh 32 ‖ ek 32 ‖ spk_id u32
//!                     ‖ opk_id u32 (0xFFFFFFFF = none) ‖ <type 1 body>                 (4 KiB)
//! type 3, request:    pow_nonce u64 ‖ suite u8 ‖ con_kem u8 ‖ e 32 ‖ dev_dh 32
//!                     ‖ [ct_R 1088 if con_kem] ‖ sealed part                         (16 KiB)
//! type 4, KEM reply:  ct 1088 ‖ <type 1 body>                                        (4 KiB)
//! pow   = SHA-256("trino/p1/v2/pow" ‖ R ‖ SHA-256(type 3 body after pow_nonce) ‖ pow_nonce)
//! ```
//!
//! - **The MAC comes before the ratchet.** A frame that fails it is dropped
//!   without touching any state; anyone who sees a mailbox can NIP-44 seal
//!   something to it, and a forged header with a large `n` would otherwise
//!   make the ratchet derive up to 1000 skipped keys.
//! - **Post-quantum fields first** in type 2 (`suite`, `pq_spk_id`, `ct`),
//!   identity after, so a version 2 can encrypt the identity under the KEM
//!   secret without reordering (§21.1). Version 2 is reserved; any version
//!   other than 1 is refused without touching the ratchet.
//! - **No classical suite exists** (PQ-01): `suite` is `0x01` (X25519 +
//!   ML-KEM-768 + HKDF-SHA-256 + AES-256-GCM) or the frame is refused.
//! - **Steps are fixed per type** (R-22): type 2 and 4 always 4 KiB, type 3
//!   always 16 KiB, type 1 whichever step its content class takes (the app
//!   chooses: a profile is always 40 KiB, a call signal always 16 KiB).
//! - **Type 3 has no MAC key** (a stranger cannot know one); its proof of
//!   work is checked after NIP-44 and before any Diffie-Hellman.
//!
//! The ratchet's plaintext is the binary frame of `p1/frame.rs` (§21.4).
//!
//! The tests check frames and a 24-bit proof of work built independently in
//! Python (`tests/vectors/p1_wire.py`).

use crate::crypto::sha256;
use crate::ratchet::{EncryptedMessage, MessageHeader};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The inner frame version this code reads and writes.
pub const VERSION: u8 = 1;
/// Reserved for post-quantum metadata (PQ-12); refused today.
pub const VERSION_PQ_METADATA: u8 = 2;
/// X25519 + ML-KEM-768 + HKDF-SHA-256 + AES-256-GCM: the only suite.
pub const SUITE_X25519_MLKEM768: u8 = 0x01;
/// `ver`, `type`, `ts` and `len`.
pub const HEADER_LEN: usize = 1 + 1 + 8 + 4;
/// The HMAC-SHA256 tag at the end of every frame.
pub const MAC_LEN: usize = 32;
/// An ML-KEM-768 ciphertext.
pub const KEM_CT_LEN: usize = 1088;
/// `opk_id` when no one-time prekey was used.
pub const NO_OPK: u32 = u32::MAX;
/// The proof of work a request needs (decision D10).
pub const POW_BITS: u32 = 24;

const MAC_LABEL: &[u8] = b"trino/p1/v1/inner";
const POW_LABEL: &[u8] = b"trino/p1/v2/pow";
const GCM_TAG_LEN: usize = 16;
/// dh 32, pn 4, n 4, nonce 12.
const MESSAGE_FIXED: usize = 32 + 4 + 4 + 12;
/// suite 1, pq_spk_id 4, ct 1088, dev_dh 32, ek 32, spk_id 4, opk_id 4.
pub const HANDSHAKE_FIXED: usize = 1 + 4 + KEM_CT_LEN + 32 + 32 + 4 + 4;
/// pow_nonce 8, suite 1, con_kem 1, e 32, dev_dh 32.
const REQUEST_FIXED: usize = 8 + 1 + 1 + 32 + 32;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("frame length is not a P1 step")]
    NotAStep,
    #[error("unknown or reserved inner version {0}")]
    Version(u8),
    #[error("unknown inner type {0}")]
    UnknownType(u8),
    #[error("type {0} does not travel at this step")]
    WrongStep(u8),
    #[error("body does not fit the step")]
    TooLong,
    #[error("padding is not all zero")]
    Padding,
    #[error("invalid MAC")]
    Mac,
    #[error("not enough proof of work")]
    Pow,
    #[error("unknown suite {0}")]
    Suite(u8),
    #[error("malformed body")]
    Malformed,
    #[error("this call does not handle type {0}")]
    WrongType(u8),
}

/// The four P1 size steps (decision D14).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    K1,
    K4,
    K16,
    K40,
}

/// The inner frame types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InnerType {
    /// A ratchet message (session mailbox).
    Message = 1,
    /// A hybrid X3DH handshake with its first message (introduction mailbox).
    Handshake = 2,
    /// A request from a stranger (request mailbox), with proof of work.
    Request = 3,
    /// The first reply of a PQ-11 session: the KEM ciphertext (§21.6).
    KemReply = 4,
}

/// An opened inner frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inner {
    pub kind: InnerType,
    /// The sender's network time (design P1 §3.5).
    pub ts: u64,
    pub body: Vec<u8>,
}

impl Step {
    /// The frame length of this step.
    pub fn frame_len(self) -> usize {
        match self {
            Step::K1 => 1024,
            Step::K4 => 4096,
            Step::K16 => 16384,
            Step::K40 => 40960,
        }
    }

    /// How many body bytes fit.
    pub fn capacity(self) -> usize {
        self.frame_len() - HEADER_LEN - MAC_LEN
    }

    /// The step whose frame length is `n`.
    pub fn of_len(n: usize) -> Option<Step> {
        STEPS.into_iter().find(|s| s.frame_len() == n)
    }

    /// The smallest step a body of `n` bytes fits in.
    pub fn smallest_for(n: usize) -> Option<Step> {
        STEPS.into_iter().find(|s| s.capacity() >= n)
    }
}

const STEPS: [Step; 4] = [Step::K1, Step::K4, Step::K16, Step::K40];

impl InnerType {
    fn from_byte(b: u8) -> Result<Self, WireError> {
        match b {
            1 => Ok(InnerType::Message),
            2 => Ok(InnerType::Handshake),
            3 => Ok(InnerType::Request),
            4 => Ok(InnerType::KemReply),
            other => Err(WireError::UnknownType(other)),
        }
    }

    /// Whether this type travels at `step` (R-22).
    pub fn allows(self, step: Step) -> bool {
        match self {
            InnerType::Message => true,
            InnerType::Handshake | InnerType::KemReply => step == Step::K4,
            InnerType::Request => step == Step::K16,
        }
    }
}

fn build(kind: InnerType, ts: u64, body: &[u8], step: Step) -> Result<Vec<u8>, WireError> {
    if !kind.allows(step) {
        return Err(WireError::WrongStep(kind as u8));
    }
    if body.len() > step.capacity() {
        return Err(WireError::TooLong);
    }
    let mut f = Vec::with_capacity(step.frame_len());
    f.push(VERSION);
    f.push(kind as u8);
    f.extend_from_slice(&ts.to_be_bytes());
    f.extend_from_slice(&(body.len() as u32).to_be_bytes());
    f.extend_from_slice(body);
    f.resize(step.frame_len(), 0);
    Ok(f)
}

/// Seals a type 1, 2 or 4 frame with its MAC.
pub fn seal_inner(
    kind: InnerType,
    ts: u64,
    body: &[u8],
    step: Step,
    k_mac: &[u8; 32],
) -> Result<Vec<u8>, WireError> {
    if kind == InnerType::Request {
        return Err(WireError::WrongType(kind as u8));
    }
    let mut f = build(kind, ts, body, step)?;
    let n = f.len();
    let mac = inner_mac(k_mac, &f[..n - MAC_LEN]);
    f[n - MAC_LEN..].copy_from_slice(&mac);
    Ok(f)
}

/// Checks the length, then the MAC, then everything else. `None` as the MAC
/// key means a type 3, whose MAC must be 32 zero bytes.
fn open(frame: &[u8], k_mac: Option<&[u8; 32]>) -> Result<Inner, WireError> {
    let step = Step::of_len(frame.len()).ok_or(WireError::NotAStep)?;
    let (data, tag) = frame.split_at(frame.len() - MAC_LEN);
    let want = match k_mac {
        Some(k) => inner_mac(k, data),
        None => [0u8; MAC_LEN],
    };
    // Nothing below reads bytes the MAC did not cover.
    if !ct_eq(&want, tag) {
        return Err(WireError::Mac);
    }
    if data[0] != VERSION {
        return Err(WireError::Version(data[0]));
    }
    let kind = InnerType::from_byte(data[1])?;
    if !kind.allows(step) {
        return Err(WireError::WrongStep(kind as u8));
    }
    let ts = u64::from_be_bytes(data[2..10].try_into().expect("8 bytes"));
    let len = u32::from_be_bytes(data[10..14].try_into().expect("4 bytes")) as usize;
    if len > step.capacity() {
        return Err(WireError::TooLong);
    }
    let (body, pad) = data[HEADER_LEN..].split_at(len);
    if pad.iter().any(|&b| b != 0) {
        return Err(WireError::Padding);
    }
    Ok(Inner {
        kind,
        ts,
        body: body.to_vec(),
    })
}

/// Checks and opens a type 1, 2 or 4 frame. The caller then checks that the
/// type is the one its mailbox class carries (P1 §6.2, step 7).
pub fn open_inner(frame: &[u8], k_mac: &[u8; 32]) -> Result<Inner, WireError> {
    // A type 3 carries a MAC of zeros, so it would fail on the MAC; name it.
    if frame.get(1) == Some(&(InnerType::Request as u8)) {
        return Err(WireError::WrongType(InnerType::Request as u8));
    }
    open(frame, Some(k_mac))
}

/// Seals a type 3 frame (16 KiB, MAC of zeros). `body` already carries its
/// proof of work (see [`solve_pow`]).
pub fn seal_request(ts: u64, body: &[u8]) -> Result<Vec<u8>, WireError> {
    build(InnerType::Request, ts, body, Step::K16)
}

/// Checks and opens a type 3 frame sent to request mailbox `r`, with at
/// least `bits` of proof of work.
pub fn open_request(frame: &[u8], r: &[u8; 32], bits: u32) -> Result<Inner, WireError> {
    match frame.get(1) {
        Some(&t) if t != InnerType::Request as u8 => return Err(WireError::WrongType(t)),
        _ => {}
    }
    let inner = open(frame, None)?;
    if leading_zero_bits(&pow_hash(r, &inner.body)?) < bits {
        return Err(WireError::Pow);
    }
    Ok(inner)
}

fn pow_prefix(r: &[u8; 32], rest: &[u8]) -> Sha256 {
    let mut h = Sha256::new();
    h.update(POW_LABEL);
    h.update(r);
    h.update(sha256(rest));
    h
}

/// The proof-of-work hash of a full type 3 body (`pow_nonce` first).
pub fn pow_hash(r: &[u8; 32], body: &[u8]) -> Result<[u8; 32], WireError> {
    if body.len() < 8 {
        return Err(WireError::Malformed);
    }
    let (nonce, rest) = body.split_at(8);
    let mut h = pow_prefix(r, rest);
    h.update(nonce);
    Ok(h.finalize().into())
}

/// Finds a `pow_nonce` that gives `bits` leading zero bits for the type 3
/// body that follows it (`rest`), counting up from `start`. With 24 bits it
/// takes about 2^24 hashes of 87 bytes.
pub fn solve_pow(r: &[u8; 32], rest: &[u8], bits: u32, start: u64) -> u64 {
    let prefix = pow_prefix(r, rest);
    (start..=u64::MAX)
        .find(|nonce| {
            let mut h = prefix.clone();
            h.update(nonce.to_be_bytes());
            leading_zero_bits(&h.finalize().into()) >= bits
        })
        .expect("2^64 nonces always hold a solution for any useful number of bits")
}

/// The leading zero bits of a hash.
pub fn leading_zero_bits(h: &[u8; 32]) -> u32 {
    let mut n = 0;
    for &b in h {
        n += b.leading_zeros();
        if b != 0 {
            break;
        }
    }
    n
}

/// A type 1 body: one Double Ratchet message in bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageBody {
    pub dh: [u8; 32],
    pub pn: u32,
    pub n: u32,
    pub nonce: [u8; 12],
    /// AES-256-GCM ciphertext with its 16-byte tag.
    pub ciphertext: Vec<u8>,
}

/// A type 2 body: the hybrid handshake and its first message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeBody {
    pub suite: u8,
    pub pq_spk_id: u32,
    pub ct: Box<[u8; KEM_CT_LEN]>,
    pub dev_dh: [u8; 32],
    pub ek: [u8; 32],
    pub spk_id: u32,
    pub opk_id: Option<u32>,
    pub message: MessageBody,
}

/// A type 4 body: the KEM ciphertext of a PQ-11 session and the first reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KemReplyBody {
    pub ct: Box<[u8; KEM_CT_LEN]>,
    pub message: MessageBody,
}

/// A type 3 body: a request (§21.8). `sealed` is the AEAD part, opened by
/// the request layer once the proof of work and the X25519 checks pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestBody {
    pub pow_nonce: u64,
    pub suite: u8,
    pub e: [u8; 32],
    pub dev_dh: [u8; 32],
    pub ct_r: Option<Box<[u8; KEM_CT_LEN]>>,
    pub sealed: Vec<u8>,
}

/// A cursor that refuses to read past the end.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.0.len() < n {
            return Err(WireError::Malformed);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }

    fn arr<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        Ok(self.take(N)?.try_into().expect("length taken"))
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.arr()?))
    }

    fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.arr()?))
    }

    fn kem_ct(&mut self) -> Result<Box<[u8; KEM_CT_LEN]>, WireError> {
        Ok(Box::new(self.arr()?))
    }

    fn rest(self) -> &'a [u8] {
        self.0
    }
}

fn check_suite(b: u8) -> Result<u8, WireError> {
    if b == SUITE_X25519_MLKEM768 {
        Ok(b)
    } else {
        Err(WireError::Suite(b))
    }
}

impl MessageBody {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MESSAGE_FIXED + self.ciphertext.len());
        out.extend_from_slice(&self.dh);
        out.extend_from_slice(&self.pn.to_be_bytes());
        out.extend_from_slice(&self.n.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader(b);
        let m = MessageBody {
            dh: r.arr()?,
            pn: r.u32()?,
            n: r.u32()?,
            nonce: r.arr()?,
            ciphertext: r.rest().to_vec(),
        };
        if m.ciphertext.len() < GCM_TAG_LEN {
            return Err(WireError::Malformed);
        }
        Ok(m)
    }

    /// From the ratchet's message (hex fields today).
    pub fn from_ratchet(m: &EncryptedMessage) -> Result<Self, WireError> {
        let bad = |_| WireError::Malformed;
        let dh = hex::decode(&m.header.dh_pub).map_err(bad)?;
        let nonce = hex::decode(&m.nonce).map_err(bad)?;
        let ciphertext = hex::decode(&m.ciphertext).map_err(bad)?;
        if ciphertext.len() < GCM_TAG_LEN {
            return Err(WireError::Malformed);
        }
        Ok(MessageBody {
            dh: dh.try_into().map_err(|_| WireError::Malformed)?,
            pn: m.header.pn,
            n: m.header.n,
            nonce: nonce.try_into().map_err(|_| WireError::Malformed)?,
            ciphertext,
        })
    }

    /// Back to the ratchet's message.
    pub fn to_ratchet(&self) -> EncryptedMessage {
        EncryptedMessage {
            header: MessageHeader {
                dh_pub: hex::encode(self.dh),
                pn: self.pn,
                n: self.n,
            },
            nonce: hex::encode(self.nonce),
            ciphertext: hex::encode(&self.ciphertext),
        }
    }
}

impl HandshakeBody {
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(HANDSHAKE_FIXED + MESSAGE_FIXED + self.message.ciphertext.len());
        out.push(self.suite);
        out.extend_from_slice(&self.pq_spk_id.to_be_bytes());
        out.extend_from_slice(&self.ct[..]);
        out.extend_from_slice(&self.dev_dh);
        out.extend_from_slice(&self.ek);
        out.extend_from_slice(&self.spk_id.to_be_bytes());
        out.extend_from_slice(&self.opk_id.unwrap_or(NO_OPK).to_be_bytes());
        out.extend_from_slice(&self.message.encode());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader(b);
        let suite = check_suite(r.u8()?)?;
        let pq_spk_id = r.u32()?;
        let ct = r.kem_ct()?;
        let dev_dh = r.arr()?;
        let ek = r.arr()?;
        let spk_id = r.u32()?;
        let opk_id = Some(r.u32()?).filter(|&id| id != NO_OPK);
        Ok(HandshakeBody {
            suite,
            pq_spk_id,
            ct,
            dev_dh,
            ek,
            spk_id,
            opk_id,
            message: MessageBody::decode(r.rest())?,
        })
    }
}

impl KemReplyBody {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.ct.to_vec();
        out.extend_from_slice(&self.message.encode());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader(b);
        let ct = r.kem_ct()?;
        Ok(KemReplyBody {
            ct,
            message: MessageBody::decode(r.rest())?,
        })
    }
}

impl RequestBody {
    /// Everything after `pow_nonce`: what the proof of work covers.
    pub fn encode_rest(&self) -> Vec<u8> {
        let mut out = vec![self.suite, u8::from(self.ct_r.is_some())];
        out.extend_from_slice(&self.e);
        out.extend_from_slice(&self.dev_dh);
        if let Some(ct) = &self.ct_r {
            out.extend_from_slice(&ct[..]);
        }
        out.extend_from_slice(&self.sealed);
        out
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.pow_nonce.to_be_bytes().to_vec();
        out.extend_from_slice(&self.encode_rest());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        if b.len() < REQUEST_FIXED {
            return Err(WireError::Malformed);
        }
        let mut r = Reader(b);
        let pow_nonce = r.u64()?;
        let suite = check_suite(r.u8()?)?;
        let con_kem = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(WireError::Malformed),
        };
        let e = r.arr()?;
        let dev_dh = r.arr()?;
        let ct_r = if con_kem { Some(r.kem_ct()?) } else { None };
        Ok(RequestBody {
            pow_nonce,
            suite,
            e,
            dev_dh,
            ct_r,
            sealed: r.rest().to_vec(),
        })
    }
}

fn inner_mac(k_mac: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(k_mac).expect("HMAC takes any key length");
    mac.update(MAC_LABEL);
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Equality of two byte strings in time that depends only on their length.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../../tests/vectors/p1_wire.json");

    fn v() -> Value {
        serde_json::from_str(VECTORS).unwrap()
    }

    fn hx(s: &Value) -> Vec<u8> {
        hex::decode(s.as_str().unwrap()).unwrap()
    }

    fn h32(s: &Value) -> [u8; 32] {
        hx(s).try_into().unwrap()
    }

    fn step_of(n: u64) -> Step {
        Step::of_len(n as usize).unwrap()
    }

    fn kind_of(n: u64) -> InnerType {
        InnerType::from_byte(n as u8).unwrap()
    }

    fn sample_message(ct_len: usize) -> MessageBody {
        MessageBody {
            dh: [1; 32],
            pn: 2,
            n: 3,
            nonce: [4; 12],
            ciphertext: vec![5; ct_len],
        }
    }

    fn sample_handshake() -> HandshakeBody {
        HandshakeBody {
            suite: SUITE_X25519_MLKEM768,
            pq_spk_id: 9,
            ct: Box::new([6; KEM_CT_LEN]),
            dev_dh: [7; 32],
            ek: [8; 32],
            spk_id: 10,
            opk_id: None,
            message: sample_message(100),
        }
    }

    #[test]
    fn steps_have_their_lengths() {
        let lens: Vec<usize> = [Step::K1, Step::K4, Step::K16, Step::K40]
            .iter()
            .map(|s| s.frame_len())
            .collect();
        assert_eq!(lens, [1024, 4096, 16384, 40960]);
        assert_eq!(Step::K1.capacity(), 1024 - HEADER_LEN - MAC_LEN);
        assert_eq!(Step::of_len(4096), Some(Step::K4));
        assert_eq!(Step::of_len(4095), None);
        assert_eq!(Step::smallest_for(978), Some(Step::K1));
        assert_eq!(Step::smallest_for(979), Some(Step::K4));
        assert_eq!(
            Step::smallest_for(40960 - 46 + 1),
            None,
            "past 40 KiB is refused"
        );
    }

    #[test]
    fn frames_match_the_independent_vectors() {
        for c in v()["frames"].as_array().unwrap() {
            let name = c["name"].as_str().unwrap();
            let kind = kind_of(c["type"].as_u64().unwrap());
            let step = step_of(c["step"].as_u64().unwrap());
            let ts = c["ts"].as_u64().unwrap();
            let body = hx(&c["body"]);
            let frame = if kind == InnerType::Request {
                seal_request(ts, &body).unwrap()
            } else {
                seal_inner(kind, ts, &body, step, &h32(&c["k_mac"])).unwrap()
            };
            assert_eq!(frame.len(), step.frame_len(), "{name}");
            assert_eq!(
                hex::encode(sha256(&frame)),
                c["inner_sha256"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                hex::encode(&frame[frame.len() - 32..]),
                c["mac"].as_str().unwrap(),
                "{name}"
            );
            if kind != InnerType::Request {
                let opened = open_inner(&frame, &h32(&c["k_mac"])).unwrap();
                assert_eq!(opened, Inner { kind, ts, body }, "{name}");
            }
        }
    }

    #[test]
    fn independent_bodies_parse_and_reencode() {
        for c in v()["frames"].as_array().unwrap() {
            let body = hx(&c["body"]);
            match kind_of(c["type"].as_u64().unwrap()) {
                InnerType::Message => {
                    assert_eq!(MessageBody::decode(&body).unwrap().encode(), body)
                }
                InnerType::Handshake => {
                    let h = HandshakeBody::decode(&body).unwrap();
                    assert_eq!(h.pq_spk_id, 0x0102_0304);
                    assert_eq!((h.spk_id, h.opk_id), (42, None));
                    assert_eq!(h.encode(), body);
                }
                InnerType::KemReply => {
                    assert_eq!(KemReplyBody::decode(&body).unwrap().encode(), body)
                }
                InnerType::Request => {
                    assert_eq!(RequestBody::decode(&body).unwrap().encode(), body)
                }
            }
        }
    }

    #[test]
    fn the_independent_proofs_of_work_check() {
        for p in v()["pow"].as_array().unwrap() {
            let r = h32(&p["R"]);
            let body = hx(&p["body"]);
            assert_eq!(pow_hash(&r, &body).unwrap(), h32(&p["hash"]));
            assert_eq!(
                leading_zero_bits(&h32(&p["hash"])) as u64,
                p["zero_bits"].as_u64().unwrap()
            );
            let frame = seal_request(1_793_102_400, &body).unwrap();
            let opened = open_request(&frame, &r, POW_BITS).unwrap();
            assert_eq!(opened.kind, InnerType::Request);
            assert_eq!(opened.body, body);
            // One bit more than it has is refused; another R is refused.
            let bits = p["zero_bits"].as_u64().unwrap() as u32;
            assert_eq!(
                open_request(&frame, &r, bits + 1).unwrap_err(),
                WireError::Pow
            );
            assert_eq!(
                open_request(&frame, &[0x55; 32], POW_BITS).unwrap_err(),
                WireError::Pow
            );
            // The solver finds the same nonce when started just before it.
            let req = RequestBody::decode(&body).unwrap();
            let nonce = p["nonce"].as_u64().unwrap();
            assert_eq!(
                solve_pow(&r, &req.encode_rest(), POW_BITS, nonce.saturating_sub(3)),
                nonce
            );
        }
    }

    #[test]
    fn a_solved_request_round_trips() {
        let r = [0x11; 32];
        let mut req = RequestBody {
            pow_nonce: 0,
            suite: SUITE_X25519_MLKEM768,
            e: [1; 32],
            dev_dh: [2; 32],
            ct_r: Some(Box::new([3; KEM_CT_LEN])),
            sealed: vec![4; 900],
        };
        req.pow_nonce = solve_pow(&r, &req.encode_rest(), 12, 0);
        let frame = seal_request(5, &req.encode()).unwrap();
        assert_eq!(frame.len(), 16384);
        let opened = open_request(&frame, &r, 12).unwrap();
        assert_eq!(RequestBody::decode(&opened.body).unwrap(), req);
    }

    #[test]
    fn handshake_and_kem_reply_round_trip() {
        let h = sample_handshake();
        let enc = h.encode();
        assert_eq!(enc.len(), HANDSHAKE_FIXED + MESSAGE_FIXED + 100);
        assert_eq!(
            HANDSHAKE_FIXED, 1165,
            "§21.4: the fixed part of type 2 is 1.165 bytes"
        );
        assert_eq!(HandshakeBody::decode(&enc).unwrap(), h);
        let with_opk = HandshakeBody {
            opk_id: Some(77),
            ..sample_handshake()
        };
        assert_eq!(HandshakeBody::decode(&with_opk.encode()).unwrap(), with_opk);
        let k = KemReplyBody {
            ct: Box::new([9; KEM_CT_LEN]),
            message: sample_message(40),
        };
        assert_eq!(KemReplyBody::decode(&k.encode()).unwrap(), k);
    }

    #[test]
    fn a_classical_or_unknown_suite_is_refused() {
        for suite in [0x00, 0x02, 0xFF] {
            let mut h = sample_handshake().encode();
            h[0] = suite;
            assert_eq!(
                HandshakeBody::decode(&h).unwrap_err(),
                WireError::Suite(suite)
            );
        }
        let mut req = RequestBody {
            pow_nonce: 0,
            suite: 0,
            e: [1; 32],
            dev_dh: [2; 32],
            ct_r: None,
            sealed: vec![4; 10],
        }
        .encode();
        assert_eq!(RequestBody::decode(&req).unwrap_err(), WireError::Suite(0));
        req[9] = 2; // con_kem must be 0 or 1
        req[8] = SUITE_X25519_MLKEM768;
        assert_eq!(RequestBody::decode(&req).unwrap_err(), WireError::Malformed);
    }

    #[test]
    fn truncated_bodies_are_malformed() {
        let enc = sample_handshake().encode();
        for n in [
            0,
            1,
            HANDSHAKE_FIXED,
            HANDSHAKE_FIXED + MESSAGE_FIXED + GCM_TAG_LEN - 1,
        ] {
            assert_eq!(
                HandshakeBody::decode(&enc[..n]).unwrap_err(),
                WireError::Malformed,
                "{n}"
            );
        }
        let m = sample_message(GCM_TAG_LEN).encode();
        assert!(MessageBody::decode(&m).is_ok());
        assert_eq!(
            MessageBody::decode(&m[..m.len() - 1]).unwrap_err(),
            WireError::Malformed
        );
    }

    #[test]
    fn steps_are_fixed_per_type() {
        let k = [1u8; 32];
        let body = sample_handshake().encode();
        assert_eq!(
            seal_inner(InnerType::Handshake, 1, &body, Step::K16, &k).unwrap_err(),
            WireError::WrongStep(2)
        );
        assert_eq!(
            seal_inner(InnerType::Request, 1, &body, Step::K16, &k).unwrap_err(),
            WireError::WrongType(3)
        );
        for step in [Step::K1, Step::K4, Step::K16, Step::K40] {
            assert!(seal_inner(InnerType::Message, 1, &[0; 70], step, &k).is_ok());
        }
        // A frame claiming type 2 at 1 KiB is refused even with a valid MAC.
        let mut frame = seal_inner(InnerType::Message, 1, &[0; 70], Step::K1, &k).unwrap();
        frame[1] = 2;
        let mac = inner_mac(&k, &frame[..1024 - 32]);
        frame[1024 - 32..].copy_from_slice(&mac);
        assert_eq!(open_inner(&frame, &k).unwrap_err(), WireError::WrongStep(2));
    }

    #[test]
    fn a_body_too_long_for_its_step_is_refused() {
        let k = [1u8; 32];
        assert!(seal_inner(InnerType::Message, 1, &vec![0; 978], Step::K1, &k).is_ok());
        assert_eq!(
            seal_inner(InnerType::Message, 1, &vec![0; 979], Step::K1, &k).unwrap_err(),
            WireError::TooLong
        );
    }

    #[test]
    fn every_flipped_bit_is_refused() {
        let k = [2u8; 32];
        let frame = seal_inner(
            InnerType::Message,
            77,
            &sample_message(64).encode(),
            Step::K1,
            &k,
        )
        .unwrap();
        for i in 0..frame.len() * 8 {
            let mut bad = frame.clone();
            bad[i / 8] ^= 1 << (i % 8);
            assert!(open_inner(&bad, &k).is_err(), "bit {i}");
        }
        assert_eq!(open_inner(&frame, &[3u8; 32]).unwrap_err(), WireError::Mac);
    }

    #[test]
    fn version_type_length_and_padding_are_checked_under_a_valid_mac() {
        let k = [2u8; 32];
        let base = seal_inner(InnerType::Message, 1, &[9; 70], Step::K1, &k).unwrap();
        let remac = |mut f: Vec<u8>| {
            let n = f.len();
            let mac = inner_mac(&k, &f[..n - 32]);
            f[n - 32..].copy_from_slice(&mac);
            f
        };
        let mut f = base.clone();
        f[0] = VERSION_PQ_METADATA;
        assert_eq!(
            open_inner(&remac(f), &k).unwrap_err(),
            WireError::Version(2)
        );
        let mut f = base.clone();
        f[1] = 9;
        assert_eq!(
            open_inner(&remac(f), &k).unwrap_err(),
            WireError::UnknownType(9)
        );
        let mut f = base.clone();
        f[10..14].copy_from_slice(&979u32.to_be_bytes());
        assert_eq!(open_inner(&remac(f), &k).unwrap_err(), WireError::TooLong);
        let mut f = base.clone();
        f[HEADER_LEN + 70] = 1;
        assert_eq!(open_inner(&remac(f), &k).unwrap_err(), WireError::Padding);
        assert_eq!(
            open_inner(&base[..1000], &k).unwrap_err(),
            WireError::NotAStep
        );
        // open_inner never takes a type 3, open_request never a type 1.
        let req = seal_request(1, &[0; 200]).unwrap();
        assert_eq!(open_inner(&req, &k).unwrap_err(), WireError::WrongType(3));
        assert_eq!(
            open_request(&base, &[0; 32], 0).unwrap_err(),
            WireError::WrongType(1)
        );
    }

    #[test]
    fn ratchet_messages_convert_both_ways() {
        let m = sample_message(33);
        let r = m.to_ratchet();
        assert_eq!(r.header.dh_pub, hex::encode([1u8; 32]));
        assert_eq!(MessageBody::from_ratchet(&r).unwrap(), m);
        let mut bad = r.clone();
        bad.nonce = "00".into();
        assert_eq!(
            MessageBody::from_ratchet(&bad).unwrap_err(),
            WireError::Malformed
        );
    }

    #[test]
    fn a_real_ratchet_message_travels_in_a_type_1() {
        use crate::identity::{create_identity, decode_array_32, public_bundle_for};
        use crate::ratchet::{init_initiator, init_responder, ratchet_decrypt, ratchet_encrypt};
        use crate::x3dh::{initiate, respond};
        let alice = create_identity();
        let mut bob = create_identity();
        let bundle = public_bundle_for(&bob);
        let init = initiate(&alice, &bundle).unwrap();
        let resp = respond(&mut bob, &init.message).unwrap();
        let mut a = init_initiator(
            init.master_secret,
            decode_array_32(&bundle.spk_pub).unwrap(),
        )
        .unwrap();
        let mut b = init_responder(resp.master_secret, resp.spk_keypair.clone());
        let sent = ratchet_encrypt(&mut a, b"hola", &init.associated_data).unwrap();
        let k = [7u8; 32];
        let body = MessageBody::from_ratchet(&sent).unwrap().encode();
        let frame = seal_inner(InnerType::Message, 1, &body, Step::K1, &k).unwrap();
        let got = MessageBody::decode(&open_inner(&frame, &k).unwrap().body).unwrap();
        let plain = ratchet_decrypt(&mut b, &got.to_ratchet(), &resp.associated_data).unwrap();
        assert_eq!(plain, b"hola");
    }

    #[test]
    fn leading_zero_bits_counts_bits() {
        let mut h = [0u8; 32];
        assert_eq!(leading_zero_bits(&h), 256);
        h[0] = 0x80;
        assert_eq!(leading_zero_bits(&h), 0);
        h[0] = 0;
        h[2] = 0x10;
        assert_eq!(leading_zero_bits(&h), 19);
    }
}
