//! Mailbox derivations (design P1 §3.2-§3.5, with the device keys of
//! `diseno-vinculacion.md` §4.1).
//!
//! ```text
//! dh        = X25519(dev_dh_mine, dev_dh_theirs)        refused if not contributory (R-24)
//! S_intro   = HKDF(ikm = dh, salt = "trino/p1/v1/intro" ‖ lo ‖ hi, info = "seed")
//! S_ses     = HKDF(ikm = master_secret, salt = "trino/p1/v1/session", info = AD)
//! s_e       = HKDF(ikm = S, info = "epoch" ‖ e u32 BE)      (S = S_intro or S_ses)
//! s_e+1     = HKDF(ikm = s_e, info = "next")                  (session chain only)
//! sk_mbox   = HKDF(ikm = s, info = "mbox" ‖ d ‖ gen ‖ ctr)   as a scalar; ctr + 1 if 0 or ≥ n
//! mailbox   = x-only(sk_mbox · G)                            → the event's `p` tag
//! k_mac     = HKDF(ikm = s, info = "mac" ‖ d ‖ gen)
//! k_dedup   = HKDF(ikm = s, info = "dedup")
//! ```
//!
//! Every HKDF is HKDF-SHA256 with 32 bytes out; where no salt is written it
//! is empty, which RFC 5869 defines as 32 zero bytes.
//!
//! - `lo` and `hi` are the two X25519 device keys sorted as bytes. Direction
//!   `d = 0` goes from `lo` to `hi`, `d = 1` the other way. Initiator and
//!   responder roles are never used: crossed handshakes and resyncs swap them.
//! - The **introduction** mailbox needs no state and only carries
//!   handshakes. It has no forward secrecy by design (§3.2).
//! - The **session** mailbox comes from the X3DH secret and moves one way
//!   only: [`next_epoch`] exists, a function back does not (O4). The app
//!   keeps today's and yesterday's `s_e` and wipes the rest.
//! - Epochs are 24 h of network time, aligned on UTC (§3.5).
//!
//! The tests check vectors computed independently with OpenSSL
//! (`tests/vectors/p1_mailbox.py`).

use crate::crypto::hkdf_expand;
use secp256k1::{SecretKey, SECP256K1};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Length of an epoch: 24 hours.
pub const EPOCH_SECS: u64 = 86_400;
/// How many epochs [`advance`] walks at most. A handshake or invitation
/// processed late advances the session chain from its `e0`; a gap larger
/// than this is not a real late message.
pub const MAX_ADVANCE: u32 = 1_000;

const INTRO_SALT: &[u8] = b"trino/p1/v1/intro";
const SESSION_SALT: &[u8] = b"trino/p1/v1/session";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MailboxError {
    #[error("the X25519 exchange is not contributory (low-order key)")]
    NonContributory,
    #[error("both sides have the same device key")]
    SameKey,
    #[error("cannot move a session chain back or that far forward")]
    BadAdvance,
}

/// Which way a mailbox carries messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// From the lower device key (as bytes) to the higher one.
    LoToHi = 0,
    /// From the higher device key to the lower one.
    HiToLo = 1,
}

/// One mailbox: what a relay sees (`tag`) and the keys of its two ends.
pub struct Mailbox {
    /// The secp256k1 secret both ends know; it opens the NIP-44 layer.
    pub sk: Zeroizing<[u8; 32]>,
    /// `x-only(sk · G)`: the event's `p` tag and the subscription value.
    pub tag: [u8; 32],
    /// The key of the inner frame's MAC (design P1 §2.2).
    pub k_mac: Zeroizing<[u8; 32]>,
}

/// A session's mailbox chain as it is kept: today's `s_e` and yesterday's,
/// never older ones and never `S_ses` (§3.3, O4).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct SessionChain {
    /// The epoch of `current`.
    pub epoch: u32,
    current: [u8; 32],
    previous: Option<[u8; 32]>,
}

impl std::fmt::Debug for SessionChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionChain {{ epoch: {} }}", self.epoch)
    }
}

impl SessionChain {
    /// Starts from `S_ses`: `s_e0`, walked forward to `today` when the
    /// handshake is processed late. A `today` before `e0` (a sender whose
    /// clock is ahead) starts at `e0`.
    pub fn start(s_ses: &[u8; 32], e0: u32, today: u32) -> Result<Self, MailboxError> {
        let mut chain = SessionChain {
            epoch: e0,
            current: *epoch_secret(s_ses, e0),
            previous: None,
        };
        chain.advance_to(today.max(e0))?;
        Ok(chain)
    }

    /// Moves to epoch `e`, keeping the one before it. Never goes back.
    pub fn advance_to(&mut self, e: u32) -> Result<(), MailboxError> {
        if e == self.epoch {
            return Ok(());
        }
        // Checks the direction and the distance before touching anything.
        let yesterday = advance(&self.current, self.epoch, e - 1)?;
        let today = next_epoch(&yesterday);
        self.previous = Some(*yesterday);
        self.current = *today;
        self.epoch = e;
        Ok(())
    }

    /// `s_e` for today's epoch or the one before; `None` for any other.
    pub fn secret(&self, e: u32) -> Option<&[u8; 32]> {
        if e == self.epoch {
            Some(&self.current)
        } else if Some(e) == self.epoch.checked_sub(1) {
            self.previous.as_ref()
        } else {
            None
        }
    }
}

/// The epoch of a network time `ts` (seconds since the Unix epoch).
pub fn epoch_of(ts: u64) -> u32 {
    // u32 epochs last until the year 11 million; saturate rather than wrap.
    u32::try_from(ts / EPOCH_SECS).unwrap_or(u32::MAX)
}

/// The direction of a message sent by device key `from` to `to`.
pub fn direction(from: &[u8; 32], to: &[u8; 32]) -> Result<Direction, MailboxError> {
    match from.cmp(to) {
        std::cmp::Ordering::Less => Ok(Direction::LoToHi),
        std::cmp::Ordering::Greater => Ok(Direction::HiToLo),
        std::cmp::Ordering::Equal => Err(MailboxError::SameKey),
    }
}

/// `S_intro` between this device (`my_priv`, `my_pub`) and `their_pub`.
pub fn intro_seed(
    my_priv: &[u8; 32],
    my_pub: &[u8; 32],
    their_pub: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, MailboxError> {
    let (lo, hi) = match direction(my_pub, their_pub)? {
        Direction::LoToHi => (my_pub, their_pub),
        Direction::HiToLo => (their_pub, my_pub),
    };
    let dh = x25519(my_priv, their_pub)?;
    let mut salt = Vec::with_capacity(INTRO_SALT.len() + 64);
    salt.extend_from_slice(INTRO_SALT);
    salt.extend_from_slice(lo);
    salt.extend_from_slice(hi);
    Ok(hkdf32(&dh[..], &salt, b"seed"))
}

/// `S_ses` from the X3DH master secret and its associated data.
pub fn session_seed(master_secret: &[u8; 32], ad: &[u8]) -> Zeroizing<[u8; 32]> {
    hkdf32(master_secret, SESSION_SALT, ad)
}

/// `s_e` of a seed (introduction or session) for epoch `e`.
pub fn epoch_secret(seed: &[u8; 32], e: u32) -> Zeroizing<[u8; 32]> {
    // "epoch" || e as u32 BE.
    let mut info = [0u8; 9];
    info[..5].copy_from_slice(b"epoch");
    info[5..].copy_from_slice(&e.to_be_bytes());
    hkdf32(seed, &[], &info)
}

/// The next link of a session chain. One way only.
pub fn next_epoch(s_e: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf32(s_e, &[], b"next")
}

/// Walks a session chain from epoch `from` to epoch `to` (`to ≥ from`).
pub fn advance(s_e: &[u8; 32], from: u32, to: u32) -> Result<Zeroizing<[u8; 32]>, MailboxError> {
    if to < from || to - from > MAX_ADVANCE {
        return Err(MailboxError::BadAdvance);
    }
    let mut s = Zeroizing::new(*s_e);
    for _ in from..to {
        s = next_epoch(&s);
    }
    Ok(s)
}

/// The mailbox of epoch secret `s` for direction `d` and generation `gen`
/// (always 0 for now; R-17 keeps the field for a later move).
pub fn mailbox(s: &[u8; 32], d: Direction, gen: u8) -> Mailbox {
    let d = d as u8;
    // A 32-byte HKDF output is 0 or ≥ n with probability about 2^-128, so
    // the second try already never happens in practice.
    let (sk, secret) = (0..=u8::MAX)
        .find_map(|ctr| {
            let k = hkdf32(s, &[], &[b'm', b'b', b'o', b'x', d, gen, ctr]);
            scalar_ok(&k).map(|secret| (k, secret))
        })
        .expect("256 HKDF outputs are never all outside the secp256k1 scalar range");
    Mailbox {
        tag: xonly(&secret),
        sk,
        k_mac: hkdf32(s, &[], &[b'm', b'a', b'c', d, gen]),
    }
}

/// The key that turns an event id into a duplicate marker for epoch secret
/// `s` (R-08): the app keeps `HMAC(k_dedup, id)`, never the id.
pub fn dedup_key(s: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf32(s, &[], b"dedup")
}

fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let okm = hkdf_expand(ikm, salt, info, 32).expect("32 bytes is a valid HKDF-SHA256 length");
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&okm);
    out
}

fn x25519(my_priv: &[u8; 32], their_pub: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, MailboxError> {
    let shared = StaticSecret::from(*my_priv).diffie_hellman(&XPublicKey::from(*their_pub));
    if !shared.was_contributory() {
        return Err(MailboxError::NonContributory);
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

fn scalar_ok(k: &[u8; 32]) -> Option<SecretKey> {
    SecretKey::from_slice(k).ok()
}

fn xonly(sk: &SecretKey) -> [u8; 32] {
    sk.x_only_public_key(SECP256K1).0.serialize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../../tests/vectors/p1_mailbox.json");

    fn v() -> Value {
        serde_json::from_str(VECTORS).unwrap()
    }

    fn h32(s: &Value) -> [u8; 32] {
        hex::decode(s.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn dir(d: &Value) -> Direction {
        match d.as_u64().unwrap() {
            0 => Direction::LoToHi,
            _ => Direction::HiToLo,
        }
    }

    #[test]
    fn intro_seed_and_epoch_secret_match_the_vectors_from_both_sides() {
        for c in v()["intro"].as_array().unwrap() {
            let (pa, a, pb, b) = (
                h32(&c["priv_a"]),
                h32(&c["pub_a"]),
                h32(&c["priv_b"]),
                h32(&c["pub_b"]),
            );
            let from_a = intro_seed(&pa, &a, &b).unwrap();
            let from_b = intro_seed(&pb, &b, &a).unwrap();
            assert_eq!(*from_a, h32(&c["intro_seed"]));
            assert_eq!(*from_b, *from_a);
            let e = c["epoch"].as_u64().unwrap() as u32;
            let s_e = epoch_secret(&from_a, e);
            assert_eq!(*s_e, h32(&c["epoch_secret"]));
            assert_eq!(*dedup_key(&s_e), h32(&c["k_dedup"]));
        }
    }

    #[test]
    fn session_seed_and_chain_match_the_vectors() {
        for c in v()["session"].as_array().unwrap() {
            let ad = hex::decode(c["ad"].as_str().unwrap()).unwrap();
            let seed = session_seed(&h32(&c["master_secret"]), &ad);
            assert_eq!(*seed, h32(&c["session_seed"]));
            let e0 = c["e0"].as_u64().unwrap() as u32;
            let chain: Vec<[u8; 32]> = c["chain"].as_array().unwrap().iter().map(h32).collect();
            let mut s = epoch_secret(&seed, e0);
            assert_eq!(*s, chain[0]);
            for want in &chain[1..] {
                s = next_epoch(&s);
                assert_eq!(*s, *want);
            }
            assert_eq!(*advance(&chain[0], e0, e0 + 3).unwrap(), chain[3]);
            assert_eq!(*advance(&chain[0], e0, e0).unwrap(), chain[0]);
        }
    }

    #[test]
    fn mailboxes_match_the_vectors() {
        for c in v()["mailboxes"].as_array().unwrap() {
            let m = mailbox(
                &h32(&c["s"]),
                dir(&c["d"]),
                c["gen"].as_u64().unwrap() as u8,
            );
            assert_eq!(*m.sk, h32(&c["sk"]));
            assert_eq!(m.tag, h32(&c["mailbox"]));
            assert_eq!(*m.k_mac, h32(&c["k_mac"]));
        }
    }

    #[test]
    fn low_order_keys_are_refused() {
        let me = &v()["intro"][0];
        let (pa, a) = (h32(&me["priv_a"]), h32(&me["pub_a"]));
        for u in v()["low_order"].as_array().unwrap() {
            assert_eq!(
                intro_seed(&pa, &a, &h32(u)).unwrap_err(),
                MailboxError::NonContributory,
                "{u}"
            );
        }
    }

    #[test]
    fn the_same_key_on_both_sides_is_refused() {
        let me = &v()["intro"][0];
        let (pa, a) = (h32(&me["priv_a"]), h32(&me["pub_a"]));
        assert_eq!(intro_seed(&pa, &a, &a).unwrap_err(), MailboxError::SameKey);
        assert_eq!(direction(&a, &a).unwrap_err(), MailboxError::SameKey);
    }

    #[test]
    fn what_one_side_sends_on_is_what_the_other_listens_to() {
        // Symmetry (test 3): A's outgoing mailbox is B's incoming one, both
        // ways, whoever computes it.
        let c = &v()["intro"][1];
        let (pa, a, pb, b) = (
            h32(&c["priv_a"]),
            h32(&c["pub_a"]),
            h32(&c["priv_b"]),
            h32(&c["pub_b"]),
        );
        let s_a = epoch_secret(&intro_seed(&pa, &a, &b).unwrap(), 7);
        let s_b = epoch_secret(&intro_seed(&pb, &b, &a).unwrap(), 7);
        let a_to_b = direction(&a, &b).unwrap();
        let b_to_a = direction(&b, &a).unwrap();
        assert_ne!(a_to_b, b_to_a);
        assert_eq!(mailbox(&s_a, a_to_b, 0).tag, mailbox(&s_b, a_to_b, 0).tag);
        assert_eq!(mailbox(&s_a, b_to_a, 0).tag, mailbox(&s_b, b_to_a, 0).tag);
        assert_ne!(mailbox(&s_a, a_to_b, 0).tag, mailbox(&s_a, b_to_a, 0).tag);
        assert_ne!(
            *mailbox(&s_a, a_to_b, 0).k_mac,
            *mailbox(&s_a, b_to_a, 0).k_mac
        );
    }

    #[test]
    fn epochs_and_generations_give_unrelated_mailboxes() {
        let seed = [3u8; 32];
        let tags: Vec<[u8; 32]> = [(1, 0), (2, 0), (1, 1)]
            .iter()
            .map(|&(e, gen)| mailbox(&epoch_secret(&seed, e), Direction::LoToHi, gen).tag)
            .collect();
        assert_ne!(tags[0], tags[1]);
        assert_ne!(tags[0], tags[2]);
    }

    #[test]
    fn a_chain_never_goes_back() {
        assert_eq!(
            advance(&[1u8; 32], 10, 9).unwrap_err(),
            MailboxError::BadAdvance
        );
        assert_eq!(
            advance(&[1u8; 32], 0, MAX_ADVANCE + 1).unwrap_err(),
            MailboxError::BadAdvance
        );
        assert!(advance(&[1u8; 32], 0, MAX_ADVANCE).is_ok());
    }

    #[test]
    fn a_session_chain_keeps_today_and_yesterday_only() {
        for c in v()["session"].as_array().unwrap() {
            let seed = h32(&c["session_seed"]);
            let chain: Vec<[u8; 32]> = c["chain"].as_array().unwrap().iter().map(h32).collect();
            let e0 = c["e0"].as_u64().unwrap() as u32;
            let mut s = SessionChain::start(&seed, e0, e0).unwrap();
            assert_eq!((s.epoch, s.secret(e0)), (e0, Some(&chain[0])));
            assert_eq!(s.secret(e0 - 1), None);
            s.advance_to(e0 + 1).unwrap();
            assert_eq!(s.secret(e0 + 1), Some(&chain[1]));
            assert_eq!(s.secret(e0), Some(&chain[0]));
            // Two days at once: yesterday is e0 + 2, not e0 + 1.
            s.advance_to(e0 + 3).unwrap();
            assert_eq!(s.secret(e0 + 3), Some(&chain[3]));
            assert_eq!(s.secret(e0 + 2), Some(&chain[2]));
            assert_eq!(s.secret(e0 + 1), None);
            assert_eq!(s.advance_to(e0 + 2).unwrap_err(), MailboxError::BadAdvance);
            s.advance_to(e0 + 3).unwrap();
            assert_eq!(s.epoch, e0 + 3);
            // Processed three days late: the same place.
            let late = SessionChain::start(&seed, e0, e0 + 3).unwrap();
            assert_eq!(late, s);
            // A sender whose clock is ahead: start at e0.
            let early = SessionChain::start(&seed, e0, e0 - 1).unwrap();
            assert_eq!(early.epoch, e0);
        }
    }

    #[test]
    fn epochs_are_utc_days() {
        assert_eq!(epoch_of(0), 0);
        assert_eq!(epoch_of(86_399), 0);
        assert_eq!(epoch_of(86_400), 1);
        // 27 Oct 2026 12:00 UTC.
        assert_eq!(epoch_of(1_793_102_400), 20_753);
    }

    #[test]
    fn direction_follows_the_byte_order() {
        let lo = [1u8; 32];
        let mut hi = [1u8; 32];
        hi[31] = 2;
        assert_eq!(direction(&lo, &hi).unwrap(), Direction::LoToHi);
        assert_eq!(direction(&hi, &lo).unwrap(), Direction::HiToLo);
    }

    #[test]
    fn the_mailbox_tag_is_the_x_only_key_of_its_secret() {
        let m = mailbox(&[5u8; 32], Direction::HiToLo, 0);
        let sk = SecretKey::from_slice(&m.sk[..]).unwrap();
        assert_eq!(sk.x_only_public_key(SECP256K1).0.serialize(), m.tag);
    }
}
