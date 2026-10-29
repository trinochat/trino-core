//! The outer layer of P1: the Nostr event every message travels in
//! (`diseno.md` §2.1).
//!
//! ```text
//! kind       1059 (21059 for call signals)
//! pubkey     a one-time key, made for this event and wiped after signing
//! created_at 1059: now − U(0, 300 s), 21059: now (strfry drops ephemeral
//!            events older than 60 s)
//! tags       [["p", <mailbox>], ["expiration", <1059: created_at + U(6 d, 8 d),
//!                                               21059: created_at + U(1 h, 2 h)>]]
//!            no other tag (`diseno-vinculacion.md` §23.8)
//! content    NIP-44 v2 of the inner frame, from the one-time key to the mailbox
//! sig        BIP-340 by the one-time key, with auxiliary randomness
//! ```
//!
//! The id is NIP-01's: SHA-256 of `[0, pubkey, created_at, kind, tags,
//! content]` as compact JSON. `serde_json` escapes every control character,
//! where NIP-01 escapes only seven; a P1 event has none (hex, digits and
//! base64), and [`verify_event`] simply refuses an event whose id it
//! computes differently.
//!
//! The admission order (`diseno.md` §6.2) starts here: [`verify_event`] and
//! [`mailbox_of`] are the cheap checks before any decryption; [`open_event`]
//! decrypts with the mailbox's secret key once the app knows the mailbox.

use crate::nip44::{self, Nip44Error};
use rand::Rng;
use rand_core::{CryptoRng, OsRng, RngCore};
use secp256k1::{schnorr::Signature, Keypair, Message, SecretKey, XOnlyPublicKey, SECP256K1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// Kind of every P1 event but call signals.
pub const KIND_MESSAGE: u32 = 1059;
/// Kind of call signals (ephemeral).
pub const KIND_CALL: u32 = 21059;
/// A message's `created_at` goes back at most this many seconds.
pub const MAX_BACKDATE_SECS: i64 = 300;
/// A message expires 6 to 8 days after its `created_at`.
pub const MIN_EXPIRATION_SECS: i64 = 6 * 86_400;
pub const MAX_EXPIRATION_SECS: i64 = 8 * 86_400;
/// A call signal expires 1 to 2 hours after its `created_at`
/// (`diseno-vinculacion.md` §23.8): public relays drop it sooner anyway, but
/// the tag makes it look like every other P1 event and meets the minimum of
/// Trino's own relay gate.
pub const MIN_CALL_EXPIRATION_SECS: i64 = 3_600;
pub const MAX_CALL_EXPIRATION_SECS: i64 = 7_200;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EventError {
    #[error("kind {0} is not a P1 kind")]
    Kind(u32),
    #[error("the mailbox is not a valid x-only public key")]
    Mailbox,
    #[error("the event's author is not a valid x-only public key")]
    Author,
    #[error(transparent)]
    Nip44(#[from] Nip44Error),
}

/// A Nostr event, as relays carry it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

/// The NIP-01 id of an event with these fields.
pub fn event_id(
    pubkey: &str,
    created_at: i64,
    kind: u32,
    tags: &[Vec<String>],
    content: &str,
) -> [u8; 32] {
    let serialized = serde_json::json!([0, pubkey, created_at, kind, tags, content]).to_string();
    Sha256::digest(serialized.as_bytes()).into()
}

/// Seals `inner` for `mailbox` in an event of `kind` sent at `now`, with a
/// fresh one-time key and the system's generator.
pub fn seal_event(
    kind: u32,
    now: i64,
    mailbox: &[u8; 32],
    inner: &[u8],
) -> Result<Event, EventError> {
    seal_event_with_rng(kind, now, mailbox, inner, &mut OsRng)
}

/// [`seal_event`] with every random choice from `rng`: the one-time key,
/// the times, the NIP-44 nonce and the signature's auxiliary randomness.
pub fn seal_event_with_rng<R: RngCore + CryptoRng>(
    kind: u32,
    now: i64,
    mailbox: &[u8; 32],
    inner: &[u8],
    rng: &mut R,
) -> Result<Event, EventError> {
    let (created_at, expiration) = match kind {
        KIND_MESSAGE => {
            let created_at = now - rng.gen_range(0..=MAX_BACKDATE_SECS);
            let expiration = created_at + rng.gen_range(MIN_EXPIRATION_SECS..=MAX_EXPIRATION_SECS);
            (created_at, expiration)
        }
        KIND_CALL => {
            let expiration =
                now + rng.gen_range(MIN_CALL_EXPIRATION_SECS..=MAX_CALL_EXPIRATION_SECS);
            (now, expiration)
        }
        other => return Err(EventError::Kind(other)),
    };
    let mut one_time = loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut bytes[..]);
        if let Ok(sk) = SecretKey::from_slice(&bytes[..]) {
            break sk;
        }
    };
    let mut nip44_nonce = [0u8; 32];
    rng.fill_bytes(&mut nip44_nonce);
    let mut aux = [0u8; 32];
    rng.fill_bytes(&mut aux);
    let event = seal_parts(
        kind,
        created_at,
        expiration,
        &one_time,
        mailbox,
        inner,
        &nip44_nonce,
        &aux,
    );
    // secp256k1's keys do not wipe themselves on drop: this is the best its
    // API offers (`seal_parts` does the same with the keypair).
    one_time.non_secure_erase();
    event
}

/// The event made of exactly these parts; the vectors pin it.
#[allow(clippy::too_many_arguments)]
fn seal_parts(
    kind: u32,
    created_at: i64,
    expiration: i64,
    one_time: &SecretKey,
    mailbox: &[u8; 32],
    inner: &[u8],
    nip44_nonce: &[u8; 32],
    aux: &[u8; 32],
) -> Result<Event, EventError> {
    if kind != KIND_MESSAGE && kind != KIND_CALL {
        return Err(EventError::Kind(kind));
    }
    XOnlyPublicKey::from_slice(mailbox).map_err(|_| EventError::Mailbox)?;
    let mut keypair = Keypair::from_secret_key(SECP256K1, one_time);
    let pubkey = hex::encode(keypair.x_only_public_key().0.serialize());
    let one_time_bytes = Zeroizing::new(one_time.secret_bytes());
    let conversation = nip44::conversation_key(&one_time_bytes, mailbox)?;
    let content = nip44::encrypt_with_nonce(&conversation, inner, nip44_nonce)?;
    let tags = vec![
        vec!["p".to_string(), hex::encode(mailbox)],
        vec!["expiration".to_string(), expiration.to_string()],
    ];
    let id = event_id(&pubkey, created_at, kind, &tags, &content);
    let sig = SECP256K1.sign_schnorr_with_aux_rand(&Message::from_digest(id), &keypair, aux);
    keypair.non_secure_erase();
    Ok(Event {
        id: hex::encode(id),
        pubkey,
        created_at,
        kind,
        tags,
        content,
        sig: hex::encode(sig.as_ref()),
    })
}

/// Whether the event's id is its NIP-01 id and its signature is a valid
/// BIP-340 signature of that id by its `pubkey`.
pub fn verify_event(event: &Event) -> bool {
    let id = event_id(
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    );
    if hex::encode(id) != event.id {
        return false;
    }
    let (Some(pubkey), Some(sig)) = (
        decode_hex::<32>(&event.pubkey),
        decode_hex::<64>(&event.sig),
    ) else {
        return false;
    };
    let (Ok(pubkey), Ok(sig)) = (
        XOnlyPublicKey::from_slice(&pubkey),
        Signature::from_slice(&sig),
    ) else {
        return false;
    };
    SECP256K1
        .verify_schnorr(&sig, &Message::from_digest(id), &pubkey)
        .is_ok()
}

/// `N` bytes from exactly `2N` lower-case hex digits.
fn decode_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

/// The mailbox of an event with the shape of P1, or `None`: kind 1059 or
/// 21059 with exactly one `p` and one `expiration` and nothing else
/// (`diseno-vinculacion.md` §23.8). The mailbox is 64 lower-case hex digits.
pub fn mailbox_of(event: &Event) -> Option<[u8; 32]> {
    if event.kind != KIND_MESSAGE && event.kind != KIND_CALL {
        return None;
    }
    let mut mailbox = None;
    let mut expiration = false;
    for tag in &event.tags {
        match tag.as_slice() {
            [name, value] if name == "p" && mailbox.is_none() => {
                mailbox = Some(decode_hex::<32>(value)?);
            }
            [name, value] if name == "expiration" && !expiration => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                expiration = true;
            }
            _ => return None,
        }
    }
    expiration.then_some(mailbox?)
}

/// The inner frame of an event, opened with the secret key of its mailbox.
pub fn open_event(mailbox_sk: &[u8; 32], event: &Event) -> Result<Zeroizing<Vec<u8>>, EventError> {
    let author = decode_hex::<32>(&event.pubkey).ok_or(EventError::Author)?;
    let conversation = nip44::conversation_key(mailbox_sk, &author).map_err(|e| match e {
        Nip44Error::InvalidPublicKey => EventError::Author,
        other => EventError::Nip44(other),
    })?;
    Ok(nip44::decrypt(&conversation, &event.content)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../../tests/vectors/p1_event.json");

    fn cases() -> Vec<Value> {
        serde_json::from_str::<Value>(VECTORS).unwrap()["cases"]
            .as_array()
            .unwrap()
            .clone()
    }

    fn h32(v: &Value) -> [u8; 32] {
        hex::decode(v.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn inner_of(c: &Value) -> Vec<u8> {
        let (len, seed) = (
            c["inner_len"].as_u64().unwrap() as usize,
            c["inner_seed"].as_u64().unwrap() as usize,
        );
        (0..len).map(|j| ((5 * j + seed) & 0xFF) as u8).collect()
    }

    fn event_of(c: &Value) -> Event {
        serde_json::from_value(c["event"].clone()).unwrap()
    }

    fn rng() -> rand_chacha::ChaCha20Rng {
        rand_chacha::ChaCha20Rng::from_seed([8; 32])
    }

    #[test]
    fn the_events_match_the_independent_vectors() {
        for c in cases() {
            let want = event_of(&c);
            let one_time = SecretKey::from_slice(&h32(&c["one_time_sk"])).unwrap();
            let expiration = want.tags[1][1].parse().unwrap();
            let got = seal_parts(
                want.kind,
                want.created_at,
                expiration,
                &one_time,
                &h32(&want.tags[0][1].clone().into()),
                &inner_of(&c),
                &h32(&c["nip44_nonce"]),
                &h32(&c["aux"]),
            )
            .unwrap();
            assert_eq!(got, want);
            assert_eq!(
                hex::encode(event_id(
                    &want.pubkey,
                    want.created_at,
                    want.kind,
                    &want.tags,
                    &want.content
                )),
                want.id
            );
        }
    }

    #[test]
    fn the_vector_events_verify_and_open() {
        for c in cases() {
            let event = event_of(&c);
            assert!(verify_event(&event));
            let mailbox_sk = h32(&c["mailbox_sk"]);
            let mailbox = mailbox_of(&event).unwrap();
            assert_eq!(hex::encode(mailbox), event.tags[0][1]);
            assert_eq!(
                &open_event(&mailbox_sk, &event).unwrap()[..],
                &inner_of(&c)[..]
            );
        }
    }

    #[test]
    fn any_change_breaks_the_event() {
        let good = event_of(&cases()[0]);
        let mut e = good.clone();
        e.created_at += 1;
        assert!(!verify_event(&e));
        let mut e = good.clone();
        e.tags[1][1] = (e.created_at + 6 * 86_400 + 1).to_string();
        assert!(!verify_event(&e));
        let mut e = good.clone();
        e.content
            .replace_range(10..11, if &e.content[10..11] == "A" { "B" } else { "A" });
        assert!(!verify_event(&e));
        let mut e = good.clone();
        e.sig
            .replace_range(0..1, if &e.sig[0..1] == "0" { "1" } else { "0" });
        assert!(!verify_event(&e));
        let mut e = good.clone();
        e.pubkey = hex::encode([0xFFu8; 32]);
        assert!(!verify_event(&e));
        let mut e = good;
        e.id = e.id.to_uppercase();
        assert!(!verify_event(&e));
    }

    #[test]
    fn the_wrong_mailbox_key_does_not_open() {
        let c = &cases()[0];
        let mut other = h32(&c["mailbox_sk"]);
        other[31] ^= 1;
        assert_eq!(
            open_event(&other, &event_of(c)).unwrap_err(),
            EventError::Nip44(Nip44Error::InvalidMac)
        );
    }

    #[test]
    fn a_message_has_its_times_in_range_and_a_call_has_now() {
        let mailbox = h32(&cases()[0]["event"]["tags"][0][1]);
        let now = 1_800_000_000;
        let mut rng = rng();
        for _ in 0..200 {
            let e = seal_event_with_rng(KIND_MESSAGE, now, &mailbox, b"x", &mut rng).unwrap();
            assert!((now - MAX_BACKDATE_SECS..=now).contains(&e.created_at));
            let exp: i64 = e.tags[1][1].parse().unwrap();
            assert!(
                (e.created_at + MIN_EXPIRATION_SECS..=e.created_at + MAX_EXPIRATION_SECS)
                    .contains(&exp)
            );
            assert_eq!(mailbox_of(&e), Some(mailbox));
            assert!(verify_event(&e));
        }
        let mut call_expirations = std::collections::HashSet::new();
        for _ in 0..200 {
            let call = seal_event_with_rng(KIND_CALL, now, &mailbox, b"x", &mut rng).unwrap();
            assert_eq!(call.created_at, now);
            assert_eq!(call.tags.len(), 2);
            assert_eq!(call.tags[0], vec!["p".to_string(), hex::encode(mailbox)]);
            assert_eq!(call.tags[1][0], "expiration");
            let exp: i64 = call.tags[1][1].parse().unwrap();
            assert!(
                (now + MIN_CALL_EXPIRATION_SECS..=now + MAX_CALL_EXPIRATION_SECS).contains(&exp)
            );
            call_expirations.insert(exp);
            assert_eq!(mailbox_of(&call), Some(mailbox));
            assert!(verify_event(&call));
        }
        assert!(
            call_expirations.len() > 150,
            "the call's expiration is not a fixed offset"
        );
    }

    #[test]
    fn two_events_never_share_an_author_or_a_created_at_pattern() {
        let mailbox = h32(&cases()[0]["event"]["tags"][0][1]);
        let mut authors = std::collections::HashSet::new();
        let mut expirations = std::collections::HashSet::new();
        for _ in 0..50 {
            let e = seal_event(KIND_MESSAGE, 1_800_000_000, &mailbox, b"same").unwrap();
            assert!(authors.insert(e.pubkey.clone()));
            expirations.insert(e.tags[1][1].clone());
            assert_ne!(e.pubkey, hex::encode(mailbox));
        }
        assert!(
            expirations.len() > 40,
            "the expiration is not a fixed offset"
        );
    }

    #[test]
    fn only_p1_kinds_and_valid_mailboxes_are_sealed() {
        let mailbox = h32(&cases()[0]["event"]["tags"][0][1]);
        assert_eq!(
            seal_event(4848, 0, &mailbox, b"x").unwrap_err(),
            EventError::Kind(4848)
        );
        // 0xFF…FF is above the field prime: no x coordinate.
        assert_eq!(
            seal_event(KIND_MESSAGE, 0, &[0xFF; 32], b"x").unwrap_err(),
            EventError::Mailbox
        );
    }

    #[test]
    fn only_the_p1_shape_has_a_mailbox() {
        let good = event_of(&cases()[0]);
        let p = good.tags[0].clone();
        let exp = good.tags[1].clone();
        let with = |kind: u32, tags: Vec<Vec<String>>| Event {
            kind,
            tags,
            ..good.clone()
        };
        assert!(mailbox_of(&with(KIND_MESSAGE, vec![p.clone(), exp.clone()])).is_some());
        assert!(mailbox_of(&with(KIND_MESSAGE, vec![exp.clone(), p.clone()])).is_some());
        assert!(mailbox_of(&with(KIND_MESSAGE, vec![p.clone()])).is_none());
        assert!(mailbox_of(&with(KIND_MESSAGE, vec![p.clone(), exp.clone(), p.clone()])).is_none());
        assert!(mailbox_of(&with(
            KIND_MESSAGE,
            vec![p.clone(), exp.clone(), vec!["e".into(), "00".into()]]
        ))
        .is_none());
        assert!(mailbox_of(&with(
            KIND_MESSAGE,
            vec![p.clone(), vec!["expiration".into(), "soon".into()]]
        ))
        .is_none());
        // diseno-vinculacion.md §23.8: a call signal carries an expiration too.
        assert!(mailbox_of(&with(KIND_CALL, vec![p.clone(), exp.clone()])).is_some());
        assert!(mailbox_of(&with(KIND_CALL, vec![exp.clone(), p.clone()])).is_some());
        assert!(mailbox_of(&with(KIND_CALL, vec![p.clone()])).is_none());
        assert!(mailbox_of(&with(KIND_CALL, vec![p.clone(), exp.clone(), exp.clone()])).is_none());
        assert!(mailbox_of(&with(4848, vec![p.clone(), exp.clone()])).is_none());
        let upper = vec!["p".to_string(), p[1].to_uppercase()];
        assert!(mailbox_of(&with(KIND_MESSAGE, vec![upper, exp.clone()])).is_none());
        let long = vec!["p".to_string(), p[1].clone(), "wss://relay".to_string()];
        assert!(mailbox_of(&with(KIND_MESSAGE, vec![long, exp])).is_none());
    }
}
