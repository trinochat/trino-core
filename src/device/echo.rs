//! The `dl` echo (`diseno-vinculacion.md` §3.5, RV-09, RV-14).
//!
//! Every ratchet message carries the marks of both device lists, as
//! WhatsApp's in-chat consistency does:
//!
//! ```text
//! dl = gen u32 ‖ seq u64 ‖ hash16 of the SENDER's list
//!    ‖ gen u32 ‖ seq u64 ‖ hash16 of the RECEIVER's list that the sender uses      → 56 bytes
//! ```
//!
//! `hash16` is the first 16 bytes of the list's SHA-256: forging a match
//! takes about 2^64 signatures, not the 2^32 of the 4 bytes first drafted.
//!
//! **The echo only asks; it never changes anything by itself.** If the
//! sender announces a list of theirs the receiver does not hold, the
//! receiver asks for it; if the sender uses an old list of the receiver's,
//! the receiver sends its own. An echo with an unknown hash never raises
//! the fork alarm: only a list with a valid signature of the account's `A`
//! can (see [`super::chain`]). The 1–10 minute random delays are the app's.

use super::chain::Chain;
use super::list::DeviceList;
use super::DeviceError;

/// The echo's length.
pub const ECHO_LEN: usize = 56;
const MARK_LEN: usize = 28;

/// Which list: its (`gen`, `seq`) and the first 16 bytes of its hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListMark {
    pub gen: u32,
    pub seq: u64,
    pub hash16: [u8; 16],
}

/// The `dl` field, as the sender writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Echo {
    /// The sender's own list.
    pub sender: ListMark,
    /// The receiver's list that the sender holds.
    pub receiver: ListMark,
}

/// What an echo asks the receiver to do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EchoActions {
    /// Ask the sender for their list: they announce one this receiver does
    /// not hold.
    pub request_their_list: bool,
    /// Send our list to the sender: they use an old one.
    pub send_our_list: bool,
}

impl ListMark {
    pub fn of(list: &DeviceList) -> ListMark {
        let mut hash16 = [0u8; 16];
        hash16.copy_from_slice(&list.hash()[..16]);
        ListMark {
            gen: list.body.gen,
            seq: list.body.seq,
            hash16,
        }
    }

    fn encode_into(&self, out: &mut [u8]) {
        out[..4].copy_from_slice(&self.gen.to_be_bytes());
        out[4..12].copy_from_slice(&self.seq.to_be_bytes());
        out[12..MARK_LEN].copy_from_slice(&self.hash16);
    }

    fn decode(b: &[u8]) -> ListMark {
        ListMark {
            gen: u32::from_be_bytes(b[..4].try_into().expect("4 bytes")),
            seq: u64::from_be_bytes(b[4..12].try_into().expect("8 bytes")),
            hash16: b[12..MARK_LEN].try_into().expect("16 bytes"),
        }
    }

    fn order(&self) -> (u32, u64) {
        (self.gen, self.seq)
    }
}

impl Echo {
    /// The echo a sender writes: its own list and the receiver's it holds.
    pub fn new(mine: &DeviceList, theirs: &DeviceList) -> Echo {
        Echo {
            sender: ListMark::of(mine),
            receiver: ListMark::of(theirs),
        }
    }

    pub fn encode(&self) -> [u8; ECHO_LEN] {
        let mut out = [0u8; ECHO_LEN];
        self.sender.encode_into(&mut out[..MARK_LEN]);
        self.receiver.encode_into(&mut out[MARK_LEN..]);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Echo, DeviceError> {
        if b.len() != ECHO_LEN {
            return Err(DeviceError::Malformed);
        }
        Ok(Echo {
            sender: ListMark::decode(&b[..MARK_LEN]),
            receiver: ListMark::decode(&b[MARK_LEN..]),
        })
    }
}

/// What to do about an echo received from an account whose chain this
/// receiver holds (`theirs`), given this receiver's own list (`ours`).
pub fn on_echo(echo: &Echo, theirs: &Chain, ours: &DeviceList) -> EchoActions {
    let held = ListMark::of(theirs.current());
    let our_mark = ListMark::of(ours);
    EchoActions {
        // Newer, or the same (gen, seq) with another hash: ask. Older: the
        // sender's device is behind on its own account; nothing to do.
        request_their_list: echo.sender != held && echo.sender.order() >= held.order(),
        // Older, or the same (gen, seq) with another hash: send ours. A
        // claim newer than ours proves nothing without a signed list.
        send_our_list: echo.receiver != our_mark && echo.receiver.order() <= our_mark.order(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::chain::tests::{Account, T0};

    fn no_one(_: &[u8; 32]) -> bool {
        false
    }

    #[test]
    fn the_format_is_56_bytes_in_order() {
        let mut acct = Account::new(1);
        let list = acct.sign_next(T0);
        let mark = ListMark::of(&list);
        assert_eq!((mark.gen, mark.seq), (1, 1));
        assert_eq!(mark.hash16, list.hash()[..16]);
        let echo = Echo {
            sender: ListMark {
                gen: 0x01020304,
                seq: 0x05060708090A0B0C,
                hash16: [0xAA; 16],
            },
            receiver: ListMark {
                gen: 7,
                seq: 9,
                hash16: [0xBB; 16],
            },
        };
        let raw = echo.encode();
        assert_eq!(
            hex::encode(&raw[..28]),
            "0102030405060708090a0b0caaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(&raw[28..32], &7u32.to_be_bytes());
        assert_eq!(&raw[32..40], &9u64.to_be_bytes());
        assert_eq!(&raw[40..], &[0xBB; 16]);
        assert_eq!(Echo::decode(&raw).unwrap(), echo);
        assert_eq!(Echo::decode(&raw[..55]), Err(DeviceError::Malformed));
        assert_eq!(
            Echo::decode(&[raw.as_slice(), &[0]].concat()),
            Err(DeviceError::Malformed)
        );
    }

    /// Ana (the sender) and Beto (the receiver), each with their lists.
    struct Pair {
        ana: Account,
        ana_lists: Vec<DeviceList>,
        beto_lists: Vec<DeviceList>,
    }

    fn pair() -> Pair {
        let mut ana = Account::new(2);
        let mut beto = Account::new(1);
        let ana_lists = (0..3).map(|i| ana.sign_next(T0 + i)).collect();
        let beto_lists = (0..3).map(|i| beto.sign_next(T0 + i)).collect();
        Pair {
            ana,
            ana_lists,
            beto_lists,
        }
    }

    #[test]
    fn matching_marks_ask_nothing() {
        let p = pair();
        let held = Chain::first(p.ana_lists[1].clone(), &p.ana.a.pub_bytes, T0, no_one).unwrap();
        let echo = Echo::new(&p.ana_lists[1], &p.beto_lists[2]);
        assert_eq!(
            on_echo(&echo, &held, &p.beto_lists[2]),
            EchoActions::default()
        );
    }

    #[test]
    fn a_newer_list_of_the_sender_is_requested_and_an_older_one_ignored() {
        let p = pair();
        let held = Chain::first(p.ana_lists[1].clone(), &p.ana.a.pub_bytes, T0, no_one).unwrap();
        let newer = Echo::new(&p.ana_lists[2], &p.beto_lists[2]);
        assert_eq!(
            on_echo(&newer, &held, &p.beto_lists[2]),
            EchoActions {
                request_their_list: true,
                send_our_list: false
            }
        );
        let older = Echo::new(&p.ana_lists[0], &p.beto_lists[2]);
        assert_eq!(
            on_echo(&older, &held, &p.beto_lists[2]),
            EchoActions::default()
        );
    }

    #[test]
    fn an_unknown_hash_only_asks_for_the_list_and_raises_no_alarm() {
        // Same (gen, seq) as the list held, another hash: maybe a fork,
        // maybe a lie. Without a signed list, it is only a request.
        let p = pair();
        let held = Chain::first(p.ana_lists[1].clone(), &p.ana.a.pub_bytes, T0, no_one).unwrap();
        let mut echo = Echo::new(&p.ana_lists[1], &p.beto_lists[2]);
        echo.sender.hash16 = [0x55; 16];
        let actions = on_echo(&echo, &held, &p.beto_lists[2]);
        assert!(actions.request_their_list);
        assert!(!actions.send_our_list);
        assert_eq!(held.current(), &p.ana_lists[1]);
    }

    #[test]
    fn a_sender_with_an_old_list_of_ours_gets_ours_and_a_newer_claim_gets_nothing() {
        let p = pair();
        let held = Chain::first(p.ana_lists[1].clone(), &p.ana.a.pub_bytes, T0, no_one).unwrap();
        let old = Echo::new(&p.ana_lists[1], &p.beto_lists[0]);
        assert_eq!(
            on_echo(&old, &held, &p.beto_lists[2]),
            EchoActions {
                request_their_list: false,
                send_our_list: true
            }
        );
        let mut forged = Echo::new(&p.ana_lists[1], &p.beto_lists[2]);
        forged.receiver.hash16 = [0x66; 16];
        assert!(on_echo(&forged, &held, &p.beto_lists[2]).send_our_list);
        let mut ahead = Echo::new(&p.ana_lists[1], &p.beto_lists[2]);
        ahead.receiver.seq += 1;
        assert_eq!(
            on_echo(&ahead, &held, &p.beto_lists[2]),
            EchoActions::default()
        );
    }
}
