//! What a receiver keeps of one account's device lists, and the eight rules
//! for accepting a new one (`diseno-vinculacion.md` §3.2, §2.3 and §3.5).
//!
//! A receiver is a contact, or one of the account's own devices. It accepts
//! a list only if:
//!
//! 1. **it belongs to the account's chain.** A normal list: the same `A`
//!    and the same `gen`. A rotation: `gen` one more, `seq` 1, `rot` = the
//!    `A` held, and the reserve key's commitment equal to the `next`
//!    **in force** (never a pending one);
//! 2. **(`gen`, `seq`) grows**, and `seq` by at most 2^20 at once;
//! 3. **`prev` is the hash of the list held, or `seq` jumps.** A jump is
//!    accepted (a list may have been lost) and reported as a gap;
//! 4. **every signature verifies**, no key appears twice, and no key is one
//!    the caller knows from another account. A collision is an error of
//!    its own ([`DeviceError::Collision`]) so the app can warn, never drop
//!    it silently;
//! 5. **no `dev_sign` the account removed, or that retired itself, comes
//!    back**;
//! 6. **it has not expired** (network time) and is valid for at most 90
//!    days;
//! 7. **it has exactly one primary**, and a rotation only that one;
//! 8. **a `next` other than the one in force waits 7 days** from the first
//!    time this receiver saw it. Another change meanwhile replaces the
//!    pending one and restarts the wait. Only the very first list of an
//!    account (`gen` 1, `seq` 1) sets its `next` at once.
//!
//! Two different lists of the same chain with the same (`gen`, `seq`) are a
//! fork: the first one stays and the second is reported
//! ([`DeviceError::Fork`]).
//!
//! **Choices this module makes where the design is silent** (to review):
//!
//! - **After a rotation, no reserve is in force for 7 days.** The rotation
//!   spends `B` (RV-15), and its new `next` is a change like any other, so
//!   it waits. Meanwhile nothing can rotate the account again.
//! - **A rotation may name a device that the old `A` had removed:** the
//!   reserve key outranks the old `A`, and the device that rotates is
//!   typically the one a thief holding `A` just removed (§3.5).
//! - **A rotation whose `prev` is not the list held is accepted as a gap**,
//!   like a `seq` jump: the device that rotates may have missed a list.
//! - **The first list a receiver sees** is pinned by the caller to an `A`
//!   learned out of band (a code, a QR, the migration); unless it is `gen`
//!   1, `seq` 1, its `next` waits 7 days like any change.

use super::list::{DeviceList, Entry};
use super::DeviceError;
use crate::reserve::commitment;
use std::collections::VecDeque;

/// The most `seq` may grow in one list (RV-03).
pub const MAX_SEQ_STEP: u64 = 1 << 20;
/// How long a new `next` waits before it is in force (RV-02).
pub const NEXT_DELAY_SECS: u64 = 7 * 24 * 60 * 60;
/// How many accepted lists are remembered to tell a fork.
pub const HISTORY_LEN: usize = 32;

const ZERO32: [u8; 32] = [0; 32];

/// A reserve commitment waiting for its 7 days.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingNext {
    pub next: [u8; 32],
    /// Network time when this receiver first saw it.
    pub first_seen: u64,
}

/// What accepting a list changed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Accepted {
    /// `seq` jumped, or a rotation's `prev` was not the list held.
    pub gap: bool,
    pub rotated: bool,
    /// The ids of the devices that left the list.
    pub removed: Vec<u32>,
    /// A reserve change is waiting for its 7 days.
    pub next_pending: bool,
}

/// One accepted list, as remembered to tell a fork.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    gen: u32,
    seq: u64,
    account: [u8; 32],
    rot: [u8; 32],
    hash: [u8; 32],
}

/// What a receiver holds of one account.
#[derive(Clone, Debug)]
pub struct Chain {
    current: DeviceList,
    current_hash: [u8; 32],
    next_in_force: [u8; 32],
    pending: Option<PendingNext>,
    /// `dev_sign` of every device removed or retired: never to come back.
    removed: Vec<[u8; 32]>,
    history: VecDeque<Seen>,
}

impl Chain {
    /// The first list of an account, whose `A` the caller pinned out of
    /// band. `claimed` says whether a device key belongs to another account
    /// the caller knows.
    pub fn first(
        list: DeviceList,
        pinned: &[u8; 32],
        now: u64,
        claimed: impl Fn(&[u8; 32]) -> bool,
    ) -> Result<Chain, DeviceError> {
        list.verify()?;
        let b = &list.body;
        if &b.account != pinned {
            return Err(DeviceError::WrongAccount);
        }
        check_keys(&list, &claimed)?;
        if b.expires <= now {
            return Err(DeviceError::Expired);
        }
        // Only the very first list of an account sets its reserve at once.
        let first_of_account = !b.is_rotation() && b.gen == 1 && b.seq == 1;
        let (next_in_force, pending) = if first_of_account || b.next == ZERO32 {
            (b.next, None)
        } else {
            (
                ZERO32,
                Some(PendingNext {
                    next: b.next,
                    first_seen: now,
                }),
            )
        };
        let current_hash = list.hash();
        let mut chain = Chain {
            current: list,
            current_hash,
            next_in_force,
            pending,
            removed: Vec::new(),
            history: VecDeque::new(),
        };
        chain.remember();
        Ok(chain)
    }

    /// Applies the eight rules to a newer list and, if it passes, holds it.
    /// On any error nothing changes.
    pub fn accept(
        &mut self,
        list: DeviceList,
        now: u64,
        claimed: impl Fn(&[u8; 32]) -> bool,
    ) -> Result<Accepted, DeviceError> {
        list.verify()?;
        let hash = list.hash();
        let b = &list.body;
        let cur = &self.current.body;
        let rotation = b.is_rotation();

        // A fork: another list of this chain with the same (gen, seq).
        if let Some(seen) = self.history.iter().find(|s| {
            s.gen == b.gen
                && s.seq == b.seq
                && if rotation {
                    s.rot == b.rot
                } else {
                    s.account == b.account
                }
        }) {
            return Err(if seen.hash == hash {
                DeviceError::Stale
            } else {
                DeviceError::Fork {
                    gen: b.gen,
                    seq: b.seq,
                }
            });
        }

        // Rules 1 to 3.
        let in_force = self.next_in_force(now);
        let gap = if rotation {
            if b.rot != cur.account {
                return Err(DeviceError::WrongAccount);
            }
            if b.gen <= cur.gen {
                return Err(DeviceError::Stale);
            }
            if b.gen != cur.gen + 1 || b.seq != 1 {
                return Err(DeviceError::Generation);
            }
            if in_force == ZERO32 || commitment(&b.rot_key, &b.rot_pqh) != in_force {
                return Err(DeviceError::Reserve);
            }
            b.prev != self.current_hash
        } else {
            if b.account != cur.account {
                return Err(DeviceError::WrongAccount);
            }
            if b.gen < cur.gen || (b.gen == cur.gen && b.seq <= cur.seq) {
                return Err(DeviceError::Stale);
            }
            if b.gen != cur.gen {
                return Err(DeviceError::Generation);
            }
            if b.seq - cur.seq > MAX_SEQ_STEP {
                return Err(DeviceError::SeqJump);
            }
            if b.seq == cur.seq + 1 && b.prev != self.current_hash {
                return Err(DeviceError::BrokenPrev);
            }
            b.seq > cur.seq + 1
        };

        // Rules 4 to 6 (7 and the rest of 4 are in `verify`). A rotation
        // may bring back the device the old `A` removed.
        check_keys(&list, &claimed)?;
        if !rotation {
            if let Some(e) = b.entries.iter().find(|e| self.is_removed(&e.dev_sign)) {
                return Err(DeviceError::Removed(e.dev_sign));
            }
        }
        if b.expires <= now {
            return Err(DeviceError::Expired);
        }

        // Accepted; nothing above changed the state. Rule 8: a rotation
        // spends the reserve in force, and its own `next` waits like any
        // change.
        let (next_in_force, pending) = if rotation {
            let pending = (b.next != ZERO32).then_some(PendingNext {
                next: b.next,
                first_seen: now,
            });
            (ZERO32, pending)
        } else if b.next == in_force {
            (in_force, None)
        } else {
            let pending = self.pending.clone().filter(|p| p.next != in_force);
            (in_force, pending_for(b.next, pending, now))
        };
        let leaving: Vec<(u32, [u8; 32])> = cur
            .entries
            .iter()
            .filter(|old| !b.entries.iter().any(|e| e.dev_sign == old.dev_sign))
            .map(|e| (e.id, e.dev_sign))
            .collect();
        let accepted = Accepted {
            gap,
            rotated: rotation,
            removed: leaving.iter().map(|(id, _)| *id).collect(),
            next_pending: pending.is_some(),
        };
        for (_, key) in leaving {
            if !self.removed.contains(&key) {
                self.removed.push(key);
            }
        }
        if rotation {
            self.removed
                .retain(|k| !list.body.entries.iter().any(|e| &e.dev_sign == k));
        }
        self.next_in_force = next_in_force;
        self.pending = pending;
        self.current = list;
        self.current_hash = hash;
        self.remember();
        Ok(accepted)
    }

    /// Remembers the list held, to tell a fork later.
    fn remember(&mut self) {
        let b = &self.current.body;
        if self.history.len() == HISTORY_LEN {
            self.history.pop_front();
        }
        self.history.push_back(Seen {
            gen: b.gen,
            seq: b.seq,
            account: b.account,
            rot: b.rot,
            hash: self.current_hash,
        });
    }

    /// The list held.
    pub fn current(&self) -> &DeviceList {
        &self.current
    }

    /// The account key `A` of the list held.
    pub fn account(&self) -> [u8; 32] {
        self.current.body.account
    }

    /// The reserve commitment in force at `now`, zeros for none.
    pub fn next_in_force(&self, now: u64) -> [u8; 32] {
        match &self.pending {
            Some(p) if now >= p.first_seen.saturating_add(NEXT_DELAY_SECS) => p.next,
            _ => self.next_in_force,
        }
    }

    /// The reserve commitment still waiting, if any.
    pub fn pending_next(&self) -> Option<&PendingNext> {
        self.pending.as_ref()
    }

    /// Never lets this `dev_sign` back (a retirement).
    pub(super) fn mark_removed(&mut self, dev_sign: [u8; 32]) {
        if !self.removed.contains(&dev_sign) {
            self.removed.push(dev_sign);
        }
    }

    /// Whether this `dev_sign` was removed or retired.
    pub fn is_removed(&self, dev_sign: &[u8; 32]) -> bool {
        self.removed.contains(dev_sign)
    }

    /// The device of the list held with this `dev_dh`, if it is still
    /// active (neither removed nor retired).
    pub fn device_for_dh(&self, dev_dh: &[u8; 32]) -> Option<&Entry> {
        self.current
            .entry_by_dh(dev_dh)
            .filter(|e| !self.is_removed(&e.dev_sign))
    }

    /// The devices to send to at `now` (§5.3): all active ones, or only the
    /// primary while the list is expired or the contact is provisional.
    pub fn destinations(&self, now: u64, provisional: bool) -> Vec<&Entry> {
        let only_primary = provisional || self.current.body.expires <= now;
        self.current
            .body
            .entries
            .iter()
            .filter(|e| !self.is_removed(&e.dev_sign))
            .filter(|e| !only_primary || e.is_primary())
            .collect()
    }
}

/// The part of rule 4 that needs the caller: no device key of another
/// account.
fn check_keys(list: &DeviceList, claimed: &impl Fn(&[u8; 32]) -> bool) -> Result<(), DeviceError> {
    for e in &list.body.entries {
        for key in [&e.dev_sign, &e.dev_dh] {
            if claimed(key) {
                return Err(DeviceError::Collision(*key));
            }
        }
    }
    Ok(())
}

/// What waits after a list with `next` was seen at `now`: the value already
/// pending keeps its clock, another one (zeros too) starts over.
fn pending_for(next: [u8; 32], pending: Option<PendingNext>, now: u64) -> Option<PendingNext> {
    match pending {
        Some(p) if p.next == next => Some(p),
        _ => Some(PendingNext {
            next,
            first_seen: now,
        }),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::device::list::tests::{body, Device};
    use crate::device::list::{ListBody, FLAG_PRIMARY, MAX_VALIDITY_SECS};
    use crate::identity::{generate_ed25519, KeyPair};
    use crate::reserve::ReserveKey;

    pub(crate) const T0: u64 = 1_793_000_000;
    const DAY: u64 = 24 * 60 * 60;

    fn nobody(_: &[u8; 32]) -> bool {
        false
    }

    /// An account that signs its own lists.
    pub(crate) struct Account {
        pub a: KeyPair,
        pub devices: Vec<(u32, Device)>,
        pub gen: u32,
        pub seq: u64,
        pub prev: [u8; 32],
        pub next: [u8; 32],
    }

    impl Account {
        pub fn new(devices: usize) -> Account {
            Account {
                a: generate_ed25519(),
                devices: (0..devices)
                    .map(|i| (i as u32 + 1, Device::new()))
                    .collect(),
                gen: 1,
                seq: 0,
                prev: [0; 32],
                next: [0; 32],
            }
        }

        /// The body of list `seq` with the current devices; the first one
        /// is the primary.
        pub fn body_at(&self, seq: u64, issued: u64) -> ListBody {
            let entries = self
                .devices
                .iter()
                .enumerate()
                .map(|(i, (id, d))| {
                    let flags = if i == 0 { FLAG_PRIMARY } else { 0 };
                    Entry::sign(&self.a.pub_bytes, *id, flags, (1, 1), &d.sign, &d.dh)
                })
                .collect();
            let mut b = body(&self.a.pub_bytes, entries);
            b.gen = self.gen;
            b.seq = seq;
            b.issued = issued;
            b.expires = issued + MAX_VALIDITY_SECS;
            b.prev = self.prev;
            b.next = self.next;
            b
        }

        /// Signs the next list and remembers it as the previous one.
        pub fn sign_next(&mut self, issued: u64) -> DeviceList {
            self.seq += 1;
            let list = self.body_at(self.seq, issued).sign(&self.a).unwrap();
            self.prev = list.hash();
            list
        }
    }

    fn start(acct: &mut Account) -> Chain {
        let first = acct.sign_next(T0);
        Chain::first(first, &acct.a.pub_bytes, T0, nobody).unwrap()
    }

    // ---- Rule 1 ------------------------------------------------------------

    #[test]
    fn rule1_a_list_of_another_account_or_generation_is_refused() {
        let mut acct = Account::new(1);
        let mut chain = start(&mut acct);

        let other = Account::new(1).sign_next(T0);
        assert_eq!(
            chain.accept(other, T0, nobody).unwrap_err(),
            DeviceError::WrongAccount
        );

        // The first list must be the pinned account's.
        let mut stranger = Account::new(1);
        let list = stranger.sign_next(T0);
        assert_eq!(
            Chain::first(list, &acct.a.pub_bytes, T0, nobody).unwrap_err(),
            DeviceError::WrongAccount
        );

        // A normal list cannot change the generation.
        acct.gen = 2;
        let jumped = acct.sign_next(T0);
        assert_eq!(
            chain.accept(jumped, T0, nobody).unwrap_err(),
            DeviceError::Generation
        );
    }

    // ---- Rule 2 ------------------------------------------------------------

    #[test]
    fn rule2_gen_seq_must_grow_and_seq_by_at_most_2_pow_20() {
        let mut acct = Account::new(1);
        let first = acct.sign_next(T0);
        let mut chain = Chain::first(first.clone(), &acct.a.pub_bytes, T0, nobody).unwrap();
        let second = acct.sign_next(T0 + 1);
        chain.accept(second.clone(), T0 + 1, nobody).unwrap();

        // The same list again, and an older one (another older one with
        // the same (gen, seq) would be a fork, see v5).
        assert_eq!(
            chain.accept(second, T0 + 2, nobody).unwrap_err(),
            DeviceError::Stale
        );
        assert_eq!(
            chain.accept(first, T0 + 5, nobody).unwrap_err(),
            DeviceError::Stale
        );

        // Exactly 2^20 more is fine; one more than that is not.
        let too_far = acct
            .body_at(2 + MAX_SEQ_STEP + 1, T0)
            .sign(&acct.a)
            .unwrap();
        assert_eq!(
            chain.accept(too_far, T0, nobody).unwrap_err(),
            DeviceError::SeqJump
        );
        let far = acct.body_at(2 + MAX_SEQ_STEP, T0).sign(&acct.a).unwrap();
        assert!(chain.accept(far, T0, nobody).unwrap().gap);
    }

    // ---- Rule 3 ------------------------------------------------------------

    #[test]
    fn rule3_prev_must_match_unless_seq_jumps_and_a_jump_is_reported() {
        let mut acct = Account::new(1);
        let mut chain = start(&mut acct);

        let mut broken = acct.body_at(2, T0);
        broken.prev = [7; 32];
        assert_eq!(
            chain
                .accept(broken.sign(&acct.a).unwrap(), T0, nobody)
                .unwrap_err(),
            DeviceError::BrokenPrev
        );

        let next = acct.sign_next(T0);
        assert!(!chain.accept(next, T0, nobody).unwrap().gap);

        // Seq 4 after 2: list 3 was lost. Its prev cannot match; accepted.
        let mut skipped = acct.body_at(4, T0);
        skipped.prev = [7; 32];
        let accepted = chain
            .accept(skipped.sign(&acct.a).unwrap(), T0, nobody)
            .unwrap();
        assert!(accepted.gap);
        assert_eq!(chain.current().body.seq, 4);
    }

    // ---- Rule 4 ------------------------------------------------------------

    #[test]
    fn rule4_bad_entries_and_keys_of_other_accounts_are_refused_out_loud() {
        let mut acct = Account::new(2);
        let mut chain = start(&mut acct);

        let mut bad = acct.sign_next(T0);
        bad.body.entries[1].dh_sig[0] ^= 1;
        let bad = bad.body.sign(&acct.a).unwrap();
        assert_eq!(
            chain.accept(bad, T0, nobody).unwrap_err(),
            DeviceError::Entry(2)
        );

        // The second device's dev_dh is proven by another account.
        let taken = acct.devices[1].1.dh.pub_bytes;
        let mut list = acct.body_at(2, T0);
        list.prev = chain.current().hash();
        let list = list.sign(&acct.a).unwrap();
        assert_eq!(
            chain.accept(list.clone(), T0, |k| k == &taken).unwrap_err(),
            DeviceError::Collision(taken)
        );
        let taken_sign = acct.devices[1].1.sign.pub_bytes;
        assert_eq!(
            chain.accept(list, T0, |k| k == &taken_sign).unwrap_err(),
            DeviceError::Collision(taken_sign)
        );
        let first = Account::new(1);
        let theirs = first.devices[0].1.dh.pub_bytes;
        let mut first = first;
        let l = first.sign_next(T0);
        assert_eq!(
            Chain::first(l, &first.a.pub_bytes, T0, |k| k == &theirs).unwrap_err(),
            DeviceError::Collision(theirs)
        );
    }

    // ---- Rule 5 ------------------------------------------------------------

    #[test]
    fn rule5_a_removed_device_never_comes_back() {
        let mut acct = Account::new(2);
        let mut chain = start(&mut acct);
        let phone = acct.devices.pop().unwrap();
        let without = acct.sign_next(T0 + 1);
        let accepted = chain.accept(without, T0 + 1, nobody).unwrap();
        assert_eq!(accepted.removed, vec![phone.0]);
        assert!(chain.is_removed(&phone.1.sign.pub_bytes));

        acct.devices.push(phone);
        let back = acct.sign_next(T0 + 2);
        assert_eq!(
            chain.accept(back, T0 + 2, nobody).unwrap_err(),
            DeviceError::Removed(acct.devices[1].1.sign.pub_bytes)
        );
    }

    // ---- Rule 6 ------------------------------------------------------------

    #[test]
    fn rule6_an_expired_list_or_one_valid_too_long_is_refused() {
        let mut acct = Account::new(1);
        let mut chain = start(&mut acct);
        let list = acct.sign_next(T0);
        let expires = list.body.expires;
        assert_eq!(
            chain.accept(list.clone(), expires, nobody).unwrap_err(),
            DeviceError::Expired
        );
        chain.accept(list, expires - 1, nobody).unwrap();

        let mut long = acct.body_at(3, T0);
        long.expires = T0 + MAX_VALIDITY_SECS + 1;
        assert_eq!(
            chain
                .accept(long.sign(&acct.a).unwrap(), T0, nobody)
                .unwrap_err(),
            DeviceError::Validity
        );

        // The first list too.
        let mut late = Account::new(1);
        let l = late.sign_next(T0);
        assert_eq!(
            Chain::first(l, &late.a.pub_bytes, T0 + MAX_VALIDITY_SECS, nobody).unwrap_err(),
            DeviceError::Expired
        );
    }

    // ---- Rule 7 ------------------------------------------------------------

    #[test]
    fn rule7_exactly_one_primary() {
        let mut acct = Account::new(2);
        let mut chain = start(&mut acct);
        let mut two = acct.body_at(2, T0);
        two.entries[1] = {
            let (id, d) = &acct.devices[1];
            Entry::sign(&acct.a.pub_bytes, *id, FLAG_PRIMARY, (1, 1), &d.sign, &d.dh)
        };
        assert_eq!(
            chain
                .accept(two.sign(&acct.a).unwrap(), T0, nobody)
                .unwrap_err(),
            DeviceError::Primary
        );
    }

    // ---- Rule 8 and the reserve (V3) -------------------------------------

    #[test]
    fn rule8_the_first_list_of_an_account_sets_next_at_once() {
        let mut acct = Account::new(1);
        acct.next = ReserveKey::generate().next();
        let chain = start(&mut acct);
        assert_eq!(chain.next_in_force(T0), acct.next);
        assert_eq!(chain.pending_next(), None);
    }

    #[test]
    fn rule8_a_first_seen_list_that_is_not_the_first_waits_like_a_change() {
        let mut acct = Account::new(1);
        acct.next = ReserveKey::generate().next();
        acct.sign_next(T0);
        let second = acct.sign_next(T0);
        let chain = Chain::first(second, &acct.a.pub_bytes, T0 + 3, nobody).unwrap();
        assert_eq!(chain.next_in_force(T0 + 3), [0; 32]);
        assert_eq!(chain.next_in_force(T0 + 3 + NEXT_DELAY_SECS), acct.next);
    }

    #[test]
    fn rule8_a_new_next_waits_7_days_from_first_sight_even_from_zeros() {
        let mut acct = Account::new(1);
        let mut chain = start(&mut acct);
        assert_eq!(chain.next_in_force(T0), [0; 32]);

        // The kit is made later: zeros → a commitment. It is backdated by
        // a year, which must not shorten anything.
        acct.next = ReserveKey::generate().next();
        let seen_at = T0 + 10 * DAY;
        let list = acct.body_at(2, T0 - 365 * DAY + MAX_VALIDITY_SECS / 2);
        let mut list = list;
        list.prev = chain.current().hash();
        list.issued = seen_at - 89 * DAY;
        list.expires = list.issued + MAX_VALIDITY_SECS;
        let accepted = chain
            .accept(list.sign(&acct.a).unwrap(), seen_at, nobody)
            .unwrap();
        assert!(accepted.next_pending);
        assert_eq!(chain.next_in_force(seen_at + NEXT_DELAY_SECS - 1), [0; 32]);
        assert_eq!(chain.next_in_force(seen_at + NEXT_DELAY_SECS), acct.next);
    }

    #[test]
    fn rule8_another_change_restarts_the_wait_and_the_same_one_does_not() {
        let mut acct = Account::new(1);
        acct.next = ReserveKey::generate().next();
        let mut chain = start(&mut acct);
        let original = acct.next;

        acct.next = ReserveKey::generate().next();
        let first_change = acct.next;
        chain
            .accept(acct.sign_next(T0 + DAY), T0 + DAY, nobody)
            .unwrap();
        // The same pending value again: the clock keeps running.
        chain
            .accept(acct.sign_next(T0 + 3 * DAY), T0 + 3 * DAY, nobody)
            .unwrap();
        assert_eq!(chain.pending_next().unwrap().first_seen, T0 + DAY);
        assert_eq!(
            chain.next_in_force(T0 + DAY + NEXT_DELAY_SECS),
            first_change
        );

        // Another value replaces it and starts over.
        acct.next = ReserveKey::generate().next();
        let second_change = acct.next;
        chain
            .accept(acct.sign_next(T0 + 4 * DAY), T0 + 4 * DAY, nobody)
            .unwrap();
        assert_eq!(chain.next_in_force(T0 + DAY + NEXT_DELAY_SECS), original);
        assert_eq!(
            chain.next_in_force(T0 + 4 * DAY + NEXT_DELAY_SECS),
            second_change
        );

        // Back to the value in force: nothing waits any more.
        acct.next = original;
        let back = chain
            .accept(acct.sign_next(T0 + 5 * DAY), T0 + 5 * DAY, nobody)
            .unwrap();
        assert!(!back.next_pending);
        assert_eq!(chain.pending_next(), None);
    }

    #[test]
    fn rule8_a_matured_change_is_in_force_for_the_next_list() {
        let mut acct = Account::new(1);
        let mut chain = start(&mut acct);
        acct.next = ReserveKey::generate().next();
        chain.accept(acct.sign_next(T0), T0, nobody).unwrap();
        let later = T0 + NEXT_DELAY_SECS + 1;
        let accepted = chain.accept(acct.sign_next(later), later, nobody).unwrap();
        assert!(!accepted.next_pending);
        assert_eq!(chain.next_in_force(later), acct.next);
        assert_eq!(chain.pending_next(), None);
    }

    // ---- Rotation (V4) ---------------------------------------------------

    /// The rotation of `acct` by its device `keep` with reserve `b`.
    fn rotation(
        acct: &Account,
        keep: usize,
        b: &ReserveKey,
        a_star: &KeyPair,
        at: u64,
    ) -> DeviceList {
        let (id, d) = &acct.devices[keep];
        let entry = Entry::sign(
            &a_star.pub_bytes,
            *id,
            FLAG_PRIMARY,
            (acct.gen + 1, 1),
            &d.sign,
            &d.dh,
        );
        let mut b_ = body(&a_star.pub_bytes, vec![entry]);
        b_.gen = acct.gen + 1;
        b_.seq = 1;
        b_.issued = at;
        b_.expires = at + MAX_VALIDITY_SECS;
        b_.prev = acct.prev;
        b_.rot = acct.a.pub_bytes;
        b_.next = ReserveKey::generate().next();
        b_.sign_rotation(a_star, b).unwrap()
    }

    #[test]
    fn v4_a_rotation_with_the_reserve_in_force_wins_and_removes_the_rest() {
        let b = ReserveKey::generate();
        let mut acct = Account::new(3);
        acct.next = b.next();
        let mut chain = start(&mut acct);

        let a_star = generate_ed25519();
        let rot = rotation(&acct, 1, &b, &a_star, T0 + DAY);
        let accepted = chain.accept(rot, T0 + DAY, nobody).unwrap();
        assert!(accepted.rotated);
        assert!(!accepted.gap);
        assert_eq!(accepted.removed, vec![1, 3]);
        assert_eq!(chain.account(), a_star.pub_bytes);
        assert_eq!(chain.current().body.gen, 2);

        // B is spent: no reserve is in force until the new one has waited.
        assert_eq!(chain.next_in_force(T0 + DAY), [0; 32]);
        assert!(chain.pending_next().is_some());

        // Everything signed with the old A is refused, even with a huge seq.
        let mut old = acct.body_at(u64::MAX, T0 + DAY);
        old.prev = [0; 32];
        assert_eq!(
            chain
                .accept(old.sign(&acct.a).unwrap(), T0 + DAY, nobody)
                .unwrap_err(),
            DeviceError::WrongAccount
        );
        let next_old = acct.sign_next(T0 + DAY);
        assert_eq!(
            chain.accept(next_old, T0 + DAY, nobody).unwrap_err(),
            DeviceError::WrongAccount
        );
    }

    #[test]
    fn v4_a_rotation_against_a_pending_next_or_a_spent_b_is_refused() {
        let b = ReserveKey::generate();
        let mut acct = Account::new(2);
        let mut chain = start(&mut acct);
        // B is only pending.
        acct.next = b.next();
        chain.accept(acct.sign_next(T0), T0, nobody).unwrap();
        let a_star = generate_ed25519();
        assert_eq!(
            chain
                .accept(rotation(&acct, 1, &b, &a_star, T0 + DAY), T0 + DAY, nobody)
                .unwrap_err(),
            DeviceError::Reserve
        );

        // Once in force, the rotation passes; the same B a second time does
        // not, whoever signs it.
        let later = T0 + NEXT_DELAY_SECS;
        chain
            .accept(rotation(&acct, 1, &b, &a_star, later), later, nobody)
            .unwrap();
        let mut rotated = Account::new(0);
        rotated.a = a_star;
        rotated.devices.push(acct.devices.remove(1));
        rotated.gen = 2;
        rotated.seq = 1;
        rotated.prev = chain.current().hash();
        let a_third = generate_ed25519();
        assert_eq!(
            chain
                .accept(
                    rotation(&rotated, 0, &b, &a_third, later + 1),
                    later + 1,
                    nobody
                )
                .unwrap_err(),
            DeviceError::Reserve
        );
    }

    #[test]
    fn v4_a_rotation_by_a_device_the_old_a_removed_is_accepted() {
        // A thief with A removes the phone; the phone rotates with B (§3.5).
        let b = ReserveKey::generate();
        let mut acct = Account::new(2);
        acct.next = b.next();
        let mut chain = start(&mut acct);
        let phone = acct.devices.pop().unwrap();
        chain
            .accept(acct.sign_next(T0 + 1), T0 + 1, nobody)
            .unwrap();
        assert!(chain.is_removed(&phone.1.sign.pub_bytes));

        acct.devices.push(phone);
        let a_star = generate_ed25519();
        let rot = rotation(&acct, 1, &b, &a_star, T0 + 2);
        let accepted = chain.accept(rot, T0 + 2, nobody).unwrap();
        assert!(accepted.rotated);
        assert!(!chain.is_removed(&acct.devices[1].1.sign.pub_bytes));
        assert!(chain.is_removed(&acct.devices[0].1.sign.pub_bytes));
    }

    #[test]
    fn v4_a_rotation_must_be_the_next_generation_with_seq_1() {
        let b = ReserveKey::generate();
        let mut acct = Account::new(1);
        acct.next = b.next();
        let mut chain = start(&mut acct);
        let a_star = generate_ed25519();
        let mut skip = acct.body_at(1, T0);
        skip.account = a_star.pub_bytes;
        skip.entries = vec![{
            let (id, d) = &acct.devices[0];
            Entry::sign(&a_star.pub_bytes, *id, FLAG_PRIMARY, (1, 1), &d.sign, &d.dh)
        }];
        skip.gen = 3;
        skip.rot = acct.a.pub_bytes;
        let skip = skip.sign_rotation(&a_star, &b).unwrap();
        assert_eq!(
            chain.accept(skip, T0, nobody).unwrap_err(),
            DeviceError::Generation
        );
    }

    // ---- Fork (V5) -------------------------------------------------------

    #[test]
    fn v5_two_lists_with_the_same_gen_seq_are_a_fork_and_the_first_stays() {
        let mut acct = Account::new(2);
        let mut chain = start(&mut acct);
        let honest = acct.sign_next(T0 + 1);
        let honest_hash = honest.hash();
        chain.accept(honest, T0 + 1, nobody).unwrap();

        // Same (gen, seq), other content, valid signature of A.
        let mut fork = acct.body_at(2, T0 + 2);
        fork.entries.pop();
        assert_eq!(
            chain
                .accept(fork.sign(&acct.a).unwrap(), T0 + 2, nobody)
                .unwrap_err(),
            DeviceError::Fork { gen: 1, seq: 2 }
        );
        assert_eq!(chain.current().hash(), honest_hash);

        // Also against an older list still remembered.
        let mut old_fork = acct.body_at(1, T0 + 3);
        old_fork.issued = T0 + 3;
        assert_eq!(
            chain
                .accept(old_fork.sign(&acct.a).unwrap(), T0 + 3, nobody)
                .unwrap_err(),
            DeviceError::Fork { gen: 1, seq: 1 }
        );
    }

    #[test]
    fn a_refused_list_changes_nothing() {
        let mut acct = Account::new(2);
        acct.next = ReserveKey::generate().next();
        let mut chain = start(&mut acct);
        let before = (
            chain.current().clone(),
            chain.next_in_force(T0),
            chain.pending_next().cloned(),
        );
        acct.next = ReserveKey::generate().next();
        acct.devices.pop();
        let mut list = acct.body_at(2, T0);
        list.prev = [1; 32];
        let _ = chain
            .accept(list.sign(&acct.a).unwrap(), T0, nobody)
            .unwrap_err();
        assert_eq!(
            before,
            (
                chain.current().clone(),
                chain.next_in_force(T0),
                chain.pending_next().cloned()
            )
        );
        assert_eq!(chain.destinations(T0, false).len(), 2);
    }

    // ---- Destinations (§5.3) -----------------------------------------------

    #[test]
    fn only_the_primary_while_expired_or_provisional() {
        let mut acct = Account::new(3);
        let chain = start(&mut acct);
        let primary = acct.devices[0].1.dh.pub_bytes;
        assert_eq!(chain.destinations(T0, false).len(), 3);
        let only = |v: Vec<&Entry>| v.iter().map(|e| e.dev_dh).collect::<Vec<_>>();
        assert_eq!(only(chain.destinations(T0, true)), vec![primary]);
        let expires = chain.current().body.expires;
        assert_eq!(only(chain.destinations(expires, false)), vec![primary]);
        assert_eq!(chain.destinations(expires - 1, false).len(), 3);
        assert_eq!(chain.device_for_dh(&primary).unwrap().id, 1);
        assert!(chain.device_for_dh(&[9; 32]).is_none());
    }
}
