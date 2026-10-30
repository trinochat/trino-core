//! A device that unlinks itself (`diseno-vinculacion.md` §8.1, DV-15).
//!
//! ```text
//! retirement = A 32 ‖ gen u32 ‖ id u32 ‖ ts u64 ‖ sig 64                     → 112 bytes
//! sig        = Ed25519(dev_sign, "trino/retire/v1\0" ‖ A ‖ gen ‖ id ‖ ts)
//! ```
//!
//! A retirement only removes the device that signs it, so it needs no `A`:
//! whoever receives it stops sending to that device and never lets its
//! `dev_sign` back (rule 5). The primary cannot retire itself (it holds
//! `A`); it removes others by signing a new list. `ts` is signed and kept
//! for the app; replaying a retirement changes nothing.

use super::chain::Chain;
use super::list::ed25519_verify_strict;
use super::DeviceError;
use crate::identity::{ed25519_sign, KeyPair};

/// A retirement's length.
pub const RETIREMENT_LEN: usize = 32 + 4 + 4 + 8 + 64;
const DOMAIN: &[u8] = b"trino/retire/v1\0";

/// A device's signed word that it left the account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retirement {
    pub account: [u8; 32],
    pub gen: u32,
    pub id: u32,
    pub ts: u64,
    pub sig: [u8; 64],
}

impl Retirement {
    /// The retirement of device `id`, signed with its `dev_sign`.
    pub fn sign(account: &[u8; 32], gen: u32, id: u32, ts: u64, dev_sign: &KeyPair) -> Self {
        let mut r = Retirement {
            account: *account,
            gen,
            id,
            ts,
            sig: [0; 64],
        };
        r.sig = ed25519_sign(dev_sign, &r.message());
        r
    }

    pub fn encode(&self) -> [u8; RETIREMENT_LEN] {
        let mut out = [0u8; RETIREMENT_LEN];
        out[..48].copy_from_slice(&self.signed_fields());
        out[48..].copy_from_slice(&self.sig);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, DeviceError> {
        if b.len() != RETIREMENT_LEN {
            return Err(DeviceError::Malformed);
        }
        Ok(Retirement {
            account: b[..32].try_into().expect("32 bytes"),
            gen: u32::from_be_bytes(b[32..36].try_into().expect("4 bytes")),
            id: u32::from_be_bytes(b[36..40].try_into().expect("4 bytes")),
            ts: u64::from_be_bytes(b[40..48].try_into().expect("8 bytes")),
            sig: b[48..].try_into().expect("64 bytes"),
        })
    }

    /// `A ‖ gen ‖ id ‖ ts`.
    fn signed_fields(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        out[..32].copy_from_slice(&self.account);
        out[32..36].copy_from_slice(&self.gen.to_be_bytes());
        out[36..40].copy_from_slice(&self.id.to_be_bytes());
        out[40..].copy_from_slice(&self.ts.to_be_bytes());
        out
    }

    fn message(&self) -> Vec<u8> {
        [DOMAIN, &self.signed_fields()].concat()
    }
}

impl Chain {
    /// Applies a retirement to the list held; returns the id of the device
    /// that left.
    pub fn retire(&mut self, r: &Retirement) -> Result<u32, DeviceError> {
        let list = self.current();
        if r.account != list.body.account {
            return Err(DeviceError::WrongAccount);
        }
        if r.gen < list.body.gen {
            return Err(DeviceError::Stale);
        }
        if r.gen > list.body.gen {
            return Err(DeviceError::Generation);
        }
        let entry = list.entry_by_id(r.id).ok_or(DeviceError::UnknownDevice)?;
        if !ed25519_verify_strict(&entry.dev_sign, &r.message(), &r.sig) {
            return Err(DeviceError::Signature);
        }
        if entry.is_primary() {
            return Err(DeviceError::PrimaryRetirement);
        }
        let (id, key) = (entry.id, entry.dev_sign);
        self.mark_removed(key);
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::chain::tests::{Account, T0};
    use crate::identity::generate_ed25519;

    fn chain_of(acct: &mut Account) -> Chain {
        let first = acct.sign_next(T0);
        Chain::first(first, &acct.a.pub_bytes, T0, |_| false).unwrap()
    }

    #[test]
    fn a_device_retires_itself_and_never_comes_back() {
        let mut acct = Account::new(3);
        let mut chain = chain_of(&mut acct);
        let (id, phone) = &acct.devices[1];
        let r = Retirement::sign(&acct.a.pub_bytes, 1, *id, T0 + 5, &phone.sign);
        let r = Retirement::decode(&r.encode()).unwrap();
        assert_eq!(chain.retire(&r), Ok(*id));
        assert!(chain.is_removed(&phone.sign.pub_bytes));
        assert_eq!(chain.destinations(T0, false).len(), 2);
        assert!(chain.device_for_dh(&phone.dh.pub_bytes).is_none());
        // A replay changes nothing.
        assert_eq!(chain.retire(&r), Ok(*id));
        assert_eq!(chain.destinations(T0, false).len(), 2);

        // The primary's next list still names it by mistake: refused.
        let back = acct.sign_next(T0 + 6);
        assert_eq!(
            chain.accept(back, T0 + 6, |_| false).unwrap_err(),
            DeviceError::Removed(acct.devices[1].1.sign.pub_bytes)
        );
        // Without it, accepted.
        acct.devices.remove(1);
        acct.seq -= 1;
        acct.prev = chain.current().hash();
        let without = acct.sign_next(T0 + 7);
        let accepted = chain.accept(without, T0 + 7, |_| false).unwrap();
        assert_eq!(accepted.removed, vec![2]);
    }

    #[test]
    fn only_the_device_itself_can_retire_it_and_not_the_primary() {
        let mut acct = Account::new(2);
        let mut chain = chain_of(&mut acct);
        let a = acct.a.pub_bytes;

        // Signed by another device, or by A, or by a stranger.
        let pc = &acct.devices[0].1;
        for key in [&pc.sign, &acct.a, &generate_ed25519()] {
            let r = Retirement::sign(&a, 1, 2, T0, key);
            assert_eq!(chain.retire(&r), Err(DeviceError::Signature));
        }
        // Another field than the one signed.
        let mut r = Retirement::sign(&a, 1, 2, T0, &acct.devices[1].1.sign);
        r.ts += 1;
        assert_eq!(chain.retire(&r), Err(DeviceError::Signature));

        // The primary cannot retire.
        let r = Retirement::sign(&a, 1, 1, T0, &pc.sign);
        assert_eq!(chain.retire(&r), Err(DeviceError::PrimaryRetirement));

        // Unknown device, other account, other generation.
        let phone = &acct.devices[1].1.sign;
        assert_eq!(
            chain.retire(&Retirement::sign(&a, 1, 9, T0, phone)),
            Err(DeviceError::UnknownDevice)
        );
        assert_eq!(
            chain.retire(&Retirement::sign(&[3; 32], 1, 2, T0, phone)),
            Err(DeviceError::WrongAccount)
        );
        assert_eq!(
            chain.retire(&Retirement::sign(&a, 2, 2, T0, phone)),
            Err(DeviceError::Generation)
        );
        assert_eq!(
            chain.retire(&Retirement::sign(&a, 0, 2, T0, phone)),
            Err(DeviceError::Stale)
        );
        assert_eq!(chain.destinations(T0, false).len(), 2);
    }

    #[test]
    fn the_format_is_fixed() {
        let kp = generate_ed25519();
        let r = Retirement::sign(&[1; 32], 7, 0xA1B2C3D4, 0x0102030405060708, &kp);
        let raw = r.encode();
        assert_eq!(raw.len(), 112);
        assert_eq!(&raw[32..36], &7u32.to_be_bytes());
        assert_eq!(&raw[36..40], &0xA1B2C3D4u32.to_be_bytes());
        assert_eq!(&raw[40..48], &0x0102030405060708u64.to_be_bytes());
        let mut msg = b"trino/retire/v1\0".to_vec();
        msg.extend_from_slice(&raw[..48]);
        assert_eq!(ed25519_sign(&kp, &msg), r.sig);
        assert_eq!(Retirement::decode(&raw[..111]), Err(DeviceError::Malformed));
        assert_eq!(
            Retirement::decode(&[raw.as_slice(), &[0]].concat()),
            Err(DeviceError::Malformed)
        );
    }
}
