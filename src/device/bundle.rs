//! `DeviceList` as it travels: the list with each device's prekeys
//! (`diseno-vinculacion.md` §3.4 and §21.4, PB-07).
//!
//! ```text
//! compact = list ‖ SignedSpk[n]                       → 367 + 309·n   (5 devices: 1912)
//! full    = list ‖ (SignedSpk ‖ SignedPqPrekey)[n]    → 367 + 1561·n  (5 devices: 8172)
//! ```
//!
//! The prekeys follow the order of the entries, and each one must be signed
//! by its entry's `dev_sign`. The compact form goes in the type 2 handshake
//! and in the first reply (frame part 2); the full one in a 16 KiB envelope
//! of its own (frame part 3). The list does not carry the prekeys because
//! they rotate more often (RV-24).

use super::list::{DeviceList, Entry};
use super::DeviceError;
use crate::pq_spk::{SignedPqPrekey, SIGNED_PQ_SPK_LEN};
use crate::pqxdh::{SignedSpk, SIGNED_SPK_LEN};

/// A device list with each device's prekeys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceBundle {
    pub list: DeviceList,
    /// One classical signed prekey per entry, in the same order.
    pub spks: Vec<SignedSpk>,
    /// One post-quantum prekey per entry in the full form; `None` in the
    /// compact one.
    pub pq_spks: Option<Vec<SignedPqPrekey>>,
}

/// One device of a bundle with its prekeys.
pub struct DevicePrekeys<'a> {
    pub entry: &'a Entry,
    pub spk: &'a SignedSpk,
    pub pq_spk: Option<&'a SignedPqPrekey>,
}

impl DeviceBundle {
    /// `list ‖ spk[n]`.
    pub fn encode_compact(&self) -> Vec<u8> {
        let mut out = self.list.encode();
        for spk in &self.spks {
            out.extend_from_slice(&spk.encode());
        }
        out
    }

    /// `list ‖ (spk ‖ pq_spk)[n]`; `None` without the post-quantum prekeys.
    pub fn encode_full(&self) -> Option<Vec<u8>> {
        let pq_spks = self.pq_spks.as_ref()?;
        let mut out = self.list.encode();
        for (spk, pq) in self.spks.iter().zip(pq_spks) {
            out.extend_from_slice(&spk.encode());
            out.extend_from_slice(&pq.encode());
        }
        Some(out)
    }

    /// A compact bundle that fills `b` exactly.
    pub fn decode_compact(b: &[u8]) -> Result<DeviceBundle, DeviceError> {
        let (list, used) = DeviceList::decode_prefix(b)?;
        let rest = &b[used..];
        let n = list.body.entries.len();
        if rest.len() != n * SIGNED_SPK_LEN {
            return Err(DeviceError::Malformed);
        }
        let spks = rest
            .as_chunks::<SIGNED_SPK_LEN>()
            .0
            .iter()
            .map(|c| SignedSpk::decode(c).map_err(|_| DeviceError::Malformed))
            .collect::<Result<_, _>>()?;
        Ok(DeviceBundle {
            list,
            spks,
            pq_spks: None,
        })
    }

    /// A full bundle that fills `b` exactly.
    pub fn decode_full(b: &[u8]) -> Result<DeviceBundle, DeviceError> {
        let (list, used) = DeviceList::decode_prefix(b)?;
        let rest = &b[used..];
        let n = list.body.entries.len();
        let each = SIGNED_SPK_LEN + SIGNED_PQ_SPK_LEN;
        if rest.len() != n * each {
            return Err(DeviceError::Malformed);
        }
        let mut spks = Vec::with_capacity(n);
        let mut pq_spks = Vec::with_capacity(n);
        for c in rest.chunks_exact(each) {
            let (spk, pq) = c.split_at(SIGNED_SPK_LEN);
            spks.push(SignedSpk::decode(spk).map_err(|_| DeviceError::Malformed)?);
            pq_spks.push(SignedPqPrekey::decode(pq).map_err(|_| DeviceError::Malformed)?);
        }
        Ok(DeviceBundle {
            list,
            spks,
            pq_spks: Some(pq_spks),
        })
    }

    /// The list verifies on its own ([`DeviceList::verify`]), there is one
    /// prekey of each kind per entry, and each is signed by its entry's
    /// `dev_sign`.
    pub fn verify(&self) -> Result<(), DeviceError> {
        self.list.verify()?;
        let entries = &self.list.body.entries;
        if self.spks.len() != entries.len()
            || self
                .pq_spks
                .as_ref()
                .is_some_and(|p| p.len() != entries.len())
        {
            return Err(DeviceError::Malformed);
        }
        for (i, e) in entries.iter().enumerate() {
            let spk_ok = self.spks[i].verify(&e.dev_sign).is_ok();
            let pq_ok = self
                .pq_spks
                .as_ref()
                .is_none_or(|p| p[i].verify(&e.dev_sign).is_ok());
            if !(spk_ok && pq_ok) {
                return Err(DeviceError::Prekey(e.id));
            }
        }
        Ok(())
    }

    /// The device with this `dev_dh` and its prekeys.
    pub fn device(&self, dev_dh: &[u8; 32]) -> Option<DevicePrekeys<'_>> {
        let i = self
            .list
            .body
            .entries
            .iter()
            .position(|e| &e.dev_dh == dev_dh)?;
        Some(DevicePrekeys {
            entry: &self.list.body.entries[i],
            spk: self.spks.get(i)?,
            pq_spk: self.pq_spks.as_ref().and_then(|p| p.get(i)),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::device::chain::tests::{Account, T0};
    use crate::identity::KeyPair;
    use crate::kem::drbg;
    use crate::pq_spk::PqPrekeys;

    /// A bundle of `acct`'s current devices, with fresh prekeys.
    pub(crate) fn bundle_of(acct: &mut Account, full: bool) -> DeviceBundle {
        let list = acct.sign_next(T0);
        let mut rng = drbg();
        let spks = acct
            .devices
            .iter()
            .map(|(_, d)| {
                SignedSpk::sign(&d.sign, 1, &crate::identity::generate_x25519().pub_bytes)
            })
            .collect();
        let pq_spks = full.then(|| {
            acct.devices
                .iter()
                .map(|(_, d)| PqPrekeys::new_with_rng(T0 as i64, &mut rng).signed_current(&d.sign))
                .collect()
        });
        DeviceBundle {
            list,
            spks,
            pq_spks,
        }
    }

    #[test]
    fn compact_and_full_have_the_sizes_of_the_design() {
        for n in [1usize, 5] {
            let mut acct = Account::new(n);
            let b = bundle_of(&mut acct, true);
            b.verify().unwrap();
            let compact = b.encode_compact();
            let full = b.encode_full().unwrap();
            assert_eq!(compact.len(), 367 + 309 * n);
            assert_eq!(full.len(), 367 + 1561 * n);
            let mut c = DeviceBundle::decode_compact(&compact).unwrap();
            c.verify().unwrap();
            c.pq_spks = b.pq_spks.clone();
            assert_eq!(c, b);
            assert_eq!(DeviceBundle::decode_full(&full).unwrap(), b);
        }
        let mut five = Account::new(5);
        let b = bundle_of(&mut five, true);
        assert_eq!(b.encode_compact().len(), 1912);
        assert_eq!(b.encode_full().unwrap().len(), 8172);
        let compact_only = DeviceBundle { pq_spks: None, ..b };
        assert_eq!(compact_only.encode_full(), None);
    }

    #[test]
    fn each_prekey_must_be_signed_by_its_own_device() {
        let mut acct = Account::new(3);
        let b = bundle_of(&mut acct, true);

        // The second device's SPK signed by the first device.
        let mut swapped = b.clone();
        let first: &KeyPair = &acct.devices[0].1.sign;
        swapped.spks[1] = SignedSpk::sign(first, 1, &swapped.spks[1].public);
        assert_eq!(swapped.verify(), Err(DeviceError::Prekey(2)));

        // Two prekeys exchanged between devices.
        let mut crossed = b.clone();
        crossed.spks.swap(0, 2);
        assert_eq!(crossed.verify(), Err(DeviceError::Prekey(1)));
        let mut crossed_pq = b.clone();
        crossed_pq.pq_spks.as_mut().unwrap().swap(1, 2);
        assert_eq!(crossed_pq.verify(), Err(DeviceError::Prekey(2)));

        // One prekey missing or one too many.
        let mut short = b.clone();
        short.spks.pop();
        assert_eq!(short.verify(), Err(DeviceError::Malformed));
        let mut long = b;
        let extra = long.pq_spks.as_ref().unwrap()[0].clone();
        long.pq_spks.as_mut().unwrap().push(extra);
        assert_eq!(long.verify(), Err(DeviceError::Malformed));
    }

    #[test]
    fn the_lengths_must_match_the_list() {
        let mut acct = Account::new(2);
        let b = bundle_of(&mut acct, true);
        let compact = b.encode_compact();
        let full = b.encode_full().unwrap();
        assert_eq!(
            DeviceBundle::decode_compact(&full).unwrap_err(),
            DeviceError::Malformed
        );
        assert_eq!(
            DeviceBundle::decode_full(&compact).unwrap_err(),
            DeviceError::Malformed
        );
        assert_eq!(
            DeviceBundle::decode_compact(&compact[..compact.len() - 1]).unwrap_err(),
            DeviceError::Malformed
        );
        assert_eq!(
            DeviceBundle::decode_compact(&[compact.as_slice(), &[0]].concat()).unwrap_err(),
            DeviceError::Malformed
        );
    }

    #[test]
    fn a_device_is_found_with_its_prekeys() {
        let mut acct = Account::new(3);
        let b = bundle_of(&mut acct, true);
        let dh = acct.devices[2].1.dh.pub_bytes;
        let d = b.device(&dh).unwrap();
        assert_eq!(d.entry.id, 3);
        assert_eq!(d.spk, &b.spks[2]);
        assert_eq!(d.pq_spk, Some(&b.pq_spks.as_ref().unwrap()[2]));
        assert!(b.device(&[0; 32]).is_none());
        let compact = DeviceBundle::decode_compact(&b.encode_compact()).unwrap();
        assert!(compact.device(&dh).unwrap().pq_spk.is_none());
    }
}
