//! The handshake bound to the device lists (`diseno-vinculacion.md` §5.1,
//! RV-06; VI-3).
//!
//! The hybrid handshake ([`crate::pqxdh`]) already puts both accounts in its
//! AD (`"trino/x3dh/v2\0" ‖ suite ‖ A_ini ‖ dev_dh_ini ‖ A_resp ‖
//! dev_dh_resp`) against unknown-key-share attacks. What this module adds is
//! that **both ends check the other device against its account's list**:
//!
//! - **the initiator** takes the other device's prekeys only from a bundle
//!   whose list is the one it holds for that account, with the device still
//!   active ([`peer_prekeys`], or [`peer_classical`] for PQ-11 when the
//!   bundle is compact), and after the first reply checks that the device
//!   is still in the list that reply brought ([`check_peer_device`]);
//! - **the responder** reads the initiator's list from message 0, accepts
//!   it into its chain (or pins a first one), and only then admits the
//!   session if the initiator's `dev_dh` is an active device of the account
//!   it named in the AD ([`check_peer_device`]). Until then nothing is
//!   stored and nothing is sent.
//!
//! [`DeviceIdentity::responder_keys`] looks up the responder's own keys by
//! the ids a handshake names.

use super::bundle::{DeviceBundle, DevicePrekeys};
use super::chain::Chain;
use super::list::Entry;
use super::DeviceError;
use crate::identity_v2::DeviceIdentity;
use crate::pqxdh::{ClassicalResponderKeys, PeerClassical, PeerPrekeys, ResponderKeys};

/// RV-06: `dev_dh` is an active device of `account` in the chain held for
/// it.
pub fn check_peer_device<'a>(
    chain: &'a Chain,
    account: &[u8; 32],
    dev_dh: &[u8; 32],
) -> Result<&'a Entry, DeviceError> {
    if &chain.account() != account {
        return Err(DeviceError::WrongAccount);
    }
    chain
        .device_for_dh(dev_dh)
        .ok_or(DeviceError::UnknownDevice)
}

/// The initiator's view of device `dev_dh`, from a full bundle of the list
/// held in `chain`.
pub fn peer_prekeys(
    bundle: &DeviceBundle,
    chain: &Chain,
    dev_dh: &[u8; 32],
) -> Result<PeerPrekeys, DeviceError> {
    let (entry, prekeys) = device_in(bundle, chain, dev_dh)?;
    Ok(PeerPrekeys {
        account: chain.account(),
        dev_sign: entry.dev_sign,
        dev_dh: entry.dev_dh,
        spk: prekeys.spk.clone(),
        pq_spk: prekeys.pq_spk.ok_or(DeviceError::NoPqPrekey)?.clone(),
    })
}

/// The same for a PQ-11 handshake, from a compact or full bundle (§21.6).
pub fn peer_classical(
    bundle: &DeviceBundle,
    chain: &Chain,
    dev_dh: &[u8; 32],
) -> Result<PeerClassical, DeviceError> {
    let (entry, prekeys) = device_in(bundle, chain, dev_dh)?;
    Ok(PeerClassical {
        account: chain.account(),
        dev_sign: entry.dev_sign,
        dev_dh: entry.dev_dh,
        spk: prekeys.spk.clone(),
    })
}

/// The device and its prekeys, if the bundle is of the list held, every
/// prekey in it is signed by its device, and the device is still active.
fn device_in<'a>(
    bundle: &'a DeviceBundle,
    chain: &Chain,
    dev_dh: &[u8; 32],
) -> Result<(&'a Entry, DevicePrekeys<'a>), DeviceError> {
    if bundle.list.hash() != chain.current().hash() {
        return Err(DeviceError::NotCurrent);
    }
    bundle.verify()?;
    chain
        .device_for_dh(dev_dh)
        .ok_or(DeviceError::UnknownDevice)?;
    let prekeys = bundle.device(dev_dh).ok_or(DeviceError::UnknownDevice)?;
    Ok((prekeys.entry, prekeys))
}

impl DeviceIdentity {
    /// This device's keys for a handshake that names `spk_id` and
    /// `pq_spk_id`, current or retired; `account` is its account's `A`.
    pub fn responder_keys(
        &self,
        account: [u8; 32],
        spk_id: u32,
        pq_spk_id: u32,
    ) -> Option<ResponderKeys<'_>> {
        Some(ResponderKeys {
            account,
            dev_dh: &self.dev_dh,
            spk: self.spk_by_id(spk_id)?,
            pq: self.pq.by_id(pq_spk_id)?,
        })
    }

    /// The same for a PQ-11 handshake, which names only the SPK.
    pub fn classical_responder_keys(
        &self,
        account: [u8; 32],
        spk_id: u32,
    ) -> Option<ClassicalResponderKeys<'_>> {
        Some(ClassicalResponderKeys {
            account,
            dev_dh: &self.dev_dh,
            spk: self.spk_by_id(spk_id)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{DeviceBundle, DeviceList};
    use crate::identity_v2::IdentityV2;
    use crate::kem::drbg;
    use crate::p1::wire::MessageBody;
    use crate::pqxdh::{initiate_pq11_with_rng, initiate_with_rng, respond, respond_pq11};
    use rand_chacha::ChaCha20Rng;

    const T0: u64 = 1_793_000_000;

    /// An account with its identity, its list and its full bundle.
    struct Person {
        id: IdentityV2,
        list: DeviceList,
        bundle: DeviceBundle,
    }

    impl Person {
        fn new(rng: &mut ChaCha20Rng) -> Person {
            let id = IdentityV2::new_account_with_rng(T0 as i64, rng);
            let list = id.first_list(T0, [0; 32], rng).unwrap();
            let bundle = DeviceBundle {
                list: list.clone(),
                spks: vec![id.device.signed_spk()],
                pq_spks: Some(vec![id.device.signed_pq_spk()]),
            };
            Person { id, list, bundle }
        }

        fn a(&self) -> [u8; 32] {
            self.id.account.as_ref().unwrap().a.pub_bytes
        }

        fn dh(&self) -> [u8; 32] {
            self.id.device.dev_dh.pub_bytes
        }

        /// What someone who pinned this account holds of it.
        fn chain(&self) -> Chain {
            Chain::first(self.list.clone(), &self.a(), T0, |_| false).unwrap()
        }
    }

    fn message() -> MessageBody {
        MessageBody {
            dh: [3; 32],
            pn: 0,
            n: 0,
            nonce: [5; 12],
            ciphertext: vec![4; 40],
        }
    }

    #[test]
    fn v8_both_sides_get_the_same_s_ses_through_their_lists() {
        let mut rng = drbg();
        let ana = Person::new(&mut rng);
        let beto = Person::new(&mut rng);

        // Ana holds Beto's chain and his full bundle.
        let beto_chain = beto.chain();
        let peer = peer_prekeys(&beto.bundle, &beto_chain, &beto.dh()).unwrap();
        assert_eq!(peer.account, beto.a());
        let init = initiate_with_rng(&ana.a(), &ana.id.device.dev_dh, &peer, &mut rng).unwrap();
        let hs = init.handshake(message());

        // Beto reads Ana's list from message 0, pins it, admits her device.
        let ana_chain = ana.chain();
        check_peer_device(&ana_chain, &ana.a(), &hs.dev_dh).unwrap();
        let keys = beto
            .id
            .device
            .responder_keys(beto.a(), hs.spk_id, hs.pq_spk_id)
            .unwrap();
        let resp = respond(&keys, &ana.a(), &hs).unwrap();
        assert_eq!(*resp.s_ses, *init.s_ses);
        assert_eq!(*resp.sk, *init.sk);

        // Ana checks Beto's device against the list his reply brought.
        check_peer_device(&beto_chain, &beto.a(), &beto.dh()).unwrap();

        // V8: an AD with another A gives another S_ses.
        let wrong = respond(&keys, &beto.a(), &hs).unwrap();
        assert_ne!(*wrong.s_ses, *init.s_ses);
    }

    #[test]
    fn a_device_outside_the_account_list_is_not_admitted() {
        let mut rng = drbg();
        let ana = Person::new(&mut rng);
        let mallory = Person::new(&mut rng);
        let ana_chain = ana.chain();

        // Mallory names Ana's account with her own device.
        assert_eq!(
            check_peer_device(&ana_chain, &ana.a(), &mallory.dh()).unwrap_err(),
            DeviceError::UnknownDevice
        );
        // Ana's device under another account than the one held.
        assert_eq!(
            check_peer_device(&ana_chain, &mallory.a(), &ana.dh()).unwrap_err(),
            DeviceError::WrongAccount
        );
    }

    #[test]
    fn a_retired_device_is_not_admitted_nor_used() {
        let mut rng = drbg();
        let ana = Person::new(&mut rng);
        // A second device of Ana's, then it retires.
        let phone = crate::identity_v2::DeviceIdentity::generate_with_rng(T0 as i64, &mut rng);
        let a_keys = &ana.id.account.as_ref().unwrap().a;
        let mut body = ana.list.body.clone();
        body.seq = 2;
        body.prev = ana.list.hash();
        body.entries
            .push(phone.entry_with_rng(&ana.a(), 0, (1, 2), &mut rng));
        let list2 = body.sign(a_keys).unwrap();
        let mut chain = ana.chain();
        chain.accept(list2.clone(), T0, |_| false).unwrap();
        let bundle2 = DeviceBundle {
            list: list2,
            spks: vec![ana.id.device.signed_spk(), phone.signed_spk()],
            pq_spks: Some(vec![ana.id.device.signed_pq_spk(), phone.signed_pq_spk()]),
        };
        check_peer_device(&chain, &ana.a(), &phone.dev_dh.pub_bytes).unwrap();
        peer_prekeys(&bundle2, &chain, &phone.dev_dh.pub_bytes).unwrap();

        let r = crate::device::Retirement::sign(&ana.a(), 1, phone.id, T0, &phone.dev_sign);
        chain.retire(&r).unwrap();
        assert_eq!(
            check_peer_device(&chain, &ana.a(), &phone.dev_dh.pub_bytes).unwrap_err(),
            DeviceError::UnknownDevice
        );
        assert_eq!(
            peer_prekeys(&bundle2, &chain, &phone.dev_dh.pub_bytes).unwrap_err(),
            DeviceError::UnknownDevice
        );
    }

    #[test]
    fn prekeys_come_only_from_the_list_held_and_signed_by_the_device() {
        let mut rng = drbg();
        let ana = Person::new(&mut rng);
        let beto = Person::new(&mut rng);
        let beto_chain = beto.chain();

        // A bundle of another list than the one held.
        assert_eq!(
            peer_prekeys(&ana.bundle, &beto_chain, &ana.dh()).unwrap_err(),
            DeviceError::NotCurrent
        );
        // A prekey that its device did not sign.
        let mut forged = beto.bundle.clone();
        forged.spks[0] = crate::pqxdh::SignedSpk::sign(
            &ana.id.device.dev_sign,
            forged.spks[0].id,
            &forged.spks[0].public,
        );
        assert_eq!(
            peer_prekeys(&forged, &beto_chain, &beto.dh()).unwrap_err(),
            DeviceError::Prekey(beto.id.device.id)
        );
        // A device the bundle does not have.
        assert_eq!(
            peer_prekeys(&beto.bundle, &beto_chain, &ana.dh()).unwrap_err(),
            DeviceError::UnknownDevice
        );
    }

    #[test]
    fn a_compact_bundle_leads_to_pq11() {
        let mut rng = drbg();
        let ana = Person::new(&mut rng);
        let beto = Person::new(&mut rng);
        let beto_chain = beto.chain();
        let compact = DeviceBundle {
            pq_spks: None,
            ..beto.bundle.clone()
        };
        assert_eq!(
            peer_prekeys(&compact, &beto_chain, &beto.dh()).unwrap_err(),
            DeviceError::NoPqPrekey
        );
        let peer = peer_classical(&compact, &beto_chain, &beto.dh()).unwrap();
        let init =
            initiate_pq11_with_rng(&ana.a(), &ana.id.device.dev_dh, &peer, &mut rng).unwrap();
        let hs = init.handshake(message());
        let keys = beto
            .id
            .device
            .classical_responder_keys(beto.a(), hs.spk_id)
            .unwrap();
        let resp = respond_pq11(&keys, &ana.a(), &hs).unwrap();
        let (ct, root) = resp.reply_with_rng(&mut rng).unwrap();
        assert_eq!(*init.finish(&ct).s_ses, *root.s_ses);
    }

    #[test]
    fn the_responder_finds_retired_prekeys_and_not_unknown_ones() {
        let mut rng = drbg();
        let mut beto = Person::new(&mut rng);
        let (spk1, pq1) = (beto.id.device.spk.id, beto.id.device.pq.current.id);
        let day = 24 * 60 * 60;
        beto.id
            .device
            .rotate_prekeys_if_due_with_rng(T0 as i64 + 30 * day, &mut rng);
        assert!(beto.id.device.responder_keys(beto.a(), spk1, pq1).is_some());
        let (spk2, pq2) = (beto.id.device.spk.id, beto.id.device.pq.current.id);
        assert!(beto.id.device.responder_keys(beto.a(), spk2, pq2).is_some());
        assert!(beto.id.device.responder_keys(beto.a(), spk2, 999).is_none());
        assert!(beto.id.device.responder_keys(beto.a(), 999, pq2).is_none());
        assert!(beto
            .id
            .device
            .classical_responder_keys(beto.a(), 999)
            .is_none());
        let keys = beto.id.device.responder_keys(beto.a(), spk1, pq2).unwrap();
        assert_eq!(keys.account, beto.a());
    }
}
