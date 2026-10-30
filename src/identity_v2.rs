//! The identity after P1 and device linking (`diseno-vinculacion.md` §2.1,
//! §2.2, §2.4, §13.1, §21.3 and §23.1; VI-2).
//!
//! | Key | Where | What for |
//! | --- | --- | --- |
//! | account key `A` (Ed25519) and the account's Nostr key | only on the primary ([`AccountKeys`]) | `A` signs the device list; Nostr is only for the @name |
//! | `dev_sign` (Ed25519), `dev_dh` (X25519) | every device ([`DeviceIdentity`]) | its entry in the list, the handshake, the mailboxes |
//! | SPK (X25519), signed by `dev_sign` as `"trino/spk/v2\0" ‖ id ‖ spk` | every device | the classical half of the handshake |
//! | `pq_spk` (ML-KEM-768), kept as 64-byte seeds | every device | the post-quantum half |
//!
//! - **Today's identity becomes device 0** ([`IdentityV2::migrate_from_v1`],
//!   §13.1): `ik_sign` is `A`, `ik_dh` is `dev_dh`, `nostr` stays the
//!   account's; `dev_sign` and the `pq_spk` are new, and the current SPK is
//!   signed again by `dev_sign` with its domain. Contacts keep `A` and
//!   `dev_dh`, so their pinned keys and introduction mailboxes do not move.
//! - **The fingerprint covers `A` alone**: `SHA-256("trino/fp/v2\0" ‖ A)`,
//!   first 16 bytes ([`fingerprint`], §2.4). Linking a device does not
//!   change it, and the migration keeps "verified", since today's
//!   fingerprint also covered `ik_sign`.
//! - **The classical SPK rotates with the `pq_spk`**, every 30 days, and
//!   both are kept 45 days after they retire (DN-06, PB-06): a new SPK only
//!   reaches contacts inside a device list, which travels that slowly.
//! - **The first list of an account** ([`IdentityV2::first_list`]) is
//!   `gen` 1, `seq` 1, with this device as the primary and allowed to sign
//!   group rosters (§13.1 steps 2 and 6).
//!
//! In the vault, this identity is the body's `identityV2` field next to
//! today's `identity`, which stays until the app stops using it (VI-8).

use crate::device::list::{Entry, ListBody, FLAG_GROUPS, FLAG_PRIMARY, MAX_VALIDITY_SECS};
use crate::device::{DeviceError, DeviceList};
use crate::identity::{
    generate_nostr_keypair, Identity, KeyPair, RetiredSignedPreKey, SignedPreKey,
};
use crate::kem::KemSecret;
use crate::pq_spk::{
    PqPrekey, PqPrekeys, RetiredPqPrekey, SignedPqPrekey, PQ_SPK_RETENTION_SECS,
    PQ_SPK_ROTATION_SECS,
};
use crate::pqxdh::SignedSpk;
use ed25519_dalek::SigningKey;
use rand_core::{CryptoRng, RngCore};
use secp256k1::{Keypair, Secp256k1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A fingerprint: 128 bits (§2.4, RV-18).
pub const FINGERPRINT_LEN: usize = 16;
/// The classical SPK rotates with the `pq_spk` (DN-06).
pub const SPK_ROTATION_SECS: i64 = PQ_SPK_ROTATION_SECS;
/// And is kept as long after it retires.
pub const SPK_RETENTION_SECS: i64 = PQ_SPK_RETENTION_SECS;

const FP_DOMAIN: &[u8] = b"trino/fp/v2\0";

/// The fingerprint of an account: `SHA-256("trino/fp/v2\0" ‖ A)[..16]`.
pub fn fingerprint(account: &[u8; 32]) -> [u8; FINGERPRINT_LEN] {
    let digest = Sha256::new()
        .chain_update(FP_DOMAIN)
        .chain_update(account)
        .finalize();
    let mut fp = [0u8; FINGERPRINT_LEN];
    fp.copy_from_slice(&digest[..FINGERPRINT_LEN]);
    fp
}

/// The keys only the primary holds.
#[derive(Clone, Debug)]
pub struct AccountKeys {
    /// `A`, the account key.
    pub a: KeyPair,
    /// The account's Nostr key, only for the @name.
    pub nostr: KeyPair,
}

/// One device's keys.
pub struct DeviceIdentity {
    /// Its id in the device list: random, never reused.
    pub id: u32,
    pub dev_sign: KeyPair,
    pub dev_dh: KeyPair,
    /// The current SPK, signed by `dev_sign` with its domain.
    pub spk: SignedPreKey,
    pub retired_spks: Vec<RetiredSignedPreKey>,
    pub pq: PqPrekeys,
}

/// A device's identity, with the account keys if it is the primary.
pub struct IdentityV2 {
    pub device: DeviceIdentity,
    pub account: Option<AccountKeys>,
}

impl DeviceIdentity {
    /// A new device: new keys, a random id, first prekeys at `now`.
    pub fn generate_with_rng<R: RngCore + CryptoRng>(now: i64, rng: &mut R) -> DeviceIdentity {
        let dev_sign = ed25519_with_rng(rng);
        let dev_dh = x25519_with_rng(rng);
        let spk = signed_prekey_with_rng(&dev_sign, 1, now, rng);
        DeviceIdentity {
            id: rng.next_u32(),
            dev_sign,
            dev_dh,
            spk,
            retired_spks: Vec::new(),
            pq: PqPrekeys::new_with_rng(now, rng),
        }
    }

    /// The current SPK as it travels (§2.1).
    pub fn signed_spk(&self) -> SignedSpk {
        SignedSpk {
            id: self.spk.id,
            public: self.spk.keypair.pub_bytes,
            sig: self.spk.signature,
        }
    }

    /// The current `pq_spk` as it travels.
    pub fn signed_pq_spk(&self) -> SignedPqPrekey {
        self.pq.signed_current(&self.dev_sign)
    }

    /// The SPK a handshake names: the current one or a retired one held.
    pub fn spk_by_id(&self, id: u32) -> Option<&KeyPair> {
        std::iter::once(&self.spk)
            .chain(self.retired_spks.iter().map(|r| &r.prekey))
            .find(|spk| spk.id == id)
            .map(|spk| &spk.keypair)
    }

    /// This device's entry in account `account`'s list.
    pub fn entry_with_rng<R: RngCore + CryptoRng>(
        &self,
        account: &[u8; 32],
        flags: u8,
        since: (u32, u64),
        rng: &mut R,
    ) -> Entry {
        Entry::sign_with_rng(
            account,
            self.id,
            flags,
            since,
            &self.dev_sign,
            &self.dev_dh,
            rng,
        )
    }

    /// Rotates both prekeys when due and drops retired ones past retention;
    /// true if anything changed (re-seal the vault, send the full list).
    pub fn rotate_prekeys_if_due_with_rng<R: RngCore + CryptoRng>(
        &mut self,
        now: i64,
        rng: &mut R,
    ) -> bool {
        let mut changed = false;
        if now - self.spk.created_at >= SPK_ROTATION_SECS {
            let next_id = self
                .retired_spks
                .iter()
                .map(|r| r.prekey.id)
                .fold(self.spk.id, u32::max)
                .wrapping_add(1);
            let fresh = signed_prekey_with_rng(&self.dev_sign, next_id, now, rng);
            let outgoing = std::mem::replace(&mut self.spk, fresh);
            self.retired_spks.push(RetiredSignedPreKey {
                prekey: outgoing,
                retired_at: now,
            });
            changed = true;
        }
        let before = self.retired_spks.len();
        self.retired_spks
            .retain(|r| now - r.retired_at < SPK_RETENTION_SECS);
        // As for the pq_spk: never more than three held.
        let excess = (1 + self.retired_spks.len()).saturating_sub(MAX_SPKS);
        self.retired_spks.drain(..excess);
        changed |= self.retired_spks.len() != before;
        self.pq.rotate_if_due_with_rng(now, rng) || changed
    }
}

impl IdentityV2 {
    /// The identity of a new account, created on this device.
    pub fn new_account_with_rng<R: RngCore + CryptoRng>(now: i64, rng: &mut R) -> IdentityV2 {
        IdentityV2 {
            device: DeviceIdentity::generate_with_rng(now, rng),
            account: Some(AccountKeys {
                a: ed25519_with_rng(rng),
                // libsecp256k1's own generator, as for every Nostr key.
                nostr: generate_nostr_keypair(),
            }),
        }
    }

    /// Today's identity as device 0 (§13.1, §2.2).
    pub fn migrate_from_v1<R: RngCore + CryptoRng>(
        v1: &Identity,
        now: i64,
        rng: &mut R,
    ) -> IdentityV2 {
        let dev_sign = ed25519_with_rng(rng);
        let resign = |spk: &SignedPreKey| SignedPreKey {
            id: spk.id,
            keypair: spk.keypair.clone(),
            signature: SignedSpk::sign(&dev_sign, spk.id, &spk.keypair.pub_bytes).sig,
            created_at: spk.created_at,
        };
        let device = DeviceIdentity {
            id: rng.next_u32(),
            spk: resign(&v1.signed_prekey),
            retired_spks: v1
                .retired_signed_prekeys
                .iter()
                .map(|r| RetiredSignedPreKey {
                    prekey: resign(&r.prekey),
                    retired_at: r.retired_at,
                })
                .collect(),
            dev_dh: v1.ik_dh.clone(),
            pq: PqPrekeys::new_with_rng(now, rng),
            dev_sign,
        };
        IdentityV2 {
            device,
            account: Some(AccountKeys {
                a: v1.ik_sign.clone(),
                nostr: v1.nostr.clone(),
            }),
        }
    }

    /// The account's first list, `gen` 1, `seq` 1, issued at network time
    /// `now`, with `next` (zeros without a kit). Only the primary can sign.
    pub fn first_list<R: RngCore + CryptoRng>(
        &self,
        now: u64,
        next: [u8; 32],
        rng: &mut R,
    ) -> Result<DeviceList, DeviceError> {
        let account = self.account.as_ref().ok_or(DeviceError::Key)?;
        let a = account.a.pub_bytes;
        let entry = self
            .device
            .entry_with_rng(&a, FLAG_PRIMARY | FLAG_GROUPS, (1, 1), rng);
        ListBody {
            account: a,
            gen: 1,
            seq: 1,
            issued: now,
            expires: now + MAX_VALIDITY_SECS,
            prev: [0; 32],
            next,
            rot: [0; 32],
            rot_key: [0; 32],
            rot_pqh: [0; 32],
            entries: vec![entry],
        }
        .sign(&account.a)
    }
}

// ---- In the vault ----------------------------------------------------------

/// The identity as the vault body stores it: private keys only (every
/// public key is derived again on load), the SPK signatures, and the
/// `pq_spk` seeds.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SerializedIdentityV2 {
    device_id: u32,
    dev_sign: String,
    dev_dh: String,
    spk: SerializedSpk,
    #[serde(default)]
    retired_spks: Vec<SerializedSpk>,
    pq_spk: SerializedPqSpk,
    #[serde(default)]
    retired_pq_spks: Vec<SerializedPqSpk>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account: Option<SerializedAccount>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct SerializedSpk {
    id: u32,
    #[serde(rename = "priv")]
    priv_hex: String,
    sig: String,
    created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retired_at: Option<i64>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct SerializedPqSpk {
    id: u32,
    seed: String,
    created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retired_at: Option<i64>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SerializedAccount {
    a: String,
    nostr: String,
}

/// For the vault body.
pub(crate) fn to_serialized(id: &IdentityV2) -> SerializedIdentityV2 {
    let d = &id.device;
    let spk = |spk: &SignedPreKey, retired_at: Option<i64>| SerializedSpk {
        id: spk.id,
        priv_hex: hex::encode(spk.keypair.priv_bytes),
        sig: hex::encode(spk.signature),
        created_at: spk.created_at,
        retired_at,
    };
    let pq = |p: &PqPrekey, retired_at: Option<i64>| SerializedPqSpk {
        id: p.id,
        seed: hex::encode(p.secret.seed()),
        created_at: p.created_at,
        retired_at,
    };
    SerializedIdentityV2 {
        device_id: d.id,
        dev_sign: hex::encode(d.dev_sign.priv_bytes),
        dev_dh: hex::encode(d.dev_dh.priv_bytes),
        spk: spk(&d.spk, None),
        retired_spks: d
            .retired_spks
            .iter()
            .map(|r| spk(&r.prekey, Some(r.retired_at)))
            .collect(),
        pq_spk: pq(&d.pq.current, None),
        retired_pq_spks: d
            .pq
            .retired
            .iter()
            .map(|r| pq(&r.prekey, Some(r.retired_at)))
            .collect(),
        account: id.account.as_ref().map(|a| SerializedAccount {
            a: hex::encode(a.a.priv_bytes),
            nostr: hex::encode(a.nostr.priv_bytes),
        }),
    }
}

/// From the vault body; `None` if anything is malformed.
pub(crate) fn from_serialized(s: &SerializedIdentityV2) -> Option<IdentityV2> {
    let spk = |x: &SerializedSpk| -> Option<SignedPreKey> {
        Some(SignedPreKey {
            id: x.id,
            keypair: x25519_from_priv(&*hex32(&x.priv_hex)?),
            signature: hex::decode(&x.sig).ok()?.try_into().ok()?,
            created_at: x.created_at,
        })
    };
    let pq = |x: &SerializedPqSpk| -> Option<PqPrekey> {
        let seed = Zeroizing::new(hex::decode(&x.seed).ok()?);
        Some(PqPrekey {
            id: x.id,
            secret: KemSecret::from_seed(seed.as_slice().try_into().ok()?),
            created_at: x.created_at,
        })
    };
    let device = DeviceIdentity {
        id: s.device_id,
        dev_sign: ed25519_from_priv(&*hex32(&s.dev_sign)?),
        dev_dh: x25519_from_priv(&*hex32(&s.dev_dh)?),
        spk: spk(&s.spk)?,
        retired_spks: s
            .retired_spks
            .iter()
            .map(|r| {
                Some(RetiredSignedPreKey {
                    prekey: spk(r)?,
                    retired_at: r.retired_at?,
                })
            })
            .collect::<Option<_>>()?,
        pq: PqPrekeys {
            current: pq(&s.pq_spk)?,
            retired: s
                .retired_pq_spks
                .iter()
                .map(|r| {
                    Some(RetiredPqPrekey {
                        prekey: pq(r)?,
                        retired_at: r.retired_at?,
                    })
                })
                .collect::<Option<_>>()?,
        },
    };
    let account = match &s.account {
        None => None,
        Some(a) => Some(AccountKeys {
            a: ed25519_from_priv(&*hex32(&a.a)?),
            nostr: nostr_from_priv(&*hex32(&a.nostr)?)?,
        }),
    };
    Some(IdentityV2 { device, account })
}

/// 32 bytes from hex, in a buffer that wipes itself.
fn hex32(s: &str) -> Option<Zeroizing<[u8; 32]>> {
    let v = Zeroizing::new(hex::decode(s).ok()?);
    Some(Zeroizing::new(v.as_slice().try_into().ok()?))
}

fn ed25519_from_priv(seed: &[u8; 32]) -> KeyPair {
    KeyPair {
        priv_bytes: *seed,
        pub_bytes: SigningKey::from_bytes(seed).verifying_key().to_bytes(),
    }
}

fn x25519_from_priv(k: &[u8; 32]) -> KeyPair {
    let secret = StaticSecret::from(*k);
    KeyPair {
        priv_bytes: secret.to_bytes(),
        pub_bytes: XPublicKey::from(&secret).to_bytes(),
    }
}

fn nostr_from_priv(k: &[u8; 32]) -> Option<KeyPair> {
    let kp = Keypair::from_seckey_slice(&Secp256k1::new(), k).ok()?;
    Some(KeyPair {
        priv_bytes: *k,
        pub_bytes: kp.x_only_public_key().0.serialize(),
    })
}

/// The most classical SPKs held: the current one and two retired (§21.3).
const MAX_SPKS: usize = 3;

fn ed25519_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> KeyPair {
    let signing = SigningKey::generate(rng);
    KeyPair {
        priv_bytes: signing.to_bytes(),
        pub_bytes: signing.verifying_key().to_bytes(),
    }
}

fn x25519_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> KeyPair {
    let secret = StaticSecret::random_from_rng(rng);
    KeyPair {
        priv_bytes: secret.to_bytes(),
        pub_bytes: XPublicKey::from(&secret).to_bytes(),
    }
}

/// A new SPK, signed by `dev_sign` with its domain.
fn signed_prekey_with_rng<R: RngCore + CryptoRng>(
    dev_sign: &KeyPair,
    id: u32,
    now: i64,
    rng: &mut R,
) -> SignedPreKey {
    let keypair = x25519_with_rng(rng);
    SignedPreKey {
        id,
        signature: SignedSpk::sign(dev_sign, id, &keypair.pub_bytes).sig,
        keypair,
        created_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::Chain;
    use crate::identity::{create_identity, ed25519_verify};
    use crate::kem::drbg;
    use crate::reserve::ReserveKey;
    use crate::xeddsa;

    const T0: i64 = 1_793_000_000;
    const DAY: i64 = 24 * 60 * 60;

    #[test]
    fn the_fingerprint_is_128_bits_of_a_alone() {
        // Python: sha256(b"trino/fp/v2\0" + bytes(range(32))).hexdigest()[:32]
        let a: [u8; 32] = std::array::from_fn(|i| i as u8);
        assert_eq!(
            hex::encode(fingerprint(&a)),
            "2acfef94d2eb620bbb9a5c135318f8f1"
        );
        // Linking a device does not change it: it never sees the devices.
        let mut rng = drbg();
        let id = IdentityV2::new_account_with_rng(T0, &mut rng);
        let a = id.account.as_ref().unwrap().a.pub_bytes;
        let other_device = DeviceIdentity::generate_with_rng(T0, &mut rng);
        assert_ne!(other_device.dev_dh.pub_bytes, id.device.dev_dh.pub_bytes);
        assert_eq!(fingerprint(&a), fingerprint(&a));
        assert_ne!(fingerprint(&a), fingerprint(&id.device.dev_sign.pub_bytes));
    }

    #[test]
    fn today_s_identity_becomes_device_0() {
        let v1 = create_identity();
        let mut rng = drbg();
        let v2 = IdentityV2::migrate_from_v1(&v1, T0, &mut rng);
        let acct = v2.account.as_ref().unwrap();
        assert_eq!(acct.a.pub_bytes, v1.ik_sign.pub_bytes);
        assert_eq!(acct.a.priv_bytes, v1.ik_sign.priv_bytes);
        assert_eq!(acct.nostr.pub_bytes, v1.nostr.pub_bytes);
        assert_eq!(v2.device.dev_dh.pub_bytes, v1.ik_dh.pub_bytes);
        assert_eq!(v2.device.dev_dh.priv_bytes, v1.ik_dh.priv_bytes);
        assert_ne!(v2.device.dev_sign.pub_bytes, v1.ik_sign.pub_bytes);

        // The same SPK, signed again by dev_sign with its domain.
        assert_eq!(v2.device.spk.id, v1.signed_prekey.id);
        assert_eq!(
            v2.device.spk.keypair.pub_bytes,
            v1.signed_prekey.keypair.pub_bytes
        );
        let spk = v2.device.signed_spk();
        spk.verify(&v2.device.dev_sign.pub_bytes).unwrap();
        assert!(spk.verify(&v1.ik_sign.pub_bytes).is_err());
        assert!(!ed25519_verify(
            &v2.device.dev_sign.pub_bytes,
            &spk.public,
            &v2.device.spk.signature
        ));
        v2.device
            .signed_pq_spk()
            .verify(&v2.device.dev_sign.pub_bytes)
            .unwrap();

        // Retired SPKs come along, still usable.
        let mut old = create_identity();
        let later = old.signed_prekey.created_at + 3 * DAY;
        crate::identity::rotate_signed_prekey_if_due(&mut old, later);
        let retired_id = old.retired_signed_prekeys[0].prekey.id;
        let v2 = IdentityV2::migrate_from_v1(&old, T0, &mut rng);
        assert!(v2.device.spk_by_id(retired_id).is_some());
        assert!(v2.device.spk_by_id(v2.device.spk.id).is_some());
        assert!(v2.device.spk_by_id(9999).is_none());
    }

    #[test]
    fn the_first_list_is_accepted_by_a_contact_pinned_to_ik_sign() {
        // V11, the core's part: gen 1, seq 1, dev_dh = ik_dh, accepted
        // without a warning by whoever pinned ik_sign; next in force at once.
        let v1 = create_identity();
        let mut rng = drbg();
        let v2 = IdentityV2::migrate_from_v1(&v1, T0, &mut rng);
        let next = ReserveKey::generate().next();
        let list = v2.first_list(T0 as u64, next, &mut rng).unwrap();
        list.verify().unwrap();
        assert_eq!((list.body.gen, list.body.seq), (1, 1));
        assert_eq!(list.body.expires - list.body.issued, MAX_VALIDITY_SECS);
        let e = &list.body.entries[0];
        assert_eq!(list.body.entries.len(), 1);
        assert!(e.is_primary() && e.may_sign_groups());
        assert_eq!(e.dev_dh, v1.ik_dh.pub_bytes);
        assert_eq!(e.id, v2.device.id);
        let chain = Chain::first(list, &v1.ik_sign.pub_bytes, T0 as u64, |_| false).unwrap();
        assert_eq!(chain.next_in_force(T0 as u64), next);

        // A linked device has no A and cannot sign one.
        let linked = IdentityV2 {
            device: DeviceIdentity::generate_with_rng(T0, &mut rng),
            account: None,
        };
        assert_eq!(
            linked.first_list(T0 as u64, [0; 32], &mut rng).unwrap_err(),
            DeviceError::Key
        );
    }

    #[test]
    fn a_new_account_has_fresh_keys_that_agree() {
        let mut rng = drbg();
        let id = IdentityV2::new_account_with_rng(T0, &mut rng);
        let d = &id.device;
        assert_eq!(d.spk.created_at, T0);
        assert_eq!(d.pq.current.created_at, T0);
        // dev_dh is a real X25519 pair, so it can make dh_sig.
        let e = d.entry_with_rng(
            &id.account.as_ref().unwrap().a.pub_bytes,
            FLAG_PRIMARY,
            (1, 1),
            &mut rng,
        );
        e.verify(&id.account.as_ref().unwrap().a.pub_bytes).unwrap();
        assert!(xeddsa::convert_mont(&d.dev_dh.pub_bytes).is_some());
        let other = IdentityV2::new_account_with_rng(T0, &mut rng);
        assert_ne!(other.device.id, d.id);
        assert_ne!(
            other.account.unwrap().a.pub_bytes,
            id.account.unwrap().a.pub_bytes
        );
    }

    #[test]
    fn both_prekeys_rotate_every_30_days_and_are_kept_45() {
        let mut rng = drbg();
        let mut d = DeviceIdentity::generate_with_rng(T0, &mut rng);
        let (spk1, pq1) = (d.spk.id, d.pq.current.id);
        assert!(!d.rotate_prekeys_if_due_with_rng(T0 + 30 * DAY - 1, &mut rng));
        let rotated_at = T0 + 30 * DAY;
        assert!(d.rotate_prekeys_if_due_with_rng(rotated_at, &mut rng));
        assert_ne!(d.spk.id, spk1);
        assert_ne!(d.pq.current.id, pq1);
        d.signed_spk().verify(&d.dev_sign.pub_bytes).unwrap();
        assert!(d.spk_by_id(spk1).is_some());
        assert!(d.pq.by_id(pq1).is_some());

        assert!(!d.rotate_prekeys_if_due_with_rng(rotated_at + 30 * DAY - 1, &mut rng));
        // At 30 days the next rotation; the first ones are still within 45.
        assert!(d.rotate_prekeys_if_due_with_rng(rotated_at + 30 * DAY, &mut rng));
        assert!(d.spk_by_id(spk1).is_some());
        assert_eq!(d.retired_spks.len(), 2);
        // 45 days after it retired, the first SPK is gone.
        assert!(d.rotate_prekeys_if_due_with_rng(rotated_at + 45 * DAY, &mut rng));
        assert!(d.spk_by_id(spk1).is_none());
        assert!(d.pq.by_id(pq1).is_none());
        assert_eq!(d.retired_spks.len(), 1);
    }

    #[test]
    fn the_vault_form_keeps_private_keys_and_derives_the_rest() {
        let mut rng = drbg();
        let mut id = IdentityV2::migrate_from_v1(&create_identity(), T0, &mut rng);
        // The migrated SPK was created by `create_identity` at the real
        // time: rotate 30 days after that, not after T0.
        let due = id.device.spk.created_at.max(T0) + 30 * DAY;
        id.device.rotate_prekeys_if_due_with_rng(due, &mut rng);
        let s = to_serialized(&id);
        let json = serde_json::to_string(&s).unwrap();
        let back = from_serialized(&s).unwrap();
        assert_eq!(serde_json::to_string(&to_serialized(&back)).unwrap(), json);
        assert_eq!(back.device.dev_dh.pub_bytes, id.device.dev_dh.pub_bytes);
        assert_eq!(back.device.dev_sign.pub_bytes, id.device.dev_sign.pub_bytes);
        assert_eq!(
            back.device.spk.keypair.pub_bytes,
            id.device.spk.keypair.pub_bytes
        );
        assert_eq!(back.device.retired_spks.len(), 1);
        assert_eq!(
            back.device.pq.current.secret.seed(),
            id.device.pq.current.secret.seed()
        );
        let acct = back.account.as_ref().unwrap();
        assert_eq!(acct.a.pub_bytes, id.account.as_ref().unwrap().a.pub_bytes);
        assert_eq!(
            acct.nostr.pub_bytes,
            id.account.as_ref().unwrap().nostr.pub_bytes
        );
        // No public key is stored, so none can disagree with its private key.
        let id_pub = hex::encode(id.device.dev_dh.pub_bytes);
        assert!(!json.contains(&id_pub));

        // Malformed fields are refused.
        for (from, to) in [
            (hex::encode(id.device.dev_sign.priv_bytes), "00".to_string()),
            (
                hex::encode(id.device.pq.current.secret.seed()),
                "zz".repeat(64),
            ),
        ] {
            let bad: SerializedIdentityV2 =
                serde_json::from_str(&json.replace(&from, &to)).unwrap();
            assert!(from_serialized(&bad).is_none());
        }
    }
}
