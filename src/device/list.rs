//! The device list's binary format (`diseno-vinculacion.md` §3.1, with the
//! §21.4 header). All integers are big-endian.
//!
//! ```text
//! list  = "trino/devices/v1\0" 17 ‖ sig_suite u8 ‖ A 32 ‖ gen u32 ‖ seq u64 ‖ issued u64
//!       ‖ expires u64 ‖ prev 32 ‖ next 32 ‖ rot 32 ‖ rot_key 32 ‖ rot_pqh 32
//!       ‖ n u8 (1..=5) ‖ entries[n] ‖ sig 64 ‖ rot_sig 64                 → 367 + 209·n bytes
//! entry = id u32 ‖ flags u8 (bit0 primary, bit1 groups) ‖ dev_sign 32 ‖ dev_dh 32
//!       ‖ since (gen u32, seq u64) ‖ d_sig 64 ‖ dh_sig 64                 → 209 bytes
//! d_sig   = Ed25519(dev_sign, "trino/device/v1\0" ‖ A ‖ id ‖ dev_dh)
//! dh_sig  = XEdDSA(dev_dh, "trino/device-dh/v1\0" ‖ A ‖ id ‖ dev_sign)
//! sig     = Ed25519(A, everything before sig)
//! rot_sig = Ed25519(rot_key, the same bytes) in a rotation; zeros otherwise
//! ```
//!
//! - **`sig_suite` is `0x01`** (Ed25519). `0x02` is reserved for a future
//!   post-quantum rotation (§21.1); any other value is refused.
//! - **A rotation** (§2.3, §8.3) names the old `A` in `rot`, the reserve
//!   key `B_ed` in `rot_key` and `SHA-256(B_pq_pub)` in `rot_pqh`, and `B_ed`
//!   signs `rot_sig`. Outside a rotation the four fields are zero; a list
//!   that sets some of them and not the others is malformed.
//! - **Every Ed25519 signature is checked strictly** (no small-order keys,
//!   no malleable signatures), and `dh_sig` with [`crate::xeddsa`].
//! - **Unknown flag bits are refused**, so a later meaning cannot be
//!   misread by this version.
//!
//! [`DeviceList::verify`] checks what a list proves on its own: its
//! signatures, its entries, no key or id twice, exactly one primary (and a
//! single device in a rotation), and a validity window of at most 90 days.
//! Whether it may replace the list a receiver holds is [`super::chain`]'s.
//!
//! The tests check lists made by `tests/vectors/device_list.py`.

use super::DeviceError;
use crate::crypto::sha256;
use crate::identity::{ed25519_sign, KeyPair};
use crate::reserve::ReserveKey;
use crate::xeddsa;
use ed25519_dalek::{Signature, VerifyingKey};
use rand_core::{CryptoRng, OsRng, RngCore};

/// The list's domain, its first 17 bytes.
pub const LIST_DOMAIN: &[u8; 17] = b"trino/devices/v1\0";
const ENTRY_DOMAIN: &[u8] = b"trino/device/v1\0";
const ENTRY_DH_DOMAIN: &[u8] = b"trino/device-dh/v1\0";

/// The only signature suite: Ed25519.
pub const SIG_SUITE_ED25519: u8 = 0x01;
/// The most devices an account has (DV-09).
pub const MAX_DEVICES: usize = 5;
/// An entry's length.
pub const ENTRY_LEN: usize = 209;
/// Everything up to and including `n`.
const HEAD_LEN: usize = 17 + 1 + 32 + 4 + 8 + 8 + 8 + 5 * 32 + 1;
/// A list's length without its entries: 367.
pub const LIST_FIXED_LEN: usize = HEAD_LEN + 64 + 64;
/// Longest a list can be: five entries, 1412 bytes.
pub const MAX_LIST_LEN: usize = list_len(MAX_DEVICES);
/// Entry flag: the primary device, which holds `A`.
pub const FLAG_PRIMARY: u8 = 0x01;
/// Entry flag: may sign group rosters (§9).
pub const FLAG_GROUPS: u8 = 0x02;
/// The longest a list may be valid for, from `issued` (DV-05).
pub const MAX_VALIDITY_SECS: u64 = 90 * 24 * 60 * 60;

const ZERO32: [u8; 32] = [0; 32];

/// The length of a list with `n` entries.
pub const fn list_len(n: usize) -> usize {
    LIST_FIXED_LEN + ENTRY_LEN * n
}

/// One device of the list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Random, never reused within the account.
    pub id: u32,
    pub flags: u8,
    pub dev_sign: [u8; 32],
    pub dev_dh: [u8; 32],
    /// The (`gen`, `seq`) of the list that first named this device.
    pub since: (u32, u64),
    pub d_sig: [u8; 64],
    pub dh_sig: [u8; 64],
}

/// Everything a list says, without its two signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListBody {
    /// `A`, the account key (in a rotation, the new `A*`).
    pub account: [u8; 32],
    /// Generation: one more with every rotation.
    pub gen: u32,
    /// Within the generation, from 1.
    pub seq: u64,
    /// Network time when it was signed.
    pub issued: u64,
    /// When it stops being valid; at most 90 days after `issued`.
    pub expires: u64,
    /// SHA-256 of the previous list, zeros in the first.
    pub prev: [u8; 32],
    /// The reserve commitment (`reserve::commitment`), or zeros.
    pub next: [u8; 32],
    /// In a rotation, the old `A`; zeros otherwise.
    pub rot: [u8; 32],
    /// In a rotation, `B_ed_pub`; zeros otherwise.
    pub rot_key: [u8; 32],
    /// In a rotation, `SHA-256(B_pq_pub)`; zeros otherwise.
    pub rot_pqh: [u8; 32],
    pub entries: Vec<Entry>,
}

/// A signed device list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceList {
    pub body: ListBody,
    pub sig: [u8; 64],
    pub rot_sig: [u8; 64],
}

impl Entry {
    /// The entry of the device with these keys in account `account`.
    pub fn sign(
        account: &[u8; 32],
        id: u32,
        flags: u8,
        since: (u32, u64),
        dev_sign: &KeyPair,
        dev_dh: &KeyPair,
    ) -> Entry {
        Entry::sign_with_rng(account, id, flags, since, dev_sign, dev_dh, &mut OsRng)
    }

    /// [`Entry::sign`] with XEdDSA's random bytes from `rng`.
    pub fn sign_with_rng<R: RngCore + CryptoRng>(
        account: &[u8; 32],
        id: u32,
        flags: u8,
        since: (u32, u64),
        dev_sign: &KeyPair,
        dev_dh: &KeyPair,
        rng: &mut R,
    ) -> Entry {
        Entry {
            id,
            flags,
            dev_sign: dev_sign.pub_bytes,
            dev_dh: dev_dh.pub_bytes,
            since,
            d_sig: ed25519_sign(dev_sign, &d_sig_message(account, id, &dev_dh.pub_bytes)),
            dh_sig: xeddsa::sign_with_rng(
                &dev_dh.priv_bytes,
                &dh_sig_message(account, id, &dev_sign.pub_bytes),
                rng,
            ),
        }
    }

    pub fn is_primary(&self) -> bool {
        self.flags & FLAG_PRIMARY != 0
    }

    pub fn may_sign_groups(&self) -> bool {
        self.flags & FLAG_GROUPS != 0
    }

    /// Checks `d_sig` and `dh_sig` for account `account`.
    pub fn verify(&self, account: &[u8; 32]) -> Result<(), DeviceError> {
        let d_ok = ed25519_verify_strict(
            &self.dev_sign,
            &d_sig_message(account, self.id, &self.dev_dh),
            &self.d_sig,
        );
        let dh_ok = xeddsa::verify(
            &self.dev_dh,
            &dh_sig_message(account, self.id, &self.dev_sign),
            &self.dh_sig,
        );
        if d_ok && dh_ok {
            Ok(())
        } else {
            Err(DeviceError::Entry(self.id))
        }
    }

    /// The entry's 209 bytes, as a list carries it. A `trino3:` contact
    /// code carries the primary's entry on its own (`diseno-vinculacion.md`
    /// §13.3).
    pub fn to_bytes(&self) -> [u8; ENTRY_LEN] {
        let mut out = Vec::with_capacity(ENTRY_LEN);
        self.encode_into(&mut out);
        out.try_into().expect("an entry is ENTRY_LEN bytes")
    }

    /// An entry from exactly [`ENTRY_LEN`] bytes. Its signatures are not
    /// checked here: [`Entry::verify`] does, for the account it claims.
    pub fn from_bytes(b: &[u8]) -> Result<Entry, DeviceError> {
        if b.len() != ENTRY_LEN {
            return Err(DeviceError::Malformed);
        }
        Entry::decode(b)
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id.to_be_bytes());
        out.push(self.flags);
        out.extend_from_slice(&self.dev_sign);
        out.extend_from_slice(&self.dev_dh);
        out.extend_from_slice(&self.since.0.to_be_bytes());
        out.extend_from_slice(&self.since.1.to_be_bytes());
        out.extend_from_slice(&self.d_sig);
        out.extend_from_slice(&self.dh_sig);
    }

    fn decode(b: &[u8]) -> Result<Entry, DeviceError> {
        let mut r = Reader(b);
        let entry = Entry {
            id: r.u32(),
            flags: r.u8(),
            dev_sign: r.take(),
            dev_dh: r.take(),
            since: (r.u32(), r.u64()),
            d_sig: r.take(),
            dh_sig: r.take(),
        };
        if entry.flags & !(FLAG_PRIMARY | FLAG_GROUPS) != 0 {
            return Err(DeviceError::Malformed);
        }
        Ok(entry)
    }
}

fn d_sig_message(account: &[u8; 32], id: u32, dev_dh: &[u8; 32]) -> Vec<u8> {
    [ENTRY_DOMAIN, account, &id.to_be_bytes(), dev_dh].concat()
}

fn dh_sig_message(account: &[u8; 32], id: u32, dev_sign: &[u8; 32]) -> Vec<u8> {
    [ENTRY_DH_DOMAIN, account, &id.to_be_bytes(), dev_sign].concat()
}

/// Reads fixed-size fields from a slice whose length was already checked.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let (head, rest) = self.0.split_at(N);
        self.0 = rest;
        head.try_into().expect("length checked by the caller")
    }

    fn u8(&mut self) -> u8 {
        self.take::<1>()[0]
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take())
    }

    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.take())
    }
}

impl ListBody {
    /// Whether this is a rotation (it names an old `A`).
    pub fn is_rotation(&self) -> bool {
        self.rot != ZERO32
    }

    /// The signed bytes: everything before `sig`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEAD_LEN + ENTRY_LEN * self.entries.len());
        out.extend_from_slice(LIST_DOMAIN);
        out.push(SIG_SUITE_ED25519);
        out.extend_from_slice(&self.account);
        out.extend_from_slice(&self.gen.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.issued.to_be_bytes());
        out.extend_from_slice(&self.expires.to_be_bytes());
        for field in [
            &self.prev,
            &self.next,
            &self.rot,
            &self.rot_key,
            &self.rot_pqh,
        ] {
            out.extend_from_slice(field);
        }
        out.push(self.entries.len() as u8);
        for e in &self.entries {
            e.encode_into(&mut out);
        }
        out
    }

    /// Signs a list that is not a rotation with the account key.
    pub fn sign(self, account_key: &KeyPair) -> Result<DeviceList, DeviceError> {
        if self.is_rotation() || self.rot_key != ZERO32 || self.rot_pqh != ZERO32 {
            return Err(DeviceError::Malformed);
        }
        if account_key.pub_bytes != self.account {
            return Err(DeviceError::Key);
        }
        let sig = ed25519_sign(account_key, &self.to_bytes());
        Ok(DeviceList {
            body: self,
            sig,
            rot_sig: [0; 64],
        })
    }

    /// Signs a rotation with the new account key `A*` and the reserve key,
    /// filling in `rot_key` and `rot_pqh`. `rot` must already name the old
    /// `A`.
    pub fn sign_rotation(
        self,
        account_key: &KeyPair,
        reserve: &ReserveKey,
    ) -> Result<DeviceList, DeviceError> {
        if !self.is_rotation() {
            return Err(DeviceError::Malformed);
        }
        if account_key.pub_bytes != self.account {
            return Err(DeviceError::Key);
        }
        let mut body = self;
        body.rot_key = reserve.ed_public();
        body.rot_pqh = reserve.pq_hash();
        let bytes = body.to_bytes();
        Ok(DeviceList {
            sig: ed25519_sign(account_key, &bytes),
            rot_sig: reserve.sign_rotation(&bytes),
            body,
        })
    }
}

impl DeviceList {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.body.to_bytes();
        out.extend_from_slice(&self.sig);
        out.extend_from_slice(&self.rot_sig);
        out
    }

    /// A list that fills `b` exactly.
    pub fn decode(b: &[u8]) -> Result<DeviceList, DeviceError> {
        let (list, used) = DeviceList::decode_prefix(b)?;
        if used != b.len() {
            return Err(DeviceError::Malformed);
        }
        Ok(list)
    }

    /// A list at the start of `b`, and how many bytes it took.
    pub fn decode_prefix(b: &[u8]) -> Result<(DeviceList, usize), DeviceError> {
        if b.len() < HEAD_LEN || &b[..LIST_DOMAIN.len()] != LIST_DOMAIN {
            return Err(DeviceError::Malformed);
        }
        let suite = b[LIST_DOMAIN.len()];
        if suite != SIG_SUITE_ED25519 {
            return Err(DeviceError::SigSuite(suite));
        }
        let n = b[HEAD_LEN - 1] as usize;
        if !(1..=MAX_DEVICES).contains(&n) || b.len() < list_len(n) {
            return Err(DeviceError::Malformed);
        }
        let mut r = Reader(&b[LIST_DOMAIN.len() + 1..list_len(n)]);
        let mut body = ListBody {
            account: r.take(),
            gen: r.u32(),
            seq: r.u64(),
            issued: r.u64(),
            expires: r.u64(),
            prev: r.take(),
            next: r.take(),
            rot: r.take(),
            rot_key: r.take(),
            rot_pqh: r.take(),
            entries: Vec::with_capacity(n),
        };
        let _n = r.u8();
        for _ in 0..n {
            body.entries.push(Entry::decode(&r.take::<ENTRY_LEN>())?);
        }
        let list = DeviceList {
            body,
            sig: r.take(),
            rot_sig: r.take(),
        };
        // A rotation sets its three fields and its signature; any other
        // list sets none of them.
        let b = &list.body;
        let set = [
            b.rot != ZERO32,
            b.rot_key != ZERO32,
            b.rot_pqh != ZERO32,
            list.rot_sig != [0; 64],
        ];
        if set.iter().any(|&f| f) && !set.iter().all(|&f| f) {
            return Err(DeviceError::Malformed);
        }
        Ok((list, list_len(n)))
    }

    /// SHA-256 of the encoded list: what `prev` and the echo name.
    pub fn hash(&self) -> [u8; 32] {
        sha256(&self.encode())
    }

    /// Checks everything the list proves on its own (see the module docs).
    pub fn verify(&self) -> Result<(), DeviceError> {
        let b = &self.body;
        let bytes = b.to_bytes();
        if !ed25519_verify_strict(&b.account, &bytes, &self.sig) {
            return Err(DeviceError::Signature);
        }
        if b.is_rotation() {
            if b.account == b.rot_key || b.account == b.rot {
                return Err(DeviceError::Key);
            }
            if !ed25519_verify_strict(&b.rot_key, &bytes, &self.rot_sig) {
                return Err(DeviceError::RotationSignature);
            }
        }
        for (i, e) in b.entries.iter().enumerate() {
            if e.since > (b.gen, b.seq) {
                return Err(DeviceError::Malformed);
            }
            e.verify(&b.account)?;
            for other in &b.entries[..i] {
                if other.id == e.id || other.dev_sign == e.dev_sign || other.dev_dh == e.dev_dh {
                    return Err(DeviceError::Duplicate);
                }
            }
        }
        let primaries = b.entries.iter().filter(|e| e.is_primary()).count();
        if primaries != 1 || (b.is_rotation() && b.entries.len() != 1) {
            return Err(DeviceError::Primary);
        }
        if b.expires <= b.issued || b.expires - b.issued > MAX_VALIDITY_SECS {
            return Err(DeviceError::Validity);
        }
        Ok(())
    }

    pub fn is_rotation(&self) -> bool {
        self.body.is_rotation()
    }

    /// The primary's entry. Only meaningful on a list that verifies.
    pub fn primary(&self) -> Option<&Entry> {
        self.body.entries.iter().find(|e| e.is_primary())
    }

    pub fn entry_by_id(&self, id: u32) -> Option<&Entry> {
        self.body.entries.iter().find(|e| e.id == id)
    }

    pub fn entry_by_dh(&self, dev_dh: &[u8; 32]) -> Option<&Entry> {
        self.body.entries.iter().find(|e| &e.dev_dh == dev_dh)
    }
}

/// Strict Ed25519 verification, as everywhere in the device list.
pub(crate) fn ed25519_verify_strict(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(public)
        .and_then(|k| k.verify_strict(msg, &Signature::from_bytes(sig)))
        .is_ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::identity::{generate_ed25519, generate_x25519};
    use ed25519_dalek::SigningKey;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../../tests/vectors/device_list.json");

    fn h<const N: usize>(v: &Value) -> [u8; N] {
        hex::decode(v.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    pub(crate) fn ed_from_seed(seed: &[u8; 32]) -> KeyPair {
        KeyPair {
            priv_bytes: *seed,
            pub_bytes: SigningKey::from_bytes(seed).verifying_key().to_bytes(),
        }
    }

    /// A device's two key pairs.
    pub(crate) struct Device {
        pub sign: KeyPair,
        pub dh: KeyPair,
    }

    impl Device {
        pub fn new() -> Device {
            Device {
                sign: generate_ed25519(),
                dh: generate_x25519(),
            }
        }

        pub fn entry(&self, account: &[u8; 32], id: u32, flags: u8) -> Entry {
            Entry::sign(account, id, flags, (1, 1), &self.sign, &self.dh)
        }
    }

    pub(crate) fn body(account: &[u8; 32], entries: Vec<Entry>) -> ListBody {
        ListBody {
            account: *account,
            gen: 1,
            seq: 1,
            issued: 1_793_000_000,
            expires: 1_793_000_000 + MAX_VALIDITY_SECS,
            prev: [0; 32],
            next: [0; 32],
            rot: [0; 32],
            rot_key: [0; 32],
            rot_pqh: [0; 32],
            entries,
        }
    }

    #[test]
    fn an_entry_alone_encodes_and_decodes_as_in_its_list() {
        let account = [7u8; 32];
        let device = Device::new();
        let entry = device.entry(&account, 0x0102_0304, FLAG_PRIMARY);
        let bytes = entry.to_bytes();
        // The same 209 bytes a list carries after its head.
        let mut in_list = Vec::new();
        entry.encode_into(&mut in_list);
        assert_eq!(bytes.as_slice(), in_list.as_slice());
        assert_eq!(&bytes[..5], &[1, 2, 3, 4, FLAG_PRIMARY]);
        let back = Entry::from_bytes(&bytes).unwrap();
        assert_eq!(back, entry);
        back.verify(&account).unwrap();
    }

    #[test]
    fn an_entry_of_another_length_or_with_unknown_flags_is_refused() {
        let entry = Device::new().entry(&[7; 32], 1, FLAG_PRIMARY);
        let bytes = entry.to_bytes();
        assert_eq!(
            Entry::from_bytes(&bytes[..208]),
            Err(DeviceError::Malformed)
        );
        let longer = [bytes.as_slice(), &[0]].concat();
        assert_eq!(Entry::from_bytes(&longer), Err(DeviceError::Malformed));
        let mut flags = bytes;
        flags[4] = 0x80;
        assert_eq!(Entry::from_bytes(&flags), Err(DeviceError::Malformed));
    }

    #[test]
    fn the_vector_lists_decode_verify_and_encode_back() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        let cases = v["cases"].as_array().unwrap();
        let lens: Vec<usize> = cases
            .iter()
            .map(|c| c["list"].as_str().unwrap().len() / 2)
            .collect();
        assert_eq!(lens, vec![576, 1412, 576], "367 + 209·n");
        for c in cases {
            let raw = hex::decode(c["list"].as_str().unwrap()).unwrap();
            let list = DeviceList::decode(&raw).unwrap();
            assert_eq!(list.encode(), raw);
            assert_eq!(list.hash(), h::<32>(&c["sha256"]));
            list.verify().unwrap();
            assert_eq!(
                list.body.entries.len() * ENTRY_LEN + LIST_FIXED_LEN,
                raw.len()
            );
        }
        assert_eq!(MAX_LIST_LEN, 1412);
    }

    #[test]
    fn the_vector_signatures_are_reproduced() {
        // Ed25519 is deterministic: the same body under the same keys gives
        // the same bytes. dh_sig carries XEdDSA's random Z, so it is kept.
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        for c in v["cases"].as_array().unwrap() {
            let raw = hex::decode(c["list"].as_str().unwrap()).unwrap();
            let list = DeviceList::decode(&raw).unwrap();
            let a = ed_from_seed(&h(&c["account_seed"]));
            assert_eq!(a.pub_bytes, list.body.account);
            for (e, d) in list
                .body
                .entries
                .iter()
                .zip(c["devices"].as_array().unwrap())
            {
                let dev_sign = ed_from_seed(&h(&d["dev_sign_seed"]));
                let mut msg = ENTRY_DOMAIN.to_vec();
                msg.extend_from_slice(&list.body.account);
                msg.extend_from_slice(&e.id.to_be_bytes());
                msg.extend_from_slice(&e.dev_dh);
                assert_eq!(ed25519_sign(&dev_sign, &msg), e.d_sig);
                let dh_priv: [u8; 32] = h(&d["dev_dh_priv"]);
                assert_eq!(
                    xeddsa::calculate_key_pair(&dh_priv).0,
                    xeddsa::convert_mont(&e.dev_dh).unwrap()
                );
            }
            let bytes = list.body.to_bytes();
            assert_eq!(bytes.len() + 128, raw.len());
            assert_eq!(ed25519_sign(&a, &bytes), list.sig);
            if list.is_rotation() {
                let b = ed_from_seed(&h(&c["reserve_seed"]));
                assert_eq!(b.pub_bytes, list.body.rot_key);
                assert_eq!(ed25519_sign(&b, &bytes), list.rot_sig);
                assert_eq!(list.body.rot_pqh, h::<32>(&c["reserve_pq_hash"]));
            } else {
                assert_eq!(list.rot_sig, [0; 64]);
            }
        }
    }

    #[test]
    fn a_list_signed_here_round_trips_and_verifies() {
        let a = generate_ed25519();
        let pc = Device::new();
        let phone = Device::new();
        let list = body(
            &a.pub_bytes,
            vec![
                pc.entry(&a.pub_bytes, 1, FLAG_PRIMARY | FLAG_GROUPS),
                phone.entry(&a.pub_bytes, 2, 0),
            ],
        )
        .sign(&a)
        .unwrap();
        list.verify().unwrap();
        let raw = list.encode();
        assert_eq!(raw.len(), list_len(2));
        assert_eq!(DeviceList::decode(&raw).unwrap(), list);
        assert_eq!(list.primary().unwrap().dev_dh, pc.dh.pub_bytes);
        assert!(list.primary().unwrap().may_sign_groups());
        assert_eq!(list.entry_by_dh(&phone.dh.pub_bytes).unwrap().id, 2);
        assert_eq!(list.entry_by_id(1).unwrap().dev_sign, pc.sign.pub_bytes);

        // Signing with a key that is not the list's `A` is refused.
        assert_eq!(
            body(&a.pub_bytes, vec![pc.entry(&a.pub_bytes, 1, FLAG_PRIMARY)])
                .sign(&generate_ed25519()),
            Err(DeviceError::Key)
        );
    }

    #[test]
    fn a_rotation_is_signed_by_the_new_account_and_the_reserve_key() {
        let old = generate_ed25519();
        let a_star = generate_ed25519();
        let reserve = ReserveKey::generate();
        let phone = Device::new();
        let mut b = body(
            &a_star.pub_bytes,
            vec![phone.entry(&a_star.pub_bytes, 7, FLAG_PRIMARY)],
        );
        b.gen = 2;
        b.rot = old.pub_bytes;
        let list = b.sign_rotation(&a_star, &reserve).unwrap();
        assert!(list.is_rotation());
        assert_eq!(list.body.rot_key, reserve.ed_public());
        assert_eq!(list.body.rot_pqh, reserve.pq_hash());
        list.verify().unwrap();
        assert_eq!(DeviceList::decode(&list.encode()).unwrap(), list);

        // A rotation needs `rot`; a list with `rot` needs `sign_rotation`.
        let plain = body(
            &a_star.pub_bytes,
            vec![phone.entry(&a_star.pub_bytes, 7, FLAG_PRIMARY)],
        );
        assert_eq!(
            plain.clone().sign_rotation(&a_star, &reserve),
            Err(DeviceError::Malformed)
        );
        let mut with_rot = plain;
        with_rot.rot = old.pub_bytes;
        assert_eq!(with_rot.sign(&a_star), Err(DeviceError::Malformed));
    }

    /// A valid two-device list and its encoding, to break.
    fn sample() -> (DeviceList, Vec<u8>) {
        let a = generate_ed25519();
        let list = body(
            &a.pub_bytes,
            vec![
                Device::new().entry(&a.pub_bytes, 1, FLAG_PRIMARY),
                Device::new().entry(&a.pub_bytes, 2, 0),
            ],
        )
        .sign(&a)
        .unwrap();
        let raw = list.encode();
        (list, raw)
    }

    #[test]
    fn any_changed_bit_is_refused() {
        // Every bit of a list is covered by a signature or by the format.
        let (_, raw) = sample();
        for i in 0..raw.len() * 8 {
            let mut bad = raw.clone();
            bad[i / 8] ^= 1 << (i % 8);
            let refused = match DeviceList::decode(&bad) {
                Err(_) => true,
                Ok(list) => list.verify().is_err(),
            };
            assert!(refused, "bit {i} (byte {})", i / 8);
        }
    }

    #[test]
    fn the_format_is_strict() {
        let (_, raw) = sample();
        // Cut, extended, another domain, another suite, unknown flags.
        assert_eq!(
            DeviceList::decode(&raw[..raw.len() - 1]),
            Err(DeviceError::Malformed)
        );
        let mut longer = raw.clone();
        longer.push(0);
        assert_eq!(DeviceList::decode(&longer), Err(DeviceError::Malformed));
        assert_eq!(DeviceList::decode_prefix(&longer).unwrap().1, raw.len());
        let mut domain = raw.clone();
        domain[15] = b'2';
        assert_eq!(DeviceList::decode(&domain), Err(DeviceError::Malformed));
        for suite in [0u8, 0x02, 0xFF] {
            let mut bad = raw.clone();
            bad[17] = suite;
            assert_eq!(DeviceList::decode(&bad), Err(DeviceError::SigSuite(suite)));
        }
        let mut flags = raw.clone();
        flags[HEAD_LEN + 4] |= 0x04;
        assert_eq!(DeviceList::decode(&flags), Err(DeviceError::Malformed));

        // n = 0 and n = 6 are refused even at the matching length.
        for n in [0usize, 6] {
            let mut bad = raw[..HEAD_LEN].to_vec();
            bad[HEAD_LEN - 1] = n as u8;
            bad.resize(list_len(n), 0);
            assert_eq!(DeviceList::decode(&bad), Err(DeviceError::Malformed));
        }

        // Rotation fields: all or nothing.
        let (list, _) = sample();
        let mut half = list.clone();
        half.body.rot_key = [9; 32];
        assert_eq!(
            DeviceList::decode(&half.encode()),
            Err(DeviceError::Malformed)
        );
        let mut only_sig = list;
        only_sig.rot_sig = [9; 64];
        assert_eq!(
            DeviceList::decode(&only_sig.encode()),
            Err(DeviceError::Malformed)
        );
    }

    #[test]
    fn an_entry_signed_for_another_account_or_with_another_key_fails() {
        let a = generate_ed25519();
        let other = generate_ed25519();
        let dev = Device::new();
        let entry = dev.entry(&a.pub_bytes, 1, FLAG_PRIMARY);
        entry.verify(&a.pub_bytes).unwrap();
        assert_eq!(entry.verify(&other.pub_bytes), Err(DeviceError::Entry(1)));

        // Someone else's dev_dh under my dev_sign: dh_sig cannot be made.
        let victim = generate_x25519();
        let mut stolen = entry.clone();
        stolen.dev_dh = victim.pub_bytes;
        stolen.d_sig = {
            let mut msg = ENTRY_DOMAIN.to_vec();
            msg.extend_from_slice(&a.pub_bytes);
            msg.extend_from_slice(&1u32.to_be_bytes());
            msg.extend_from_slice(&victim.pub_bytes);
            ed25519_sign(&dev.sign, &msg)
        };
        assert_eq!(stolen.verify(&a.pub_bytes), Err(DeviceError::Entry(1)));

        // Another id breaks both signatures.
        let mut moved = entry;
        moved.id = 2;
        assert_eq!(moved.verify(&a.pub_bytes), Err(DeviceError::Entry(2)));
    }

    #[test]
    fn duplicates_primaries_and_validity_are_checked() {
        let a = generate_ed25519();
        let dev = Device::new();
        let sign = |entries: Vec<Entry>| body(&a.pub_bytes, entries).sign(&a).unwrap();

        // The same device twice, or the same id twice.
        let twice = sign(vec![
            dev.entry(&a.pub_bytes, 1, FLAG_PRIMARY),
            dev.entry(&a.pub_bytes, 2, 0),
        ]);
        assert_eq!(twice.verify(), Err(DeviceError::Duplicate));
        let same_id = sign(vec![
            dev.entry(&a.pub_bytes, 1, FLAG_PRIMARY),
            Device::new().entry(&a.pub_bytes, 1, 0),
        ]);
        assert_eq!(same_id.verify(), Err(DeviceError::Duplicate));

        // Zero or two primaries.
        let none = sign(vec![dev.entry(&a.pub_bytes, 1, 0)]);
        assert_eq!(none.verify(), Err(DeviceError::Primary));
        let two = sign(vec![
            dev.entry(&a.pub_bytes, 1, FLAG_PRIMARY),
            Device::new().entry(&a.pub_bytes, 2, FLAG_PRIMARY),
        ]);
        assert_eq!(two.verify(), Err(DeviceError::Primary));

        // Valid for more than 90 days, or expiring before it is issued.
        let mut long = body(&a.pub_bytes, vec![dev.entry(&a.pub_bytes, 1, FLAG_PRIMARY)]);
        long.expires = long.issued + MAX_VALIDITY_SECS + 1;
        assert_eq!(long.sign(&a).unwrap().verify(), Err(DeviceError::Validity));
        let mut backwards = body(&a.pub_bytes, vec![dev.entry(&a.pub_bytes, 1, FLAG_PRIMARY)]);
        backwards.expires = backwards.issued;
        assert_eq!(
            backwards.sign(&a).unwrap().verify(),
            Err(DeviceError::Validity)
        );

        // `since` after the list itself.
        let mut early = dev.entry(&a.pub_bytes, 1, FLAG_PRIMARY);
        early.since = (1, 2);
        assert_eq!(sign(vec![early]).verify(), Err(DeviceError::Malformed));
    }

    #[test]
    fn a_rotation_has_one_device_and_keys_apart() {
        let old = generate_ed25519();
        let a_star = generate_ed25519();
        let reserve = ReserveKey::generate();
        let mut b = body(
            &a_star.pub_bytes,
            vec![
                Device::new().entry(&a_star.pub_bytes, 7, FLAG_PRIMARY),
                Device::new().entry(&a_star.pub_bytes, 8, 0),
            ],
        );
        b.gen = 2;
        b.rot = old.pub_bytes;
        assert_eq!(
            b.sign_rotation(&a_star, &reserve).unwrap().verify(),
            Err(DeviceError::Primary)
        );

        // The new A cannot be the reserve key, nor the old A.
        let mut same = body(
            &old.pub_bytes,
            vec![Device::new().entry(&old.pub_bytes, 7, FLAG_PRIMARY)],
        );
        same.gen = 2;
        same.rot = old.pub_bytes;
        assert_eq!(
            same.sign_rotation(&old, &reserve).unwrap().verify(),
            Err(DeviceError::Key)
        );

        // A rotation whose reserve signature is not B's.
        let mut fine = body(
            &a_star.pub_bytes,
            vec![Device::new().entry(&a_star.pub_bytes, 7, FLAG_PRIMARY)],
        );
        fine.gen = 2;
        fine.rot = old.pub_bytes;
        let mut list = fine.sign_rotation(&a_star, &reserve).unwrap();
        list.rot_sig = ed25519_sign(&generate_ed25519(), &list.body.to_bytes());
        assert_eq!(list.verify(), Err(DeviceError::RotationSignature));
    }
}
