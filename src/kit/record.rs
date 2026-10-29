//! What a device keeps of the kit: the vault's `kit` field
//! (`diseno-vinculacion.md` §23.1, at most 1024 bytes).
//!
//! ```text
//! record = version 1 ‖ h_check 32 ‖ next 32 ‖ blob 92            = 157 bytes
//! ```
//!
//! Never the words nor `E` (`Recuperacion/diseno.md` §3.3): there is no "show
//! my words again", and a lost sheet means a new kit. `h_check` runs the
//! sheet drill, `next` goes into the device list without opening anything,
//! and the blob opens only with the words. Without a kit there is no record,
//! and the device list carries a `next` of zeros (§2.3).
//!
//! Dates and reminders (created, last drilled) are the app's, not part of
//! this record.

use super::Kit;
use crate::kdf::KdfError;
use crate::reserve::{ReserveError, ReserveKey, BLOB_LEN};
use thiserror::Error;

/// Length of a record.
pub const RECORD_LEN: usize = 1 + 32 + 32 + BLOB_LEN;
const RECORD_VERSION: u8 = 1;
// It must fit the vault's `kit` field.
const _: () = assert!(RECORD_LEN <= crate::vault_v3::MAX_KIT_LEN);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecordError {
    #[error("a kit record is 157 bytes, got {0}")]
    Length(usize),
    #[error("unknown kit record version {0}")]
    Version(u8),
    #[error(transparent)]
    Kdf(#[from] KdfError),
    #[error(transparent)]
    Reserve(#[from] ReserveError),
}

/// The kit's record in the vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KitRecord {
    pub h_check: [u8; 32],
    pub next: [u8; 32],
    pub blob: [u8; BLOB_LEN],
}

impl KitRecord {
    /// Wraps `reserve` with `kit` (one Argon2id).
    pub fn create(kit: &Kit, reserve: &ReserveKey) -> Result<KitRecord, RecordError> {
        let keys = kit.derive()?;
        Ok(KitRecord {
            h_check: keys.h_check,
            next: reserve.next(),
            blob: reserve.seal(&keys.k_reserva),
        })
    }

    /// Opens the reserve key with the kit's words (one Argon2id).
    pub fn open_reserve(&self, kit: &Kit) -> Result<ReserveKey, RecordError> {
        let keys = kit.derive()?;
        Ok(ReserveKey::open(&keys.k_reserva, &self.blob, &self.next)?)
    }

    pub fn to_bytes(&self) -> [u8; RECORD_LEN] {
        let mut out = [0u8; RECORD_LEN];
        out[0] = RECORD_VERSION;
        out[1..33].copy_from_slice(&self.h_check);
        out[33..65].copy_from_slice(&self.next);
        out[65..].copy_from_slice(&self.blob);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<KitRecord, RecordError> {
        if bytes.len() != RECORD_LEN {
            return Err(RecordError::Length(bytes.len()));
        }
        if bytes[0] != RECORD_VERSION {
            return Err(RecordError::Version(bytes[0]));
        }
        Ok(KitRecord {
            h_check: bytes[1..33].try_into().expect("length checked"),
            next: bytes[33..65].try_into().expect("length checked"),
            blob: bytes[65..].try_into().expect("length checked"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "test-kdf"))]
    use crate::kit::ENTROPY_LEN;
    use serde_json::Value;

    const RESERVE: &str = include_str!("../../tests/vectors/reserve.json");

    fn cases() -> Vec<Value> {
        serde_json::from_str::<Value>(RESERVE).unwrap()["cases"]
            .as_array()
            .unwrap()
            .clone()
    }

    fn bytes(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap()).unwrap()
    }

    #[test]
    fn the_record_matches_the_independent_vectors() {
        for c in cases() {
            let record = KitRecord::from_bytes(&bytes(&c["record"])).unwrap();
            assert_eq!(record.h_check.to_vec(), bytes(&c["h_check"]));
            assert_eq!(record.next.to_vec(), bytes(&c["next"]));
            assert_eq!(record.blob.to_vec(), bytes(&c["blob"]));
            assert_eq!(record.to_bytes().to_vec(), bytes(&c["record"]));
        }
    }

    #[test]
    #[cfg(not(feature = "test-kdf"))]
    fn the_all_zero_kit_opens_the_openssl_record() {
        // kit.json's all-zero kit gives the k_reserva that sealed case 0.
        let c = &cases()[0];
        let record = KitRecord::from_bytes(&bytes(&c["record"])).unwrap();
        let kit = Kit::from_entropy([0; ENTROPY_LEN]);
        assert!(kit.matches(&record.h_check).unwrap());
        let key = record.open_reserve(&kit).unwrap();
        assert_eq!(key.ed_public().to_vec(), bytes(&c["ed_pub"]));
        let other = Kit::from_entropy([1; ENTROPY_LEN]);
        assert_eq!(
            record.open_reserve(&other).unwrap_err(),
            RecordError::Reserve(ReserveError::Blob)
        );
    }

    #[test]
    #[cfg(not(feature = "test-kdf"))]
    fn a_new_record_opens_with_its_kit() {
        let kit = Kit::generate();
        let reserve = ReserveKey::generate();
        let record = KitRecord::create(&kit, &reserve).unwrap();
        assert_eq!(record.next, reserve.next());
        assert!(kit.matches(&record.h_check).unwrap());
        let back = KitRecord::from_bytes(&record.to_bytes()).unwrap();
        assert_eq!(back.open_reserve(&kit).unwrap().next(), reserve.next());
    }

    #[test]
    fn a_bad_record_is_refused() {
        let good = bytes(&cases()[0]["record"]);
        assert_eq!(
            KitRecord::from_bytes(&good[..RECORD_LEN - 1]).unwrap_err(),
            RecordError::Length(RECORD_LEN - 1)
        );
        let mut longer = good.clone();
        longer.push(0);
        assert_eq!(
            KitRecord::from_bytes(&longer).unwrap_err(),
            RecordError::Length(RECORD_LEN + 1)
        );
        let mut v2 = good;
        v2[0] = 2;
        assert_eq!(
            KitRecord::from_bytes(&v2).unwrap_err(),
            RecordError::Version(2)
        );
    }

    #[test]
    fn a_record_is_157_bytes() {
        assert_eq!(RECORD_LEN, 157);
    }
}
