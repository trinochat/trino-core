//! The device list of an account (`diseno-vinculacion.md` §3 and §21.4;
//! VI-1).
//!
//! An account is its account key `A` (Ed25519, today's `ik_sign`) and up to
//! five devices. `A` signs the list of devices; each device signs its own
//! entry twice, with `dev_sign` (`d_sig`) and with its X25519 key `dev_dh`
//! (`dh_sig`, XEdDSA), so nobody can list a key they do not hold.
//!
//! - [`list`]: the binary format, its signatures and its hash.
//!
//! The list only ever travels inside the ratchet or sealed in the account
//! mailbox (§3.4), never in a public event.

pub mod list;

pub use list::{DeviceList, Entry, ListBody};

use thiserror::Error;

/// Why a device list, an entry or a retirement is refused.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DeviceError {
    /// Wrong length, domain, count, flags or rotation fields.
    #[error("malformed device list")]
    Malformed,
    /// A signature suite this version does not use (`0x02` is reserved).
    #[error("unknown signature suite {0}")]
    SigSuite(u8),
    /// `A`'s signature over the list does not verify.
    #[error("the account signature does not verify")]
    Signature,
    /// The reserve key's signature over a rotation does not verify.
    #[error("the rotation signature does not verify")]
    RotationSignature,
    /// An entry's `d_sig` or `dh_sig` does not verify.
    #[error("the entry of device {0} does not verify")]
    Entry(u32),
    /// The same `dev_sign`, `dev_dh` or id twice in one list.
    #[error("a device key or id appears twice")]
    Duplicate,
    /// Zero or several primaries, or a rotation with more than one device.
    #[error("a list needs exactly one primary")]
    Primary,
    /// `expires` is not after `issued`, or more than 90 days after it.
    #[error("the validity window is wrong")]
    Validity,
    /// The key used to sign is not the one the list names.
    #[error("the signing key is not the list's")]
    Key,
}
