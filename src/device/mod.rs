//! The device list of an account (`diseno-vinculacion.md` §3 and §21.4;
//! VI-1).
//!
//! An account is its account key `A` (Ed25519, today's `ik_sign`) and up to
//! five devices. `A` signs the list of devices; each device signs its own
//! entry twice, with `dev_sign` (`d_sig`) and with its X25519 key `dev_dh`
//! (`dh_sig`, XEdDSA), so nobody can list a key they do not hold.
//!
//! - [`list`]: the binary format, its signatures and its hash;
//! - [`chain`]: what a receiver keeps of an account, and the eight rules
//!   for accepting a new list;
//! - [`retire`]: a device that unlinks itself;
//! - [`echo`]: the `dl` echo every message carries;
//! - [`bundle`]: the list with each device's prekeys, compact or full;
//! - [`handshake`]: the handshake bound to the lists (RV-06).
//!
//! The list only ever travels inside the ratchet or sealed in the account
//! mailbox (§3.4), never in a public event.

pub mod bundle;
pub mod chain;
pub mod echo;
pub mod handshake;
pub mod list;
pub mod retire;

pub use bundle::{DeviceBundle, DevicePrekeys};
pub use chain::{Accepted, Chain, PendingNext};
pub use echo::{on_echo, Echo, EchoActions, ListMark};
pub use handshake::{check_peer_device, peer_classical, peer_prekeys};
pub use list::{DeviceList, Entry, ListBody};
pub use retire::Retirement;

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
    /// `A`'s signature over the list, or a device's over its retirement,
    /// does not verify.
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
    /// The key used to sign is not the one the list names, or a rotation
    /// reuses the old `A` or the reserve key as the new `A`.
    #[error("the signing key is not the list's")]
    Key,
    /// Rule 1: not this account's chain.
    #[error("the list is not this account's")]
    WrongAccount,
    /// Rule 1: a normal list with another generation, or a rotation that
    /// is not the next one.
    #[error("the generation does not follow")]
    Generation,
    /// Rule 2: (`gen`, `seq`) does not grow. Also the list already held.
    #[error("the list is not newer than the one held")]
    Stale,
    /// Rule 2: `seq` grows by more than 2^20.
    #[error("seq grows by more than 2^20")]
    SeqJump,
    /// Rule 3: `seq` is the next one but `prev` is not the list held.
    #[error("prev is not the list held")]
    BrokenPrev,
    /// Rule 4: a device key belongs to another account the caller knows.
    /// Never dropped silently: the app warns.
    #[error("a device key belongs to another account")]
    Collision([u8; 32]),
    /// Rule 5: a removed or retired `dev_sign` comes back.
    #[error("a removed device comes back")]
    Removed([u8; 32]),
    /// Rule 6: the list has expired.
    #[error("the list has expired")]
    Expired,
    /// Rule 1: the reserve key of a rotation is not the one in force.
    #[error("the rotation's reserve key is not the one in force")]
    Reserve,
    /// Two different lists of the chain with the same (`gen`, `seq`). The
    /// first one stays.
    #[error("fork at generation {gen}, seq {seq}")]
    Fork { gen: u32, seq: u64 },
    /// A retirement names no device of the list held.
    #[error("no such device")]
    UnknownDevice,
    /// A device's prekey is not signed by its `dev_sign`.
    #[error("a prekey of device {0} does not verify")]
    Prekey(u32),
    /// A bundle whose list is not the one held for its account.
    #[error("the bundle is not of the list held")]
    NotCurrent,
    /// A compact bundle has no post-quantum prekey: use PQ-11.
    #[error("no post-quantum prekey for this device")]
    NoPqPrekey,
    /// The primary holds `A`: it cannot retire, only hand it over.
    #[error("the primary cannot retire")]
    PrimaryRetirement,
}
