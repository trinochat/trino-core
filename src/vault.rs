//! The sealed vault: the identity, its prekeys, a TOTP secret if the user
//! turned it on, and data the app keeps there, encrypted under a passphrase.
//!
//! On disk (`encode_vault`):
//!
//! | Bytes | Field                                              |
//! |-------|----------------------------------------------------|
//! | 6     | magic, `TRINO\0`                                   |
//! | 1     | format version: `2` is written, `1` is still read  |
//! | 1     | flags: bit 0 set means sealed without TOTP         |
//! | 16    | PBKDF2 salt                                        |
//! | 12    | AES-GCM nonce                                      |
//! | rest  | the JSON payload under AES-256-GCM                 |
//!
//! The key is PBKDF2-HMAC-SHA256 of the passphrase, 600 000 iterations.
//!
//! # Version 2
//!
//! What `seal_vault` writes. It differs from version 1 in two ways:
//!
//! - **The header is authenticated.** The 24 bytes before the nonce (magic,
//!   version, flags and salt) are the AES-GCM associated data, and AES-GCM
//!   binds the nonce itself, so a vault with any header byte changed does not
//!   open. The flags are still read before decrypting, as a hint, but once the
//!   vault opens they are the ones it was sealed with.
//! - **It can carry app data**, the payload's `app` field: 1 to
//!   `MAX_APP_DATA_LEN` bytes that the app keeps there, sealed under the same
//!   passphrase and TOTP rules as the identity. This crate treats them as
//!   opaque; the desktop app keeps the key to its local data there.
//!
//! The version byte changes, rather than a new flag bit, because of the
//! readers that came before. A reader that opened a vault with app data would
//! drop the field on its next re-seal, since it writes only the fields it
//! knows, and the app's data would go with it. trino-core 1bac851 checks the
//! version byte and never reads the flags; 4ce6775 checks the version and then
//! the flags. Both refuse version 2 with `UnsupportedVersion` before deriving
//! any key. Relabelling a version 2 vault as version 1 does not get it past
//! them either: the associated data no longer matches, and it fails to
//! decrypt.
//!
//! # Version 1
//!
//! Still read, so existing vaults open and the app can migrate them. Its
//! header is not authenticated, so nothing in it is trusted: the flags only
//! tell the UI whether to ask for a code (`vault_requires_totp`), and once the
//! payload is decrypted it alone decides. The flags byte was reserved, and
//! always zero, until TOTP became optional, so older vaults read as "TOTP on",
//! which is true of all of them. A version 1 vault never carries app data, and
//! one that does is refused.
//!
//! In either version, flag bits this crate does not know are rejected with
//! `VaultError::UnsupportedFlags` before any key derivation, as an unknown
//! version is: they are kept for format changes an older reader would misread.
//!
//! The TOTP code is checked after decryption, against a secret stored inside
//! the vault. It guards the unlock screen, not a stolen copy of the file:
//! whoever has the file and the passphrase has the secret too, and the app
//! data.

use crate::crypto::{
    aes_gcm_decrypt, aes_gcm_encrypt, pbkdf2_sha256, random_array, CryptoError, NONCE_SIZE,
};
use crate::identity::{
    decode_array_32, decode_array_64, Identity, IdentityError, KeyPair, OneTimePreKey,
    RetiredSignedPreKey, SignedPreKey,
};
use crate::kdf::KdfError;
use crate::totp::is_totp_code_valid;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const PBKDF2_ITERATIONS: u32 = 600_000;
const SALT_SIZE: usize = 16;
const VAULT_MAGIC: &[u8] = b"TRINO\0";
/// The version `seal_vault` writes: an authenticated header, and app data.
const VAULT_VERSION: u8 = 2;
/// The version before it, still read: no associated data, no app data.
const VAULT_VERSION_1: u8 = 1;
/// Magic, version, flags and salt: everything before the nonce, and the
/// associated data of a version 2 vault.
const HEADER_LEN: usize = VAULT_MAGIC.len() + 2 + SALT_SIZE;
/// Header flag: sealed without TOTP. A zero flags byte, as in every vault from
/// before TOTP became optional, means TOTP is on.
const FLAG_NO_TOTP: u8 = 0b0000_0001;
/// Every flag bit this version understands. Any other bit set is rejected.
const KNOWN_FLAGS: u8 = FLAG_NO_TOTP;
/// The most app data a vault carries, in bytes.
pub const MAX_APP_DATA_LEN: usize = 256;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("unsupported vault version: {0}")]
    UnsupportedVersion(u8),
    /// The header sets flag bits this version does not know, most likely from
    /// a newer Trino.
    #[error("unsupported vault flags: {0:#04x}")]
    UnsupportedFlags(u8),
    #[error("vault file is too short or corrupted")]
    Corrupted,
    #[error("not a trino vault (bad magic bytes)")]
    BadMagic,
    #[error("decryption failed (wrong passphrase or tampered vault)")]
    DecryptionFailed,
    /// The vault holds a TOTP secret and no code was given. Distinct from
    /// `InvalidTotp`, so the app can ask for the code instead of rejecting one.
    #[error("TOTP code required")]
    TotpRequired,
    #[error("invalid TOTP code")]
    InvalidTotp,
    #[error("malformed identity payload")]
    BadPayload,
    /// `seal_vault` was given app data that is empty or longer than
    /// `MAX_APP_DATA_LEN`.
    #[error("app data must be 1 to {max} bytes, got {0}", max = MAX_APP_DATA_LEN)]
    InvalidAppData(usize),
    /// The version 3 header names a KDF this version does not know.
    #[error("unsupported vault kdf: {0}")]
    UnsupportedKdf(u8),
    /// The KDF refused its parameters (out of bounds) or failed.
    #[error("kdf: {0}")]
    Kdf(#[from] KdfError),
    /// A field of a version 3 vault does not fit its fixed size.
    #[error("{what} is {len} bytes, more than the {max} a version 3 vault holds")]
    TooLarge {
        what: &'static str,
        len: usize,
        max: usize,
    },
    /// The new passphrase would open the emergency slot: it is the
    /// emergency key. The user picks another one.
    #[error("the new passphrase opens the emergency slot")]
    PassphraseOpensEmergencySlot,
    /// The emergency key would open another slot, which is the passphrase
    /// itself (or the recovery slot's key).
    #[error("the emergency key opens another slot")]
    EmergencyKeyOpensAnotherSlot,
    /// The empty account was given the `id_vault` of the vault it replaces.
    #[error("the empty account needs a new id_vault")]
    IdVaultReused,
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("identity: {0}")]
    Identity(#[from] IdentityError),
}

#[derive(Debug, Clone)]
pub struct SealedVault {
    pub version: u8,
    /// Header flags: see `vault_requires_totp`.
    pub flags: u8,
    pub salt: [u8; SALT_SIZE],
    pub nonce: [u8; NONCE_SIZE],
    pub ciphertext: Vec<u8>,
}

/// What an opened vault holds.
///
/// To re-seal it after a change (a new passphrase, TOTP turned on or off, a
/// rotated signed prekey), give `seal_vault` all three fields back. It seals
/// only what it is given: app data left out is app data lost.
pub struct UnsealedVault {
    pub identity: Identity,
    /// The TOTP secret, if the user turned TOTP on.
    pub totp_secret: Option<Vec<u8>>,
    /// The app data, if the vault carries any. Always `None` from a version 1
    /// vault, which is how the app knows it has not moved its data in yet.
    pub app: Option<Zeroizing<Vec<u8>>>,
}

// The serialized forms hold every private key as hex, and the app data, so
// they are wiped when dropped.

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SerializedKeyPair {
    #[serde(rename = "priv")]
    priv_hex: String,
    #[serde(rename = "pub")]
    pub_hex: String,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct SerializedSignedPreKey {
    id: u32,
    keypair: SerializedKeyPair,
    signature: String,
    created_at: i64,
    /// Only on retired keys. Absent in vaults sealed before retention was
    /// measured from retirement; `legacy_retired_at` fills it in on load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retired_at: Option<i64>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SerializedOneTimePreKey {
    id: u32,
    keypair: SerializedKeyPair,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SerializedIdentity {
    ik_sign: SerializedKeyPair,
    ik_dh: SerializedKeyPair,
    nostr: SerializedKeyPair,
    signed_pre_key: SerializedSignedPreKey,
    one_time_pre_keys: Vec<SerializedOneTimePreKey>,
    /// Absent when the user did not turn TOTP on. Every vault sealed before
    /// TOTP became optional has it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    totp_secret: Option<String>,
    /// Rotated-out signed prekeys still within their retention window.
    /// Defaulted so vaults sealed before rotation existed still open.
    #[serde(default)]
    retired_signed_pre_keys: Vec<SerializedSignedPreKey>,
    /// The app data, as hex. Only in version 2 vaults, and only when the app
    /// gave some.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    app: Option<String>,
}

/// Seals the identity under `passphrase`, as a version 2 vault.
///
/// With `totp_secret` set, opening the vault will also demand a valid code for
/// it; with `None`, it will not. `app`, if given, must be 1 to
/// `MAX_APP_DATA_LEN` bytes; it is sealed with the rest and comes back from
/// `unseal_vault`. A re-seal writes only what it is given, so pass back the
/// `app` that `unseal_vault` returned.
pub fn seal_vault(
    identity: &Identity,
    totp_secret: Option<&[u8]>,
    app: Option<&[u8]>,
    passphrase: &str,
) -> Result<SealedVault, VaultError> {
    check_app_data(app)?;
    let salt: [u8; SALT_SIZE] = random_array();
    let key = vault_key(passphrase, &salt);
    seal_with_key(&key, salt, identity, totp_secret, app)
}

/// Opens the vault and returns what it holds.
///
/// The decrypted payload decides whether a code is needed: a vault that holds
/// a TOTP secret fails with `TotpRequired` when `totp_code` is `None` and with
/// `InvalidTotp` when the code is wrong. A vault without a secret ignores any
/// code it is given. The app data comes back only once those checks pass.
pub fn unseal_vault(
    blob: &SealedVault,
    passphrase: &str,
    totp_code: Option<&str>,
) -> Result<UnsealedVault, VaultError> {
    check_header(blob.version, blob.flags)?;

    let key = vault_key(passphrase, &blob.salt);
    let opened = open_with_key(blob, &key)?;

    if let Some(secret) = &opened.totp_secret {
        let code = totp_code.ok_or(VaultError::TotpRequired)?;
        if !is_totp_code_valid(code, secret) {
            return Err(VaultError::InvalidTotp);
        }
    }

    Ok(opened)
}

/// Whether opening this encoded vault will ask for a TOTP code, read from the
/// header flags without decrypting anything.
///
/// **A UI hint only.** It is read before the vault is opened, so nothing has
/// checked it yet, and anyone who can write the file can flip it. It grants
/// and denies nothing: `unseal_vault` follows the sealed payload, so a vault
/// that holds a TOTP secret still demands a valid code whatever its header
/// says, and a version 2 vault whose flags were changed does not open at all.
/// Use it to decide whether to show the code field, and still handle
/// `TotpRequired`.
pub fn vault_requires_totp(bytes: &[u8]) -> Result<bool, VaultError> {
    let vault = decode_vault(bytes)?;
    check_header(vault.version, vault.flags)?;
    Ok(vault.flags & FLAG_NO_TOTP == 0)
}

/// Rejects a header this version cannot read, before any key derivation.
fn check_header(version: u8, flags: u8) -> Result<(), VaultError> {
    if version != VAULT_VERSION && version != VAULT_VERSION_1 {
        return Err(VaultError::UnsupportedVersion(version));
    }
    if flags & !KNOWN_FLAGS != 0 {
        return Err(VaultError::UnsupportedFlags(flags));
    }
    Ok(())
}

pub(crate) fn check_app_data(app: Option<&[u8]>) -> Result<(), VaultError> {
    match app {
        Some(app) if !app_data_len_is_valid(app.len()) => {
            Err(VaultError::InvalidAppData(app.len()))
        }
        _ => Ok(()),
    }
}

fn app_data_len_is_valid(len: usize) -> bool {
    (1..=MAX_APP_DATA_LEN).contains(&len)
}

fn vault_key(passphrase: &str, salt: &[u8; SALT_SIZE]) -> Zeroizing<[u8; 32]> {
    // `pbkdf2_sha256` already hands the key back in a Zeroizing buffer.
    pbkdf2_sha256(passphrase.as_bytes(), salt, PBKDF2_ITERATIONS)
}

/// The header up to the nonce, as `encode_vault` writes it.
fn header_bytes(version: u8, flags: u8, salt: &[u8; SALT_SIZE]) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    let magic = VAULT_MAGIC.len();
    header[..magic].copy_from_slice(VAULT_MAGIC);
    header[magic] = version;
    header[magic + 1] = flags;
    header[magic + 2..].copy_from_slice(salt);
    header
}

/// `seal_vault` past the key derivation.
fn seal_with_key(
    key: &[u8; 32],
    salt: [u8; SALT_SIZE],
    identity: &Identity,
    totp_secret: Option<&[u8]>,
    app: Option<&[u8]>,
) -> Result<SealedVault, VaultError> {
    check_app_data(app)?;
    let flags = match totp_secret {
        Some(_) => 0,
        None => FLAG_NO_TOTP,
    };
    let aad = header_bytes(VAULT_VERSION, flags, &salt);

    let payload = serialize_identity(identity, totp_secret, app);
    let payload_bytes =
        Zeroizing::new(serde_json::to_vec(&payload).map_err(|_| VaultError::BadPayload)?);
    let (ciphertext, nonce) = aes_gcm_encrypt(key, &payload_bytes, Some(&aad))?;

    Ok(SealedVault {
        version: VAULT_VERSION,
        flags,
        salt,
        nonce,
        ciphertext,
    })
}

/// `unseal_vault` past the key derivation, before the TOTP check.
fn open_with_key(blob: &SealedVault, key: &[u8; 32]) -> Result<UnsealedVault, VaultError> {
    check_header(blob.version, blob.flags)?;
    let is_version_1 = blob.version == VAULT_VERSION_1;

    let aad = header_bytes(blob.version, blob.flags, &blob.salt);
    let aad = (!is_version_1).then_some(aad.as_slice());
    let plaintext = Zeroizing::new(
        aes_gcm_decrypt(key, &blob.ciphertext, &blob.nonce, aad)
            .map_err(|_| VaultError::DecryptionFailed)?,
    );
    let serialized: SerializedIdentity =
        serde_json::from_slice(&plaintext).map_err(|_| VaultError::BadPayload)?;

    if is_version_1 {
        // An older reader would open it and drop the field on its next
        // re-seal: app data lives only under a version 2 header.
        if serialized.app.is_some() {
            return Err(VaultError::BadPayload);
        }
    } else {
        // Authenticated, so it can only disagree if a writer holding the key
        // got it wrong.
        let flags_say_no_totp = blob.flags & FLAG_NO_TOTP != 0;
        if flags_say_no_totp != serialized.totp_secret.is_none() {
            return Err(VaultError::BadPayload);
        }
    }

    deserialize_identity(&serialized)
}

pub fn encode_vault(v: &SealedVault) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + NONCE_SIZE + v.ciphertext.len());
    out.extend_from_slice(&header_bytes(v.version, v.flags, &v.salt));
    out.extend_from_slice(&v.nonce);
    out.extend_from_slice(&v.ciphertext);
    out
}

pub fn decode_vault(bytes: &[u8]) -> Result<SealedVault, VaultError> {
    if bytes.len() < HEADER_LEN + NONCE_SIZE {
        return Err(VaultError::Corrupted);
    }
    if &bytes[..VAULT_MAGIC.len()] != VAULT_MAGIC {
        return Err(VaultError::BadMagic);
    }
    let mut off = VAULT_MAGIC.len();
    let version = bytes[off];
    let flags = bytes[off + 1];
    off += 2;
    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&bytes[off..off + SALT_SIZE]);
    off += SALT_SIZE;
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&bytes[off..off + NONCE_SIZE]);
    off += NONCE_SIZE;
    let ciphertext = bytes[off..].to_vec();
    Ok(SealedVault {
        version,
        flags,
        salt,
        nonce,
        ciphertext,
    })
}

pub(crate) fn serialize_identity(
    identity: &Identity,
    totp_secret: Option<&[u8]>,
    app: Option<&[u8]>,
) -> SerializedIdentity {
    SerializedIdentity {
        ik_sign: kp_to_ser(&identity.ik_sign),
        ik_dh: kp_to_ser(&identity.ik_dh),
        nostr: kp_to_ser(&identity.nostr),
        signed_pre_key: SerializedSignedPreKey {
            id: identity.signed_prekey.id,
            keypair: kp_to_ser(&identity.signed_prekey.keypair),
            signature: hex::encode(identity.signed_prekey.signature),
            created_at: identity.signed_prekey.created_at,
            retired_at: None,
        },
        one_time_pre_keys: identity
            .one_time_prekeys
            .iter()
            .map(|o| SerializedOneTimePreKey {
                id: o.id,
                keypair: kp_to_ser(&o.keypair),
            })
            .collect(),
        totp_secret: totp_secret.map(hex::encode),
        retired_signed_pre_keys: identity
            .retired_signed_prekeys
            .iter()
            .map(|r| SerializedSignedPreKey {
                id: r.prekey.id,
                keypair: kp_to_ser(&r.prekey.keypair),
                signature: hex::encode(r.prekey.signature),
                created_at: r.prekey.created_at,
                retired_at: Some(r.retired_at),
            })
            .collect(),
        app: app.map(hex::encode),
    }
}

pub(crate) fn deserialize_identity(s: &SerializedIdentity) -> Result<UnsealedVault, VaultError> {
    let identity = Identity {
        ik_sign: kp_from_ser(&s.ik_sign)?,
        ik_dh: kp_from_ser(&s.ik_dh)?,
        nostr: kp_from_ser(&s.nostr)?,
        signed_prekey: SignedPreKey {
            id: s.signed_pre_key.id,
            keypair: kp_from_ser(&s.signed_pre_key.keypair)?,
            signature: decode_array_64(&s.signed_pre_key.signature)?,
            created_at: s.signed_pre_key.created_at,
        },
        one_time_prekeys: s
            .one_time_pre_keys
            .iter()
            .map(|o| {
                Ok::<OneTimePreKey, VaultError>(OneTimePreKey {
                    id: o.id,
                    keypair: kp_from_ser(&o.keypair)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        retired_signed_prekeys: s
            .retired_signed_pre_keys
            .iter()
            .map(|r| {
                Ok::<RetiredSignedPreKey, VaultError>(RetiredSignedPreKey {
                    prekey: SignedPreKey {
                        id: r.id,
                        keypair: kp_from_ser(&r.keypair)?,
                        signature: decode_array_64(&r.signature)?,
                        created_at: r.created_at,
                    },
                    retired_at: r.retired_at.unwrap_or_else(|| {
                        legacy_retired_at(r.id, &s.retired_signed_pre_keys, &s.signed_pre_key)
                    }),
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    let totp_secret = s
        .totp_secret
        .as_deref()
        .map(hex::decode)
        .transpose()
        .map_err(|_| VaultError::BadPayload)?;
    let app = s
        .app
        .as_deref()
        .map(|app| {
            let app = Zeroizing::new(hex::decode(app).map_err(|_| VaultError::BadPayload)?);
            if app_data_len_is_valid(app.len()) {
                Ok(app)
            } else {
                Err(VaultError::BadPayload)
            }
        })
        .transpose()?;
    Ok(UnsealedVault {
        identity,
        totp_secret,
        app,
    })
}

/// Retirement time of a retired prekey from a vault sealed before
/// `retiredAt` was stored.
///
/// Rotation creates the next key at the very moment it retires the outgoing
/// one, and ids only grow, so the creation time of the key with the next
/// higher id IS the retirement time. If no such key exists (it always does
/// for vaults this crate wrote), the current key's creation time, the latest
/// rotation, is used: it can only keep the key longer, never strand a peer.
fn legacy_retired_at(
    id: u32,
    retired: &[SerializedSignedPreKey],
    current: &SerializedSignedPreKey,
) -> i64 {
    retired
        .iter()
        .chain(std::iter::once(current))
        .filter(|next| next.id > id)
        .min_by_key(|next| next.id)
        .map_or(current.created_at, |next| next.created_at)
}

fn kp_to_ser(kp: &KeyPair) -> SerializedKeyPair {
    SerializedKeyPair {
        priv_hex: hex::encode(kp.priv_bytes),
        pub_hex: hex::encode(kp.pub_bytes),
    }
}

fn kp_from_ser(s: &SerializedKeyPair) -> Result<KeyPair, VaultError> {
    Ok(KeyPair {
        priv_bytes: decode_array_32(&s.priv_hex)?,
        pub_bytes: decode_array_32(&s.pub_hex)?,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::identity::create_identity;
    use crate::totp::{generate_totp_secret, totp_now};
    use std::sync::{Mutex, MutexGuard, OnceLock};

    // PBKDF2-600k tests are intentionally expensive. Running them concurrently
    // can push a freshly generated TOTP outside its validation window.
    static VAULT_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock() -> MutexGuard<'static, ()> {
        VAULT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    const PASSPHRASE: &str = "correct horse battery";

    /// A vault sealed by this version, kept with what went into it.
    struct TestVault {
        identity: Identity,
        totp_secret: Option<Vec<u8>>,
        app: Option<Vec<u8>>,
        sealed: SealedVault,
    }

    impl TestVault {
        fn seal(totp_secret: Option<Vec<u8>>, app: Option<Vec<u8>>) -> Self {
            let identity = create_identity();
            let sealed = seal_vault(
                &identity,
                totp_secret.as_deref(),
                app.as_deref(),
                PASSPHRASE,
            )
            .unwrap();
            TestVault {
                identity,
                totp_secret,
                app,
                sealed,
            }
        }
    }

    // Every seal is a full PBKDF2 run, so the tests share one vault of each
    // kind. Call these with the lock held: the first call does the sealing.

    /// With TOTP, without app data.
    fn with_totp() -> &'static TestVault {
        static VAULT: OnceLock<TestVault> = OnceLock::new();
        VAULT.get_or_init(|| TestVault::seal(Some(generate_totp_secret()), None))
    }

    /// Without TOTP, with app data: how the desktop app seals by default.
    fn without_totp() -> &'static TestVault {
        static VAULT: OnceLock<TestVault> = OnceLock::new();
        VAULT.get_or_init(|| TestVault::seal(None, Some(vec![0xd4; 32])))
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let _guard = lock();
        let vault = with_totp();
        let totp_secret = vault.totp_secret.as_deref().unwrap();
        let code = totp_now(totp_secret);
        let opened = unseal_vault(&vault.sealed, PASSPHRASE, Some(&code)).unwrap();
        assert_eq!(
            opened.identity.ik_sign.priv_bytes,
            vault.identity.ik_sign.priv_bytes
        );
        assert_eq!(
            opened.identity.ik_dh.pub_bytes,
            vault.identity.ik_dh.pub_bytes
        );
        assert_eq!(opened.totp_secret.as_deref(), Some(totp_secret));
        assert!(opened.app.is_none());
    }

    #[test]
    fn wrong_passphrase_fails() {
        let _guard = lock();
        let vault = with_totp();
        let code = totp_now(vault.totp_secret.as_deref().unwrap());
        let err = unseal_vault(&vault.sealed, "wrong", Some(&code)).err();
        assert!(matches!(err, Some(VaultError::DecryptionFailed)));
    }

    #[test]
    fn wrong_totp_fails() {
        let _guard = lock();
        let err = unseal_vault(&with_totp().sealed, PASSPHRASE, Some("000000")).err();
        assert!(matches!(err, Some(VaultError::InvalidTotp)));
    }

    #[test]
    fn vault_with_totp_requires_a_code() {
        let _guard = lock();
        let err = unseal_vault(&with_totp().sealed, PASSPHRASE, None).err();
        assert!(matches!(err, Some(VaultError::TotpRequired)));
    }

    #[test]
    fn vault_without_totp_opens_without_a_code() {
        let _guard = lock();
        let vault = without_totp();
        let opened = unseal_vault(&vault.sealed, PASSPHRASE, None).unwrap();
        assert_eq!(
            opened.identity.ik_sign.priv_bytes,
            vault.identity.ik_sign.priv_bytes
        );
        assert_eq!(
            opened.identity.ik_dh.pub_bytes,
            vault.identity.ik_dh.pub_bytes
        );
        assert_eq!(opened.totp_secret, None);
        assert_eq!(opened.app.as_deref(), vault.app.as_ref());
    }

    #[test]
    fn vault_without_totp_ignores_a_supplied_code() {
        let _guard = lock();
        let opened = unseal_vault(&without_totp().sealed, PASSPHRASE, Some("000000"));
        assert_eq!(opened.unwrap().totp_secret, None);
    }

    #[test]
    fn payload_without_totp_has_no_secret_field() {
        let id = create_identity();
        let raw = serde_json::to_value(serialize_identity(&id, None, None)).unwrap();
        assert!(raw.get("totpSecret").is_none());
        assert!(raw.get("app").is_none());
        let opened = deserialize_identity(&serde_json::from_value(raw).unwrap()).unwrap();
        assert_eq!(opened.totp_secret, None);
    }

    #[test]
    fn binary_encode_decode_roundtrip() {
        let _guard = lock();
        let sealed = &with_totp().sealed;
        let bytes = encode_vault(sealed);
        let decoded = decode_vault(&bytes).unwrap();
        assert_eq!(decoded.salt, sealed.salt);
        assert_eq!(decoded.nonce, sealed.nonce);
        assert_eq!(decoded.ciphertext, sealed.ciphertext);
        assert_eq!(decoded.version, sealed.version);
        assert_eq!(decoded.flags, sealed.flags);
    }

    /// The version byte, after the 6-byte magic.
    const VERSION_BYTE: usize = 6;
    /// The flags byte: after the magic and the version.
    const FLAGS_BYTE: usize = 7;

    #[test]
    fn sealing_records_whether_totp_is_on_in_the_header() {
        // The flags byte used to be reserved. Zero, as in every older vault,
        // means TOTP on; bit 0 means the vault was sealed without TOTP.
        let _guard = lock();
        assert_eq!(encode_vault(&with_totp().sealed)[FLAGS_BYTE], 0b0000_0000);
        assert_eq!(
            encode_vault(&without_totp().sealed)[FLAGS_BYTE],
            0b0000_0001
        );
    }

    #[test]
    fn header_says_whether_to_ask_for_a_code() {
        let _guard = lock();
        assert!(vault_requires_totp(&encode_vault(&with_totp().sealed)).unwrap());
        assert!(!vault_requires_totp(&encode_vault(&without_totp().sealed)).unwrap());
    }

    #[test]
    fn unknown_header_flags_are_rejected() {
        // Unknown bits are kept for format changes this version could only
        // misread, so it refuses them before deriving any key: the wrong
        // passphrase below is never tried.
        for flags in [0b0000_0010, 0b1000_0000, FLAG_NO_TOTP | 0b0000_0100] {
            let mut bytes = old_vault();
            bytes[FLAGS_BYTE] = flags;
            assert!(matches!(
                vault_requires_totp(&bytes),
                Err(VaultError::UnsupportedFlags(f)) if f == flags
            ));
            let blob = decode_vault(&bytes).unwrap();
            assert!(matches!(
                unseal_vault(&blob, "not the passphrase", None).err(),
                Some(VaultError::UnsupportedFlags(f)) if f == flags
            ));
        }
    }

    #[test]
    fn header_hint_refuses_unsupported_versions() {
        // Another version may give the flags byte another meaning. Versions 1
        // and 2 are this crate's own; 0 and 3 are unknown.
        for version in [0, 3] {
            let mut bytes = old_vault();
            bytes[VERSION_BYTE] = version;
            assert!(matches!(
                vault_requires_totp(&bytes),
                Err(VaultError::UnsupportedVersion(v)) if v == version
            ));
        }
    }

    // In a version 1 vault the flags sit outside the AES-GCM envelope, so
    // whoever can write the file can flip them. They only steer the UI; the
    // sealed payload decides.

    #[test]
    fn header_claiming_no_totp_cannot_skip_the_code() {
        let _guard = lock();
        let mut bytes = old_vault();
        bytes[FLAGS_BYTE] |= FLAG_NO_TOTP;
        assert!(!vault_requires_totp(&bytes).unwrap());
        let blob = decode_vault(&bytes).unwrap();
        let err = unseal_vault(&blob, OLD_VAULT_PASSPHRASE, None).err();
        assert!(matches!(err, Some(VaultError::TotpRequired)));
    }

    #[test]
    fn header_claiming_totp_adds_no_code_to_a_vault_without_one() {
        let _guard = lock();
        let mut bytes = v1_vault_without_totp();
        bytes[FLAGS_BYTE] &= !FLAG_NO_TOTP;
        assert!(vault_requires_totp(&bytes).unwrap());
        let blob = decode_vault(&bytes).unwrap();
        let opened = unseal_vault(&blob, V1_VAULT_PASSPHRASE, None).unwrap();
        assert_eq!(
            hex::encode(opened.identity.ik_sign.pub_bytes),
            V1_VAULT_IK_SIGN_PUB
        );
        assert_eq!(opened.totp_secret, None);
    }

    /// An identity that has rotated twice, so it holds two retired prekeys.
    fn rotated_twice() -> Identity {
        use crate::identity::{rotate_signed_prekey_if_due, SPK_ROTATION_SECS};
        let mut id = create_identity();
        let t0 = id.signed_prekey.created_at;
        assert!(rotate_signed_prekey_if_due(&mut id, t0 + SPK_ROTATION_SECS));
        assert!(rotate_signed_prekey_if_due(
            &mut id,
            t0 + 5 * SPK_ROTATION_SECS
        ));
        assert_eq!(id.retired_signed_prekeys.len(), 2);
        id
    }

    fn retirement_times(id: &Identity) -> Vec<(u32, i64)> {
        id.retired_signed_prekeys
            .iter()
            .map(|r| (r.prekey.id, r.retired_at))
            .collect()
    }

    #[test]
    fn retirement_times_survive_sealing() {
        let id = rotated_twice();
        let raw =
            serde_json::to_value(serialize_identity(&id, Some(b"totp".as_slice()), None)).unwrap();
        let opened = deserialize_identity(&serde_json::from_value(raw).unwrap()).unwrap();
        assert_eq!(retirement_times(&opened.identity), retirement_times(&id));
    }

    #[test]
    fn vault_without_retirement_times_takes_them_from_the_next_key() {
        // Vaults sealed before `retiredAt` existed store only `createdAt`.
        // Rotation creates the next key at the moment it retires the old one,
        // so the next key's creation time is the old key's retirement time.
        let id = rotated_twice();
        let mut raw =
            serde_json::to_value(serialize_identity(&id, Some(b"totp".as_slice()), None)).unwrap();
        for retired in raw["retiredSignedPreKeys"].as_array_mut().unwrap() {
            retired.as_object_mut().unwrap().remove("retiredAt");
        }
        let opened = deserialize_identity(&serde_json::from_value(raw).unwrap()).unwrap();
        assert_eq!(retirement_times(&opened.identity), retirement_times(&id));
    }

    #[test]
    fn bad_magic_rejected() {
        let bad = vec![0u8; 64];
        assert!(matches!(
            decode_vault(&bad).err(),
            Some(VaultError::BadMagic)
        ));
    }

    /// A vault sealed by trino-core 1bac851, from before TOTP became optional,
    /// with that commit's `seal_vault` and `encode_vault` (the identity was
    /// trimmed to one one-time prekey to keep it short). The header is the
    /// magic, version 1 and a zero reserved byte, then the salt and the nonce.
    const OLD_VAULT_HEX: &str = "
        5452494e4f00 01 00
        11c4199f1adaab5f338db0889ddee638
        c3797418765bf2b055e59104
        277430af36c4a3688b92c7dbb775e2475a5f6601d31aafd3f70ec362ebfeb0b52bb1ecaa15d431b2
        1e276f1109bbe903b13fd43e801531c0b8bcc3e2217b5cf84eaaa9134e68098746edbaa77f1d3f7d
        9e015620ea69ac07dd2480c9800e640beff805db51be716b80d0b2b9d80bd2ff8ae2d4015adf57af
        2ff5250c2074e7142af6ef9fe85ef10d9ff365d1e75d911e61a0d4ac63b3bd5ecf777272ae78383f
        b14ecb9cb5d6dc7f551c0d98a78da4156308116200ad730fa8c2e0cf52d9d3c88be86107e9417c42
        ab85f679f49c3f168ac1fd7594e6d4d9777194e9f5ee874e4eb418e0f24ac859dabfa04cc6ea80da
        a877ca369857fd1b42182e7bf59329a922bd2a1282e1777de5c5a69b2f4043e75d238b00330aa05c
        809cefa1f600077d21ff548fad1f9abfe257da099f75d6410059c95f138bf1bf05115f6b4b789c38
        409788db03073920902182c84b1d0f26a3398c7751ff5147ca64e5271ecd751097b3434f8c416a3e
        78d93d764ded6befc5da7f178840d9acd2f42831cff79816e8e27e577f2f61a523818eaf6c8dfcfd
        60824cb54328cf1ef968261edd7bf0d9aee114f12c22344224523265c53f2611be6a816d9c9f223f
        e7834dbd1876d3cc474a48b74fb47d2118090dbfc1e8604e0d937dd42c2f796f27e1bcbffe31613b
        a2ab42a588584cb9cc6f99539572467163288304f973fd7681d8a48f351420924e8e3482d3c8fd5b
        111de54cd4ac32f0b3028927e6c7f4f9a2dce657cf07e17c4f71aa13504e2ca3c01147e79056bdad
        72ed81b3e5ac4ae7cf3f01292ea0d034c79911e89e8365e9aaf5ee10e1f8b8996ef051d015e10d43
        96b9ea895137ca57c4ceeb16381ddcd3999008688a231946ed11f5704a0a82ce6dee1285c064a1f9
        719a6fade39d1fc2ad9de725a506d4e6ba48043b5ba2e5b1bf6e5616ba304e551dc2c8fd009660bf
        a12b4aa3e53670337f51dd4a29e719d39305227a2a607f01343996e3d7db92b87dcec1d696125ed6
        cd64a7936aae7ebf896e0cebb29e77722e9ee80b73e997148b1ed9cfbd9aa30356069612b026d11a
        25d4cc50097899112beddee4a6b9896f7a69f5876acc64ae085d3c47c9da33fe8c6181c39a0030d5
        b1c9d5681d3ebb8ee04658e9f7d7309cf68b74aa8a3c62aa699438f5e24c211ec25a821ba5708a6b
        873c5cc3c378825fb38944e12fded8b75768fbc376588224a3a8c3eab641f18cf3b75f071bee7917
        4d50812f1accf635c08f0d1c36c0ed386906f1d890094759a80d2a452774fb95db997e0a0e4917a3
        765ba75bfe6342bae07a5ead6d660839bb9e6a3f4ecd264cc8525dbd98f12c346b8676bc5f7a80b1
        07d9fc46b3ba4b976d1ecda3b134e967476b4c00aac8f0fdaeace6165255e6cb896b909b51a38c94
        dcc403e4c51b8e1b33cb07e29eda5e3fbcc9ecc4e519cb3349701da9b19f16b5018829a10ec80b5e
        5ae93761280ab6868b7d4157cd566f3a7f8bd8dce05d108d396a64b429f0ec502373478d634f7384
        bd8bf0fde31c4ed84189d12415b2f53c6c5b8f577099c47c90e0
    ";
    pub(crate) const OLD_VAULT_PASSPHRASE: &str = "trino-core 1bac851 fixture";
    /// RFC 6238's SHA-1 seed, so the tests can compute a valid code.
    pub(crate) const OLD_VAULT_TOTP_SECRET: &[u8] = b"12345678901234567890";
    pub(crate) const OLD_VAULT_IK_SIGN_PUB: &str =
        "84aa175b86e7d4eb0f1b84afd20e4654174c929e699c8e548ee535ae6292d06a";

    pub(crate) fn old_vault() -> Vec<u8> {
        hex::decode(OLD_VAULT_HEX.split_whitespace().collect::<String>()).unwrap()
    }

    #[test]
    fn vault_sealed_before_optional_totp_opens_with_its_code() {
        let _guard = lock();
        let blob = decode_vault(&old_vault()).unwrap();
        let code = totp_now(OLD_VAULT_TOTP_SECRET);
        let opened = unseal_vault(&blob, OLD_VAULT_PASSPHRASE, Some(&code)).unwrap();
        assert_eq!(
            hex::encode(opened.identity.ik_sign.pub_bytes),
            OLD_VAULT_IK_SIGN_PUB
        );
        assert_eq!(opened.totp_secret.as_deref(), Some(OLD_VAULT_TOTP_SECRET));
        // Older vaults carry no app data; the app migrates them.
        assert!(opened.app.is_none());
    }

    #[test]
    fn vault_sealed_before_optional_totp_requires_its_code() {
        let _guard = lock();
        let blob = decode_vault(&old_vault()).unwrap();
        let err = unseal_vault(&blob, OLD_VAULT_PASSPHRASE, None).err();
        assert!(matches!(err, Some(VaultError::TotpRequired)));
    }

    #[test]
    fn vault_sealed_before_optional_totp_rejects_a_wrong_code() {
        let _guard = lock();
        let blob = decode_vault(&old_vault()).unwrap();
        let err = unseal_vault(&blob, OLD_VAULT_PASSPHRASE, Some("000000")).err();
        assert!(matches!(err, Some(VaultError::InvalidTotp)));
    }

    #[test]
    fn vault_sealed_before_optional_totp_reports_totp_in_its_header() {
        assert!(vault_requires_totp(&old_vault()).unwrap());
    }

    /// A vault sealed by trino-core 4ce6775 without TOTP, with that commit's
    /// `seal_vault` and `encode_vault`, the identity trimmed to one one-time
    /// prekey. Version 1, flags `0x01`: what the desktop app writes until it
    /// moves to app data, and what it has to migrate.
    const V1_VAULT_HEX: &str = "
        5452494e4f00 01 01
        f91744d63cc2a1fec4f08eca77d059ad
        2010b3a1e100d68bf6007067
        6f0f3373a0573fef50b9f59742756b6c9cad79ed98771f73e711bc53902ccfbbf29e7e0155b9108d
        dc96e17874c037dcb737157ab4d90163f5c16531ee0b157feda1c8b8c359dfba8c09e226c9268131
        ca8218f42270487c47d41a450ef0794c961fdf314da2a46802a0957552a369de7bd6315fbf31dbaa
        9fc3379c3fbab4c2607d19a64cead14be2af42bf2308e4176b5665373966cd3c424ab4c5588ef672
        03721e91b700315b485c50bf5bf6f5700692290e5ad0d554562f276044b02786aaf39593468dd9f6
        4430314735949a5bde050232320dfef4ef288818d34245de472d280bc0675e0ef744c65fef62d196
        405094fad677a93b0ea98ab35e49b23b5bd20c7737b9685203c2b95a469f60334922a39575f70f50
        ca6f4bfa968702dde4e7b9e0c828c72dcfe5a639517d1be302df5c4f96ffd18a6b66ce00ae19d119
        1fa9ae7e1dcfea5105d8af15ab2d6b878b312bc93acc2968a0e2d1369ee6bfae6490c2cf6b30f46a
        77257046644603f70aa78d3750663f6d84ecdc07150d149c8513d3996b3dfe27ce5ed7679e5d3a9c
        b4da16a354b75163767fa11b46d0635627d9b252abf4d6d195ebfbbae55d8da5698f86bd51bdfae0
        340015c2353dd6957f1ad720121b219a0ad243fafd2075ad683d436a396ce963c554b6e73898c86b
        c46bc7a732457fdddea5581c846e0e4b6eaebad9172897244b6f81fa9aa458bdd0619f87ec8ef16c
        3907ea73de92e043d96bd2add5d9b8c21f8d7873a2e9ed39f6f2e184d0f7e03a21973c1762f8ed7e
        1be6286df75175d15b12d1887fa78da9e4458cec4fdc4a6070cb719c7188f91b2d676cddcd2891b5
        e38599fdd5fbfed47c129e7dad45a5313dd20998d8b3a8610e952dd17c34a16e456554f2697dd216
        95189e95165392b96cdb448cc338d0f75192a0dbd0aa67e6c716c82618e7c56d0e45afbc5532562f
        789a0a08341f2daecbafa5e5bb84bc318865e1e9209d47aff78ca3d62dbcb96c7d5dae058e2697a9
        b641cf744c1cf1d2366981d2e46274dbe21133b62887707a464e60a6d93e46db26a78f581d6ee566
        5ec3e54aeaded7ca117e17281a559787dd75be2a838562f770e0d364e4cb5ab022c1508d18f1bfdb
        8a1c1a5355e58d182b940047f0fedb276f6e523474e7debb77f85ddff6d14e3353dd6c6e962435ce
        070812198ab20428edd9c59ae3f2acb4018af2e590d83eee32f9e87297e0bbdf3ca4452918c0df2d
        ee0f3e3c82b8a9649ad864fec47e0f2cb9b52ceaa1ab0fcb438143f1ad0979f8e72d0b6e4e877cb5
        8d9ebf0257d57af3dcbd1485518a20b27afcca730547b953366c46ca2cfbe438c1de9135b56b0711
        6c8f9446dfcb399e7665fbafd68ac7adaed23cc0d77ced65026bbbfa6f2bdcb2df4b7c5336455437
        6dfc5a3f1847eb987d8542724f8d7fe74bdd79cad687988a8bb475d9f909a65f5cebac9a5bd74581
        3e20e0a289dfc530bf83
    ";
    const V1_VAULT_PASSPHRASE: &str = "trino-core 4ce6775 fixture";
    const V1_VAULT_IK_SIGN_PUB: &str =
        "abff1ade52739f195de74903bcc7c1f4345d1f5c587403239f841fa094edab44";

    fn v1_vault_without_totp() -> Vec<u8> {
        hex::decode(V1_VAULT_HEX.split_whitespace().collect::<String>()).unwrap()
    }

    #[test]
    fn vault_sealed_by_4ce6775_without_totp_opens_without_app_data() {
        let _guard = lock();
        let bytes = v1_vault_without_totp();
        assert!(!vault_requires_totp(&bytes).unwrap());
        let blob = decode_vault(&bytes).unwrap();
        let opened = unseal_vault(&blob, V1_VAULT_PASSPHRASE, None).unwrap();
        assert_eq!(
            hex::encode(opened.identity.ik_sign.pub_bytes),
            V1_VAULT_IK_SIGN_PUB
        );
        assert_eq!(opened.totp_secret, None);
        assert!(opened.app.is_none());
    }

    // ---- App data ----------------------------------------------------------
    //
    // Most of these tests seal and open with a fixed key instead of a
    // passphrase: the format is the same, and they skip the PBKDF2 run that
    // makes every passphrase test slow.

    const KEY: [u8; 32] = [0x4b; 32];
    const OTHER_KEY: [u8; 32] = [0x6f; 32];
    const SALT: [u8; SALT_SIZE] = [0x5a; SALT_SIZE];
    /// What the desktop app keeps there: its data key.
    const DATA_KEY: [u8; 32] = [0xd4; 32];
    /// The bytes before the nonce: magic, version, flags and salt.
    const HEADER_LEN: usize = 24;
    /// Magic, version, flags, salt and nonce: everything before the
    /// ciphertext.
    const FULL_HEADER_LEN: usize = HEADER_LEN + 12;

    fn seal_fast(totp_secret: Option<&[u8]>, app: Option<&[u8]>) -> (Identity, SealedVault) {
        let identity = create_identity();
        let sealed = seal_with_key(&KEY, SALT, &identity, totp_secret, app).unwrap();
        (identity, sealed)
    }

    /// Seals any payload under any header with `KEY`, for vaults `seal_vault`
    /// never writes. Version 1 has no associated data; later versions take
    /// the header up to the nonce, as the format says.
    fn seal_raw(version: u8, flags: u8, payload: &serde_json::Value) -> SealedVault {
        let header = SealedVault {
            version,
            flags,
            salt: SALT,
            nonce: [0; 12],
            ciphertext: Vec::new(),
        };
        let aad = encode_vault(&header)[..HEADER_LEN].to_vec();
        let plaintext = serde_json::to_vec(payload).unwrap();
        let aad = (version != 1).then_some(aad.as_slice());
        let (ciphertext, nonce) = aes_gcm_encrypt(&KEY, &plaintext, aad).unwrap();
        SealedVault {
            nonce,
            ciphertext,
            ..header
        }
    }

    fn payload(totp_secret: Option<&[u8]>, app: Option<&[u8]>) -> serde_json::Value {
        serde_json::to_value(serialize_identity(&create_identity(), totp_secret, app)).unwrap()
    }

    #[test]
    fn sealing_writes_version_2() {
        let (_, sealed) = seal_fast(None, Some(&DATA_KEY));
        assert_eq!(encode_vault(&sealed)[VERSION_BYTE], 2);
        let (_, sealed) = seal_fast(None, None);
        assert_eq!(encode_vault(&sealed)[VERSION_BYTE], 2);
    }

    #[test]
    fn app_data_comes_back_when_the_vault_opens() {
        let (identity, sealed) = seal_fast(None, Some(&DATA_KEY));
        let opened = open_with_key(&sealed, &KEY).unwrap();
        assert_eq!(
            opened.app.as_deref().map(Vec::as_slice),
            Some(&DATA_KEY[..])
        );
        assert_eq!(
            opened.identity.ik_sign.priv_bytes,
            identity.ik_sign.priv_bytes
        );
    }

    #[test]
    fn a_version_2_vault_without_app_data_opens_without_it() {
        let (_, sealed) = seal_fast(Some(b"totp secret"), None);
        let opened = open_with_key(&sealed, &KEY).unwrap();
        assert!(opened.app.is_none());
        assert_eq!(opened.totp_secret.as_deref(), Some(&b"totp secret"[..]));
    }

    #[test]
    fn a_version_1_vault_still_opens_and_has_no_app_data() {
        let sealed = seal_raw(1, FLAG_NO_TOTP, &payload(None, None));
        let opened = open_with_key(&sealed, &KEY).unwrap();
        assert!(opened.app.is_none());
        assert_eq!(opened.totp_secret, None);
    }

    /// Opens with `key`, lets `change` alter what came out, and seals the
    /// result again with `new_key`, as the app does on every re-seal.
    fn reseal(
        sealed: &SealedVault,
        key: &[u8; 32],
        new_key: &[u8; 32],
        change: impl FnOnce(&mut UnsealedVault),
    ) -> SealedVault {
        let mut opened = open_with_key(sealed, key).unwrap();
        change(&mut opened);
        seal_with_key(
            new_key,
            random_array(),
            &opened.identity,
            opened.totp_secret.as_deref(),
            opened.app.as_deref().map(Vec::as_slice),
        )
        .unwrap()
    }

    fn app_data_of(sealed: &SealedVault, key: &[u8; 32]) -> Option<Vec<u8>> {
        open_with_key(sealed, key)
            .unwrap()
            .app
            .map(|app| app.to_vec())
    }

    #[test]
    fn app_data_survives_a_passphrase_change() {
        let (_, sealed) = seal_fast(None, Some(&DATA_KEY));
        let resealed = reseal(&sealed, &KEY, &OTHER_KEY, |_| {});
        assert_eq!(app_data_of(&resealed, &OTHER_KEY), Some(DATA_KEY.to_vec()));
    }

    #[test]
    fn app_data_survives_turning_totp_on_and_off() {
        let (_, sealed) = seal_fast(None, Some(&DATA_KEY));
        let on = reseal(&sealed, &KEY, &KEY, |v| {
            v.totp_secret = Some(b"new secret".to_vec())
        });
        assert_eq!(encode_vault(&on)[FLAGS_BYTE] & FLAG_NO_TOTP, 0);
        assert_eq!(app_data_of(&on, &KEY), Some(DATA_KEY.to_vec()));

        let off = reseal(&on, &KEY, &KEY, |v| v.totp_secret = None);
        assert_eq!(encode_vault(&off)[FLAGS_BYTE], FLAG_NO_TOTP);
        assert_eq!(app_data_of(&off, &KEY), Some(DATA_KEY.to_vec()));
    }

    #[test]
    fn app_data_survives_a_signed_prekey_rotation() {
        use crate::identity::{rotate_signed_prekey_if_due, SPK_ROTATION_SECS};
        let (identity, sealed) = seal_fast(None, Some(&DATA_KEY));
        let due = identity.signed_prekey.created_at + SPK_ROTATION_SECS;
        let rotated = reseal(&sealed, &KEY, &KEY, |v| {
            assert!(rotate_signed_prekey_if_due(&mut v.identity, due))
        });
        let opened = open_with_key(&rotated, &KEY).unwrap();
        assert_eq!(opened.identity.retired_signed_prekeys.len(), 1);
        assert_eq!(
            opened.app.as_deref().map(Vec::as_slice),
            Some(&DATA_KEY[..])
        );
    }

    #[test]
    fn app_data_size_is_bounded() {
        let identity = create_identity();
        let seal = |app: &[u8]| seal_with_key(&KEY, SALT, &identity, None, Some(app));
        assert!(matches!(seal(&[]), Err(VaultError::InvalidAppData(0))));
        let too_long = [1u8; MAX_APP_DATA_LEN + 1];
        assert!(matches!(
            seal(&too_long),
            Err(VaultError::InvalidAppData(n)) if n == MAX_APP_DATA_LEN + 1
        ));
        let longest = [1u8; MAX_APP_DATA_LEN];
        let sealed = seal(&longest).unwrap();
        assert_eq!(app_data_of(&sealed, &KEY), Some(longest.to_vec()));
    }

    #[test]
    fn a_payload_with_app_data_out_of_bounds_is_refused() {
        // Only someone with the key could write these: a bug, not an attack.
        for app in [vec![], vec![1u8; MAX_APP_DATA_LEN + 1]] {
            let sealed = seal_raw(2, FLAG_NO_TOTP, &payload(None, Some(&app)));
            assert!(matches!(
                open_with_key(&sealed, &KEY).err(),
                Some(VaultError::BadPayload)
            ));
        }
    }

    #[test]
    fn a_version_1_vault_carrying_app_data_is_refused() {
        // Readers before version 2 would open it and drop the field on their
        // next re-seal, so app data never lives under a version 1 header.
        let sealed = seal_raw(1, FLAG_NO_TOTP, &payload(None, Some(&DATA_KEY)));
        assert!(matches!(
            open_with_key(&sealed, &KEY).err(),
            Some(VaultError::BadPayload)
        ));
    }

    // ---- Older readers -----------------------------------------------------
    //
    // These copy, line for line, the header checks that the two trino-core
    // versions apps were built with run before deriving any key. A version 2
    // vault has to stop both there: past that point either one opens the
    // vault, and its next re-seal (an SPK rotation, a passphrase or TOTP
    // change) writes it back without the app data.

    /// trino-core 1bac851 (`unseal_vault`): the version byte only. It never
    /// read the flags byte, which was reserved then.
    fn header_check_of_1bac851(blob: &SealedVault) -> Result<(), VaultError> {
        if blob.version != 1 {
            return Err(VaultError::UnsupportedVersion(blob.version));
        }
        Ok(())
    }

    /// trino-core 4ce6775 (`check_header`).
    fn header_check_of_4ce6775(version: u8, flags: u8) -> Result<(), VaultError> {
        if version != 1 {
            return Err(VaultError::UnsupportedVersion(version));
        }
        if flags & !0b0000_0001 != 0 {
            return Err(VaultError::UnsupportedFlags(flags));
        }
        Ok(())
    }

    #[test]
    fn older_readers_refuse_a_vault_with_app_data_before_any_key() {
        for totp_secret in [None, Some(&b"totp"[..])] {
            let (_, sealed) = seal_fast(totp_secret, Some(&DATA_KEY));
            let blob = decode_vault(&encode_vault(&sealed)).unwrap();
            assert!(matches!(
                header_check_of_1bac851(&blob),
                Err(VaultError::UnsupportedVersion(2))
            ));
            assert!(matches!(
                header_check_of_4ce6775(blob.version, blob.flags),
                Err(VaultError::UnsupportedVersion(2))
            ));
        }
    }

    #[test]
    fn a_new_flag_bit_alone_would_not_stop_1bac851() {
        // Why the version changes rather than a flag bit: 1bac851 skips the
        // flags byte, so it would open a version 1 vault whatever bit is set.
        let mut bytes = old_vault();
        bytes[FLAGS_BYTE] = 0b0000_0010;
        let blob = decode_vault(&bytes).unwrap();
        assert!(header_check_of_1bac851(&blob).is_ok());
    }

    #[test]
    fn a_version_2_vault_relabelled_version_1_does_not_open() {
        // The downgrade an older reader would need: it fails the AEAD.
        let (_, sealed) = seal_fast(None, Some(&DATA_KEY));
        let mut bytes = encode_vault(&sealed);
        bytes[VERSION_BYTE] = 1;
        let blob = decode_vault(&bytes).unwrap();
        assert!(matches!(
            open_with_key(&blob, &KEY).err(),
            Some(VaultError::DecryptionFailed)
        ));
    }

    // ---- The header is authenticated ---------------------------------------

    #[test]
    fn every_header_byte_is_authenticated() {
        // Every bit of magic, version, flags, salt and nonce. The salt also
        // feeds the passphrase key; with a fixed key here, only the
        // associated data can catch it.
        for totp_secret in [None, Some(&b"totp"[..])] {
            let (_, sealed) = seal_fast(totp_secret, Some(&DATA_KEY));
            let bytes = encode_vault(&sealed);
            for byte in 0..FULL_HEADER_LEN {
                for bit in 0..8 {
                    let mut tampered = bytes.clone();
                    tampered[byte] ^= 1 << bit;
                    let opened = decode_vault(&tampered).and_then(|b| open_with_key(&b, &KEY));
                    assert!(opened.is_err(), "byte {byte} bit {bit} went unnoticed");
                }
            }
        }
    }

    #[test]
    fn flipping_a_known_flag_of_a_version_2_vault_fails_decryption() {
        for totp_secret in [None, Some(&b"totp"[..])] {
            let (_, sealed) = seal_fast(totp_secret, Some(&DATA_KEY));
            let mut bytes = encode_vault(&sealed);
            bytes[FLAGS_BYTE] ^= FLAG_NO_TOTP;
            let blob = decode_vault(&bytes).unwrap();
            assert!(matches!(
                open_with_key(&blob, &KEY).err(),
                Some(VaultError::DecryptionFailed)
            ));
        }
    }

    #[test]
    fn unknown_flags_of_a_version_2_vault_are_rejected() {
        let (_, sealed) = seal_fast(None, Some(&DATA_KEY));
        for flags in [0b0000_0010, 0b1000_0000, FLAG_NO_TOTP | 0b0000_0100] {
            let mut bytes = encode_vault(&sealed);
            bytes[FLAGS_BYTE] = flags;
            assert!(matches!(
                vault_requires_totp(&bytes),
                Err(VaultError::UnsupportedFlags(f)) if f == flags
            ));
        }
    }

    #[test]
    fn tampered_or_cut_ciphertext_does_not_open() {
        let (_, sealed) = seal_fast(None, Some(&DATA_KEY));
        let bytes = encode_vault(&sealed);
        let mut flipped = bytes.clone();
        *flipped.last_mut().unwrap() ^= 1;
        let mut body = bytes.clone();
        body[FULL_HEADER_LEN] ^= 1;
        for tampered in [flipped, body, bytes[..bytes.len() - 1].to_vec()] {
            let blob = decode_vault(&tampered).unwrap();
            assert!(matches!(
                open_with_key(&blob, &KEY).err(),
                Some(VaultError::DecryptionFailed)
            ));
        }
    }

    #[test]
    fn a_totp_flag_that_disagrees_with_the_sealed_payload_is_refused() {
        // In version 2 the flag is authenticated, so only a writer holding the
        // key could make it disagree: a bug, which must not open quietly.
        let claims_no_totp = seal_raw(2, FLAG_NO_TOTP, &payload(Some(b"totp"), None));
        let claims_totp = seal_raw(2, 0, &payload(None, None));
        for sealed in [claims_no_totp, claims_totp] {
            assert!(matches!(
                open_with_key(&sealed, &KEY).err(),
                Some(VaultError::BadPayload)
            ));
        }
    }

    #[test]
    fn a_wrong_key_does_not_open_a_version_2_vault() {
        let (_, sealed) = seal_fast(None, Some(&DATA_KEY));
        assert!(matches!(
            open_with_key(&sealed, &OTHER_KEY).err(),
            Some(VaultError::DecryptionFailed)
        ));
    }

    // ---- Version 2 golden vectors ------------------------------------------
    //
    // Sealed by this version's `seal_vault` and `encode_vault`, the identity
    // trimmed to one one-time prekey. They pin the format: AES-256-GCM under
    // PBKDF2-HMAC-SHA256 (600 000 iterations) of the passphrase, the 24 header
    // bytes before the nonce as associated data, and the app data as hex in
    // the payload's `app` field. Checked once outside this crate with Python's
    // `cryptography`, and against the real readers of 1bac851 and 4ce6775,
    // which both answer "unsupported vault version: 2".

    /// With TOTP (the RFC 6238 seed, `OLD_VAULT_TOTP_SECRET`); app data
    /// `01 02 .. 20`.
    pub(crate) const V2_VAULT_HEX: &str = "
        5452494e4f00 02 00
        03f0212ed18709eca055c9fe50d3473e
        dc0cc2c76dcbe69bfea4a4e4
        ad77d80e00d323baae65fc9d9c98b82f7e5aea49f4d38a8aa40060a98ef3701286125583af309098
        520a438a56ecede8315039a2cf3e398eba7c0be2088889b7ec0e4abee48f0cc649f3438c160482d4
        3a4add441790ead72edcafb5bb055f877c6ec2aeee69edff619e3c6ed30eef827a2bd6c6fac0a436
        af86350dfc515f4aefbf240806080cf731f805ef2316f464a3787848341ee0377209683b47f7eb01
        1b28f1f4d956c10279b64d2c6867701304bfdb16e5d9e00324b6cabde212b8a9821fd65ba121b885
        f487a4e3666f986eec59504a6896b4e9fa15b795b3b29a9baa48ff742b0f49ff1133e941257fa2e0
        f3b34a7a9e0c07ead6eb802b9475546cde3f5aa405e1b674dc16bac38cdcf9b05e168964e03306e6
        34a326ef07f820d5e758bbbfd56b04f4f43389f0ee77373b256f90edbbdad1f80ca5ff6487768422
        7a7dbf21326c6afc6ead17c97a0f6b3bdd5a935aafdb313341beef6b253c45c5ab0d524ef382b820
        9cdd9c2e6184c2d378485d1efe5008c510066db9b875106f2bb672d9e9a5f5d1b737c3a3fab6116b
        8ddae37e6567b9ef171f7de8caacb557fe12e42e907ce10481f4dfb3d4df64e4bea61eae0bc73ef2
        ba6ea51ae03a83a194baba7d3d6c6cd11885f91d3d98aee04c92727f1bbce0f32c0eb62f470aa2ca
        77ac8f8bc284210c0ebb29f24ee584ad5621eebba9b562091900a55c9e5ec3aac2d2982c8004eb5d
        02b0449ad0f49c946ec4ee94c7242d33bec2832244f6a383faa452c5817921b96238f1841b549907
        d0579534ab4a5dae0205f54fa0680756396a11d4323ed51f9dbf13f386f39ec23a5612cd5190fa17
        187fae9f8348c948b990a1c22c4d3b2d4f7d123744af5b0bdc4d1b24c63c2b1b052a5890c2c71a83
        8e783179cdeb19774068693300408bc2193559ba20af6b71e8e9956b3051e06da19e52a8e97d5990
        ee908d985764b1fc32d9d2c1984f8988c46bb33e32a274f71ab274a9530b9b084fe7513003bf3657
        cfedb07fecfc5fa2e1ef74121e6dbff8514ae0c0c308ff3856741b1eca0e1597d0090f154977a1ca
        80877475c07d7800e4e2a182e9fe26f4daabdddd6452b430547f79e468d11ff0562da7ef50d3b436
        8e87662a9f4062337c15bda3bf99c5e917a122aceb14e594db2de59669eae7142f3d97bf4c59c099
        d2bb8e1c871ea75d10df8c030f033bf7008524af00325f12c6fc0e377c5f4fe43b538e8a81395e57
        43cd11c2242717b2f5645a3a4c3228241381dc820a367b77a32402074b76dd95581345640fd68311
        d70ae0e2684aa266fb1265c7bb9ff7cd867f9e8a48c9d2071d1df9afb0eda059e18277c4c8dcb5a9
        d489b3419f17ad22adf7498ad6b886e49a205120a523678f907bbc53b4645eda7b12cc7d8a4e89fb
        7c29746b07d3162c6b99b7eb6aa7ea478092185079266e49288ccee99a84c9694a39a7f70059f691
        7deabef8959f130fe47abe8398562c5d0c68d12432f86f2003ebbeeb4c815f8c8f69eeca3dad0069
        b3b658523fcb945012e4c09d3cb2c60c4b14d51d9db2344da692540fa1c703cdadafa28776aa3318
        723be342060bf06bc342f6d90d11eeb4501042c8a7644b34358168da70e915b6f0a3912e7f1efd6f
        6e6ccdae1ad343dffd69c88e43ed20c5be7397
    ";
    pub(crate) const V2_VAULT_PASSPHRASE: &str = "trino-core vault v2 fixture";
    pub(crate) const V2_VAULT_IK_SIGN_PUB: &str =
        "909e237bfe6a53460dc9cb099b8ec2d00cf4ba23c5e20b33bdef46bd95e15c83";

    /// Without TOTP; 48 bytes of app data, `30 31 .. 5f`.
    pub(crate) const V2_VAULT_NO_TOTP_HEX: &str = "
        5452494e4f00 02 01
        5418bd3ae1762019ae459a9fc7c67214
        2765e7b9086505a8e4f1f1a7
        50c039e02b5600a9c933fef95e5279c68aaedc19d1e6324d499dda33db1bf6bfca125a6f4bac82f0
        927efa2a39e5ccbf0585f53459cd6732c45997d2e7c3ea545b1aac0058658c30801d216dd37b0985
        d412f5536049d9ae79fe73132030e5689d955293e5ef1e3c2894cb0d870e31a0eb008cd25d00fdb3
        34f15c3915165f60e7ee9c1773c1cba4d76d674702b7e0dd64f39d0fbe570bc55d3e01dcea5756d4
        755e61cce929b0f62542f00d45ff340659ec771fcd974f7d26ae8672af63d72d1a000337555e37fa
        40860aea8bc181591101c09d55d5e76ebac5053ad7d0e594e781406c77a522d73de0f3e3531f6db9
        5d3572445675d31fdb42dd774ef8bc9c470ed623f892ac733972c216d4ca95334493b0efffdfc458
        d1b0a8c505faed3bf6602fcba7c2f85619a2bc21824cbff3897cd015a1e26eec655cd47c22a82d8a
        ca3b4087cf6b13d74c27248a1bfdc1ca20fd3e52275ae9a9d9e473d002b2b0c4ebf59f1ad168b3f3
        6497ad14fb4176d2172a616d601f551f4354ce1ffc7a620bf040d9a157ab350908fd972aca811642
        61f03baa1c24314d3e3779f4d713c6e6b191c214501ab3bc83d04f00ae1e982192cf35f9fac05955
        1b9c9227986a986db106e59c326fd8d757a54fb722ff5d9e5b7a8207b404623837b0a1b1addd0676
        6f1a33b6dcaae553e3dabd72e8914c5ad76bfed8bc508cdb3151cbe465b9b8ea5a18c67f27885a12
        b8d724f08c8408569f4da953974c365b098d187f4376c8645b1ee10196f71197b73364eb9e8a4ba1
        a444b181b6f7930bd56e0ae1291509a062b92a69f692eca147ab16c299fe0861fc8fd3612a0a44c6
        30a9761c767f8f149c0d5d7fe4866bf4ddaba83d31642dda4ce02a1bfb45cac3315849f8d62fdb85
        0222861392fa7bf0107dd5e053e4d5aee7767040f17c01fc7f675219fd6f383a90ed5bfbdd4bad56
        27367c9cd799d127a9f35e89f95b17326112684259ef954257cb2528e05ae3f6917b63c8a55163a1
        a4ff71d198078a8a16552e143b16b55dc09470698e5b11298969e72e9e3230a02ac08dd0a3b28660
        ecc1993208765a1eb33e582bb6ea01e66c92a601f042e725833645aff3e73428a91c6fbe99b677a9
        911f843a599fbb6a0f172ca710aaf2e9effeaeb22f5ddebb14db9ea020dcec18a57e82da2b4ba378
        b1b6cb4972e0c2a65e1ad292bf37857cb02fece4f704aef75469cfbf4085046046946035d0de954b
        ef7f5ba53763859b1491ca47ee290b35e7c29b6a038daa7eccbb25f1edc4f7e25ba79d6bf3f87946
        f50588886c938c325cd96b513df5f99a366e216aacdc25a639e6aa3eb47fa076cdf0483e85498858
        a1a3821d4983b15a331d36bb616f559f53bd8f16eb9c52ab8214c76d6ed40cb2a2b5c170524b4f57
        29ca5c3adc85186b7601db54d7134c339c92f97826890dfd1ccadecbe555f46a6d3a6344cb6c6f6f
        5d4eaa70bb0eab9f63354e56e775683dc1f02dcbdaecf6a9fccdcedb73b80e903d3a6d76d1afd554
        30424856453804e24304116177c17c018f8f1007aec8109331fc75b40003aa38a3a7547301bf7f99
        b945fc2fad978719fe120d0e4616e7c61c440c545b84961dc6ac2e6c904ff85f676969
    ";
    pub(crate) const V2_VAULT_NO_TOTP_PASSPHRASE: &str = "trino-core vault v2 fixture, no TOTP";
    pub(crate) const V2_VAULT_NO_TOTP_IK_SIGN_PUB: &str =
        "e95155e0b833b6330c4a51b5800d6472750dd64d3b30b7defb9c3df6350514a9";

    pub(crate) fn golden(hex_block: &str) -> Vec<u8> {
        hex::decode(hex_block.split_whitespace().collect::<String>()).unwrap()
    }

    #[test]
    fn golden_version_2_vault_with_totp_opens_to_its_app_data() {
        let _guard = lock();
        let bytes = golden(V2_VAULT_HEX);
        assert_eq!((bytes[VERSION_BYTE], bytes[FLAGS_BYTE]), (2, 0));
        assert!(vault_requires_totp(&bytes).unwrap());
        let blob = decode_vault(&bytes).unwrap();
        let code = totp_now(OLD_VAULT_TOTP_SECRET);
        let opened = unseal_vault(&blob, V2_VAULT_PASSPHRASE, Some(&code)).unwrap();
        assert_eq!(
            hex::encode(opened.identity.ik_sign.pub_bytes),
            V2_VAULT_IK_SIGN_PUB
        );
        assert_eq!(opened.totp_secret.as_deref(), Some(OLD_VAULT_TOTP_SECRET));
        let app: Vec<u8> = (1..=32).collect();
        assert_eq!(opened.app.as_deref(), Some(&app));
    }

    #[test]
    fn golden_version_2_vault_gives_nothing_without_its_code() {
        let _guard = lock();
        let blob = decode_vault(&golden(V2_VAULT_HEX)).unwrap();
        assert!(matches!(
            unseal_vault(&blob, V2_VAULT_PASSPHRASE, None).err(),
            Some(VaultError::TotpRequired)
        ));
    }

    #[test]
    fn golden_version_2_vault_without_totp_opens_to_its_app_data() {
        let _guard = lock();
        let bytes = golden(V2_VAULT_NO_TOTP_HEX);
        assert_eq!((bytes[VERSION_BYTE], bytes[FLAGS_BYTE]), (2, FLAG_NO_TOTP));
        assert!(!vault_requires_totp(&bytes).unwrap());
        let blob = decode_vault(&bytes).unwrap();
        let opened = unseal_vault(&blob, V2_VAULT_NO_TOTP_PASSPHRASE, None).unwrap();
        assert_eq!(
            hex::encode(opened.identity.ik_sign.pub_bytes),
            V2_VAULT_NO_TOTP_IK_SIGN_PUB
        );
        assert_eq!(opened.totp_secret, None);
        let app: Vec<u8> = (0x30..0x60).collect();
        assert_eq!(opened.app.as_deref(), Some(&app));
    }

    #[test]
    fn golden_version_2_vaults_stop_older_readers() {
        for bytes in [golden(V2_VAULT_HEX), golden(V2_VAULT_NO_TOTP_HEX)] {
            let blob = decode_vault(&bytes).unwrap();
            assert!(matches!(
                header_check_of_1bac851(&blob),
                Err(VaultError::UnsupportedVersion(2))
            ));
            assert!(matches!(
                header_check_of_4ce6775(blob.version, blob.flags),
                Err(VaultError::UnsupportedVersion(2))
            ));
        }
    }
}
