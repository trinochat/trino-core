//! The sealed vault: the identity, its prekeys and, if the user turned it on,
//! a TOTP secret, encrypted under a passphrase.
//!
//! On disk (`encode_vault`):
//!
//! | Bytes | Field                                          |
//! |-------|------------------------------------------------|
//! | 6     | magic, `TRINO\0`                               |
//! | 1     | format version, `1`                            |
//! | 1     | flags: bit 0 set means sealed without TOTP     |
//! | 16    | PBKDF2 salt                                    |
//! | 12    | AES-GCM nonce                                  |
//! | rest  | the JSON payload under AES-256-GCM             |
//!
//! The key is PBKDF2-HMAC-SHA256 of the passphrase, 600 000 iterations.
//!
//! The header is not authenticated, so nothing in it is trusted. The flags
//! only tell the UI whether to ask for a code (`vault_requires_totp`); once the
//! payload is decrypted, it alone decides. The flags byte was reserved, and
//! always zero, until TOTP became optional, so older vaults read as "TOTP on",
//! which is true of all of them. Bits this version does not know are rejected
//! with `VaultError::UnsupportedFlags` before any key derivation, as an unknown
//! version is: they are kept for format changes an older reader would misread.
//!
//! The TOTP code is checked after decryption, against a secret stored inside
//! the vault. It guards the unlock screen, not a stolen copy of the file:
//! whoever has the file and the passphrase has the secret too.

use crate::crypto::{aes_gcm_decrypt, aes_gcm_encrypt, pbkdf2_sha256, random_array, CryptoError};
use crate::identity::{
    decode_array_32, decode_array_64, Identity, IdentityError, KeyPair, OneTimePreKey,
    RetiredSignedPreKey, SignedPreKey,
};
use crate::totp::is_totp_code_valid;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const PBKDF2_ITERATIONS: u32 = 600_000;
const SALT_SIZE: usize = 16;
const VAULT_VERSION: u8 = 1;
const VAULT_MAGIC: &[u8] = b"TRINO\0";
/// Header flag: sealed without TOTP. A zero flags byte, as in every vault from
/// before TOTP became optional, means TOTP is on.
const FLAG_NO_TOTP: u8 = 0b0000_0001;
/// Every flag bit this version understands. Any other bit set is rejected.
const KNOWN_FLAGS: u8 = FLAG_NO_TOTP;

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
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("identity: {0}")]
    Identity(#[from] IdentityError),
}

#[derive(Debug, Clone)]
pub struct SealedVault {
    pub version: u8,
    /// Header flags, stored outside the encryption: see `vault_requires_totp`.
    pub flags: u8,
    pub salt: [u8; SALT_SIZE],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SerializedKeyPair {
    #[serde(rename = "priv")]
    priv_hex: String,
    #[serde(rename = "pub")]
    pub_hex: String,
}

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
struct SerializedOneTimePreKey {
    id: u32,
    keypair: SerializedKeyPair,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SerializedIdentity {
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
}

/// Seals the identity under `passphrase`. With `totp_secret` set, opening the
/// vault will also demand a valid code for it; with `None`, it will not.
pub fn seal_vault(
    identity: &Identity,
    totp_secret: Option<&[u8]>,
    passphrase: &str,
) -> Result<SealedVault, VaultError> {
    let salt: [u8; SALT_SIZE] = random_array();
    let key = pbkdf2_sha256(passphrase.as_bytes(), &salt, PBKDF2_ITERATIONS);

    let payload = serialize_identity(identity, totp_secret);
    let payload_bytes = serde_json::to_vec(&payload).map_err(|_| VaultError::BadPayload)?;

    let (ciphertext, nonce) = aes_gcm_encrypt(&key, &payload_bytes, None)?;
    let flags = match totp_secret {
        Some(_) => 0,
        None => FLAG_NO_TOTP,
    };

    Ok(SealedVault {
        version: VAULT_VERSION,
        flags,
        salt,
        nonce,
        ciphertext,
    })
}

/// Opens the vault and returns the identity and its TOTP secret, if it has one.
///
/// The decrypted payload decides whether a code is needed: a vault that holds
/// a TOTP secret fails with `TotpRequired` when `totp_code` is `None` and with
/// `InvalidTotp` when the code is wrong. A vault without a secret ignores any
/// code it is given.
pub fn unseal_vault(
    blob: &SealedVault,
    passphrase: &str,
    totp_code: Option<&str>,
) -> Result<(Identity, Option<Vec<u8>>), VaultError> {
    check_header(blob.version, blob.flags)?;

    let key = pbkdf2_sha256(passphrase.as_bytes(), &blob.salt, PBKDF2_ITERATIONS);
    let plaintext = aes_gcm_decrypt(&key, &blob.ciphertext, &blob.nonce, None)
        .map_err(|_| VaultError::DecryptionFailed)?;

    let serialized: SerializedIdentity =
        serde_json::from_slice(&plaintext).map_err(|_| VaultError::BadPayload)?;
    let (identity, totp_secret) = deserialize_identity(serialized)?;

    if let Some(secret) = &totp_secret {
        let code = totp_code.ok_or(VaultError::TotpRequired)?;
        if !is_totp_code_valid(code, secret) {
            return Err(VaultError::InvalidTotp);
        }
    }

    Ok((identity, totp_secret))
}

/// Whether opening this encoded vault will ask for a TOTP code, read from the
/// header flags without decrypting anything.
///
/// **An unauthenticated UI hint only.** The header is outside the encryption,
/// so anyone who can write the file can flip the answer. It grants and denies
/// nothing: `unseal_vault` follows the sealed payload, so a vault that holds a
/// TOTP secret still demands a valid code whatever its header says. Use it to
/// decide whether to show the code field, and still handle `TotpRequired`.
pub fn vault_requires_totp(bytes: &[u8]) -> Result<bool, VaultError> {
    let vault = decode_vault(bytes)?;
    check_header(vault.version, vault.flags)?;
    Ok(vault.flags & FLAG_NO_TOTP == 0)
}

/// Rejects a header this version cannot read, before any key derivation.
fn check_header(version: u8, flags: u8) -> Result<(), VaultError> {
    if version != VAULT_VERSION {
        return Err(VaultError::UnsupportedVersion(version));
    }
    if flags & !KNOWN_FLAGS != 0 {
        return Err(VaultError::UnsupportedFlags(flags));
    }
    Ok(())
}

pub fn encode_vault(v: &SealedVault) -> Vec<u8> {
    let mut out = Vec::with_capacity(VAULT_MAGIC.len() + 2 + SALT_SIZE + 12 + v.ciphertext.len());
    out.extend_from_slice(VAULT_MAGIC);
    out.push(v.version);
    out.push(v.flags);
    out.extend_from_slice(&v.salt);
    out.extend_from_slice(&v.nonce);
    out.extend_from_slice(&v.ciphertext);
    out
}

pub fn decode_vault(bytes: &[u8]) -> Result<SealedVault, VaultError> {
    let min_size = VAULT_MAGIC.len() + 2 + SALT_SIZE + 12;
    if bytes.len() < min_size {
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
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bytes[off..off + 12]);
    off += 12;
    let ciphertext = bytes[off..].to_vec();
    Ok(SealedVault {
        version,
        flags,
        salt,
        nonce,
        ciphertext,
    })
}

fn serialize_identity(identity: &Identity, totp_secret: Option<&[u8]>) -> SerializedIdentity {
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
    }
}

fn deserialize_identity(s: SerializedIdentity) -> Result<(Identity, Option<Vec<u8>>), VaultError> {
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
    Ok((identity, totp_secret))
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
mod tests {
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
        sealed: SealedVault,
    }

    impl TestVault {
        fn seal(totp_secret: Option<Vec<u8>>) -> Self {
            let identity = create_identity();
            let sealed = seal_vault(&identity, totp_secret.as_deref(), PASSPHRASE).unwrap();
            TestVault {
                identity,
                totp_secret,
                sealed,
            }
        }
    }

    // Every seal is a full PBKDF2 run, so the tests share one vault of each
    // kind. Call these with the lock held: the first call does the sealing.
    fn with_totp() -> &'static TestVault {
        static VAULT: OnceLock<TestVault> = OnceLock::new();
        VAULT.get_or_init(|| TestVault::seal(Some(generate_totp_secret())))
    }

    fn without_totp() -> &'static TestVault {
        static VAULT: OnceLock<TestVault> = OnceLock::new();
        VAULT.get_or_init(|| TestVault::seal(None))
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let _guard = lock();
        let vault = with_totp();
        let totp_secret = vault.totp_secret.as_deref().unwrap();
        let code = totp_now(totp_secret);
        let (restored, secret) = unseal_vault(&vault.sealed, PASSPHRASE, Some(&code)).unwrap();
        assert_eq!(
            restored.ik_sign.priv_bytes,
            vault.identity.ik_sign.priv_bytes
        );
        assert_eq!(restored.ik_dh.pub_bytes, vault.identity.ik_dh.pub_bytes);
        assert_eq!(secret.as_deref(), Some(totp_secret));
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
        let (restored, secret) = unseal_vault(&vault.sealed, PASSPHRASE, None).unwrap();
        assert_eq!(
            restored.ik_sign.priv_bytes,
            vault.identity.ik_sign.priv_bytes
        );
        assert_eq!(restored.ik_dh.pub_bytes, vault.identity.ik_dh.pub_bytes);
        assert_eq!(secret, None);
    }

    #[test]
    fn vault_without_totp_ignores_a_supplied_code() {
        let _guard = lock();
        let opened = unseal_vault(&without_totp().sealed, PASSPHRASE, Some("000000"));
        assert_eq!(opened.unwrap().1, None);
    }

    #[test]
    fn payload_without_totp_has_no_secret_field() {
        let id = create_identity();
        let raw = serde_json::to_value(serialize_identity(&id, None)).unwrap();
        assert!(raw.get("totpSecret").is_none());
        let (_, secret) = deserialize_identity(serde_json::from_value(raw).unwrap()).unwrap();
        assert_eq!(secret, None);
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

    /// The flags byte: after the 6-byte magic and the version.
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
        // Another version may give the flags byte another meaning.
        let mut bytes = old_vault();
        bytes[FLAGS_BYTE - 1] = 2;
        assert!(matches!(
            vault_requires_totp(&bytes),
            Err(VaultError::UnsupportedVersion(2))
        ));
    }

    // The flags sit outside the AES-GCM envelope, so whoever can write the file
    // can flip them. They only steer the UI; the sealed payload decides.

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
        let vault = without_totp();
        let mut bytes = encode_vault(&vault.sealed);
        bytes[FLAGS_BYTE] &= !FLAG_NO_TOTP;
        assert!(vault_requires_totp(&bytes).unwrap());
        let blob = decode_vault(&bytes).unwrap();
        let (restored, secret) = unseal_vault(&blob, PASSPHRASE, None).unwrap();
        assert_eq!(
            restored.ik_sign.priv_bytes,
            vault.identity.ik_sign.priv_bytes
        );
        assert_eq!(secret, None);
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
        let raw = serde_json::to_value(serialize_identity(&id, Some(b"totp".as_slice()))).unwrap();
        let (restored, _) = deserialize_identity(serde_json::from_value(raw).unwrap()).unwrap();
        assert_eq!(retirement_times(&restored), retirement_times(&id));
    }

    #[test]
    fn vault_without_retirement_times_takes_them_from_the_next_key() {
        // Vaults sealed before `retiredAt` existed store only `createdAt`.
        // Rotation creates the next key at the moment it retires the old one,
        // so the next key's creation time is the old key's retirement time.
        let id = rotated_twice();
        let mut raw =
            serde_json::to_value(serialize_identity(&id, Some(b"totp".as_slice()))).unwrap();
        for retired in raw["retiredSignedPreKeys"].as_array_mut().unwrap() {
            retired.as_object_mut().unwrap().remove("retiredAt");
        }
        let (restored, _) = deserialize_identity(serde_json::from_value(raw).unwrap()).unwrap();
        assert_eq!(retirement_times(&restored), retirement_times(&id));
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
    const OLD_VAULT_PASSPHRASE: &str = "trino-core 1bac851 fixture";
    /// RFC 6238's SHA-1 seed, so the tests can compute a valid code.
    const OLD_VAULT_TOTP_SECRET: &[u8] = b"12345678901234567890";
    const OLD_VAULT_IK_SIGN_PUB: &str =
        "84aa175b86e7d4eb0f1b84afd20e4654174c929e699c8e548ee535ae6292d06a";

    fn old_vault() -> Vec<u8> {
        hex::decode(OLD_VAULT_HEX.split_whitespace().collect::<String>()).unwrap()
    }

    #[test]
    fn vault_sealed_before_optional_totp_opens_with_its_code() {
        let _guard = lock();
        let blob = decode_vault(&old_vault()).unwrap();
        let code = totp_now(OLD_VAULT_TOTP_SECRET);
        let (restored, secret) = unseal_vault(&blob, OLD_VAULT_PASSPHRASE, Some(&code)).unwrap();
        assert_eq!(
            hex::encode(restored.ik_sign.pub_bytes),
            OLD_VAULT_IK_SIGN_PUB
        );
        assert_eq!(secret.as_deref(), Some(OLD_VAULT_TOTP_SECRET));
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
}
