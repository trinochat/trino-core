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

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("unsupported vault version: {0}")]
    UnsupportedVersion(u8),
    #[error("vault file is too short or corrupted")]
    Corrupted,
    #[error("not a trino vault (bad magic bytes)")]
    BadMagic,
    #[error("decryption failed (wrong passphrase or tampered vault)")]
    DecryptionFailed,
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
    totp_secret: String,
    /// Rotated-out signed prekeys still within their retention window.
    /// Defaulted so vaults sealed before rotation existed still open.
    #[serde(default)]
    retired_signed_pre_keys: Vec<SerializedSignedPreKey>,
}

pub fn seal_vault(
    identity: &Identity,
    totp_secret: &[u8],
    passphrase: &str,
) -> Result<SealedVault, VaultError> {
    let salt: [u8; SALT_SIZE] = random_array();
    let key = pbkdf2_sha256(passphrase.as_bytes(), &salt, PBKDF2_ITERATIONS);

    let payload = serialize_identity(identity, totp_secret);
    let payload_bytes = serde_json::to_vec(&payload).map_err(|_| VaultError::BadPayload)?;

    let (ciphertext, nonce) = aes_gcm_encrypt(&key, &payload_bytes, None)?;

    Ok(SealedVault {
        version: VAULT_VERSION,
        salt,
        nonce,
        ciphertext,
    })
}

pub fn unseal_vault(
    blob: &SealedVault,
    passphrase: &str,
    totp_code_input: &str,
) -> Result<(Identity, Vec<u8>), VaultError> {
    if blob.version != VAULT_VERSION {
        return Err(VaultError::UnsupportedVersion(blob.version));
    }

    let key = pbkdf2_sha256(passphrase.as_bytes(), &blob.salt, PBKDF2_ITERATIONS);
    let plaintext = aes_gcm_decrypt(&key, &blob.ciphertext, &blob.nonce, None)
        .map_err(|_| VaultError::DecryptionFailed)?;

    let serialized: SerializedIdentity =
        serde_json::from_slice(&plaintext).map_err(|_| VaultError::BadPayload)?;
    let (identity, totp_secret) = deserialize_identity(serialized)?;

    if !is_totp_code_valid(totp_code_input, &totp_secret) {
        return Err(VaultError::InvalidTotp);
    }

    Ok((identity, totp_secret))
}

pub fn encode_vault(v: &SealedVault) -> Vec<u8> {
    let mut out = Vec::with_capacity(VAULT_MAGIC.len() + 2 + SALT_SIZE + 12 + v.ciphertext.len());
    out.extend_from_slice(VAULT_MAGIC);
    out.push(v.version);
    out.push(0);
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
        salt,
        nonce,
        ciphertext,
    })
}

fn serialize_identity(identity: &Identity, totp_secret: &[u8]) -> SerializedIdentity {
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
        totp_secret: hex::encode(totp_secret),
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

fn deserialize_identity(s: SerializedIdentity) -> Result<(Identity, Vec<u8>), VaultError> {
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
    let totp_secret = hex::decode(&s.totp_secret).map_err(|_| VaultError::BadPayload)?;
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
    use std::sync::Mutex;

    // PBKDF2-600k tests are intentionally expensive. Running them concurrently
    // can push a freshly generated TOTP outside its validation window.
    static VAULT_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn seal_unseal_roundtrip() {
        let _guard = VAULT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let id = create_identity();
        let totp_secret = generate_totp_secret();
        let sealed = seal_vault(&id, &totp_secret, "correct horse battery").unwrap();
        let code = totp_now(&totp_secret);
        let (restored, secret) = unseal_vault(&sealed, "correct horse battery", &code).unwrap();
        assert_eq!(restored.ik_sign.priv_bytes, id.ik_sign.priv_bytes);
        assert_eq!(restored.ik_dh.pub_bytes, id.ik_dh.pub_bytes);
        assert_eq!(secret, totp_secret);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let _guard = VAULT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let id = create_identity();
        let totp_secret = generate_totp_secret();
        let sealed = seal_vault(&id, &totp_secret, "right").unwrap();
        let code = totp_now(&totp_secret);
        assert!(unseal_vault(&sealed, "wrong", &code).is_err());
    }

    #[test]
    fn wrong_totp_fails() {
        let _guard = VAULT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let id = create_identity();
        let totp_secret = generate_totp_secret();
        let sealed = seal_vault(&id, &totp_secret, "pass").unwrap();
        let err = unseal_vault(&sealed, "pass", "000000").err();
        assert!(matches!(err, Some(VaultError::InvalidTotp)));
    }

    #[test]
    fn binary_encode_decode_roundtrip() {
        let _guard = VAULT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let id = create_identity();
        let totp_secret = generate_totp_secret();
        let sealed = seal_vault(&id, &totp_secret, "pass").unwrap();
        let bytes = encode_vault(&sealed);
        let decoded = decode_vault(&bytes).unwrap();
        assert_eq!(decoded.salt, sealed.salt);
        assert_eq!(decoded.nonce, sealed.nonce);
        assert_eq!(decoded.ciphertext, sealed.ciphertext);
        assert_eq!(decoded.version, sealed.version);
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
        let raw = serde_json::to_value(serialize_identity(&id, b"totp")).unwrap();
        let (restored, _) = deserialize_identity(serde_json::from_value(raw).unwrap()).unwrap();
        assert_eq!(retirement_times(&restored), retirement_times(&id));
    }

    #[test]
    fn vault_without_retirement_times_takes_them_from_the_next_key() {
        // Vaults sealed before `retiredAt` existed store only `createdAt`.
        // Rotation creates the next key at the moment it retires the old one,
        // so the next key's creation time is the old key's retirement time.
        let id = rotated_twice();
        let mut raw = serde_json::to_value(serialize_identity(&id, b"totp")).unwrap();
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
}
