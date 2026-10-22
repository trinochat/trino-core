//! The bytes of a version 3 vault: header, slots, shared block and body.

use super::{MAX_KIT_LEN, MAX_TOTP_SECRET_LEN, V3_VAULT_LEN};
use crate::crypto::{
    aes_gcm_decrypt, aes_gcm_encrypt, aes_gcm_encrypt_with_nonce, hkdf_expand, random_array,
    NONCE_SIZE, TAG_SIZE,
};
use crate::identity::Identity;
use crate::kdf::KdfParams;
use crate::vault::{
    check_app_data, deserialize_identity, serialize_identity, SerializedIdentity, VaultError,
};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub(super) const MAGIC: &[u8; 6] = b"TRINO\0";
pub(super) const VERSION: u8 = 3;
/// The `kdf` byte for Argon2id, version 0x13.
pub(super) const KDF_ARGON2ID: u8 = 1;

pub(super) const HEADER_LEN: usize = 64;
pub(super) const VERSION_AT: usize = 6;
pub(super) const FLAGS_AT: usize = 7;
pub(super) const KDF_AT: usize = 8;
pub(super) const M_AT: usize = 9;
pub(super) const T_AT: usize = 13;
pub(super) const P_AT: usize = 17;
pub(super) const SALT_AT: usize = 18;
pub(super) const ID_VAULT_AT: usize = 34;
pub(super) const RESERVED_AT: usize = 50;
pub(super) const HINT_AT: usize = HEADER_LEN;

pub(super) const SLOT_COUNT: usize = 3;
pub(super) const SLOT_LEN: usize = 81;
pub(super) const SLOT_LEAD_LEN: usize = 32;
pub(super) const SLOTS_AT: usize = HINT_AT + 1;
pub(super) const SHARED_AT: usize = SLOTS_AT + SLOT_COUNT * SLOT_LEN;
pub(super) const SHARED_LEN: usize = 8 * 1024;
pub(super) const BODY_AT: usize = SHARED_AT + SHARED_LEN;
pub(super) const BODY_LEN: usize = V3_VAULT_LEN - BODY_AT;

const AEAD_OVERHEAD: usize = NONCE_SIZE + TAG_SIZE;
pub(super) const SHARED_PLAIN_LEN: usize = SHARED_LEN - AEAD_OVERHEAD;
/// Version, TOTP length, TOTP (padded to 64), redirect key, app length.
const SHARED_FIXED_LEN: usize = 1 + 1 + MAX_TOTP_SECRET_LEN + 32 + 2;
pub(super) const SHARED_APP_CAPACITY: usize = SHARED_PLAIN_LEN - SHARED_FIXED_LEN;
const SHARED_FORMAT: u8 = 1;
pub(super) const BODY_PLAIN_LEN: usize = BODY_LEN - AEAD_OVERHEAD;
/// The longest body JSON that fits, after its 4-byte length.
pub(super) const BODY_JSON_MAX: usize = BODY_PLAIN_LEN - 4;

/// What a slot wraps (the type byte, inside the encryption). The emergency
/// slot is type 2, the recovery kit's (later) type 3 and the redirect type 4.
pub(super) const SLOT_REAL: u8 = 1;
pub(super) const SLOT_EMERGENCY: u8 = 2;

pub(super) type SlotBytes = [u8; SLOT_LEN];

const SLOT_INFO: &[u8] = b"trino/vault/v3/slot";
const BODY_INFO: &[u8] = b"trino/vault/v3/body";
const SHARED_INFO: &[u8] = b"trino/vault/v3/shared";

/// The header fields that are not constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Header {
    pub params: KdfParams,
    pub salt: [u8; 16],
    pub id_vault: [u8; 16],
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[..VERSION_AT].copy_from_slice(MAGIC);
        h[VERSION_AT] = VERSION;
        h[FLAGS_AT] = 0;
        h[KDF_AT] = KDF_ARGON2ID;
        h[M_AT..T_AT].copy_from_slice(&self.params.m_kib.to_le_bytes());
        h[T_AT..P_AT].copy_from_slice(&self.params.t.to_le_bytes());
        h[P_AT] = self.params.p;
        h[SALT_AT..ID_VAULT_AT].copy_from_slice(&self.salt);
        h[ID_VAULT_AT..RESERVED_AT].copy_from_slice(&self.id_vault);
        h
    }

    /// Reads and checks the header and the hint of an encoded vault, before
    /// any key is derived. Returns the header and the hint.
    ///
    /// Everything here fails the same way for any passphrase: the length,
    /// the magic, the version, the flags (zero in version 3), the KDF, the
    /// parameter bounds, the reserved bytes and the hint.
    pub fn parse(bytes: &[u8]) -> Result<(Header, bool), VaultError> {
        if bytes.len() != V3_VAULT_LEN {
            return Err(VaultError::Corrupted);
        }
        if &bytes[..VERSION_AT] != MAGIC {
            return Err(VaultError::BadMagic);
        }
        if bytes[VERSION_AT] != VERSION {
            return Err(VaultError::UnsupportedVersion(bytes[VERSION_AT]));
        }
        if bytes[FLAGS_AT] != 0 {
            return Err(VaultError::UnsupportedFlags(bytes[FLAGS_AT]));
        }
        if bytes[KDF_AT] != KDF_ARGON2ID {
            return Err(VaultError::UnsupportedKdf(bytes[KDF_AT]));
        }
        if bytes[RESERVED_AT..HEADER_LEN].iter().any(|&b| b != 0) {
            return Err(VaultError::Corrupted);
        }
        let params = KdfParams {
            m_kib: u32::from_le_bytes(bytes[M_AT..T_AT].try_into().expect("4 bytes")),
            t: u32::from_le_bytes(bytes[T_AT..P_AT].try_into().expect("4 bytes")),
            p: bytes[P_AT],
        };
        params.check()?;
        let hint = match bytes[HINT_AT] {
            0 => false,
            1 => true,
            _ => return Err(VaultError::Corrupted),
        };
        let header = Header {
            params,
            salt: bytes[SALT_AT..ID_VAULT_AT].try_into().expect("16 bytes"),
            id_vault: bytes[ID_VAULT_AT..RESERVED_AT]
                .try_into()
                .expect("16 bytes"),
        };
        Ok((header, hint))
    }
}

/// Which slot is which. Drawn at random when the vault is created, and
/// written in the body of every vault (RC-11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Positions {
    pub real: u8,
    pub emergency: u8,
    pub recovery: u8,
}

impl Positions {
    pub fn random() -> Positions {
        let mut order = [0u8, 1, 2];
        order.shuffle(&mut rand::thread_rng());
        Positions {
            real: order[0],
            emergency: order[1],
            recovery: order[2],
        }
    }

    fn to_array(self) -> [u8; 3] {
        [self.real, self.emergency, self.recovery]
    }

    fn from_array(a: [u8; 3]) -> Result<Positions, VaultError> {
        let mut sorted = a;
        sorted.sort_unstable();
        if sorted != [0, 1, 2] {
            return Err(VaultError::BadPayload);
        }
        Ok(Positions {
            real: a[0],
            emergency: a[1],
            recovery: a[2],
        })
    }
}

// ---- Keys -------------------------------------------------------------------

fn derive_key(ikm: &[u8], id_vault: &[u8; 16], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let okm = hkdf_expand(ikm, id_vault, info, 32).expect("32 bytes is a valid HKDF length");
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&okm);
    key
}

/// `k_r`: what a passphrase's KEK opens slots with.
pub(super) fn slot_key(kek: &[u8; 32], id_vault: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    derive_key(kek, id_vault, SLOT_INFO)
}

fn body_key(mk: &[u8; 32], id_vault: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    derive_key(mk, id_vault, BODY_INFO)
}

fn shared_key(k2fa: &[u8; 32], id_vault: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    derive_key(k2fa, id_vault, SHARED_INFO)
}

// ---- Slots ------------------------------------------------------------------

/// A slot's associated data: its format, the vault and its position.
pub(super) fn slot_aad(id_vault: &[u8; 16], position: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SLOT_INFO.len() + 17);
    aad.extend_from_slice(SLOT_INFO);
    aad.extend_from_slice(id_vault);
    aad.push(position);
    aad
}

/// Seals `kind ‖ key` under `k` with `lead` in front; the nonce is the
/// lead's first 12 bytes.
pub(super) fn seal_slot_with_lead(
    k: &[u8; 32],
    lead: [u8; SLOT_LEAD_LEN],
    id_vault: &[u8; 16],
    position: u8,
    kind: u8,
    key: &[u8; 32],
) -> SlotBytes {
    let mut plain = Zeroizing::new([0u8; 33]);
    plain[0] = kind;
    plain[1..].copy_from_slice(key);
    let nonce: [u8; NONCE_SIZE] = lead[..NONCE_SIZE].try_into().expect("12 bytes");
    let sealed =
        aes_gcm_encrypt_with_nonce(k, &nonce, &plain[..], Some(&slot_aad(id_vault, position)))
            .expect("a 32-byte key always encrypts");
    let mut slot = [0u8; SLOT_LEN];
    slot[..SLOT_LEAD_LEN].copy_from_slice(&lead);
    slot[SLOT_LEAD_LEN..].copy_from_slice(&sealed);
    slot
}

/// A slot wrapping `key` as `kind` under `k`: a random lead (the nonce and
/// 20 random bytes), then the sealed type and key.
pub(super) fn seal_slot(
    k: &[u8; 32],
    id_vault: &[u8; 16],
    position: u8,
    kind: u8,
    key: &[u8; 32],
) -> SlotBytes {
    seal_slot_with_lead(k, random_array(), id_vault, position, kind, key)
}

/// Opens a slot with `k`, or `None`. Whatever happens, the same work.
pub(super) fn open_slot(
    k: &[u8; 32],
    id_vault: &[u8; 16],
    position: u8,
    slot: &[u8],
) -> Option<(u8, Zeroizing<[u8; 32]>)> {
    #[cfg(test)]
    super::tests::count_slot_try();
    let nonce = &slot[..NONCE_SIZE];
    let plain = aes_gcm_decrypt(
        k,
        &slot[SLOT_LEAD_LEN..],
        nonce,
        Some(&slot_aad(id_vault, position)),
    )
    .ok()
    .map(Zeroizing::new)?;
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&plain[1..]);
    Some((plain[0], key))
}

/// An unused slot: random bytes, as long as any slot.
pub(super) fn random_slot() -> SlotBytes {
    random_array()
}

pub(super) fn slot_range(position: u8) -> std::ops::Range<usize> {
    let at = SLOTS_AT + usize::from(position) * SLOT_LEN;
    at..at + SLOT_LEN
}

// ---- The shared block -----------------------------------------------------

/// The shared block, opened.
pub(super) struct Shared {
    pub totp: Option<Zeroizing<Vec<u8>>>,
    /// `R`, the public redirect key of the current real passphrase (§3.8).
    pub redirect_pub: [u8; 32],
    pub app: Zeroizing<Vec<u8>>,
}

impl Shared {
    pub fn new(
        totp: Option<&[u8]>,
        redirect_pub: [u8; 32],
        app: &[u8],
    ) -> Result<Shared, VaultError> {
        check_totp_secret(totp)?;
        check_len("shared app data", app.len(), SHARED_APP_CAPACITY)?;
        Ok(Shared {
            totp: totp.map(|t| Zeroizing::new(t.to_vec())),
            redirect_pub,
            app: Zeroizing::new(app.to_vec()),
        })
    }

    pub fn seal(&self, k2fa: &[u8; 32], header: &Header) -> Result<Vec<u8>, VaultError> {
        let mut plain = Zeroizing::new(vec![0u8; SHARED_PLAIN_LEN]);
        plain[0] = SHARED_FORMAT;
        if let Some(totp) = &self.totp {
            plain[1] = totp.len() as u8;
            plain[2..2 + totp.len()].copy_from_slice(totp);
        }
        let at = 2 + MAX_TOTP_SECRET_LEN;
        plain[at..at + 32].copy_from_slice(&self.redirect_pub);
        let at = at + 32;
        plain[at..at + 2].copy_from_slice(&(self.app.len() as u16).to_le_bytes());
        plain[at + 2..at + 2 + self.app.len()].copy_from_slice(&self.app);
        let key = shared_key(k2fa, &header.id_vault);
        let (sealed, nonce) = aes_gcm_encrypt(&key[..], &plain, Some(&header.encode()))?;
        let mut out = Vec::with_capacity(SHARED_LEN);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        debug_assert_eq!(out.len(), SHARED_LEN);
        Ok(out)
    }

    /// Opens the shared block. It only fails if the vault was damaged or
    /// tampered with after a slot opened: `BadPayload`.
    pub fn open(bytes: &[u8], k2fa: &[u8; 32], header: &Header) -> Result<Shared, VaultError> {
        let region = &bytes[SHARED_AT..BODY_AT];
        let key = shared_key(k2fa, &header.id_vault);
        let plain = Zeroizing::new(
            aes_gcm_decrypt(
                &key[..],
                &region[NONCE_SIZE..],
                &region[..NONCE_SIZE],
                Some(&header.encode()),
            )
            .map_err(|_| VaultError::BadPayload)?,
        );
        if plain[0] != SHARED_FORMAT {
            return Err(VaultError::BadPayload);
        }
        let totp_len = usize::from(plain[1]);
        if totp_len > MAX_TOTP_SECRET_LEN {
            return Err(VaultError::BadPayload);
        }
        let totp = (totp_len > 0).then(|| Zeroizing::new(plain[2..2 + totp_len].to_vec()));
        let at = 2 + MAX_TOTP_SECRET_LEN;
        let redirect_pub = plain[at..at + 32].try_into().expect("32 bytes");
        let at = at + 32;
        let app_len = usize::from(u16::from_le_bytes([plain[at], plain[at + 1]]));
        if app_len > SHARED_APP_CAPACITY {
            return Err(VaultError::BadPayload);
        }
        let app = Zeroizing::new(plain[at + 2..at + 2 + app_len].to_vec());
        Ok(Shared {
            totp,
            redirect_pub,
            app,
        })
    }
}

pub(super) fn check_totp_secret(totp: Option<&[u8]>) -> Result<(), VaultError> {
    match totp {
        Some([]) => Err(VaultError::TooLarge {
            what: "TOTP secret (empty)",
            len: 0,
            max: MAX_TOTP_SECRET_LEN,
        }),
        Some(t) => check_len("TOTP secret", t.len(), MAX_TOTP_SECRET_LEN),
        None => Ok(()),
    }
}

pub(super) fn check_len(what: &'static str, len: usize, max: usize) -> Result<(), VaultError> {
    if len > max {
        Err(VaultError::TooLarge { what, len, max })
    } else {
        Ok(())
    }
}

// ---- The body ---------------------------------------------------------------

/// The body, opened.
pub(super) struct Body {
    pub identity: Identity,
    pub k2fa: Zeroizing<[u8; 32]>,
    pub app: Option<Zeroizing<Vec<u8>>>,
    pub kit: Option<Zeroizing<Vec<u8>>>,
    pub positions: Positions,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SerializedBody {
    identity: SerializedIdentity,
    k2fa: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kit: Option<String>,
    /// Positions of the real, emergency and recovery slots.
    slots: [u8; 3],
}

impl Body {
    pub fn seal(&self, mk: &[u8; 32], header: &Header) -> Result<Vec<u8>, VaultError> {
        check_app_data(self.app.as_deref().map(Vec::as_slice))?;
        if let Some(kit) = &self.kit {
            check_len("kit", kit.len(), MAX_KIT_LEN)?;
        }
        let serialized = SerializedBody {
            identity: serialize_identity(
                &self.identity,
                None,
                self.app.as_deref().map(Vec::as_slice),
            ),
            k2fa: hex::encode(&self.k2fa[..]),
            kit: self.kit.as_deref().map(hex::encode),
            slots: self.positions.to_array(),
        };
        let json =
            Zeroizing::new(serde_json::to_vec(&serialized).map_err(|_| VaultError::BadPayload)?);
        check_len("vault body", json.len(), BODY_JSON_MAX)?;
        let mut plain = Zeroizing::new(vec![0u8; BODY_PLAIN_LEN]);
        plain[..4].copy_from_slice(&(json.len() as u32).to_le_bytes());
        plain[4..4 + json.len()].copy_from_slice(&json);
        let key = body_key(mk, &header.id_vault);
        let (sealed, nonce) = aes_gcm_encrypt(&key[..], &plain, Some(&header.encode()))?;
        let mut out = Vec::with_capacity(BODY_LEN);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        debug_assert_eq!(out.len(), BODY_LEN);
        Ok(out)
    }

    pub fn open(bytes: &[u8], mk: &[u8; 32], header: &Header) -> Result<Body, VaultError> {
        let json = open_body_json(bytes, mk, header)?;
        let s: SerializedBody =
            serde_json::from_slice(&json).map_err(|_| VaultError::BadPayload)?;
        let k2fa_bytes = Zeroizing::new(hex::decode(&s.k2fa).map_err(|_| VaultError::BadPayload)?);
        let k2fa: [u8; 32] = k2fa_bytes[..]
            .try_into()
            .map_err(|_| VaultError::BadPayload)?;
        let k2fa = Zeroizing::new(k2fa);
        let kit = match &s.kit {
            Some(kit) => {
                let kit = Zeroizing::new(hex::decode(kit).map_err(|_| VaultError::BadPayload)?);
                if kit.len() > MAX_KIT_LEN {
                    return Err(VaultError::BadPayload);
                }
                Some(kit)
            }
            None => None,
        };
        let positions = Positions::from_array(s.slots)?;
        let unsealed = deserialize_identity(&s.identity)?;
        // The TOTP secret lives in the shared block (design §4).
        if unsealed.totp_secret.is_some() {
            return Err(VaultError::BadPayload);
        }
        Ok(Body {
            identity: unsealed.identity,
            k2fa,
            app: unsealed.app,
            kit,
            positions,
        })
    }
}

/// The decrypted body JSON, without its padding.
pub(super) fn open_body_json(
    bytes: &[u8],
    mk: &[u8; 32],
    header: &Header,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let region = &bytes[BODY_AT..];
    let key = body_key(mk, &header.id_vault);
    let plain = Zeroizing::new(
        aes_gcm_decrypt(
            &key[..],
            &region[NONCE_SIZE..],
            &region[..NONCE_SIZE],
            Some(&header.encode()),
        )
        .map_err(|_| VaultError::BadPayload)?,
    );
    let len = u32::from_le_bytes(plain[..4].try_into().expect("4 bytes")) as usize;
    if len > BODY_JSON_MAX {
        return Err(VaultError::BadPayload);
    }
    Ok(Zeroizing::new(plain[4..4 + len].to_vec()))
}
