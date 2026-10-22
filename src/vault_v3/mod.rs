//! The version 3 vault: Argon2id, three fixed slots, a shared block and a
//! padded body, in a file of one fixed size.
//!
//! Design: `research_notes/Clave de emergencia/diseno.md` §3 to §6, with the
//! CE-D12 addendum (§3.8). Layout (`format.rs`):
//!
//! ```text
//! header, 64 bytes       "TRINO\0" | version 3 | flags 0 | kdf 1 (Argon2id)
//!                        | m_kib u32 | t u32 | p u8 | salt 16 | id_vault 16 | zeros 14
//! hint, 1 byte           0 or 1: whether to show the TOTP field. Not authenticated
//! slot[0..3], 81 bytes   lead 32 | AES-256-GCM(type u8 | key 32) | tag 16
//! shared block, 8 KiB    nonce 12 | AES-256-GCM(TOTP secret, redirect key, app) | tag 16
//! body, the rest         nonce 12 | AES-256-GCM(len u32 | JSON | zeros) | tag 16
//! ```
//!
//! The whole file is always `V3_VAULT_LEN` bytes, whatever it holds: nothing
//! in it says whether an emergency key or a recovery kit exists, how many
//! prekeys the identity has, or how long the app's data is.
//!
//! **Keys.** The passphrase goes through Argon2id once per attempt, with the
//! salt and parameters of the header, into the KEK. From the KEK come the
//! slot key and the redirect key pair (`redirect.rs`). A slot wraps either
//! the body key MK (the real slot) or K2FA (the emergency slot). MK opens the
//! body, which holds the identity, K2FA, the app data, the kit and the
//! position of each slot. K2FA opens the shared block, which holds the TOTP
//! secret, the public redirect key and what the app wants the empty account
//! to inherit.
//!
//! **Unlocking** derives once and tries every slot, always all three, so the
//! work up to the decision is the same for any passphrase.

mod format;
mod redirect;

#[cfg(test)]
mod tests;

use crate::crypto::random_array;
use crate::identity::Identity;
use crate::kdf::KdfParams;
use crate::totp::is_totp_code_valid;
use crate::vault::{check_app_data, UnsealedVault, VaultError};
use zeroize::Zeroizing;

use format::{
    check_len, check_totp_secret, open_slot, random_slot, seal_slot, slot_key, slot_range, Body,
    Header, Positions, Shared, BODY_AT, HEADER_LEN, HINT_AT, SHARED_AT, SLOT_COUNT, SLOT_EMERGENCY,
    SLOT_REAL,
};

/// Every version 3 vault is this long.
pub const V3_VAULT_LEN: usize = 32 * 1024;
/// The bytes of `id_vault`, the name of the account's store on this device.
pub const ID_VAULT_LEN: usize = 16;
/// The most the app can keep in the shared block, in bytes.
pub const MAX_SHARED_APP_LEN: usize = format::SHARED_APP_CAPACITY;
/// The most the recovery kit field holds, in bytes.
pub const MAX_KIT_LEN: usize = 1024;
/// The longest TOTP secret the shared block holds, in bytes.
pub const MAX_TOTP_SECRET_LEN: usize = 64;

/// How the KEK is derived. Production code only ever uses Argon2id; tests
/// add a fast KDF that counts its calls.
#[derive(Clone)]
pub(crate) enum Kdf {
    Argon2id,
    #[cfg(test)]
    Spy(std::sync::Arc<std::sync::atomic::AtomicUsize>),
}

impl Kdf {
    fn derive(&self, passphrase: &str, header: &Header) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        match self {
            Kdf::Argon2id => Ok(crate::kdf::argon2id(
                passphrase.as_bytes(),
                &header.salt,
                &header.params,
            )?),
            #[cfg(test)]
            Kdf::Spy(count) => {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let p = header.params;
                let info = [
                    &b"spy kdf"[..],
                    &p.m_kib.to_le_bytes(),
                    &p.t.to_le_bytes(),
                    &[p.p],
                ]
                .concat();
                let okm =
                    crate::crypto::hkdf_expand(passphrase.as_bytes(), &header.salt, &info, 32)?;
                let mut kek = Zeroizing::new([0u8; 32]);
                kek.copy_from_slice(&okm);
                Ok(kek)
            }
        }
    }
}

/// What a new vault holds besides its passphrase and TOTP secret.
pub struct NewAccount<'a> {
    pub identity: &'a Identity,
    /// The app's data in the body: 1 to `MAX_APP_DATA_LEN` bytes.
    pub app: Option<&'a [u8]>,
    /// The app's data in the shared block, up to `MAX_SHARED_APP_LEN` bytes:
    /// what an empty account made by the emergency path inherits.
    pub shared_app: &'a [u8],
    /// The name of the account's store; the header carries it.
    pub id_vault: [u8; ID_VAULT_LEN],
}

/// A vault opened with its real passphrase: everything needed to change it
/// and seal it again without asking for the passphrase.
pub struct OpenVault {
    kdf: Kdf,
    header: Header,
    /// The vault as it stands, always `V3_VAULT_LEN` bytes. Each setter
    /// rewrites only its own part.
    bytes: Vec<u8>,
    mk: Zeroizing<[u8; 32]>,
    body: Body,
    shared: Shared,
}

/// What `unseal_vault_v3` opened.
pub enum Unlocked {
    /// The real passphrase.
    Real(Box<OpenVault>),
    /// The emergency key: the app runs the emergency path (design §6).
    Emergency(Box<EmergencyVault>),
}

/// A vault opened with its emergency key. It holds the shared block and the
/// emergency key's KEK, and nothing that opens the body.
pub struct EmergencyVault {
    kdf: Kdf,
    header: Header,
    /// The emergency key's KEK: the empty account keeps the same salt and
    /// parameters, so it needs no second derivation.
    kek: Zeroizing<[u8; 32]>,
    shared: Shared,
    /// The position of the slot that opened.
    position: u8,
}

impl EmergencyVault {
    /// The app's data in the shared block: what the empty account inherits,
    /// and what the network action needs.
    pub fn shared_app(&self) -> &[u8] {
        &self.shared.app
    }

    pub fn totp_secret(&self) -> Option<&[u8]> {
        self.shared.totp.as_deref().map(Vec::as_slice)
    }

    pub fn id_vault(&self) -> [u8; ID_VAULT_LEN] {
        self.header.id_vault
    }

    /// Step E2 of the emergency path (design §6.1 and §3.8), the core's
    /// part: the vault of the empty account, in memory. Nothing is written;
    /// the app writes `bytes()` with its two-phase write (E4).
    ///
    /// The empty account keeps the salt, the parameters and the KEK of the
    /// emergency key, which now opens its real slot. It gets a new
    /// `id_vault` (the app's, which must differ), new MK, K2FA and identity,
    /// and the TOTP secret of the old shared block. Where the emergency slot
    /// was goes the redirect: the new MK sealed to the `R` of the old shared
    /// block, so the real passphrase opens the empty account too (CE-D12,
    /// design §3.8). The recovery slot is random bytes. No derivation.
    pub fn into_empty_account(self, account: &NewAccount) -> Result<OpenVault, VaultError> {
        if account.id_vault == self.header.id_vault {
            return Err(VaultError::IdVaultReused);
        }
        check_app_data(account.app)?;
        let header = Header {
            id_vault: account.id_vault,
            ..self.header
        };
        let shared = Shared::new(
            self.shared.totp.as_deref().map(Vec::as_slice),
            redirect::public_key(&self.kek),
            account.shared_app,
        )?;
        let mk = Zeroizing::new(random_array::<32>());
        let positions = Positions::random_keeping_emergency(self.position);
        let mut slots: [format::SlotBytes; SLOT_COUNT] = std::array::from_fn(|_| random_slot());
        let k_r = slot_key(&self.kek, &header.id_vault);
        slots[usize::from(positions.real)] =
            seal_slot(&k_r, &header.id_vault, positions.real, SLOT_REAL, &mk);
        slots[usize::from(positions.emergency)] = redirect::seal(
            &self.shared.redirect_pub,
            &header.id_vault,
            positions.emergency,
            &mk,
        )?;
        let body = Body {
            identity: account.identity.clone(),
            k2fa: Zeroizing::new(random_array()),
            app: account.app.map(|a| Zeroizing::new(a.to_vec())),
            kit: None,
            positions,
        };
        assemble(self.kdf.clone(), header, slots, mk, body, shared)
    }
}

/// Creates a version 3 vault for a new account.
pub fn create_vault_v3(
    account: &NewAccount,
    totp_secret: Option<&[u8]>,
    passphrase: &str,
) -> Result<OpenVault, VaultError> {
    create_with(Kdf::Argon2id, account, totp_secret, passphrase)
}

fn create_with(
    kdf: Kdf,
    account: &NewAccount,
    totp_secret: Option<&[u8]>,
    passphrase: &str,
) -> Result<OpenVault, VaultError> {
    check_app_data(account.app)?;
    let header = Header {
        params: KdfParams::PRODUCTION,
        salt: random_array(),
        id_vault: account.id_vault,
    };
    // Checked before the derivation, which is the slow part.
    let shared_draft = Shared::new(totp_secret, [0; 32], account.shared_app)?;
    let kek = kdf.derive(passphrase, &header)?;
    let mk = Zeroizing::new(random_array::<32>());
    let body = Body {
        identity: account.identity.clone(),
        k2fa: Zeroizing::new(random_array()),
        app: account.app.map(|a| Zeroizing::new(a.to_vec())),
        kit: None,
        positions: Positions::random(),
    };
    let shared = Shared {
        redirect_pub: redirect::public_key(&kek),
        ..shared_draft
    };
    let mut slots: [format::SlotBytes; SLOT_COUNT] = std::array::from_fn(|_| random_slot());
    let real = body.positions.real;
    let k_r = slot_key(&kek, &header.id_vault);
    slots[usize::from(real)] = seal_slot(&k_r, &header.id_vault, real, SLOT_REAL, &mk);
    assemble(kdf, header, slots, mk, body, shared)
}

/// Lays out a vault from its parts.
fn assemble(
    kdf: Kdf,
    header: Header,
    slots: [format::SlotBytes; SLOT_COUNT],
    mk: Zeroizing<[u8; 32]>,
    body: Body,
    shared: Shared,
) -> Result<OpenVault, VaultError> {
    let mut bytes = vec![0u8; V3_VAULT_LEN];
    bytes[..HEADER_LEN].copy_from_slice(&header.encode());
    bytes[HINT_AT] = u8::from(shared.totp.is_some());
    for (position, slot) in (0u8..).zip(&slots) {
        bytes[slot_range(position)].copy_from_slice(slot);
    }
    bytes[SHARED_AT..BODY_AT].copy_from_slice(&shared.seal(&body.k2fa, &header)?);
    bytes[BODY_AT..].copy_from_slice(&body.seal(&mk, &header)?);
    Ok(OpenVault {
        kdf,
        header,
        bytes,
        mk,
        body,
        shared,
    })
}

/// Moves a version 1 or 2 vault to version 3 (design §3.7), once the app has
/// opened it with `vault::unseal_vault`.
///
/// The identity and the TOTP secret come from the old vault; the secret
/// moves to the shared block and leaves the body. `app` is the app's new
/// record (the design rotates the data key here), `shared_app` what the
/// shared block carries, and `id_vault` the store's name, which a migration
/// keeps. A new salt, Argon2id at the production parameters, and new MK
/// and K2FA; the emergency and recovery slots start as random bytes, as in
/// every new vault.
pub fn migrate_to_v3(
    old: &UnsealedVault,
    passphrase: &str,
    app: Option<&[u8]>,
    shared_app: &[u8],
    id_vault: [u8; ID_VAULT_LEN],
) -> Result<OpenVault, VaultError> {
    migrate_with(Kdf::Argon2id, old, passphrase, app, shared_app, id_vault)
}

fn migrate_with(
    kdf: Kdf,
    old: &UnsealedVault,
    passphrase: &str,
    app: Option<&[u8]>,
    shared_app: &[u8],
    id_vault: [u8; ID_VAULT_LEN],
) -> Result<OpenVault, VaultError> {
    let account = NewAccount {
        identity: &old.identity,
        app,
        shared_app,
        id_vault,
    };
    create_with(kdf, &account, old.totp_secret.as_deref(), passphrase)
}

/// Opens a version 3 vault.
///
/// Derives the KEK once, tries all three slots, and decides: the real slot
/// wins. A passphrase that opens nothing fails with `DecryptionFailed`, the
/// same as a version 2 vault. With TOTP on, `TotpRequired` without a code and
/// `InvalidTotp` with a wrong one, checked against the shared block.
pub fn unseal_vault_v3(
    bytes: &[u8],
    passphrase: &str,
    totp_code: Option<&str>,
) -> Result<Unlocked, VaultError> {
    unseal_with(Kdf::Argon2id, bytes, passphrase, totp_code)
}

fn unseal_with(
    kdf: Kdf,
    bytes: &[u8],
    passphrase: &str,
    totp_code: Option<&str>,
) -> Result<Unlocked, VaultError> {
    let (header, _hint) = Header::parse(bytes)?;
    let kek = kdf.derive(passphrase, &header)?;
    let k_r = slot_key(&kek, &header.id_vault);
    let r = redirect::secret_key(&kek);
    let r_pub = redirect::public_key(&kek);

    // Every slot, both ways, always; the decision comes after (design §3.8.3).
    let mut real = None;
    let mut redirected = None;
    let mut emergency = None;
    for position in 0..SLOT_COUNT as u8 {
        let slot = &bytes[slot_range(position)];
        let opened = open_slot(&k_r, &header.id_vault, position, slot);
        if let Some(mk) = redirect::open(&r, &r_pub, &header.id_vault, position, slot) {
            redirected.get_or_insert((position, mk));
        }
        match opened {
            Some((SLOT_REAL, mk)) => {
                real.get_or_insert((position, mk));
            }
            Some((SLOT_EMERGENCY, k2fa)) => {
                emergency.get_or_insert((position, k2fa));
            }
            _ => {}
        }
    }

    // The real slot wins (design §2, principle 3), then the redirect, which
    // is the real passphrase too (CE-D12), then the emergency key.
    let real = real.map(|(at, mk)| (at, mk, false));
    let redirected = redirected.map(|(at, mk)| (at, mk, true));
    let Some((position, mk, via_redirect)) = real.or(redirected) else {
        let Some((position, k2fa)) = emergency else {
            return Err(VaultError::DecryptionFailed);
        };
        let shared = Shared::open(bytes, &k2fa, &header)?;
        check_totp(&shared, totp_code)?;
        return Ok(Unlocked::Emergency(Box::new(EmergencyVault {
            kdf,
            header,
            kek,
            shared,
            position,
        })));
    };
    let body = Body::open(bytes, &mk, &header)?;
    let expected = if via_redirect {
        body.positions.emergency
    } else {
        body.positions.real
    };
    if expected != position {
        return Err(VaultError::BadPayload);
    }
    let shared = Shared::open(bytes, &body.k2fa, &header)?;
    check_totp(&shared, totp_code)?;
    Ok(Unlocked::Real(Box::new(OpenVault {
        kdf,
        header,
        bytes: bytes.to_vec(),
        mk,
        body,
        shared,
    })))
}

/// The same check on either path, against the shared block's secret.
fn check_totp(shared: &Shared, totp_code: Option<&str>) -> Result<(), VaultError> {
    if let Some(secret) = &shared.totp {
        let code = totp_code.ok_or(VaultError::TotpRequired)?;
        if !is_totp_code_valid(code, secret) {
            return Err(VaultError::InvalidTotp);
        }
    }
    Ok(())
}

/// Whether opening this vault will ask for a TOTP code: the hint byte, read
/// after the header checks and without deriving anything.
///
/// **A UI hint only,** as `vault::vault_requires_totp`: it is outside the
/// authenticated data, so that turning TOTP on or off never has to touch the
/// emergency slot. The shared block decides.
pub fn vault_v3_requires_totp(bytes: &[u8]) -> Result<bool, VaultError> {
    Ok(Header::parse(bytes)?.1)
}

/// The format version of an encoded vault, 1 to 3, after its magic bytes.
/// The app reads it to choose between opening and migrating.
pub fn vault_version(bytes: &[u8]) -> Result<u8, VaultError> {
    if bytes.len() <= format::VERSION_AT {
        return Err(VaultError::Corrupted);
    }
    if &bytes[..format::VERSION_AT] != format::MAGIC {
        return Err(VaultError::BadMagic);
    }
    Ok(bytes[format::VERSION_AT])
}

impl OpenVault {
    /// The vault as it stands now, to write to disk.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn identity(&self) -> &Identity {
        &self.body.identity
    }

    pub fn app(&self) -> Option<&[u8]> {
        self.body.app.as_deref().map(Vec::as_slice)
    }

    pub fn kit(&self) -> Option<&[u8]> {
        self.body.kit.as_deref().map(Vec::as_slice)
    }

    pub fn totp_secret(&self) -> Option<&[u8]> {
        self.shared.totp.as_deref().map(Vec::as_slice)
    }

    pub fn shared_app(&self) -> &[u8] {
        &self.shared.app
    }

    pub fn id_vault(&self) -> [u8; ID_VAULT_LEN] {
        self.header.id_vault
    }

    pub fn params(&self) -> KdfParams {
        self.header.params
    }

    /// Replaces the identity (a rotated signed prekey, used one-time
    /// prekeys) and re-seals the body. Slots and shared block stay as they
    /// are, byte for byte.
    pub fn set_identity(&mut self, identity: Identity) -> Result<(), VaultError> {
        let previous = std::mem::replace(&mut self.body.identity, identity);
        self.write_body()
            .inspect_err(|_| self.body.identity = previous)
    }

    /// Replaces the app data in the body.
    pub fn set_app(&mut self, app: Option<&[u8]>) -> Result<(), VaultError> {
        check_app_data(app)?;
        let app = app.map(|a| Zeroizing::new(a.to_vec()));
        let previous = std::mem::replace(&mut self.body.app, app);
        self.write_body().inspect_err(|_| self.body.app = previous)
    }

    /// Replaces the recovery kit field in the body, up to `MAX_KIT_LEN`.
    pub fn set_kit(&mut self, kit: Option<&[u8]>) -> Result<(), VaultError> {
        if let Some(kit) = kit {
            check_len("kit", kit.len(), MAX_KIT_LEN)?;
        }
        let kit = kit.map(|k| Zeroizing::new(k.to_vec()));
        let previous = std::mem::replace(&mut self.body.kit, kit);
        self.write_body().inspect_err(|_| self.body.kit = previous)
    }

    /// Turns TOTP on (with a new secret) or off. Rewrites the shared block
    /// and the hint only: the emergency slot wraps K2FA, not the secret, so
    /// it is left alone and the change holds for the emergency key too.
    pub fn set_totp_secret(&mut self, totp_secret: Option<&[u8]>) -> Result<(), VaultError> {
        check_totp_secret(totp_secret)?;
        self.shared.totp = totp_secret.map(|t| Zeroizing::new(t.to_vec()));
        self.write_shared()
    }

    /// Replaces the app data in the shared block.
    pub fn set_shared_app(&mut self, shared_app: &[u8]) -> Result<(), VaultError> {
        check_len("shared app data", shared_app.len(), MAX_SHARED_APP_LEN)?;
        self.shared.app = Zeroizing::new(shared_app.to_vec());
        self.write_shared()
    }

    /// Re-wraps the real slot under `new_passphrase`, same salt and
    /// parameters, and moves the redirect key `R` to it. One derivation.
    ///
    /// Refused with `PassphraseOpensEmergencySlot` if the new passphrase is
    /// the emergency key. The other two slots are copied byte for byte.
    pub fn change_passphrase(&mut self, new_passphrase: &str) -> Result<(), VaultError> {
        let kek = self.kdf.derive(new_passphrase, &self.header)?;
        let k_r = slot_key(&kek, &self.header.id_vault);
        let at = self.body.positions.emergency;
        if let Some((SLOT_EMERGENCY, _)) = open_slot(&k_r, &self.header.id_vault, at, self.slot(at))
        {
            return Err(VaultError::PassphraseOpensEmergencySlot);
        }
        self.become_real(&kek)
    }

    /// Writes the emergency slot: K2FA under `emergency_key`, in its own
    /// position, over whatever was there. `current` must be the passphrase
    /// that opens this account. Two derivations.
    ///
    /// Refused with `EmergencyKeyOpensAnotherSlot` if the emergency key
    /// opens another slot, which means it is the passphrase.
    pub fn set_emergency_key(
        &mut self,
        current: &str,
        emergency_key: &str,
    ) -> Result<(), VaultError> {
        let (current_kek, via_redirect) = self.current_kek(current)?;
        let kek = self.kdf.derive(emergency_key, &self.header)?;
        if ct_eq(&kek, &current_kek) {
            return Err(VaultError::EmergencyKeyOpensAnotherSlot);
        }
        let k_r = slot_key(&kek, &self.header.id_vault);
        let id_vault = self.header.id_vault;
        let positions = self.body.positions;
        for at in [positions.real, positions.recovery] {
            if open_slot(&k_r, &id_vault, at, self.slot(at)).is_some() {
                return Err(VaultError::EmergencyKeyOpensAnotherSlot);
            }
        }
        let slot = seal_slot(
            &k_r,
            &id_vault,
            positions.emergency,
            SLOT_EMERGENCY,
            &self.body.k2fa,
        );
        if via_redirect {
            // The passphrase typed in Settings becomes the real one (§3.8.5).
            self.become_real(&current_kek)?;
        }
        self.bytes[slot_range(positions.emergency)].copy_from_slice(&slot);
        Ok(())
    }

    /// Fills the emergency slot with random bytes. `current` must be the
    /// passphrase that opens this account.
    pub fn remove_emergency_key(&mut self, current: &str) -> Result<(), VaultError> {
        let (current_kek, via_redirect) = self.current_kek(current)?;
        if via_redirect {
            self.become_real(&current_kek)?;
        }
        let at = self.body.positions.emergency;
        self.bytes[slot_range(at)].copy_from_slice(&random_slot());
        Ok(())
    }

    /// Whether `candidate` is the emergency key ("Probar", design §8.4).
    /// Derives once and writes nothing.
    pub fn is_emergency_key(&self, candidate: &str) -> Result<bool, VaultError> {
        let kek = self.kdf.derive(candidate, &self.header)?;
        let k_r = slot_key(&kek, &self.header.id_vault);
        let at = self.body.positions.emergency;
        Ok(matches!(
            open_slot(&k_r, &self.header.id_vault, at, self.slot(at)),
            Some((SLOT_EMERGENCY, _))
        ))
    }

    fn slot(&self, position: u8) -> &[u8] {
        &self.bytes[slot_range(position)]
    }

    /// The KEK of `passphrase`, if it opens this account: through the real
    /// slot, or through the redirect (then `true`).
    fn current_kek(&self, passphrase: &str) -> Result<(Zeroizing<[u8; 32]>, bool), VaultError> {
        let kek = self.kdf.derive(passphrase, &self.header)?;
        let id_vault = &self.header.id_vault;
        let positions = self.body.positions;
        let k_r = slot_key(&kek, id_vault);
        let real = open_slot(&k_r, id_vault, positions.real, self.slot(positions.real));
        if let Some((SLOT_REAL, mk)) = real {
            if ct_eq(&mk, &self.mk) {
                return Ok((kek, false));
            }
        }
        let r = redirect::secret_key(&kek);
        let r_pub = redirect::public_key(&kek);
        let at = positions.emergency;
        match redirect::open(&r, &r_pub, id_vault, at, self.slot(at)) {
            Some(mk) if ct_eq(&mk, &self.mk) => Ok((kek, true)),
            _ => Err(VaultError::DecryptionFailed),
        }
    }

    /// Makes `kek` the real passphrase's: re-wraps the real slot and moves
    /// the redirect key to it.
    fn become_real(&mut self, kek: &[u8; 32]) -> Result<(), VaultError> {
        let k_r = slot_key(kek, &self.header.id_vault);
        let at = self.body.positions.real;
        let slot = seal_slot(&k_r, &self.header.id_vault, at, SLOT_REAL, &self.mk);
        let redirect_pub = redirect::public_key(kek);
        let previous = std::mem::replace(&mut self.shared.redirect_pub, redirect_pub);
        self.write_shared()
            .inspect_err(|_| self.shared.redirect_pub = previous)?;
        self.bytes[slot_range(at)].copy_from_slice(&slot);
        Ok(())
    }

    fn write_body(&mut self) -> Result<(), VaultError> {
        let sealed = self.body.seal(&self.mk, &self.header)?;
        self.bytes[BODY_AT..].copy_from_slice(&sealed);
        Ok(())
    }

    fn write_shared(&mut self) -> Result<(), VaultError> {
        let sealed = self.shared.seal(&self.body.k2fa, &self.header)?;
        self.bytes[SHARED_AT..BODY_AT].copy_from_slice(&sealed);
        self.bytes[HINT_AT] = u8::from(self.shared.totp.is_some());
        Ok(())
    }
}

/// Compares two keys without stopping at the first difference.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}
