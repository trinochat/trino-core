//! Tests of the version 3 vault. Numbers in brackets are those of design
//! §12.1 and §3.8.8.
//!
//! Most tests run with `Kdf::Spy`, a fast stand-in for Argon2id that counts
//! its calls; the header still carries the production parameters. A few run
//! the real Argon2id (`real_argon2id_*`).

use super::format::*;
use super::*;
use crate::identity::{create_identity, rotate_signed_prekey_if_due, SPK_ROTATION_SECS};
use crate::totp::{generate_totp_secret, totp_now};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const PASS: &str = "correct horse battery staple";
const OTHER: &str = "a passphrase nobody set";
const ID_VAULT: [u8; ID_VAULT_LEN] = [0x11; ID_VAULT_LEN];
const APP: &[u8] = &[0xa5; 60];
const SHARED_APP: &[u8] = b"{\"name\":\"Ana\"}";

thread_local! {
    /// Slot openings tried with the slot key, on this thread.
    static SLOT_TRIES: Cell<usize> = const { Cell::new(0) };
}

/// Called by `format::open_slot` in test builds.
pub(super) fn count_slot_try() {
    SLOT_TRIES.with(|n| n.set(n.get() + 1));
}

fn slot_tries() -> usize {
    SLOT_TRIES.with(Cell::get)
}

fn reset_slot_tries() {
    SLOT_TRIES.with(|n| n.set(0));
}

fn spy() -> (Kdf, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0));
    (Kdf::Spy(count.clone()), count)
}

fn account(identity: &Identity) -> NewAccount<'_> {
    NewAccount {
        identity,
        app: Some(APP),
        shared_app: SHARED_APP,
        id_vault: ID_VAULT,
    }
}

fn create(totp_secret: Option<&[u8]>) -> OpenVault {
    let identity = create_identity();
    create_with(spy().0, &account(&identity), totp_secret, PASS).unwrap()
}

fn unseal(bytes: &[u8], passphrase: &str, code: Option<&str>) -> Result<Unlocked, VaultError> {
    unseal_with(spy().0, bytes, passphrase, code)
}

fn real(unlocked: Unlocked) -> OpenVault {
    match unlocked {
        Unlocked::Real(vault) => *vault,
        #[allow(unreachable_patterns)]
        _ => panic!("expected the real account"),
    }
}

/// A code that is not the current one, nor the one before or after it.
fn wrong_code(secret: &[u8]) -> String {
    let now = chrono::Utc::now().timestamp() as u64;
    let valid: Vec<String> = [now - 30, now, now + 30]
        .iter()
        .map(|t| crate::totp::totp_code(secret, *t, 6, 30))
        .collect();
    (0..1_000_000)
        .map(|n| format!("{n:06}"))
        .find(|c| !valid.contains(c))
        .unwrap()
}

fn rotated_identity(times: i64) -> Identity {
    let mut identity = create_identity();
    let start = identity.signed_prekey.created_at;
    for k in 1..=times {
        assert!(rotate_signed_prekey_if_due(
            &mut identity,
            start + k * (SPK_ROTATION_SECS + 1)
        ));
    }
    identity
}

// ---- Format and size ------------------------------------------------------

/// [1]
#[test]
fn a_v3_vault_is_always_the_same_size() {
    let secret = generate_totp_secret();
    let big_app = [0x5au8; crate::vault::MAX_APP_DATA_LEN];
    let big_shared = vec![0x33u8; MAX_SHARED_APP_LEN];
    for identity in [create_identity(), rotated_identity(10)] {
        for totp in [None, Some(secret.as_slice())] {
            for app in [None, Some(APP), Some(&big_app[..])] {
                for shared_app in [&[][..], SHARED_APP, &big_shared[..]] {
                    let new = NewAccount {
                        identity: &identity,
                        app,
                        shared_app,
                        id_vault: ID_VAULT,
                    };
                    let vault = create_with(spy().0, &new, totp, PASS).unwrap();
                    assert_eq!(vault.bytes().len(), V3_VAULT_LEN);
                }
            }
        }
    }
}

/// [2]
#[test]
fn every_v3_vault_has_three_slots_a_shared_block_and_a_body() {
    assert_eq!(HEADER_LEN, 64);
    assert_eq!((SLOTS_AT, SLOT_LEN, SLOT_COUNT), (65, 81, 3));
    assert_eq!(SHARED_AT, SLOTS_AT + 3 * 81);
    assert_eq!(BODY_AT, SHARED_AT + 8192);
    assert_eq!(BODY_AT + BODY_LEN, V3_VAULT_LEN);

    let vault = create(None);
    let bytes = vault.bytes();
    assert_eq!(&bytes[..6], MAGIC);
    assert_eq!(bytes[VERSION_AT], 3);
    let (header, hint) = Header::parse(bytes).unwrap();
    assert_eq!(header.id_vault, ID_VAULT);
    assert!(!hint);

    // Three slots of the same length, none alike: the two unused ones are
    // random bytes, as long as the one in use.
    let slots: Vec<&[u8]> = (0..3)
        .map(|i| &bytes[SLOTS_AT + i * SLOT_LEN..SLOTS_AT + (i + 1) * SLOT_LEN])
        .collect();
    assert_ne!(slots[0], slots[1]);
    assert_ne!(slots[1], slots[2]);
    assert_ne!(slots[0], slots[2]);
}

#[test]
fn the_id_vault_and_parameters_are_in_the_header() {
    let vault = create(None);
    assert_eq!(vault.id_vault(), ID_VAULT);
    assert_eq!(vault.params(), KdfParams::PRODUCTION);
    let bytes = vault.bytes();
    assert_eq!(&bytes[ID_VAULT_AT..ID_VAULT_AT + 16], &ID_VAULT);
    assert_eq!(bytes[KDF_AT], KDF_ARGON2ID);
    assert_eq!(&bytes[M_AT..M_AT + 4], &(64u32 * 1024).to_le_bytes());
    assert_eq!(&bytes[T_AT..T_AT + 4], &3u32.to_le_bytes());
    assert_eq!(bytes[P_AT], 4);
    assert_eq!(&bytes[RESERVED_AT..HEADER_LEN], &[0u8; 14]);
}

#[test]
fn oversized_fields_are_refused() {
    let identity = create_identity();
    let too_big_shared = vec![0u8; MAX_SHARED_APP_LEN + 1];
    let new = NewAccount {
        shared_app: &too_big_shared,
        ..account(&identity)
    };
    assert!(matches!(
        create_with(spy().0, &new, None, PASS).err(),
        Some(VaultError::TooLarge { .. })
    ));
    let too_big_app = vec![0u8; crate::vault::MAX_APP_DATA_LEN + 1];
    let new = NewAccount {
        app: Some(&too_big_app),
        ..account(&identity)
    };
    assert!(matches!(
        create_with(spy().0, &new, None, PASS).err(),
        Some(VaultError::InvalidAppData(_))
    ));
    let too_long_secret = vec![1u8; MAX_TOTP_SECRET_LEN + 1];
    assert!(matches!(
        create_with(spy().0, &account(&identity), Some(&too_long_secret), PASS).err(),
        Some(VaultError::TooLarge { .. })
    ));
}

// ---- Unlocking with the real passphrase -----------------------------------

/// [3], the real half.
#[test]
fn the_real_passphrase_opens_the_real_slot() {
    let secret = generate_totp_secret();
    let identity = create_identity();
    let created = create_with(spy().0, &account(&identity), Some(&secret), PASS).unwrap();
    let opened = real(unseal(created.bytes(), PASS, Some(&totp_now(&secret))).unwrap());
    assert_eq!(
        opened.identity().ik_sign.pub_bytes,
        identity.ik_sign.pub_bytes
    );
    assert_eq!(
        opened.identity().one_time_prekeys.len(),
        identity.one_time_prekeys.len()
    );
    assert_eq!(opened.app(), Some(APP));
    assert_eq!(opened.kit(), None);
    assert_eq!(opened.shared_app(), SHARED_APP);
    assert_eq!(opened.totp_secret(), Some(secret.as_slice()));
    assert_eq!(opened.id_vault(), ID_VAULT);
    assert_eq!(opened.bytes(), created.bytes());
}

/// [4]
#[test]
fn any_other_passphrase_fails_as_wrong_passphrase() {
    let vault = create(None);
    for wrong in [
        "",
        OTHER,
        "correct horse battery staple ",
        "Correct horse battery staple",
    ] {
        assert!(
            matches!(
                unseal(vault.bytes(), wrong, None).err(),
                Some(VaultError::DecryptionFailed)
            ),
            "{wrong:?}"
        );
    }
}

/// [5]
#[test]
fn unseal_derives_once_and_tries_all_three_slots() {
    let vault = create(None);
    for passphrase in [PASS, OTHER] {
        let (kdf, count) = spy();
        reset_slot_tries();
        let _ = unseal_with(kdf, vault.bytes(), passphrase, None);
        assert_eq!(count.load(Ordering::SeqCst), 1, "{passphrase}");
        assert_eq!(slot_tries(), 3, "{passphrase}");
    }
}

/// [7], the real half: the code is checked against the shared block.
#[test]
fn the_real_path_checks_the_totp_from_the_shared_block() {
    let secret = generate_totp_secret();
    let vault = create(Some(&secret));
    assert!(matches!(
        unseal(vault.bytes(), PASS, None).err(),
        Some(VaultError::TotpRequired)
    ));
    assert!(matches!(
        unseal(vault.bytes(), PASS, Some(&wrong_code(&secret))).err(),
        Some(VaultError::InvalidTotp)
    ));
    real(unseal(vault.bytes(), PASS, Some(&totp_now(&secret))).unwrap());
    // Without TOTP, a code is ignored.
    let plain = create(None);
    real(unseal(plain.bytes(), PASS, Some("123456")).unwrap());
}

#[test]
fn the_hint_says_whether_to_ask_for_a_code() {
    let secret = generate_totp_secret();
    assert!(vault_v3_requires_totp(create(Some(&secret)).bytes()).unwrap());
    assert!(!vault_v3_requires_totp(create(None).bytes()).unwrap());
}

/// The hint is outside the authenticated data and decides nothing.
#[test]
fn the_hint_is_a_hint_only() {
    let secret = generate_totp_secret();
    let mut with_totp = create(Some(&secret)).bytes().to_vec();
    with_totp[HINT_AT] = 0;
    assert!(!vault_v3_requires_totp(&with_totp).unwrap());
    assert!(matches!(
        unseal(&with_totp, PASS, None).err(),
        Some(VaultError::TotpRequired)
    ));
    let mut without = create(None).bytes().to_vec();
    without[HINT_AT] = 1;
    real(unseal(&without, PASS, None).unwrap());
    without[HINT_AT] = 2;
    assert!(matches!(
        vault_v3_requires_totp(&without).err(),
        Some(VaultError::Corrupted)
    ));
}

// ---- The header -----------------------------------------------------------

/// [8]: every header byte is bound, before deriving or at the slots.
#[test]
fn a_changed_header_byte_fails_before_or_at_the_slots() {
    let vault = create(None);
    for at in 0..HEADER_LEN {
        let mut bytes = vault.bytes().to_vec();
        bytes[at] ^= 0x01;
        let (kdf, count) = spy();
        let result = unseal_with(kdf, &bytes, PASS, None);
        assert!(result.is_err(), "byte {at} changed and the vault opened");
        let before_deriving = !(M_AT..ID_VAULT_AT + 16).contains(&at);
        if before_deriving {
            assert_eq!(count.load(Ordering::SeqCst), 0, "byte {at} derived");
        }
    }
}

/// [9]
#[test]
fn parameters_out_of_bounds_are_refused_before_deriving() {
    let vault = create(None);
    let cases: [(usize, &[u8]); 4] = [
        (M_AT, &(1024u32 * 1024 + 1).to_le_bytes()),
        (M_AT, &(1024u32).to_le_bytes()),
        (T_AT, &11u32.to_le_bytes()),
        (P_AT, &[0u8]),
    ];
    for (at, value) in cases {
        let mut bytes = vault.bytes().to_vec();
        bytes[at..at + value.len()].copy_from_slice(value);
        let (kdf, count) = spy();
        assert!(matches!(
            unseal_with(kdf, &bytes, PASS, None).err(),
            Some(VaultError::Kdf(crate::kdf::KdfError::ParamsOutOfBounds))
        ));
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }
    let mut bytes = vault.bytes().to_vec();
    bytes[KDF_AT] = 2;
    assert!(matches!(
        unseal(&bytes, PASS, None).err(),
        Some(VaultError::UnsupportedKdf(2))
    ));
    let mut bytes = vault.bytes().to_vec();
    bytes[FLAGS_AT] = 1;
    assert!(matches!(
        unseal(&bytes, PASS, None).err(),
        Some(VaultError::UnsupportedFlags(1))
    ));
}

#[test]
fn a_vault_of_another_length_is_refused_before_deriving() {
    let vault = create(None);
    let mut longer = vault.bytes().to_vec();
    longer.push(0);
    for bytes in [&vault.bytes()[..V3_VAULT_LEN - 1], &longer[..]] {
        let (kdf, count) = spy();
        assert!(matches!(
            unseal_with(kdf, bytes, PASS, None).err(),
            Some(VaultError::Corrupted)
        ));
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }
}

/// [16]
#[test]
fn an_older_reader_refuses_v3_before_deriving() {
    let bytes = create(None).bytes().to_vec();
    // 3421e16, the version 2 reader the app pins today.
    let blob = crate::vault::decode_vault(&bytes).unwrap();
    assert!(matches!(
        crate::vault::unseal_vault(&blob, PASS, None).err(),
        Some(VaultError::UnsupportedVersion(3))
    ));
    assert!(matches!(
        crate::vault::vault_requires_totp(&bytes).err(),
        Some(VaultError::UnsupportedVersion(3))
    ));
    // 1bac851 and 4ce6775 accept version 1 only, before deriving.
    assert_ne!(blob.version, 1);
}

#[test]
fn vault_version_reads_every_version() {
    assert_eq!(vault_version(create(None).bytes()).unwrap(), 3);
    for version in [1u8, 2] {
        let old = crate::vault::encode_vault(&crate::vault::SealedVault {
            version,
            flags: 0,
            salt: [0; 16],
            nonce: [0; 12],
            ciphertext: vec![0; 40],
        });
        assert_eq!(vault_version(&old).unwrap(), version);
    }
    assert!(matches!(
        vault_version(b"NOTTRINO and more bytes").err(),
        Some(VaultError::BadMagic)
    ));
    assert!(matches!(
        vault_version(b"TRI").err(),
        Some(VaultError::Corrupted)
    ));
}

// ---- The body -------------------------------------------------------------

/// [18]
#[test]
fn the_body_holds_no_totp_secret() {
    let secret = generate_totp_secret();
    let vault = create(Some(&secret));
    let json = open_body_json(vault.bytes(), &vault.mk, &vault.header).unwrap();
    let json = String::from_utf8(json.to_vec()).unwrap();
    assert!(!json.contains("totp"), "{json}");
    assert!(!json.contains(&hex::encode(&secret)));
    assert!(json.contains("k2fa"));
}

/// [61]
#[test]
fn the_vault_body_names_all_three_slot_positions_in_every_vault() {
    let mut real_positions = std::collections::BTreeSet::new();
    for _ in 0..24 {
        let vault = create(None);
        let p = vault.body.positions;
        let mut all = [p.real, p.emergency, p.recovery];
        all.sort();
        assert_eq!(all, [0, 1, 2]);
        real_positions.insert(p.real);
        let json = open_body_json(vault.bytes(), &vault.mk, &vault.header).unwrap();
        assert!(String::from_utf8(json.to_vec())
            .unwrap()
            .contains("\"slots\""));
    }
    assert!(real_positions.len() > 1, "the positions are not drawn");
}

// ---- The real Argon2id ----------------------------------------------------

#[test]
fn real_argon2id_vault_opens_with_its_passphrase_only() {
    let identity = create_identity();
    let vault = create_vault_v3(&account(&identity), None, PASS).unwrap();
    let opened = real(unseal_vault_v3(vault.bytes(), PASS, None).unwrap());
    assert_eq!(opened.identity().ik_dh.pub_bytes, identity.ik_dh.pub_bytes);
    assert!(matches!(
        unseal_vault_v3(vault.bytes(), OTHER, None).err(),
        Some(VaultError::DecryptionFailed)
    ));
}
