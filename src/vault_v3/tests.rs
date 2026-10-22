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
        Unlocked::Emergency(_) => panic!("expected the real account"),
    }
}

fn emergency(unlocked: Unlocked) -> EmergencyVault {
    match unlocked {
        Unlocked::Emergency(vault) => *vault,
        Unlocked::Real(_) => panic!("expected the emergency path"),
    }
}

const EMERGENCY: &str = "the key for a bad day";
const NEW_PASS: &str = "a brand new passphrase";

fn with_emergency(totp_secret: Option<&[u8]>) -> OpenVault {
    let mut vault = create(totp_secret);
    vault.set_emergency_key(PASS, EMERGENCY).unwrap();
    vault
}

/// The parts of an encoded vault, to compare what a change touched.
#[derive(Debug, PartialEq, Eq, Clone)]
struct Parts {
    header: Vec<u8>,
    hint: u8,
    slots: [Vec<u8>; 3],
    shared: Vec<u8>,
    body: Vec<u8>,
}

fn parts(bytes: &[u8]) -> Parts {
    Parts {
        header: bytes[..HEADER_LEN].to_vec(),
        hint: bytes[HINT_AT],
        slots: [0u8, 1, 2].map(|p| bytes[slot_range(p)].to_vec()),
        shared: bytes[SHARED_AT..BODY_AT].to_vec(),
        body: bytes[BODY_AT..].to_vec(),
    }
}

/// The KEK the spy derives for `passphrase` under this header.
fn spy_kek(header: &Header, passphrase: &str) -> Zeroizing<[u8; 32]> {
    spy().0.derive(passphrase, header).unwrap()
}

fn spy_count(vault: &OpenVault) -> usize {
    match &vault.kdf {
        Kdf::Spy(count) => count.load(Ordering::SeqCst),
        Kdf::Argon2id => panic!("not a spy"),
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

// ---- The emergency key ------------------------------------------------------

/// [3]
#[test]
fn the_real_passphrase_opens_the_real_slot_and_the_emergency_key_the_emergency_slot() {
    let vault = with_emergency(None);
    let opened = real(unseal(vault.bytes(), PASS, None).unwrap());
    assert_eq!(opened.bytes(), vault.bytes());
    let e = emergency(unseal(vault.bytes(), EMERGENCY, None).unwrap());
    assert_eq!(e.shared_app(), SHARED_APP);
    assert_eq!(e.id_vault(), ID_VAULT);
    assert_eq!(e.position, vault.body.positions.emergency);
    assert_eq!(*e.k2fa, *vault.body.k2fa);
}

/// [5], with an emergency key set.
#[test]
fn unseal_derives_once_and_tries_all_three_slots_with_an_emergency_key() {
    let vault = with_emergency(None);
    for passphrase in [PASS, EMERGENCY, OTHER] {
        let (kdf, count) = spy();
        reset_slot_tries();
        let _ = unseal_with(kdf, vault.bytes(), passphrase, None);
        assert_eq!(count.load(Ordering::SeqCst), 1, "{passphrase}");
        assert_eq!(slot_tries(), 3, "{passphrase}");
    }
}

/// [6]: a slot the real passphrase opens as emergency loses to the real one.
#[test]
fn the_real_slot_wins_when_both_open() {
    let mut vault = create(None);
    let kek = spy_kek(&vault.header, PASS);
    let k_r = slot_key(&kek, &ID_VAULT);
    let at = vault.body.positions.emergency;
    let planted = seal_slot(&k_r, &ID_VAULT, at, SLOT_EMERGENCY, &vault.body.k2fa);
    vault.bytes[slot_range(at)].copy_from_slice(&planted);
    real(unseal(vault.bytes(), PASS, None).unwrap());
}

/// [7]
#[test]
fn the_emergency_path_checks_the_same_totp_from_the_shared_block() {
    let secret = generate_totp_secret();
    let vault = with_emergency(Some(&secret));
    assert!(matches!(
        unseal(vault.bytes(), EMERGENCY, None).err(),
        Some(VaultError::TotpRequired)
    ));
    assert!(matches!(
        unseal(vault.bytes(), EMERGENCY, Some(&wrong_code(&secret))).err(),
        Some(VaultError::InvalidTotp)
    ));
    let e = emergency(unseal(vault.bytes(), EMERGENCY, Some(&totp_now(&secret))).unwrap());
    assert_eq!(e.totp_secret(), Some(secret.as_slice()));
}

/// Turning TOTP on after the key was set holds for the key too (design §4).
#[test]
fn totp_turned_on_later_holds_for_the_emergency_key() {
    let mut vault = with_emergency(None);
    let secret = generate_totp_secret();
    vault.set_totp_secret(Some(&secret)).unwrap();
    assert!(matches!(
        unseal(vault.bytes(), EMERGENCY, None).err(),
        Some(VaultError::TotpRequired)
    ));
    emergency(unseal(vault.bytes(), EMERGENCY, Some(&totp_now(&secret))).unwrap());
}

#[test]
fn the_emergency_key_cannot_be_the_passphrase() {
    let mut vault = create(None);
    let before = vault.bytes().to_vec();
    assert!(matches!(
        vault.set_emergency_key(PASS, PASS).err(),
        Some(VaultError::EmergencyKeyOpensAnotherSlot)
    ));
    assert!(matches!(
        vault.set_emergency_key(OTHER, EMERGENCY).err(),
        Some(VaultError::DecryptionFailed)
    ));
    assert_eq!(vault.bytes(), &before[..]);
}

/// [13]
#[test]
fn setting_and_removing_the_emergency_key_touch_only_its_slot() {
    let mut vault = create(None);
    let at = usize::from(vault.body.positions.emergency);
    let before = parts(vault.bytes());

    vault.set_emergency_key(PASS, EMERGENCY).unwrap();
    let set = parts(vault.bytes());
    assert_ne!(set.slots[at], before.slots[at]);
    let mut expected = set.clone();
    expected.slots[at] = before.slots[at].clone();
    assert_eq!(expected, before);
    emergency(unseal(vault.bytes(), EMERGENCY, None).unwrap());

    vault.remove_emergency_key(PASS).unwrap();
    let removed = parts(vault.bytes());
    assert_ne!(removed.slots[at], set.slots[at]);
    let mut expected = removed.clone();
    expected.slots[at] = set.slots[at].clone();
    assert_eq!(expected, set);
    assert!(matches!(
        unseal(vault.bytes(), EMERGENCY, None).err(),
        Some(VaultError::DecryptionFailed)
    ));
    real(unseal(vault.bytes(), PASS, None).unwrap());
}

/// [10]
#[test]
fn resealing_copies_the_emergency_and_recovery_slots_byte_for_byte() {
    let secret = generate_totp_secret();
    let mut vault = with_emergency(None);
    let positions = vault.body.positions;
    let before = parts(vault.bytes());
    let keep = |vault: &OpenVault, what: &str| {
        let now = parts(vault.bytes());
        for at in [positions.emergency, positions.recovery] {
            assert_eq!(
                now.slots[usize::from(at)],
                before.slots[usize::from(at)],
                "{what}"
            );
        }
    };
    vault.set_identity(rotated_identity(1)).unwrap();
    keep(&vault, "signed prekey rotation");
    vault.change_passphrase(NEW_PASS).unwrap();
    keep(&vault, "passphrase change");
    vault.set_totp_secret(Some(&secret)).unwrap();
    keep(&vault, "TOTP on");
    vault.set_shared_app(b"{\"name\":\"Ana Maria\"}").unwrap();
    keep(&vault, "name change");
    vault.set_kit(Some(&[9u8; 300])).unwrap();
    keep(&vault, "kit");
    let e = emergency(unseal(vault.bytes(), EMERGENCY, Some(&totp_now(&secret))).unwrap());
    assert_eq!(e.shared_app(), b"{\"name\":\"Ana Maria\"}");
}

/// [11]
#[test]
fn a_new_passphrase_that_opens_the_emergency_slot_is_refused() {
    let mut vault = with_emergency(None);
    let before = vault.bytes().to_vec();
    assert!(matches!(
        vault.change_passphrase(EMERGENCY).err(),
        Some(VaultError::PassphraseOpensEmergencySlot)
    ));
    assert_eq!(vault.bytes(), &before[..]);
}

#[test]
fn changing_the_passphrase_opens_with_the_new_one_only() {
    let mut vault = with_emergency(None);
    let before = parts(vault.bytes());
    vault.change_passphrase(NEW_PASS).unwrap();
    let after = parts(vault.bytes());
    assert_eq!(after.body, before.body);
    assert_ne!(after.shared, before.shared, "R moves to the new passphrase");
    real(unseal(vault.bytes(), NEW_PASS, None).unwrap());
    assert!(matches!(
        unseal(vault.bytes(), PASS, None).err(),
        Some(VaultError::DecryptionFailed)
    ));
    let reopened = real(unseal(vault.bytes(), NEW_PASS, None).unwrap());
    let kek = spy_kek(&vault.header, NEW_PASS);
    assert_eq!(reopened.shared.redirect_pub, redirect::public_key(&kek));
}

/// [12]
#[test]
fn turning_totp_on_or_off_rewrites_only_the_shared_block() {
    let mut vault = with_emergency(None);
    let off = parts(vault.bytes());
    vault
        .set_totp_secret(Some(&generate_totp_secret()))
        .unwrap();
    let on = parts(vault.bytes());
    assert_eq!((off.hint, on.hint), (0, 1));
    assert_ne!(on.shared, off.shared);
    assert_eq!(
        (&on.header, &on.slots, &on.body),
        (&off.header, &off.slots, &off.body)
    );
    vault.set_totp_secret(None).unwrap();
    let off_again = parts(vault.bytes());
    assert_eq!(off_again.hint, 0);
    assert_eq!(
        (&off_again.header, &off_again.slots, &off_again.body),
        (&off.header, &off.slots, &off.body)
    );
    real(unseal(vault.bytes(), PASS, None).unwrap());
}

/// [14]
#[test]
fn the_salt_and_parameters_survive_every_reseal() {
    let mut vault = create(None);
    let header = vault.bytes()[..HEADER_LEN].to_vec();
    vault.set_identity(rotated_identity(2)).unwrap();
    vault.set_app(Some(&[1u8; 100])).unwrap();
    vault.set_kit(Some(&[2u8; 50])).unwrap();
    vault
        .set_totp_secret(Some(&generate_totp_secret()))
        .unwrap();
    vault.set_shared_app(b"other").unwrap();
    vault.set_emergency_key(PASS, EMERGENCY).unwrap();
    vault.change_passphrase(NEW_PASS).unwrap();
    vault.remove_emergency_key(NEW_PASS).unwrap();
    assert_eq!(&vault.bytes()[..HEADER_LEN], &header[..]);
}

/// [60]
#[test]
fn testing_the_key_never_writes_the_vault() {
    let vault = with_emergency(None);
    let before = vault.bytes().to_vec();
    for (candidate, expected) in [(EMERGENCY, true), (PASS, false), (OTHER, false)] {
        let derived = spy_count(&vault);
        assert_eq!(
            vault.is_emergency_key(candidate).unwrap(),
            expected,
            "{candidate}"
        );
        assert_eq!(spy_count(&vault), derived + 1);
    }
    assert_eq!(vault.bytes(), &before[..]);
    assert!(!create(None).is_emergency_key(EMERGENCY).unwrap());
}

#[test]
fn the_setters_leave_the_vault_whole_when_a_field_does_not_fit() {
    let mut vault = create(None);
    let before = vault.bytes().to_vec();
    assert!(matches!(
        vault.set_kit(Some(&vec![0u8; MAX_KIT_LEN + 1])).err(),
        Some(VaultError::TooLarge { .. })
    ));
    assert!(matches!(
        vault
            .set_shared_app(&vec![0u8; MAX_SHARED_APP_LEN + 1])
            .err(),
        Some(VaultError::TooLarge { .. })
    ));
    assert!(matches!(
        vault.set_app(Some(&[])).err(),
        Some(VaultError::InvalidAppData(0))
    ));
    let mut huge = create_identity();
    huge.one_time_prekeys = crate::identity::create_one_time_prekeys(1, 400);
    assert!(matches!(
        vault.set_identity(huge).err(),
        Some(VaultError::TooLarge {
            what: "vault body",
            ..
        })
    ));
    assert_eq!(vault.bytes(), &before[..]);
    assert_eq!(vault.kit(), None);
    assert_eq!(
        vault.identity().one_time_prekeys.len(),
        crate::identity::OPK_COUNT
    );
}

/// [1], with an emergency key and a kit as well. And CE-D2: the largest
/// body the app writes today (`OPK_COUNT` one-time prekeys, the retired
/// signed prekeys of 30 days, 256 bytes of app data and a full kit) fits in
/// 32 KiB with more than a quarter to spare.
#[test]
fn the_largest_body_fits_in_32_kib() {
    let mut identity = rotated_identity(40);
    let retired = identity.retired_signed_prekeys.len();
    assert!(retired >= 14, "{retired} retired");
    let mut vault = with_emergency(Some(&generate_totp_secret()));
    vault
        .set_app(Some(&[0xffu8; crate::vault::MAX_APP_DATA_LEN]))
        .unwrap();
    vault.set_kit(Some(&[0xeeu8; MAX_KIT_LEN])).unwrap();
    vault.set_identity(identity.clone()).unwrap();
    let json = open_body_json(vault.bytes(), &vault.mk, &vault.header).unwrap();
    let opk = identity.one_time_prekeys.len();
    println!(
        "largest body: {} of {} bytes ({} OPK, {} retired SPK, 256 B app, 1 KiB kit), {} to spare",
        json.len(),
        BODY_JSON_MAX,
        opk,
        retired,
        BODY_JSON_MAX - json.len()
    );
    assert_eq!(vault.bytes().len(), V3_VAULT_LEN);
    assert!(
        BODY_JSON_MAX - json.len() > BODY_JSON_MAX / 4,
        "less than a quarter to spare"
    );
    // How many one-time prekeys fit with all the rest; one more is refused
    // and leaves the vault as it was.
    let mut fitting = opk;
    loop {
        identity
            .one_time_prekeys
            .extend(crate::identity::create_one_time_prekeys(
                1000 + fitting as u32,
                1,
            ));
        match vault.set_identity(identity.clone()) {
            Ok(()) => fitting += 1,
            Err(VaultError::TooLarge { .. }) => break,
            Err(e) => panic!("{e}"),
        }
    }
    println!("at most {fitting} OPK fit with the rest");
    assert!(fitting >= 80, "{fitting}");
    assert_eq!(vault.identity().one_time_prekeys.len(), fitting);
}
