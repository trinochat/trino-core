// group.rs — signed group roster (closed membership, WhatsApp-style admin).
//
// Roster v2
// ---------
// A roster tells every member who is in the group AND which keys reach them,
// and clients add members they don't know yet as contacts from it. Roster v1
// had the admin sign only the sorted list of identity keys (ik_sign_pub): the
// DH, Nostr and prekey fields travelled unauthenticated. Signing them would
// still only prove what the ADMIN claims, and any contact can be the admin of a
// group of their own. So a contact could list someone else's real identity key
// next to transport keys they control, and have those keys installed as that
// person on every member's device.
//
// v2 closes both gaps:
//   * each `MemberBundle` carries the member's OWN `id_sig` (ik_sign over
//     ik_dh_pub || nostr_pub, the binding a pasted bundle carries), and
//     `validate_roster` checks it and the signed prekey for every member;
//   * the admin signs `ROSTER_SIG_DOMAIN` followed by every field of every
//     member, sorted canonically, plus gid, name, photo, admin_pub and epoch.
//
// PROTOCOL BUMP: v1 rosters (no member id_sig, different signed bytes) fail
// validation, so clients from before v2 stop interoperating in groups. This is
// intentional. The TS implementation (trino/src/core/group.ts), which this file
// used to mirror byte for byte, still speaks v1.

use crate::identity::{
    ed25519_sign, ed25519_verify, verify_bundle_binding, Identity, PublicBundle,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

/// Upper bound on roster size, enforced when building a roster and when
/// receiving one. It bounds the work a roster costs (two signature checks per
/// member) and the number of contacts one roster can introduce. Fan-out is
/// pairwise, so much larger groups would be impractical anyway; relay event
/// size limits may bite before this does.
pub const MAX_GROUP_MEMBERS: usize = 128;

/// Domain-separation prefix of the bytes the admin signs, so a roster
/// signature can never be confused with any other ik_sign signature.
pub const ROSTER_SIG_DOMAIN: &[u8] = b"trino/roster/v2\0";

#[derive(Debug, Error)]
pub enum GroupError {
    #[error("only the group admin can change the roster")]
    NotAdmin,
    #[error("cannot remove the admin")]
    RemoveAdmin,
    #[error("hex decode failed")]
    Hex,
    #[error("the group is full ({MAX_GROUP_MEMBERS} members)")]
    Full,
    #[error("the roster would be invalid: {0}")]
    InvalidRoster(RosterError),
}

/// Why a roster fails `validate_roster`.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RosterError {
    #[error("roster has no members")]
    Empty,
    #[error("roster has {0} members, more than {MAX_GROUP_MEMBERS}")]
    TooManyMembers(usize),
    #[error("the admin is not a member")]
    AdminNotMember,
    #[error("two members share a key")]
    DuplicateMember,
    /// Malformed keys, a bad signed prekey signature, or keys the member's own
    /// identity key did not sign (missing or wrong `id_sig`).
    #[error("member #{0} does not bind its own keys")]
    InvalidMemberBinding(usize),
    #[error("admin signature invalid")]
    InvalidSignature,
}

/// Why `evaluate_incoming_roster` refused a roster.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RosterRejection {
    #[error("sender is not the group admin")]
    SenderNotAdmin,
    #[error("roster does not include us")]
    NotAMember,
    #[error("roster is for a different group")]
    GroupMismatch,
    #[error("roster changes the group admin")]
    AdminChanged,
    #[error("roster epoch is not newer")]
    Stale,
    #[error("invalid roster: {0}")]
    Invalid(RosterError),
}

/// What to do with a roster that arrived from a contact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RosterDecision {
    /// A valid, newer roster for a group we are already in: apply it.
    Accept,
    /// A valid roster for a group we are not in. Never apply it directly; the
    /// user must accept the invitation first.
    PendingInvite,
    Reject(RosterRejection),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FileRef {
    pub url: String,
    pub key: String,
    pub sha256: String,
    pub mime: String,
    pub name: String,
    pub size: u64,
    // Small inline preview (data: URL), travels E2E-encrypted inside the message
    // so the recipient sees a thumbnail without downloading the full blob.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub thumb: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MemberBundle {
    pub handle: String,
    pub ik_sign_pub: String,
    pub ik_dh_pub: String,
    pub nostr_pub: String,
    pub spk_id: u32,
    pub spk_pub: String,
    pub spk_sig: String,
    /// The member's own ik_sign signature over (ik_dh_pub || nostr_pub): the
    /// `id_sig` of their `PublicBundle`. It is what proves the transport keys
    /// belong to the member and were not picked by the admin. Defaults to empty
    /// so a v1 roster still parses (and is then rejected as a roster rather
    /// than shown as text).
    #[serde(default)]
    pub id_sig: String,
}

impl MemberBundle {
    pub fn from_public_bundle(handle: &str, bundle: &PublicBundle) -> Self {
        MemberBundle {
            handle: handle.to_string(),
            ik_sign_pub: bundle.ik_sign_pub.clone(),
            ik_dh_pub: bundle.ik_dh_pub.clone(),
            nostr_pub: bundle.nostr_pub.clone(),
            spk_id: bundle.spk_id,
            spk_pub: bundle.spk_pub.clone(),
            spk_sig: bundle.spk_sig.clone(),
            id_sig: bundle.id_sig.clone(),
        }
    }

    /// The member as a contact bundle, binding signature included, ready for
    /// `verify_bundle_binding`.
    pub fn to_public_bundle(&self) -> PublicBundle {
        PublicBundle {
            ik_sign_pub: self.ik_sign_pub.clone(),
            ik_dh_pub: self.ik_dh_pub.clone(),
            nostr_pub: self.nostr_pub.clone(),
            spk_id: self.spk_id,
            spk_pub: self.spk_pub.clone(),
            spk_sig: self.spk_sig.clone(),
            opk_id: None,
            opk_pub: None,
            id_sig: self.id_sig.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GroupRoster {
    pub group_id: String,
    pub name: String,
    pub photo: Option<FileRef>,
    pub admin_pub: String,
    pub members: Vec<MemberBundle>,
    pub epoch: u64,
    pub signature: String,
}

/// Canonical bytes the admin signs (roster v2).
///
/// `ROSTER_SIG_DOMAIN` followed by the compact JSON array
/// `[groupId, name, photo, adminPub, members, epoch]`, where `photo` is
/// `[url, key, sha256, mime, name, size]` or null, and `members` holds one
/// `[ikSignPub, ikDhPub, nostrPub, spkId, spkPub, spkSig, idSig, handle]` per
/// member, sorted by its serialized form so wire order does not matter. The
/// photo thumbnail is a display hint and is not covered.
pub fn roster_signing_bytes(
    group_id: &str,
    name: &str,
    photo: &Option<FileRef>,
    admin_pub: &str,
    members: &[MemberBundle],
    epoch: u64,
) -> Vec<u8> {
    let photo_val = match photo {
        Some(p) => serde_json::json!([p.url, p.key, p.sha256, p.mime, p.name, p.size]),
        None => serde_json::Value::Null,
    };
    let mut member_vals: Vec<serde_json::Value> = members
        .iter()
        .map(|m| {
            serde_json::json!([
                m.ik_sign_pub,
                m.ik_dh_pub,
                m.nostr_pub,
                m.spk_id,
                m.spk_pub,
                m.spk_sig,
                m.id_sig,
                m.handle
            ])
        })
        .collect();
    member_vals.sort_by_cached_key(|v| v.to_string());
    let body = serde_json::json!([group_id, name, photo_val, admin_pub, member_vals, epoch]);
    let mut out = ROSTER_SIG_DOMAIN.to_vec();
    out.extend_from_slice(body.to_string().as_bytes());
    out
}

fn decode_64(s: &str) -> Result<[u8; 64], GroupError> {
    let v = hex::decode(s).map_err(|_| GroupError::Hex)?;
    if v.len() != 64 {
        return Err(GroupError::Hex);
    }
    let mut a = [0u8; 64];
    a.copy_from_slice(&v);
    Ok(a)
}

fn decode_32(s: &str) -> Result<[u8; 32], GroupError> {
    let v = hex::decode(s).map_err(|_| GroupError::Hex)?;
    if v.len() != 32 {
        return Err(GroupError::Hex);
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

/// Lowercase hex of exactly `len` bytes. Keys are compared as strings across
/// the app, so "AB.." and "ab.." must not both pass as the same key.
fn is_canonical_hex(s: &str, len: usize) -> bool {
    s.len() == len * 2 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn member_is_bound(m: &MemberBundle) -> bool {
    is_canonical_hex(&m.ik_sign_pub, 32)
        && is_canonical_hex(&m.ik_dh_pub, 32)
        && is_canonical_hex(&m.nostr_pub, 32)
        && is_canonical_hex(&m.spk_pub, 32)
        && is_canonical_hex(&m.spk_sig, 64)
        && is_canonical_hex(&m.id_sig, 64)
        && verify_bundle_binding(&m.to_public_bundle())
}

fn sign_unsigned(
    group_id: String,
    name: String,
    photo: Option<FileRef>,
    admin_pub: String,
    members: Vec<MemberBundle>,
    epoch: u64,
    admin: &Identity,
) -> Result<GroupRoster, GroupError> {
    if members.len() > MAX_GROUP_MEMBERS {
        return Err(GroupError::Full);
    }
    let bytes = roster_signing_bytes(&group_id, &name, &photo, &admin_pub, &members, epoch);
    let sig = ed25519_sign(&admin.ik_sign, &bytes);
    let roster = GroupRoster {
        group_id,
        name,
        photo,
        admin_pub,
        members,
        epoch,
        signature: hex::encode(sig),
    };
    // Never hand out a roster the members would reject.
    validate_roster(&roster).map_err(GroupError::InvalidRoster)?;
    Ok(roster)
}

/// Full validity check of a roster on its own (no group context), cheapest
/// checks first: size, admin membership, duplicate keys, then every member's
/// own key binding, then the admin signature. Any failure rejects the whole
/// roster.
pub fn validate_roster(roster: &GroupRoster) -> Result<(), RosterError> {
    let count = roster.members.len();
    if count == 0 {
        return Err(RosterError::Empty);
    }
    if count > MAX_GROUP_MEMBERS {
        return Err(RosterError::TooManyMembers(count));
    }
    if !is_member(roster, &roster.admin_pub) {
        return Err(RosterError::AdminNotMember);
    }
    // No key may appear twice. A second identity key can validly bind someone
    // else's DH/Nostr keys (id_sig only proves which keys the identity chose),
    // and clients look contacts up by those keys.
    let mut seen = HashSet::with_capacity(count * 3);
    for m in &roster.members {
        for key in [&m.ik_sign_pub, &m.ik_dh_pub, &m.nostr_pub] {
            if !seen.insert(key.as_str()) {
                return Err(RosterError::DuplicateMember);
            }
        }
    }
    if let Some(i) = roster.members.iter().position(|m| !member_is_bound(m)) {
        return Err(RosterError::InvalidMemberBinding(i));
    }
    let (Ok(admin_pub), Ok(sig)) = (decode_32(&roster.admin_pub), decode_64(&roster.signature))
    else {
        return Err(RosterError::InvalidSignature);
    };
    let bytes = roster_signing_bytes(
        &roster.group_id,
        &roster.name,
        &roster.photo,
        &roster.admin_pub,
        &roster.members,
        roster.epoch,
    );
    if !ed25519_verify(&admin_pub, &bytes, &sig) {
        return Err(RosterError::InvalidSignature);
    }
    Ok(())
}

pub fn verify_roster(roster: &GroupRoster) -> bool {
    validate_roster(roster).is_ok()
}

pub fn create_group(
    admin: &Identity,
    admin_bundle: MemberBundle,
    name: &str,
) -> Result<GroupRoster, GroupError> {
    let seed = crate::crypto::random_array::<32>();
    let group_id = hex::encode(seed);
    let admin_pub = admin_bundle.ik_sign_pub.clone();
    sign_unsigned(
        group_id,
        name.to_string(),
        None,
        admin_pub,
        vec![admin_bundle],
        0,
        admin,
    )
}

fn assert_admin(roster: &GroupRoster, admin: &Identity) -> Result<(), GroupError> {
    if hex::encode(admin.ik_sign.pub_bytes) != roster.admin_pub {
        return Err(GroupError::NotAdmin);
    }
    Ok(())
}

pub fn add_member(
    roster: &GroupRoster,
    admin: &Identity,
    member: MemberBundle,
) -> Result<GroupRoster, GroupError> {
    assert_admin(roster, admin)?;
    if roster
        .members
        .iter()
        .any(|m| m.ik_sign_pub == member.ik_sign_pub)
    {
        return Ok(roster.clone());
    }
    if roster.members.len() >= MAX_GROUP_MEMBERS {
        return Err(GroupError::Full);
    }
    let mut members = roster.members.clone();
    members.push(member);
    sign_unsigned(
        roster.group_id.clone(),
        roster.name.clone(),
        roster.photo.clone(),
        roster.admin_pub.clone(),
        members,
        roster.epoch + 1,
        admin,
    )
}

pub fn remove_member(
    roster: &GroupRoster,
    admin: &Identity,
    ik_sign_pub: &str,
) -> Result<GroupRoster, GroupError> {
    assert_admin(roster, admin)?;
    if ik_sign_pub == roster.admin_pub {
        return Err(GroupError::RemoveAdmin);
    }
    let members: Vec<MemberBundle> = roster
        .members
        .iter()
        .filter(|m| m.ik_sign_pub != ik_sign_pub)
        .cloned()
        .collect();
    sign_unsigned(
        roster.group_id.clone(),
        roster.name.clone(),
        roster.photo.clone(),
        roster.admin_pub.clone(),
        members,
        roster.epoch + 1,
        admin,
    )
}

pub fn set_group_name(
    roster: &GroupRoster,
    admin: &Identity,
    name: &str,
) -> Result<GroupRoster, GroupError> {
    assert_admin(roster, admin)?;
    sign_unsigned(
        roster.group_id.clone(),
        name.to_string(),
        roster.photo.clone(),
        roster.admin_pub.clone(),
        roster.members.clone(),
        roster.epoch + 1,
        admin,
    )
}

pub fn set_group_photo(
    roster: &GroupRoster,
    admin: &Identity,
    photo: Option<FileRef>,
) -> Result<GroupRoster, GroupError> {
    assert_admin(roster, admin)?;
    sign_unsigned(
        roster.group_id.clone(),
        roster.name.clone(),
        photo,
        roster.admin_pub.clone(),
        roster.members.clone(),
        roster.epoch + 1,
        admin,
    )
}

pub fn is_member(roster: &GroupRoster, ik_sign_pub: &str) -> bool {
    roster.members.iter().any(|m| m.ik_sign_pub == ik_sign_pub)
}

/// The update rules on their own: same group, same admin, strictly newer epoch.
fn check_update_rules(
    current: &GroupRoster,
    incoming: &GroupRoster,
) -> Result<(), RosterRejection> {
    if incoming.group_id != current.group_id {
        return Err(RosterRejection::GroupMismatch);
    }
    if incoming.admin_pub != current.admin_pub {
        return Err(RosterRejection::AdminChanged);
    }
    if incoming.epoch <= current.epoch {
        return Err(RosterRejection::Stale);
    }
    Ok(())
}

/// Accept an update only if valid, same group, same admin, strictly newer epoch.
pub fn accept_roster_update(current: &GroupRoster, incoming: &GroupRoster) -> bool {
    check_update_rules(current, incoming).is_ok() && verify_roster(incoming)
}

/// Decide what to do with a roster a contact sent us. Pure: the caller passes
/// the group we hold for that gid (if any), the identity key of the contact the
/// roster came from (as authenticated by the pairwise session), and ours.
///
/// * Only the roster's admin may send it. A member relaying a valid roster is
///   rejected, so nobody but the admin can push group state at us.
/// * The roster must pass `validate_roster` and list us.
/// * A group we don't hold is never applied directly: it is a `PendingInvite`
///   the user accepts or declines.
/// * An update must pass the `accept_roster_update` rules.
pub fn evaluate_incoming_roster(
    current: Option<&GroupRoster>,
    incoming: &GroupRoster,
    sender_ik_sign_pub: &str,
    my_ik_sign_pub: &str,
) -> RosterDecision {
    if sender_ik_sign_pub != incoming.admin_pub {
        return RosterDecision::Reject(RosterRejection::SenderNotAdmin);
    }
    if let Err(e) = validate_roster(incoming) {
        return RosterDecision::Reject(RosterRejection::Invalid(e));
    }
    if !is_member(incoming, my_ik_sign_pub) {
        return RosterDecision::Reject(RosterRejection::NotAMember);
    }
    match current {
        None => RosterDecision::PendingInvite,
        Some(current) => match check_update_rules(current, incoming) {
            Ok(()) => RosterDecision::Accept,
            Err(why) => RosterDecision::Reject(why),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{
        create_identity, create_signed_prekey, generate_ed25519, generate_nostr_keypair,
        generate_x25519, public_bundle_for, verify_bundle_binding,
    };

    fn member_of(id: &Identity, handle: &str) -> MemberBundle {
        MemberBundle::from_public_bundle(handle, &public_bundle_for(id))
    }

    fn ik_of(id: &Identity) -> String {
        hex::encode(id.ik_sign.pub_bytes)
    }

    fn new_gid() -> String {
        hex::encode(crate::crypto::random_array::<32>())
    }

    /// A complete identity without one-time prekeys, cheap enough to mint by
    /// the hundred.
    fn light_identity() -> Identity {
        let ik_sign = generate_ed25519();
        let signed_prekey = create_signed_prekey(&ik_sign, 1);
        Identity {
            ik_sign,
            ik_dh: generate_x25519(),
            nostr: generate_nostr_keypair(),
            signed_prekey,
            one_time_prekeys: vec![],
            retired_signed_prekeys: vec![],
        }
    }

    /// Sign a roster exactly as given, skipping every builder check: what a
    /// hostile admin running a modified client can produce.
    fn sign_raw(
        admin: &Identity,
        group_id: &str,
        members: Vec<MemberBundle>,
        epoch: u64,
    ) -> GroupRoster {
        let admin_pub = ik_of(admin);
        let bytes = roster_signing_bytes(group_id, "amigos", &None, &admin_pub, &members, epoch);
        GroupRoster {
            group_id: group_id.to_string(),
            name: "amigos".to_string(),
            photo: None,
            admin_pub,
            members,
            epoch,
            signature: hex::encode(ed25519_sign(&admin.ik_sign, &bytes)),
        }
    }

    fn signing_bytes_of(r: &GroupRoster) -> Vec<u8> {
        roster_signing_bytes(
            &r.group_id,
            &r.name,
            &r.photo,
            &r.admin_pub,
            &r.members,
            r.epoch,
        )
    }

    #[test]
    fn create_and_verify() {
        let admin = create_identity();
        let roster = create_group(&admin, member_of(&admin, "me"), "amigos").unwrap();
        assert!(verify_roster(&roster));
        assert_eq!(roster.epoch, 0);
        assert!(is_member(&roster, &roster.admin_pub));
    }

    #[test]
    fn admin_adds_member() {
        let admin = create_identity();
        let juan = create_identity();
        let roster = create_group(&admin, member_of(&admin, "me"), "amigos").unwrap();
        let roster = add_member(&roster, &admin, member_of(&juan, "juan")).unwrap();
        assert!(verify_roster(&roster));
        assert_eq!(roster.epoch, 1);
        assert!(is_member(&roster, &public_bundle_for(&juan).ik_sign_pub));
    }

    #[test]
    fn non_admin_rejected() {
        let admin = create_identity();
        let juan = create_identity();
        let ana = create_identity();
        let roster = create_group(&admin, member_of(&admin, "me"), "amigos").unwrap();
        assert!(matches!(
            add_member(&roster, &juan, member_of(&ana, "ana")),
            Err(GroupError::NotAdmin)
        ));
    }

    #[test]
    fn tampered_name_fails_verify() {
        let admin = create_identity();
        let mut roster = create_group(&admin, member_of(&admin, "me"), "amigos").unwrap();
        roster.name = "hackeado".to_string();
        assert!(!verify_roster(&roster));
    }

    #[test]
    fn injected_member_fails_verify() {
        let admin = create_identity();
        let intruso = create_identity();
        let mut roster = create_group(&admin, member_of(&admin, "me"), "amigos").unwrap();
        roster.members.push(member_of(&intruso, "intruso"));
        assert!(!verify_roster(&roster));
    }

    #[test]
    fn v1_roster_is_rejected() {
        // Roster signed by the TS client (tools/emit-roster.ts) in the v1
        // format: members carry no idSig and the admin signature covers only
        // the sorted ikSignPub list. Roster v2 deliberately stops accepting
        // it: that format is what let an admin pair a real identity key with
        // transport keys of their choosing. It must still PARSE (idSig
        // defaults to empty) so it is rejected as a roster instead of being
        // shown to the user as a text message full of JSON.
        let raw = r#"{"groupId":"a740e9b19b5b678aa16420d617c89b01a22b130fd9e7d45e9c21477610d5a765","name":"amigos test","photo":null,"adminPub":"b968235dad39f27dec0622349cc0c305130cb9550ff1a394075b0ea8b1f9adba","members":[{"handle":"admin","ikSignPub":"b968235dad39f27dec0622349cc0c305130cb9550ff1a394075b0ea8b1f9adba","ikDhPub":"d290573f7555d977a658cf76a8d7ef613d6dc13223ba59abddac2706aa0a011f","nostrPub":"ce7a974d032b0a3ad5a3c58f286ce5e35be109e9d6048971ebd90c5737d2b531","spkId":1,"spkPub":"e67e0af4be0a314cabcf1c2d1b705e1f0a7f04d82ef9a51a31a15d2ecaed8450","spkSig":"8cc6c0b2e99f25269308b4ae911858b58cc821e8f8a5b97e7af30f2c17484b3fbc572da8b27c2aa50b381804e09cc8e1c6f0fa09dd4caf82381e2c97e0afab08"},{"handle":"juan","ikSignPub":"fe86ff3a92c5ad43f29bfcc82bcf5e41740529bbd736d4d5aaaec4d7fd864e6c","ikDhPub":"ced9abf0d5f5fcf049fff84f2c8d34da970a61c5789d257fd01ea90cf89c2d3f","nostrPub":"a75025409d1a3322bd49f300126eab7cec686a56cf2a5ad11552f9535b15b875","spkId":1,"spkPub":"eb64a24b6645deb4cfe0f488bc531e0c29b77a3cf4687b61972fb1f2b5d76473","spkSig":"fe72078dde99f4223fbc26943fd43599a2c96b37e7c2a21c0f0e255ed5f188c6da4abfc0d4cf3f7c5c20d0d361e95ae5d25f601cfc199266f6f6319d27ea4300"}],"epoch":1,"signature":"9b0d6f65aaadb866ddacd234522dbf87aedf263d9013263d316d43de99fd84ce71cebb48ca38b97c59498ec1508f350c0ca380f1fc882ad42b7bd23bc8b0c506"}"#;
        let roster: GroupRoster = serde_json::from_str(raw).unwrap();
        assert!(roster.members.iter().all(|m| m.id_sig.is_empty()));
        assert!(!verify_roster(&roster), "a v1 roster must not verify");
    }

    #[test]
    fn rollback_and_takeover_rejected() {
        let admin = create_identity();
        let juan = create_identity();
        let attacker = create_identity();
        let v0 = create_group(&admin, member_of(&admin, "me"), "amigos").unwrap();
        let v1 = add_member(&v0, &admin, member_of(&juan, "juan")).unwrap();
        assert!(accept_roster_update(&v0, &v1));
        assert!(!accept_roster_update(&v1, &v0)); // rollback
        assert!(!accept_roster_update(&v1, &v1)); // same epoch
        let forged = create_group(&attacker, member_of(&attacker, "evil"), "amigos").unwrap();
        let mut forged_v2 = forged;
        forged_v2.group_id = v1.group_id.clone();
        forged_v2.epoch = 99;
        assert!(!accept_roster_update(&v1, &forged_v2)); // admin takeover
    }

    #[test]
    fn member_bundle_round_trip_keeps_the_binding() {
        let alice = create_identity();
        let bundle = public_bundle_for(&alice);
        let member = MemberBundle::from_public_bundle("alice", &bundle);
        assert_eq!(member.id_sig, bundle.id_sig);
        assert!(verify_bundle_binding(&member.to_public_bundle()));
    }

    #[test]
    fn forged_member_binding_rejected() {
        // C1. Mallory is the legitimate admin of HER OWN group. She lists
        // "alice" with Alice's real identity key and signed prekey, but with
        // Mallory2's DH and Nostr keys. Under roster v1 the admin signature
        // covered only ik_sign_pub, so this verified and Victim auto-added an
        // "alice" whose transport keys belonged to Mallory2.
        let mallory = create_identity();
        let victim = create_identity();
        let alice = create_identity();
        let mallory2 = create_identity();
        let m2 = public_bundle_for(&mallory2);
        // Either id_sig Mallory can lay hands on: Alice's real one (over
        // Alice's keys) or Mallory2's own (signed by the wrong identity key).
        for id_sig in [public_bundle_for(&alice).id_sig, m2.id_sig.clone()] {
            let mut fake_alice = member_of(&alice, "alice");
            fake_alice.ik_dh_pub = m2.ik_dh_pub.clone();
            fake_alice.nostr_pub = m2.nostr_pub.clone();
            fake_alice.id_sig = id_sig;
            let roster = sign_raw(
                &mallory,
                &new_gid(),
                vec![
                    member_of(&mallory, "mallory"),
                    member_of(&victim, "victim"),
                    fake_alice,
                ],
                0,
            );
            assert!(!verify_roster(&roster), "forged member must not verify");
            assert_eq!(
                validate_roster(&roster),
                Err(RosterError::InvalidMemberBinding(2))
            );
            assert_eq!(
                evaluate_incoming_roster(None, &roster, &ik_of(&mallory), &ik_of(&victim)),
                RosterDecision::Reject(RosterRejection::Invalid(
                    RosterError::InvalidMemberBinding(2)
                ))
            );
        }
    }

    #[test]
    fn every_member_field_is_covered_by_the_admin_signature() {
        let admin = create_identity();
        let juan = create_identity();
        let v0 = create_group(&admin, member_of(&admin, "me"), "amigos").unwrap();
        let roster = add_member(&v0, &admin, member_of(&juan, "juan")).unwrap();
        let base = signing_bytes_of(&roster);

        type Tamper<'a> = Box<dyn Fn(&mut MemberBundle) + 'a>;
        let other = public_bundle_for(&create_identity());
        let tamperers: Vec<(&str, Tamper)> = vec![
            ("handle", Box::new(|m| m.handle.push('x'))),
            (
                "ikDhPub",
                Box::new(|m| m.ik_dh_pub = other.ik_dh_pub.clone()),
            ),
            (
                "nostrPub",
                Box::new(|m| m.nostr_pub = other.nostr_pub.clone()),
            ),
            ("spkId", Box::new(|m| m.spk_id += 1)),
            ("spkPub", Box::new(|m| m.spk_pub = other.spk_pub.clone())),
            ("spkSig", Box::new(|m| m.spk_sig = other.spk_sig.clone())),
            ("idSig", Box::new(|m| m.id_sig = other.id_sig.clone())),
        ];
        let juan_idx = roster
            .members
            .iter()
            .position(|m| m.handle == "juan")
            .unwrap();
        for (field, tamper) in &tamperers {
            let mut tampered = roster.clone();
            tamper(&mut tampered.members[juan_idx]);
            assert_ne!(
                signing_bytes_of(&tampered),
                base,
                "{field} must be in the signed bytes"
            );
            assert_eq!(
                validate_roster(&tampered).err(),
                Some(match *field {
                    // These also break the member's own binding, which is
                    // checked first; the admin signature is proven above.
                    "ikDhPub" | "nostrPub" | "spkPub" | "spkSig" | "idSig" => {
                        RosterError::InvalidMemberBinding(juan_idx)
                    }
                    _ => RosterError::InvalidSignature,
                }),
                "{field}"
            );
        }
        assert!(base.starts_with(ROSTER_SIG_DOMAIN), "domain separation");
    }

    #[test]
    fn member_order_does_not_change_the_signed_bytes() {
        let admin = create_identity();
        let a = member_of(&create_identity(), "a");
        let b = member_of(&create_identity(), "b");
        let me = member_of(&admin, "me");
        let gid = new_gid();
        let r1 = sign_raw(&admin, &gid, vec![me.clone(), a.clone(), b.clone()], 3);
        let r2 = sign_raw(&admin, &gid, vec![b, me, a], 3);
        assert_eq!(signing_bytes_of(&r1), signing_bytes_of(&r2));
        assert!(verify_roster(&r2));
    }

    #[test]
    fn duplicate_member_keys_rejected() {
        // Mallory binds Alice's DH and Nostr keys to a second identity key of
        // her own. That binding is valid (id_sig only proves the identity key
        // chose those keys), so the roster must refuse the duplicate instead:
        // otherwise Alice's events could be matched to Mallory's entry.
        let mallory = create_identity();
        let alice = create_identity();
        let mut shadow = create_identity();
        shadow.ik_dh = alice.ik_dh.clone();
        shadow.nostr = alice.nostr.clone();
        let roster = sign_raw(
            &mallory,
            &new_gid(),
            vec![
                member_of(&mallory, "mallory"),
                member_of(&alice, "alice"),
                member_of(&shadow, "alice2"),
            ],
            0,
        );
        assert_eq!(validate_roster(&roster), Err(RosterError::DuplicateMember));

        let twice = sign_raw(
            &mallory,
            &new_gid(),
            vec![
                member_of(&mallory, "mallory"),
                member_of(&alice, "alice"),
                member_of(&alice, "alice-again"),
            ],
            0,
        );
        assert_eq!(validate_roster(&twice), Err(RosterError::DuplicateMember));
    }

    #[test]
    fn roster_from_non_admin_sender_rejected() {
        // Juan forwards a perfectly valid roster to Ana. Only the admin may
        // hand out rosters, so Ana must not act on it.
        let admin = create_identity();
        let juan = create_identity();
        let ana = create_identity();
        let v0 = create_group(&admin, member_of(&admin, "me"), "amigos").unwrap();
        let v1 = add_member(&v0, &admin, member_of(&juan, "juan")).unwrap();
        let v2 = add_member(&v1, &admin, member_of(&ana, "ana")).unwrap();
        assert!(verify_roster(&v2));
        let not_admin = RosterDecision::Reject(RosterRejection::SenderNotAdmin);
        assert_eq!(
            evaluate_incoming_roster(None, &v2, &ik_of(&juan), &ik_of(&ana)),
            not_admin
        );
        assert_eq!(
            evaluate_incoming_roster(Some(&v1), &v2, &ik_of(&ana), &ik_of(&juan)),
            not_admin
        );
    }

    #[test]
    fn unknown_group_is_a_pending_invite() {
        let admin = create_identity();
        let juan = create_identity();
        let v0 = create_group(&admin, member_of(&admin, "me"), "amigos").unwrap();
        let v1 = add_member(&v0, &admin, member_of(&juan, "juan")).unwrap();
        assert_eq!(
            evaluate_incoming_roster(None, &v1, &ik_of(&admin), &ik_of(&juan)),
            RosterDecision::PendingInvite
        );
    }

    #[test]
    fn legitimate_update_is_accepted() {
        let admin = create_identity();
        let juan = create_identity();
        let ana = create_identity();
        let v0 = create_group(&admin, member_of(&admin, "me"), "amigos").unwrap();
        let v1 = add_member(&v0, &admin, member_of(&juan, "juan")).unwrap();
        let v2 = add_member(&v1, &admin, member_of(&ana, "ana")).unwrap();
        let v3 = set_group_name(&v2, &admin, "amigos 2").unwrap();
        assert_eq!(
            evaluate_incoming_roster(Some(&v1), &v2, &ik_of(&admin), &ik_of(&juan)),
            RosterDecision::Accept
        );
        assert_eq!(
            evaluate_incoming_roster(Some(&v2), &v3, &ik_of(&admin), &ik_of(&juan)),
            RosterDecision::Accept
        );
    }

    #[test]
    fn update_rules_still_apply() {
        let admin = create_identity();
        let juan = create_identity();
        let ana = create_identity();
        let v0 = create_group(&admin, member_of(&admin, "me"), "amigos").unwrap();
        let v1 = add_member(&v0, &admin, member_of(&juan, "juan")).unwrap();
        let v2 = add_member(&v1, &admin, member_of(&ana, "ana")).unwrap();
        let (admin_ik, juan_ik) = (ik_of(&admin), ik_of(&juan));

        assert_eq!(
            evaluate_incoming_roster(Some(&v2), &v1, &admin_ik, &juan_ik),
            RosterDecision::Reject(RosterRejection::Stale)
        );
        assert_eq!(
            evaluate_incoming_roster(None, &v1, &admin_ik, &ik_of(&ana)),
            RosterDecision::Reject(RosterRejection::NotAMember)
        );
        let other = add_member(
            &create_group(&admin, member_of(&admin, "me"), "otro").unwrap(),
            &admin,
            member_of(&juan, "juan"),
        )
        .unwrap();
        assert_eq!(
            evaluate_incoming_roster(Some(&other), &v2, &admin_ik, &juan_ik),
            RosterDecision::Reject(RosterRejection::GroupMismatch)
        );
        // A different admin re-using the gid with a higher epoch.
        let attacker = create_identity();
        let takeover = sign_raw(
            &attacker,
            &v2.group_id,
            vec![member_of(&attacker, "evil"), member_of(&juan, "juan")],
            99,
        );
        assert_eq!(
            evaluate_incoming_roster(Some(&v2), &takeover, &ik_of(&attacker), &juan_ik),
            RosterDecision::Reject(RosterRejection::AdminChanged)
        );
    }

    #[test]
    fn oversized_roster_rejected() {
        let admin = light_identity();
        let mut members = vec![member_of(&admin, "admin")];
        members.extend(
            (1..=MAX_GROUP_MEMBERS).map(|i| member_of(&light_identity(), &format!("m{i}"))),
        );
        assert_eq!(members.len(), MAX_GROUP_MEMBERS + 1);

        let oversized = sign_raw(&admin, &new_gid(), members.clone(), 0);
        assert_eq!(
            validate_roster(&oversized),
            Err(RosterError::TooManyMembers(MAX_GROUP_MEMBERS + 1))
        );

        // A full roster is fine, but the builder refuses to grow it.
        members.pop();
        let full = sign_raw(&admin, &new_gid(), members, 0);
        assert_eq!(validate_roster(&full), Ok(()));
        assert!(matches!(
            add_member(&full, &admin, member_of(&light_identity(), "one more")),
            Err(GroupError::Full)
        ));
    }

    #[test]
    fn builders_refuse_unbound_members() {
        // A contact stored before roster v2 (no id_sig) cannot be vouched for,
        // so it must not reach a roster that every member would reject.
        let admin = create_identity();
        let juan = create_identity();
        let roster = create_group(&admin, member_of(&admin, "me"), "amigos").unwrap();
        let mut legacy = member_of(&juan, "juan");
        legacy.id_sig.clear();
        assert!(matches!(
            add_member(&roster, &admin, legacy),
            Err(GroupError::InvalidRoster(
                RosterError::InvalidMemberBinding(_)
            ))
        ));
        let mut legacy_admin = member_of(&admin, "me");
        legacy_admin.id_sig.clear();
        assert!(create_group(&admin, legacy_admin, "amigos").is_err());
    }
}
