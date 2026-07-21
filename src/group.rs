// group.rs — signed group roster (closed membership, WhatsApp-style admin).
// Mirrors trino/src/core/group.ts. The signing bytes are byte-identical to the TS
// side (compact JSON array) so a roster signed on one runtime verifies on the other.

use crate::identity::{ed25519_sign, ed25519_verify, Identity};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GroupError {
    #[error("only the group admin can change the roster")]
    NotAdmin,
    #[error("cannot remove the admin")]
    RemoveAdmin,
    #[error("hex decode failed")]
    Hex,
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

/// Canonical bytes the admin signs — identical layout to group.ts.
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
    let mut member_ids: Vec<String> = members.iter().map(|m| m.ik_sign_pub.clone()).collect();
    member_ids.sort();
    serde_json::json!([group_id, name, photo_val, admin_pub, member_ids, epoch])
        .to_string()
        .into_bytes()
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

fn sign_unsigned(
    group_id: String,
    name: String,
    photo: Option<FileRef>,
    admin_pub: String,
    members: Vec<MemberBundle>,
    epoch: u64,
    admin: &Identity,
) -> GroupRoster {
    let bytes = roster_signing_bytes(&group_id, &name, &photo, &admin_pub, &members, epoch);
    let sig = ed25519_sign(&admin.ik_sign, &bytes);
    GroupRoster {
        group_id,
        name,
        photo,
        admin_pub,
        members,
        epoch,
        signature: hex::encode(sig),
    }
}

pub fn verify_roster(roster: &GroupRoster) -> bool {
    if !roster
        .members
        .iter()
        .any(|m| m.ik_sign_pub == roster.admin_pub)
    {
        return false;
    }
    let Ok(admin_pub) = decode_32(&roster.admin_pub) else {
        return false;
    };
    let Ok(sig) = decode_64(&roster.signature) else {
        return false;
    };
    let bytes = roster_signing_bytes(
        &roster.group_id,
        &roster.name,
        &roster.photo,
        &roster.admin_pub,
        &roster.members,
        roster.epoch,
    );
    ed25519_verify(&admin_pub, &bytes, &sig)
}

pub fn create_group(admin: &Identity, admin_bundle: MemberBundle, name: &str) -> GroupRoster {
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
    let mut members = roster.members.clone();
    members.push(member);
    Ok(sign_unsigned(
        roster.group_id.clone(),
        roster.name.clone(),
        roster.photo.clone(),
        roster.admin_pub.clone(),
        members,
        roster.epoch + 1,
        admin,
    ))
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
    Ok(sign_unsigned(
        roster.group_id.clone(),
        roster.name.clone(),
        roster.photo.clone(),
        roster.admin_pub.clone(),
        members,
        roster.epoch + 1,
        admin,
    ))
}

pub fn set_group_name(
    roster: &GroupRoster,
    admin: &Identity,
    name: &str,
) -> Result<GroupRoster, GroupError> {
    assert_admin(roster, admin)?;
    Ok(sign_unsigned(
        roster.group_id.clone(),
        name.to_string(),
        roster.photo.clone(),
        roster.admin_pub.clone(),
        roster.members.clone(),
        roster.epoch + 1,
        admin,
    ))
}

pub fn set_group_photo(
    roster: &GroupRoster,
    admin: &Identity,
    photo: Option<FileRef>,
) -> Result<GroupRoster, GroupError> {
    assert_admin(roster, admin)?;
    Ok(sign_unsigned(
        roster.group_id.clone(),
        roster.name.clone(),
        photo,
        roster.admin_pub.clone(),
        roster.members.clone(),
        roster.epoch + 1,
        admin,
    ))
}

pub fn is_member(roster: &GroupRoster, ik_sign_pub: &str) -> bool {
    roster.members.iter().any(|m| m.ik_sign_pub == ik_sign_pub)
}

/// Accept an update only if valid, same group, same admin, strictly newer epoch.
pub fn accept_roster_update(current: &GroupRoster, incoming: &GroupRoster) -> bool {
    incoming.group_id == current.group_id
        && incoming.admin_pub == current.admin_pub
        && incoming.epoch > current.epoch
        && verify_roster(incoming)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{create_identity, public_bundle_for};

    fn member_of(id: &Identity, handle: &str) -> MemberBundle {
        let b = public_bundle_for(id);
        MemberBundle {
            handle: handle.to_string(),
            ik_sign_pub: b.ik_sign_pub,
            ik_dh_pub: b.ik_dh_pub,
            nostr_pub: b.nostr_pub,
            spk_id: b.spk_id,
            spk_pub: b.spk_pub,
            spk_sig: b.spk_sig,
        }
    }

    #[test]
    fn create_and_verify() {
        let admin = create_identity();
        let roster = create_group(&admin, member_of(&admin, "me"), "amigos");
        assert!(verify_roster(&roster));
        assert_eq!(roster.epoch, 0);
        assert!(is_member(&roster, &roster.admin_pub));
    }

    #[test]
    fn admin_adds_member() {
        let admin = create_identity();
        let juan = create_identity();
        let roster = create_group(&admin, member_of(&admin, "me"), "amigos");
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
        let roster = create_group(&admin, member_of(&admin, "me"), "amigos");
        assert!(matches!(
            add_member(&roster, &juan, member_of(&ana, "ana")),
            Err(GroupError::NotAdmin)
        ));
    }

    #[test]
    fn tampered_name_fails_verify() {
        let admin = create_identity();
        let mut roster = create_group(&admin, member_of(&admin, "me"), "amigos");
        roster.name = "hackeado".to_string();
        assert!(!verify_roster(&roster));
    }

    #[test]
    fn injected_member_fails_verify() {
        let admin = create_identity();
        let intruso = create_identity();
        let mut roster = create_group(&admin, member_of(&admin, "me"), "amigos");
        roster.members.push(member_of(&intruso, "intruso"));
        assert!(!verify_roster(&roster));
    }

    #[test]
    fn verifies_ts_signed_roster() {
        // Roster created + signed by the TS implementation (tools/emit-roster.ts).
        // Confirms the signing-bytes layout and ed25519 are cross-compatible.
        let raw = r#"{"groupId":"a740e9b19b5b678aa16420d617c89b01a22b130fd9e7d45e9c21477610d5a765","name":"amigos test","photo":null,"adminPub":"b968235dad39f27dec0622349cc0c305130cb9550ff1a394075b0ea8b1f9adba","members":[{"handle":"admin","ikSignPub":"b968235dad39f27dec0622349cc0c305130cb9550ff1a394075b0ea8b1f9adba","ikDhPub":"d290573f7555d977a658cf76a8d7ef613d6dc13223ba59abddac2706aa0a011f","nostrPub":"ce7a974d032b0a3ad5a3c58f286ce5e35be109e9d6048971ebd90c5737d2b531","spkId":1,"spkPub":"e67e0af4be0a314cabcf1c2d1b705e1f0a7f04d82ef9a51a31a15d2ecaed8450","spkSig":"8cc6c0b2e99f25269308b4ae911858b58cc821e8f8a5b97e7af30f2c17484b3fbc572da8b27c2aa50b381804e09cc8e1c6f0fa09dd4caf82381e2c97e0afab08"},{"handle":"juan","ikSignPub":"fe86ff3a92c5ad43f29bfcc82bcf5e41740529bbd736d4d5aaaec4d7fd864e6c","ikDhPub":"ced9abf0d5f5fcf049fff84f2c8d34da970a61c5789d257fd01ea90cf89c2d3f","nostrPub":"a75025409d1a3322bd49f300126eab7cec686a56cf2a5ad11552f9535b15b875","spkId":1,"spkPub":"eb64a24b6645deb4cfe0f488bc531e0c29b77a3cf4687b61972fb1f2b5d76473","spkSig":"fe72078dde99f4223fbc26943fd43599a2c96b37e7c2a21c0f0e255ed5f188c6da4abfc0d4cf3f7c5c20d0d361e95ae5d25f601cfc199266f6f6319d27ea4300"}],"epoch":1,"signature":"9b0d6f65aaadb866ddacd234522dbf87aedf263d9013263d316d43de99fd84ce71cebb48ca38b97c59498ec1508f350c0ca380f1fc882ad42b7bd23bc8b0c506"}"#;
        let roster: GroupRoster = serde_json::from_str(raw).unwrap();
        assert!(
            verify_roster(&roster),
            "Rust must verify a TS-signed roster"
        );
    }

    #[test]
    fn rollback_and_takeover_rejected() {
        let admin = create_identity();
        let juan = create_identity();
        let attacker = create_identity();
        let v0 = create_group(&admin, member_of(&admin, "me"), "amigos");
        let v1 = add_member(&v0, &admin, member_of(&juan, "juan")).unwrap();
        assert!(accept_roster_update(&v0, &v1));
        assert!(!accept_roster_update(&v1, &v0)); // rollback
        assert!(!accept_roster_update(&v1, &v1)); // same epoch
        let forged = create_group(&attacker, member_of(&attacker, "evil"), "amigos");
        let mut forged_v2 = forged;
        forged_v2.group_id = v1.group_id.clone();
        forged_v2.epoch = 99;
        assert!(!accept_roster_update(&v1, &forged_v2)); // admin takeover
    }
}
