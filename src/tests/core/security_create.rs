//! Module: ntfs_rs::security_create::tests
//! Purpose: Check inheritance, restricted recovery permissions and encoding bounds.
//! Created: 2026-11-25
//! Architecture: These unit controls exercise the core descriptor encoder without storage IO.

use super::super::security::FileAccessToken;
use super::*;

const OWNER: [u8; 12] = super::super::security::SYSTEM_SID;
const GROUP: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 19, 0, 0, 0];
const OTHER: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 20, 0, 0, 0];
const CREATOR: [u8; 12] = CREATOR_OWNER;

fn parent(aces: &[(u8, u8, u32, [u8; 12])]) -> [u8; 128] {
    let mut b = [0; 128];
    b[0] = 1;
    b[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    b[16..20].copy_from_slice(&20u32.to_le_bytes());
    b[20] = 2;
    b[22..24].copy_from_slice(&((8 + aces.len() * 20) as u16).to_le_bytes());
    b[24..26].copy_from_slice(&(aces.len() as u16).to_le_bytes());
    for (i, &(kind, flags, mask, sid)) in aces.iter().enumerate() {
        let at = 28 + i * 20;
        b[at] = kind;
        b[at + 1] = flags;
        b[at + 2..at + 4].copy_from_slice(&20u16.to_le_bytes());
        b[at + 4..at + 8].copy_from_slice(&mask.to_le_bytes());
        b[at + 8..at + 20].copy_from_slice(&sid);
    }
    b
}
#[test]
fn inherits_deny_order_and_resolves_creator_without_broadening() {
    let p = parent(&[(1, 1, 2, CREATOR), (0, 9, 3, CREATOR), (0, 2, 0x1f01ff, OTHER)]);
    let mut out = [0; 512];
    let n = file_descriptor(&p, &OWNER, &GROUP, 0o777, &mut out).unwrap();
    let sd = SecurityDescriptor::parse(&out[..n]).unwrap();
    let token = FileAccessToken { user: &OWNER, groups: &[] };
    assert_eq!(sd.check_file_access(&token, 1), Ok(true));
    assert_eq!(sd.check_file_access(&token, 2), Ok(false));
    assert_eq!(sd.check_file_access(&FileAccessToken { user: &OTHER, groups: &[] }, 1), Ok(false));
    let AclState::Present(acl) = sd.dacl else { panic!("missing DACL") };
    assert_eq!(acl.ace_count(), 2);
    for ace in acl.aces() {
        assert_eq!(ace.flags(), 0x10);
        assert_eq!(ace.basic_access().unwrap().sid.raw(), OWNER);
    }
}
#[test]
fn inherited_generic_rights_are_concrete_only_on_effective_aces() {
    let p = parent(&[(0, 3, 0x1000_0000, OWNER)]);
    let mut out = [0; 512];
    let n = file_descriptor(&p, &OWNER, &GROUP, 0o600, &mut out).unwrap();
    let sd = SecurityDescriptor::parse(&out[..n]).unwrap();
    let AclState::Present(acl) = sd.dacl else { panic!("missing DACL") };
    let ace = acl.aces().next().unwrap();
    assert_eq!(ace.basic_access().unwrap().mask, super::super::security::FILE_ALL_ACCESS);
    assert_eq!(ace.flags(), INHERITED);
    let n = descriptor(&p, &OWNER, &GROUP, 0o700, true, &mut out).unwrap();
    let sd = SecurityDescriptor::parse(&out[..n]).unwrap();
    let AclState::Present(acl) = sd.dacl else { panic!("missing DACL") };
    let aces: std::vec::Vec<_> = acl.aces().collect();
    assert_eq!(aces.len(), 2);
    assert_eq!(aces[0].basic_access().unwrap().mask, super::super::security::FILE_ALL_ACCESS);
    assert_eq!(aces[0].flags(), INHERITED);
    assert_eq!(aces[1].basic_access().unwrap().mask, 0x1000_0000);
    assert_eq!(aces[1].flags(), INHERITED | INHERIT_ONLY | OBJECT_INHERIT | CONTAINER_INHERIT);
}
#[test]
fn default_mode_does_not_grant_other_users_file_data_access() {
    let p = parent(&[]);
    let mut out = [0; 512];
    let n = file_descriptor(&p, &OWNER, &GROUP, 0o640, &mut out).unwrap();
    let sd = SecurityDescriptor::parse(&out[..n]).unwrap();
    for (user, rights, expected) in
        [(&OWNER, 3, true), (&GROUP, 1, true), (&GROUP, 2, false), (&OTHER, 1, false), (&OWNER, 0x20, false)]
    {
        assert_eq!(sd.check_file_access(&FileAccessToken { user, groups: &[] }, rights), Ok(expected));
    }
}
#[test]
fn refuses_unknown_inheritable_policy_sacl_and_small_output() {
    let p = parent(&[(0x11, 1, 1, OWNER)]);
    assert_eq!(file_descriptor(&p, &OWNER, &GROUP, 0o600, &mut [0; 512]), Err(Error::Unsupported));
    let mut p = parent(&[(0, 1, 1, OWNER)]);
    p[2..4].copy_from_slice(&0x8014u16.to_le_bytes());
    p[12..16].copy_from_slice(&20u32.to_le_bytes());
    assert_eq!(file_descriptor(&p, &OWNER, &GROUP, 0o600, &mut [0; 512]), Err(Error::Unsupported));
    assert_eq!(file_descriptor(&parent(&[]), &OWNER, &GROUP, 0o600, &mut [0; 32]), Err(Error::NoSpace));
}

#[test]
fn recovery_defaults_grant_only_system_and_administrators() {
    use super::super::security::{ADMINISTRATORS_SID, FILE_ALL_ACCESS, SYSTEM_SID};
    let mut output = [0; RECOVERY_DESCRIPTOR_BYTES];
    let length = recovery_descriptor(&mut output).unwrap();
    assert_eq!(length, RECOVERY_DESCRIPTOR_BYTES);
    let descriptor = SecurityDescriptor::parse(&output).unwrap();
    assert_eq!(descriptor.owner.unwrap().raw(), SYSTEM_SID);
    assert_eq!(descriptor.group.unwrap().raw(), ADMINISTRATORS_SID);
    for (sid, expected) in
        [(SYSTEM_SID.as_slice(), true), (ADMINISTRATORS_SID.as_slice(), true), (OTHER.as_slice(), false)]
    {
        let token = FileAccessToken { user: sid, groups: &[] };
        assert_eq!(descriptor.check_file_access(&token, FILE_ALL_ACCESS).unwrap(), expected);
    }
    let AclState::Present(acl) = descriptor.dacl else { panic!("missing recovery DACL") };
    assert_eq!(acl.aces().count(), 2);
    assert!(matches!(descriptor.sacl, AclState::Absent));
    assert_eq!(recovery_descriptor(&mut output[..RECOVERY_DESCRIPTOR_BYTES - 1]), Err(Error::NoSpace));
}
