//! Module: ntfs_rs::security_create
//! Purpose: Native descriptor inheritance for new files and directories.
//! Created: 2026-10-01
//! Architecture: These operations edit Tx images that the shared journal publishes atomically.

//! Native descriptor inheritance for new files and directories.
//! Unknown inheritable policy is refused, never silently discarded.
use super::security::{AclState, SecurityDescriptor};
use super::{Error, Result};

const OBJECT_INHERIT: u8 = 0x01;
const CONTAINER_INHERIT: u8 = 0x02;
const NO_PROPAGATE: u8 = 0x04;
const INHERIT_ONLY: u8 = 0x08;
const INHERITED: u8 = 0x10;
const CREATOR_OWNER: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0];
const CREATOR_GROUP: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 3, 1, 0, 0, 0];

pub fn file_descriptor(parent: &[u8], owner: &[u8], group: &[u8], mode: u16, out: &mut [u8]) -> Result<usize> {
    descriptor(parent, owner, group, mode, false, out)
}

/// ACE layouts whose SID follows the mask at offset 8: allow, deny, audit,
/// alarm and mandatory label. Other inheritable ACE layouts are refused.
fn basic_layout(kind: u8, sacl: bool) -> bool {
    if sacl {
        matches!(kind, 2 | 3 | 0x11)
    } else {
        matches!(kind, 0 | 1)
    }
}

struct AclWriter<'a> {
    out: &'a mut [u8],
    start: usize,
    cursor: usize,
    count: u16,
}

impl AclWriter<'_> {
    fn push(&mut self, kind: u8, flags: u8, mask: u32, sid: &[u8]) -> Result<()> {
        let len = 8 + sid.len();
        if self.cursor + len > self.out.len() || len > u16::MAX as usize {
            return Err(Error::NoSpace);
        }
        let at = self.cursor;
        self.out[at] = kind;
        self.out[at + 1] = flags;
        self.out[at + 2..at + 4].copy_from_slice(&(len as u16).to_le_bytes());
        self.out[at + 4..at + 8].copy_from_slice(&mask.to_le_bytes());
        self.out[at + 8..at + len].copy_from_slice(sid);
        self.cursor += len;
        self.count += 1;
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        let size = self.cursor - self.start;
        if size > u16::MAX as usize {
            return Err(Error::NoSpace);
        }
        self.out[self.start] = 2;
        self.out[self.start + 2..self.start + 4].copy_from_slice(&(size as u16).to_le_bytes());
        self.out[self.start + 4..self.start + 6].copy_from_slice(&self.count.to_le_bytes());
        Ok(())
    }
}

/// Apply Windows inheritance rules for one parent ACL. Returns false when
/// nothing was inherited.
fn inherit(
    acl: AclState<'_>,
    sacl: bool,
    directory: bool,
    owner: &[u8],
    group: &[u8],
    w: &mut AclWriter<'_>,
) -> Result<bool> {
    let AclState::Present(acl) = acl else {
        return Ok(false);
    };
    let before = w.count;
    for ace in acl.aces() {
        let flags = ace.flags();
        let applies =
            if directory { flags & (OBJECT_INHERIT | CONTAINER_INHERIT) != 0 } else { flags & OBJECT_INHERIT != 0 };
        if !applies {
            continue;
        }
        if !basic_layout(ace.kind(), sacl) || ace.raw().len() < 16 {
            return Err(Error::Unsupported);
        }
        let raw = ace.raw();
        let mask = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
        let effective = if ace.kind() <= 3 { super::security::map_file_generic_rights(mask)? } else { mask }; // Mandatory-label masks are not file access rights.
        let sid = &raw[8..];
        let resolved = if sid == CREATOR_OWNER {
            owner
        } else if sid == CREATOR_GROUP {
            group
        } else {
            sid
        };
        let audit = flags & 0xc0; // SUCCESSFUL/FAILED_ACCESS audit flags
        if !directory {
            w.push(ace.kind(), INHERITED | audit, effective, resolved)?;
            continue;
        }
        let container = flags & CONTAINER_INHERIT != 0;
        let propagate = flags & NO_PROPAGATE == 0;
        if container {
            if resolved.as_ptr() != sid.as_ptr() || effective != mask {
                // Map generic rights/SIDs for the child. Preserve the original
                // inherit-only template for the next generation.
                w.push(ace.kind(), INHERITED | audit, effective, resolved)?;
                if propagate {
                    w.push(
                        ace.kind(),
                        (flags & (OBJECT_INHERIT | CONTAINER_INHERIT)) | INHERIT_ONLY | INHERITED | audit,
                        mask,
                        sid,
                    )?;
                }
            } else {
                let keep = if propagate { flags & (OBJECT_INHERIT | CONTAINER_INHERIT) } else { 0 };
                w.push(ace.kind(), keep | INHERITED | audit, mask, sid)?;
            }
        } else if propagate {
            // Object-inherit only: not effective on the directory itself.
            w.push(ace.kind(), OBJECT_INHERIT | INHERIT_ONLY | INHERITED | audit, mask, sid)?;
        }
    }
    Ok(w.count != before)
}

/// Build a new object's self-relative descriptor: owner, group, inherited
/// SACL (audit and mandatory-label ACEs) and inherited DACL, or a DACL
/// derived from the Linux creation mode when nothing is inheritable.
pub fn descriptor(
    parent: &[u8],
    owner: &[u8],
    group: &[u8],
    mode: u16,
    directory: bool,
    out: &mut [u8],
) -> Result<usize> {
    let parent = SecurityDescriptor::parse(parent)?;
    if out.len() < 20 + owner.len() + group.len() + 16 {
        return Err(Error::NoSpace);
    }
    out.fill(0);
    out[0] = 1;
    out[4..8].copy_from_slice(&20u32.to_le_bytes());
    out[20..20 + owner.len()].copy_from_slice(owner);
    let group_at = 20 + owner.len();
    out[8..12].copy_from_slice(&(group_at as u32).to_le_bytes());
    out[group_at..group_at + group.len()].copy_from_slice(group);
    let mut control: u16 = 0x8004;
    let sacl_at = group_at + group.len();
    let mut w = AclWriter { out: &mut *out, start: sacl_at, cursor: sacl_at + 8, count: 0 };
    let acl = if inherit(parent.sacl, true, directory, owner, group, &mut w)? {
        w.finish()?;
        control |= 0x0010 | 0x0800; // SACL present, auto-inherited
        let end = w.cursor;
        out[12..16].copy_from_slice(&(sacl_at as u32).to_le_bytes());
        end
    } else {
        out[sacl_at..sacl_at + 8].fill(0);
        sacl_at
    };
    out[16..20].copy_from_slice(&(acl as u32).to_le_bytes());
    let mut w = AclWriter { out: &mut *out, start: acl, cursor: acl + 8, count: 0 };
    if inherit(parent.dacl, false, directory, owner, group, &mut w)? {
        control |= 0x0400; // DACL auto-inherited
    } else {
        // Without inherited ACEs, derive the creator's default DACL from the
        // VFS mode. This is only a creation policy, never a lossy ACL rewrite.
        for (sid, bits, owner_rights) in [
            (owner, (mode >> 6) & 7, 0x60000u32),
            (group, (mode >> 3) & 7, 0),
            (&[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0][..], mode & 7, 0),
        ] {
            let mut rights = owner_rights | 0x100080;
            if bits & 4 != 0 {
                rights |= 1;
            }
            if bits & 2 != 0 {
                rights |= 0x116;
                if directory {
                    rights |= 0x40; // FILE_DELETE_CHILD
                }
            }
            if bits & 1 != 0 {
                rights |= 0x20;
            }
            w.push(0, 0, rights, sid)?;
        }
    }
    w.finish()?;
    let end = w.cursor;
    out[2..4].copy_from_slice(&control.to_le_bytes());
    SecurityDescriptor::parse(&out[..end])?;
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::super::security::FileAccessToken;
    use super::*;
    const OWNER: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    const GROUP: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 19, 0, 0, 0];
    const OTHER: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 20, 0, 0, 0];
    const CREATOR: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0];
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
}
