//! Module: ntfs_rs::security_create
//! Purpose: Encode inherited permissions and restricted recovery defaults.
//! Created: 2026-10-01
//! Architecture: Writers and offline repair share these encoders; journal and
//! family publication remain the callers' responsibility.

//! Native descriptor inheritance for new files and directories.
//! Unknown inheritable policy is refused, never silently discarded.
use super::security::{AclState, SecurityDescriptor};
use super::{Error, Result};

const ACL_HEADER_BYTES: usize = 8;
const ACE_TYPE_OFFSET: usize = 0;
const ACE_FLAGS_OFFSET: usize = ACE_TYPE_OFFSET + 1;
const ACE_LENGTH_OFFSET: usize = ACE_FLAGS_OFFSET + 1;
const ACE_MASK_OFFSET: usize = ACE_LENGTH_OFFSET + core::mem::size_of::<u16>();
const ACE_HEADER_BYTES: usize = ACE_MASK_OFFSET + core::mem::size_of::<u32>();
const ACL_SIZE_OFFSET: usize = 2;
const ACL_COUNT_OFFSET: usize = ACL_SIZE_OFFSET + core::mem::size_of::<u16>();
const ACL_REVISION: u8 = 2;
const ACCESS_ALLOWED_ACE: u8 = 0;
pub const RECOVERY_DESCRIPTOR_BYTES: usize = super::security::DESCRIPTOR_HEADER_BYTES
    + ACL_HEADER_BYTES
    + ACE_HEADER_BYTES * 2
    + (super::security::SYSTEM_SID.len() + super::security::ADMINISTRATORS_SID.len()) * 2;

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
        let len = ACE_HEADER_BYTES + sid.len();
        if self.cursor + len > self.out.len() || len > u16::MAX as usize {
            return Err(Error::NoSpace);
        }
        let at = self.cursor;
        self.out[at + ACE_TYPE_OFFSET] = kind;
        self.out[at + ACE_FLAGS_OFFSET] = flags;
        self.out[at + ACE_LENGTH_OFFSET..at + ACE_MASK_OFFSET].copy_from_slice(&(len as u16).to_le_bytes());
        self.out[at + ACE_MASK_OFFSET..at + ACE_HEADER_BYTES].copy_from_slice(&mask.to_le_bytes());
        self.out[at + ACE_HEADER_BYTES..at + len].copy_from_slice(sid);
        self.cursor += len;
        self.count += 1;
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        let size = self.cursor - self.start;
        if size > u16::MAX as usize {
            return Err(Error::NoSpace);
        }
        self.out[self.start] = ACL_REVISION;
        self.out[self.start + ACL_SIZE_OFFSET..self.start + ACL_COUNT_OFFSET]
            .copy_from_slice(&(size as u16).to_le_bytes());
        self.out[self.start + ACL_COUNT_OFFSET..self.start + ACL_COUNT_OFFSET + core::mem::size_of::<u16>()]
            .copy_from_slice(&self.count.to_le_bytes());
        Ok(())
    }
}

/// Restricted replacement for irretrievably invalid permission metadata.
/// Only SYSTEM and Administrators receive access; intact policy is never replaced.
pub fn recovery_descriptor(output: &mut [u8]) -> Result<usize> {
    use super::bytes::{p16, p32};
    use super::security::{
        descriptor_layout as layout, ADMINISTRATORS_SID, DACL_PRESENT, DESCRIPTOR_HEADER_BYTES, FILE_ALL_ACCESS,
        SELF_RELATIVE, SYSTEM_SID,
    };
    let output = output.get_mut(..RECOVERY_DESCRIPTOR_BYTES).ok_or(Error::NoSpace)?;
    output.fill(0);
    output[layout::REVISION_OFFSET] = layout::REVISION;
    p16(output, layout::CONTROL_OFFSET, SELF_RELATIVE | DACL_PRESENT)?;
    p32(output, layout::DACL_OFFSET, DESCRIPTOR_HEADER_BYTES as u32)?;
    let mut acl = AclWriter {
        out: output,
        start: DESCRIPTOR_HEADER_BYTES,
        cursor: DESCRIPTOR_HEADER_BYTES + ACL_HEADER_BYTES,
        count: 0,
    };
    for sid in [SYSTEM_SID.as_slice(), ADMINISTRATORS_SID.as_slice()] {
        acl.push(ACCESS_ALLOWED_ACE, 0, FILE_ALL_ACCESS, sid)?;
    }
    acl.finish()?;
    let owner_at = acl.cursor;
    let group_at = owner_at + SYSTEM_SID.len();
    output[owner_at..group_at].copy_from_slice(&SYSTEM_SID);
    output[group_at..].copy_from_slice(&ADMINISTRATORS_SID);
    p32(output, layout::OWNER_OFFSET, owner_at as u32)?;
    p32(output, layout::GROUP_OFFSET, group_at as u32)?;
    SecurityDescriptor::parse(output)?;
    Ok(output.len())
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
    let mut w = AclWriter { out: &mut *out, start: sacl_at, cursor: sacl_at + ACL_HEADER_BYTES, count: 0 };
    let acl = if inherit(parent.sacl, true, directory, owner, group, &mut w)? {
        w.finish()?;
        control |= 0x0010 | 0x0800; // SACL present, auto-inherited
        let end = w.cursor;
        out[12..16].copy_from_slice(&(sacl_at as u32).to_le_bytes());
        end
    } else {
        out[sacl_at..sacl_at + ACL_HEADER_BYTES].fill(0);
        sacl_at
    };
    out[16..20].copy_from_slice(&(acl as u32).to_le_bytes());
    let mut w = AclWriter { out: &mut *out, start: acl, cursor: acl + ACL_HEADER_BYTES, count: 0 };
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
#[path = "../tests/core/security_create.rs"]
mod tests;
