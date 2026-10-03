//! Module: ntfs_rs::security
//! Purpose: Provide a checked, lossless self-relative security-descriptor view.
//! Created: 2026-10-01
//! Architecture: Readers, writers and offline tools share framing; authorization is separate.
//! Unknown ACE types remain opaque and unchanged until understood.

use super::bytes::{range, u16_at, u32_at, u64_at};
use super::{Error, Result};

const SELF_RELATIVE: u16 = 0x8000;
const DACL_PRESENT: u16 = 0x0004;
const SACL_PRESENT: u16 = 0x0010;
const SDS_HEADER_BYTES: usize = 20;
const SDS_MAX_DESCRIPTOR_BYTES: usize = 0x20000;

/// Fixed revision/count/identifier-authority header of a binary Windows SID.
pub const SID_HEADER_BYTES: usize = 8;
/// Each binary SID subauthority is a little-endian 32-bit value.
pub const SID_SUBAUTHORITY_BYTES: usize = 4;
/// Maximum count representable by the supported Windows SID format.
pub const MAX_SID_SUBAUTHORITIES: u8 = 15;
/// Maximum binary SID length, excluding any container padding.
pub const MAX_SID_BYTES: usize = SID_HEADER_BYTES + MAX_SID_SUBAUTHORITIES as usize * SID_SUBAUTHORITY_BYTES;

/// Concrete file/directory rights, including DELETE, READ_CONTROL,
/// WRITE_DAC, WRITE_OWNER and SYNCHRONIZE. Privilege-only rights and
/// MAXIMUM_ALLOWED require a richer authorization context.
pub const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
/// Mandatory integrity levels (the RID of S-1-16-*).
pub const INTEGRITY_UNTRUSTED: u32 = 0;
pub const INTEGRITY_LOW: u32 = 0x1000;
pub const INTEGRITY_MEDIUM: u32 = 0x2000;
pub const INTEGRITY_HIGH: u32 = 0x3000;
pub const INTEGRITY_SYSTEM: u32 = 0x4000;
const LABEL_NO_WRITE_UP: u32 = 1;
const LABEL_NO_READ_UP: u32 = 2;
const LABEL_NO_EXECUTE_UP: u32 = 4;
const OWNER_RIGHTS: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];

#[derive(Clone, Copy, Debug)]
pub struct TokenSid<'a> {
    pub sid: &'a [u8],
    /// A deny-only group participates in deny ACEs, never allow ACEs.
    pub deny_only: bool,
}

/// Caller-resolved Windows identity. No UID->SID guessing is performed.
/// This represents an unrestricted token without privilege overrides;
/// restricted tokens and mandatory integrity checks are not implemented.
pub struct FileAccessToken<'a> {
    pub user: &'a [u8],
    pub groups: &'a [TokenSid<'a>],
}

pub fn map_file_generic_rights(mask: u32) -> Result<u32> {
    let mut concrete = mask & !0xf000_0000;
    for (generic, specific) in [
        (0x8000_0000, 0x0012_0089),
        (0x4000_0000, 0x0012_0116),
        (0x2000_0000, 0x0012_00a0),
        (0x1000_0000, FILE_ALL_ACCESS),
    ] {
        if mask & generic != 0 {
            concrete |= specific;
        }
    }
    if concrete & !FILE_ALL_ACCESS != 0 {
        return Err(Error::Unsupported);
    }
    Ok(concrete)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sid<'a> {
    raw: &'a [u8],
}

impl<'a> Sid<'a> {
    fn parse(data: &'a [u8], offset: usize) -> Result<Self> {
        let header = range(data, offset, SID_HEADER_BYTES).map_err(|_| Error::InvalidSecurity)?;
        if header[0] != 1 || header[1] > MAX_SID_SUBAUTHORITIES {
            return Err(Error::InvalidSecurity);
        }
        let length =
            SID_HEADER_BYTES.checked_add(usize::from(header[1]) * SID_SUBAUTHORITY_BYTES).ok_or(Error::Overflow)?;
        let raw = range(data, offset, length).map_err(|_| Error::InvalidSecurity)?;
        Ok(Self { raw })
    }

    pub fn raw(self) -> &'a [u8] {
        self.raw
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ace<'a> {
    raw: &'a [u8],
}

impl<'a> Ace<'a> {
    pub fn kind(self) -> u8 {
        self.raw[0]
    }
    pub fn flags(self) -> u8 {
        self.raw[1]
    }
    pub fn raw(self) -> &'a [u8] {
        self.raw
    }

    /// Basic allow/deny ACEs only. Object, callback, audit, and unknown ACEs
    /// stay opaque; callers must not infer that access is allowed from them.
    pub fn basic_access(self) -> Option<BasicAccess<'a>> {
        if !matches!(self.kind(), 0 | 1) {
            return None;
        }
        let mask = u32_at(self.raw, 4).ok()?;
        let sid = Sid::parse(self.raw, 8).ok()?;
        Some(BasicAccess { allow: self.kind() == 0, mask, sid })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BasicAccess<'a> {
    pub allow: bool,
    pub mask: u32,
    pub sid: Sid<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Acl<'a> {
    raw: &'a [u8],
    ace_count: u16,
}

impl<'a> Acl<'a> {
    fn parse(data: &'a [u8], offset: usize) -> Result<Self> {
        let header = range(data, offset, 8).map_err(|_| Error::InvalidSecurity)?;
        if !matches!(header[0], 2 | 4) {
            return Err(Error::InvalidSecurity);
        }
        let length = usize::from(u16_at(header, 2).map_err(|_| Error::InvalidSecurity)?);
        if length < 8 || length % 4 != 0 {
            return Err(Error::InvalidSecurity);
        }
        let raw = range(data, offset, length).map_err(|_| Error::InvalidSecurity)?;
        let ace_count = u16_at(header, 4).map_err(|_| Error::InvalidSecurity)?;
        let mut cursor = 8_usize;
        for _ in 0..ace_count {
            let ace = range(raw, cursor, 4).map_err(|_| Error::InvalidSecurity)?;
            let ace_len = usize::from(u16_at(ace, 2).map_err(|_| Error::InvalidSecurity)?);
            if ace_len < 4 || ace_len % 4 != 0 {
                return Err(Error::InvalidSecurity);
            }
            let bytes = range(raw, cursor, ace_len).map_err(|_| Error::InvalidSecurity)?;
            if matches!(bytes[0], 0 | 1) {
                if ace_len < 16 || Sid::parse(bytes, 8)?.raw().len() > ace_len - 8 {
                    return Err(Error::InvalidSecurity);
                }
            }
            cursor = cursor.checked_add(ace_len).ok_or(Error::Overflow)?;
        }
        Ok(Self { raw, ace_count })
    }

    pub fn raw(self) -> &'a [u8] {
        self.raw
    }
    pub fn ace_count(self) -> u16 {
        self.ace_count
    }
    pub fn aces(self) -> AceIter<'a> {
        AceIter { raw: self.raw, cursor: 8, remaining: self.ace_count }
    }
}

pub struct AceIter<'a> {
    raw: &'a [u8],
    cursor: usize,
    remaining: u16,
}

impl<'a> Iterator for AceIter<'a> {
    type Item = Ace<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        // Acl::parse validated every ACE boundary before creating this iterator.
        let length = usize::from(u16_at(self.raw, self.cursor + 2).ok()?);
        let raw = range(self.raw, self.cursor, length).ok()?;
        self.cursor += length;
        self.remaining -= 1;
        Some(Ace { raw })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AclState<'a> {
    Absent,
    Null,
    Present(Acl<'a>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityDescriptor<'a> {
    raw: &'a [u8],
    pub control: u16,
    pub owner: Option<Sid<'a>>,
    pub group: Option<Sid<'a>>,
    pub sacl: AclState<'a>,
    pub dacl: AclState<'a>,
}

impl<'a> SecurityDescriptor<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        let header = range(raw, 0, 20).map_err(|_| Error::InvalidSecurity)?;
        let control = u16_at(header, 2).map_err(|_| Error::InvalidSecurity)?;
        if header[0] != 1 || control & SELF_RELATIVE == 0 {
            return Err(Error::InvalidSecurity);
        }
        let owner = sid_at(raw, u32_at(header, 4).map_err(|_| Error::InvalidSecurity)?)?;
        let group = sid_at(raw, u32_at(header, 8).map_err(|_| Error::InvalidSecurity)?)?;
        let sacl = acl_at(raw, control & SACL_PRESENT != 0, u32_at(header, 12).map_err(|_| Error::InvalidSecurity)?)?;
        let dacl = acl_at(raw, control & DACL_PRESENT != 0, u32_at(header, 16).map_err(|_| Error::InvalidSecurity)?)?;
        Ok(Self { raw, control, owner, group, sacl, dacl })
    }

    pub fn raw(self) -> &'a [u8] {
        self.raw
    }

    /// Ordered discretionary check for ordinary allow/deny file ACEs, for a
    /// medium-integrity token. See check_file_access_at.
    pub fn check_file_access(self, token: &FileAccessToken<'_>, requested: u32) -> Result<bool> {
        self.check_file_access_at(token, INTEGRITY_MEDIUM, requested)
    }

    /// Ordered discretionary check for ordinary allow/deny file ACEs.
    /// Preserves the on-disk ACE order, maps generic rights, respects
    /// deny-only groups and OWNER RIGHTS overrides.
    ///
    /// The SACL is evaluated for access-affecting policy: the mandatory
    /// integrity label (no-write-up/no-read-up/no-execute-up against the
    /// token's integrity RID; unlabeled objects are medium/no-write-up) and
    /// process trust labels (Linux callers are untrusted). Audit and alarm
    /// ACEs do not affect access and are not reported. Resource attributes
    /// only matter to conditional ACEs, which remain unsupported. Scoped
    /// policy, access filters and unknown SACL or DACL ACEs fail closed.
    pub fn check_file_access_at(self, token: &FileAccessToken<'_>, integrity: u32, requested: u32) -> Result<bool> {
        if Sid::parse(token.user, 0)?.raw() != token.user {
            return Err(Error::InvalidSecurity);
        }
        for group in token.groups {
            if Sid::parse(group.sid, 0)?.raw() != group.sid {
                return Err(Error::InvalidSecurity);
            }
        }
        let mut remaining = map_file_generic_rights(requested)?;
        if remaining == 0 {
            return Ok(true);
        }
        let mut label = None;
        let mut trust = None;
        if let AclState::Present(sacl) = self.sacl {
            for ace in sacl.aces() {
                if ace.flags() & 8 != 0 {
                    continue;
                }
                match ace.kind() {
                    // Audit, alarm and their object/callback forms.
                    2 | 3 | 7 | 8 | 0xd | 0xe | 0xf | 0x10 => {}
                    // Resource attributes are claims for conditional ACEs.
                    0x12 => {}
                    0x11 => {
                        let raw = ace.raw();
                        let mask = u32_at(raw, 4).map_err(|_| Error::InvalidSecurity)?;
                        let sid = Sid::parse(raw, 8)?.raw();
                        // S-1-16-<level>: authority 16, one subauthority.
                        if sid.len() != 12 || sid[1] != 1 || sid[2..8] != [0, 0, 0, 0, 0, 16] {
                            return Err(Error::InvalidSecurity);
                        }
                        // The first label ACE is authoritative, as in Windows.
                        if label.is_none() {
                            label = Some((u32_at(sid, 8)?, mask & 7));
                        }
                    }
                    0x14 => {
                        let mask = u32_at(ace.raw(), 4).map_err(|_| Error::InvalidSecurity)?;
                        trust = Some(trust.unwrap_or(FILE_ALL_ACCESS) & map_file_generic_rights(mask)?);
                    }
                    _ => return Err(Error::Unsupported),
                }
            }
        }
        let (level, policy) = label.unwrap_or((INTEGRITY_MEDIUM, LABEL_NO_WRITE_UP));
        if integrity < level {
            let mut denied = 0;
            if policy & LABEL_NO_WRITE_UP != 0 {
                denied |= 0x116 | 0x40 | 0x0001_0000 | WRITE_DAC | WRITE_OWNER;
            }
            if policy & LABEL_NO_READ_UP != 0 {
                denied |= 0x9;
            }
            if policy & LABEL_NO_EXECUTE_UP != 0 {
                denied |= 0x20;
            }
            if remaining & denied != 0 {
                return Ok(false);
            }
        }
        if let Some(allowed) = trust {
            if remaining & !allowed & !(READ_CONTROL | 0x0010_0000) != 0 {
                return Ok(false);
            }
        }
        let dacl = match self.dacl {
            AclState::Null | AclState::Absent => return Ok(true),
            AclState::Present(dacl) => dacl,
        };
        let owner = self.owner.is_some_and(|sid| sid.raw() == token.user);
        let mut owner_override = false;
        // Validate the supported policy before any early allow result.
        for ace in dacl.aces() {
            if ace.flags() & 8 != 0 {
                continue;
            }
            if ace.flags() & !0x1f != 0 {
                return Err(Error::Unsupported);
            }
            let access = ace.basic_access().ok_or(Error::Unsupported)?;
            if ace.raw().len() != 8 + access.sid.raw().len() {
                return Err(Error::InvalidSecurity);
            }
            map_file_generic_rights(access.mask)?;
            owner_override |= access.sid.raw() == OWNER_RIGHTS;
        }
        if owner && !owner_override {
            remaining &= !(READ_CONTROL | WRITE_DAC);
        }
        if remaining == 0 {
            return Ok(true);
        }
        for ace in dacl.aces() {
            if ace.flags() & 8 != 0 {
                continue;
            }
            let access = ace.basic_access().ok_or(Error::Unsupported)?;
            let sid = access.sid.raw();
            let matches = if sid == OWNER_RIGHTS {
                owner
            } else {
                sid == token.user
                    || token.groups.iter().any(|group| group.sid == sid && (!access.allow || !group.deny_only))
            };
            if !matches {
                continue;
            }
            let mask = map_file_generic_rights(access.mask)?;
            if access.allow {
                remaining &= !mask;
            } else if remaining & mask != 0 {
                return Ok(false);
            }
            if remaining == 0 {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// One $Secure:$SDS entry, excluding its 16-byte alignment padding.
/// The descriptor and header remain borrowed from the exact on-disk bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SdsEntry<'a> {
    raw: &'a [u8],
    pub hash: u32,
    pub security_id: u32,
    pub offset: u64,
    pub descriptor: SecurityDescriptor<'a>,
}

impl<'a> SdsEntry<'a> {
    /// offset is the entry's absolute byte offset in $Secure:$SDS.
    /// A caller must separately resolve $SII and $SDH and compare their
    /// copied headers with this entry before granting access or modifying it.
    pub fn parse(data: &'a [u8], offset: u64) -> Result<Self> {
        let header = range(data, 0, SDS_HEADER_BYTES).map_err(|_| Error::InvalidSecurity)?;
        let size =
            usize::try_from(u32_at(header, 16).map_err(|_| Error::InvalidSecurity)?).map_err(|_| Error::Overflow)?;
        let descriptor_bytes = size.checked_sub(SDS_HEADER_BYTES).ok_or(Error::InvalidSecurity)?;
        if descriptor_bytes < 20 || descriptor_bytes > SDS_MAX_DESCRIPTOR_BYTES {
            return Err(Error::InvalidSecurity);
        }
        let raw = range(data, 0, size).map_err(|_| Error::InvalidSecurity)?;
        let stored_offset = u64_at(header, 8).map_err(|_| Error::InvalidSecurity)?;
        if stored_offset != offset || offset % 16 != 0 {
            return Err(Error::InvalidSecurity);
        }
        let descriptor_raw = &raw[SDS_HEADER_BYTES..];
        let hash = u32_at(header, 0).map_err(|_| Error::InvalidSecurity)?;
        if hash != security_hash(descriptor_raw) {
            return Err(Error::InvalidSecurity);
        }
        let descriptor = SecurityDescriptor::parse(descriptor_raw)?;
        Ok(Self { raw, hash, security_id: u32_at(header, 4).map_err(|_| Error::InvalidSecurity)?, offset, descriptor })
    }

    pub fn raw(self) -> &'a [u8] {
        self.raw
    }

    /// $SII and $SDH both store a copy of the 20-byte SDS header.
    pub fn matches_index_header(self, header: &[u8]) -> bool {
        header == &self.raw[..SDS_HEADER_BYTES]
    }
}

/// NTFS descriptor hash: rotate the accumulator by three and add each
/// complete little-endian dword. Trailing bytes do not enter the hash.
pub fn security_hash(descriptor: &[u8]) -> u32 {
    let mut hash = 0_u32;
    for word in descriptor.chunks_exact(4) {
        hash = hash.rotate_left(3).wrapping_add(u32::from_le_bytes([word[0], word[1], word[2], word[3]]));
    }
    hash
}

fn checked_offset(offset: u32) -> Result<usize> {
    let offset = usize::try_from(offset).map_err(|_| Error::Overflow)?;
    if offset < 20 || offset % 4 != 0 {
        return Err(Error::InvalidSecurity);
    }
    Ok(offset)
}

fn sid_at<'a>(data: &'a [u8], offset: u32) -> Result<Option<Sid<'a>>> {
    if offset == 0 {
        return Ok(None);
    }
    Ok(Some(Sid::parse(data, checked_offset(offset)?)?))
}

fn acl_at<'a>(data: &'a [u8], present: bool, offset: u32) -> Result<AclState<'a>> {
    if !present {
        return if offset == 0 { Ok(AclState::Absent) } else { Err(Error::InvalidSecurity) };
    }
    if offset == 0 {
        return Ok(AclState::Null);
    }
    Ok(AclState::Present(Acl::parse(data, checked_offset(offset)?)?))
}

/// Required to change the owner or primary group.
pub const WRITE_OWNER: u32 = 0x0008_0000;
const OWNER_GROUP_CONTROL: u16 = 0x0003;
const DACL_CONTROL: u16 = 0x0004 | 0x0008 | 0x0040 | 0x0080 | 0x0100 | 0x0400 | 0x1000;
const SACL_CONTROL: u16 = 0x0010 | 0x0020 | 0x0200 | 0x0800 | 0x2000;
/// Largest descriptor stored in one $Secure:$SDS entry.
pub const MAX_STORED_DESCRIPTOR: usize = SDS_MAX_DESCRIPTOR_BYTES;

fn acl_image<'a>(state: AclState<'a>) -> (u8, &'a [u8]) {
    match state {
        AclState::Absent => (0, &[]),
        AclState::Null => (1, &[]),
        AclState::Present(acl) => (2, acl.raw()),
    }
}

/// Validate a descriptor supplied for storage. It must be self-relative,
/// structurally valid, name an owner and a group, and fit an SDS entry.
pub fn validate_storable(raw: &[u8]) -> Result<SecurityDescriptor<'_>> {
    if raw.len() < 20 || raw.len() > SDS_MAX_DESCRIPTOR_BYTES {
        return Err(Error::InvalidSecurity);
    }
    let sd = SecurityDescriptor::parse(raw)?;
    if sd.owner.is_none() || sd.group.is_none() {
        return Err(Error::InvalidSecurity);
    }
    // Every component must lie within the supplied bytes (checked by parse)
    // and the stored length must not hide unparsed trailing data.
    let mut end = 20;
    for part in [
        sd.owner.map(|s| s.raw()),
        sd.group.map(|s| s.raw()),
        match sd.sacl {
            AclState::Present(a) => Some(a.raw()),
            _ => None,
        },
        match sd.dacl {
            AclState::Present(a) => Some(a.raw()),
            _ => None,
        },
    ]
    .into_iter()
    .flatten()
    {
        let start = part.as_ptr() as usize - raw.as_ptr() as usize;
        end = end.max(start + part.len());
    }
    if (raw.len() + 3) & !3 < end || raw.len() > (end + 3) & !3 {
        return Err(Error::InvalidSecurity);
    }
    Ok(sd)
}

/// Windows rights needed to replace old with new (SetSecurityInfo
/// semantics): WRITE_OWNER for owner/group changes, WRITE_DAC for DACL
/// changes, and ACCESS_SYSTEM_SECURITY for SACL changes. The latter must
/// be checked against an explicit privilege, never against a DACL grant.
pub fn replacement_rights(old: SecurityDescriptor<'_>, new: SecurityDescriptor<'_>) -> Result<u32> {
    if old.raw() == new.raw() {
        return Ok(0);
    }
    let changed = old.control ^ new.control;
    let mut rights = 0;
    if changed & SACL_CONTROL != 0 || acl_image(old.sacl) != acl_image(new.sacl) {
        rights |= ACCESS_SYSTEM_SECURITY;
    }
    if changed & OWNER_GROUP_CONTROL != 0
        || old.owner.map(|s| s.raw()) != new.owner.map(|s| s.raw())
        || old.group.map(|s| s.raw()) != new.group.map(|s| s.raw())
    {
        rights |= WRITE_OWNER;
    }
    // DACL control bits, the resource-manager control flag and byte.
    if changed & (DACL_CONTROL | 0x4000) != 0
        || acl_image(old.dacl) != acl_image(new.dacl)
        || old.raw()[1] != new.raw()[1]
    {
        rights |= WRITE_DAC;
    }
    // Same components in a different self-relative layout: still a write of
    // the discretionary descriptor bytes.
    if rights == 0 {
        rights = WRITE_DAC;
    }
    Ok(rights)
}

/// Rebuild old with a replacement owner and/or group SID, preserving the
/// control word, SACL and DACL bytes exactly. Layout: header, SACL, DACL,
/// owner, group (the Windows self-relative order). Returns the new length.
pub fn replace_owner_group(
    old: SecurityDescriptor<'_>,
    owner: Option<&[u8]>,
    group: Option<&[u8]>,
    out: &mut [u8],
) -> Result<usize> {
    let owner = owner.or(old.owner.map(|s| s.raw()));
    let group = group.or(old.group.map(|s| s.raw()));
    for sid in [owner, group].into_iter().flatten() {
        if Sid::parse(sid, 0)?.raw() != sid {
            return Err(Error::InvalidSecurity);
        }
    }
    let mut at = 20;
    let header = old.raw().get(..4).ok_or(Error::InvalidSecurity)?;
    let mut offsets = [0_u32; 4];
    let parts = [
        match old.sacl {
            AclState::Present(a) => Some(a.raw()),
            _ => None,
        },
        match old.dacl {
            AclState::Present(a) => Some(a.raw()),
            _ => None,
        },
        owner,
        group,
    ];
    let total = 20 + parts.iter().flatten().map(|p| (p.len() + 3) & !3).sum::<usize>();
    let out = out.get_mut(..total).ok_or(Error::Truncated)?;
    out.fill(0);
    out[..4].copy_from_slice(header);
    for (i, part) in parts.iter().enumerate() {
        if let Some(part) = part {
            offsets[i] = at as u32;
            out[at..at + part.len()].copy_from_slice(part);
            at += (part.len() + 3) & !3;
        }
    }
    out[4..8].copy_from_slice(&offsets[2].to_le_bytes());
    out[8..12].copy_from_slice(&offsets[3].to_le_bytes());
    out[12..16].copy_from_slice(&offsets[0].to_le_bytes());
    out[16..20].copy_from_slice(&offsets[1].to_le_bytes());
    validate_storable(out)?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> [u8; 60] {
        let mut raw = [0_u8; 60];
        raw[0] = 1;
        raw[2..4].copy_from_slice(&(SELF_RELATIVE | DACL_PRESENT).to_le_bytes());
        raw[4..8].copy_from_slice(&20_u32.to_le_bytes());
        raw[8..12].copy_from_slice(&20_u32.to_le_bytes());
        raw[16..20].copy_from_slice(&32_u32.to_le_bytes());
        raw[20] = 1;
        raw[21] = 1;
        raw[27] = 5;
        raw[28..32].copy_from_slice(&18_u32.to_le_bytes());
        raw[32] = 2;
        raw[34..36].copy_from_slice(&28_u16.to_le_bytes());
        raw[36..38].copy_from_slice(&1_u16.to_le_bytes());
        raw[40] = 1; // deny ACE
        raw[42..44].copy_from_slice(&20_u16.to_le_bytes());
        raw[44..48].copy_from_slice(&0x0000_0002_u32.to_le_bytes());
        raw[48] = 1;
        raw[49] = 1;
        raw[55] = 5;
        raw[56..60].copy_from_slice(&21_u32.to_le_bytes());
        raw
    }

    #[test]
    fn parses_and_preserves_deny_ace() {
        let raw = descriptor();
        let sd = SecurityDescriptor::parse(&raw).unwrap();
        assert_eq!(sd.raw(), &raw);
        let AclState::Present(dacl) = sd.dacl else { panic!("DACL missing") };
        assert_eq!(dacl.ace_count(), 1);
        let ace = dacl.aces().next().unwrap();
        let access = ace.basic_access().unwrap();
        assert!(!access.allow);
        assert_eq!(access.mask, 2);
        assert_eq!(access.sid.raw(), &raw[48..60]);
    }

    #[test]
    fn standard_rights_generic_mapping_and_owner_override() {
        let mut raw = descriptor();
        let owner = raw[20..32].to_vec();
        let token = FileAccessToken { user: &owner, groups: &[] };
        assert_eq!(
            SecurityDescriptor::parse(&raw).unwrap().check_file_access(&token, WRITE_DAC | READ_CONTROL),
            Ok(true)
        );
        // An explicit OWNER RIGHTS deny removes implicit WRITE_DAC.
        raw[48..60].copy_from_slice(&OWNER_RIGHTS);
        raw[44..48].copy_from_slice(&WRITE_DAC.to_le_bytes());
        assert_eq!(SecurityDescriptor::parse(&raw).unwrap().check_file_access(&token, WRITE_DAC), Ok(false));
        raw[40] = 0;
        raw[44..48].copy_from_slice(&0x4000_0000_u32.to_le_bytes());
        assert_eq!(SecurityDescriptor::parse(&raw).unwrap().check_file_access(&token, 2), Ok(true));
        assert_eq!(SecurityDescriptor::parse(&raw).unwrap().check_file_access(&token, 1), Ok(false));
        assert_eq!(map_file_generic_rights(0x1000_0000), Ok(FILE_ALL_ACCESS));
        assert_eq!(map_file_generic_rights(0x0200_0000), Err(Error::Unsupported));
    }

    #[test]
    fn deny_only_groups_never_supply_allow_rights() {
        let mut raw = descriptor();
        let user = raw[20..32].to_vec();
        let group = raw[48..60].to_vec();
        let groups = [TokenSid { sid: &group, deny_only: true }];
        let token = FileAccessToken { user: &user, groups: &groups };
        assert_eq!(SecurityDescriptor::parse(&raw).unwrap().check_file_access(&token, 2), Ok(false));
        raw[40] = 0;
        assert_eq!(SecurityDescriptor::parse(&raw).unwrap().check_file_access(&token, 2), Ok(false));
        let groups = [TokenSid { sid: &group, deny_only: false }];
        assert_eq!(
            SecurityDescriptor::parse(&raw)
                .unwrap()
                .check_file_access(&FileAccessToken { user: &user, groups: &groups }, 2),
            Ok(true)
        );
        raw[41] = 8;
        assert_eq!(
            SecurityDescriptor::parse(&raw)
                .unwrap()
                .check_file_access(&FileAccessToken { user: &user, groups: &groups }, 2),
            Ok(false)
        );
    }

    #[test]
    fn access_check_keeps_ace_order_and_refuses_unknown_policy() {
        let mut raw = descriptor().to_vec();
        let user = raw[48..60].to_vec();
        let first = raw[40..60].to_vec();
        raw.extend_from_slice(&first);
        raw[34..36].copy_from_slice(&48_u16.to_le_bytes());
        raw[36..38].copy_from_slice(&2_u16.to_le_bytes());
        raw[40] = 0; // Allow first; later deny does not revoke granted bits.
        let token = FileAccessToken { user: &user, groups: &[] };
        assert_eq!(SecurityDescriptor::parse(&raw).unwrap().check_file_access(&token, 2), Ok(true));
        raw[40] = 1;
        raw[60] = 0;
        assert_eq!(SecurityDescriptor::parse(&raw).unwrap().check_file_access(&token, 2), Ok(false));
        raw[40] = 0;
        raw[60] = 0x11;
        for first_kind in [0, 1] {
            raw[40] = first_kind;
            assert_eq!(SecurityDescriptor::parse(&raw).unwrap().check_file_access(&token, 2), Err(Error::Unsupported));
        }
        // Even a conclusive deny must validate a trailing unsupported mask.
        raw[60] = 0;
        raw[64..68].copy_from_slice(&0x0200_0000_u32.to_le_bytes());
        assert_eq!(SecurityDescriptor::parse(&raw).unwrap().check_file_access(&token, 2), Err(Error::Unsupported));
    }

    #[test]
    fn trailing_owner_rights_override_and_inherit_only_policy() {
        let mut raw = descriptor().to_vec();
        let user = raw[20..32].to_vec();
        let first = raw[40..60].to_vec();
        raw.extend_from_slice(&first);
        raw[34..36].copy_from_slice(&48_u16.to_le_bytes());
        raw[36..38].copy_from_slice(&2_u16.to_le_bytes());
        raw[40] = 0;
        raw[44..48].copy_from_slice(&1_u32.to_le_bytes());
        raw[48..60].copy_from_slice(&user);
        raw[64..68].copy_from_slice(&WRITE_DAC.to_le_bytes());
        raw[68..80].copy_from_slice(&OWNER_RIGHTS);
        let token = FileAccessToken { user: &user, groups: &[] };
        let sd = SecurityDescriptor::parse(&raw).unwrap();
        assert_eq!(sd.check_file_access(&token, 1), Ok(true));
        assert_eq!(sd.check_file_access(&token, 1 | WRITE_DAC), Ok(false));
        raw[61] = 8; // An inherited-only OWNER RIGHTS deny is not effective.
        assert_eq!(SecurityDescriptor::parse(&raw).unwrap().check_file_access(&token, 1 | WRITE_DAC), Ok(true));
        raw[60] = 0x11; // Unsupported inherited-only policy also has no effect.
        assert_eq!(SecurityDescriptor::parse(&raw).unwrap().check_file_access(&token, 1 | WRITE_DAC), Ok(true));
    }

    #[test]
    fn distinguishes_null_empty_and_absent_dacls() {
        let mut raw = descriptor();
        raw[16..20].fill(0);
        assert_eq!(SecurityDescriptor::parse(&raw).unwrap().dacl, AclState::Null);
        raw[2..4].copy_from_slice(&SELF_RELATIVE.to_le_bytes());
        assert_eq!(SecurityDescriptor::parse(&raw).unwrap().dacl, AclState::Absent);
        raw[2..4].copy_from_slice(&(SELF_RELATIVE | DACL_PRESENT).to_le_bytes());
        raw[16..20].copy_from_slice(&32_u32.to_le_bytes());
        raw[36..38].fill(0);
        raw[34..36].copy_from_slice(&8_u16.to_le_bytes());
        assert!(matches!(SecurityDescriptor::parse(&raw).unwrap().dacl, AclState::Present(_)));
    }

    #[test]
    fn rejects_bad_offsets_and_ace_bounds() {
        let mut raw = descriptor();
        raw[42..44].copy_from_slice(&40_u16.to_le_bytes());
        assert_eq!(SecurityDescriptor::parse(&raw), Err(Error::InvalidSecurity));
        raw = descriptor();
        raw[16..20].copy_from_slice(&8_u32.to_le_bytes());
        assert_eq!(SecurityDescriptor::parse(&raw), Err(Error::InvalidSecurity));
    }

    #[test]
    fn sds_entry_checks_offset_hash_and_index_copy() {
        let descriptor = descriptor();
        let mut data = [0_u8; 80];
        data[4..8].copy_from_slice(&0x101_u32.to_le_bytes());
        data[8..16].copy_from_slice(&0x100_u64.to_le_bytes());
        data[16..20].copy_from_slice(&80_u32.to_le_bytes());
        data[20..].copy_from_slice(&descriptor);
        data[0..4].copy_from_slice(&security_hash(&descriptor).to_le_bytes());
        let entry = SdsEntry::parse(&data, 0x100).unwrap();
        assert_eq!(entry.security_id, 0x101);
        assert_eq!(entry.descriptor.raw(), &descriptor);
        assert!(entry.matches_index_header(&data[..20]));
        assert!(!entry.matches_index_header(&data[1..21]));
        assert_eq!(SdsEntry::parse(&data, 0x110), Err(Error::InvalidSecurity));
        data[21] ^= 1;
        assert_eq!(SdsEntry::parse(&data, 0x100), Err(Error::InvalidSecurity));
    }

    #[test]
    fn sds_entry_rejects_truncation_and_oversize() {
        let mut data = [0_u8; 20];
        data[16..20].copy_from_slice(&40_u32.to_le_bytes());
        assert_eq!(SdsEntry::parse(&data, 0), Err(Error::InvalidSecurity));
        data[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(SdsEntry::parse(&data, 0), Err(Error::InvalidSecurity));
    }

    fn build(owner: &[u8], group: &[u8], dacl: &[u8], sacl: Option<&[u8]>) -> std::vec::Vec<u8> {
        let mut out = std::vec![0_u8; 20];
        out[0] = 1;
        let control = SELF_RELATIVE | DACL_PRESENT | if sacl.is_some() { SACL_PRESENT } else { 0 };
        out[2..4].copy_from_slice(&control.to_le_bytes());
        if let Some(sacl) = sacl {
            let at = out.len() as u32;
            out.extend_from_slice(sacl);
            out[12..16].copy_from_slice(&at.to_le_bytes());
        }
        let at = out.len() as u32;
        out.extend_from_slice(dacl);
        out[16..20].copy_from_slice(&at.to_le_bytes());
        let at = out.len() as u32;
        out.extend_from_slice(owner);
        out[4..8].copy_from_slice(&at.to_le_bytes());
        let at = out.len() as u32;
        out.extend_from_slice(group);
        out[8..12].copy_from_slice(&at.to_le_bytes());
        out
    }
    fn sid(sub: u32) -> [u8; 12] {
        let mut s = [1, 1, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0];
        s[8..12].copy_from_slice(&sub.to_le_bytes());
        s
    }
    fn dacl(mask: u32) -> std::vec::Vec<u8> {
        let mut a = std::vec![2, 0, 28, 0, 1, 0, 0, 0, 0, 0, 20, 0];
        a.extend_from_slice(&mask.to_le_bytes());
        a.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]);
        a
    }

    #[test]
    fn replacement_rights_follow_changed_components() {
        let base = build(&sid(1), &sid(2), &dacl(0x1f01ff), None);
        let old = SecurityDescriptor::parse(&base).unwrap();
        assert_eq!(replacement_rights(old, old), Ok(0));
        let dac = build(&sid(1), &sid(2), &dacl(0x120089), None);
        assert_eq!(replacement_rights(old, SecurityDescriptor::parse(&dac).unwrap()), Ok(WRITE_DAC));
        let owner = build(&sid(3), &sid(2), &dacl(0x1f01ff), None);
        assert_eq!(replacement_rights(old, SecurityDescriptor::parse(&owner).unwrap()), Ok(WRITE_OWNER));
        let both = build(&sid(1), &sid(4), &dacl(1), None);
        assert_eq!(replacement_rights(old, SecurityDescriptor::parse(&both).unwrap()), Ok(WRITE_OWNER | WRITE_DAC));
        let empty_sacl = [2, 0, 8, 0, 0, 0, 0, 0];
        let sacl = build(&sid(1), &sid(2), &dacl(0x1f01ff), Some(&empty_sacl));
        assert_eq!(replacement_rights(old, SecurityDescriptor::parse(&sacl).unwrap()), Ok(ACCESS_SYSTEM_SECURITY));
    }

    #[test]
    fn owner_group_replacement_preserves_acl_bytes() {
        let base = build(&sid(1), &sid(2), &dacl(0x1f01ff), None);
        let old = SecurityDescriptor::parse(&base).unwrap();
        let mut out = [0_u8; 256];
        let n = replace_owner_group(old, None, Some(&sid(9)), &mut out).unwrap();
        let new = validate_storable(&out[..n]).unwrap();
        assert_eq!(new.owner.unwrap().raw(), &sid(1));
        assert_eq!(new.group.unwrap().raw(), &sid(9));
        assert_eq!(new.dacl, old.dacl);
        assert_eq!(new.control, old.control);
        assert_eq!(replacement_rights(old, new), Ok(WRITE_OWNER));
        let mut trailing = base.clone();
        trailing.extend_from_slice(&[0; 8]);
        assert_eq!(validate_storable(&trailing).err(), Some(Error::InvalidSecurity));
        let no_group = {
            let mut b = base.clone();
            b[8..12].fill(0);
            b
        };
        assert_eq!(validate_storable(&no_group).err(), Some(Error::InvalidSecurity));
    }
}
