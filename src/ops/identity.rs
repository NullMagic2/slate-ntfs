//! Module: ntfs_rs::identity
//! Purpose: Explicit initial-user-namespace Linux IDs -> Windows SIDs.
//! Created: 2026-10-01
//! Architecture: These operations edit Tx images that the shared journal publishes atomically.

//! Explicit initial-user-namespace Linux IDs -> Windows SIDs. No guessing.
use super::security::{
    FileAccessToken, SecurityDescriptor, TokenSid, MAX_SID_BYTES, SID_HEADER_BYTES, SID_SUBAUTHORITY_BYTES,
};
use super::{Error, Result};

pub const MAX_GROUPS: usize = 64;
pub const MAX_MAP_ENTRIES: usize = 64;
pub const MAX_MAP_BYTES: usize = 4096;
const EVERYONE: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
const AUTHENTICATED: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0];

#[derive(Clone, Copy)]
struct OwnedSid {
    bytes: [u8; MAX_SID_BYTES],
    length: usize,
}

fn decimal(text: &str, max: u64) -> Result<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidSecurity);
    }
    let mut result = 0u64;
    for digit in text.bytes() {
        result = result.checked_mul(10).and_then(|n| n.checked_add(u64::from(digit - b'0'))).ok_or(Error::Overflow)?;
    }
    if result > max {
        return Err(Error::InvalidSecurity);
    }
    Ok(result)
}

fn sid(text: &str) -> Result<OwnedSid> {
    let mut pieces = text.strip_prefix("S-1-").ok_or(Error::InvalidSecurity)?.split('-');
    let authority = decimal(pieces.next().ok_or(Error::InvalidSecurity)?, 0xffff_ffff_ffff)?;
    let mut output = OwnedSid { bytes: [0; MAX_SID_BYTES], length: SID_HEADER_BYTES };
    output.bytes[0] = 1;
    output.bytes[2..SID_HEADER_BYTES].copy_from_slice(&authority.to_be_bytes()[2..]);
    for sub in pieces {
        if output.length == MAX_SID_BYTES {
            return Err(Error::InvalidSecurity);
        }
        let sub = decimal(sub, u32::MAX as u64)? as u32;
        output.bytes[output.length..output.length + SID_SUBAUTHORITY_BYTES].copy_from_slice(&sub.to_le_bytes());
        output.length += SID_SUBAUTHORITY_BYTES;
        output.bytes[1] += 1;
    }
    Ok(output)
}

fn entry(text: &str) -> Result<(bool, u32, OwnedSid, super::security_writer::SecurityPrivileges)> {
    let mut parts = text.split(':');
    let group = match parts.next() {
        Some("u") => false,
        Some("g") => true,
        _ => return Err(Error::InvalidSecurity),
    };
    let id = decimal(parts.next().ok_or(Error::InvalidSecurity)?, u32::MAX as u64 - 1)? as u32;
    let sid = sid(parts.next().ok_or(Error::InvalidSecurity)?)?;
    let mut privileges = super::security_writer::SecurityPrivileges::default();
    if let Some(grants) = parts.next() {
        // Privileges belong to an explicitly mapped user, never a group SID.
        if group {
            return Err(Error::InvalidSecurity);
        }
        let mut seen = 0;
        for grant in grants.split('+') {
            let bit = match grant {
                "security" => {
                    privileges.security = true;
                    1
                }
                "restore" => {
                    privileges.restore = true;
                    2
                }
                "take-ownership" => {
                    privileges.take_ownership = true;
                    4
                }
                // One explicit mandatory integrity level (default medium).
                "low-integrity" | "high-integrity" | "system-integrity" => {
                    privileges.integrity = match grant {
                        "low-integrity" => super::security::INTEGRITY_LOW,
                        "high-integrity" => super::security::INTEGRITY_HIGH,
                        _ => super::security::INTEGRITY_SYSTEM,
                    };
                    8
                }
                _ => return Err(Error::InvalidSecurity),
            };
            if seen & bit != 0 {
                return Err(Error::InvalidSecurity);
            }
            seen |= bit;
        }
    }
    if parts.next().is_some() {
        return Err(Error::InvalidSecurity);
    }
    Ok((group, id, sid, privileges))
}

/// Validate explicit mount identities, rejecting ambiguous IDs/SIDs.
pub fn validate_sidmap(text: &str) -> Result<()> {
    if text.is_empty() || text.len() > MAX_MAP_BYTES {
        return Err(Error::InvalidSecurity);
    }
    let mut user = false;
    for (i, piece) in text.split(';').enumerate() {
        if i >= MAX_MAP_ENTRIES {
            return Err(Error::Unsupported);
        }
        let (group, id, principal, _) = entry(piece)?;
        user |= !group;
        for prior in text.split(';').take(i) {
            let (previous_group, previous_id, previous_sid, _) = entry(prior)?;
            if group == previous_group && (id == previous_id || principal.bytes == previous_sid.bytes) {
                return Err(Error::InvalidSecurity);
            }
        }
    }
    if !user {
        return Err(Error::InvalidSecurity);
    }
    Ok(())
}

/// Parsed once at mount. Private fields prevent unchecked construction in safe
/// Rust; an all-zero value is valid but grants nothing until initialize succeeds.
pub struct CompiledSidMap {
    count: usize,
    entries: [CompiledEntry; MAX_MAP_ENTRIES],
}

#[derive(Clone, Copy)]
struct CompiledEntry {
    group: bool,
    id: u32,
    sid: OwnedSid,
    privileges: super::security_writer::SecurityPrivileges,
}

impl CompiledSidMap {
    /// A map that grants nothing until initialize succeeds.
    pub const fn empty() -> Self {
        Self {
            count: 0,
            entries: [CompiledEntry {
                group: false,
                id: 0,
                privileges: super::security_writer::SecurityPrivileges {
                    security: false,
                    restore: false,
                    take_ownership: false,
                    integrity: 0,
                },
                sid: OwnedSid { bytes: [0; MAX_SID_BYTES], length: 0 },
            }; MAX_MAP_ENTRIES],
        }
    }

    pub fn initialize(&mut self, text: &str) -> Result<()> {
        self.count = 0;
        validate_sidmap(text)?;
        for (i, piece) in text.split(';').enumerate() {
            let (group, id, sid, privileges) = entry(piece)?;
            self.entries[i] = CompiledEntry { group, id, sid, privileges };
            self.count += 1;
        }
        Ok(())
    }

    fn resolve(&self, group: bool, id: u32) -> Result<&OwnedSid> {
        self.entries[..self.count]
            .iter()
            .find(|entry| entry.group == group && entry.id == id)
            .map(|entry| &entry.sid)
            .ok_or(Error::AccessDenied)
    }

    pub fn linux_id(&self, group: bool, sid: &[u8]) -> Option<u32> {
        self.entries[..self.count]
            .iter()
            .find(|entry| entry.group == group && entry.sid.bytes[..entry.sid.length] == *sid)
            .map(|entry| entry.id)
    }

    pub fn sid_for_id(&self, group: bool, id: u32) -> Result<&[u8]> {
        let sid = self.resolve(group, id)?;
        Ok(&sid.bytes[..sid.length])
    }

    pub fn check_access(
        &self,
        descriptor: SecurityDescriptor<'_>,
        uid: u32,
        gids: &[u32],
        requested: u32,
    ) -> Result<bool> {
        if gids.is_empty() || gids.len() > MAX_GROUPS {
            return Err(Error::Unsupported);
        }
        let user = self.resolve(false, uid)?;
        let integrity = self.entries[..self.count]
            .iter()
            .find(|e| !e.group && e.id == uid)
            .map(|e| e.privileges.integrity_level())
            .unwrap_or(super::security::INTEGRITY_MEDIUM);
        let mut groups = [TokenSid { sid: &[], deny_only: false }; MAX_GROUPS + 2];
        // Resolve every group before evaluating even a null DACL. Borrowed
        // slices cannot outlive the immutable compiled map and no grant is cached.
        for (i, gid) in gids.iter().enumerate() {
            let sid = self.resolve(true, *gid)?;
            groups[i].sid = &sid.bytes[..sid.length];
        }
        groups[gids.len()].sid = &EVERYONE;
        groups[gids.len() + 1].sid = &AUTHENTICATED;
        descriptor.check_file_access_at(
            &FileAccessToken { user: &user.bytes[..user.length], groups: &groups[..gids.len() + 2] },
            integrity,
            requested,
        )
    }
}

/// A mapped Linux caller evaluated as an unrestricted Windows token.
pub struct MappedCaller<'a> {
    pub map: &'a CompiledSidMap,
    pub uid: u32,
    pub gids: &'a [u32],
}

impl CompiledSidMap {
    /// SID mapped to a Linux user (group == false) or group ID.
    pub fn sid_for(&self, group: bool, id: u32) -> Result<&[u8]> {
        self.sid_for_id(group, id)
    }
}

impl super::security_writer::SecurityPolicy for MappedCaller<'_> {
    fn allowed(&self, current: SecurityDescriptor<'_>, rights: u32) -> Result<bool> {
        self.map.check_access(current, self.uid, self.gids, rights)
    }
    fn user_sid(&self) -> Result<&[u8]> {
        self.map.sid_for(false, self.uid)
    }
    fn privileges(&self) -> super::security_writer::SecurityPrivileges {
        self.map.entries[..self.map.count]
            .iter()
            .find(|e| !e.group && e.id == self.uid)
            .map(|e| e.privileges)
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_map_capacity_matches_compiled_storage() {
        let entries: std::vec::Vec<_> = (0..MAX_MAP_ENTRIES).map(|id| std::format!("u:{id}:S-1-5-{id}")).collect();
        let text = entries.join(";");
        assert_eq!(validate_sidmap(&text), Ok(()));
        let mut map = CompiledSidMap::empty();
        map.initialize(&text).unwrap();
        assert_eq!(map.count, MAX_MAP_ENTRIES);
        assert!(map.sid_for(false, (MAX_MAP_ENTRIES - 1) as u32).is_ok());

        let oversized = std::format!("{text};u:{MAX_MAP_ENTRIES}:S-1-5-{MAX_MAP_ENTRIES}");
        assert_eq!(validate_sidmap(&oversized), Err(Error::Unsupported));
        assert_eq!(map.initialize(&oversized), Err(Error::Unsupported));
        assert_eq!(map.count, 0);
        assert!(map.sid_for(false, 0).is_err());
    }

    #[test]
    fn privilege_grants_are_explicit_and_user_scoped() {
        use super::super::security_writer::SecurityPolicy;
        let mut map = CompiledSidMap::empty();
        map.initialize("u:0:S-1-5-32-544;u:1000:S-1-5-1000:security+restore+take-ownership;g:0:S-1-5-18").unwrap();
        let root = MappedCaller { map: &map, uid: 0, gids: &[0] };
        assert!(!root.privileges().security && !root.privileges().restore);
        let user = MappedCaller { map: &map, uid: 1000, gids: &[0] };
        assert!(user.privileges().security && user.privileges().restore && user.privileges().take_ownership);
        for invalid in ["u:0:S-1-5-18:security+security", "u:0:S-1-5-18;g:0:S-1-5-32-544:restore", "u:0:S-1-5-18:admin"]
        {
            assert!(map.initialize(invalid).is_err());
            assert!(map.sid_for(false, 0).is_err());
        }
    }
    #[test]
    fn compiled_map_keeps_missing_groups_fail_closed_and_resets_on_error() {
        let mut map = CompiledSidMap {
            count: 0,
            entries: [CompiledEntry {
                group: false,
                id: 0,
                privileges: super::super::security_writer::SecurityPrivileges {
                    security: false,
                    restore: false,
                    take_ownership: false,
                    integrity: 0,
                },
                sid: OwnedSid { bytes: [0; MAX_SID_BYTES], length: 0 },
            }; MAX_MAP_ENTRIES],
        };
        map.initialize("u:1000:S-1-5-1000;g:2000:S-1-5-2000").unwrap();
        let mut raw = [0u8; 20];
        raw[0] = 1;
        raw[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
        let sd = SecurityDescriptor::parse(&raw).unwrap();
        assert_eq!(map.check_access(sd, 1000, &[2000], 1), Ok(true));
        assert_eq!(map.check_access(sd, 1000, &[2000; MAX_GROUPS], 1), Ok(true));
        assert!(map.check_access(sd, 1000, &[2000; MAX_GROUPS + 1], 1).is_err());
        assert!(map.check_access(sd, 1000, &[2000, 3000], 1).is_err());
        assert!(map.check_access(sd, 0, &[2000], 1).is_err());
        assert!(map.check_access(sd, 1000, &[], 1).is_err());
        assert_eq!(map.linux_id(false, &sid("S-1-5-1000").unwrap().bytes[..12]), Some(1000));
        assert!(map.initialize("u:1:S-1-5-1;u:1:S-1-5-2").is_err());
        assert!(map.check_access(sd, 1000, &[2000], 1).is_err());
    }

    #[test]
    fn text_sid_preserves_binary_format_boundaries() {
        let mut text = std::string::String::from("S-1-281474976710655");
        let header = sid(&text).unwrap();
        assert_eq!(&header.bytes[..header.length], &[1, 0, 255, 255, 255, 255, 255, 255]);
        for _ in 0..15 {
            text.push_str("-4294967295");
        }
        let encoded = sid(&text).unwrap();
        assert_eq!(encoded.length, 68);
        assert_eq!(encoded.bytes[1], 15);
        assert!(encoded.bytes[8..].iter().all(|&byte| byte == 255));
        text.push_str("-0");
        assert!(matches!(sid(&text), Err(Error::InvalidSecurity)));
        assert!(matches!(sid("S-1-5-4294967296"), Err(Error::InvalidSecurity)));
    }

    #[test]
    fn mapping_rejects_ambiguity_and_bad_sids() {
        for text in [
            "",
            "u:0:S-2-5-18",
            "u:0:S-1-281474976710656-1",
            "u:4294967295:S-1-5-1",
            "u:0:S-1-5-1;u:0:S-1-5-2",
            "u:0:S-1-5-1;u:1:S-1-5-1",
            "g:1:S-1-5-1",
            "u:1:S-1-5--1",
            "u:1:S-1-5-1;",
        ] {
            assert!(validate_sidmap(text).is_err(), "{text}");
        }
    }
}
