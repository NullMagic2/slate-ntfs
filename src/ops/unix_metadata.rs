//! Module: ntfs_rs::unix_metadata
//! Purpose: Linux metadata in native NTFS extended attributes.
//! Created: 2026-10-01
//! Architecture: These operations edit Tx images that the shared journal publishes atomically.

//! Linux metadata in native NTFS extended attributes. ACLs stay byte-exact.
//! $LXMOD follows the WSL/ntfs3 little-endian mode convention.
use super::bytes::u32_at;
use super::ea::{visit, EA, EA_INFO};
use super::mft::MftRecord;
use super::record_edit::{self, p16, p32};
use super::resident_writer::{WriteIo, Writer, METADATA_SCRATCH_BYTES};
use super::{Error, Result};

pub const MODE: &[u8] = b"$LXMOD";
/// Optional Slate Linux-view policy, stored in a standard NTFS EA.
/// Other NTFS implementations can ignore it without changing stream layout.
pub const FLAGS: &[u8] = b"$SLATE_FLAGS";
pub const FLAGS_SUPPORTED: u32 = 0x10 | 0x20 | 0x40 | 0x80;
pub fn flags_in(stream: &[u8]) -> Result<u32> {
    let mut found = None;
    visit(stream, |name, value, _| {
        if name == FLAGS {
            if found.is_some() || value.len() != 4 {
                return Err(Error::InvalidAttribute);
            }
            let flags = u32_at(value, 0)?;
            if flags & !FLAGS_SUPPORTED != 0 {
                return Err(Error::Unsupported);
            }
            found = Some(flags);
        }
        Ok(())
    })?;
    Ok(found.unwrap_or(0))
}

/// Device number of a character or block special file.
pub const DEVICE: &[u8] = b"$LXDEV";

/// Encode $LXDEV in the WSL layout: 32-bit major, then 32-bit minor,
/// little-endian (the layout Windows exposes as LxDeviceIdMajor/Minor).
pub fn device_bytes(major: u32, minor: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&major.to_le_bytes());
    out[4..].copy_from_slice(&minor.to_le_bytes());
    out
}

/// Decode a $LXDEV value into (major, minor). Two layouts exist on disk:
/// the 8-byte WSL layout above, and the 4-byte Linux-internal dev_t
/// (major in bits 20..32, minor in bits 0..20) written by the Linux ntfs3
/// driver. Other lengths are not device numbers.
pub fn device_from(value: &[u8]) -> Option<(u32, u32)> {
    match value.len() {
        8 => Some((u32_at(value, 0).ok()?, u32_at(value, 4).ok()?)),
        4 => {
            let dev = u32_at(value, 0).ok()?;
            Some((dev >> 20, dev & 0xf_ffff))
        }
        _ => None,
    }
}

/// Find and decode $LXDEV in a complete EA stream.
pub fn device_in(stream: &[u8]) -> Result<Option<(u32, u32)>> {
    let mut found = None;
    visit(stream, |name, value, _| {
        if name == DEVICE && found.is_none() {
            found = device_from(value);
        }
        Ok(())
    })?;
    Ok(found)
}

/// Parse $LXMOD from a complete EA stream (resident or nonresident).
pub fn mode_in(stream: &[u8], directory: bool) -> Result<Option<u32>> {
    let mut found = None;
    visit(stream, |name, value, _| {
        if name == MODE {
            if value.len() != 4 || found.is_some() {
                return Err(Error::InvalidAttribute);
            }
            let mode = u32_at(value, 0)?;
            let valid_kind = if directory {
                mode & 0o170000 == 0o040000
            } else {
                matches!(mode & 0o170000, 0o100000 | 0o120000 | 0o010000 | 0o020000 | 0o060000 | 0o140000)
            };
            // Symbolic links carry S_IFLNK; the VFS type comes from the reparse tag.
            if mode & !0o177777 != 0 || !valid_kind {
                return Err(Error::Unsupported);
            }
            found = Some(mode);
        }
        Ok(())
    })?;
    Ok(found)
}

pub fn mode(record: &MftRecord<'_>) -> Result<Option<u32>> {
    let mut found = None;
    for a in record.attributes() {
        let a = a?;
        if a.kind == EA {
            if found.is_some() || a.nonresident {
                return Err(Error::Unsupported);
            }
            found = Some(mode_in(a.resident_value()?, record.flags()? & 2 != 0)?);
        }
    }
    Ok(found.flatten())
}

/// Edit only $LXMOD; all other EA names, flags and values are retained.
/// The caller edits an unpublished record image and discards it on error.
pub fn set_mode(record: &mut [u8], mode: u32, work: &mut [u8]) -> Result<()> {
    // Keep the stored file type (FIFO, socket, device); default by record kind.
    let kind = match self::mode(&MftRecord::from_decoded(record)?)? {
        Some(old) => old & 0o170000,
        None if MftRecord::from_decoded(record)?.flags()? & 2 != 0 => 0o040000,
        None => 0o100000,
    };
    // Set-user-ID, set-group-ID and sticky bits are ordinary Linux mode bits.
    if mode & !0o7777 != 0 {
        return Err(Error::Unsupported);
    }
    let mode_bytes = (kind | mode).to_le_bytes();
    let mut used = 0;
    let mut packed = 0u16;
    let mut needed = 0u16;
    let mut had_mode = false;
    let mut emit = |name: &[u8], value: &[u8], flags: u8| -> Result<()> {
        let size = 9 + name.len() + value.len();
        let stride = (size + 3) & !3;
        let dest = work.get_mut(used..used + stride).ok_or(Error::NoSpace)?;
        dest.fill(0);
        p32(dest, 0, stride as u32)?;
        dest[4] = flags;
        dest[5] = name.len() as u8;
        p16(dest, 6, value.len() as u16)?;
        dest[8..8 + name.len()].copy_from_slice(name);
        dest[9 + name.len()..size].copy_from_slice(value);
        packed = packed.checked_add((size - 4) as u16).ok_or(Error::Overflow)?;
        needed += u16::from(flags & 0x80 != 0);
        used += stride;
        Ok(())
    };
    if let Some(at) = record_edit::find(record, EA, &[])? {
        visit(record_edit::resident_value(record, at)?, |name, value, flags| {
            if name == MODE {
                if had_mode || value.len() != 4 {
                    return Err(Error::InvalidAttribute);
                }
                had_mode = true;
                emit(name, &mode_bytes, flags)
            } else {
                emit(name, value, flags)
            }
        })?;
    }
    if !had_mode {
        emit(MODE, &mode_bytes, 0)?;
    }
    let mut info = [0u8; 8];
    p16(&mut info, 0, packed)?;
    p16(&mut info, 2, needed)?;
    p32(&mut info, 4, used as u32)?;
    let mut attr = [0u8; 1024];
    for (kind, value) in [(EA_INFO, &info[..]), (EA, &work[..used])] {
        if let Some(at) = record_edit::find(record, kind, &[])? {
            record_edit::set_resident_value(record, at, value)?;
        } else {
            let n = record_edit::build_resident(kind, &[], value, &mut attr)?;
            record_edit::insert(record, &attr[..n])?;
        }
    }
    record_edit::validate(record)
}

impl Writer {
    /// Adapter checks Linux ownership and native WRITE_DAC before this call.
    /// Resident and nonresident EA streams are both supported.
    pub fn set_unix_mode<I: WriteIo>(
        &mut self,
        io: &mut I,
        reference: u64,
        mode: u32,
        scratch: &mut [u8],
    ) -> Result<()> {
        if scratch.len() < METADATA_SCRATCH_BYTES {
            return Err(Error::Truncated);
        }
        self.edit_eas(io, reference, &[], Some(mode), scratch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mode_round_trip_keeps_other_eas_and_rejects_bad_chains() {
        let mut record = [0u8; 1024];
        record_edit::format_empty(&mut record, 64).unwrap();
        p16(&mut record, 22, 1).unwrap();
        let mut raw = [0u8; 16];
        p32(&mut raw, 0, 16).unwrap();
        raw[5] = 3;
        p16(&mut raw, 6, 3).unwrap();
        raw[8..11].copy_from_slice(b"app");
        raw[12..15].copy_from_slice(b"abc");
        let mut image = [0u8; 128];
        let n = record_edit::build_resident(EA, &[], &raw, &mut image).unwrap();
        record_edit::insert(&mut record, &image[..n]).unwrap();
        set_mode(&mut record, 0o751, &mut [0; 1024]).unwrap();
        assert_eq!(mode(&MftRecord::from_decoded(&record).unwrap()).unwrap(), Some(0o100751));
        set_mode(&mut record, 0o640, &mut [0; 1024]).unwrap();
        let ea = record_edit::require(&record, EA, &[]).unwrap();
        let value = record_edit::resident_value(&record, ea).unwrap();
        assert_eq!(&value[..16], &raw);
        let mut broken = value.to_vec();
        broken[0] = 4;
        assert!(visit(&broken, |_, _, _| Ok(())).is_err());
        set_mode(&mut record, 0o4755, &mut [0; 1024]).unwrap();
        assert_eq!(mode(&MftRecord::from_decoded(&record).unwrap()).unwrap(), Some(0o104755));
        assert_eq!(set_mode(&mut record, 0o10755, &mut [0; 1024]), Err(Error::Unsupported));
    }

    #[test]
    fn device_numbers_in_wsl_and_ntfs3_layouts() {
        // WSL / Windows layout: major then minor, 32 bits each.
        assert_eq!(device_bytes(8, 1), [8, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(device_from(&device_bytes(259, 0x12345)), Some((259, 0x12345)));
        // Linux ntfs3 layout: kernel dev_t, 12-bit major and 20-bit minor.
        assert_eq!(device_from(&((8u32 << 20) | 1).to_le_bytes()), Some((8, 1)));
        assert_eq!(device_from(&[1, 2, 3]), None);
        assert_eq!(device_from(&[0; 12]), None);
    }

    #[test]
    fn chmod_keeps_special_file_type() {
        let mut record = [0u8; 1024];
        record_edit::format_empty(&mut record, 64).unwrap();
        p16(&mut record, 22, 1).unwrap();
        set_mode(&mut record, 0o644, &mut [0; 1024]).unwrap();
        assert_eq!(mode(&MftRecord::from_decoded(&record).unwrap()).unwrap(), Some(0o100644));
        // Replace the type with FIFO through a raw rewrite, then chmod.
        let at = record_edit::find(&record, EA, &[]).unwrap().unwrap();
        let mut value = record_edit::resident_value(&record, at).unwrap().to_vec();
        // One entry: 8-byte header, "$LXMOD\0", then the 4-byte value.
        value[15..19].copy_from_slice(&0o010644u32.to_le_bytes());
        record_edit::set_resident_value(&mut record, at, &value).unwrap();
        set_mode(&mut record, 0o600, &mut [0; 1024]).unwrap();
        assert_eq!(mode(&MftRecord::from_decoded(&record).unwrap()).unwrap(), Some(0o010600));
    }
}
