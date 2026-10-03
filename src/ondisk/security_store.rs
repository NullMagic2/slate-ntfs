//! Module: ntfs_rs::security_store
//! Purpose: Read-only security descriptor resolution.
//! Created: 2026-10-01
//! Architecture: Volume readers, the writer and offline tools consume these checked format
//! views.

//! Read-only security descriptor resolution. No SID mapping or privilege grants.
//! All workspace and result storage belongs to the caller; usable in no_std.
use super::bytes::{range, u16_at, u32_at, u64_at};
use super::index::IndexBlock;
use super::mft::{Attribute, MftRecord, ATTR_ATTRIBUTE_LIST};
use super::security::{SdsEntry, SecurityDescriptor};
use super::volume::{ReadAt, Volume};
use super::{Error, Result};

fn attribute<'a>(record: &MftRecord<'a>, kind: u32, name: &[u8]) -> Result<Attribute<'a>> {
    let attr = record.local_attribute(kind, name)?.ok_or(Error::InvalidSecurity)?;
    if attr.flags()? != 0 {
        return Err(Error::InvalidSecurity);
    }
    Ok(attr)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Search {
    Found([u8; 20]),
    Child(u64),
    Missing,
}

const MAX_SECURITY_INDEX_DEPTH: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityIndexEntry {
    pub hash: u32,
    pub security_id: u32,
    pub offset: u64,
    pub length: u32,
}

#[derive(Clone, Copy)]
enum WalkNode {
    Root,
    Block(u64),
}

#[derive(Clone, Copy)]
struct WalkFrame {
    node: WalkNode,
    cursor: usize,
    after_child: bool,
}

#[derive(Clone, Copy)]
struct SecuritySlot {
    key: Option<(u32, u32)>,
    value: Option<[u8; 20]>,
    child_vcn: Option<u64>,
    next_offset: usize,
}

fn key(bytes: &[u8], hashed: bool) -> Result<(u32, u32)> {
    if bytes.len() != if hashed { 8 } else { 4 } {
        return Err(Error::InvalidSecurity);
    }
    Ok(if hashed { (u32_at(bytes, 0)?, u32_at(bytes, 4)?) } else { (0, u32_at(bytes, 0)?) })
}

/// Validate the complete visited node, including entries after the match.
fn search_node(
    data: &[u8],
    header: usize,
    wanted: (u32, u32),
    hashed: bool,
    lower: Option<(u32, u32)>,
    upper: Option<(u32, u32)>,
) -> Result<(Search, Option<(u32, u32)>, Option<(u32, u32)>)> {
    let (mut cursor, end, has_children) = node_bounds(data, header)?;
    let mut previous = lower;
    let mut chosen = None;
    loop {
        let head = range(data, cursor, 16)?;
        let length = usize::from(u16_at(head, 8)?);
        let key_length = usize::from(u16_at(head, 10)?);
        let flags = u16_at(head, 12)?;
        if length < 16
            || length % 8 != 0
            || flags & !3 != 0
            || (flags & 1 != 0) != has_children
            || cursor.checked_add(length).is_none_or(|n| n > end)
        {
            return Err(Error::InvalidIndex);
        }
        let entry = range(data, cursor, length)?;
        let data_end = length - if flags & 1 != 0 { 8 } else { 0 };
        let child = if flags & 1 != 0 { Search::Child(u64_at(entry, data_end)?) } else { Search::Missing };
        if flags & 2 != 0 {
            if key_length != 0 || cursor + length != end || data_end != 16 {
                return Err(Error::InvalidIndex);
            }
            return Ok(chosen.unwrap_or((child, previous, upper)));
        }
        let current = key(range(entry, 16, key_length)?, hashed)?;
        if previous.is_some_and(|p| current <= p) || upper.is_some_and(|u| current >= u) {
            return Err(Error::InvalidIndex);
        }
        let offset = usize::from(u16_at(head, 0)?);
        let bytes = usize::from(u16_at(head, 2)?);
        // Both indices contain a 20-byte SDS header; entry alignment padding
        // (including SDH's reserved ULONG) is outside the declared data.
        if bytes != 20 || offset < 16 + key_length || offset.checked_add(bytes).is_none_or(|n| n > data_end) {
            return Err(Error::InvalidSecurity);
        }
        let value = range(entry, offset, bytes)?;
        if u32_at(value, 4)? != current.1 || (hashed && u32_at(value, 0)? != current.0) {
            return Err(Error::InvalidSecurity);
        }
        if chosen.is_none() && wanted <= current {
            chosen = Some((
                if wanted == current {
                    let mut result = [0; 20];
                    result.copy_from_slice(&value[..20]);
                    Search::Found(result)
                } else {
                    child
                },
                previous,
                Some(current),
            ));
        }
        previous = Some(current);
        cursor += length;
    }
}

fn node_bounds(data: &[u8], header: usize) -> Result<(usize, usize, bool)> {
    let first = usize::try_from(u32_at(data, header)?).map_err(|_| Error::Overflow)?;
    let used = usize::try_from(u32_at(data, header + 4)?).map_err(|_| Error::Overflow)?;
    let allocated = usize::try_from(u32_at(data, header + 8)?).map_err(|_| Error::Overflow)?;
    let flags = *data.get(header + 12).ok_or(Error::Truncated)?;
    if first < 16
        || first % 8 != 0
        || first > used
        || used > allocated
        || header.checked_add(allocated).is_none_or(|end| end > data.len())
        || flags > 1
    {
        return Err(Error::InvalidIndex);
    }
    let start = header.checked_add(first).ok_or(Error::Overflow)?;
    let end = header.checked_add(used).ok_or(Error::Overflow)?;
    Ok((start, end, flags == 1))
}

fn security_slot(data: &[u8], cursor: usize, end: usize, has_children: bool, hashed: bool) -> Result<SecuritySlot> {
    let head = range(data, cursor, 16)?;
    let length = usize::from(u16_at(head, 8)?);
    let key_length = usize::from(u16_at(head, 10)?);
    let flags = u16_at(head, 12)?;
    if length < 16
        || length % 8 != 0
        || flags & !3 != 0
        || (flags & 1 != 0) != has_children
        || cursor.checked_add(length).is_none_or(|next| next > end)
    {
        return Err(Error::InvalidIndex);
    }
    let entry = range(data, cursor, length)?;
    let child_bytes = if flags & 1 != 0 { 8 } else { 0 };
    let data_end = length.checked_sub(child_bytes).ok_or(Error::InvalidIndex)?;
    let child_vcn = if flags & 1 != 0 { Some(u64_at(entry, data_end)?) } else { None };
    let next_offset = cursor.checked_add(length).ok_or(Error::Overflow)?;
    if flags & 2 != 0 {
        if key_length != 0 || next_offset != end || data_end != 16 {
            return Err(Error::InvalidIndex);
        }
        return Ok(SecuritySlot { key: None, value: None, child_vcn, next_offset });
    }
    let expected_key = if hashed { 8 } else { 4 };
    if key_length != expected_key {
        return Err(Error::InvalidSecurity);
    }
    let current = key(range(entry, 16, key_length)?, hashed)?;
    let offset = usize::from(u16_at(head, 0)?);
    let bytes = usize::from(u16_at(head, 2)?);
    if bytes != 20 || offset < 16 + key_length || offset.checked_add(bytes).is_none_or(|n| n > data_end) {
        return Err(Error::InvalidSecurity);
    }
    let value = range(entry, offset, bytes)?;
    if u32_at(value, 4)? != current.1 || (hashed && u32_at(value, 0)? != current.0) {
        return Err(Error::InvalidSecurity);
    }
    let mut copied = [0_u8; 20];
    copied.copy_from_slice(value);
    Ok(SecuritySlot { key: Some(current), value: Some(copied), child_vcn, next_offset })
}

fn walk_index<R: ReadAt>(
    volume: &mut Volume<R>,
    secure: &MftRecord<'_>,
    name: &[u8],
    hashed: bool,
    scratch: &mut [u8],
    mut visitor: impl FnMut(&mut Volume<R>, (u32, u32), [u8; 20]) -> Result<()>,
) -> Result<()> {
    let root = attribute(secure, 0x90, name)?;
    let bytes = root.resident_value()?;
    if u32_at(bytes, 0)? != 0 || u32_at(bytes, 4)? != if hashed { 18 } else { 16 } {
        return Err(Error::InvalidIndex);
    }
    let block_bytes = usize::try_from(u32_at(bytes, 8)?).map_err(|_| Error::Overflow)?;
    let units = usize::from(*bytes.get(12).ok_or(Error::Truncated)?);
    let unit =
        if block_bytes < volume.boot.cluster_bytes as usize { 512_usize } else { volume.boot.cluster_bytes as usize };
    if block_bytes < 512
        || !block_bytes.is_power_of_two()
        || units == 0
        || unit.checked_mul(units) != Some(block_bytes)
        || block_bytes > scratch.len()
    {
        return Err(Error::InvalidIndex);
    }
    let (_, _, root_children) = node_bounds(bytes, 16)?;
    let allocation = if root_children {
        let attr = attribute(secure, 0xa0, name)?;
        if !attr.nonresident || attr.data_size()? % block_bytes as u64 != 0 {
            return Err(Error::InvalidIndex);
        }
        Some(attr)
    } else {
        None
    };
    let bitmap = if root_children { Some(attribute(secure, 0xb0, name)?) } else { None };
    let max_blocks = match allocation {
        Some(attribute) => attribute.data_size()? / block_bytes as u64,
        None => 0,
    };
    if root_children && max_blocks == 0 {
        return Err(Error::InvalidIndex);
    }
    let empty = WalkFrame { node: WalkNode::Root, cursor: usize::MAX, after_child: false };
    let mut frames = [empty; MAX_SECURITY_INDEX_DEPTH];
    let mut depth = 1_usize;
    let mut visited_blocks = 0_u64;
    let mut previous = None;
    while depth != 0 {
        let frame = frames[depth - 1];
        let (first, slot) = match frame.node {
            WalkNode::Root => {
                let (first, end, has_children) = node_bounds(bytes, 16)?;
                let cursor = if frame.cursor == usize::MAX { first } else { frame.cursor };
                (first, security_slot(bytes, cursor, end, has_children, hashed)?)
            }
            WalkNode::Block(vcn) => {
                let offset = vcn.checked_mul(unit as u64).ok_or(Error::Overflow)?;
                if offset % block_bytes as u64 != 0 {
                    return Err(Error::InvalidIndex);
                }
                let number = offset / block_bytes as u64;
                if number >= max_blocks {
                    return Err(Error::InvalidIndex);
                }
                let mut bit = [0_u8; 1];
                volume.read_attribute(bitmap.ok_or(Error::InvalidIndex)?, number / 8, &mut bit)?;
                if bit[0] & (1 << (number % 8)) == 0 {
                    return Err(Error::InvalidIndex);
                }
                let buffer = &mut scratch[..block_bytes];
                volume.read_attribute(allocation.ok_or(Error::InvalidIndex)?, offset, buffer)?;
                IndexBlock::parse(buffer, volume.boot.bytes_per_sector, vcn)?;
                let (first, end, has_children) = node_bounds(buffer, 24)?;
                let cursor = if frame.cursor == usize::MAX { first } else { frame.cursor };
                (first, security_slot(buffer, cursor, end, has_children, hashed)?)
            }
        };
        let cursor = if frame.cursor == usize::MAX { first } else { frame.cursor };
        if !frame.after_child {
            if let Some(child_vcn) = slot.child_vcn {
                if depth == MAX_SECURITY_INDEX_DEPTH || visited_blocks >= max_blocks {
                    return Err(Error::Unsupported);
                }
                if frames[..depth]
                    .iter()
                    .any(|ancestor| matches!(ancestor.node, WalkNode::Block(vcn) if vcn == child_vcn))
                {
                    return Err(Error::InvalidIndex);
                }
                visited_blocks = visited_blocks.checked_add(1).ok_or(Error::Overflow)?;
                frames[depth - 1].cursor = cursor;
                frames[depth - 1].after_child = true;
                frames[depth] = WalkFrame { node: WalkNode::Block(child_vcn), cursor: usize::MAX, after_child: false };
                depth += 1;
                continue;
            }
        }
        match (slot.key, slot.value) {
            (Some(current), Some(value)) => {
                if previous.is_some_and(|old| current <= old) {
                    return Err(Error::InvalidIndex);
                }
                previous = Some(current);
                visitor(volume, current, value)?;
                frames[depth - 1].cursor = slot.next_offset;
                frames[depth - 1].after_child = false;
            }
            (None, None) => depth -= 1,
            _ => return Err(Error::InvalidSecurity),
        }
    }
    if let Some(bitmap) = bitmap {
        volume.validate_index_bitmap(bitmap, max_blocks, visited_blocks)?;
    }
    Ok(())
}

fn validate_sds_header<R: ReadAt>(
    volume: &mut Volume<R>,
    secure: &MftRecord<'_>,
    header: &[u8; 20],
    result: &mut [u8],
) -> Result<SecurityIndexEntry> {
    let hash = u32_at(header, 0)?;
    let security_id = u32_at(header, 4)?;
    let offset = u64_at(header, 8)?;
    let length_u32 = u32_at(header, 16)?;
    let length = length_u32 as usize;
    if security_id < 0x100
        || offset % 16 != 0
        || offset % 0x80000 >= 0x40000
        || length < 40
        || length > 0x20014
        || (offset % 0x40000) + length as u64 > 0x40000
    {
        return Err(Error::InvalidSecurity);
    }
    let output = result.get_mut(..length).ok_or(Error::Truncated)?;
    let sds = attribute(secure, 0x80, b"$\0S\0D\0S\0")?;
    volume.read_attribute(sds, offset, output)?;
    let entry = SdsEntry::parse(output, offset)?;
    if entry.hash != hash || entry.security_id != security_id || !entry.matches_index_header(header) {
        return Err(Error::InvalidSecurity);
    }
    let mirror = offset.checked_add(0x40000).ok_or(Error::Overflow)?;
    let mut chunk = [0_u8; 512];
    for (i, expected) in output.chunks(512).enumerate() {
        let bytes = &mut chunk[..expected.len()];
        volume.read_attribute(sds, mirror + (i * 512) as u64, bytes)?;
        if bytes != expected {
            return Err(Error::InvalidSecurity);
        }
    }
    Ok(SecurityIndexEntry { hash, security_id, offset, length: length_u32 })
}

/// Validate one security index independently against both complete $SDS
/// copies. This lets offline repair identify a damaged $SII or $SDH tree
/// without treating the other tree as authority for descriptor contents.
pub fn validate_index_against_sds<R: ReadAt>(
    volume: &mut Volume<R>,
    secure: &MftRecord<'_>,
    hashed: bool,
    walk_buffer: &mut [u8],
    descriptor_buffer: &mut [u8],
) -> Result<u64> {
    let name = if hashed { b"$\0S\0D\0H\0".as_slice() } else { b"$\0S\0I\0I\0".as_slice() };
    let mut count = 0_u64;
    walk_index(volume, secure, name, hashed, walk_buffer, |volume, key, header| {
        if key.1 != u32_at(&header, 4)? || (hashed && key.0 != u32_at(&header, 0)?) || (!hashed && key.0 != 0) {
            return Err(Error::InvalidSecurity);
        }
        validate_sds_header(volume, secure, &header, descriptor_buffer)?;
        count = count.checked_add(1).ok_or(Error::Overflow)?;
        Ok(())
    })?;
    Ok(count)
}

/// Audit an already resolved, validated $Secure attribute family. The caller
/// is responsible for resolving every attribute-list entry before this call.
pub fn visit_record_descriptors<R: ReadAt>(
    volume: &mut Volume<R>,
    secure: &MftRecord<'_>,
    walk_buffer: &mut [u8],
    lookup_buffer: &mut [u8],
    descriptor_buffer: &mut [u8],
    mut visitor: impl FnMut(SecurityIndexEntry) -> Result<()>,
) -> Result<()> {
    if secure.flags()? & 1 == 0 || secure.base_file_reference()? != 0 {
        return Err(Error::InvalidSecurity);
    }
    let mut sii_entries = 0_u64;
    walk_index(volume, &secure, b"$\0S\0I\0I\0", false, walk_buffer, |volume, current, header| {
        if current.0 != 0 || current.1 != u32_at(&header, 4)? {
            return Err(Error::InvalidSecurity);
        }
        let counterpart =
            lookup(volume, &secure, b"$\0S\0D\0H\0", (u32_at(&header, 0)?, current.1), true, lookup_buffer)?;
        if counterpart != header {
            return Err(Error::InvalidSecurity);
        }
        let entry = validate_sds_header(volume, &secure, &header, descriptor_buffer)?;
        visitor(entry)?;
        sii_entries = sii_entries.checked_add(1).ok_or(Error::Overflow)?;
        Ok(())
    })?;
    let mut sdh_entries = 0_u64;
    walk_index(volume, &secure, b"$\0S\0D\0H\0", true, walk_buffer, |volume, current, header| {
        if current != (u32_at(&header, 0)?, u32_at(&header, 4)?) {
            return Err(Error::InvalidSecurity);
        }
        let counterpart = lookup(volume, &secure, b"$\0S\0I\0I\0", (0, current.1), false, lookup_buffer)?;
        if counterpart != header {
            return Err(Error::InvalidSecurity);
        }
        validate_sds_header(volume, &secure, &header, descriptor_buffer)?;
        sdh_entries = sdh_entries.checked_add(1).ok_or(Error::Overflow)?;
        Ok(())
    })?;
    if sii_entries != sdh_entries {
        return Err(Error::InvalidSecurity);
    }
    Ok(())
}

fn lookup<R: ReadAt>(
    volume: &mut Volume<R>,
    secure: &MftRecord<'_>,
    name: &[u8],
    wanted: (u32, u32),
    hashed: bool,
    scratch: &mut [u8],
) -> Result<[u8; 20]> {
    let root = attribute(secure, 0x90, name)?;
    let bytes = root.resident_value()?;
    if u32_at(bytes, 0)? != 0 || u32_at(bytes, 4)? != if hashed { 18 } else { 16 } {
        return Err(Error::InvalidIndex);
    }
    let block_bytes = u32_at(bytes, 8)? as usize;
    let units = usize::from(*bytes.get(12).ok_or(Error::Truncated)?);
    let unit = if block_bytes < volume.boot.cluster_bytes as usize { 512 } else { volume.boot.cluster_bytes as usize };
    if block_bytes < 512
        || !block_bytes.is_power_of_two()
        || units == 0
        || unit.checked_mul(units) != Some(block_bytes)
        || block_bytes > scratch.len()
    {
        return Err(Error::InvalidIndex);
    }
    let (mut next, mut lower, mut upper) = search_node(bytes, 16, wanted, hashed, None, None)?;
    let mut visited = [u64::MAX; 32];
    for depth in 0..=32 {
        let vcn = match next {
            Search::Found(value) => return Ok(value),
            Search::Missing => return Err(Error::InvalidSecurity),
            Search::Child(vcn) => vcn,
        };
        if depth == 32 || visited[..depth].contains(&vcn) {
            return Err(Error::InvalidIndex);
        }
        visited[depth] = vcn;
        let offset = vcn.checked_mul(unit as u64).ok_or(Error::Overflow)?;
        if offset % block_bytes as u64 != 0 {
            return Err(Error::InvalidIndex);
        }
        let number = offset / block_bytes as u64;
        let mut bit = [0];
        volume.read_attribute(attribute(secure, 0xb0, name)?, number / 8, &mut bit)?;
        if bit[0] & (1 << (number % 8)) == 0 {
            return Err(Error::InvalidIndex);
        }
        let buffer = &mut scratch[..block_bytes];
        let allocation = attribute(secure, 0xa0, name)?;
        if !allocation.nonresident {
            return Err(Error::InvalidIndex);
        }
        volume.read_attribute(allocation, offset, buffer)?;
        IndexBlock::parse(buffer, volume.boot.bytes_per_sector, vcn)?;
        (next, lower, upper) = search_node(buffer, 24, wanted, hashed, lower, upper)?;
    }
    Err(Error::InvalidIndex)
}

/// Resolve a live base record's security descriptor. The caller must validate
/// the requested file identity/sequence before passing file. Missing IDs,
/// conflicting indices, corrupt mirrors, and unsupported layouts are errors.
/// Scratch needs one MFT record, one index block, and up to 0x20014 SDS bytes.
pub fn read_descriptor<'a, R: ReadAt>(
    volume: &mut Volume<R>,
    mft: &MftRecord<'_>,
    file: &MftRecord<'_>,
    secure_buffer: &mut [u8],
    index_buffer: &mut [u8],
    result: &'a mut [u8],
) -> Result<SecurityDescriptor<'a>> {
    if file.flags()? & 1 == 0 || file.base_file_reference()? != 0 {
        return Err(Error::InvalidSecurity);
    }
    let mut inline = None;
    for attr in file.attributes() {
        let attr = attr?;
        if attr.kind == ATTR_ATTRIBUTE_LIST {
            file.local_attribute(0x10, &[])?;
            file.local_attribute(0x50, &[])?;
        }
        if attr.kind == 0x50 {
            if !attr.name_utf16le()?.is_empty() || attr.flags()? != 0 || inline.replace(attr).is_some() {
                return Err(Error::InvalidSecurity);
            }
        }
    }
    let info = attribute(file, 0x10, &[])?;
    let info = info.resident_value()?;
    let security_id = if info.len() >= 72 {
        u32_at(info, 52)?
    } else if info.len() == 48 {
        0
    } else {
        return Err(Error::InvalidSecurity);
    };
    if let Some(inline) = inline {
        if security_id != 0 {
            return Err(Error::InvalidSecurity);
        }
        let length = usize::try_from(inline.data_size()?).map_err(|_| Error::Overflow)?;
        if !(20..=0x20000).contains(&length) {
            return Err(Error::InvalidSecurity);
        }
        let output = result.get_mut(..length).ok_or(Error::Truncated)?;
        volume.read_attribute(inline, 0, output)?;
        return SecurityDescriptor::parse(output);
    }
    if security_id < 0x100 {
        return Err(Error::InvalidSecurity);
    }
    volume.read_mft_record(mft, 9, secure_buffer)?;
    let secure = MftRecord::parse(secure_buffer, volume.boot.bytes_per_sector)?;
    if secure.flags()? & 1 == 0 || secure.base_file_reference()? != 0 {
        return Err(Error::InvalidSecurity);
    }
    let sii = lookup(volume, &secure, b"$\0S\0I\0I\0", (0, security_id), false, index_buffer)?;
    let hash = u32_at(&sii, 0)?;
    let sdh = lookup(volume, &secure, b"$\0S\0D\0H\0", (hash, security_id), true, index_buffer)?;
    if sii != sdh {
        return Err(Error::InvalidSecurity);
    }
    let offset = u64_at(&sii, 8)?;
    let length = u32_at(&sii, 16)? as usize;
    // SDS entries cannot straddle a 256-KiB primary block. The matching
    // descriptor copy is in the immediately following 256-KiB mirror block.
    if offset % 16 != 0
        || offset % 0x80000 >= 0x40000
        || length < 40
        || length > 0x20014
        || (offset % 0x40000) + length as u64 > 0x40000
    {
        return Err(Error::InvalidSecurity);
    }
    let output = result.get_mut(..length).ok_or(Error::Truncated)?;
    let sds = attribute(&secure, 0x80, b"$\0S\0D\0S\0")?;
    volume.read_attribute(sds, offset, output)?;
    let entry = SdsEntry::parse(output, offset)?;
    if !entry.matches_index_header(&sii) {
        return Err(Error::InvalidSecurity);
    }
    let mirror = offset.checked_add(0x40000).ok_or(Error::Overflow)?;
    let mut chunk = [0; 512];
    for (i, expected) in output.chunks(512).enumerate() {
        let bytes = &mut chunk[..expected.len()];
        volume.read_attribute(sds, mirror + (i * 512) as u64, bytes)?;
        if bytes != expected {
            return Err(Error::InvalidSecurity);
        }
    }
    SecurityDescriptor::parse(&output[20..])
}

#[cfg(test)]
mod tests {
    use super::super::bytes::{p16, p32};
    use super::*;

    #[test]
    fn search_refuses_invalid_header_geometry_before_entry_data() {
        let mut data = [0_u8; 64];
        p32(&mut data, 16, 16).unwrap();
        p32(&mut data, 20, 16).unwrap();
        p32(&mut data, 24, u32::MAX).unwrap();
        assert_eq!(search_node(&data, 16, (0, 0x100), false, None, None), Err(Error::InvalidIndex));
        p32(&mut data, 24, 16).unwrap();
        data[28] = 2;
        assert_eq!(search_node(&data, 16, (0, 0x100), false, None, None), Err(Error::InvalidIndex));
        assert_eq!(search_node(&data[..28], 16, (0, 0x100), false, None, None), Err(Error::Truncated));
    }

    #[test]
    fn search_checks_entries_after_the_selected_match() {
        let mut data = [0_u8; 128];
        p32(&mut data, 0, 16).unwrap();
        p32(&mut data, 4, 128).unwrap();
        p32(&mut data, 8, 128).unwrap();
        for (cursor, id) in [(16, 0x100), (64, 0x101)] {
            p16(&mut data, cursor, 20).unwrap();
            p16(&mut data, cursor + 2, 20).unwrap();
            p16(&mut data, cursor + 8, 48).unwrap();
            p16(&mut data, cursor + 10, 4).unwrap();
            p32(&mut data, cursor + 16, id).unwrap();
            p32(&mut data, cursor + 24, id).unwrap();
        }
        p16(&mut data, 120, 16).unwrap();
        p16(&mut data, 124, 2).unwrap();
        let mut expected = [0_u8; 20];
        expected[4..8].copy_from_slice(&0x100_u32.to_le_bytes());
        assert_eq!(
            search_node(&data, 0, (0, 0x100), false, None, None),
            Ok((Search::Found(expected), None, Some((0, 0x100))))
        );
        // The second key is now out of order; finding the first never skips it.
        p32(&mut data, 80, 0xff).unwrap();
        assert_eq!(search_node(&data, 0, (0, 0x100), false, None, None), Err(Error::InvalidIndex));
    }
}
