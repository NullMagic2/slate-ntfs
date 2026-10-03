//! Module: slate_ntfs_tools::metadata_replay
//! Purpose: Checked metadata redo/undo primitives.
//! Created: 2026-10-01
//! Architecture: Userspace commands use this module with checked core formats and owned image
//! I/O.

//! Checked metadata redo/undo primitives. Caller supplies decoded target and
//! scratch, resolves identity and serializes by LSN. No allocation or I/O.
use ntfs_rs::bytes::{p16, p32, p64, u16_at, u32_at, u64_at};
use ntfs_rs::logfile::NtfsLogOperation;
use ntfs_rs::mft::MftRecord;
use ntfs_rs::runlist::DataRuns;
use ntfs_rs::{Error, Result};

fn replace(b: &mut [u8], used: usize, at: usize, old: usize, data: &[u8]) -> Result<usize> {
    let end = at.checked_add(old).ok_or(Error::Overflow)?;
    let new_used = used.checked_sub(old).and_then(|n| n.checked_add(data.len())).ok_or(Error::Overflow)?;
    if end > used || used > b.len() || new_used > b.len() {
        return Err(Error::InvalidRecord);
    }
    b.copy_within(end..used, at + data.len());
    b[at..at + data.len()].copy_from_slice(data);
    if new_used < used {
        b[new_used..used].fill(0);
    }
    Ok(new_used)
}
fn attr(b: &[u8], at: usize) -> Result<(u32, usize, bool)> {
    let a = MftRecord::from_decoded(b)?.attribute_at(at)?;
    Ok((a.kind, u32_at(b, at + 4)? as usize, a.nonresident))
}
fn validate_mft(b: &[u8]) -> Result<()> {
    let record = MftRecord::from_decoded(b)?;
    if u32_at(b, 28)? as usize != b.len() {
        return Err(Error::InvalidRecord);
    }
    let mut previous = 0;
    let mut ids = [0_u16; 256];
    let mut count = 0;
    for entry in record.attributes() {
        let a = entry?;
        if a.kind < previous || count == ids.len() || ids[..count].contains(&a.id) {
            return Err(Error::InvalidAttribute);
        }
        previous = a.kind;
        ids[count] = a.id;
        count += 1;
        a.validate_value()?;
    }
    Ok(())
}
fn resize_attr(b: &mut [u8], at: usize, new: usize) -> Result<()> {
    let old = u32_at(b, at + 4)? as usize;
    let used = u32_at(b, 24)? as usize;
    let new_used = used.checked_sub(old).and_then(|n| n.checked_add(new)).ok_or(Error::Overflow)?;
    if new % 8 != 0 || new_used > b.len() || at + old > used {
        return Err(Error::InvalidAttribute);
    }
    b.copy_within(at + old..used, at + new);
    if new > old {
        b[at + old..at + new].fill(0);
    } else {
        b[new_used..used].fill(0);
    }
    p32(b, 24, new_used as u32)?;
    p32(b, at + 4, new as u32)
}
fn entry_size(b: &[u8], at: usize, end: usize) -> Result<usize> {
    let n = u16_at(b, at + 8)? as usize;
    let flags = u16_at(b, at + 12)?;
    if n < 16
        || n % 8 != 0
        || at + n > end
        || flags & !3 != 0
        || 16 + usize::from(u16_at(b, at + 10)?) + if flags & 1 != 0 { 8 } else { 0 } > n
    {
        return Err(Error::InvalidIndex);
    }
    Ok(n)
}
fn validate_index(b: &[u8], head: usize) -> Result<()> {
    let first = u32_at(b, head)? as usize;
    let used = u32_at(b, head + 4)? as usize;
    let size = u32_at(b, head + 8)? as usize;
    if first < 16 || first % 8 != 0 || first > used || used > size || head + size > b.len() || b[head + 12] > 1 {
        return Err(Error::InvalidIndex);
    }
    let mut at = head + first;
    while at < head + used {
        let n = entry_size(b, at, head + used)?;
        let flags = u16_at(b, at + 12)?;
        if (flags & 1 != 0) != (b[head + 12] == 1) {
            return Err(Error::InvalidIndex);
        }
        if flags & 2 != 0 {
            return if at + n == head + used { Ok(()) } else { Err(Error::InvalidIndex) };
        }
        at += n;
    }
    Err(Error::InvalidIndex)
}
fn index_action(b: &mut [u8], head: usize, at: usize, code: u16, data: &[u8]) -> Result<()> {
    validate_index(b, head)?;
    let used = u32_at(b, head + 4)? as usize;
    let size = u32_at(b, head + 8)? as usize;
    let mut cursor = head + u32_at(b, head)? as usize;
    while cursor < at {
        cursor += entry_size(b, cursor, head + used)?;
    }
    if cursor != at || at >= head + used {
        return Err(Error::InvalidIndex);
    }
    let n = entry_size(b, at, head + used)?;
    match code {
        12 | 14 => {
            let len = entry_size(data, 0, data.len())?;
            if len != data.len() || u16_at(data, 12)? & 2 != 0 || used + len > size {
                return Err(Error::InvalidIndex);
            }
            replace(b, head + used, at, 0, data)?;
            p32(b, head + 4, (used + len) as u32)?;
        }
        13 | 15 => {
            if u16_at(b, at + 12)? & 2 != 0 {
                return Err(Error::InvalidIndex);
            }
            replace(b, head + used, at, n, &[])?;
            p32(b, head + 4, (used - n) as u32)?;
        }
        16 => {
            if at + data.len() > head + size {
                return Err(Error::InvalidIndex);
            }
            b[at..at + data.len()].copy_from_slice(data);
            p32(b, head + 4, (at + data.len() - head) as u32)?;
        }
        17 | 18 => {
            if data.len() != 8 || u16_at(b, at + 12)? & 1 == 0 {
                return Err(Error::InvalidIndex);
            }
            b[at + n - 8..at + n].copy_from_slice(data);
        }
        19 | 20 => {
            if data.len() != 56 || 24 + data.len() > n {
                return Err(Error::InvalidIndex);
            }
            b[at + 24..at + 24 + data.len()].copy_from_slice(data);
        }
        33 | 34 => {
            let off = u16_at(b, at)? as usize;
            let len = u16_at(b, at + 2)? as usize;
            // Native records may update only a prefix of the entry value.
            // Keep its declared length, key and child pointer intact.
            let payload_end = n - if u16_at(b, at + 12)? & 1 != 0 { 8 } else { 0 };
            if data.len() > len || off < 16 || off + len > payload_end {
                return Err(Error::InvalidIndex);
            }
            b[at + off..at + off + data.len()].copy_from_slice(data);
        }
        _ => return Err(Error::Unsupported),
    }
    validate_index(b, head)
}

// ntfs.sys!NtOfsRestartUpdateRelativeDataInIndex reads the u16 data offset
// at the beginning of the selected index entry, then adds a logged 32- or
// 64-bit delta to the value at entry+offset. Opcode 0x23 selects an index
// root; 0x24 selects an INDX allocation block. The caller supplies the exact
// entry boundary from the log, so no byte-pattern search is involved.
fn relative_index_action(b: &mut [u8], head: usize, at: usize, data: &[u8]) -> Result<()> {
    validate_index(b, head)?;
    let used = u32_at(b, head + 4)? as usize;
    let mut cursor = head + u32_at(b, head)? as usize;
    while cursor < at {
        cursor += entry_size(b, cursor, head + used)?;
    }
    if cursor != at || at >= head + used || !matches!(data.len(), 4 | 8) {
        return Err(Error::InvalidIndex);
    }
    let size = entry_size(b, at, head + used)?;
    let flags = u16_at(b, at + 12)?;
    if flags & 2 != 0 {
        return Err(Error::InvalidIndex);
    }
    let offset = u16_at(b, at)? as usize;
    let length = u16_at(b, at + 2)? as usize;
    let payload_end = size - if flags & 1 != 0 { 8 } else { 0 };
    if offset < 16 + usize::from(u16_at(b, at + 10)?)
        || length < data.len()
        || offset.checked_add(length).is_none_or(|end| end > payload_end)
    {
        return Err(Error::InvalidIndex);
    }
    let field = at + offset;
    if data.len() == 4 {
        p32(b, field, u32_at(b, field)?.wrapping_add(u32_at(data, 0)?))?;
    } else {
        p64(b, field, u64_at(b, field)?.wrapping_add(u64_at(data, 0)?))?;
    }
    validate_index(b, head)
}

/// Apply exactly once; the caller controls redo LSN and undo-chain ordering.
/// Failure leaves target unchanged. Both buffers contain decoded bytes.
pub fn apply(target: &mut [u8], scratch: &mut [u8], op: NtfsLogOperation<'_>, undo: bool, index: bool) -> Result<()> {
    let work = scratch.get_mut(..target.len()).ok_or(Error::Truncated)?;
    work.copy_from_slice(target);
    let code = if undo { op.undo_code } else { op.redo_code };
    if code == 0 {
        // Noop: for example the undo of initializing a fresh index block.
        return Ok(());
    }
    let data = if undo { op.undo } else { op.redo };
    if matches!(code, 35 | 36) && op.redo_code == op.undo_code {
        if op.redo.len() != op.undo.len() || !matches!(op.redo.len(), 4 | 8) {
            return Err(Error::Unsupported);
        }
        let inverse = if op.redo.len() == 4 {
            u32_at(op.redo, 0)?.wrapping_add(u32_at(op.undo, 0)?) == 0
        } else {
            u64_at(op.redo, 0)?.wrapping_add(u64_at(op.undo, 0)?) == 0
        };
        if !inverse {
            return Err(Error::Unsupported);
        }
    }
    let ro = usize::from(op.record_offset);
    let ao = usize::from(op.attribute_offset);
    if index {
        if code == 8 {
            if ao != 0 || ro + data.len() > work.len() {
                return Err(Error::InvalidIndex);
            }
            work[ro..ro + data.len()].copy_from_slice(data);
            if work.get(..4) != Some(b"INDX") {
                return Err(Error::InvalidIndex);
            }
            validate_index(work, 24)?;
        } else if code == 36 {
            if work.get(..4) != Some(b"INDX") || ro != 0 {
                return Err(Error::Unsupported);
            }
            relative_index_action(work, 24, ao, data)?;
        } else {
            if work.get(..4) != Some(b"INDX") || ro != 0 {
                return Err(Error::Unsupported);
            }
            index_action(work, 24, ao, code, data)?;
        }
    } else {
        if code != 2 {
            validate_mft(work)?;
        }
        let used = u32_at(work, 24)? as usize;
        match code {
            0 => {}
            2 => {
                if ro + data.len() > work.len() || data.is_empty() {
                    return Err(Error::InvalidRecord);
                }
                work[ro..ro + data.len()].copy_from_slice(data);
            }
            3 => {
                let flags = u16_at(work, 22)?;
                p16(work, 22, flags & !1)?;
                let seq = ntfs_rs::mft::next_sequence(work)?;
                p16(work, 16, seq)?;
            }
            4 => {
                if ro < usize::from(u16_at(work, 20)?) || ro + data.len() > work.len() {
                    return Err(Error::InvalidRecord);
                }
                work[ro..ro + data.len()].copy_from_slice(data);
                p32(work, 24, ((ro + data.len() + 7) & !7) as u32)?;
            }
            5 => {
                let end_marker = ro + 8 <= used && u32_at(work, ro)? == u32::MAX;
                if !end_marker {
                    attr(work, ro)?;
                }
                if data.len() < 24 || u32_at(data, 4)? as usize != data.len() || data.len() % 8 != 0 {
                    return Err(Error::InvalidAttribute);
                }
                let size = replace(work, used, ro, 0, data)?;
                p32(work, 24, size as u32)?;
                let next = u16_at(work, 40)?.max(u16_at(data, 14)?.checked_add(1).ok_or(Error::Overflow)?);
                p16(work, 40, next)?;
                if u32_at(data, 0)? == 0x30 {
                    let links = u16_at(work, 18)?.checked_add(1).ok_or(Error::Overflow)?;
                    p16(work, 18, links)?;
                }
            }
            6 => {
                let (kind, len, _) = attr(work, ro)?;
                let size = replace(work, used, ro, len, &[])?;
                p32(work, 24, size as u32)?;
                if kind == 0x30 {
                    let links = u16_at(work, 18)?.checked_sub(1).ok_or(Error::InvalidRecord)?;
                    p16(work, 18, links)?;
                }
            }
            7 => {
                let (_, len, nonresident) = attr(work, ro)?;
                if nonresident {
                    return Err(Error::InvalidAttribute);
                }
                let vo = usize::from(u16_at(work, ro + 20)?);
                let value = u32_at(work, ro + 16)? as usize;
                if ao < vo || ao > vo + value {
                    return Err(Error::InvalidAttribute);
                }
                // Native UpdateResidentValue: equal lengths overwrite; unequal
                // lengths replace the suffix, setting its new end to ao+dlen.
                // Undo contains the old suffix, not an arbitrary splice range.
                let resizing = op.redo.len() != op.undo.len();
                if !resizing && ao + data.len() > vo + value {
                    return Err(Error::InvalidAttribute);
                }
                let new_value = if resizing { ao + data.len() - vo } else { value };
                let new_len = (vo + new_value + 7) & !7;
                if new_len > len {
                    resize_attr(work, ro, new_len)?;
                }
                work[ro + ao..ro + ao + data.len()].copy_from_slice(data);
                if new_len < len {
                    resize_attr(work, ro, new_len)?;
                }
                p32(work, ro + 16, new_value as u32)?;
            }
            9 => {
                let (_, _, nr) = attr(work, ro)?;
                let run = usize::from(u16_at(work, ro + 32)?);
                if !nr || ao < run || data.is_empty() {
                    return Err(Error::InvalidRunlist);
                }
                resize_attr(work, ro, (ao + data.len() + 7) & !7)?;
                work[ro + ao..ro + ao + data.len()].copy_from_slice(data);
                let mut next = u64_at(work, ro + 16)?;
                for r in DataRuns::new(&work[ro + run..ro + u32_at(work, ro + 4)? as usize], next) {
                    let r = r?;
                    next = next.checked_add(r.len).ok_or(Error::Overflow)?;
                }
                p64(work, ro + 24, next.wrapping_sub(1))?;
            }
            11 => {
                let (_, len, nr) = attr(work, ro)?;
                if !nr || !matches!(data.len(), 24 | 32) || len < 64 || (data.len() == 32 && len < 72) {
                    return Err(Error::InvalidAttribute);
                }
                p64(work, ro + 40, u64_at(data, 0)?)?;
                p64(work, ro + 48, u64_at(data, 16)?)?;
                p64(work, ro + 56, u64_at(data, 8)?)?;
                if data.len() == 32 {
                    p64(work, ro + 64, u64_at(data, 24)?)?;
                }
            }
            37 => {
                if ro < used || ro + data.len() > work.len() {
                    return Err(Error::InvalidRecord);
                }
                work[ro..ro + data.len()].fill(0);
            }
            12 | 13 | 17 | 19 | 33 | 35 => {
                let (kind, len, nr) = attr(work, ro)?;
                if kind != 0x90 || nr {
                    return Err(Error::InvalidIndex);
                }
                let vo = usize::from(u16_at(work, ro + 20)?);
                let head = ro + vo + 16;
                let value = u32_at(work, ro + 16)? as usize;
                let change = if code == 12 {
                    data.len() as isize
                } else if code == 13 {
                    -(entry_size(work, ro + ao, head + u32_at(work, head + 4)? as usize)? as isize)
                } else {
                    0
                };
                if change > 0 {
                    resize_attr(work, ro, len + change as usize)?;
                    p32(work, head + 8, u32_at(work, head + 8)? + change as u32)?;
                }
                if code == 35 {
                    relative_index_action(work, head, ro + ao, data)?;
                } else {
                    index_action(work, head, ro + ao, code, data)?;
                }
                if change < 0 {
                    p32(work, head + 8, (u32_at(work, head + 8)? as isize + change) as u32)?;
                    resize_attr(work, ro, (len as isize + change) as usize)?;
                }
                p32(work, ro + 16, (value as isize + change) as u32)?;
            }
            _ => return Err(Error::Unsupported),
        }
        validate_mft(work)?;
    }
    target.copy_from_slice(work);
    Ok(())
}
