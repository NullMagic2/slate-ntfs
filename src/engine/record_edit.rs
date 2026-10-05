//! Module: ntfs_rs::record_edit
//! Purpose: Build and edit checked MFT record images and mapping descriptors.
//! Created: 2026-09-30
//! Architecture: Mounted transactions and offline repair planners edit their
//!     caller-owned images here. Shared parsers validate layouts; callers own
//!     allocation, family ownership, fixup protection and durable publication.

use super::allocation::encode_runs_at;
pub use super::bytes::{p16, p32, p64};
use super::bytes::{u16_at, u32_at, u64_at};
use super::mft::{attribute_layout as af, record_layout as rf, Attribute, MftRecord};
use super::runlist::{encode_mapping_pair as encode_extent, mapping_pair_widths};
use super::runlist::{DataRuns, Extent};
use super::{Error, Result};

pub fn used(rec: &[u8]) -> Result<usize> {
    Ok(u32_at(rec, 24)? as usize)
}
pub fn capacity(rec: &[u8]) -> Result<usize> {
    let n = u32_at(rec, rf::CAPACITY_OFFSET)? as usize;
    if n > rec.len() || n < 512 {
        return Err(Error::InvalidRecord);
    }
    Ok(n)
}
pub fn attr_len(rec: &[u8], at: usize) -> Result<usize> {
    Ok(u32_at(rec, at + af::LENGTH_OFFSET)? as usize)
}
pub fn attr_kind(rec: &[u8], at: usize) -> Result<u32> {
    u32_at(rec, at)
}
pub fn is_nonresident(rec: &[u8], at: usize) -> Result<bool> {
    Ok(*rec.get(at + af::NONRESIDENT_OFFSET).ok_or(Error::Truncated)? != 0)
}
pub fn attr_name(rec: &[u8], at: usize) -> Result<&[u8]> {
    let chars = usize::from(*rec.get(at + af::NAME_LENGTH_OFFSET).ok_or(Error::Truncated)?);
    let off = usize::from(u16_at(rec, at + af::NAME_OFFSET_OFFSET)?);
    rec.get(at + off..at + off + chars * 2).ok_or(Error::InvalidAttribute)
}

/// Attribute IDs validate tracks in a stack table; later ones are checked
/// by rescanning the record.
const RECENT_IDS: usize = 128;

/// Whether an attribute before offset at already carries this id.
fn id_before(record: &MftRecord<'_>, at: usize, id: u16) -> Result<bool> {
    for entry in record.attributes() {
        let a = entry?;
        if a.record_offset() >= at {
            return Ok(false);
        }
        if a.id == id {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Structural validation shared by every edit: sorted attribute types,
/// unique IDs, bounded values and runlists, and a terminating end marker.
pub fn validate(rec: &[u8]) -> Result<()> {
    let record = MftRecord::from_decoded(rec)?;
    let cap = capacity(rec)?;
    if used(rec)? > cap || used(rec)? % 8 != 0 {
        return Err(Error::InvalidRecord);
    }
    let mut previous = 0;
    let mut ids = [0_u16; RECENT_IDS];
    let mut count = 0;
    let mut end = 0;
    for entry in record.attributes() {
        let a = entry?;
        // An assembled family of a file with many hard links holds more
        // attributes than the stack-sized table: rescan only past its end.
        let repeated = if count < ids.len() {
            ids[..count].contains(&a.id)
        } else {
            id_before(&record, a.record_offset(), a.id)?
        };
        if a.kind < previous || repeated {
            return Err(Error::InvalidAttribute);
        }
        previous = a.kind;
        if count < ids.len() {
            ids[count] = a.id;
        }
        count += 1;
        a.validate_value()?;
        end = a.record_offset() + attr_len(rec, a.record_offset())?;
    }
    let marker = if count == 0 { usize::from(u16_at(rec, 20)?) } else { end };
    if u32_at(rec, marker)? != u32::MAX || marker + 8 > used(rec)? {
        return Err(Error::InvalidRecord);
    }
    Ok(())
}

fn names_order(a_kind: u32, a_name: &[u8], b_kind: u32, b_name: &[u8]) -> core::cmp::Ordering {
    // NTFS orders attributes by type, then by name. The names this engine
    // creates ($I30, $SDH, $SII) are ASCII, where binary UTF-16 order after
    // ASCII upcasing is identical to $UpCase collation.
    a_kind.cmp(&b_kind).then_with(|| {
        let up = |c: u16| if (97..=122).contains(&c) { c - 32 } else { c };
        let a = a_name.chunks_exact(2).map(|c| up(u16::from_le_bytes([c[0], c[1]])));
        let b = b_name.chunks_exact(2).map(|c| up(u16::from_le_bytes([c[0], c[1]])));
        a.cmp(b)
    })
}

/// Locate an attribute confirmed to live wholly in this record.
pub fn find(rec: &[u8], kind: u32, name: &[u8]) -> Result<Option<usize>> {
    Ok(MftRecord::from_decoded(rec)?.local_attribute(kind, name)?.map(|a| a.record_offset()))
}

pub fn require(rec: &[u8], kind: u32, name: &[u8]) -> Result<usize> {
    find(rec, kind, name)?.ok_or(Error::InvalidAttribute)
}

pub fn resident_value(rec: &[u8], at: usize) -> Result<&[u8]> {
    if is_nonresident(rec, at)? {
        return Err(Error::InvalidAttribute);
    }
    let len = u32_at(rec, at + 16)? as usize;
    let off = usize::from(u16_at(rec, at + 20)?);
    rec.get(at + off..at + off + len).ok_or(Error::InvalidAttribute)
}
pub fn resident_value_offset(rec: &[u8], at: usize) -> Result<usize> {
    resident_value(rec, at)?;
    Ok(at + usize::from(u16_at(rec, at + 20)?))
}

/// Change one attribute's allocated length, moving later attributes.
fn resize_raw(rec: &mut [u8], at: usize, new: usize) -> Result<()> {
    let old = attr_len(rec, at)?;
    let used = used(rec)?;
    let cap = capacity(rec)?;
    let new_used = used.checked_sub(old).and_then(|n| n.checked_add(new)).ok_or(Error::Overflow)?;
    if new % 8 != 0 || at + old > used {
        return Err(Error::InvalidAttribute);
    }
    if new_used > cap {
        return Err(Error::NoSpace);
    }
    rec.copy_within(at + old..used, at + new);
    if new > old {
        rec[at + old..at + new].fill(0);
    } else {
        rec[new_used..used].fill(0);
    }
    p32(rec, 24, new_used as u32)?;
    p32(rec, at + af::LENGTH_OFFSET, new as u32)
}

/// Replace a resident attribute value, resizing the attribute as needed.
pub fn set_resident_value(rec: &mut [u8], at: usize, value: &[u8]) -> Result<()> {
    if is_nonresident(rec, at)? {
        return Err(Error::InvalidAttribute);
    }
    let off = usize::from(u16_at(rec, at + 20)?);
    let new_len = (off + value.len() + 7) & !7;
    let old_len = attr_len(rec, at)?;
    if new_len != old_len {
        resize_raw(rec, at, new_len)?;
    }
    rec[at + off..at + off + value.len()].copy_from_slice(value);
    rec[at + off + value.len()..at + new_len].fill(0);
    p32(rec, at + 16, value.len() as u32)
}

/// Insert a complete attribute image in NTFS order and assign a fresh ID.
/// Returns its record offset.
pub fn insert(rec: &mut [u8], attribute: &[u8]) -> Result<usize> {
    let len = attribute.len();
    if len < 24 || len % 8 != 0 || u32_at(attribute, 4)? as usize != len {
        return Err(Error::InvalidAttribute);
    }
    let kind = u32_at(attribute, 0)?;
    let chars = usize::from(attribute[9]);
    let noff = usize::from(u16_at(attribute, 10)?);
    let name = attribute.get(noff..noff + chars * 2).ok_or(Error::InvalidAttribute)?;
    let mut at = usize::from(u16_at(rec, 20)?);
    for a in MftRecord::from_decoded(rec)?.attributes() {
        let a = a?;
        match names_order(a.kind, a.name_utf16le()?, kind, name) {
            core::cmp::Ordering::Less => at = a.record_offset() + attr_len(rec, a.record_offset())?,
            core::cmp::Ordering::Equal if kind == 0x30 => {
                at = a.record_offset() + attr_len(rec, a.record_offset())?;
            }
            core::cmp::Ordering::Equal => return Err(Error::InvalidAttribute),
            core::cmp::Ordering::Greater => break,
        }
    }
    let used = used(rec)?;
    if used + len > capacity(rec)? {
        return Err(Error::NoSpace);
    }
    let id = u16_at(rec, 40)?;
    if id == u16::MAX {
        return Err(Error::NoSpace);
    }
    rec.copy_within(at..used, at + len);
    rec[at..at + len].copy_from_slice(attribute);
    p16(rec, at + af::ID_OFFSET, id)?;
    p16(rec, 40, id + 1)?;
    p32(rec, 24, (used + len) as u32)?;
    Ok(at)
}

pub fn remove(rec: &mut [u8], at: usize) -> Result<()> {
    let len = attr_len(rec, at)?;
    let used = used(rec)?;
    if at + len > used {
        return Err(Error::InvalidAttribute);
    }
    rec.copy_within(at + len..used, at);
    rec[used - len..used].fill(0);
    p32(rec, 24, (used - len) as u32)
}

/// Build a resident attribute image without an ID. Returns its length.
pub fn build_resident(kind: u32, name: &[u8], value: &[u8], out: &mut [u8]) -> Result<usize> {
    let noff = 24;
    let voff = (noff + name.len() + 7) & !7;
    let len = (voff + value.len() + 7) & !7;
    if name.len() % 2 != 0 || name.len() > 510 || len > out.len() {
        return Err(Error::Unsupported);
    }
    out[..len].fill(0);
    p32(out, 0, kind)?;
    p32(out, 4, len as u32)?;
    out[9] = (name.len() / 2) as u8;
    p16(out, 10, if name.is_empty() { 0 } else { noff as u16 })?;
    p32(out, 16, value.len() as u32)?;
    p16(out, 20, voff as u16)?;
    // $FILE_NAME participates in its parent's directory index. Windows
    // rejects an unindexed filename attribute even when its value is valid.
    out[22] = u8::from(kind == 0x30);
    out[noff..noff + name.len()].copy_from_slice(name);
    out[voff..voff + value.len()].copy_from_slice(value);
    Ok(len)
}

/// Merge a checked on-disk attribute into a caller-owned logical record.
/// Nonresident continuation segments must be contiguous and have equal flags.
pub fn merge_attribute(rec: &mut [u8], raw: &[u8]) -> Result<()> {
    let kind = u32_at(raw, 0)?;
    let name = attr_name(raw, 0)?;
    if kind == 0x30 {
        insert(rec, raw)?;
        return Ok(());
    }
    if let Some(at) = find(rec, kind, name)? {
        if !is_nonresident(rec, at)?
            || raw[8] == 0
            || u16_at(rec, at + 12)? != u16_at(raw, 12)?
            || u64_at(rec, at + 24)?.checked_add(1) != Some(u64_at(raw, 16)?)
        {
            return Err(Error::InvalidAttributeList);
        }
        append_mapping_segment(rec, at, raw)?;
    } else {
        if raw[8] != 0 && u64_at(raw, 16)? != 0 {
            return Err(Error::InvalidAttributeList);
        }
        insert(rec, raw)?;
    }
    Ok(())
}

/// Build a nonresident attribute image starting at VCN zero.
pub fn build_nonresident(
    kind: u32,
    name: &[u8],
    runs: &[Extent],
    allocated: u64,
    data: u64,
    initialized: u64,
    out: &mut [u8],
) -> Result<usize> {
    build_nonresident_at(kind, name, runs, 0, allocated, data, initialized, out)
}

/// Build one physical segment of a nonresident stream. Continuation segments
/// retain the stream's full sizes while their mapping pairs start at first_vcn.
pub fn build_nonresident_at(
    kind: u32,
    name: &[u8],
    runs: &[Extent],
    first_vcn: u64,
    allocated: u64,
    data: u64,
    initialized: u64,
    out: &mut [u8],
) -> Result<usize> {
    let noff = af::EXTENDED_HEADER_BYTES;
    let roff = (noff + name.len() + af::ALIGNMENT - 1) & !(af::ALIGNMENT - 1);
    if name.len() % 2 != 0 || name.len() > 510 || roff >= out.len() {
        return Err(Error::Unsupported);
    }
    out.fill(0);
    let n = encode_runs_at(first_vcn, runs, &mut out[roff..])?;
    let len = (roff + n + af::ALIGNMENT - 1) & !(af::ALIGNMENT - 1);
    if len > out.len() {
        return Err(Error::NoSpace);
    }
    let clusters = runs.iter().try_fold(0_u64, |sum, run| sum.checked_add(run.len)).ok_or(Error::Overflow)?;
    p32(out, af::TYPE_OFFSET, kind)?;
    p32(out, af::LENGTH_OFFSET, len as u32)?;
    out[af::NONRESIDENT_OFFSET] = 1;
    out[af::NAME_LENGTH_OFFSET] = (name.len() / 2) as u8;
    p16(out, af::NAME_OFFSET_OFFSET, if name.is_empty() { 0 } else { noff as u16 })?;
    p64(out, af::FIRST_VCN_OFFSET, first_vcn)?;
    p64(out, af::LAST_VCN_OFFSET, first_vcn.checked_add(clusters).ok_or(Error::Overflow)?.wrapping_sub(1))?;
    p16(out, af::MAPPING_PAIRS_OFFSET, roff as u16)?;
    p64(out, af::ALLOCATED_SIZE_OFFSET, allocated)?;
    p64(out, af::DATA_SIZE_OFFSET, data)?;
    p64(out, af::INITIALIZED_SIZE_OFFSET, initialized)?;
    if runs.iter().any(|r| r.lcn.is_none()) {
        p16(out, af::FLAGS_OFFSET, af::SPARSE)?;
        p64(out, af::COMPRESSED_SIZE_OFFSET, allocated)?;
    }
    out[noff..noff + name.len()].copy_from_slice(name);
    Ok(len)
}

/// Decode a nonresident attribute's runs. Sparse runs are refused because
/// no metadata stream edited here may be sparse.
pub fn runs(rec: &[u8], at: usize, out: &mut [Extent]) -> Result<usize> {
    if !is_nonresident(rec, at)? {
        return Err(Error::InvalidAttribute);
    }
    let first = u64_at(rec, at + 16)?;
    let roff = usize::from(u16_at(rec, at + 32)?);
    let len = attr_len(rec, at)?;
    let bytes = rec.get(at + roff..at + len).ok_or(Error::InvalidAttribute)?;
    let mut n = 0;
    for run in DataRuns::new(bytes, first) {
        let run = run?;
        if run.lcn.is_none() {
            return Err(Error::Unsupported);
        }
        if n == out.len() {
            return Err(Error::Unsupported);
        }
        out[n] = run;
        n += 1;
    }
    Ok(n)
}

/// Decode the final runs of a nonresident attribute into out, oldest first,
/// without a table of the whole mapping. Returns how many were stored.
pub fn tail_runs(rec: &[u8], at: usize, out: &mut [Extent]) -> Result<usize> {
    if !is_nonresident(rec, at)? || out.is_empty() {
        return Err(Error::InvalidAttribute);
    }
    let first = u64_at(rec, at + 16)?;
    let roff = usize::from(u16_at(rec, at + 32)?);
    let bytes = rec.get(at + roff..at + attr_len(rec, at)?).ok_or(Error::InvalidAttribute)?;
    let mut n = 0;
    for run in DataRuns::new(bytes, first) {
        let run = run?;
        if run.lcn.is_none() {
            return Err(Error::Unsupported);
        }
        if n == out.len() {
            out.copy_within(1.., 0);
            n -= 1;
        }
        out[n] = run;
        n += 1;
    }
    Ok(n)
}

/// Replace mapping pairs of a nonresident attribute. Sizes stay with caller.
pub fn set_runs(rec: &mut [u8], at: usize, runs: &[Extent]) -> Result<()> {
    if !is_nonresident(rec, at)? {
        return Err(Error::InvalidAttribute);
    }
    let first = u64_at(rec, at + 16)?;
    let roff = usize::from(u16_at(rec, at + 32)?);
    // Preflight mapping pairs without a fixed temporary buffer. The second
    // pass encodes directly into the resized attribute after every possible
    // layout and arithmetic failure has been checked.
    let mut n = 1_usize; // terminator
    let mut previous = 0_i64;
    let mut vcn = first;
    for run in runs {
        if run.vcn != vcn || run.len == 0 || run.len > i64::MAX as u64 {
            return Err(Error::InvalidRunlist);
        }
        let lcn = run.lcn.map(i64::try_from).transpose().map_err(|_| Error::Overflow)?.unwrap_or(previous);
        let delta = lcn.checked_sub(previous).ok_or(Error::Overflow)?;
        let (length_bytes, delta_bytes) = mapping_pair_widths(run.len, run.lcn.map(|_| delta))?;
        n = n.checked_add(1 + length_bytes + delta_bytes).ok_or(Error::Overflow)?;
        previous = lcn;
        vcn = vcn.checked_add(run.len).ok_or(Error::Overflow)?;
    }
    let new_len = roff.checked_add(n).and_then(|length| length.checked_add(7)).ok_or(Error::Overflow)? & !7;
    let old_len = attr_len(rec, at)?;
    let new_used =
        used(rec)?.checked_sub(old_len).and_then(|length| length.checked_add(new_len)).ok_or(Error::Overflow)?;
    if new_used > capacity(rec)? || rec.get(at + 24..at + 32).is_none() {
        return Err(Error::NoSpace);
    }
    resize_raw(rec, at, new_len)?;
    rec[at + roff..at + new_len].fill(0);
    let written = encode_runs_at(first, runs, &mut rec[at + roff..at + new_len])?;
    if written != n {
        return Err(Error::InvalidRunlist);
    }
    p64(rec, at + 24, vcn.wrapping_sub(1))
}

pub fn sizes(rec: &[u8], at: usize) -> Result<(u64, u64, u64)> {
    if !is_nonresident(rec, at)? {
        return Err(Error::InvalidAttribute);
    }
    Ok((
        u64_at(rec, at + af::ALLOCATED_SIZE_OFFSET)?,
        u64_at(rec, at + af::DATA_SIZE_OFFSET)?,
        u64_at(rec, at + af::INITIALIZED_SIZE_OFFSET)?,
    ))
}
pub fn set_sizes(rec: &mut [u8], at: usize, allocated: u64, data: u64, initialized: u64) -> Result<()> {
    if !is_nonresident(rec, at)? || initialized > data || data > allocated {
        return Err(Error::InvalidAttribute);
    }
    p64(rec, at + af::ALLOCATED_SIZE_OFFSET, allocated)?;
    p64(rec, at + af::DATA_SIZE_OFFSET, data)?;
    p64(rec, at + af::INITIALIZED_SIZE_OFFSET, initialized)?;
    if u16_at(rec, at + 12)? & 0x8001 != 0 {
        let roff = usize::from(u16_at(rec, at + 32)?);
        if roff < 72 {
            return Err(Error::InvalidAttribute);
        }
        // The clusters with storage, as a share of the allocation: the
        // mapping covers the whole allocated size.
        let (mut physical, mut covered) = (0u64, 0u64);
        for r in DataRuns::new(&rec[at + roff..at + attr_len(rec, at)?], u64_at(rec, at + 16)?) {
            let r = r?;
            covered = covered.checked_add(r.len).ok_or(Error::Overflow)?;
            if r.lcn.is_some() {
                physical = physical.checked_add(r.len).ok_or(Error::Overflow)?;
            }
        }
        let cluster = allocated.checked_div(covered).unwrap_or(0);
        p64(rec, at + 64, physical.checked_mul(cluster).ok_or(Error::Overflow)?)?;
    }
    Ok(())
}

/// One decoded mapping pair: encoded size, run length and LCN delta.
struct Pair {
    size: usize,
    length: u64,
    delta: i64,
    sparse: bool,
}

/// Decode the mapping pair at cursor; None at the terminator. Sparse
/// pairs have no offset and preserve the previous physical LCN.
fn pair(rec: &[u8], cursor: usize, end: usize) -> Result<Option<Pair>> {
    let header = *rec.get(cursor).ok_or(Error::InvalidRunlist)?;
    if header == 0 {
        return Ok(None);
    }
    let len_bytes = usize::from(header & 0x0f);
    let off_bytes = usize::from(header >> 4);
    if len_bytes == 0 || len_bytes > 8 || off_bytes > 8 {
        return Err(Error::Unsupported);
    }
    let size = 1 + len_bytes + off_bytes;
    if cursor + size > end {
        return Err(Error::InvalidRunlist);
    }
    let body = &rec[cursor + 1..cursor + size];
    let mut length = [0_u8; 8];
    length[..len_bytes].copy_from_slice(&body[..len_bytes]);
    let length = u64::from_le_bytes(length);
    if length == 0 || body[len_bytes - 1] & 0x80 != 0 {
        return Err(Error::InvalidRunlist);
    }
    let mut delta = [0_u8; 8];
    delta[..off_bytes].copy_from_slice(&body[len_bytes..]);
    if off_bytes != 0 && body[len_bytes + off_bytes - 1] & 0x80 != 0 {
        delta[off_bytes..].fill(0xff);
    }
    Ok(Some(Pair { size, length, delta: i64::from_le_bytes(delta), sparse: off_bytes == 0 }))
}

/// Drop every cluster at or after VCN keep from the mapping pairs, in place
/// and without a run table (any run count). The attribute shrinks; sizes stay
/// with the caller.
pub fn truncate_runs(rec: &mut [u8], at: usize, keep: u64) -> Result<()> {
    if !is_nonresident(rec, at)? || keep < u64_at(rec, at + 16)? {
        return Err(Error::InvalidAttribute);
    }
    let roff = usize::from(u16_at(rec, at + 32)?);
    let old_len = attr_len(rec, at)?;
    let end = at + old_len;
    let mut cursor = at + roff;
    let mut vcn = u64_at(rec, at + 16)?;
    let mut cut = None;
    while let Some(p) = pair(rec, cursor, end)? {
        if vcn >= keep {
            cut = Some(cursor);
            break;
        }
        if vcn + p.length > keep {
            let mut run = [0_u8; 20];
            let n = encode_extent(keep - vcn, if p.sparse { None } else { Some(p.delta) }, &mut run)?;
            rec[cursor..cursor + n].copy_from_slice(&run[..n]);
            cut = Some(cursor + n);
            break;
        }
        vcn += p.length;
        cursor += p.size;
    }
    let Some(cut) = cut else {
        return Ok(());
    };
    rec[cut..end].fill(0);
    let needed = (cut + 1 - at + 7) & !7;
    if needed < old_len {
        resize_raw(rec, at, needed)?;
    }
    p64(rec, at + 24, keep.wrapping_sub(1))
}

/// Join a checked continuation in two streaming passes. Repeatedly calling
/// append_extent rescans all previous runs for each new run, making fragmented
/// file reads and writes quadratic. Preflight capacity and arithmetic before
/// resizing; then rebase each delta directly into the destination mapping.
fn append_mapping_segment(rec: &mut [u8], at: usize, raw: &[u8]) -> Result<()> {
    let mut cursor = at + usize::from(u16_at(rec, at + 32)?);
    let end = at + attr_len(rec, at)?;
    let mut previous = 0_i64;
    while let Some(pair) = pair(rec, cursor, end)? {
        if !pair.sparse {
            previous = previous.checked_add(pair.delta).ok_or(Error::Overflow)?;
        }
        cursor += pair.size;
    }
    let origin = previous;
    let first_vcn = u64_at(raw, 16)?;
    let mapping = &raw[usize::from(u16_at(raw, 32)?)..attr_len(raw, 0)?];
    let mut next_vcn = first_vcn;
    let mut encoded = [0_u8; 20];
    let mut bytes = 0_usize;
    for run in DataRuns::new(mapping, first_vcn) {
        let run = run?;
        let lcn = run.lcn.map(i64::try_from).transpose().map_err(|_| Error::Overflow)?;
        let delta = lcn.map(|lcn| lcn.checked_sub(previous).ok_or(Error::Overflow)).transpose()?;
        bytes = bytes.checked_add(encode_extent(run.len, delta, &mut encoded)?).ok_or(Error::Overflow)?;
        next_vcn = next_vcn.checked_add(run.len).ok_or(Error::Overflow)?;
        if let Some(lcn) = lcn {
            previous = lcn;
        }
    }
    if next_vcn.checked_sub(1) != Some(u64_at(raw, 24)?) {
        return Err(Error::InvalidRunlist);
    }
    let needed = cursor
        .checked_add(bytes)
        .and_then(|end| end.checked_add(8))
        .and_then(|end| end.checked_sub(at))
        .ok_or(Error::Overflow)?
        & !7;
    resize_raw(rec, at, needed)?;

    previous = origin;
    for run in DataRuns::new(mapping, first_vcn) {
        let run = run?;
        let lcn = run.lcn.map(i64::try_from).transpose().map_err(|_| Error::Overflow)?;
        let delta = lcn.map(|lcn| lcn - previous);
        let length = encode_extent(run.len, delta, &mut encoded)?;
        rec[cursor..cursor + length].copy_from_slice(&encoded[..length]);
        cursor += length;
        if let Some(lcn) = lcn {
            previous = lcn;
        }
    }
    rec[cursor..at + needed].fill(0);
    p64(rec, at + 24, next_vcn - 1)
}

/// Pack whole mapping pairs up to the caller's byte limit, rather than a
/// fixed run count. Each physical segment resets its signed LCN delta origin.
/// Returns the encoded size and the first VCN for the next segment.
pub(crate) fn pack_mapping_segment(source: Attribute<'_>, first_vcn: u64, out: &mut [u8]) -> Result<(usize, u64)> {
    let mut end = build_nonresident_at(
        source.kind,
        source.name_utf16le()?,
        &[],
        first_vcn,
        source.allocated_size()?,
        source.data_size()?,
        source.initialized_size()?,
        out,
    )?;
    p16(out, 12, source.flags()?)?;
    p16(out, 34, u16_at(source.raw(), 34)?)?;
    if source.flags()? & 0x8001 != 0 {
        p64(out, 64, u64_at(source.raw(), 64)?)?;
    }

    let mut cursor = usize::from(u16_at(out, 32)?);
    let mut next_vcn = first_vcn;
    let mut previous_lcn = 0_i64;
    let mut encoded = [0_u8; 20];
    for run in DataRuns::new(source.data_runs()?, source.first_vcn()?) {
        let run = run?;
        if run.vcn < first_vcn {
            continue;
        }
        if run.vcn != next_vcn {
            return Err(Error::InvalidRunlist);
        }
        let lcn = run.lcn.map(i64::try_from).transpose().map_err(|_| Error::Overflow)?;
        let delta = lcn.map(|lcn| lcn.checked_sub(previous_lcn).ok_or(Error::Overflow)).transpose()?;
        let bytes = encode_extent(run.len, delta, &mut encoded)?;
        let needed = cursor.checked_add(bytes + 8).ok_or(Error::Overflow)? & !7;
        if needed > out.len() {
            break;
        }
        out[cursor..cursor + bytes].copy_from_slice(&encoded[..bytes]);
        cursor += bytes;
        end = needed;
        next_vcn = next_vcn.checked_add(run.len).ok_or(Error::Overflow)?;
        if let Some(lcn) = lcn {
            previous_lcn = lcn;
        }
    }
    if next_vcn == first_vcn {
        return Err(Error::NoSpace);
    }
    out[cursor..end].fill(0);
    p32(out, 4, end as u32)?;
    p64(out, 24, next_vcn - 1)?;
    Ok((end, next_vcn))
}

/// Physical cluster just after the final run, used as an allocation hint.
pub fn last_run_end(rec: &[u8], at: usize) -> Result<Option<u64>> {
    if !is_nonresident(rec, at)? {
        return Err(Error::InvalidAttribute);
    }
    let start = at + usize::from(u16_at(rec, at + 32)?);
    let mut end = None;
    for run in DataRuns::new(&rec[start..at + attr_len(rec, at)?], u64_at(rec, at + 16)?) {
        let run = run?;
        end = run.lcn.map(|lcn| lcn.checked_add(run.len).ok_or(Error::Overflow)).transpose()?;
    }
    Ok(end)
}

/// Append clusters to the final extent of a nonresident attribute, merging
/// with the final run when physically contiguous. Streaming: no run table.
pub fn append_run(rec: &mut [u8], at: usize, lcn: u64, count: u64) -> Result<()> {
    append_extent(rec, at, Some(lcn), count)
}

/// Append either real clusters or an NTFS sparse mapping pair.
pub(crate) fn append_extent(rec: &mut [u8], at: usize, lcn: Option<u64>, count: u64) -> Result<()> {
    if count == 0 || lcn == Some(0) {
        return Err(Error::InvalidRunlist);
    }
    let first = u64_at(rec, at + 16)?;
    let roff = usize::from(u16_at(rec, at + 32)?);
    let end = at + attr_len(rec, at)?;
    let mut cursor = at + roff;
    let mut previous = 0i64;
    let mut vcn = first;
    let mut last = None;
    while let Some(p) = pair(rec, cursor, end)? {
        let prior = previous;
        if !p.sparse {
            previous = previous.checked_add(p.delta).ok_or(Error::Overflow)?;
        }
        if previous < 0 {
            return Err(Error::InvalidRunlist);
        }
        last = Some((cursor, p.length, if p.sparse { None } else { Some(previous as u64) }, prior));
        vcn = vcn.checked_add(p.length).ok_or(Error::Overflow)?;
        cursor += p.size;
    }
    let mut run = [0u8; 20];
    let (start, len, prior) = match last {
        Some((start, len, old, prior))
            if (old.is_none() && lcn.is_none()) || (old.is_some() && lcn == old.and_then(|n| n.checked_add(len))) =>
        {
            (start, len.checked_add(count).ok_or(Error::Overflow)?, prior)
        }
        _ => (cursor, count, previous),
    };
    let merged_lcn = if start != cursor { last.unwrap().2 } else { lcn };
    let delta = merged_lcn
        .map(|n| {
            i64::try_from(n).map_err(|_| Error::Overflow).and_then(|n| n.checked_sub(prior).ok_or(Error::Overflow))
        })
        .transpose()?;
    let n = encode_extent(len, delta, &mut run)?;
    let needed = (start + n + 1 - at + 7) & !7;
    if needed > attr_len(rec, at)? {
        resize_raw(rec, at, needed)?;
    }
    let stop = at + attr_len(rec, at)?;
    rec[start..start + n].copy_from_slice(&run[..n]);
    rec[start + n..stop].fill(0);
    p64(rec, at + 24, vcn.checked_add(count).ok_or(Error::Overflow)? - 1)?;
    if lcn.is_none() {
        p16(rec, at + 12, u16_at(rec, at + 12)? | 0x8000)?;
    }
    Ok(())
}

/// A formatted, unused NTFS 3.1 file record (decoded USA values).
/// Where the first attribute of an empty record of this size starts: after
/// the header and a fixup array with one entry for each stride and one more.
pub const fn first_attribute_offset(record_bytes: usize) -> usize {
    (0x30 + (record_bytes / 512 + 1) * 2 + 7) & !7
}

/// The largest attribute an empty record of this size holds before its
/// end marker.
pub const fn attribute_room(record_bytes: usize) -> usize {
    record_bytes - first_attribute_offset(record_bytes) - rf::END_MARKER_BYTES
}

pub fn format_empty(buf: &mut [u8], number: u64) -> Result<()> {
    let n = buf.len();
    if n < 512 || n % 512 != 0 {
        return Err(Error::InvalidRecord);
    }
    buf.fill(0);
    buf[..4].copy_from_slice(b"FILE");
    let count = n / 512 + 1;
    p16(buf, 4, 0x30)?;
    p16(buf, 6, count as u16)?;
    let first = first_attribute_offset(n);
    p16(buf, 16, 1)?; // sequence
    p16(buf, 20, first as u16)?;
    p32(buf, 24, (first + 8) as u32)?;
    p32(buf, 28, n as u32)?;
    p32(buf, 44, number as u32)?;
    p32(buf, first, u32::MAX)?;
    Ok(())
}

#[cfg(test)]
#[path = "../tests/core/record_edit.rs"]
mod tests;
