//! Module: ntfs_rs::write_plan
//! Purpose: Validated physical spans for an overwrite inside an existing data stream.
//! Created: 2026-10-01
//! Architecture: Writer operations use caller-owned scratch and delegate durable I/O to
//! adapters.

//! Validated physical spans for an overwrite inside an existing data stream.
//! This module never writes. A future caller must separately establish ACL
//! authorization, journal state, exclusive access, and transaction durability.

use super::boot::BootSector;
use super::mft::Attribute;
use super::runlist::DataRuns;
use super::{Error, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteSpan {
    pub physical_offset: u64,
    pub source_offset: u64,
    pub length: u64,
}

/// Validate the complete runlist before mapping initialized allocated bytes.
/// Resident, compressed, encrypted, extending, uninitialized and hole writes
/// are refused; allocated sparse runs are accepted. Mapping does not authorize writes.
pub fn plan_nonresident_overwrite(
    attribute: Attribute<'_>,
    boot: BootSector,
    offset: u64,
    length: u64,
    mut visitor: impl FnMut(WriteSpan) -> Result<()>,
) -> Result<u64> {
    map_nonresident(attribute, boot, offset, length, true, &mut visitor)
}

/// Map allocated metadata during journal replay, including pages whose valid
/// length is advanced by a later log record. Accepts one attribute extent.
/// This does not authorize writes; recovery must validate logged LCNs, owner
/// references and the completed metadata state before publishing its plan.
pub fn plan_nonresident_recovery(
    attribute: Attribute<'_>,
    boot: BootSector,
    offset: u64,
    length: u64,
    mut visitor: impl FnMut(WriteSpan) -> Result<()>,
) -> Result<u64> {
    map_nonresident(attribute, boot, offset, length, false, &mut visitor)
}

fn map_nonresident(
    attribute: Attribute<'_>,
    boot: BootSector,
    offset: u64,
    length: u64,
    initialized_only: bool,
    visitor: &mut impl FnMut(WriteSpan) -> Result<()>,
) -> Result<u64> {
    if !attribute.nonresident || (initialized_only && attribute.first_vcn()? != 0) || attribute.flags()? & !0x8000 != 0
    {
        return Err(Error::Unsupported);
    }
    let end = offset.checked_add(length).ok_or(Error::Overflow)?;
    let data_size = attribute.data_size()?;
    let initialized_size = attribute.initialized_size()?;
    if initialized_only && (initialized_size > data_size || end > initialized_size) {
        return Err(Error::InvalidAttribute);
    }
    let last_vcn = attribute.last_vcn()?;
    if last_vcn == u64::MAX {
        return if data_size == 0 && length == 0 { Ok(0) } else { Err(Error::InvalidRunlist) };
    }
    let cluster_bytes = u64::from(boot.cluster_bytes);
    let volume_bytes = boot.total_sectors.checked_mul(u64::from(boot.bytes_per_sector)).ok_or(Error::Overflow)?;
    let runs = attribute.data_runs()?;
    let first_vcn = attribute.first_vcn()?;
    let mut next_vcn = first_vcn;
    for entry in DataRuns::new(runs, first_vcn) {
        let run = entry?;
        if run.vcn != next_vcn || (run.lcn.is_none() && attribute.flags()? & 0x8000 == 0) {
            return Err(Error::InvalidRunlist);
        }
        next_vcn = next_vcn.checked_add(run.len).ok_or(Error::Overflow)?;
        if next_vcn > last_vcn + 1 {
            return Err(Error::InvalidRunlist);
        }
        if let Some(lcn) = run.lcn {
            let physical_end =
                lcn.checked_add(run.len).and_then(|n| n.checked_mul(cluster_bytes)).ok_or(Error::Overflow)?;
            if physical_end > volume_bytes {
                return Err(Error::InvalidRunlist);
            }
        } else {
            let start = run.vcn.checked_mul(cluster_bytes).ok_or(Error::Overflow)?;
            let stop = next_vcn.checked_mul(cluster_bytes).ok_or(Error::Overflow)?;
            if offset < stop && start < end {
                return Err(Error::InvalidRunlist);
            }
        }
    }
    if next_vcn != last_vcn + 1
        || (initialized_only && data_size > next_vcn.checked_mul(cluster_bytes).ok_or(Error::Overflow)?)
    {
        return Err(Error::InvalidRunlist);
    }
    let mut spans = 0_u64;
    let mut covered = 0_u64;
    for entry in DataRuns::new(runs, first_vcn) {
        let run = entry?;
        let run_start = run.vcn.checked_mul(cluster_bytes).ok_or(Error::Overflow)?;
        let run_end =
            run.vcn.checked_add(run.len).and_then(|vcn| vcn.checked_mul(cluster_bytes)).ok_or(Error::Overflow)?;
        let start = offset.max(run_start);
        let stop = end.min(run_end);
        if start >= stop {
            continue;
        }
        let physical_offset = run
            .lcn
            .ok_or(Error::InvalidRunlist)?
            .checked_mul(cluster_bytes)
            .and_then(|base| base.checked_add(start - run_start))
            .ok_or(Error::Overflow)?;
        let span = WriteSpan { physical_offset, source_offset: start - offset, length: stop - start };
        visitor(span)?;
        covered = covered.checked_add(span.length).ok_or(Error::Overflow)?;
        spans = spans.checked_add(1).ok_or(Error::Overflow)?;
    }
    if covered != length {
        return Err(Error::InvalidRunlist);
    }
    Ok(spans)
}

/// Maximum physical clusters occupied by an admitted metadata structure.
pub const METADATA_CLUSTERS: usize = super::boot::MAX_WRITER_RECORD_BYTES / super::boot::MIN_SECTOR_BYTES as usize;
pub(crate) const LCN_BYTES: usize = core::mem::size_of::<u64>();
pub(crate) const METADATA_MAP_BYTES: usize = METADATA_CLUSTERS * LCN_BYTES;

/// Retain actual LCNs for split metadata; contiguous mappings need no sidecar.
pub(crate) fn map_metadata(
    attr: Attribute<'_>,
    boot: BootSector,
    offset: u64,
    length: usize,
    output: &mut [u8],
) -> Result<(u64, usize)> {
    if length == 0 || length > super::boot::MAX_WRITER_RECORD_BYTES {
        return Err(Error::Unsupported);
    }
    let cluster = u64::from(boot.cluster_bytes);
    if cluster < u64::from(super::boot::MIN_SECTOR_BYTES) || !super::bytes::nonzero_power_of_two(cluster) {
        return Err(Error::InvalidGeometry);
    }
    let count = ((offset % cluster + length as u64).div_ceil(cluster)) as usize;
    if count > METADATA_CLUSTERS || output.len() < count * LCN_BYTES {
        return Err(Error::NoSpace);
    }
    let mut first = None;
    let mut contiguous = true;
    plan_nonresident_recovery(attr, boot, offset, length as u64, |span| {
        let physical = *first.get_or_insert(span.physical_offset);
        contiguous &= span.physical_offset == physical + span.source_offset;
        let mut source = span.source_offset;
        let mut disk = span.physical_offset;
        while source < span.source_offset + span.length {
            let index = ((offset % cluster + source) / cluster) as usize;
            output[index * LCN_BYTES..(index + 1) * LCN_BYTES].copy_from_slice(&(disk / cluster).to_le_bytes());
            let bytes = (cluster - disk % cluster).min(span.source_offset + span.length - source);
            source += bytes;
            disk += bytes;
        }
        Ok(())
    })?;
    let physical = first.ok_or(Error::InvalidRunlist)?;
    let used = if contiguous { 0 } else { count * LCN_BYTES };
    metadata_spans(physical, &output[..used], cluster, length, |_| Ok(()))?;
    Ok((physical, used))
}

/// Validate the complete map before visiting any physical span.
pub(crate) fn metadata_spans(
    physical: u64,
    map: &[u8],
    cluster: u64,
    length: usize,
    mut visitor: impl FnMut(WriteSpan) -> Result<()>,
) -> Result<()> {
    if cluster < u64::from(super::boot::MIN_SECTOR_BYTES) || !super::bytes::nonzero_power_of_two(cluster) {
        return Err(Error::InvalidGeometry);
    }
    let count = (physical % cluster + length as u64).div_ceil(cluster) as usize;
    if length == 0 || count > METADATA_CLUSTERS || (!map.is_empty() && map.len() != count * LCN_BYTES) {
        return Err(Error::InvalidRunlist);
    }
    if map.is_empty() {
        physical.checked_add(length as u64).ok_or(Error::Overflow)?;
        return visitor(WriteSpan { physical_offset: physical, source_offset: 0, length: length as u64 });
    }
    for (index, bytes) in map.chunks_exact(LCN_BYTES).enumerate() {
        let lcn = u64::from_le_bytes(bytes.try_into().map_err(|_| Error::InvalidRunlist)?);
        lcn.checked_mul(cluster).and_then(|n| n.checked_add(cluster)).ok_or(Error::Overflow)?;
        if (index == 0 && lcn != physical / cluster)
            || map[..index * LCN_BYTES].chunks_exact(LCN_BYTES).any(|b| b == bytes)
        {
            return Err(Error::InvalidRunlist);
        }
    }
    let mut source = 0;
    for (index, bytes) in map.chunks_exact(LCN_BYTES).enumerate() {
        let lcn = u64::from_le_bytes(bytes.try_into().map_err(|_| Error::InvalidRunlist)?);
        let skip = if index == 0 { physical % cluster } else { 0 };
        let bytes = (cluster - skip).min(length as u64 - source);
        visitor(WriteSpan { physical_offset: lcn * cluster + skip, source_offset: source, length: bytes })?;
        source += bytes;
    }
    Ok(())
}

pub(crate) fn metadata_overlap(
    physical: u64,
    map: &[u8],
    length: usize,
    other: u64,
    other_map: &[u8],
    other_length: usize,
    cluster: u64,
) -> Result<bool> {
    let mut overlap = false;
    metadata_spans(physical, map, cluster, length, |a| {
        metadata_spans(other, other_map, cluster, other_length, |b| {
            overlap |=
                a.physical_offset < b.physical_offset + b.length && b.physical_offset < a.physical_offset + a.length;
            Ok(())
        })
    })?;
    Ok(overlap)
}

#[cfg(test)]
#[path = "../tests/core/write_plan.rs"]
mod tests;
