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

/// Map an initialized, nonresident unnamed data attribute to physical spans.
/// The entire runlist and requested range are checked before visitor runs.
/// Resident, compressed, encrypted, extending, uninitialized and hole writes
/// are refused. Allocated runs of sparse streams are accepted. This is mapping
/// only and does not authorize a write.
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

#[cfg(test)]
mod tests {
    use super::super::mft::{MftRecord, ATTR_DATA};
    use super::*;

    fn sample_record() -> [u8; 1024] {
        let mut bytes = [0_u8; 1024];
        bytes[0..4].copy_from_slice(b"FILE");
        bytes[4..6].copy_from_slice(&0x30_u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&3_u16.to_le_bytes());
        bytes[0x14..0x16].copy_from_slice(&0x38_u16.to_le_bytes());
        bytes[0x18..0x1c].copy_from_slice(&0x88_u32.to_le_bytes());
        bytes[0x30..0x32].copy_from_slice(&0x1234_u16.to_le_bytes());
        bytes[510..512].copy_from_slice(&0x1234_u16.to_le_bytes());
        bytes[1022..1024].copy_from_slice(&0x1234_u16.to_le_bytes());
        bytes[0x38..0x3c].copy_from_slice(&ATTR_DATA.to_le_bytes());
        bytes[0x3c..0x40].copy_from_slice(&0x48_u32.to_le_bytes());
        bytes[0x40] = 1;
        bytes[0x50..0x58].copy_from_slice(&1_u64.to_le_bytes());
        bytes[0x58..0x5a].copy_from_slice(&0x40_u16.to_le_bytes());
        bytes[0x68..0x70].copy_from_slice(&8192_u64.to_le_bytes());
        bytes[0x70..0x78].copy_from_slice(&8192_u64.to_le_bytes());
        bytes[0x78..0x7f].copy_from_slice(&[0x11, 1, 10, 0x11, 1, 10, 0]);
        bytes[0x80..0x84].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes
    }

    fn boot() -> BootSector {
        BootSector {
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
            cluster_bytes: 4096,
            total_sectors: 8192,
            mft_lcn: 4,
            mft_mirror_lcn: 8,
            record_bytes: 1024,
            index_block_bytes: 4096,
            serial_number: 1,
        }
    }

    #[test]
    fn maps_cross_extent_overwrite_without_writing() {
        let mut data = sample_record();
        let record = MftRecord::parse(&mut data, 512).unwrap();
        let attr = record.attributes().next().unwrap().unwrap();
        let mut spans = std::vec::Vec::new();
        assert_eq!(
            plan_nonresident_overwrite(attr, boot(), 4094, 4, |span| {
                spans.push(span);
                Ok(())
            }),
            Ok(2)
        );
        assert_eq!(
            spans,
            [
                WriteSpan { physical_offset: 10 * 4096 + 4094, source_offset: 0, length: 2 },
                WriteSpan { physical_offset: 20 * 4096, source_offset: 2, length: 2 },
            ]
        );
    }

    #[test]
    fn refuses_sparse_and_extending_writes() {
        let mut data = sample_record();
        let record = MftRecord::parse(&mut data, 512).unwrap();
        let attr = record.attributes().next().unwrap().unwrap();
        assert_eq!(plan_nonresident_overwrite(attr, boot(), 8190, 4, |_| Ok(())), Err(Error::InvalidAttribute));
        let mut data = sample_record();
        data[0x7b] = 0x01; // sparse second run
        data[0x7e] = 0;
        let record = MftRecord::parse(&mut data, 512).unwrap();
        let attr = record.attributes().next().unwrap().unwrap();
        assert_eq!(plan_nonresident_overwrite(attr, boot(), 0, 4, |_| Ok(())), Err(Error::InvalidRunlist));
    }

    #[test]
    fn sparse_hole_is_rejected_before_any_visitor_call() {
        let mut data = sample_record();
        data[0x44..0x46].copy_from_slice(&0x8000u16.to_le_bytes());
        data[0x3c..0x40].copy_from_slice(&0x58u32.to_le_bytes());
        data[0x58..0x5a].copy_from_slice(&0x48u16.to_le_bytes());
        data[0x78..0x80].copy_from_slice(&4096u64.to_le_bytes());
        data[0x80..0x90].fill(0);
        data[0x80..0x86].copy_from_slice(&[0x11, 1, 10, 0x01, 1, 0]);
        data[0x90..0x94].copy_from_slice(&u32::MAX.to_le_bytes());
        data[0x18..0x1c].copy_from_slice(&0x98u32.to_le_bytes());
        let record = MftRecord::parse(&mut data, 512).unwrap();
        let attr = record.attributes().next().unwrap().unwrap();
        let mut calls = 0;
        assert_eq!(
            plan_nonresident_overwrite(attr, boot(), 4094, 4, |_| {
                calls += 1;
                Ok(())
            }),
            Err(Error::InvalidRunlist)
        );
        assert_eq!(calls, 0);
        assert_eq!(plan_nonresident_overwrite(attr, boot(), 0, 4, |_| Ok(())), Ok(1));
    }
}
