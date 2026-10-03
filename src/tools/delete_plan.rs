//! Module: slate_ntfs_tools::delete_plan
//! Purpose: Preflight deletion of a simple root hiberfil.sys without writes.
//! Created: 2026-10-01
//! Architecture: The laboratory consumes checked identity and cluster inventory. Unsupported
//! layouts fail before callbacks; this plan cannot authorize a metadata commit.

use ntfs_rs::boot::BootSector;
use ntfs_rs::bytes::u64_at;
use ntfs_rs::mft::reference_number;
use ntfs_rs::mft::{
    Attribute, MftRecord, ATTR_DATA, ATTR_FILE_NAME, ATTR_SECURITY_DESCRIPTOR, ATTR_STANDARD_INFORMATION,
};
use ntfs_rs::runlist::DataRuns;
use ntfs_rs::{Error, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClusterRange {
    pub lcn: u64,
    pub length: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HiberDeletePlan {
    pub mft_number: u64,
    pub sequence: u16,
    pub data_bytes: u64,
    pub clusters: u64,
    pub runs: u64,
}

fn is_hiber_name(value: &[u8]) -> Result<bool> {
    const NAME: &[u8] = b"hiberfil.sys";
    if value.len() < 0x42 || value[0x40] as usize != NAME.len() || value[0x41] > 3 {
        return Ok(false);
    }
    if reference_number(u64_at(value, 0)?) != 5 {
        return Ok(false);
    }
    let units = value.get(0x42..0x42 + NAME.len() * 2).ok_or(Error::InvalidAttribute)?;
    Ok(units.chunks_exact(2).zip(NAME).all(|(unit, expected)| unit[1] == 0 && unit[0].eq_ignore_ascii_case(expected)))
}

/// Verify the root index reference and the whole file runlist before yielding
/// any allocation spans. The caller must independently check the HIBR header,
/// root index, bitmaps, log, dirty flag and transaction prerequisites.
pub fn plan_hiberfile_deletion(
    record: &MftRecord<'_>,
    index_reference: u64,
    boot: BootSector,
    mut visitor: impl FnMut(ClusterRange) -> Result<()>,
) -> Result<HiberDeletePlan> {
    let number = reference_number(index_reference);
    let sequence = record.sequence_number()?;
    if number < 16
        || (index_reference >> 48) as u16 != sequence
        || record.flags()? != 1
        || record.link_count()? != 1
        || record.base_file_reference()? != 0
    {
        return Err(Error::InvalidRecord);
    }
    let mut name_count = 0;
    let mut standard_count = 0;
    let mut security_count = 0;
    let mut data: Option<Attribute<'_>> = None;
    for item in record.attributes() {
        let attr = item?;
        if !attr.name_utf16le()?.is_empty() || attr.flags()? != 0 {
            return Err(Error::Unsupported);
        }
        match attr.kind {
            ATTR_STANDARD_INFORMATION if !attr.nonresident => standard_count += 1,
            ATTR_SECURITY_DESCRIPTOR if !attr.nonresident => security_count += 1,
            ATTR_FILE_NAME if !attr.nonresident && is_hiber_name(attr.resident_value()?)? => {
                name_count += 1;
            }
            ATTR_DATA if data.replace(attr).is_none() => {}
            _ => return Err(Error::Unsupported),
        }
    }
    if name_count != 1 || standard_count != 1 || security_count > 1 {
        return Err(Error::InvalidAttribute);
    }
    let data = data.ok_or(Error::InvalidAttribute)?;
    if !data.nonresident || data.first_vcn()? != 0 {
        return Err(Error::Unsupported);
    }
    let data_bytes = data.data_size()?;
    if data_bytes < 4096 || data.initialized_size()? < 4096 {
        return Err(Error::InvalidAttribute);
    }
    let last = data.last_vcn()?;
    let total_clusters = boot.total_sectors / u64::from(boot.sectors_per_cluster);
    let mut next_vcn = 0_u64;
    let mut count = 0_u64;
    for item in DataRuns::new(data.data_runs()?, 0) {
        let run = item?;
        let lcn = run.lcn.ok_or(Error::Unsupported)?;
        if run.vcn != next_vcn || lcn.checked_add(run.len).is_none_or(|end| end > total_clusters) {
            return Err(Error::InvalidRunlist);
        }
        next_vcn = next_vcn.checked_add(run.len).ok_or(Error::Overflow)?;
        count += 1;
    }
    if next_vcn == 0
        || next_vcn != last.checked_add(1).ok_or(Error::Overflow)?
        || data_bytes > next_vcn.checked_mul(u64::from(boot.cluster_bytes)).ok_or(Error::Overflow)?
    {
        return Err(Error::InvalidRunlist);
    }
    for item in DataRuns::new(data.data_runs()?, 0) {
        let run = item?;
        visitor(ClusterRange { lcn: run.lcn.ok_or(Error::InvalidRunlist)?, length: run.len })?;
    }
    Ok(HiberDeletePlan { mft_number: number, sequence, data_bytes, clusters: next_vcn, runs: count })
}
