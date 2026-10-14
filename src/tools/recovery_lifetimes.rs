//! Module: slate_ntfs_tools::recovery_io::models::lifetimes
//! Purpose: Prove stream mapping retirement from complete logged FILE images.
//! Created: 2026-10-09
//! Architecture: Dirty mapping analysis supplies committed operations and checks
//! undo dependencies; shared MFT and runlist parsers validate lifecycle evidence.

use super::log::OpenAttribute;
use ntfs_rs::boot::BootSector;
use ntfs_rs::logfile::{log_operation as operation, NtfsLogOperation};
use ntfs_rs::mft::{
    file_reference, record_layout, reference_number, system_record, MftRecord, ATTR_ATTRIBUTE_LIST, ATTR_DATA,
};
use ntfs_rs::runlist::{DataRuns, Extent};
use ntfs_rs::{Error, Result};

#[derive(Eq, PartialEq)]
struct Stream {
    kind: u32,
    name: Vec<u8>,
    runs: Vec<Extent>,
}

impl Stream {
    fn lcn(&self, vcn: u64) -> Option<u64> {
        self.runs
            .iter()
            .find(|run| vcn >= run.vcn && vcn - run.vcn < run.len)
            .and_then(|run| run.lcn.map(|lcn| lcn + (vcn - run.vcn)))
    }
}

#[derive(Eq, PartialEq)]
struct Snapshot {
    reference: u64,
    streams: Vec<Stream>,
}

impl Snapshot {
    fn read(bytes: &[u8], number: u64, clusters: u64) -> Result<Option<Self>> {
        let record = MftRecord::from_decoded(bytes)?;
        if record.physical_record_number()?.is_some_and(|actual| actual != number) {
            return Err(Error::InvalidLog);
        }
        // A moved extent in an attribute family is not evidence of deletion.
        // Keep existing refusal behavior until the whole family is available.
        if record.base_file_reference()? != 0 {
            return Ok(None);
        }
        let reference = file_reference(number, record.sequence_number()?)?;
        let mut streams = Vec::new();
        for attribute in record.attributes() {
            let attribute = attribute?;
            attribute.validate_value()?;
            if attribute.kind == ATTR_ATTRIBUTE_LIST {
                return Ok(None);
            }
            if !attribute.nonresident || record.flags()? & record_layout::IN_USE == 0 {
                continue;
            }
            if attribute.first_vcn()? != 0 {
                return Ok(None);
            }
            let name = attribute.name_utf16le()?.to_vec();
            if streams.iter().any(|stream: &Stream| stream.kind == attribute.kind && stream.name == name) {
                return Err(Error::InvalidLog);
            }
            let runs = DataRuns::new(attribute.data_runs()?, attribute.first_vcn()?).collect::<Result<Vec<_>>>()?;
            for run in &runs {
                if let Some(lcn) = run.lcn {
                    if lcn == 0 || lcn.checked_add(run.len).is_none_or(|end| end > clusters) {
                        return Err(Error::InvalidLog);
                    }
                }
            }
            streams.push(Stream { kind: attribute.kind, name, runs });
        }
        Ok(Some(Self { reference, streams }))
    }

    fn lcn(&self, kind: u32, name: &[u8], vcn: u64) -> Option<u64> {
        self.streams.iter().find(|stream| stream.kind == kind && stream.name == name).and_then(|stream| stream.lcn(vcn))
    }
}

pub(super) struct Transition {
    before: Snapshot,
    after: Snapshot,
}

impl Transition {
    pub(super) fn from_operation(
        open: &OpenAttribute,
        op: NtfsLogOperation<'_>,
        boot: BootSector,
    ) -> Result<Option<Self>> {
        if reference_number(open.reference) != system_record::MFT
            || open.kind != ATTR_DATA
            || !open.name.is_empty()
            || op.redo_code != operation::INITIALIZE_FILE_RECORD
            || op.undo_code != operation::INITIALIZE_FILE_RECORD
            || op.record_offset != 0
            || op.attribute_offset != 0
            || op.redo.len() != boot.record_bytes as usize
            || op.undo.len() != boot.record_bytes as usize
        {
            return Ok(None);
        }
        let offset = u64::from(op.cluster_offset) * super::NTFS_SECTOR_BYTES as u64;
        if offset >= u64::from(boot.cluster_bytes) {
            return Err(Error::InvalidLog);
        }
        let logical = op
            .target_vcn
            .checked_mul(u64::from(boot.cluster_bytes))
            .and_then(|start| start.checked_add(offset))
            .ok_or(Error::Overflow)?;
        if logical % u64::from(boot.record_bytes) != 0 {
            return Err(Error::InvalidLog);
        }
        let number = logical / u64::from(boot.record_bytes);
        let clusters = boot.total_sectors / u64::from(boot.sectors_per_cluster);
        let (Some(before), Some(after)) =
            (Snapshot::read(op.undo, number, clusters)?, Snapshot::read(op.redo, number, clusters)?)
        else {
            return Ok(None);
        };
        Ok((before != after).then_some(Self { before, after }))
    }

    pub(super) fn retires(&self, reference: u64, kind: u32, name: &[u8], vcn: u64, lcn: u64) -> Result<bool> {
        if reference != self.before.reference {
            return Ok(false);
        }
        let Some(old) = self.before.lcn(kind, name, vcn) else {
            return Ok(false);
        };
        let unchanged = self.after.reference == reference && self.after.lcn(kind, name, vcn) == Some(old);
        if unchanged {
            return Ok(false);
        }
        if old != lcn {
            return Err(Error::InvalidLog);
        }
        Ok(true)
    }
}

#[cfg(test)]
#[path = "../tests/recovery/lifetimes.rs"]
mod tests;
