//! Module: ntfs_rs::replay
//! Purpose: Provide allocation-free recovery primitives.
//! Created: 2026-10-01
//! Architecture: Writer operations use caller-owned scratch; adapters validate the complete
//! history and every target before writing and own durable publication.

use super::bytes::u16_at;
use super::logfile::LfsRecord;
use super::logfile::{lsn_stream_offset, RestartPage};
use super::mft::record_layout as rf;
use super::{Error, Result};

/// A bounded LFS circular window. Exact LSN equality at every read is still
/// mandatory: physical page order alone cannot distinguish old generations.
#[derive(Clone, Copy, Debug)]
pub struct LogWindow {
    pub restart: RestartPage,
    pub first_page: u64,
    pub oldest: u64,
}

impl LogWindow {
    pub fn new(restart: RestartPage) -> Result<Self> {
        if !(3..64).contains(&restart.sequence_bits) || !restart.log_page_bytes.is_power_of_two() {
            return Err(Error::InvalidLog);
        }
        let client = restart.client.ok_or(Error::InvalidLog)?;
        let first_page = u64::from(restart.log_page_bytes) * if restart.major_version == 1 { 4 } else { 34 };
        if restart.chkdsk_marker
            || restart.log_bytes % u64::from(restart.log_page_bytes) != 0
            || first_page >= restart.log_bytes
            || client.oldest_lsn == 0
            || client.oldest_lsn > restart.current_lsn
        {
            return Err(Error::InvalidLog);
        }
        let window = Self { restart, first_page, oldest: client.oldest_lsn };
        window.offset(client.oldest_lsn)?;
        window.offset(restart.current_lsn)?;
        let bits = 64 - restart.sequence_bits;
        if (restart.current_lsn >> bits) - (client.oldest_lsn >> bits) > 1 {
            return Err(Error::InvalidLog);
        }
        Ok(window)
    }

    pub fn offset(self, lsn: u64) -> Result<u64> {
        if lsn < self.oldest || lsn > self.restart.current_lsn {
            return Err(Error::InvalidLog);
        }
        let offset = lsn_stream_offset(lsn, self.restart.sequence_bits, self.restart.log_bytes)?;
        let in_page = offset % u64::from(self.restart.log_page_bytes);
        if offset < self.first_page || in_page < u64::from(self.restart.record_data_offset) {
            return Err(Error::InvalidLog);
        }
        Ok(offset)
    }

    /// Called only for a complete, non-spanning record on a checked page.
    pub fn next(self, lsn: u64, record_bytes: usize, page_last_lsn: u64) -> Result<Option<u64>> {
        let offset = self.offset(lsn)?;
        if lsn > page_last_lsn || page_last_lsn > self.restart.current_lsn {
            return Err(Error::InvalidLog);
        }
        if lsn == self.restart.current_lsn {
            return Ok(None);
        }
        let page_bytes = u64::from(self.restart.log_page_bytes);
        let page_start = offset / page_bytes * page_bytes;
        let bits = 64 - self.restart.sequence_bits;
        let mut sequence = lsn >> bits;
        let next_offset = if lsn == page_last_lsn {
            let next_page = page_start.checked_add(page_bytes).ok_or(Error::Overflow)?;
            let next_page = if next_page == self.restart.log_bytes {
                sequence = sequence.checked_add(1).ok_or(Error::Overflow)?;
                self.first_page
            } else {
                next_page
            };
            next_page + u64::from(self.restart.record_data_offset)
        } else {
            let end = offset.checked_add(record_bytes as u64).ok_or(Error::Overflow)?;
            let next = end.checked_add(7).ok_or(Error::Overflow)? & !7;
            if next >= page_start + page_bytes {
                return Err(Error::InvalidLog);
            }
            next
        };
        if sequence >= (1_u64 << self.restart.sequence_bits) {
            return Err(Error::Overflow);
        }
        let next = (sequence << bits) | (next_offset / 8);
        if next <= lsn {
            return Err(Error::InvalidLog);
        }
        self.offset(next)?;
        Ok(Some(next))
    }
}

/// Restore sector protection on a caller-owned, already USA-decoded FILE
/// record. This does not write to storage or make a torn record repairable.
pub fn protect_mft_record(raw: &mut [u8], sector: u16) -> Result<()> {
    let sector = usize::from(sector);
    if sector < 512 || !sector.is_power_of_two() || raw.len() % sector != 0 || raw.get(..4) != Some(b"FILE") {
        return Err(Error::InvalidRecord);
    }
    let usa = usize::from(u16_at(raw, 4)?);
    let count = usize::from(u16_at(raw, 6)?);
    let stride = super::mft::FIXUP_STRIDE;
    // The legacy header stores USA at 0x2a and has no record-number field.
    // Its sector protection uses the same checked geometry as modern records.
    let minimum_usa = usize::from(if usa == usize::from(rf::LEGACY_USA) { rf::LEGACY_USA } else { rf::CURRENT_USA });
    if count != raw.len() / stride + 1
        || usa < minimum_usa
        || usa % 2 != 0
        || usa + count * 2 > usize::from(u16_at(raw, 0x14)?)
        || usa + count * 2 > raw.len()
    {
        return Err(Error::InvalidFixup);
    }
    super::mft::protect_fixups(raw)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordAction {
    /// Transaction/control or checkpoint data; still requires full replay
    /// context before it can be skipped or applied.
    Control,
    /// An NTFS metadata operation whose target must be resolved and checked.
    Metadata,
}

/// Classify one checked client record. This does not decide redo/undo order,
/// resolve the target attribute or grant replay.
pub fn record_action(record: LfsRecord<'_>) -> Result<RecordAction> {
    let operation = record.ntfs_operation()?;
    let control = |code: u16| matches!(code, 0 | 1 | 0x0a | 0x17..=0x20);
    Ok(if control(operation.redo_code) && control(operation.undo_code) {
        RecordAction::Control
    } else {
        RecordAction::Metadata
    })
}

#[cfg(test)]
#[path = "../tests/core/replay.rs"]
mod tests;
