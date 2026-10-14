//! Module: ntfs_rs::journal
//! Purpose: Allocation-free reservations for the serialized resident transaction writer.
//! Created: 2026-10-01
//! Architecture: Writer operations use caller-owned scratch and delegate durable I/O to
//! adapters.

//! Allocation-free reservations for the serialized resident transaction writer.
//! Callers validate durable history and own serialization, storage and flushes.
use super::logfile::RestartPage;
use super::replay::LogWindow;
use super::{Error, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Slot {
    pub offset: u64,
    pub lsn: u64,
}

/// Next single-record page, including generation advancement at circular wrap.
/// This only computes an address; it does not authorize reuse of that page.
pub fn next_slot(restart: RestartPage) -> Result<Slot> {
    let window = LogWindow::new(restart)?;
    let page = u64::from(restart.log_page_bytes);
    let current = window.offset(restart.current_lsn)?;
    let bits = 64 - restart.sequence_bits;
    let mut generation = restart.current_lsn >> bits;
    let mut offset = current / page * page + page;
    if offset == restart.log_bytes {
        offset = window.first_page;
        generation = generation.checked_add(1).ok_or(Error::Overflow)?;
    }
    if generation >= (1_u64 << restart.sequence_bits) {
        return Err(Error::Overflow);
    }
    Ok(Slot { offset, lsn: (generation << bits) | ((offset + u64::from(restart.record_data_offset)) / 8) })
}

/// Reserve open/update/commit/checkpoint pages after a durable empty checkpoint.
/// The old checkpoint is preserved until all metadata and the new checkpoint
/// have been flushed and both restart copies have been published.
pub fn reserve_resident(mut restart: RestartPage) -> Result<[Slot; 4]> {
    let mut slots = [Slot { offset: 0, lsn: 0 }; 4];
    let client = restart.client.ok_or(Error::InvalidLog)?;
    if restart.major_version != 1
        || restart.minor_version != 1
        || restart.log_page_bytes != 4096
        || restart.record_data_offset != 64
        || client.oldest_lsn != restart.current_lsn
        || client.restart_lsn != restart.current_lsn
    {
        return Err(Error::Unsupported);
    }
    let window = LogWindow::new(restart)?;
    let checkpoint_page = window.offset(restart.current_lsn)? / 4096 * 4096;
    for index in 0..slots.len() {
        let slot = next_slot(restart)?;
        if slot.offset == checkpoint_page || slots[..index].iter().any(|old| old.offset == slot.offset) {
            return Err(Error::Unsupported);
        }
        slots[index] = slot;
        restart.current_lsn = slot.lsn;
    }
    Ok(slots)
}

/// Reserve after the caller's live head while retaining the on-disk empty
/// checkpoint and every subsequent page. Store slots in caller scratch.
/// NoSpace requires a durable checkpoint before retrying; callers also
/// reserve one spare page for that checkpoint.
#[derive(Clone, Copy)]
pub struct PageReservation {
    first: Slot,
    restart: RestartPage,
    first_page: u64,
    count: usize,
}

impl PageReservation {
    /// Validate the full live interval, including rollback and checkpoint space.
    /// Slots are computed on demand, independent of transaction fragmentation.
    pub fn new(restart: RestartPage, count: usize) -> Result<Self> {
        let client = restart.client.ok_or(Error::InvalidLog)?;
        if restart.major_version != 1
            || restart.minor_version != 1
            || restart.log_page_bytes != 4096
            || restart.record_data_offset != 64
            || client.oldest_lsn != client.restart_lsn
            || client.restart_lsn > restart.current_lsn
        {
            return Err(Error::Unsupported);
        }
        let window = LogWindow::new(restart)?;
        let page = u64::from(restart.log_page_bytes);
        let first = next_slot(restart)?;
        let checkpoint = window.offset(client.oldest_lsn)? / page * page;
        let available = if checkpoint >= first.offset {
            checkpoint - first.offset
        } else {
            restart.log_bytes - first.offset + checkpoint - window.first_page
        } / page;
        if count as u64 > available {
            return Err(Error::NoSpace);
        }
        let result = Self { first, restart, first_page: window.first_page, count };
        if count != 0 {
            result.slot(count - 1)?;
        }
        Ok(result)
    }

    pub fn slot(self, index: usize) -> Result<Slot> {
        if index >= self.count {
            return Err(Error::Truncated);
        }
        let page = u64::from(self.restart.log_page_bytes);
        let until_wrap = (self.restart.log_bytes - self.first.offset) / page;
        let bits = 64 - self.restart.sequence_bits;
        let mut generation = self.first.lsn >> bits;
        let offset = if (index as u64) < until_wrap {
            self.first.offset + index as u64 * page
        } else {
            generation = generation.checked_add(1).ok_or(Error::Overflow)?;
            self.first_page + (index as u64 - until_wrap) * page
        };
        if generation >= (1_u64 << self.restart.sequence_bits) {
            return Err(Error::Overflow);
        }
        Ok(Slot { offset, lsn: (generation << bits) | ((offset + u64::from(self.restart.record_data_offset)) / 8) })
    }
}

pub fn reserve_pages_into(restart: RestartPage, count: usize, out: &mut [u8]) -> Result<()> {
    const SLOT_BYTES: usize = 2 * core::mem::size_of::<u64>();
    if count > out.len() / SLOT_BYTES {
        return Err(Error::Unsupported);
    }
    let reservation = PageReservation::new(restart, count)?;
    for index in 0..count {
        let slot = reservation.slot(index)?;
        let at = index * SLOT_BYTES;
        out[at..at + SLOT_BYTES / 2].copy_from_slice(&slot.offset.to_le_bytes());
        out[at + SLOT_BYTES / 2..at + SLOT_BYTES].copy_from_slice(&slot.lsn.to_le_bytes());
    }
    Ok(())
}

/// Read one slot stored by reserve_pages_into.
pub fn stored_slot(bytes: &[u8], index: usize) -> Result<Slot> {
    Ok(Slot { offset: super::bytes::u64_at(bytes, index * 16)?, lsn: super::bytes::u64_at(bytes, index * 16 + 8)? })
}

#[cfg(test)]
#[path = "../tests/writer/journal.rs"]
mod tests;
