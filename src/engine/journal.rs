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
pub fn reserve_pages_into(mut restart: RestartPage, count: usize, out: &mut [u8]) -> Result<()> {
    let client = restart.client.ok_or(Error::InvalidLog)?;
    if restart.major_version != 1
        || restart.minor_version != 1
        || restart.log_page_bytes != 4096
        || restart.record_data_offset != 64
        || client.oldest_lsn != client.restart_lsn
        || client.restart_lsn > restart.current_lsn
        || out.len() < count * 16
    {
        return Err(Error::Unsupported);
    }
    let window = LogWindow::new(restart)?;
    let checkpoint_page = window.offset(client.oldest_lsn)? / 4096 * 4096;
    let mut first = None;
    for index in 0..count {
        let slot = next_slot(restart)?;
        if slot.offset == checkpoint_page || first == Some(slot.offset) {
            return Err(Error::NoSpace);
        }
        first.get_or_insert(slot.offset);
        out[index * 16..index * 16 + 8].copy_from_slice(&slot.offset.to_le_bytes());
        out[index * 16 + 8..index * 16 + 16].copy_from_slice(&slot.lsn.to_le_bytes());
        restart.current_lsn = slot.lsn;
    }
    Ok(())
}

/// Read one slot stored by reserve_pages_into.
pub fn stored_slot(bytes: &[u8], index: usize) -> Result<Slot> {
    Ok(Slot { offset: super::bytes::u64_at(bytes, index * 16)?, lsn: super::bytes::u64_at(bytes, index * 16 + 8)? })
}

#[cfg(test)]
mod tests {
    use super::super::logfile::{advance_restart_checkpoint, encode_initial_restart};
    use super::*;

    fn restart(at: u64, generation: u64) -> RestartPage {
        let mut page = [0; 4096];
        let start = (generation << 15) | ((4 * 4096 + 64) / 8);
        encode_initial_restart(&mut page, 196608, start).unwrap();
        let lsn = (generation << 15) | ((at + 64) / 8);
        if lsn != start {
            advance_restart_checkpoint(&mut page, 512, lsn).unwrap();
        }
        RestartPage::parse(&mut page, 512).unwrap()
    }

    #[test]
    fn reserves_across_wrap_without_overwriting_live_checkpoint() {
        let before = restart(46 * 4096, 1);
        let slots = reserve_resident(before).unwrap();
        assert_eq!(slots.map(|s| s.offset), [47 * 4096, 4 * 4096, 5 * 4096, 6 * 4096]);
        assert_eq!(slots.map(|s| s.lsn >> 15), [1, 2, 2, 2]);
        assert!(slots.windows(2).all(|s| s[0].lsn < s[1].lsn));
    }

    #[test]
    fn refuses_pending_transactions_and_generation_overflow() {
        let mut before = restart(4 * 4096, 1);
        before.current_lsn += 512;
        assert_eq!(reserve_resident(before), Err(Error::Unsupported));
        let before = restart(47 * 4096, (1_u64 << 49) - 1);
        assert_eq!(next_slot(before), Err(Error::Overflow));
    }
}
