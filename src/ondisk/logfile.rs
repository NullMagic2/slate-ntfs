//! Module: ntfs_rs::logfile
//! Purpose: Parse and encode checked NTFS log pages and checkpoint markers.
//! Created: 2026-09-30
//! Architecture: The shared core exposes isolated formats to the writer and offline
//!     checker; callers own replay and write authorization.

use super::bytes::{range, range_mut, u16_at, u32_at, u64_at};
use super::mft::apply_fixups;
use super::{Error, Result};

/// LFS record framing shared by the parser, encoders and recovery analysis.
pub mod lfs_layout {
    pub const ALIGNMENT: usize = core::mem::size_of::<u64>();
    pub const LSN_OFFSET_UNIT_BYTES: u64 = core::mem::size_of::<u64>() as u64;
    pub const THIS_LSN_OFFSET: usize = 0;
    pub const CLIENT_SEQUENCE_OFFSET: usize = 28;
    pub const CLIENT_INDEX_OFFSET: usize = 30;
    pub const TYPE_OFFSET: usize = 32;
    pub const FLAGS_OFFSET: usize = 40;
    pub const HEADER_BYTES: usize = 48;
    pub const NO_LSN: u64 = 0;
    pub const NO_TRANSACTION_ID: u32 = 0;
    pub const NO_FLAGS: u16 = 0;
    pub const UPDATE_RECORD: u32 = 1;
    pub const CHECKPOINT_RECORD: u32 = 2;
    pub const MULTI_PAGE: u16 = 1;
    pub const NO_UNDO: u16 = 4;
}

/// NTFS log operation identities and payload header fields.
pub mod log_operation {
    pub const NOOP: u16 = 0;
    pub const COMPENSATION: u16 = 1;
    pub const INITIALIZE_FILE_RECORD: u16 = 2;
    pub const UPDATE_NONRESIDENT_VALUE: u16 = 8;
    pub const UPDATE_MAPPING_PAIRS: u16 = 9;
    pub const DELETE_DIRTY_CLUSTERS: u16 = 10;
    pub const SET_NEW_ATTRIBUTE_SIZES: u16 = 11;
    pub const SET_BITMAP_BITS: u16 = 21;
    pub const CLEAR_BITMAP_BITS: u16 = 22;
    pub const HOT_FIX: u16 = 23;
    pub const END_TOP_LEVEL_ACTION: u16 = 24;
    pub const PREPARE_TRANSACTION: u16 = 25;
    pub const COMMIT_TRANSACTION: u16 = 26;
    pub const FORGET_TRANSACTION: u16 = 27;
    pub const OPEN_NONRESIDENT_ATTRIBUTE: u16 = 28;
    pub const OPEN_ATTRIBUTE_TABLE_DUMP: u16 = 29;
    pub const ATTRIBUTE_NAMES_DUMP: u16 = 30;
    pub const DIRTY_PAGE_TABLE_DUMP: u16 = 31;
    pub const TRANSACTION_TABLE_DUMP: u16 = 32;
    pub const UPDATE_RECORD_DATA_ROOT: u16 = 33;
    pub const ZERO_FILE_RECORD_TAIL: u16 = 37;
    pub const REDO_CODE_OFFSET: usize = 0;
    pub const UNDO_CODE_OFFSET: usize = 2;
    pub const RECORD_OFFSET_OFFSET: usize = 16;
    pub const OFFSETS_END: usize = 22;
    pub const HEADER_BYTES: usize = 32;
}

/// Supported restart versions and fixed publication page dimensions.
pub mod log_page_layout {
    pub const VERSION_LEGACY: u16 = 1;
    pub const MINOR_LEGACY: u16 = 1;
    pub const VERSION_CURRENT: u16 = 2;
    pub const MINOR_CURRENT: u16 = 0;
    pub const LEGACY_FIRST_RECORD_PAGE: usize = 4;
    pub const CURRENT_FIRST_RECORD_PAGE: usize = 34;
    pub const PUBLICATION_PAGE_BYTES: usize = 4096;
    pub const RECORD_DATA_OFFSET: usize = 64;
    pub const FRAGMENT_BYTES: usize = PUBLICATION_PAGE_BYTES - RECORD_DATA_OFFSET;
    pub const CHECKPOINT_PAYLOAD_BYTES: usize = 64;
    pub const CHECKPOINT_VERSION: u32 = 1;
    pub const CHECKPOINT_LSN_OFFSET: usize = 8;
}

const MAX_PAGE_BYTES: u32 = 65536;
const RESTART_AREA_HEADER_BYTES: usize = 0x40;
const CLIENT_RECORD_BYTES: usize = 0xa0;
const NO_CLIENT: u16 = 0xffff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogState {
    /// Every byte of the stream was checked and was 0xff.
    Uninitialized,
    /// Both restart copies validate; the newer copy has no active clients.
    NoActiveClients,
    /// The newer validated restart copy records a clean shutdown. A retained
    /// client still requires checkpoint validation before write authorization.
    CleanShutdown,
    /// Both checked-volume markers validate and carry the same LSN.
    CheckedVolume,
    /// The newer valid restart copy has at least one active client.
    ReplayRequired,
    /// Copies are missing, disagree, or use an unsupported/damaged layout.
    NeedsReview,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestartPage {
    pub system_page_bytes: u32,
    pub log_page_bytes: u32,
    pub record_data_offset: u16,
    pub major_version: u16,
    pub minor_version: u16,
    pub current_lsn: u64,
    pub log_bytes: u64,
    pub sequence_bits: u32,
    pub active_clients: bool,
    pub clean_shutdown: bool,
    pub chkdsk_marker: bool,
    pub client: Option<LogClient>,
}

impl RestartPage {
    /// Publishing the clean flag can stop between redundant copies without
    /// changing their checkpoint. Recovery must then retain the dirty state.
    pub fn same_checkpoint(self, other: Self) -> bool {
        Self { clean_shutdown: false, ..self } == Self { clean_shutdown: false, ..other }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogClient {
    pub index: u16,
    pub sequence: u16,
    pub oldest_lsn: u64,
    pub restart_lsn: u64,
}

impl RestartPage {
    /// Read just enough geometry to size the caller's page buffer. Full
    /// validation, including update-sequence fixups, follows in parse.
    pub fn peek_system_page_bytes(prefix: &[u8]) -> Result<u32> {
        let header = range(prefix, 0, 0x1e).map_err(|_| Error::InvalidLog)?;
        if &header[..4] != b"RSTR" && &header[..4] != b"CHKD" {
            return Err(Error::InvalidLog);
        }
        let size = u32_at(header, 0x10).map_err(|_| Error::InvalidLog)?;
        if !(512..=MAX_PAGE_BYTES).contains(&size) || !size.is_power_of_two() {
            return Err(Error::InvalidLog);
        }
        Ok(size)
    }

    /// Apply USA fixups to an exclusive, caller-owned copy of a restart page.
    /// An invalid page cannot be used to infer that replay is unnecessary.
    pub fn parse(page: &mut [u8], bytes_per_sector: u16) -> Result<Self> {
        let system_page_bytes = Self::peek_system_page_bytes(page)?;
        if page.len() != system_page_bytes as usize {
            return Err(Error::InvalidLog);
        }
        let log_page_bytes = u32_at(page, 0x14).map_err(|_| Error::InvalidLog)?;
        let restart_offset = usize::from(u16_at(page, 0x18).map_err(|_| Error::InvalidLog)?);
        let minor_version = u16_at(page, 0x1a).map_err(|_| Error::InvalidLog)?;
        let major_version = u16_at(page, 0x1c).map_err(|_| Error::InvalidLog)?;
        if !(512..=MAX_PAGE_BYTES).contains(&log_page_bytes)
            || !log_page_bytes.is_power_of_two()
            || restart_offset % 8 != 0
            || restart_offset < 0x20
            || !matches!(major_version, 1 | 2)
            || (major_version == 1 && minor_version == 0)
        {
            return Err(Error::InvalidLog);
        }
        let checked = &page[..4] == b"CHKD";
        let usa_count = u16_at(page, 6).map_err(|_| Error::InvalidLog)?;
        if checked && usa_count == 0 {
            if u16_at(page, 4).map_err(|_| Error::InvalidLog)? != 0 {
                return Err(Error::InvalidLog);
            }
        } else {
            apply_fixups(page, bytes_per_sector, 0x1e, restart_offset).map_err(|_| Error::InvalidLog)?;
        }
        if !checked && u64_at(page, 8).map_err(|_| Error::InvalidLog)? != 0 {
            return Err(Error::InvalidLog);
        }
        let area = range(page, restart_offset, RESTART_AREA_HEADER_BYTES).map_err(|_| Error::InvalidLog)?;
        let client_count = usize::from(u16_at(area, 8).map_err(|_| Error::InvalidLog)?);
        let free_client = u16_at(area, 0x0a).map_err(|_| Error::InvalidLog)?;
        let used_client = u16_at(area, 0x0c).map_err(|_| Error::InvalidLog)?;
        let restart_length = usize::from(u16_at(area, 0x14).map_err(|_| Error::InvalidLog)?);
        let client_offset = usize::from(u16_at(area, 0x16).map_err(|_| Error::InvalidLog)?);
        let log_bytes = u64_at(area, 0x18).map_err(|_| Error::InvalidLog)?;
        let sequence_bits = u32_at(area, 0x10).map_err(|_| Error::InvalidLog)?;
        let record_header_bytes = u16_at(area, 0x24).map_err(|_| Error::InvalidLog)?;
        let data_offset = u16_at(area, 0x26).map_err(|_| Error::InvalidLog)?;
        let client_end = client_count
            .checked_mul(CLIENT_RECORD_BYTES)
            .and_then(|bytes| client_offset.checked_add(bytes))
            .ok_or(Error::InvalidLog)?;
        if client_count > 1
            || (free_client != NO_CLIENT && usize::from(free_client) >= client_count)
            || (used_client != NO_CLIENT && usize::from(used_client) >= client_count)
            || client_offset < RESTART_AREA_HEADER_BYTES
            || client_offset % 8 != 0
            || restart_length < client_end
            || restart_offset.checked_add(restart_length).is_none_or(|end| end > page.len())
            || log_bytes < u64::from(system_page_bytes) * 2
            || log_bytes > u32::MAX as u64
            || sequence_bits != 67 - (64 - log_bytes.leading_zeros())
            || record_header_bytes < 0x30
            || record_header_bytes % 8 != 0
            || data_offset < record_header_bytes
            || data_offset % 8 != 0
            || u32::from(data_offset) >= log_page_bytes
        {
            return Err(Error::InvalidLog);
        }
        // An active client must point to a complete client record. Checking
        // the client chains and log records is still required for replay.
        let full_area = range(page, restart_offset, restart_length).map_err(|_| Error::InvalidLog)?;
        let clients =
            range(full_area, client_offset, client_count * CLIENT_RECORD_BYTES).map_err(|_| Error::InvalidLog)?;
        if free_client != NO_CLIENT && free_client == used_client {
            return Err(Error::InvalidLog);
        }
        let client = if checked || used_client == NO_CLIENT {
            None
        } else {
            let record = range(clients, usize::from(used_client) * CLIENT_RECORD_BYTES, CLIENT_RECORD_BYTES)
                .map_err(|_| Error::InvalidLog)?;
            let name_bytes = u32_at(record, 0x1c).map_err(|_| Error::InvalidLog)?;
            if u16_at(record, 0x10).map_err(|_| Error::InvalidLog)? != NO_CLIENT
                || u16_at(record, 0x12).map_err(|_| Error::InvalidLog)? != NO_CLIENT
                || name_bytes != 8
                || record[0x20..0x28] != [b'N', 0, b'T', 0, b'F', 0, b'S', 0]
            {
                return Err(Error::InvalidLog);
            }
            Some(LogClient {
                index: used_client,
                sequence: u16_at(record, 0x14).map_err(|_| Error::InvalidLog)?,
                oldest_lsn: u64_at(record, 0).map_err(|_| Error::InvalidLog)?,
                restart_lsn: u64_at(record, 8).map_err(|_| Error::InvalidLog)?,
            })
        };
        Ok(Self {
            system_page_bytes,
            log_page_bytes,
            record_data_offset: data_offset,
            major_version,
            minor_version,
            current_lsn: if checked { u64_at(page, 8) } else { u64_at(area, 0) }.map_err(|_| Error::InvalidLog)?,
            log_bytes,
            sequence_bits,
            active_clients: !checked && used_client != NO_CLIENT,
            clean_shutdown: !checked && u16_at(area, 0x0e).map_err(|_| Error::InvalidLog)? & 2 != 0,
            chkdsk_marker: checked,
            client,
        })
    }
}

/// Publish a checked-volume marker in a restart-page prefix. This replaces
/// the transfer-protection fields and preserves the page geometry and area.
/// The caller must validate the page and make both marker copies durable.
pub fn encode_checked_marker(prefix: &mut [u8], lsn: u64) -> Result<()> {
    let header = range_mut(prefix, 0, 16)?;
    header[..4].copy_from_slice(b"CHKD");
    header[4..8].fill(0);
    header[8..16].copy_from_slice(&lsn.to_le_bytes());
    Ok(())
}

/// Translate an LFS sequence/offset value to its byte position in the
/// circular stream. This does not prove that the page still holds that LSN.
pub fn lsn_stream_offset(lsn: u64, sequence_bits: u32, log_bytes: u64) -> Result<u64> {
    if !(3..64).contains(&sequence_bits) {
        return Err(Error::InvalidLog);
    }
    let offset_bits = 64 - sequence_bits;
    let mask = (1_u64 << offset_bits) - 1;
    let offset = (lsn & mask).checked_mul(8).ok_or(Error::Overflow)?;
    if offset >= log_bytes {
        return Err(Error::InvalidLog);
    }
    Ok(offset)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtfsCheckpoint {
    pub major_version: u32,
    pub minor_version: u32,
    pub start_lsn: u64,
    pub open_attributes_lsn: u64,
    pub attribute_names_lsn: u64,
    pub dirty_pages_lsn: u64,
    pub transactions_lsn: u64,
    pub open_attributes_bytes: u32,
    pub attribute_names_bytes: u32,
    pub dirty_pages_bytes: u32,
    pub transactions_bytes: u32,
}

impl NtfsCheckpoint {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let data = range(payload, 0, 0x40).map_err(|_| Error::InvalidLog)?;
        let major_version = u32_at(data, 0).map_err(|_| Error::InvalidLog)?;
        let minor_version = u32_at(data, 4).map_err(|_| Error::InvalidLog)?;
        if !matches!((major_version, minor_version), (0, 0) | (1, 0)) {
            return Err(Error::Unsupported);
        }
        let checkpoint = Self {
            major_version,
            minor_version,
            start_lsn: u64_at(data, 8).map_err(|_| Error::InvalidLog)?,
            open_attributes_lsn: u64_at(data, 0x10).map_err(|_| Error::InvalidLog)?,
            attribute_names_lsn: u64_at(data, 0x18).map_err(|_| Error::InvalidLog)?,
            dirty_pages_lsn: u64_at(data, 0x20).map_err(|_| Error::InvalidLog)?,
            transactions_lsn: u64_at(data, 0x28).map_err(|_| Error::InvalidLog)?,
            open_attributes_bytes: u32_at(data, 0x30).map_err(|_| Error::InvalidLog)?,
            attribute_names_bytes: u32_at(data, 0x34).map_err(|_| Error::InvalidLog)?,
            dirty_pages_bytes: u32_at(data, 0x38).map_err(|_| Error::InvalidLog)?,
            transactions_bytes: u32_at(data, 0x3c).map_err(|_| Error::InvalidLog)?,
        };
        for (lsn, size) in [
            (checkpoint.open_attributes_lsn, checkpoint.open_attributes_bytes),
            (checkpoint.attribute_names_lsn, checkpoint.attribute_names_bytes),
            (checkpoint.dirty_pages_lsn, checkpoint.dirty_pages_bytes),
            (checkpoint.transactions_lsn, checkpoint.transactions_bytes),
        ] {
            if (lsn == 0) != (size == 0) {
                return Err(Error::InvalidLog);
            }
        }
        Ok(checkpoint)
    }
}

/// Checked header and entries of an NTFS restart table. used is the
/// number of table slots, whereas allocated counts slots whose first word
/// is the allocation marker. No target resolution follows from this parse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestartTable<'a> {
    data: &'a [u8],
    pub entry_bytes: u16,
    pub used: u16,
    pub allocated: u16,
}

impl<'a> RestartTable<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let header = range(data, 0, 0x18).map_err(|_| Error::InvalidLog)?;
        let entry_bytes = u16_at(header, 0).map_err(|_| Error::InvalidLog)?;
        let used = u16_at(header, 2).map_err(|_| Error::InvalidLog)?;
        let allocated = u16_at(header, 4).map_err(|_| Error::InvalidLog)?;
        let table_bytes = usize::from(entry_bytes)
            .checked_mul(usize::from(used))
            .and_then(|n| n.checked_add(0x18))
            .ok_or(Error::Overflow)?;
        if entry_bytes < 4 || allocated > used || table_bytes > data.len() {
            return Err(Error::InvalidLog);
        }
        let valid_pointer = |pointer: u32| -> bool {
            if pointer == 0 {
                return true;
            }
            let pointer = pointer as usize;
            pointer >= 0x18
                && pointer.checked_add(4).is_some_and(|end| end <= table_bytes)
                && (pointer - 0x18) % usize::from(entry_bytes) == 0
        };
        let first_free = u32_at(header, 0x10).map_err(|_| Error::InvalidLog)?;
        let last_free = u32_at(header, 0x14).map_err(|_| Error::InvalidLog)?;
        if !valid_pointer(first_free) || !valid_pointer(last_free) {
            return Err(Error::InvalidLog);
        }
        let mut actual_allocated = 0_u16;
        for slot in 0..usize::from(used) {
            let offset = 0x18 + slot * usize::from(entry_bytes);
            let next = u32_at(data, offset).map_err(|_| Error::InvalidLog)?;
            if next == u32::MAX {
                actual_allocated += 1;
            }
            if next != u32::MAX && !valid_pointer(next) {
                return Err(Error::InvalidLog);
            }
        }
        if actual_allocated != allocated {
            return Err(Error::InvalidLog);
        }
        let mut pointer = first_free;
        let mut previous = 0;
        let mut free_count = 0;
        for _ in 0..=used {
            if pointer == 0 {
                if previous != last_free || free_count != used - allocated {
                    return Err(Error::InvalidLog);
                }
                return Ok(Self { data: &data[..table_bytes], entry_bytes, used, allocated });
            }
            previous = pointer;
            free_count += 1;
            pointer = u32_at(data, pointer as usize).map_err(|_| Error::InvalidLog)?;
            if pointer == u32::MAX || !valid_pointer(pointer) {
                return Err(Error::InvalidLog);
            }
        }
        Err(Error::InvalidLog)
    }

    pub fn visit_allocated(&self, mut visitor: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
        for slot in 0..usize::from(self.used) {
            let offset = 0x18 + slot * usize::from(self.entry_bytes);
            if u32_at(self.data, offset)? == u32::MAX {
                visitor(range(self.data, offset, self.entry_bytes as usize)?)?;
            }
        }
        Ok(())
    }

    pub fn visit_slots(&self, mut visitor: impl FnMut(u32, &[u8]) -> Result<()>) -> Result<()> {
        for slot in 0..usize::from(self.used) {
            let offset = 0x18 + slot * usize::from(self.entry_bytes);
            if u32_at(self.data, offset)? == u32::MAX {
                visitor(offset as u32, range(self.data, offset, self.entry_bytes as usize)?)?;
            }
        }
        Ok(())
    }
}

/// Both redundant restart pages are required for an affirmative inactive
/// result. If either copy is invalid, no write permission can follow.
pub fn classify_restart_pair(first: Result<RestartPage>, second: Result<RestartPage>) -> LogState {
    let (Ok(a), Ok(b)) = (first, second) else {
        return LogState::NeedsReview;
    };
    if a.system_page_bytes != b.system_page_bytes
        || a.log_page_bytes != b.log_page_bytes
        || (a.major_version, a.minor_version) != (b.major_version, b.minor_version)
        || a.log_bytes != b.log_bytes
        || a.chkdsk_marker != b.chkdsk_marker
        || (a.current_lsn == b.current_lsn && !a.same_checkpoint(b))
    {
        return LogState::NeedsReview;
    }
    if a.chkdsk_marker {
        return if a.current_lsn == b.current_lsn { LogState::CheckedVolume } else { LogState::NeedsReview };
    }
    // Equal checkpoints with a partially published clean flag still need recovery.
    let latest = if a.current_lsn > b.current_lsn
        || (a.current_lsn == b.current_lsn && (!a.clean_shutdown || b.clean_shutdown))
    {
        a
    } else {
        b
    };
    if latest.clean_shutdown {
        LogState::CleanShutdown
    } else if latest.active_clients {
        LogState::ReplayRequired
    } else {
        LogState::NoActiveClients
    }
}

/// A validated, caller-owned copy of one $LogFile record page. This parser
/// does not resolve tail copies, wrapped LSNs, or records spanning pages.
pub struct RecordPage<'a> {
    data: &'a [u8],
    pub last_lsn: u64,
    pub last_end_lsn: u64,
    pub page_count: u16,
    pub page_position: u16,
    pub file_offset: u32,
    pub ends_record: bool,
    first_record_offset: usize,
    next_record_offset: usize,
}

impl<'a> RecordPage<'a> {
    pub fn parse(page: &'a mut [u8], bytes_per_sector: u16, first_record_offset: u16) -> Result<Self> {
        if page.len() < 512 || &page[..4] != b"RCRD" {
            return Err(Error::InvalidLog);
        }
        let first = usize::from(first_record_offset);
        if first < 0x30 || first % 8 != 0 || first >= page.len() {
            return Err(Error::InvalidLog);
        }
        apply_fixups(page, bytes_per_sector, 0x28, first).map_err(|_| Error::InvalidLog)?;
        let flags = u32_at(page, 0x10).map_err(|_| Error::InvalidLog)?;
        let count = u16_at(page, 0x14).map_err(|_| Error::InvalidLog)?;
        let position = u16_at(page, 0x16).map_err(|_| Error::InvalidLog)?;
        let next = usize::from(u16_at(page, 0x18).map_err(|_| Error::InvalidLog)?);
        let continuation_only = count > 1 && position > 1 && flags & 1 == 0 && next == 0;
        // Windows 11 sets bit 1 on multi-page transfer pages. Bit 0 still
        // denotes that the page contains a record end.
        if flags & !3 != 0
            || count == 0
            || position == 0
            || position > count
            || (!continuation_only && (next < first || next > page.len() || next % 8 != 0))
        {
            return Err(Error::InvalidLog);
        }
        Ok(Self {
            last_lsn: u64_at(page, 8).map_err(|_| Error::InvalidLog)?,
            last_end_lsn: u64_at(page, 0x20).map_err(|_| Error::InvalidLog)?,
            page_count: count,
            page_position: position,
            file_offset: u32_at(page, 0x3c).map_err(|_| Error::InvalidLog)?,
            ends_record: flags & 1 != 0,
            data: page,
            first_record_offset: first,
            next_record_offset: next,
        })
    }

    /// Visit records wholly contained in this page. Continuation/multi-page
    /// records are deliberately refused; callers must not replay a subset.
    pub fn visit_single_page_records(&self, mut visitor: impl FnMut(LfsRecord<'_>) -> Result<()>) -> Result<u32> {
        if self.page_position != 1 {
            return Err(Error::Unsupported);
        }
        let mut offset = self.first_record_offset;
        let mut count = 0_u32;
        while offset < self.next_record_offset {
            let available =
                range(self.data, offset, self.next_record_offset - offset).map_err(|_| Error::InvalidLog)?;
            let record = LfsRecord::parse(available)?;
            if record.multi_page {
                return Err(Error::Unsupported);
            }
            let padded = record.raw().len().checked_add(7).ok_or(Error::Overflow)? & !7;
            offset = offset.checked_add(padded).ok_or(Error::Overflow)?;
            if offset > self.next_record_offset {
                return Err(Error::InvalidLog);
            }
            visitor(record)?;
            count = count.checked_add(1).ok_or(Error::Overflow)?;
        }
        Ok(count)
    }

    /// Read a record whose header and payload are wholly inside this page.
    /// A multi-page transfer can still contain such records. The caller must
    /// establish that offset is an actual record boundary by checking LSN,
    /// client identity, and the surrounding transfer before replay use.
    pub fn contained_record_at(&self, offset: usize) -> Result<LfsRecord<'_>> {
        if offset < self.first_record_offset || offset >= self.next_record_offset || offset % 8 != 0 {
            return Err(Error::InvalidLog);
        }
        let record = LfsRecord::parse(
            range(self.data, offset, self.next_record_offset - offset).map_err(|_| Error::InvalidLog)?,
        )?;
        if record.multi_page {
            return Err(Error::Unsupported);
        }
        Ok(record)
    }

    /// Fixed-up bytes of this caller-owned page, for bounded read-only
    /// reconstruction of a record that continues on following pages.
    pub fn bytes(&self) -> &[u8] {
        self.data
    }

    pub fn next_record_offset(&self) -> usize {
        self.next_record_offset
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LfsRecord<'a> {
    raw: &'a [u8],
    pub this_lsn: u64,
    pub previous_lsn: u64,
    pub undo_next_lsn: u64,
    pub client_sequence: u16,
    pub client_index: u16,
    pub record_type: u32,
    pub transaction_id: u32,
    pub multi_page: bool,
}

impl<'a> LfsRecord<'a> {
    pub fn peek_total_bytes(data: &[u8]) -> Result<usize> {
        let header = range(data, 0, lfs_layout::HEADER_BYTES).map_err(|_| Error::InvalidLog)?;
        let flags = u16_at(header, lfs_layout::FLAGS_OFFSET).map_err(|_| Error::InvalidLog)?;
        let record_type = u32_at(header, lfs_layout::TYPE_OFFSET).map_err(|_| Error::InvalidLog)?;
        // Bit 0 denotes spanning; bits 1/2 denote absent redo/undo buffers.
        if flags & !7 != 0 || !matches!(record_type, lfs_layout::UPDATE_RECORD | lfs_layout::CHECKPOINT_RECORD) {
            return Err(Error::InvalidLog);
        }
        let payload_bytes =
            usize::try_from(u32_at(header, 0x18).map_err(|_| Error::InvalidLog)?).map_err(|_| Error::Overflow)?;
        lfs_layout::HEADER_BYTES.checked_add(payload_bytes).ok_or(Error::Overflow)
    }

    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let header = range(data, 0, lfs_layout::HEADER_BYTES).map_err(|_| Error::InvalidLog)?;
        let length = Self::peek_total_bytes(data)?;
        let flags = u16_at(header, lfs_layout::FLAGS_OFFSET).map_err(|_| Error::InvalidLog)?;
        let record_type = u32_at(header, lfs_layout::TYPE_OFFSET).map_err(|_| Error::InvalidLog)?;
        let raw = range(data, 0, length).map_err(|_| {
            if flags & lfs_layout::MULTI_PAGE != 0 {
                Error::Unsupported
            } else {
                Error::InvalidLog
            }
        })?;
        Ok(Self {
            raw,
            this_lsn: u64_at(header, lfs_layout::THIS_LSN_OFFSET).map_err(|_| Error::InvalidLog)?,
            previous_lsn: u64_at(header, 8).map_err(|_| Error::InvalidLog)?,
            undo_next_lsn: u64_at(header, 0x10).map_err(|_| Error::InvalidLog)?,
            client_sequence: u16_at(header, lfs_layout::CLIENT_SEQUENCE_OFFSET).map_err(|_| Error::InvalidLog)?,
            client_index: u16_at(header, lfs_layout::CLIENT_INDEX_OFFSET).map_err(|_| Error::InvalidLog)?,
            record_type,
            transaction_id: u32_at(header, 0x24).map_err(|_| Error::InvalidLog)?,
            multi_page: flags & lfs_layout::MULTI_PAGE != 0,
        })
    }

    pub fn raw(self) -> &'a [u8] {
        self.raw
    }

    pub fn payload(self) -> &'a [u8] {
        &self.raw[lfs_layout::HEADER_BYTES..]
    }

    pub fn ntfs_operation(self) -> Result<NtfsLogOperation<'a>> {
        if self.record_type != lfs_layout::UPDATE_RECORD {
            return Err(Error::Unsupported);
        }
        NtfsLogOperation::parse(self.payload())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtfsLogOperation<'a> {
    pub redo_code: u16,
    pub undo_code: u16,
    pub target_attribute: u16,
    pub target_vcn: u64,
    pub record_offset: u16,
    pub attribute_offset: u16,
    pub cluster_offset: u16,
    pub redo: &'a [u8],
    pub undo: &'a [u8],
    pub lcns: &'a [u8],
}

impl<'a> NtfsLogOperation<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let header = range(data, 0, log_operation::HEADER_BYTES).map_err(|_| Error::InvalidLog)?;
        let lcn_count = usize::from(u16_at(header, 0x0e).map_err(|_| Error::InvalidLog)?);
        let lcn_bytes = lcn_count.checked_mul(8).ok_or(Error::Overflow)?;
        let lcns = range(data, log_operation::HEADER_BYTES, lcn_bytes).map_err(|_| Error::InvalidLog)?;
        let minimum = log_operation::HEADER_BYTES.checked_add(lcn_bytes).ok_or(Error::Overflow)?;
        let redo_code = u16_at(header, log_operation::REDO_CODE_OFFSET).map_err(|_| Error::InvalidLog)?;
        let undo_code = u16_at(header, log_operation::UNDO_CODE_OFFSET).map_err(|_| Error::InvalidLog)?;
        if redo_code > 0x25 || undo_code > 0x25 {
            return Err(Error::Unsupported);
        }
        let target_attribute = u16_at(header, 0x0c).map_err(|_| Error::InvalidLog)?;
        if target_attribute == 0 && (target_required(redo_code) || target_required(undo_code)) {
            return Err(Error::InvalidLog);
        }
        let redo_offset = usize::from(u16_at(header, 4).map_err(|_| Error::InvalidLog)?);
        let redo_bytes = usize::from(u16_at(header, 6).map_err(|_| Error::InvalidLog)?);
        let undo_offset = usize::from(u16_at(header, 8).map_err(|_| Error::InvalidLog)?);
        let undo_bytes = usize::from(u16_at(header, 10).map_err(|_| Error::InvalidLog)?);
        if redo_offset % 8 != 0 || undo_offset % 8 != 0 {
            return Err(Error::InvalidLog);
        }
        let redo = if redo_bytes == 0 {
            &[][..]
        } else {
            if redo_offset < minimum {
                return Err(Error::InvalidLog);
            }
            range(data, redo_offset, redo_bytes).map_err(|_| Error::InvalidLog)?
        };
        let undo = if undo_bytes == 0 {
            &[][..]
        } else {
            if undo_offset < minimum {
                return Err(Error::InvalidLog);
            }
            range(data, undo_offset, undo_bytes).map_err(|_| Error::InvalidLog)?
        };
        Ok(Self {
            redo_code,
            undo_code,
            target_attribute,
            target_vcn: u64_at(header, 0x18).map_err(|_| Error::InvalidLog)?,
            record_offset: u16_at(header, log_operation::RECORD_OFFSET_OFFSET)?,
            attribute_offset: u16_at(header, 0x12)?,
            cluster_offset: u16_at(header, 0x14)?,
            redo,
            undo,
            lcns,
        })
    }
}

fn target_required(operation: u16) -> bool {
    const REQUIRED: [u8; 5] = [0xfc, 0xfb, 0xff, 0x10, 0x06];
    operation <= 0x22 && REQUIRED[usize::from(operation / 8)] & (1_u8 << (operation % 8)) != 0
}

/// Structurally encodable NTFS client payload. The caller must supply a
/// supported transaction operation and valid target; encoding this payload
/// alone does not make a Windows-compatible $LogFile transaction.
pub struct NtfsOperationInput<'a> {
    pub redo_code: u16,
    pub undo_code: u16,
    pub target_attribute: u16,
    pub target_vcn: u64,
    pub lcns: &'a [u64],
    pub redo: &'a [u8],
    pub undo: &'a [u8],
}

fn align_eight(value: usize) -> Result<usize> {
    Ok(value.checked_add(7).ok_or(Error::Overflow)? & !7)
}

/// Advance an existing active-client restart page to a separately durable
/// empty checkpoint. The caller must flush recovered metadata, then the new
/// checkpoint record, before publishing either restart page. This leaves the
/// client active and does not clear the NTFS volume dirty flag.
pub fn advance_restart_checkpoint(page: &mut [u8], sector: u16, lsn: u64) -> Result<()> {
    advance_restart(page, sector, lsn, 0x40, true)
}

/// Publish the end of already-durable client records without advancing the
/// oldest LSN or discarding the prior checkpoint/transaction history.
pub fn advance_restart_tail(page: &mut [u8], sector: u16, lsn: u64, payload_bytes: u32) -> Result<()> {
    advance_restart(page, sector, lsn, payload_bytes, false)
}

fn advance_restart(page: &mut [u8], sector: u16, lsn: u64, payload_bytes: u32, checkpoint: bool) -> Result<()> {
    let restart = RestartPage::parse(page, sector)?;
    let client = restart.client.ok_or(Error::InvalidLog)?;
    if !matches!((restart.major_version, restart.minor_version), (1, 1) | (2, 0)) || lsn <= restart.current_lsn {
        return Err(Error::Unsupported);
    }
    let offset = lsn_stream_offset(lsn, restart.sequence_bits, restart.log_bytes)?;
    if offset < u64::from(restart.log_page_bytes) * if restart.major_version == 1 { 4 } else { 34 }
        || offset % u64::from(restart.log_page_bytes) != u64::from(restart.record_data_offset)
    {
        return Err(Error::InvalidLog);
    }
    let area = usize::from(u16_at(page, 0x18)?);
    let client_offset =
        area + usize::from(u16_at(page, area + 0x16)?) + usize::from(client.index) * CLIENT_RECORD_BYTES;
    page[area..area + 8].copy_from_slice(&lsn.to_le_bytes());
    // The restart area stores total client-record bytes, including for a
    // transfer spanning pages. The writer separately reserves every fragment.
    if payload_bytes == 0 || payload_bytes > 1024 * 1024 || u64::from(payload_bytes) + 48 > restart.log_bytes / 2 {
        return Err(Error::Unsupported);
    }
    page[area + 0x20..area + 0x24].copy_from_slice(&payload_bytes.to_le_bytes());
    if checkpoint {
        page[client_offset..client_offset + 8].copy_from_slice(&lsn.to_le_bytes());
        page[client_offset + 8..client_offset + 16].copy_from_slice(&lsn.to_le_bytes());
    }
    super::mft::protect_fixups(page)
}

/// Publish the standard LFS clean-shutdown bit only after the final empty
/// checkpoint, and clear it durably before accepting a new writer session.
pub(crate) fn set_restart_clean(page: &mut [u8], sector: u16, clean: bool) -> Result<()> {
    let restart = RestartPage::parse(page, sector)?;
    if clean
        && restart.client.is_none_or(|c| c.oldest_lsn != restart.current_lsn || c.restart_lsn != restart.current_lsn)
    {
        return Err(Error::InvalidLog);
    }
    let at = usize::from(u16_at(page, 0x18)?) + 0x0e;
    let flags = (u16_at(page, at)? & !2) | if clean { 2 } else { 0 };
    page[at..at + 2].copy_from_slice(&flags.to_le_bytes());
    super::mft::protect_fixups(page)
}

/// Initialize a 4 KiB LFS 1.1 restart page pointing at an already encoded
/// empty checkpoint. Only for a new, private copy with an uninitialized log.
pub fn encode_initial_restart(page: &mut [u8], log_bytes: u64, checkpoint_lsn: u64) -> Result<()> {
    if page.len() != 4096 || !(196608..=64 * 1024 * 1024).contains(&log_bytes) || log_bytes % 4096 != 0 {
        return Err(Error::Unsupported);
    }
    let sequence_bits = 67 - (64 - log_bytes.leading_zeros());
    if lsn_stream_offset(checkpoint_lsn, sequence_bits, log_bytes)? != 4 * 4096 + 64 {
        return Err(Error::InvalidLog);
    }
    page.fill(0);
    page[..4].copy_from_slice(b"RSTR");
    page[4..6].copy_from_slice(&30_u16.to_le_bytes());
    page[6..8].copy_from_slice(&9_u16.to_le_bytes());
    page[16..20].copy_from_slice(&4096_u32.to_le_bytes());
    page[20..24].copy_from_slice(&4096_u32.to_le_bytes());
    page[24..26].copy_from_slice(&48_u16.to_le_bytes());
    page[26..28].copy_from_slice(&1_u16.to_le_bytes());
    page[28..30].copy_from_slice(&1_u16.to_le_bytes());
    let area = 48;
    page[area..area + 8].copy_from_slice(&checkpoint_lsn.to_le_bytes());
    page[area + 8..area + 10].copy_from_slice(&1_u16.to_le_bytes());
    page[area + 10..area + 12].copy_from_slice(&NO_CLIENT.to_le_bytes());
    page[area + 16..area + 20].copy_from_slice(&sequence_bits.to_le_bytes());
    page[area + 20..area + 22].copy_from_slice(&224_u16.to_le_bytes());
    page[area + 22..area + 24].copy_from_slice(&64_u16.to_le_bytes());
    page[area + 24..area + 32].copy_from_slice(&log_bytes.to_le_bytes());
    page[area + 32..area + 36].copy_from_slice(&64_u32.to_le_bytes());
    page[area + 36..area + 38].copy_from_slice(&48_u16.to_le_bytes());
    page[area + 38..area + 40].copy_from_slice(&64_u16.to_le_bytes());
    page[area + 40..area + 44].copy_from_slice(&1_u32.to_le_bytes());
    let client = area + 64;
    page[client..client + 8].copy_from_slice(&checkpoint_lsn.to_le_bytes());
    page[client + 8..client + 16].copy_from_slice(&checkpoint_lsn.to_le_bytes());
    page[client + 16..client + 20].fill(0xff);
    page[client + 28..client + 32].copy_from_slice(&8_u32.to_le_bytes());
    page[client + 32..client + 40].copy_from_slice(&[b'N', 0, b'T', 0, b'F', 0, b'S', 0]);
    page[30..32].copy_from_slice(&1_u16.to_le_bytes());
    for index in 0..8 {
        let tail = (index + 1) * 512 - 2;
        let original = [page[tail], page[tail + 1]];
        page[32 + index * 2..34 + index * 2].copy_from_slice(&original);
        page[tail..tail + 2].copy_from_slice(&1_u16.to_le_bytes());
    }
    Ok(())
}

/// Encode one LOG_REC_HDR with redo/undo payloads into caller-owned space.
/// The output is untouched if validation or capacity checks fail.
pub fn encode_ntfs_operation(input: &NtfsOperationInput<'_>, output: &mut [u8]) -> Result<usize> {
    if input.redo_code > 0x25 || input.undo_code > 0x25 {
        return Err(Error::Unsupported);
    }
    if input.target_attribute == 0 && (target_required(input.redo_code) || target_required(input.undo_code)) {
        return Err(Error::InvalidLog);
    }
    let lcn_count = u16::try_from(input.lcns.len()).map_err(|_| Error::Overflow)?;
    let redo_len = u16::try_from(input.redo.len()).map_err(|_| Error::Overflow)?;
    let undo_len = u16::try_from(input.undo.len()).map_err(|_| Error::Overflow)?;
    let lcn_bytes = input.lcns.len().checked_mul(8).ok_or(Error::Overflow)?;
    let minimum = 0x20_usize.checked_add(lcn_bytes.max(8)).ok_or(Error::Overflow)?;
    let redo_offset = align_eight(minimum)?;
    let undo_offset = align_eight(redo_offset.checked_add(input.redo.len()).ok_or(Error::Overflow)?)?;
    let end = undo_offset.checked_add(input.undo.len()).ok_or(Error::Overflow)?;
    let total = align_eight(end)?;
    let redo_offset = u16::try_from(redo_offset).map_err(|_| Error::Overflow)?;
    let undo_offset = u16::try_from(undo_offset).map_err(|_| Error::Overflow)?;
    if total > output.len() {
        return Err(Error::Truncated);
    }
    output[..total].fill(0);
    output[0..2].copy_from_slice(&input.redo_code.to_le_bytes());
    output[2..4].copy_from_slice(&input.undo_code.to_le_bytes());
    output[4..6].copy_from_slice(&redo_offset.to_le_bytes());
    output[6..8].copy_from_slice(&redo_len.to_le_bytes());
    output[8..10].copy_from_slice(&undo_offset.to_le_bytes());
    output[10..12].copy_from_slice(&undo_len.to_le_bytes());
    output[12..14].copy_from_slice(&input.target_attribute.to_le_bytes());
    output[14..16].copy_from_slice(&lcn_count.to_le_bytes());
    output[0x18..0x20].copy_from_slice(&input.target_vcn.to_le_bytes());
    for (index, lcn) in input.lcns.iter().enumerate() {
        let start = 0x20 + index * 8;
        output[start..start + 8].copy_from_slice(&lcn.to_le_bytes());
    }
    range_mut(output, usize::from(redo_offset), input.redo.len())?.copy_from_slice(input.redo);
    range_mut(output, usize::from(undo_offset), input.undo.len())?.copy_from_slice(input.undo);
    Ok(total)
}

pub struct LfsRecordInput<'a> {
    pub this_lsn: u64,
    pub previous_lsn: u64,
    pub undo_next_lsn: u64,
    pub client_sequence: u16,
    pub client_index: u16,
    pub record_type: u32,
    pub transaction_id: u32,
    /// Bit 0 denotes a spanning record. Bits 1/2 are the native LFS
    /// no-redo/no-undo flags observed in Windows client records.
    pub flags: u16,
    pub payload: &'a [u8],
}

/// Encode one LFS_RECORD_HDR and payload, without a containing RCRD
/// page, fixups, or restart-area update. Those are mandatory for a writer.
pub fn encode_lfs_record(input: &LfsRecordInput<'_>, output: &mut [u8]) -> Result<usize> {
    if !matches!(input.record_type, lfs_layout::UPDATE_RECORD | lfs_layout::CHECKPOINT_RECORD) || input.flags & !7 != 0
    {
        return Err(Error::InvalidLog);
    }
    let payload_len = u32::try_from(input.payload.len()).map_err(|_| Error::Overflow)?;
    let total = 0x30_usize.checked_add(input.payload.len()).ok_or(Error::Overflow)?;
    if total > output.len() {
        return Err(Error::Truncated);
    }
    output[..total].fill(0);
    output[0..8].copy_from_slice(&input.this_lsn.to_le_bytes());
    output[8..16].copy_from_slice(&input.previous_lsn.to_le_bytes());
    output[16..24].copy_from_slice(&input.undo_next_lsn.to_le_bytes());
    output[0x18..0x1c].copy_from_slice(&payload_len.to_le_bytes());
    output[0x1c..0x1e].copy_from_slice(&input.client_sequence.to_le_bytes());
    output[0x1e..0x20].copy_from_slice(&input.client_index.to_le_bytes());
    output[lfs_layout::TYPE_OFFSET..lfs_layout::TYPE_OFFSET + core::mem::size_of::<u32>()]
        .copy_from_slice(&input.record_type.to_le_bytes());
    output[0x24..0x28].copy_from_slice(&input.transaction_id.to_le_bytes());
    output[lfs_layout::FLAGS_OFFSET..lfs_layout::FLAGS_OFFSET + core::mem::size_of::<u16>()]
        .copy_from_slice(&input.flags.to_le_bytes());
    output[0x30..total].copy_from_slice(input.payload);
    Ok(total)
}

/// Build an RCRD page of aligned, non-spanning records with shared fixups.
/// This is a format primitive, not a circular-log append or durable commit.
pub fn encode_single_record_page(
    page: &mut [u8],
    bytes_per_sector: u16,
    first_record_offset: u16,
    file_offset: u32,
    record: &[u8],
) -> Result<()> {
    let sector = usize::from(bytes_per_sector);
    let first = usize::from(first_record_offset);
    let mut cursor = 0;
    let mut last_lsn = 0;
    while cursor < record.len() {
        let parsed = LfsRecord::parse(&record[cursor..])?;
        if parsed.multi_page || parsed.this_lsn <= last_lsn {
            return Err(Error::Unsupported);
        }
        last_lsn = parsed.this_lsn;
        cursor += align_eight(parsed.raw().len())?;
    }
    if cursor != align_eight(record.len())? || last_lsn == 0 {
        return Err(Error::InvalidLog);
    }
    if page.len() < 512
        || page.len() > MAX_PAGE_BYTES as usize
        || !page.len().is_power_of_two()
        || sector < 512
        || !sector.is_power_of_two()
        || page.len() % sector != 0
        || first < 0x40
        || first % 8 != 0
    {
        return Err(Error::InvalidLog);
    }
    let sectors = page.len() / sector;
    let usa_end = 0x28_usize.checked_add((sectors + 1) * 2).ok_or(Error::Overflow)?;
    if usa_end > 0x3c || first < usa_end {
        return Err(Error::Unsupported);
    }
    let padded = align_eight(record.len())?;
    let next = first.checked_add(padded).ok_or(Error::Overflow)?;
    let next_u16 = u16::try_from(next).map_err(|_| Error::Overflow)?;
    let usa_count = u16::try_from(sectors + 1).map_err(|_| Error::Overflow)?;
    if next > page.len() {
        return Err(Error::Truncated);
    }
    page.fill(0);
    page[..4].copy_from_slice(b"RCRD");
    page[4..6].copy_from_slice(&0x28_u16.to_le_bytes());
    page[6..8].copy_from_slice(&usa_count.to_le_bytes());
    page[8..16].copy_from_slice(&last_lsn.to_le_bytes());
    page[0x10..0x14].copy_from_slice(&1_u32.to_le_bytes());
    page[0x14..0x16].copy_from_slice(&1_u16.to_le_bytes());
    page[0x16..0x18].copy_from_slice(&1_u16.to_le_bytes());
    page[0x18..0x1a].copy_from_slice(&next_u16.to_le_bytes());
    page[0x20..0x28].copy_from_slice(&last_lsn.to_le_bytes());
    page[0x3c..0x40].copy_from_slice(&file_offset.to_le_bytes());
    page[first..first + record.len()].copy_from_slice(record);
    let sequence = 0xa55a_u16.to_le_bytes();
    page[0x28..0x2a].copy_from_slice(&sequence);
    for index in 0..sectors {
        let tail = (index + 1) * sector - 2;
        let original = [page[tail], page[tail + 1]];
        page[0x2a + index * 2..0x2c + index * 2].copy_from_slice(&original);
        page[tail..tail + 2].copy_from_slice(&sequence);
    }
    Ok(())
}

/// Encode one page of a record occupying a fresh transfer group. The caller
/// reserves every page, supplies each circular file offset, advances USA tokens
/// on reuse and makes the complete group durable before metadata changes.
pub fn encode_record_fragment(page: &mut [u8], file_offset: u32, record: &[u8], fragment: usize) -> Result<()> {
    let r = LfsRecord::parse(record)?;
    if page.len() != log_page_layout::PUBLICATION_PAGE_BYTES || r.raw().len() != record.len() {
        return Err(Error::Unsupported);
    }
    let count = record.len().div_ceil(log_page_layout::FRAGMENT_BYTES);
    if count == 0 || count > 256 || fragment >= count || r.multi_page != (count > 1) {
        return Err(Error::InvalidLog);
    }
    let begin = fragment * log_page_layout::FRAGMENT_BYTES;
    let chunk = &record[begin..record.len().min(begin + log_page_layout::FRAGMENT_BYTES)];
    let last = fragment + 1 == count;
    page.fill(0);
    page[..4].copy_from_slice(b"RCRD");
    page[4..6].copy_from_slice(&40u16.to_le_bytes());
    page[6..8].copy_from_slice(&9u16.to_le_bytes());
    page[8..16].copy_from_slice(&r.this_lsn.to_le_bytes());
    let flags = u32::from(last) | if count > 1 { 2 } else { 0 };
    page[16..20].copy_from_slice(&flags.to_le_bytes());
    page[20..22].copy_from_slice(&(count as u16).to_le_bytes());
    page[22..24].copy_from_slice(&((fragment + 1) as u16).to_le_bytes());
    let next = if last {
        align_eight(log_page_layout::RECORD_DATA_OFFSET + chunk.len())?
    } else {
        log_page_layout::RECORD_DATA_OFFSET
    };
    page[24..26].copy_from_slice(&(next as u16).to_le_bytes());
    if last {
        page[32..40].copy_from_slice(&r.this_lsn.to_le_bytes());
    }
    page[60..64].copy_from_slice(&file_offset.to_le_bytes());
    page[log_page_layout::RECORD_DATA_OFFSET..log_page_layout::RECORD_DATA_OFFSET + chunk.len()].copy_from_slice(chunk);
    page[40..42].copy_from_slice(&1u16.to_le_bytes());
    for sector in 0..8 {
        let tail = (sector + 1) * 512 - 2;
        let old = [page[tail], page[tail + 1]];
        page[42 + sector * 2..44 + sector * 2].copy_from_slice(&old);
        page[tail..tail + 2].copy_from_slice(&1u16.to_le_bytes());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(active: bool, lsn: u64) -> [u8; 4096] {
        let mut page = [0_u8; 4096];
        page[..4].copy_from_slice(b"RSTR");
        page[4..6].copy_from_slice(&0x1e_u16.to_le_bytes());
        page[6..8].copy_from_slice(&9_u16.to_le_bytes());
        page[0x10..0x14].copy_from_slice(&4096_u32.to_le_bytes());
        page[0x14..0x18].copy_from_slice(&4096_u32.to_le_bytes());
        page[0x18..0x1a].copy_from_slice(&0x30_u16.to_le_bytes());
        page[0x1a..0x1c].copy_from_slice(&1_u16.to_le_bytes());
        page[0x1c..0x1e].copy_from_slice(&1_u16.to_le_bytes());
        let ra = 0x30;
        page[ra..ra + 8].copy_from_slice(&lsn.to_le_bytes());
        page[ra + 8..ra + 10].copy_from_slice(&1_u16.to_le_bytes());
        page[ra + 0x0a..ra + 0x0c].copy_from_slice(&NO_CLIENT.to_le_bytes());
        page[ra + 0x0c..ra + 0x0e].copy_from_slice(&(if active { 0_u16 } else { NO_CLIENT }).to_le_bytes());
        page[ra + 0x10..ra + 0x14].copy_from_slice(&46_u32.to_le_bytes());
        page[ra + 0x14..ra + 0x16].copy_from_slice(&0xe0_u16.to_le_bytes());
        page[ra + 0x16..ra + 0x18].copy_from_slice(&0x40_u16.to_le_bytes());
        page[ra + 0x18..ra + 0x20].copy_from_slice(&0x100000_u64.to_le_bytes());
        page[ra + 0x24..ra + 0x26].copy_from_slice(&0x30_u16.to_le_bytes());
        page[ra + 0x26..ra + 0x28].copy_from_slice(&0x40_u16.to_le_bytes());
        if active {
            let client = ra + 0x40;
            page[client..client + 8].copy_from_slice(&8_u64.to_le_bytes());
            page[client + 8..client + 0x10].copy_from_slice(&9_u64.to_le_bytes());
            page[client + 0x10..client + 0x14].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
            page[client + 0x14..client + 0x16].copy_from_slice(&2_u16.to_le_bytes());
            page[client + 0x1c..client + 0x20].copy_from_slice(&8_u32.to_le_bytes());
            page[client + 0x20..client + 0x28].copy_from_slice(&[b'N', 0, b'T', 0, b'F', 0, b'S', 0]);
        }
        page[0x1e..0x20].copy_from_slice(&0x1234_u16.to_le_bytes());
        for sector in 0..8 {
            let tail = (sector + 1) * 512 - 2;
            let original = [page[tail], page[tail + 1]];
            page[0x20 + sector * 2..0x22 + sector * 2].copy_from_slice(&original);
            page[tail..tail + 2].copy_from_slice(&0x1234_u16.to_le_bytes());
        }
        page
    }

    #[test]
    fn equal_checkpoint_lsn_cannot_choose_conflicting_client_states() {
        let a = RestartPage::parse(&mut page(false, 10), 512).unwrap();
        let b = RestartPage::parse(&mut page(true, 10), 512).unwrap();
        assert_eq!(classify_restart_pair(Ok(a), Ok(b)), LogState::NeedsReview);
        assert_eq!(classify_restart_pair(Ok(b), Ok(a)), LogState::NeedsReview);
    }

    #[test]
    fn restart_pair_uses_newer_copy() {
        let mut first = page(true, 10);
        let mut second = page(false, 11);
        assert_eq!(
            classify_restart_pair(RestartPage::parse(&mut first, 512), RestartPage::parse(&mut second, 512)),
            LogState::NoActiveClients
        );
        let mut first = page(false, 10);
        let mut second = page(true, 11);
        assert_eq!(
            classify_restart_pair(RestartPage::parse(&mut first, 512), RestartPage::parse(&mut second, 512)),
            LogState::ReplayRequired
        );
    }

    #[test]
    fn clean_shutdown_retains_a_valid_client_without_requiring_replay() {
        let mut first = page(true, 10);
        let mut second = page(true, 11);
        second[0x3e..0x40].copy_from_slice(&2_u16.to_le_bytes());
        let first = RestartPage::parse(&mut first, 512).unwrap();
        let second = RestartPage::parse(&mut second, 512).unwrap();
        assert!(second.active_clients);
        assert!(second.client.is_some());
        assert!(second.clean_shutdown);
        assert_eq!(classify_restart_pair(Ok(first), Ok(second)), LogState::CleanShutdown);

        // A later dirty copy supersedes the earlier clean shutdown.
        let newer = RestartPage::parse(&mut page(true, 12), 512).unwrap();
        assert_eq!(classify_restart_pair(Ok(second), Ok(newer)), LogState::ReplayRequired);
    }

    #[test]
    fn clean_shutdown_does_not_hide_torn_or_conflicting_restart_copies() {
        let mut clean = page(true, 11);
        clean[0x3e..0x40].copy_from_slice(&2_u16.to_le_bytes());
        let parsed = RestartPage::parse(&mut clean.clone(), 512).unwrap();
        let dirty = RestartPage::parse(&mut page(true, 11), 512).unwrap();
        assert_eq!(classify_restart_pair(Ok(parsed), Ok(dirty)), LogState::ReplayRequired);
        assert_eq!(classify_restart_pair(Ok(dirty), Ok(parsed)), LogState::ReplayRequired);
        let mut conflicting = dirty;
        conflicting.client.as_mut().unwrap().sequence += 1;
        assert_eq!(classify_restart_pair(Ok(parsed), Ok(conflicting)), LogState::NeedsReview);
        clean[510] ^= 1;
        assert_eq!(classify_restart_pair(Ok(parsed), RestartPage::parse(&mut clean, 512)), LogState::NeedsReview);
    }

    #[test]
    fn torn_or_invalid_copy_requires_review() {
        let mut first = page(false, 10);
        let mut second = page(false, 11);
        second[510] ^= 1;
        assert_eq!(
            classify_restart_pair(RestartPage::parse(&mut first, 512), RestartPage::parse(&mut second, 512)),
            LogState::NeedsReview
        );
    }

    #[test]
    fn validates_active_ntfs_client_and_rejects_wrong_name() {
        let mut bytes = page(true, 10);
        let restart = RestartPage::parse(&mut bytes, 512).unwrap();
        assert_eq!(restart.client.unwrap().restart_lsn, 9);
        let mut bytes = page(true, 10);
        bytes[0x30 + 0x40 + 0x20] = b'X';
        assert!(matches!(RestartPage::parse(&mut bytes, 512), Err(Error::InvalidLog)));
    }

    #[test]
    fn checked_marker_preserves_geometry_and_suppresses_old_clients() {
        let mut first = page(true, 10);
        let mut second = page(true, 9);
        // Client bytes are historical after checked-volume publication.
        first[0x30 + 0x40 + 0x20] = b'X';
        let tail = first[16..].to_vec();
        encode_checked_marker(&mut first, 12).unwrap();
        encode_checked_marker(&mut second, 12).unwrap();
        assert_eq!(&first[16..], tail);
        assert_eq!(&first[..8], b"CHKD\0\0\0\0");
        let a = RestartPage::parse(&mut first, 512).unwrap();
        let b = RestartPage::parse(&mut second, 512).unwrap();
        assert_eq!(a.current_lsn, 12);
        assert!(!a.active_clients);
        assert!(a.client.is_none());
        assert_eq!(classify_restart_pair(Ok(a), Ok(b)), LogState::CheckedVolume);
    }

    #[test]
    fn checked_marker_pairs_reject_partial_or_conflicting_publication() {
        let regular = RestartPage::parse(&mut page(false, 10), 512).unwrap();
        let mut a = page(false, 10);
        encode_checked_marker(&mut a, 12).unwrap();
        let checked = RestartPage::parse(&mut a, 512).unwrap();
        assert_eq!(classify_restart_pair(Ok(checked), Ok(regular)), LogState::NeedsReview);
        let mut b = page(false, 10);
        encode_checked_marker(&mut b, 13).unwrap();
        let other = RestartPage::parse(&mut b, 512).unwrap();
        assert_eq!(classify_restart_pair(Ok(checked), Ok(other)), LogState::NeedsReview);
        let mut bad = page(false, 10);
        bad[4..8].fill(0);
        assert!(RestartPage::parse(&mut bad, 512).is_err());
        encode_checked_marker(&mut bad, 12).unwrap();
        bad[4] = 1;
        assert!(RestartPage::parse(&mut bad, 512).is_err());
        bad[4] = 0;
        bad[0x18..0x1a].copy_from_slice(&4096u16.to_le_bytes());
        assert!(RestartPage::parse(&mut bad, 512).is_err());
        assert!(encode_checked_marker(&mut [0; 15], 12).is_err());
    }

    #[test]
    fn checkpoint_header_and_lsn_mapping_are_bounded() {
        let mut bytes = [0_u8; 0x40];
        bytes[..4].copy_from_slice(&1_u32.to_le_bytes());
        bytes[8..0x10].copy_from_slice(&80_u64.to_le_bytes());
        bytes[0x28..0x30].copy_from_slice(&96_u64.to_le_bytes());
        bytes[0x3c..0x40].copy_from_slice(&0x28_u32.to_le_bytes());
        let parsed = NtfsCheckpoint::parse(&bytes).unwrap();
        assert_eq!(parsed.start_lsn, 80);
        assert_eq!(parsed.transactions_bytes, 0x28);
        assert_eq!(lsn_stream_offset(0x1234, 46, 0x100000), Ok(0x91a0));
        assert_eq!(lsn_stream_offset(0x20000, 46, 0x100000), Err(Error::InvalidLog));
        bytes[0x28..0x30].fill(0);
        assert_eq!(NtfsCheckpoint::parse(&bytes), Err(Error::InvalidLog));
    }

    #[test]
    fn restart_table_rejects_free_chain_cycles() {
        let mut bytes = [0_u8; 0x68];
        bytes[..2].copy_from_slice(&0x28_u16.to_le_bytes());
        bytes[2..4].copy_from_slice(&2_u16.to_le_bytes());
        bytes[4..6].copy_from_slice(&1_u16.to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&0x40_u32.to_le_bytes());
        bytes[0x14..0x18].copy_from_slice(&0x40_u32.to_le_bytes());
        bytes[0x18..0x1c].copy_from_slice(&u32::MAX.to_le_bytes());
        let table = RestartTable::parse(&bytes).unwrap();
        let mut count = 0;
        table
            .visit_allocated(|_| {
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 1);
        bytes[0x40..0x44].copy_from_slice(&0x40_u32.to_le_bytes());
        assert_eq!(RestartTable::parse(&bytes), Err(Error::InvalidLog));
    }

    fn record_page() -> [u8; 4096] {
        let mut page = [0_u8; 4096];
        page[..4].copy_from_slice(b"RCRD");
        page[4..6].copy_from_slice(&0x28_u16.to_le_bytes());
        page[6..8].copy_from_slice(&9_u16.to_le_bytes());
        page[8..16].copy_from_slice(&42_u64.to_le_bytes());
        page[0x10..0x14].copy_from_slice(&1_u32.to_le_bytes());
        page[0x14..0x16].copy_from_slice(&1_u16.to_le_bytes());
        page[0x16..0x18].copy_from_slice(&1_u16.to_le_bytes());
        page[0x18..0x1a].copy_from_slice(&0x98_u16.to_le_bytes());
        page[0x20..0x28].copy_from_slice(&42_u64.to_le_bytes());
        page[0x3c..0x40].copy_from_slice(&0x2000_u32.to_le_bytes());
        page[0x40..0x48].copy_from_slice(&42_u64.to_le_bytes());
        page[0x58..0x5c].copy_from_slice(&0x28_u32.to_le_bytes());
        page[0x60..0x64].copy_from_slice(&1_u32.to_le_bytes());
        page[0x64..0x68].copy_from_slice(&1_u32.to_le_bytes());
        page[0x28..0x2a].copy_from_slice(&0x1234_u16.to_le_bytes());
        for sector in 0..8 {
            let tail = (sector + 1) * 512 - 2;
            let original = [page[tail], page[tail + 1]];
            page[0x2a + sector * 2..0x2c + sector * 2].copy_from_slice(&original);
            page[tail..tail + 2].copy_from_slice(&0x1234_u16.to_le_bytes());
        }
        page
    }

    #[test]
    fn parses_single_page_lfs_and_ntfs_operation() {
        let mut bytes = record_page();
        bytes[0x10..0x14].copy_from_slice(&3_u32.to_le_bytes());
        let page = RecordPage::parse(&mut bytes, 512, 0x40).unwrap();
        assert_eq!(page.last_end_lsn, 42);
        let mut seen = 0;
        assert_eq!(
            page.visit_single_page_records(|record| {
                assert_eq!(record.this_lsn, 42);
                assert_eq!(record.transaction_id, 1);
                let op = record.ntfs_operation()?;
                assert_eq!((op.redo_code, op.undo_code), (0, 0));
                seen += 1;
                Ok(())
            }),
            Ok(1)
        );
        assert_eq!(seen, 1);
    }

    #[test]
    fn refuses_torn_or_overrunning_record_page() {
        let mut bytes = record_page();
        bytes[510] ^= 1;
        assert!(matches!(RecordPage::parse(&mut bytes, 512, 0x40), Err(Error::InvalidLog)));
        let mut bytes = record_page();
        bytes[0x18..0x1a].copy_from_slice(&0x90_u16.to_le_bytes());
        let page = RecordPage::parse(&mut bytes, 512, 0x40).unwrap();
        assert_eq!(page.visit_single_page_records(|_| Ok(())), Err(Error::InvalidLog));
    }

    #[test]
    fn accepts_header_only_continuation_page() {
        let mut bytes = record_page();
        bytes[0x10..0x14].copy_from_slice(&0_u32.to_le_bytes());
        bytes[0x14..0x16].copy_from_slice(&3_u16.to_le_bytes());
        bytes[0x16..0x18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[0x18..0x1a].copy_from_slice(&0_u16.to_le_bytes());
        let page = RecordPage::parse(&mut bytes, 512, 0x40).unwrap();
        assert_eq!((page.page_count, page.page_position), (3, 2));
        assert_eq!(page.contained_record_at(0x40), Err(Error::InvalidLog));
    }

    #[test]
    fn refuses_operation_payload_outside_record() {
        let mut payload = [0_u8; 0x28];
        payload[4..6].copy_from_slice(&0x28_u16.to_le_bytes());
        payload[6..8].copy_from_slice(&8_u16.to_le_bytes());
        assert_eq!(NtfsLogOperation::parse(&payload), Err(Error::InvalidLog));
        let mut payload = [0_u8; 0x28];
        payload[0..2].copy_from_slice(&7_u16.to_le_bytes());
        assert_eq!(NtfsLogOperation::parse(&payload), Err(Error::InvalidLog));
    }

    #[test]
    fn operation_and_lfs_encoders_round_trip() {
        let mut payload = [0xa5_u8; 128];
        let payload_len = encode_ntfs_operation(
            &NtfsOperationInput {
                redo_code: 7,
                undo_code: 7,
                target_attribute: 9,
                target_vcn: 123,
                lcns: &[456, 789],
                redo: &[1, 2, 3],
                undo: &[4, 5],
            },
            &mut payload,
        )
        .unwrap();
        let parsed = NtfsLogOperation::parse(&payload[..payload_len]).unwrap();
        assert_eq!((parsed.redo_code, parsed.undo_code), (7, 7));
        assert_eq!(parsed.target_attribute, 9);
        assert_eq!(parsed.target_vcn, 123);
        assert_eq!(parsed.redo, &[1, 2, 3]);
        assert_eq!(parsed.undo, &[4, 5]);
        assert_eq!(parsed.lcns.len(), 16);
        assert_eq!(u64_at(parsed.lcns, 0).unwrap(), 456);
        assert_eq!(u64_at(parsed.lcns, 8).unwrap(), 789);

        let mut record_bytes = [0_u8; 256];
        let record_len = encode_lfs_record(
            &LfsRecordInput {
                this_lsn: 42,
                previous_lsn: 41,
                undo_next_lsn: 40,
                client_sequence: 2,
                client_index: 0,
                record_type: 1,
                transaction_id: 77,
                flags: 0,
                payload: &payload[..payload_len],
            },
            &mut record_bytes,
        )
        .unwrap();
        let record = LfsRecord::parse(&record_bytes[..record_len]).unwrap();
        assert_eq!(record.this_lsn, 42);
        assert_eq!(record.previous_lsn, 41);
        assert_eq!(record.undo_next_lsn, 40);
        assert_eq!(record.transaction_id, 77);
        assert_eq!(record.ntfs_operation().unwrap(), parsed);
        record_bytes[0x28..0x2a].copy_from_slice(&4_u16.to_le_bytes());
        assert_eq!(LfsRecord::parse(&record_bytes[..record_len]).unwrap().this_lsn, 42);
    }

    #[test]
    fn lfs_absent_buffer_flags_round_trip_and_reject_unknown_bits() {
        let mut bytes = [0xa5; 64];
        let mut input = LfsRecordInput {
            this_lsn: 42,
            previous_lsn: 0,
            undo_next_lsn: 0,
            client_sequence: 0,
            client_index: 0,
            record_type: 1,
            transaction_id: 24,
            flags: 0,
            payload: &[],
        };
        for flags in 0..=7 {
            input.flags = flags;
            let length = encode_lfs_record(&input, &mut bytes).unwrap();
            assert_eq!(u16_at(&bytes, 0x28).unwrap(), flags);
            let parsed = LfsRecord::parse(&bytes[..length]).unwrap();
            assert_eq!(parsed.multi_page, flags & 1 != 0);
        }
        let before = bytes;
        input.flags = 8;
        assert_eq!(encode_lfs_record(&input, &mut bytes), Err(Error::InvalidLog));
        assert_eq!(bytes, before);
        bytes[0x28..0x2a].copy_from_slice(&8_u16.to_le_bytes());
        assert_eq!(LfsRecord::parse(&bytes), Err(Error::InvalidLog));
    }

    #[test]
    fn failed_encoding_preserves_caller_buffer() {
        let mut payload = [0xa5_u8; 16];
        assert_eq!(
            encode_ntfs_operation(
                &NtfsOperationInput {
                    redo_code: 7,
                    undo_code: 7,
                    target_attribute: 1,
                    target_vcn: 0,
                    lcns: &[],
                    redo: &[1],
                    undo: &[2],
                },
                &mut payload,
            ),
            Err(Error::Truncated)
        );
        assert_eq!(payload, [0xa5; 16]);
        assert_eq!(
            encode_lfs_record(
                &LfsRecordInput {
                    this_lsn: 0,
                    previous_lsn: 0,
                    undo_next_lsn: 0,
                    client_sequence: 0,
                    client_index: 0,
                    record_type: 1,
                    transaction_id: 0,
                    flags: 0,
                    payload: &[1],
                },
                &mut payload,
            ),
            Err(Error::Truncated)
        );
        assert_eq!(payload, [0xa5; 16]);
    }

    #[test]
    fn encoded_record_page_round_trips_and_detects_torn_sector() {
        let mut payload = [0_u8; 64];
        let payload_len = encode_ntfs_operation(
            &NtfsOperationInput {
                redo_code: 0,
                undo_code: 0,
                target_attribute: 0,
                target_vcn: 0,
                lcns: &[],
                redo: &[],
                undo: &[],
            },
            &mut payload,
        )
        .unwrap();
        let mut bytes = [0_u8; 128];
        let record_len = encode_lfs_record(
            &LfsRecordInput {
                this_lsn: 99,
                previous_lsn: 98,
                undo_next_lsn: 0,
                client_sequence: 1,
                client_index: 0,
                record_type: 1,
                transaction_id: 4,
                flags: 0,
                payload: &payload[..payload_len],
            },
            &mut bytes,
        )
        .unwrap();
        let mut page = [0_u8; 4096];
        encode_single_record_page(&mut page, 512, 0x40, 0x2000, &bytes[..record_len]).unwrap();
        let mut valid = page;
        let parsed = RecordPage::parse(&mut valid, 512, 0x40).unwrap();
        assert_eq!(parsed.file_offset, 0x2000);
        assert_eq!(parsed.contained_record_at(0x40).unwrap().this_lsn, 99);
        assert_eq!(parsed.contained_record_at(0x48), Err(Error::InvalidLog));
        assert_eq!(
            parsed.visit_single_page_records(|record| {
                assert_eq!(record.this_lsn, 99);
                assert_eq!(record.ntfs_operation()?.redo_code, 0);
                Ok(())
            }),
            Ok(1)
        );
        page[510] ^= 1;
        assert!(matches!(RecordPage::parse(&mut page, 512, 0x40), Err(Error::InvalidLog)));
    }
}
