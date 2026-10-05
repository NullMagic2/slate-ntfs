//! Module: kernel.writer
//! Purpose: Narrow C ABI for the shared allocation-free Rust write engine.
//! Created: 2026-10-01
//! Architecture: This adapter connects its public entry points to the shared NTFS
//! implementation.

//! Narrow C ABI for the shared allocation-free Rust write engine.
use super::*;
use core::ffi::{c_char, CStr};
use core::sync::atomic::{AtomicU8, Ordering};
use format::batch::BATCH_BYTES;
use format::identity::MappedCaller;
use format::resident_writer::{WriteIo, Writer, JOURNAL_MAP_WORDS, METADATA_SCRATCH_BYTES};
use format::security_writer::SECURITY_SCRATCH_BYTES;

unsafe extern "C" {
    fn ntfs_rs_mount_refusal(context: *mut c_void, reason: *const u8, length: usize);
    fn ntfs_rs_write_data_at(context: *mut c_void, at: u64, data: *const u8, len: usize) -> c_int;
    fn ntfs_rs_hold_at(context: *mut c_void, at: u64, data: *const u8, len: usize, first: c_int) -> c_int;
    fn ntfs_rs_release_at(context: *mut c_void, at: u64, len: usize);
}
type WriteCallback = unsafe extern "C" fn(*mut c_void, u64, *const u8, usize) -> c_int;
type FlushCallback = unsafe extern "C" fn(*mut c_void) -> c_int;
struct WritableDevice {
    read: Device,
    write: WriteCallback,
    flush: FlushCallback,
}
impl ReadAt for WritableDevice {
    fn read_exact_at(&mut self, at: u64, bytes: &mut [u8]) -> Result<()> {
        self.read.read_exact_at(at, bytes)
    }
    // The writer reads the table through the map the mount keeps. A write
    // or a pending image that reaches the table's records voids it.
    fn cached_table(&mut self, space: &mut [u8]) -> Option<usize> {
        self.read.cached_table(space)
    }
    fn table_epoch(&mut self) -> u64 {
        self.read.table_epoch()
    }
    fn store_table(&mut self, table: &[u8], guard: core::ops::Range<u64>, epoch: u64) {
        self.read.store_table(table, guard, epoch)
    }
    fn drop_table(&mut self) {
        self.read.drop_table()
    }
}
impl WriteIo for WritableDevice {
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> Result<()> {
        // SAFETY: C owns a live superblock; this synchronous callback copies
        // the borrowed bytes and never retains their pointer.
        if unsafe { (self.write)(self.read.context, at, bytes.as_ptr(), bytes.len()) } == 0 {
            Ok(())
        } else {
            Err(Error::Io)
        }
    }
    fn write_data_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        // C serializes the session and selects buffered or direct stream I/O.
        if unsafe { ntfs_rs_write_data_at(self.read.context, offset, data.as_ptr(), data.len()) } == 0 {
            Ok(())
        } else {
            Err(Error::Io)
        }
    }
    fn flush(&mut self) -> Result<()> {
        // SAFETY: same live superblock and synchronous lifetime as write_at.
        if unsafe { (self.flush)(self.read.context) } == 0 {
            Ok(())
        } else {
            Err(Error::Io)
        }
    }
    fn hold_at(&mut self, offset: u64, data: &[u8], first: bool) -> Result<()> {
        if unsafe { ntfs_rs_hold_at(self.read.context, offset, data.as_ptr(), data.len(), first as c_int) } == 0 {
            Ok(())
        } else {
            Err(Error::Io)
        }
    }
    fn release_at(&mut self, offset: u64, len: usize) {
        unsafe { ntfs_rs_release_at(self.read.context, offset, len) }
    }
}
fn device(context: *mut c_void, read: ReadCallback, write: WriteCallback, flush: FlushCallback) -> WritableDevice {
    WritableDevice { read: Device { context, callback: read }, write, flush }
}

/// Leave the idle clean state before an operation that may change the volume.
/// Returns 0, or a negative errno when the dirty marker cannot be published.
/// The engine error behind the most recent refusal, kept so that the log can
/// name what ended a write session: errno alone folds most causes into EINVAL.
static LAST_REFUSAL: AtomicU8 = AtomicU8::new(NO_REFUSAL);
const NO_REFUSAL: u8 = u8::MAX;

fn ffi_error(error: Error) -> c_int {
    LAST_REFUSAL.store(error as u8, Ordering::Relaxed);
    super::ffi_error(error)
}

/// Name of the engine error recorded since the previous call, as a C string.
#[no_mangle]
pub extern "C" fn ntfs_rs_writer_last_refusal() -> *const c_char {
    // In the declaration order of `Error`.
    const NAMES: [&CStr; 20] = [
        c"Truncated",
        c"InvalidBoot",
        c"InvalidGeometry",
        c"InvalidFixup",
        c"InvalidRecord",
        c"InvalidAttribute",
        c"InvalidAttributeList",
        c"InvalidRunlist",
        c"InvalidSecurity",
        c"InvalidLog",
        c"InvalidIndex",
        c"AccessDenied",
        c"Overflow",
        c"Io",
        c"Unsupported",
        c"NoSpace",
        c"Exists",
        c"NotFound",
        c"NotPermitted",
        c"NotEmpty",
    ];
    let code = LAST_REFUSAL.swap(NO_REFUSAL, Ordering::Relaxed);
    NAMES.get(usize::from(code)).copied().unwrap_or(c"no engine error").as_ptr()
}

fn resume(
    writer: &mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: &mut [u8],
) -> c_int {
    writer.resume(&mut device(context, read, write, flush), scratch).map_or_else(ffi_error, |()| 0)
}

/// Borrow a C byte range; a null pointer is only valid for length zero.
unsafe fn bytes<'a>(data: *const u8, length: usize) -> Option<&'a [u8]> {
    if length == 0 {
        return Some(&[]);
    }
    if data.is_null() {
        return None;
    }
    // SAFETY: C passes length readable bytes live for the synchronous call.
    Some(unsafe { core::slice::from_raw_parts(data, length) })
}

/// Parse bounded packed initial EAs: repeated little-endian u16 name
/// length, u16 value length, name bytes, value bytes.
fn packed_eas<'a>(mut data: &'a [u8], out: &mut [format::ea::Edit<'a>]) -> Result<usize> {
    let mut n = 0;
    while !data.is_empty() {
        if n == out.len() || data.len() < 4 {
            return Err(Error::Unsupported);
        }
        let name_len = usize::from(u16::from_le_bytes([data[0], data[1]]));
        let value_len = usize::from(u16::from_le_bytes([data[2], data[3]]));
        let end = 4 + name_len + value_len;
        if data.len() < end || name_len == 0 {
            return Err(Error::Unsupported);
        }
        out[n] = format::ea::Edit { name: &data[4..4 + name_len], value: Some(&data[4 + name_len..end]), flags: 0 };
        n += 1;
        data = &data[end..];
    }
    Ok(n)
}

#[no_mangle]
pub extern "C" fn ntfs_rs_writer_size() -> usize {
    core::mem::size_of::<Writer>()
}

/// Bytes of journal map storage C lends to ntfs_rs_writer_init.
#[no_mangle]
pub extern "C" fn ntfs_rs_journal_map_bytes() -> usize {
    JOURNAL_MAP_WORDS * core::mem::size_of::<u64>()
}

/// C supplies mount-lifetime aligned state, 2 MiB scratch, the batch arena,
/// and a live superblock. State is initialized only on success.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_init(
    state: *mut Writer,
    boot: *const u8,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    arena: *mut u8,
    journal_map: *mut u64,
    linux_compatibility: c_int,
) -> c_int {
    if state.is_null() || boot.is_null() || scratch.is_null() || arena.is_null() || journal_map.is_null() {
        return -22;
    }
    // SAFETY: fixed buffer sizes and unique access are the documented C ABI.
    let boot = unsafe { core::slice::from_raw_parts(boot, 512) };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    let mut io = WritableDevice { read: Device { context, callback: read }, write, flush };
    let result = (|| {
        // The writer is built in C's storage: a kernel stack cannot hold one
        // beneath the admission scans. SAFETY: C allocated sufficient aligned
        // space; the blank value is copied from static data, not via the stack.
        static BLANK: Writer = Writer::BLANK;
        let writer = unsafe {
            core::ptr::copy_nonoverlapping(&BLANK, state, 1);
            &mut *state
        };
        // SAFETY: C lends JOURNAL_MAP_WORDS aligned words until after the
        // writer is finished, and nothing else uses them meanwhile.
        writer.attach_journal_map(unsafe { core::slice::from_raw_parts_mut(journal_map, JOURNAL_MAP_WORDS) });
        writer.prepare_in(&mut io, BootSector::parse(boot)?, scratch, |reason| {
            // Static strings; C consumes the bounded bytes synchronously.
            unsafe { ntfs_rs_mount_refusal(context, reason.as_ptr(), reason.len()) };
        })?;
        writer.set_linux_compatibility(linux_compatibility != 0)?;
        // SAFETY: mount owns this arena until after the writer is finished.
        let arena = unsafe { core::slice::from_raw_parts_mut(arena, BATCH_BYTES) };
        writer.attach_batch(arena)?;
        writer.initialize(&mut io, scratch)
    })();
    result.map_or_else(ffi_error, |_| 0)
}

/// Work the periodic drain still owes the device: pending structures, user
/// data and a commit that make_room journaled without its flush.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_pending(state: *const Writer) -> usize {
    if state.is_null() {
        0
    } else {
        let writer = unsafe { &*state };
        writer.pending() + usize::from(writer.data_pending()) + usize::from(writer.log_unflushed())
    }
}

/// Whether C should drain before the next operation: a drain forced inside
/// an operation runs beneath that operation's frames and the device's.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_crowded(state: *const Writer) -> c_int {
    // SAFETY: C holds the volume transaction lock for this read.
    c_int::from(!state.is_null() && unsafe { &*state }.crowded())
}

#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_drain(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    checkpoint: c_int,
) -> c_int {
    if state.is_null() || scratch.is_null() {
        return -22;
    }
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    // An idle session is already clean and has nothing to write.
    if writer.parked() {
        return 0;
    }
    let mut io = device(context, read, write, flush);
    (if checkpoint != 0 { writer.checkpoint(&mut io, scratch) } else { writer.drain(&mut io, scratch) })
        .map_or_else(ffi_error, |_| 0)
}

/// Net clusters this session's transactions have allocated; see
/// Writer::allocated_delta. C holds the volume lock at least for reading.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_allocated_delta(state: *const Writer) -> i64 {
    if state.is_null() {
        0
    } else {
        unsafe { &*state }.allocated_delta()
    }
}

/// Free a crowded batch without waiting for the device; see Writer::make_room.
/// C holds the volume lock exclusively. Returns 0 or a negative errno.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_make_room(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
) -> c_int {
    if state.is_null() || scratch.is_null() {
        return -22;
    }
    // SAFETY: C holds the volume transaction lock and owns the scratch.
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    if writer.parked() {
        return 0;
    }
    writer.make_room(&mut device(context, read, write, flush), scratch).map_or_else(ffi_error, |_| 0)
}

#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_write(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    reference: u64,
    offset: u64,
    data: *const u8,
    length: usize,
) -> c_int {
    if state.is_null() || scratch.is_null() || data.is_null() || length > format::resident_writer::MAX_WRITE {
        return -22;
    }
    // SAFETY: C holds the volume writer lock and owns these live disjoint buffers.
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    let data = unsafe { core::slice::from_raw_parts(data, length) };
    let mut io = WritableDevice { read: Device { context, callback: read }, write, flush };
    writer.write(&mut io, reference, offset, data, scratch).map_or_else(ffi_error, |_| 0)
}

/// Same exclusive state, callback and scratch lifetimes as writer_write.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_resize(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    reference: u64,
    size: u64,
) -> c_int {
    if state.is_null() || scratch.is_null() {
        return -22;
    }
    // SAFETY: the bridge holds the volume transaction lock and owns both buffers.
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    let mut io = WritableDevice { read: Device { context, callback: read }, write, flush };
    writer.resize(&mut io, reference, size, scratch).map_or_else(ffi_error, |_| 0)
}

/// Return unused preallocation; called with the volume transaction lock.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_trim(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    reference: u64,
) -> c_int {
    if state.is_null() || scratch.is_null() {
        return -22;
    }
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    // An idle session is already clean and has nothing to write.
    if writer.parked() {
        return 0;
    }
    writer.trim(&mut device(context, read, write, flush), reference, scratch).map_or_else(ffi_error, |_| 0)
}

/// Rename or move one name. C holds both directory locks, the inode locks
/// taken by the VFS and the volume transaction lock; scratch has
/// METADATA_SCRATCH_BYTES bytes.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_finish(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
) -> c_int {
    if state.is_null() || scratch.is_null() {
        return -22;
    }
    // SAFETY: C quiesces writes and holds the volume lock for the whole call.
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    // An idle session is already clean and has nothing to write.
    if writer.parked() {
        return 0;
    }
    let mut io = WritableDevice { read: Device { context, callback: read }, write, flush };
    writer.finish(&mut io, scratch).map_or_else(ffi_error, |_| 0)
}

/// Rename/move one name. target is 0 (destination absent), 1 (replace
/// the file other) or 2 (exchange with other). outcome receives the
/// replaced file's fate: 0 none, 1 a name removed, 2 freed, 3 orphaned.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_rename(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    parent: u64,
    reference: u64,
    old: *const u8,
    old_len: usize,
    new_parent: u64,
    new: *const u8,
    new_len: usize,
    target: c_int,
    other: u64,
    outcome: *mut c_int,
    linux_compatibility: c_int,
    parent_sd: *const u8,
    sd_len: usize,
    mapping: *const c_void,
    uid: u32,
    gid: u32,
    timestamp: u64,
    eas: *const u8,
    eas_len: usize,
) -> c_int {
    if state.is_null()
        || scratch.is_null()
        || outcome.is_null()
        || old_len == 0
        || new_len == 0
        || old_len > 1020
        || new_len > 1020
        || eas_len > 0x20000
    {
        return -22;
    }
    let mut descriptor = [0u8; 512];
    let mut descriptor_len = 0;
    let Some(eas) = (unsafe { bytes(eas, eas_len) }) else {
        return -22;
    };
    let mut edits = [format::ea::Edit { name: &[], value: None, flags: 0 }; 16];
    let count = match packed_eas(eas, &mut edits) {
        Ok(n) => n,
        Err(error) => return ffi_error(error),
    };
    if matches!(target, 3 | 4) {
        if mapping.is_null() || sd_len > format::security::MAX_STORED_DESCRIPTOR || linux_compatibility == 0 {
            return -22;
        }
        let Some(parent_sd) = (unsafe { bytes(parent_sd, sd_len) }) else {
            return -22;
        };
        let map = unsafe { &*mapping.cast::<format::identity::CompiledSidMap>() };
        let result = (|| -> Result<usize> {
            format::security_create::descriptor(
                parent_sd,
                map.sid_for_id(false, uid)?,
                map.sid_for_id(true, gid)?,
                0,
                false,
                &mut descriptor,
            )
        })();
        match result {
            Ok(n) => descriptor_len = n,
            Err(e) => return ffi_error(e),
        }
    }
    let target = match target {
        0 => format::namespace_writer::RenameTarget::None,
        1 => format::namespace_writer::RenameTarget::Replace(other),
        2 => format::namespace_writer::RenameTarget::Exchange(other),
        3 | 4 => format::namespace_writer::RenameTarget::Whiteout {
            destination: if target == 4 { Some(other) } else { None },
            descriptor: &descriptor[..descriptor_len],
            timestamp,
            eas: &edits[..count],
        },
        _ => return -22,
    };
    // SAFETY: C holds both directory and volume locks and supplies borrowed,
    // immutable dentry names plus exclusive state and scratch for this call.
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    let (Some(old), Some(new)) = (unsafe { bytes(old, old_len) }, unsafe { bytes(new, new_len) }) else {
        return -22;
    };
    let mut io = device(context, read, write, flush);
    let result = writer.with_compatibility(linux_compatibility != 0, |writer| {
        writer.rename_ex(&mut io, parent, reference, old, new_parent, new, target, scratch)
    });
    match result {
        Ok(victim) => {
            use format::file_lifecycle::Removal;
            let code = match victim {
                None => 0,
                Some(Removal::Unlinked) => 1,
                Some(Removal::Freed) => 2,
                Some(Removal::Orphaned) => 3,
            };
            unsafe { outcome.write(code) };
            0
        }
        Err(error) => ffi_error(error),
    }
}

/// Scratch for descriptor replacement, including owner/group rebuilds.
#[no_mangle]
pub extern "C" fn ntfs_rs_writer_security_scratch_size() -> usize {
    SECURITY_SCRATCH_BYTES
}

/// Borrow the caller's compiled map and group list for one synchronous call.
unsafe fn caller<'a>(
    mapping: *const c_void,
    uid: u32,
    gids: *const u32,
    group_count: usize,
) -> Option<MappedCaller<'a>> {
    if mapping.is_null() || gids.is_null() || group_count == 0 || group_count > format::identity::MAX_GROUPS {
        return None;
    }
    // SAFETY: C passes the mount's immutable compiled map (alive until
    // unmount) and an aligned array of group_count IDs for this call only.
    Some(MappedCaller {
        map: unsafe { &*mapping.cast::<format::identity::CompiledSidMap>() },
        uid,
        gids: unsafe { core::slice::from_raw_parts(gids, group_count) },
    })
}

/// Replace a file's whole self-relative descriptor. Rights are derived from
/// the difference against the current descriptor and checked natively:
/// WRITE_DAC, WRITE_OWNER (new owner must be the caller's own SID); SACL
/// changes are refused. C holds the inode lock and volume transaction lock.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_set_security(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    reference: u64,
    descriptor: *const u8,
    length: usize,
    mapping: *const c_void,
    uid: u32,
    gids: *const u32,
    group_count: usize,
) -> c_int {
    if state.is_null()
        || scratch.is_null()
        || descriptor.is_null()
        || length < 20
        || length > format::security::MAX_STORED_DESCRIPTOR
    {
        return -22;
    }
    let Some(policy) = (unsafe { caller(mapping, uid, gids, group_count) }) else {
        return -22;
    };
    // SAFETY: exclusive writer state and scratch; descriptor is a borrowed
    // kernel copy of the user value for the duration of this call.
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, SECURITY_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    let descriptor = unsafe { core::slice::from_raw_parts(descriptor, length) };
    let mut io = WritableDevice { read: Device { context, callback: read }, write, flush };
    writer.set_security(&mut io, reference, descriptor, &policy, scratch).map_or_else(ffi_error, |_| 0)
}

/// Linux chown: replace owner (uid != u32::MAX) and/or group (gid !=
/// u32::MAX) with their explicitly mapped SIDs, preserving ACLs exactly.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_chown(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    reference: u64,
    new_uid: u32,
    new_gid: u32,
    mapping: *const c_void,
    uid: u32,
    gids: *const u32,
    group_count: usize,
) -> c_int {
    if state.is_null() || scratch.is_null() || (new_uid == u32::MAX && new_gid == u32::MAX) {
        return -22;
    }
    let Some(policy) = (unsafe { caller(mapping, uid, gids, group_count) }) else {
        return -22;
    };
    let owner = match new_uid {
        u32::MAX => None,
        id => match policy.map.sid_for(false, id) {
            Ok(sid) => Some(sid),
            Err(_) => return -22,
        },
    };
    let group = match new_gid {
        u32::MAX => None,
        id => match policy.map.sid_for(true, id) {
            Ok(sid) => Some(sid),
            Err(_) => return -22,
        },
    };
    // SAFETY: same exclusive state/scratch contract as set_security.
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, SECURITY_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    let mut io = WritableDevice { read: Device { context, callback: read }, write, flush };
    writer.set_owner(&mut io, reference, owner, group, &policy, scratch).map_or_else(ffi_error, |_| 0)
}

/// Create a regular file (kind 0), directory (1) or symbolic link (2).
/// mode holds permission bits only; eas is a packed initial EA list
/// (inherited POSIX ACLs and LSM labels). The descriptor is inherited from parent_sd.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_create(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    parent: u64,
    name: *const u8,
    name_len: usize,
    parent_sd: *const u8,
    sd_len: usize,
    mapping: *const c_void,
    uid: u32,
    gid: u32,
    mode: u16,
    timestamp: u64,
    kind: c_int,
    link_target: *const u8,
    link_len: usize,
    eas: *const u8,
    eas_len: usize,
    result: *mut u64,
    linux_compatibility: c_int,
) -> c_int {
    if state.is_null()
        || scratch.is_null()
        || parent_sd.is_null()
        || mapping.is_null()
        || result.is_null()
        || (name_len == 0 && kind != 4)
        || name_len > 1020
        || sd_len > format::security::MAX_STORED_DESCRIPTOR
        || link_len > format::reparse::MAX_TARGET
        || eas_len > 0x20000
    {
        return -22;
    }
    // SAFETY: C supplies live immutable name/descriptor/mapping objects and
    // holds the parent and volume locks; output/scratch are exclusive.
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    let (Some(name), Some(parent_sd), Some(link_target), Some(eas)) = (
        unsafe { bytes(name, name_len) },
        unsafe { bytes(parent_sd, sd_len) },
        unsafe { bytes(link_target, link_len) },
        unsafe { bytes(eas, eas_len) },
    ) else {
        return -22;
    };
    let map = unsafe { &*mapping.cast::<format::identity::CompiledSidMap>() };
    let kind = match kind {
        0 => format::file_lifecycle::NodeKind::File,
        1 => format::file_lifecycle::NodeKind::Directory,
        2 => format::file_lifecycle::NodeKind::Symlink(link_target),
        // Special file: link_target carries the WSL $LXDEV layout
        // (little-endian major, then minor); both are zero for FIFOs/sockets.
        3 if link_target.len() == 8 => format::file_lifecycle::NodeKind::Special(
            u32::from(mode),
            format::bytes::u32_at(link_target, 0).unwrap_or(0),
            format::bytes::u32_at(link_target, 4).unwrap_or(0),
        ),
        4 => format::file_lifecycle::NodeKind::Temporary,
        _ => return -22,
    };
    let mut io = device(context, read, write, flush);
    let action = writer.with_compatibility(linux_compatibility != 0, |writer| {
        let mut edits = [format::ea::Edit { name: &[], value: None, flags: 0 }; 16];
        let count = packed_eas(eas, &mut edits)?;
        let mut descriptor = [0u8; 512];
        let n = format::security_create::descriptor(
            parent_sd,
            map.sid_for_id(false, uid)?,
            map.sid_for_id(true, gid)?,
            mode,
            matches!(kind, format::file_lifecycle::NodeKind::Directory),
            &mut descriptor,
        )?;
        writer.create_node(
            &mut io,
            parent,
            name,
            kind,
            &descriptor[..n],
            timestamp,
            (linux_compatibility != 0).then_some(u32::from(mode & 0o7777)),
            &edits[..count],
            scratch,
        )
    });
    match action {
        Ok(reference) => {
            unsafe { *result = reference };
            0
        }
        Err(error) => ffi_error(error),
    }
}

/// Publish the clean state of an idle session. C holds the volume lock and
/// guarantees that no file is open for writing. Returns 0 or a negative errno.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_park(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
) -> c_int {
    if state.is_null() || scratch.is_null() {
        return -22;
    }
    // SAFETY: C holds the volume transaction lock and owns the scratch.
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    writer.park(&mut device(context, read, write, flush), scratch).map_or_else(ffi_error, |()| 0)
}

/// A value that advances with every journaled change, and whether the
/// session is parked; C uses both to detect an idle volume.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_activity(state: *const Writer, parked: *mut c_int) -> u64 {
    if state.is_null() || parked.is_null() {
        return 0;
    }
    // SAFETY: C holds the volume transaction lock for this read.
    let writer = unsafe { &*state };
    unsafe { parked.write(c_int::from(writer.parked())) };
    writer.activity()
}

/// Make sure the records one namespace operation may take are free, growing
/// $MFT when they are not. C calls this before create, link and rename, so
/// that a growth runs from this shallow frame and not from deep inside the
/// operation: kernel stacks are small. Returns 0 or a negative errno.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_reserve(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
) -> c_int {
    if state.is_null() || scratch.is_null() {
        return -22;
    }
    // SAFETY: C holds the volume transaction lock and owns the scratch.
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    let mut io = device(context, read, write, flush);
    match writer.ensure_free_records(&mut io, format::tx::MAX_RECORDS as u64, scratch) {
        Ok(_) => 0,
        Err(error) => ffi_error(error),
    }
}

/// Whether an earlier error has ended the write session.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_failed(state: *const Writer) -> c_int {
    // SAFETY: C holds the volume transaction lock for this read.
    c_int::from(!state.is_null() && unsafe { &*state }.failed())
}

/// Remove one name. With orphan set, a last name leaves a marked orphan
/// (the file is still open). outcome: 1 name removed, 2 freed, 3 orphaned.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_unlink(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    parent: u64,
    reference: u64,
    name: *const u8,
    name_len: usize,
    orphan: c_int,
    outcome: *mut c_int,
    linux_compatibility: c_int,
) -> c_int {
    if state.is_null() || scratch.is_null() || outcome.is_null() || name_len == 0 || name_len > 1020 {
        return -22;
    }
    // SAFETY: C holds parent, victim and volume locks for this call.
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    let Some(name) = (unsafe { bytes(name, name_len) }) else {
        return -22;
    };
    let mut io = device(context, read, write, flush);
    let result = writer.with_compatibility(linux_compatibility != 0, |writer| {
        writer.remove_node(&mut io, parent, name, reference, orphan != 0, scratch)
    });
    match result {
        Ok(removal) => {
            use format::file_lifecycle::Removal;
            let code = match removal {
                Removal::Unlinked => 1,
                Removal::Freed => 2,
                Removal::Orphaned => 3,
            };
            unsafe { outcome.write(code) };
            0
        }
        Err(error) => ffi_error(error),
    }
}

/// Free one marked orphan after its last handle and name are gone.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_reclaim(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    reference: u64,
) -> c_int {
    if state.is_null() || scratch.is_null() {
        return -22;
    }
    // SAFETY: C holds the volume transaction lock and owns the scratch.
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    let mut io = device(context, read, write, flush);
    writer.reclaim_orphan(&mut io, reference, scratch).map_or_else(ffi_error, |_| 0)
}

/// One bounded step of ntfs_rs_writer_reclaim, so C can drop its locks
/// between transactions. Returns 1 once the record is freed, 0 when more
/// steps remain, or a negative errno.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_reclaim_step(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    reference: u64,
) -> c_int {
    if state.is_null() || scratch.is_null() {
        return -22;
    }
    // SAFETY: C holds the volume transaction lock and owns the scratch.
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    let mut io = device(context, read, write, flush);
    writer.reclaim_orphan_step(&mut io, reference, scratch).map_or_else(ffi_error, c_int::from)
}

/// Crash recovery at writable mount: free every marked orphan.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_reclaim_orphans(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    count: *mut u64,
) -> c_int {
    if state.is_null() || scratch.is_null() || count.is_null() {
        return -22;
    }
    // SAFETY: C calls this once after initialization, before publishing root.
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    let mut io = device(context, read, write, flush);
    match writer.reclaim_orphans(&mut io, scratch) {
        Ok(n) => {
            unsafe { count.write(n) };
            0
        }
        Err(error) => ffi_error(error),
    }
}

/// Set (or with remove delete) one EA; flags holds XATTR_CREATE (1) /
/// XATTR_REPLACE (2). mode other than u32::MAX also replaces $LXMOD
/// permission bits in the same transaction (POSIX access ACL updates).
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_set_ea(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    reference: u64,
    name: *const u8,
    name_len: usize,
    value: *const u8,
    value_len: usize,
    remove: c_int,
    flags: u32,
    mode: u32,
) -> c_int {
    if state.is_null() || scratch.is_null() || name_len == 0 || name_len > 255 || value_len > format::ea::MAX_VALUE {
        return -22;
    }
    let (Some(name), Some(value)) = (unsafe { bytes(name, name_len) }, unsafe { bytes(value, value_len) }) else {
        return -22;
    };
    // Internal metadata names are never writable through xattrs.
    if name == format::unix_metadata::MODE
        || name == format::unix_metadata::DEVICE
        || name == format::file_lifecycle::ORPHAN
    {
        return -1;
    }
    // SAFETY: C holds the inode and volume transaction locks.
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    let mut io = device(context, read, write, flush);
    let edit = format::ea::Edit { name, value: (remove == 0).then_some(value), flags };
    let mode = (mode != u32::MAX).then_some(mode);
    match writer.edit_eas(&mut io, reference, &[edit], mode, scratch) {
        Ok(()) => 0,
        Err(Error::NotFound) => -61, // ENODATA
        Err(Error::NoSpace) => -28,
        Err(error) => ffi_error(error),
    }
}

/// Mounted, typed repair: derive the EA summary under the normal writer locks.
/// Returns 1 after a durable repair, 0 for a no-op, or a negative errno.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_repair_ea(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    reference: u64,
) -> c_int {
    if state.is_null() || scratch.is_null() {
        return -22;
    }
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    writer
        .repair_ea_summary(&mut device(context, read, write, flush), reference, scratch)
        .map_or_else(ffi_error, i32::from)
}

/// Recompute a derived EA summary for the current MFT sequence of a numbered
/// base record. The C bridge holds a filesystem freeze and the writer lock.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_repair_ea_number(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    number: u64,
) -> c_int {
    if state.is_null() || scratch.is_null() {
        return -22;
    }
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    writer
        .repair_ea_summary_number(&mut device(context, read, write, flush), number, scratch)
        .map_or_else(ffi_error, i32::from)
}

/// Mounted allocation repair while the C bridge owns the freeze.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_repair_allocation_sector(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    logical: u64,
) -> c_int {
    if state.is_null() || scratch.is_null() {
        return -22;
    }
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    writer
        .repair_allocation_sector(&mut device(context, read, write, flush), logical, scratch)
        .map_or_else(ffi_error, i32::from)
}

/// Mounted allocation/cross-link repair while the C bridge owns the freeze.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_repair_data(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    reference: u64,
) -> c_int {
    if state.is_null() || scratch.is_null() {
        return -22;
    }
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    writer
        .repair_data(&mut device(context, read, write, flush), reference, scratch)
        .map_or_else(ffi_error, |flags| flags as c_int)
}

/// Update $STANDARD_INFORMATION: bit i of valid selects times[i]
/// (creation, modification, change, access); attribute_mask selects the
/// settable Windows attributes taken from attributes.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_set_times(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    reference: u64,
    times: *const u64,
    valid: u32,
    attribute_mask: u32,
    attributes: u32,
) -> c_int {
    if state.is_null() || scratch.is_null() || times.is_null() || valid & !0xf != 0 {
        return -22;
    }
    // SAFETY: C passes a four-element array and holds the volume lock.
    let values = unsafe { core::slice::from_raw_parts(times, 4) };
    let mut selected = [None; 4];
    for (i, slot) in selected.iter_mut().enumerate() {
        if valid & (1 << i) != 0 {
            *slot = Some(values[i]);
        }
    }
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    let mut io = device(context, read, write, flush);
    let attributes = (attribute_mask != 0).then_some((attribute_mask, attributes));
    writer.set_std_info(&mut io, reference, selected, attributes, scratch).map_or_else(ffi_error, |_| 0)
}

/// C serializes this operation and checks ownership plus native WRITE_DAC.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_mode(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    reference: u64,
    mode: u32,
) -> c_int {
    if state.is_null() || scratch.is_null() {
        return -22;
    }
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    let mut io = WritableDevice { read: Device { context, callback: read }, write, flush };
    writer.set_unix_mode(&mut io, reference, mode, scratch).map_or_else(ffi_error, |_| 0)
}

#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_link(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    reference: u64,
    parent: u64,
    name: *const u8,
    name_len: usize,
    linux_compatibility: c_int,
) -> c_int {
    if state.is_null() || scratch.is_null() || name.is_null() || name_len == 0 || name_len > 255 {
        return -22;
    }
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    let name = unsafe { core::slice::from_raw_parts(name, name_len) };
    let mut io = WritableDevice { read: Device { context, callback: read }, write, flush };
    writer
        .with_compatibility(linux_compatibility != 0, |writer| {
            writer.hard_link(&mut io, reference, parent, name, scratch)
        })
        .map_or_else(ffi_error, |_| 0)
}

/// Allocation/range operations; the returned size is published by the VFS.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_allocate(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    reference: u64,
    offset: u64,
    length: u64,
    mode: u32,
    size: *mut u64,
) -> c_int {
    if state.is_null() || scratch.is_null() || size.is_null() {
        return -22;
    }
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    match writer.fallocate(&mut device(context, read, write, flush), reference, offset, length, mode, scratch) {
        Ok(value) => {
            unsafe {
                *size = value;
            }
            0
        }
        Err(error) => ffi_error(error),
    }
}

/// Rename the volume ($VOLUME_NAME) from a UTF-8 label. C checks
/// CAP_SYS_ADMIN, a writable mount, and holds the volume transaction lock.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_writer_set_label(
    state: *mut Writer,
    context: *mut c_void,
    read: ReadCallback,
    write: WriteCallback,
    flush: FlushCallback,
    scratch: *mut u8,
    label: *const u8,
    label_len: usize,
) -> c_int {
    if state.is_null() || scratch.is_null() || label_len > 255 {
        return -22;
    }
    let Some(label) = (unsafe { bytes(label, label_len) }) else {
        return -22;
    };
    let Ok(label) = core::str::from_utf8(label) else {
        return -22;
    };
    let mut units = [0u16; format::resident_writer::MAX_LABEL_UNITS];
    let mut count = 0;
    for unit in label.encode_utf16() {
        if count == units.len() {
            return -22;
        }
        units[count] = unit;
        count += 1;
    }
    // SAFETY: C holds the volume transaction lock for the writer.
    let writer = unsafe { &mut *state };
    let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, METADATA_SCRATCH_BYTES) };
    let status = resume(writer, context, read, write, flush, &mut scratch[..]);
    if status != 0 {
        return status;
    }
    let mut io = device(context, read, write, flush);
    writer.set_volume_label(&mut io, &units[..count], scratch).map_or_else(ffi_error, |()| 0)
}
