//! Module: ntfs_utils::ffi
//! Purpose: Stable C ABI for one read-only snapshot.
//! Created: 2026-10-01
//! Architecture: Utility API callers and commands use this module over the shared NTFS core.

//! Stable C ABI for one read-only snapshot. Pointers are borrowed only during
//! the call; no Rust allocation crosses the ABI boundary.

use crate::{get_device, get_file_security, scan_ntfs_devices, DeviceInfo};
use std::ffi::{c_char, CStr, OsStr};
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const REPORT_CHUNK_BYTES: usize = 65536;

/// Check status uses the probe namespace; detected damage is in JSON, not an
/// API transport error. The callback borrows UTF-8 bytes only for its call.
#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_check(
    path: *const c_char,
    report: Option<unsafe extern "C" fn(*mut std::ffi::c_void, *const u8, usize)>,
    context: *mut std::ffi::c_void,
    error: *mut c_char,
    error_length: usize,
) -> i32 {
    unsafe { ntfs_utils_check_with_log(path, std::ptr::null(), report, context, error, error_length) }
}

unsafe fn check_report_call(
    path: *const c_char,
    log: *const c_char,
    error: *mut c_char,
    error_length: usize,
    emit: impl FnOnce(&crate::CheckReport) -> std::io::Result<()>,
) -> i32 {
    if path.is_null() || (error.is_null() && error_length != 0) {
        return 1;
    }
    let bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
    if bytes.is_empty() {
        return 1;
    }
    let log = if log.is_null() {
        None
    } else {
        let bytes = unsafe { CStr::from_ptr(log) }.to_bytes();
        if bytes.is_empty() {
            return 1;
        }
        Some(Path::new(OsStr::from_bytes(bytes)))
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let value = crate::check_device_with_log(Path::new(OsStr::from_bytes(bytes)), log)?;
        emit(&value)
    })) {
        Ok(Ok(())) => {
            unsafe {
                write_error(error, error_length, "");
            }
            0
        }
        Ok(Err(e)) => {
            unsafe {
                write_error(error, error_length, &e.to_string());
            }
            error_code(&e)
        }
        Err(_) => {
            unsafe {
                write_error(error, error_length, "internal check panic");
            }
            5
        }
    }
}

/// NULL log leaves the report unsaved. The callback remains one invocation;
/// its complete JSON is backed by a private file, with no findings cap.
#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_check_with_log(
    path: *const c_char,
    log: *const c_char,
    report: Option<unsafe extern "C" fn(*mut std::ffi::c_void, *const u8, usize)>,
    context: *mut std::ffi::c_void,
    error: *mut c_char,
    error_length: usize,
) -> i32 {
    let Some(report) = report else {
        return 1;
    };
    unsafe {
        check_report_call(path, log, error, error_length, |value| {
            value.with_json_bytes(|json| report(context, json.as_ptr(), json.len()))
        })
    }
}

/// Stream JSON in bounded chunks. A nonzero callback result aborts output.
#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_check_stream(
    path: *const c_char,
    log: *const c_char,
    report: Option<unsafe extern "C" fn(*mut std::ffi::c_void, *const u8, usize) -> i32>,
    context: *mut std::ffi::c_void,
    error: *mut c_char,
    error_length: usize,
) -> i32 {
    use std::io::Write;
    let Some(report) = report else {
        return 1;
    };
    struct Sink {
        report: unsafe extern "C" fn(*mut std::ffi::c_void, *const u8, usize) -> i32,
        context: *mut std::ffi::c_void,
    }
    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let size = bytes.len().min(REPORT_CHUNK_BYTES);
            if size == 0 {
                return Ok(0);
            }
            if unsafe { (self.report)(self.context, bytes.as_ptr(), size) } != 0 {
                return Err(std::io::Error::other("check report callback rejected output"));
            }
            Ok(size)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    unsafe {
        check_report_call(path, log, error, error_length, |value| {
            let mut output = std::io::BufWriter::with_capacity(REPORT_CHUNK_BYTES, Sink { report, context });
            let result = value.write_json(&mut output).and_then(|()| output.flush());
            let _ = output.into_parts(); // Do not retry a rejected callback during drop.
            result
        })
    }
}

#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_repair_start(
    source: *const c_char,
    target: *const c_char,
    mode: u32,
    out: *mut *mut crate::RepairJob,
    error: *mut c_char,
    error_length: usize,
) -> i32 {
    if source.is_null() || target.is_null() || out.is_null() || mode > 4 || (error.is_null() && error_length != 0) {
        return 1;
    }
    unsafe {
        *out = std::ptr::null_mut();
    }
    let source = unsafe { CStr::from_ptr(source) }.to_bytes();
    let target = unsafe { CStr::from_ptr(target) }.to_bytes();
    if source.is_empty() || target.is_empty() {
        return 1;
    }
    match std::panic::catch_unwind(|| {
        crate::start_repair(Path::new(OsStr::from_bytes(source)), Path::new(OsStr::from_bytes(target)), mode)
    }) {
        Ok(Ok(job)) => {
            unsafe {
                *out = Box::into_raw(Box::new(job));
                write_error(error, error_length, "");
            }
            0
        }
        Ok(Err(e)) => {
            unsafe {
                write_error(error, error_length, &e.to_string());
            }
            error_code(&e)
        }
        Err(_) => {
            unsafe {
                write_error(error, error_length, "internal repair launch panic");
            }
            5
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_repair_progress(
    job: *const crate::RepairJob,
    out: *mut crate::RepairProgress,
    out_size: usize,
    finished: *mut u32,
) -> i32 {
    if job.is_null() || out.is_null() || out_size != size_of::<crate::RepairProgress>() || finished.is_null() {
        return 1;
    }
    let value = unsafe { &*job }.progress();
    unsafe {
        *finished = u32::from(matches!(value.phase, 13 | 14));
        out.write(value);
    }
    0
}

/// Return an administration status, unlike launch/progress transport statuses.
#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_repair_wait(
    job: *const crate::RepairJob,
    message: *mut c_char,
    length: usize,
) -> i32 {
    if job.is_null() || (message.is_null() && length != 0) {
        return crate::Status::InvalidArgument as i32;
    }
    let result = unsafe { &*job }.wait();
    unsafe {
        write_error(message, length, &result.message);
    }
    result.status as i32
}

/// Destruction waits for completion. Caller must exclude concurrent API calls
/// on this handle while destroying it; NULL is accepted.
#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_repair_free(job: *mut crate::RepairJob) {
    if !job.is_null() {
        drop(unsafe { Box::from_raw(job) });
    }
}

#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_rescue_extract(
    archive: *const c_char,
    destination: *const c_char,
    message: *mut c_char,
    message_length: usize,
) -> i32 {
    unsafe {
        admin_call(message, message_length, || {
            Ok(crate::extract_rescue(admin_path(archive)?, admin_path(destination)?))
        })
    }
}

#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_rescue_reintegrate(
    source: *const c_char,
    archive: *const c_char,
    destination: *const c_char,
    message: *mut c_char,
    message_length: usize,
) -> i32 {
    unsafe {
        admin_call(message, message_length, || {
            Ok(crate::reintegrate_rescue(admin_path(source)?, admin_path(archive)?, admin_path(destination)?))
        })
    }
}

#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_rescue_repair(
    source: *const c_char,
    archive: *const c_char,
    destination: *const c_char,
    message: *mut c_char,
    message_length: usize,
) -> i32 {
    unsafe {
        admin_call(message, message_length, || {
            Ok(crate::repair_rescue(admin_path(source)?, admin_path(archive)?, admin_path(destination)?))
        })
    }
}

/// Spawn and wait in a new mount namespace. API status reports launch/wait
/// failure; exit_code reports the application's exit status (128+signal).
/// NULL options use NTFS compatibility and all visible slate-ntfs mounts.
#[repr(C)]
pub struct NtfsApplicationOptions {
    pub size: u32,
    pub compatibility: u32,
    pub mounts: *const *const c_char,
    pub mount_count: usize,
}

#[repr(C)]
pub struct NtfsApplicationOptionsExtended {
    pub base: NtfsApplicationOptions,
    pub visibility: u32,
    pub flags: u32,
}

#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_run_application(
    program: *const c_char,
    arguments: *const *const c_char,
    argument_count: usize,
    options: *const NtfsApplicationOptions,
    exit_code: *mut i32,
    message: *mut c_char,
    message_length: usize,
) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    unsafe {
        admin_call(message, message_length, || {
            let program = admin_path(program)?;
            if exit_code.is_null() || argument_count > 65536 || (argument_count != 0 && arguments.is_null()) {
                return Err(crate::Status::InvalidArgument);
            }
            *exit_code = -1;
            let mut args = Vec::with_capacity(argument_count);
            for i in 0..argument_count {
                let arg = *arguments.add(i);
                if arg.is_null() {
                    return Err(crate::Status::InvalidArgument);
                }
                args.push(OsStr::from_bytes(CStr::from_ptr(arg).to_bytes()).to_os_string());
            }
            let mut launch = crate::ApplicationOptions::default();
            if !options.is_null() {
                let opt = &*options;
                if ![size_of::<NtfsApplicationOptions>(), size_of::<NtfsApplicationOptionsExtended>()]
                    .contains(&(opt.size as usize))
                    || opt.mount_count > 65536
                    || (opt.mount_count != 0 && opt.mounts.is_null())
                {
                    return Err(crate::Status::InvalidArgument);
                }
                if opt.size as usize == size_of::<NtfsApplicationOptionsExtended>() {
                    let extended = &*options.cast::<NtfsApplicationOptionsExtended>();
                    if extended.flags & !1 != 0 {
                        return Err(crate::Status::InvalidArgument);
                    }
                    if extended.flags & 1 != 0 {
                        launch.visibility = Some(
                            crate::Visibility::from_flags(extended.visibility)
                                .map_err(|_| crate::Status::InvalidArgument)?,
                        );
                    }
                }
                launch.compatibility = match opt.compatibility {
                    0 => crate::Compatibility::Linux,
                    1 => crate::Compatibility::Ntfs,
                    _ => return Err(crate::Status::InvalidArgument),
                };
                for i in 0..opt.mount_count {
                    launch.mounts.push(admin_path(*opt.mounts.add(i))?.to_path_buf());
                }
            }
            match crate::spawn_application(program.as_os_str(), &args, &launch).and_then(|mut c| c.wait()) {
                Ok(status) => {
                    *exit_code = status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(1));
                    Ok(crate::OperationResult::new(crate::Status::Success, "application exited"))
                }
                Err(error) => {
                    let status = match error.kind() {
                        std::io::ErrorKind::PermissionDenied => crate::Status::PermissionDenied,
                        std::io::ErrorKind::InvalidInput => crate::Status::InvalidArgument,
                        _ => crate::Status::Failure,
                    };
                    Ok(crate::OperationResult::new(status, error.to_string()))
                }
            }
        })
    }
}

unsafe fn admin_path<'a>(path: *const c_char) -> Result<&'a Path, crate::Status> {
    if path.is_null() {
        return Err(crate::Status::InvalidArgument);
    }
    let bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
    if bytes.is_empty() {
        return Err(crate::Status::InvalidArgument);
    }
    Ok(Path::new(OsStr::from_bytes(bytes)))
}

/// Explicit mount using the caller's credentials and current namespace.
#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_mount(
    device: *const c_char,
    target: *const c_char,
    sidmap: *const c_char,
    compatibility: u32,
    readonly: u32,
    message: *mut c_char,
    message_length: usize,
) -> i32 {
    unsafe {
        admin_call(message, message_length, || {
            let device = admin_path(device)?;
            let target = admin_path(target)?;
            if sidmap.is_null() || readonly > 1 {
                return Err(crate::Status::InvalidArgument);
            }
            let sidmap = CStr::from_ptr(sidmap).to_str().map_err(|_| crate::Status::InvalidArgument)?;
            let mode = match compatibility {
                0 => crate::Compatibility::Linux,
                1 => crate::Compatibility::Ntfs,
                _ => return Err(crate::Status::InvalidArgument),
            };
            Ok(crate::mount_fs(device, target, sidmap, mode, readonly != 0))
        })
    }
}

#[repr(C)]
pub struct NtfsFormatOptions {
    pub size: u32,
    pub version: u32,
    pub flags: u32,
    pub sector_size: u32,
    pub cluster_size: u32,
    pub mft_zone_multiplier: u32,
    pub heads: u32,
    pub sectors_per_track: u32,
    pub partition_start: u32,
    pub reserved: u32,
    pub sectors: u64,
}

#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_format_ex(
    path: *const c_char,
    label: *const c_char,
    options: *const NtfsFormatOptions,
    message: *mut c_char,
    message_length: usize,
) -> i32 {
    unsafe {
        admin_call(message, message_length, || {
            let path = admin_path(path)?;
            if options.is_null() {
                return Err(crate::Status::InvalidArgument);
            }
            let o = &*options;
            if o.size != size_of::<NtfsFormatOptions>() as u32
                || o.version != 1
                || o.flags & !63 != 0
                || o.reserved != 0
                || o.heads > 65535
                || o.sectors_per_track > 65535
                || !(1..=4).contains(&o.mft_zone_multiplier)
            {
                return Err(crate::Status::InvalidArgument);
            }
            let label = if label.is_null() {
                ""
            } else {
                CStr::from_ptr(label).to_str().map_err(|_| crate::Status::InvalidArgument)?
            };
            Ok(crate::format_device(
                path,
                &crate::FormatOptions {
                    label: label.to_owned(),
                    quick: o.flags & 1 != 0,
                    dry_run: o.flags & 2 != 0,
                    compression: o.flags & 4 != 0,
                    disable_indexing: o.flags & 8 != 0,
                    epoch_time: o.flags & 16 != 0,
                    with_uuid: o.flags & 32 != 0,
                    sector_size: o.sector_size,
                    cluster_size: o.cluster_size,
                    sectors: o.sectors,
                    partition_start: o.partition_start,
                    heads: o.heads as u16,
                    sectors_per_track: o.sectors_per_track as u16,
                    mft_zone_multiplier: o.mft_zone_multiplier as u8,
                },
            ))
        })
    }
}

unsafe fn admin_call(
    buffer: *mut c_char,
    length: usize,
    f: impl FnOnce() -> Result<crate::OperationResult, crate::Status>,
) -> i32 {
    if (buffer.is_null() && length != 0) || length > isize::MAX as usize {
        return crate::Status::InvalidArgument as i32;
    }
    let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(result)) => result,
        Ok(Err(status)) => crate::OperationResult::new(status, "invalid administration arguments"),
        Err(_) => {
            crate::OperationResult::new(crate::Status::Failure, "internal failure; inspect target before retrying")
        }
    };
    unsafe { write_error(buffer, length, &result.message) };
    result.status as i32
}

/// Explicit destructive operation. C caller owns valid, nonoverlapping buffers.
#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_format(
    path: *const c_char,
    label: *const c_char,
    quick: u32,
    message: *mut c_char,
    message_length: usize,
) -> i32 {
    unsafe {
        admin_call(message, message_length, || {
            let path = admin_path(path)?;
            if quick > 1 {
                return Err(crate::Status::InvalidArgument);
            }
            let label = if label.is_null() {
                ""
            } else {
                CStr::from_ptr(label).to_str().map_err(|_| crate::Status::InvalidArgument)?
            };
            Ok(crate::format_device(
                path,
                &crate::FormatOptions { label: label.to_owned(), quick: quick != 0, ..Default::default() },
            ))
        })
    }
}

/// action: 1 device chmod; 2 device chown; 3 mounted chmod; 4 mounted chown;
/// 5 mounted native descriptor. No raw, offline ACL mutation is performed.
#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_change_permissions(
    device: *const c_char,
    path: *const c_char,
    action: u32,
    value1: u32,
    value2: u32,
    descriptor: *const u8,
    descriptor_length: usize,
    message: *mut c_char,
    message_length: usize,
) -> i32 {
    unsafe {
        admin_call(message, message_length, || {
            use crate::admin::*;
            let device = admin_path(device)?;
            if descriptor_length > ntfs_rs::security::MAX_STORED_DESCRIPTOR
                || (descriptor.is_null() && descriptor_length != 0)
            {
                return Err(crate::Status::InvalidArgument);
            }
            Ok(match action {
                1 => set_device_mode(device, value1),
                2 => set_device_owner(device, value1, value2),
                3 => set_file_mode(device, admin_path(path)?, value1),
                4 => set_file_owner(device, admin_path(path)?, value1, value2),
                5 => {
                    let bytes = if descriptor_length == 0 {
                        &[]
                    } else {
                        std::slice::from_raw_parts(descriptor, descriptor_length)
                    };
                    set_file_security(device, admin_path(path)?, bytes)
                }
                _ => return Err(crate::Status::InvalidArgument),
            })
        })
    }
}

#[repr(C)]
pub struct NtfsDeviceInfo {
    pub abi_version: u32,
    pub is_dirty: u8,
    pub usage_available: u8,
    pub volume_flags: u16,
    pub volume_size_bytes: u64,
    pub allocatable_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub volume_serial: u64,
    pub cluster_size_bytes: u32,
    pub device_kind: u32,
    pub path: [u8; 512],
    pub manufacturer: [u8; 128],
    pub model: [u8; 128],
}

/// Additive v3 snapshot. Legacy v2 entry points and their layouts are unchanged.
#[repr(C)]
pub struct NtfsDeviceInfoV3 {
    pub base: NtfsDeviceInfo,
    pub physical_size_bytes: u64,
    pub physical_size_available: u32,
    pub reserved: u32,
}
impl From<crate::DeviceInfo> for NtfsDeviceInfoV3 {
    fn from(info: crate::DeviceInfo) -> Self {
        let physical = info.physical_size_bytes;
        let mut base: NtfsDeviceInfo = info.into();
        base.abi_version = 3;
        Self {
            base,
            physical_size_bytes: physical.unwrap_or(0),
            physical_size_available: u32::from(physical.is_some()),
            reserved: 0,
        }
    }
}

/// Caller owns all buffers. A zero-capacity call reports the required length.
/// Nonoverlapping valid pointers are required; no pointer is retained.
#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_security_descriptor(
    path: *const c_char,
    file_reference: u64,
    output: *mut u8,
    capacity: usize,
    required: *mut usize,
    error_buffer: *mut c_char,
    error_length: usize,
) -> i32 {
    if path.is_null()
        || required.is_null()
        || (output.is_null() && capacity != 0)
        || capacity > isize::MAX as usize
        || (error_buffer.is_null() && error_length != 0)
    {
        unsafe { write_error(error_buffer, error_length, "invalid ABI arguments") };
        return 1;
    }
    unsafe { required.write(0) };
    let path_bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
    if path_bytes.is_empty() {
        return 1;
    }
    let path = Path::new(OsStr::from_bytes(path_bytes));
    match std::panic::catch_unwind(|| get_file_security(path, file_reference)) {
        Ok(Ok(security)) => {
            let raw = security.raw();
            unsafe { required.write(raw.len()) };
            if capacity != 0 && capacity < raw.len() {
                unsafe { write_error(error_buffer, error_length, "descriptor buffer too small") };
                return 1;
            }
            if capacity != 0 {
                // SAFETY: caller supplies capacity writable bytes, separately
                // owned from the Rust allocation; length was checked above.
                unsafe { std::ptr::copy_nonoverlapping(raw.as_ptr(), output, raw.len()) };
            }
            unsafe { write_error(error_buffer, error_length, "") };
            0
        }
        Ok(Err(error)) => {
            unsafe { write_error(error_buffer, error_length, &error.to_string()) };
            error_code(&error)
        }
        Err(_) => {
            unsafe { write_error(error_buffer, error_length, "internal panic") };
            5
        }
    }
}

impl Default for NtfsDeviceInfo {
    fn default() -> Self {
        Self {
            abi_version: 0,
            is_dirty: 0,
            usage_available: 0,
            volume_flags: 0,
            volume_size_bytes: 0,
            allocatable_bytes: 0,
            used_bytes: 0,
            free_bytes: 0,
            volume_serial: 0,
            cluster_size_bytes: 0,
            device_kind: 0,
            path: [0; 512],
            manufacturer: [0; 128],
            model: [0; 128],
        }
    }
}

fn c_text(target: &mut [u8], value: Option<&str>) {
    let Some(value) = value else { return };
    let mut cursor = 0;
    for ch in value.chars() {
        let width = ch.len_utf8();
        if cursor + width >= target.len() {
            break;
        }
        ch.encode_utf8(&mut target[cursor..cursor + width]);
        cursor += width;
    }
}

impl From<DeviceInfo> for NtfsDeviceInfo {
    fn from(info: DeviceInfo) -> Self {
        let mut output = Self {
            abi_version: 2,
            is_dirty: u8::from(info.is_dirty),
            usage_available: u8::from(info.used_bytes.is_some()),
            volume_flags: info.volume_flags,
            volume_size_bytes: info.volume_size_bytes,
            allocatable_bytes: info.allocatable_bytes,
            used_bytes: info.used_bytes.unwrap_or(0),
            free_bytes: info.free_bytes.unwrap_or(0),
            volume_serial: info.volume_serial,
            cluster_size_bytes: info.cluster_size_bytes,
            device_kind: info.kind as u32,
            ..Self::default()
        };
        c_text(&mut output.path, Some(&info.path.to_string_lossy()));
        c_text(&mut output.manufacturer, info.manufacturer.as_deref());
        c_text(&mut output.model, info.model.as_deref());
        output
    }
}

fn error_code(error: &std::io::Error) -> i32 {
    match error.kind() {
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof => 3,
        std::io::ErrorKind::Unsupported => 4,
        _ => 2,
    }
}

unsafe fn write_error(buffer: *mut c_char, length: usize, message: &str) {
    if buffer.is_null() || length == 0 {
        return;
    }
    // SAFETY: The C caller promises a writable buffer of length bytes.
    let output = unsafe { std::slice::from_raw_parts_mut(buffer.cast::<u8>(), length) };
    output.fill(0);
    let amount = message.len().min(length - 1);
    output[..amount].copy_from_slice(&message.as_bytes()[..amount]);
}

/// Probe a path without writing to it. out must be aligned and writable;
/// error_buffer may be null only when error_length is zero.
/// Returns 0 on success, 1 for bad arguments, 2 for I/O, 3 for invalid NTFS,
/// 4 for unsupported layouts, or 5 for an internal panic.
#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_probe(
    path: *const c_char,
    out: *mut NtfsDeviceInfo,
    out_size: usize,
    error_buffer: *mut c_char,
    error_length: usize,
) -> i32 {
    if path.is_null()
        || out.is_null()
        || out_size != size_of::<NtfsDeviceInfo>()
        || (error_buffer.is_null() && error_length != 0)
    {
        // SAFETY: A non-null error buffer is caller-owned and writable.
        unsafe { write_error(error_buffer, error_length, "invalid ABI arguments") };
        return 1;
    }
    // SAFETY: The caller promises a valid NUL-terminated string and writable
    // aligned output. Neither pointer is retained.
    let path_bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
    if path_bytes.is_empty() {
        unsafe { write_error(error_buffer, error_length, "empty device path") };
        return 1;
    }
    let path = Path::new(OsStr::from_bytes(path_bytes));
    let result = std::panic::catch_unwind(|| get_device(path));
    match result {
        Ok(Ok(info)) => {
            // SAFETY: out is caller-owned, aligned, and the size was checked.
            unsafe { out.write(info.into()) };
            unsafe { write_error(error_buffer, error_length, "") };
            0
        }
        Ok(Err(error)) => {
            let code = error_code(&error);
            unsafe { write_error(error_buffer, error_length, &error.to_string()) };
            code
        }
        Err(_) => {
            unsafe { write_error(error_buffer, error_length, "internal panic") };
            5
        }
    }
}

/// List discovered NTFS volumes. total_count is the number matching the
/// filter, including entries beyond capacity; retry with enough storage.
/// skipped_count counts unreadable or malformed candidates. The caller owns
/// all buffers; pointers are not retained.
#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_list(
    kind_filter: u32,
    out: *mut NtfsDeviceInfo,
    capacity: usize,
    total_count: *mut usize,
    skipped_count: *mut usize,
    error_buffer: *mut c_char,
    error_length: usize,
) -> i32 {
    if kind_filter > 3
        || total_count.is_null()
        || skipped_count.is_null()
        || (out.is_null() && capacity != 0)
        || (error_buffer.is_null() && error_length != 0)
        || capacity > isize::MAX as usize / size_of::<NtfsDeviceInfo>()
    {
        unsafe { write_error(error_buffer, error_length, "invalid ABI arguments") };
        return 1;
    }
    let result = std::panic::catch_unwind(scan_ntfs_devices);
    match result {
        Ok(Ok(report)) => {
            let matches = report.devices.into_iter().filter(|info| kind_filter == 0 || info.kind as u32 == kind_filter);
            let mut total = 0;
            for info in matches {
                if total < capacity {
                    // SAFETY: The caller promises capacity aligned writable entries.
                    unsafe { out.add(total).write(info.into()) };
                }
                total += 1;
            }
            // SAFETY: The caller promises writable count pointers.
            unsafe {
                total_count.write(total);
                skipped_count.write(report.skipped.len());
                write_error(error_buffer, error_length, "");
            }
            0
        }
        Ok(Err(error)) => {
            unsafe { write_error(error_buffer, error_length, &error.to_string()) };
            error_code(&error)
        }
        Err(_) => {
            unsafe { write_error(error_buffer, error_length, "internal panic") };
            5
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_probe_v3(
    path: *const c_char,
    out: *mut NtfsDeviceInfoV3,
    out_size: usize,
    error_buffer: *mut c_char,
    error_length: usize,
) -> i32 {
    if path.is_null()
        || out.is_null()
        || out_size != size_of::<NtfsDeviceInfoV3>()
        || (error_buffer.is_null() && error_length != 0)
    {
        // SAFETY: A non-null error buffer is caller-owned and writable.
        unsafe { write_error(error_buffer, error_length, "invalid ABI arguments") };
        return 1;
    }
    // SAFETY: The caller promises a valid NUL-terminated string and writable
    // aligned output. Neither pointer is retained.
    let path_bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
    if path_bytes.is_empty() {
        unsafe { write_error(error_buffer, error_length, "empty device path") };
        return 1;
    }
    let path = Path::new(OsStr::from_bytes(path_bytes));
    let result = std::panic::catch_unwind(|| get_device(path));
    match result {
        Ok(Ok(info)) => {
            // SAFETY: out is caller-owned, aligned, and the size was checked.
            unsafe { out.write(info.into()) };
            unsafe { write_error(error_buffer, error_length, "") };
            0
        }
        Ok(Err(error)) => {
            let code = error_code(&error);
            unsafe { write_error(error_buffer, error_length, &error.to_string()) };
            code
        }
        Err(_) => {
            unsafe { write_error(error_buffer, error_length, "internal panic") };
            5
        }
    }
}

/// List discovered NTFS volumes. total_count is the number matching the
/// filter, including entries beyond capacity; retry with enough storage.
/// skipped_count counts unreadable or malformed candidates. The caller owns
/// all buffers; pointers are not retained.
#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_list_v3(
    kind_filter: u32,
    out: *mut NtfsDeviceInfoV3,
    capacity: usize,
    total_count: *mut usize,
    skipped_count: *mut usize,
    error_buffer: *mut c_char,
    error_length: usize,
) -> i32 {
    if kind_filter > 3
        || total_count.is_null()
        || skipped_count.is_null()
        || (out.is_null() && capacity != 0)
        || (error_buffer.is_null() && error_length != 0)
        || capacity > isize::MAX as usize / size_of::<NtfsDeviceInfoV3>()
    {
        unsafe { write_error(error_buffer, error_length, "invalid ABI arguments") };
        return 1;
    }
    let result = std::panic::catch_unwind(scan_ntfs_devices);
    match result {
        Ok(Ok(report)) => {
            let matches = report.devices.into_iter().filter(|info| kind_filter == 0 || info.kind as u32 == kind_filter);
            let mut total = 0;
            for info in matches {
                if total < capacity {
                    // SAFETY: The caller promises capacity aligned writable entries.
                    unsafe { out.add(total).write(info.into()) };
                }
                total += 1;
            }
            // SAFETY: The caller promises writable count pointers.
            unsafe {
                total_count.write(total);
                skipped_count.write(report.skipped.len());
                write_error(error_buffer, error_length, "");
            }
            0
        }
        Ok(Err(error)) => {
            unsafe { write_error(error_buffer, error_length, &error.to_string()) };
            error_code(&error)
        }
        Err(_) => {
            unsafe { write_error(error_buffer, error_length, "internal panic") };
            5
        }
    }
}

// Additive administration API: no ABI change to existing mount/probe entry points.
fn desktop_result(result: std::io::Result<()>) -> crate::OperationResult {
    match result {
        Ok(()) => crate::OperationResult::new(crate::Status::Success, "policy updated"),
        Err(e) => crate::OperationResult::new(
            match e.raw_os_error() {
                Some(libc::EPERM | libc::EACCES) => crate::Status::PermissionDenied,
                Some(libc::ENOTTY | libc::ENOSYS) => crate::Status::Unsupported,
                _ if e.kind() == std::io::ErrorKind::InvalidInput => crate::Status::InvalidArgument,
                _ => crate::Status::Failure,
            },
            e.to_string(),
        ),
    }
}
#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_set_visibility(
    path: *const c_char,
    flags: u32,
    message: *mut c_char,
    length: usize,
) -> i32 {
    unsafe {
        admin_call(message, length, || {
            let path = admin_path(path)?;
            let policy = crate::Visibility::from_flags(flags).map_err(|_| crate::Status::InvalidArgument)?;
            Ok(desktop_result(crate::set_visibility(path, policy)))
        })
    }
}
#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_get_visibility(
    path: *const c_char,
    flags: *mut u32,
    message: *mut c_char,
    length: usize,
) -> i32 {
    unsafe {
        admin_call(message, length, || {
            if flags.is_null() {
                return Err(crate::Status::InvalidArgument);
            }
            let path = admin_path(path)?;
            Ok(desktop_result(crate::get_visibility(path).map(|v| {
                *flags = v.flags();
            })))
        })
    }
}
#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_get_desktop_policy(
    automount: *mut u32,
    flags: *mut u32,
    message: *mut c_char,
    length: usize,
) -> i32 {
    unsafe {
        admin_call(message, length, || {
            if automount.is_null() || flags.is_null() {
                return Err(crate::Status::InvalidArgument);
            }
            Ok(desktop_result(crate::get_desktop_policy().map(|v| {
                *automount = u32::from(v.automount);
                *flags = v.visibility.flags();
            })))
        })
    }
}
#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_set_desktop_policy(
    automount: u32,
    flags: u32,
    message: *mut c_char,
    length: usize,
) -> i32 {
    unsafe {
        admin_call(message, length, || {
            if automount > 1 {
                return Err(crate::Status::InvalidArgument);
            }
            let visibility = crate::Visibility::from_flags(flags).map_err(|_| crate::Status::InvalidArgument)?;
            Ok(desktop_result(crate::set_desktop_policy(crate::DesktopPolicy {
                automount: automount != 0,
                visibility,
            })))
        })
    }
}
#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_set_automount(enabled: u32, message: *mut c_char, length: usize) -> i32 {
    unsafe {
        admin_call(message, length, || {
            if enabled > 1 {
                return Err(crate::Status::InvalidArgument);
            }
            Ok(desktop_result(crate::set_automount(enabled != 0)))
        })
    }
}
#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_mount_with_visibility(
    device: *const c_char,
    target: *const c_char,
    sidmap: *const c_char,
    compatibility: u32,
    readonly: u32,
    visibility: u32,
    message: *mut c_char,
    length: usize,
) -> i32 {
    unsafe {
        admin_call(message, length, || {
            if readonly > 1 || sidmap.is_null() {
                return Err(crate::Status::InvalidArgument);
            }
            let mode = match compatibility {
                0 => crate::Compatibility::Linux,
                1 => crate::Compatibility::Ntfs,
                _ => return Err(crate::Status::InvalidArgument),
            };
            let visibility = crate::Visibility::from_flags(visibility).map_err(|_| crate::Status::InvalidArgument)?;
            let map = CStr::from_ptr(sidmap).to_str().map_err(|_| crate::Status::InvalidArgument)?;
            Ok(crate::mount::mount_fs_with_visibility(
                admin_path(device)?,
                admin_path(target)?,
                map,
                mode,
                readonly != 0,
                visibility,
            ))
        })
    }
}

#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_mount_for_user(
    device: *const c_char,
    target: *const c_char,
    uid: u32,
    gid: u32,
    compatibility: u32,
    readonly: u32,
    visibility: u32,
    message: *mut c_char,
    length: usize,
) -> i32 {
    unsafe {
        admin_call(message, length, || {
            if readonly > 1 {
                return Err(crate::Status::InvalidArgument);
            }
            let mode = match compatibility {
                0 => crate::Compatibility::Linux,
                1 => crate::Compatibility::Ntfs,
                _ => return Err(crate::Status::InvalidArgument),
            };
            let visibility = crate::Visibility::from_flags(visibility).map_err(|_| crate::Status::InvalidArgument)?;
            Ok(crate::mount_fs_for_user(
                admin_path(device)?,
                admin_path(target)?,
                uid,
                gid,
                mode,
                readonly != 0,
                visibility,
            ))
        })
    }
}
/// permissions: 0 = windows (strict ACLs; sidmap required), 1 = desktop
/// (mount-wide uid/gid and file/dir permission bits; sidmap may be NULL).
#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_mount_with_access(
    device: *const c_char,
    target: *const c_char,
    sidmap: *const c_char,
    compatibility: u32,
    readonly: u32,
    visibility: u32,
    permissions: u32,
    uid: u32,
    gid: u32,
    file_mode: u32,
    dir_mode: u32,
    message: *mut c_char,
    length: usize,
) -> i32 {
    unsafe {
        admin_call(message, length, || {
            if readonly > 1 {
                return Err(crate::Status::InvalidArgument);
            }
            let mode = match compatibility {
                0 => crate::Compatibility::Linux,
                1 => crate::Compatibility::Ntfs,
                _ => return Err(crate::Status::InvalidArgument),
            };
            let visibility = crate::Visibility::from_flags(visibility).map_err(|_| crate::Status::InvalidArgument)?;
            let access = match permissions {
                0 => crate::AccessPolicy::Windows,
                1 => crate::AccessPolicy::Desktop { uid, gid, file_mode, dir_mode },
                _ => return Err(crate::Status::InvalidArgument),
            };
            let map = if sidmap.is_null() {
                None
            } else {
                Some(CStr::from_ptr(sidmap).to_str().map_err(|_| crate::Status::InvalidArgument)?)
            };
            Ok(crate::mount_fs_with_access(
                admin_path(device)?,
                admin_path(target)?,
                map,
                mode,
                readonly != 0,
                visibility,
                access,
            ))
        })
    }
}
#[no_mangle]
pub unsafe extern "C" fn ntfs_utils_unmount(target: *const c_char, message: *mut c_char, length: usize) -> i32 {
    unsafe { admin_call(message, length, || Ok(crate::unmount_fs(admin_path(target)?))) }
}
