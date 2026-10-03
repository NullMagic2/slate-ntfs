"""
Module: ntfs_utils.python
Purpose: Expose the NTFS utility library through Python ctypes.
Created: 2026-10-01
Architecture: Python callers share the native utility API and its checked core implementation.

Read-only NTFS device information from the Rust ntfs-utils library.

Usage::

    import ntfs_utils
    device = ntfs_utils.get_device("/dev/sda1")
    print(device.is_dirty, device.size_bytes, device.used_bytes)
"""

import ctypes
import ctypes.util
import os
import json
import threading
from enum import IntEnum
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Union

_ABI_VERSION = 3
_KINDS = {0: "other", 1: "hdd", 2: "ssd", 3: "usb_stick"}
_NATIVE = None
_OPERATION_MESSAGE_BYTES = 2048


def check_device(path, *, log=None):
    """Read-only structural audit of an offline device/image.

    Returns a JSON-compatible dict. A completed API call can report damage:
    inspect passed, complete, errors and findings. Mounted block devices are
    refused; regular images must be quiesced by their owner. Set log to a new
    file to save every finding. For large reports, write_check_report streams
    JSON without constructing a Python dict containing all findings.
    """
    callback_type = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)
    reports = []
    callback_errors = []
    @callback_type
    def receive(_context, data, length):
        try:
            reports.append(ctypes.string_at(data, length))
        except BaseException as exc:
            callback_errors.append(exc)
    function = _library().ntfs_utils_check_with_log
    function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, callback_type, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    function.restype = ctypes.c_int
    error = ctypes.create_string_buffer(2048)
    code = function(_admin_path(path), None if log is None else _admin_path(log), receive, None, error, len(error))
    if callback_errors:
        raise callback_errors[0]
    if code:
        raise NtfsError(code, error.value.decode("utf-8", "replace"), os.fspath(path))
    if len(reports) != 1:
        raise RuntimeError("native checker did not return exactly one report")
    return json.loads(reports[0])


def write_check_report(path, output, *, log=None):
    """Stream complete JSON to a caller-owned binary writer in bounded chunks.

    An exception means partial output must be discarded. Optional log saves
    the full human-readable findings report to a new file.
    """
    callback_type = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)
    callback_errors = []

    @callback_type
    def receive(_context, data, length):
        if callback_errors:
            return 1
        try:
            block = ctypes.string_at(data, length)
            written = output.write(block)
            if written != len(block):
                raise OSError("short check report write")
            return 0
        except BaseException as exc:
            callback_errors.append(exc)
            return 1

    function = _library().ntfs_utils_check_stream
    function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, callback_type, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    function.restype = ctypes.c_int
    error = ctypes.create_string_buffer(2048)
    code = function(_admin_path(path), None if log is None else _admin_path(log), receive, None, error, len(error))
    if callback_errors:
        raise callback_errors[0]
    if code:
        raise NtfsError(code, error.value.decode("utf-8", "replace"), os.fspath(path))


_REPAIR_PHASES = ("planning", "scan_mft", "families", "directories", "allocation",
                  "security", "audit", "copy", "replay", "journal", "repair",
                  "verification", "publication", "complete", "failed")


class _RepairProgress(ctypes.Structure):
    _fields_ = [("phase", ctypes.c_uint32), ("sector_bytes", ctypes.c_uint32),
                ("completed_sectors", ctypes.c_uint64), ("total_sectors", ctypes.c_uint64),
                ("percentage", ctypes.c_double)]


@dataclass(frozen=True)
class RepairProgress:
    phase: str
    completed_sectors: int
    total_sectors: int
    percentage: Optional[float]
    sector_bytes: int
    finished: bool


class RepairJob:
    """Running offline repair. Poll get_progress(), then wait() for the result.

    Counts/percentages describe the current phase, not an overall estimate.
    close() and context-manager exit wait; they never cancel a repair mid-write.
    Methods are serialized per Python handle; wait() blocks other calls on it.
    """
    def __init__(self, handle, library):
        self._handle = handle
        self._library = library
        self._lock = threading.RLock()

    def _live(self):
        if not self._handle:
            raise ValueError("repair job is closed")
        return self._handle

    def get_progress(self):
        with self._lock:
            raw, finished = _RepairProgress(), ctypes.c_uint32()
            code = self._library.ntfs_utils_repair_progress(self._live(), ctypes.byref(raw), ctypes.sizeof(raw), ctypes.byref(finished))
            if code:
                raise NtfsError(code, "cannot read repair progress", "repair job")
            return RepairProgress(_REPAIR_PHASES[raw.phase] if raw.phase < len(_REPAIR_PHASES) else "unknown",
                                  raw.completed_sectors, raw.total_sectors,
                                  None if raw.percentage < 0 else raw.percentage,
                                  raw.sector_bytes, bool(finished.value))

    def wait(self):
        with self._lock:
            message = ctypes.create_string_buffer(2048)
            code = self._library.ntfs_utils_repair_wait(self._live(), message, len(message))
            return OperationResult(Status(code), message.value.decode("utf-8", "replace"))

    def close(self):
        with self._lock:
            if self._handle:
                self._library.ntfs_utils_repair_free(self._handle)
                self._handle = None

    def __enter__(self):
        self._live()
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        if getattr(self, "_handle", None):
            self.close()


def start_repair(source, target, *, mode="copy"):
    """Start explicit repair: copy -> new image; in_place/resume -> journal.

    In-place requires an unmounted block/loop device and an external journal.
    rescue/resume_rescue preserves readable sectors in an external archive,
    with no fabricated bytes for unreadable ranges. It is not a mountable image.
    The source is never silently reformatted or mounted; privileges are unchanged.
    """
    modes = {"copy": 0, "in_place": 1, "resume": 2, "rescue": 3, "resume_rescue": 4}
    if mode not in modes:
        raise ValueError("mode must be copy, in_place, resume, rescue, or resume_rescue")
    library = _library()
    library.ntfs_utils_repair_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32,
                                               ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_size_t]
    library.ntfs_utils_repair_start.restype = ctypes.c_int
    library.ntfs_utils_repair_progress.argtypes = [ctypes.c_void_p, ctypes.POINTER(_RepairProgress), ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint32)]
    library.ntfs_utils_repair_progress.restype = ctypes.c_int
    library.ntfs_utils_repair_wait.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    library.ntfs_utils_repair_wait.restype = ctypes.c_int
    library.ntfs_utils_repair_free.argtypes = [ctypes.c_void_p]
    library.ntfs_utils_repair_free.restype = None
    handle, error = ctypes.c_void_p(), ctypes.create_string_buffer(2048)
    code = library.ntfs_utils_repair_start(_admin_path(source), _admin_path(target), modes[mode], ctypes.byref(handle), error, len(error))
    if code:
        raise NtfsError(code, error.value.decode("utf-8", "replace"), os.fspath(source))
    return RepairJob(handle, library)


def extract_rescue(archive, destination):
    """Extract a complete sector archive into a new image; refuse missing data."""
    function = _library().ntfs_utils_rescue_extract
    return _operation_call(
        function,
        [_admin_path(archive), _admin_path(destination)],
        [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t],
    )


def reintegrate_rescue(source, archive, destination):
    """Retry missing sectors from the original source, then create a new image."""
    function = _library().ntfs_utils_rescue_reintegrate
    return _operation_call(
        function,
        [_admin_path(source), _admin_path(archive), _admin_path(destination)],
        [ctypes.c_char_p] * 3 + [ctypes.c_void_p, ctypes.c_size_t],
    )


def repair_rescue(source, archive, destination):
    """Retry damaged sectors, retire recovered bad clusters, and publish an audited image."""
    function = _library().ntfs_utils_rescue_repair
    return _operation_call(
        function,
        [_admin_path(source), _admin_path(archive), _admin_path(destination)],
        [ctypes.c_char_p] * 3 + [ctypes.c_void_p, ctypes.c_size_t],
    )


class Compatibility(IntEnum):
    LINUX = 0
    NTFS = 1


def _compatibility(value):
    if value == "linux" or value == Compatibility.LINUX:
        return 0
    if value == "ntfs" or value == Compatibility.NTFS:
        return 1
    raise ValueError("compatibility must be 'linux' or 'ntfs'")


class _ApplicationOptions(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("compatibility", ctypes.c_uint32),
                ("mounts", ctypes.POINTER(ctypes.c_char_p)), ("mount_count", ctypes.c_size_t),
                ("visibility", ctypes.c_uint32), ("flags", ctypes.c_uint32)]


def run_application(application, args=(), *, compatibility="ntfs", mounts=(),
                    show_hidden=None, show_system=None, show_metadata=None):
    """Run and wait with private views of existing slate-ntfs mounts.

    NTFS is the default. Returns the application's exit code (128+signal).
    Unprivileged use requires enabled user namespaces. Never elevates the caller. The calling
    Python process keeps its original namespace, credentials and mount views.
    Existing inherited file descriptors retain their original views.
    """
    def encoded(value):
        value = os.fsencode(value)
        if b"\0" in value:
            raise ValueError("embedded NUL")
        return value
    if isinstance(args, (str, bytes)) or isinstance(mounts, (str, bytes)):
        raise TypeError("args and mounts must be sequences, not strings")
    arguments = (ctypes.c_char_p * len(args))(*(encoded(a) for a in args))
    paths = (ctypes.c_char_p * len(mounts))(*(encoded(p) for p in mounts))
    visibility = _visibility_flags(show_hidden, show_system, show_metadata)
    override = any(v is not None for v in (show_hidden, show_system, show_metadata))
    options = _ApplicationOptions(ctypes.sizeof(_ApplicationOptions), _compatibility(compatibility), paths, len(paths), visibility, int(override))
    function = _library().ntfs_utils_run_application
    function.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_size_t,
                         ctypes.POINTER(_ApplicationOptions), ctypes.POINTER(ctypes.c_int32),
                         ctypes.POINTER(ctypes.c_char), ctypes.c_size_t]
    function.restype = ctypes.c_int
    result = ctypes.c_int32(-1)
    message = ctypes.create_string_buffer(512)
    code = function(encoded(application), arguments, len(arguments), ctypes.byref(options),
                    ctypes.byref(result), message, len(message))
    if code:
        raise NtfsError(code, message.value.decode("utf-8", errors="replace"), os.fspath(application))
    return result.value


def get_security_descriptor(path: Union[str, os.PathLike], file_reference: int) -> bytes:
    """Resolve an exact NTFS file reference (sequence << 48 | MFT number).

    Requires an offline image or quiesced device. Does not authorize access.
    Missing/corrupt/unsupported descriptors and stale references raise NtfsError.
    """
    if not isinstance(file_reference, int) or not 0 <= file_reference < (1 << 64):
        raise ValueError("file_reference must be an unsigned 64-bit integer")
    function = _library().ntfs_utils_security_descriptor
    function.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint8),
                         ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
                         ctypes.POINTER(ctypes.c_char), ctypes.c_size_t]
    function.restype = ctypes.c_int
    # One native read avoids a query/read race on a changing descriptor.
    output = (ctypes.c_uint8 * 0x20000)()
    size = ctypes.c_size_t()
    error = ctypes.create_string_buffer(512)
    code = function(os.fsencode(path), file_reference, output, len(output),
                    ctypes.byref(size), error, len(error))
    if code:
        raise NtfsError(code, error.value.decode("utf-8", errors="replace"), os.fspath(path))
    if size.value > len(output):
        raise RuntimeError("invalid descriptor size returned by native library")
    return bytes(output[:size.value])


class NtfsError(Exception):
    """A probe failure; code matches the C API status constants."""

    def __init__(self, code: int, message: str, path: str):
        self.code = code
        self.path = path
        super().__init__(f"{message} (code {code}, path {path})")


class _RawInfo(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("is_dirty", ctypes.c_uint8),
        ("usage_available", ctypes.c_uint8),
        ("volume_flags", ctypes.c_uint16),
        ("volume_size_bytes", ctypes.c_uint64),
        ("allocatable_bytes", ctypes.c_uint64),
        ("used_bytes", ctypes.c_uint64),
        ("free_bytes", ctypes.c_uint64),
        ("volume_serial", ctypes.c_uint64),
        ("cluster_size_bytes", ctypes.c_uint32),
        ("device_kind", ctypes.c_uint32),
        ("path", ctypes.c_char * 512),
        ("manufacturer", ctypes.c_char * 128),
        ("model", ctypes.c_char * 128),
        ("physical_size_bytes", ctypes.c_uint64),
        ("physical_size_available", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
    ]


def _library():
    global _NATIVE
    if _NATIVE is None:
        here = Path(__file__).resolve()
        candidates = [
            os.environ.get("NTFS_UTILS_LIB"),
            here.parents[2] / "target" / "release" / "libntfs_utils.so",
            here.with_name("libntfs_utils.so"),
        ]
        for candidate in candidates:
            if candidate and Path(candidate).is_file():
                _NATIVE = ctypes.CDLL(os.fspath(candidate))
                break
        if _NATIVE is None:
            name = ctypes.util.find_library("ntfs_utils")
            if name:
                _NATIVE = ctypes.CDLL(name)
        if _NATIVE is None:
            raise OSError("libntfs_utils.so not found; install slate-ntfs or set NTFS_UTILS_LIB")
        _NATIVE.ntfs_utils_probe_v3.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(_RawInfo),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_char),
            ctypes.c_size_t,
        ]
        _NATIVE.ntfs_utils_probe_v3.restype = ctypes.c_int
        _NATIVE.ntfs_utils_list_v3.argtypes = [
            ctypes.c_uint32,
            ctypes.POINTER(_RawInfo),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.POINTER(ctypes.c_char),
            ctypes.c_size_t,
        ]
        _NATIVE.ntfs_utils_list_v3.restype = ctypes.c_int
    return _NATIVE


class Status(IntEnum):
    SUCCESS = 0
    FAILURE = 1
    PERMISSION_DENIED = 2
    BUSY = 3
    INVALID_ARGUMENT = 4
    UNSUPPORTED = 5
    DEPENDENCY_MISSING = 6  # reserved; the native formatter needs no helper
    VERIFICATION_FAILED = 7


@dataclass(frozen=True)
class OperationResult:
    status: Status
    message: str

    @property
    def success(self) -> bool:
        return self.status == Status.SUCCESS

    def __bool__(self) -> bool:
        return self.success


class _FormatOptions(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in (
        "size", "version", "flags", "sector_size", "cluster_size", "mft_zone_multiplier",
        "heads", "sectors_per_track", "partition_start", "reserved")] + [("sectors", ctypes.c_uint64)]


def format_device(path, *, label="", quick=True, sector_size=0, cluster_size=0,
                  sectors=0, partition_start=0, heads=0, sectors_per_track=0,
                  mft_zone_multiplier=1, compression=False, disable_indexing=False,
                  epoch_time=False, with_uuid=False, dry_run=False) -> OperationResult:
    """Destructive native NTFS format. Failure can leave a partial filesystem.

    Never elevates privileges. Mounted/held devices are refused. Images must
    already exist and be exclusively owned by the caller. Quick is not erasure.
    """
    booleans = (quick, dry_run, compression, disable_indexing, epoch_time, with_uuid)
    numbers = (sector_size, cluster_size, partition_start, heads, sectors_per_track, mft_zone_multiplier)
    if (not isinstance(label, str) or "\0" in label
        or any(not isinstance(v, bool) for v in booleans)
        or any(not isinstance(v, int) or not 0 <= v < 2**32 for v in numbers)
        or not isinstance(sectors, int) or not 0 <= sectors < 2**64):
        return OperationResult(Status.INVALID_ARGUMENT, "invalid format options")
    options = _FormatOptions(ctypes.sizeof(_FormatOptions), 1,
        sum(int(value) << bit for bit, value in enumerate(booleans)),
        sector_size, cluster_size, mft_zone_multiplier, heads, sectors_per_track,
        partition_start, 0, sectors)
    function = _library().ntfs_utils_format_ex
    return _operation_call(
        function,
        [_admin_path(path), label.encode("utf-8"), ctypes.byref(options)],
        [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(_FormatOptions),
         ctypes.POINTER(ctypes.c_char), ctypes.c_size_t],
    )


def _admin_path(path):
    encoded = os.fsencode(path)
    if not encoded or b"\0" in encoded:
        raise ValueError("path must be nonempty and contain no NUL")
    return encoded


def _permissions(device, path, action, first=0, second=0, descriptor=b""):
    if any(not isinstance(v, int) or not 0 <= v < 2**32 for v in (first, second)):
        return OperationResult(Status.INVALID_ARGUMENT, "mode/UID/GID out of range")
    if not isinstance(descriptor, bytes) or len(descriptor) > 0x20000:
        return OperationResult(Status.INVALID_ARGUMENT, "invalid descriptor bytes")
    function = _library().ntfs_utils_change_permissions
    data = ctypes.create_string_buffer(descriptor)
    return _operation_call(
        function,
        [_admin_path(device), _admin_path(path) if path is not None else None,
         action, first, second, data, len(descriptor)],
        [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32,
         ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
         ctypes.c_size_t, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t],
    )


class _DeviceOperations:
    def check(self, *, log=None):
        return check_device(self.path, log=log)

    def write_check_report(self, output, *, log=None):
        return write_check_report(self.path, output, log=log)

    def start_repair(self, target, *, mode="copy"):
        return start_repair(self.path, target, mode=mode)

    def mount_fs(self, target, sidmap=None, compatibility="ntfs", readonly=False, *,
                 uid=None, gid=None, show_hidden=False, show_system=False, show_metadata=False):
        return mount_fs(self.path, target, sidmap, compatibility, readonly, uid=uid, gid=gid,
                        show_hidden=show_hidden, show_system=show_system, show_metadata=show_metadata)

    def unmount_fs(self, target):
        """Unmount the supplied target in this process's namespace."""
        return unmount_fs(target)

    def format_fs(self, **options) -> OperationResult:
        """Destroy the current filesystem; refresh any previous snapshot after success."""
        return format_device(self.path, **options)

    def set_device_permissions(self, mode: int) -> OperationResult:
        """Linux mode of the block node/image; does not change NTFS file ACLs."""
        return _permissions(self.path, None, 1, mode)

    def set_device_owner(self, uid: int, gid: int) -> OperationResult:
        return _permissions(self.path, None, 2, uid, gid)

    def set_permissions(self, mounted_path, mode: int) -> OperationResult:
        """Request chmod through the mounted NTFS driver's identity mapping."""
        return _permissions(self.path, mounted_path, 3, mode)

    def set_owner(self, mounted_path, uid: int, gid: int) -> OperationResult:
        return _permissions(self.path, mounted_path, 4, uid, gid)

    def set_security_descriptor(self, mounted_path, descriptor: bytes) -> OperationResult:
        """Replace the entire native descriptor, including owner/group and ordered ACEs."""
        return _permissions(self.path, mounted_path, 5, descriptor=descriptor)


@dataclass(frozen=True)
class DeviceHandle(_DeviceOperations):
    """Unprobed path for blank media; obtaining a handle does not open or write it."""
    path: str

    def refresh(self) -> "Device":
        return get_device(self.path)


@dataclass(frozen=True)
class Device(_DeviceOperations):
    path: str
    is_dirty: bool
    size_bytes: int
    allocatable_bytes: int
    used_bytes: Optional[int]
    free_bytes: Optional[int]
    cluster_size_bytes: int
    volume_serial: int
    volume_flags: int
    manufacturer: Optional[str]
    model: Optional[str]
    kind: str = "other"
    physical_size_bytes: Optional[int] = None

    def security_descriptor(self, file_reference: int) -> bytes:
        """Original descriptor bytes; includes all ACEs. Offline/quiesced device only."""
        return get_security_descriptor(self.path, file_reference)

    def refresh(self) -> "Device":
        """Read a fresh snapshot from the same path."""
        return get_device(self.path)


def _decode(raw: _RawInfo, path: str) -> Device:
    if raw.abi_version != _ABI_VERSION:
        raise RuntimeError("incompatible libntfs_utils ABI")

    def optional(value: bytes) -> Optional[str]:
        return value.decode("utf-8", "replace") or None

    return Device(
        path=path,
        is_dirty=bool(raw.is_dirty),
        size_bytes=raw.volume_size_bytes,
        allocatable_bytes=raw.allocatable_bytes,
        used_bytes=raw.used_bytes if raw.usage_available else None,
        free_bytes=raw.free_bytes if raw.usage_available else None,
        cluster_size_bytes=raw.cluster_size_bytes,
        volume_serial=raw.volume_serial,
        volume_flags=raw.volume_flags,
        manufacturer=optional(raw.manufacturer),
        model=optional(raw.model),
        kind=_KINDS.get(raw.device_kind, "other"),
        physical_size_bytes=raw.physical_size_bytes if raw.physical_size_available else None,
    )


def get_device(path: Union[str, os.PathLike], *, probe=True) -> Union[Device, DeviceHandle]:
    """Open an NTFS image or device read-only and return one snapshot.

    used_bytes counts clusters allocated in $Bitmap, including NTFS
    metadata. Hardware identity and physical_size_bytes are optional and absent for
    ordinary images. size_bytes describes NTFS; physical_size_bytes describes
    the full parent hardware disk, including its other partitions.
    """
    if not probe:
        _admin_path(path)
        return DeviceHandle(os.fspath(path))
    raw = _RawInfo()
    error = ctypes.create_string_buffer(256)
    status = _library().ntfs_utils_probe_v3(
        os.fsencode(path), ctypes.byref(raw), ctypes.sizeof(raw), error, len(error)
    )
    if status:
        raise NtfsError(status, error.value.decode("utf-8", "replace"), os.fspath(path))
    return _decode(raw, os.fspath(path))


@dataclass(frozen=True)
class ScanResult:
    devices: List[Device]
    skipped_count: int


def _list(kind_filter: int) -> ScanResult:
    capacity = 16
    while True:
        entries = (_RawInfo * capacity)()
        total = ctypes.c_size_t()
        skipped = ctypes.c_size_t()
        error = ctypes.create_string_buffer(256)
        status = _library().ntfs_utils_list_v3(
            kind_filter, entries, capacity, ctypes.byref(total),
            ctypes.byref(skipped), error, len(error)
        )
        if status:
            raise NtfsError(status, error.value.decode("utf-8", "replace"), "/sys/class/block")
        if total.value > capacity:
            capacity = total.value
            continue
        return ScanResult(
            [_decode(entries[i], entries[i].path.decode("utf-8", "replace"))
             for i in range(total.value)],
            skipped.value,
        )


def scan_ntfs_devices() -> ScanResult:
    """Return discovered devices and a count of paths that could not be probed."""
    return _list(0)


def list_ntfs_devices() -> List[Device]:
    return scan_ntfs_devices().devices


def list_ntfs_hdds() -> List[Device]:
    return _list(1).devices


def list_ntfs_ssds() -> List[Device]:
    return _list(2).devices


def list_ntfs_usb_sticks() -> List[Device]:
    return _list(3).devices


__all__ = [
    "Device", "NtfsError", "ScanResult", "get_device", "scan_ntfs_devices",
    "list_ntfs_devices", "list_ntfs_hdds", "list_ntfs_ssds",
    "list_ntfs_usb_sticks", "DeviceHandle", "Status", "OperationResult",
    "run_application", "get_visibility", "set_visibility",
    "get_desktop_policy", "set_desktop_policy", "set_automount",
    "check_device", "format_device", "write_check_report", "mount_fs", "unmount_fs",
]


def _visibility_flags(show_hidden, show_system, show_metadata):
    values = (show_hidden, show_system, show_metadata)
    if any(v is not None and type(v) is not bool for v in values):
        raise ValueError("visibility values must be bool or None")
    return sum(1 << i for i, v in enumerate(values) if v)


def _operation_call(function, arguments, argument_types):
    # Keep argument owners and the caller-owned message alive through the native call.

    function.argtypes = argument_types
    function.restype = ctypes.c_int
    message = ctypes.create_string_buffer(_OPERATION_MESSAGE_BYTES)
    code = function(*arguments, message, len(message))
    return OperationResult(Status(code), message.value.decode("utf-8", "replace"))


def _desktop_call(name, arguments, argument_types):
    return _operation_call(
        getattr(_library(), name), arguments,
        argument_types + [ctypes.c_void_p, ctypes.c_size_t],
    )


def set_visibility(mounted_path, *, show_hidden=False, show_system=False, show_metadata=False):
    """Change an existing view immediately; no unmount or on-disk changes.
    Root controls host views. Applications may change their own delegated view.
    """
    return _desktop_call("ntfs_utils_set_visibility", [_admin_path(mounted_path),
        _visibility_flags(show_hidden, show_system, show_metadata)], [ctypes.c_char_p, ctypes.c_uint32])


def get_visibility(mounted_path):
    flags = ctypes.c_uint32()
    result = _desktop_call("ntfs_utils_get_visibility", [_admin_path(mounted_path), ctypes.byref(flags)],
        [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32)])
    if not result.success:
        raise NtfsError(int(result.status), result.message, os.fspath(mounted_path))
    return {"show_hidden": bool(flags.value & 1), "show_system": bool(flags.value & 2),
            "show_metadata": bool(flags.value & 4)}


def get_desktop_policy():
    auto, flags = ctypes.c_uint32(), ctypes.c_uint32()
    result = _desktop_call("ntfs_utils_get_desktop_policy", [ctypes.byref(auto), ctypes.byref(flags)],
        [ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)])
    if not result.success:
        raise NtfsError(int(result.status), result.message, "desktop policy")
    return {"automount": bool(auto.value), "show_hidden": bool(flags.value & 1),
            "show_system": bool(flags.value & 2), "show_metadata": bool(flags.value & 4)}


def set_desktop_policy(*, automount=True, show_hidden=False, show_system=False, show_metadata=False):
    if type(automount) is not bool:
        raise ValueError("automount must be bool")
    return _desktop_call("ntfs_utils_set_desktop_policy", [int(automount),
        _visibility_flags(show_hidden, show_system, show_metadata)], [ctypes.c_uint32, ctypes.c_uint32])


def set_automount(enabled):
    """Administrator operation. Existing mounts remain intact."""
    if type(enabled) is not bool:
        raise ValueError("enabled must be bool")
    return _desktop_call("ntfs_utils_set_automount", [int(enabled)], [ctypes.c_uint32])


def mount_fs(device, target, sidmap=None, compatibility="ntfs", readonly=False, *,
             uid=None, gid=None, show_hidden=False, show_system=False, show_metadata=False,
             permissions=None, file_mode=0o600, dir_mode=0o700):
    """Mount a block device at an existing directory. No implicit elevation.

    Pass an explicit sidmap, or choose uid/gid for configured/desktop mapping.
    UID/GID default to this process's effective IDs. Images require a loop device.
    An unsupported writable volume can be retried explicitly with readonly=True.

    permissions (independent of compatibility):
      None / "windows"  strict Windows ACLs for the mapped SIDs (default)
      "desktop"         NTFS-3G-style: owner uid, group gid, and file_mode /
                        dir_mode bits for the whole mount (0o600/0o700 private,
                        0o660/0o770 shared with the group). Stored Windows
                        ownership and ACLs are kept but not evaluated.
    """
    if type(readonly) is not bool:
        raise ValueError("readonly must be bool")
    mode = _compatibility(compatibility)
    flags = _visibility_flags(show_hidden, show_system, show_metadata)
    if permissions is not None:
        if permissions not in ("windows", "desktop"):
            raise ValueError("permissions must be 'windows' or 'desktop'")
        if any(type(v) is not int or not 0 <= v <= 0o777 for v in (file_mode, dir_mode)):
            raise ValueError("file_mode/dir_mode must be within 0o777")
        uid = os.geteuid() if uid is None else uid
        gid = os.getegid() if gid is None else gid
        if any(type(v) is not int or not 0 <= v < 2**32 - 1 for v in (uid, gid)):
            raise ValueError("uid/gid out of range")
        if sidmap is not None and (not isinstance(sidmap, str) or "\0" in sidmap):
            raise ValueError("invalid sidmap")
        return _desktop_call("ntfs_utils_mount_with_access",
            [_admin_path(device), _admin_path(target),
             None if sidmap is None else sidmap.encode(), mode, int(readonly), flags,
             int(permissions == "desktop"), uid, gid, file_mode, dir_mode],
            [ctypes.c_char_p] * 3 + [ctypes.c_uint32] * 8)
    if sidmap is None:
        uid = os.geteuid() if uid is None else uid
        gid = os.getegid() if gid is None else gid
        if any(type(v) is not int or not 0 <= v < 2**32 for v in (uid, gid)):
            raise ValueError("uid/gid out of range")
        return _desktop_call("ntfs_utils_mount_for_user",
            [_admin_path(device), _admin_path(target), uid, gid, mode, int(readonly), flags],
            [ctypes.c_char_p, ctypes.c_char_p] + [ctypes.c_uint32] * 5)
    if uid is not None or gid is not None:
        raise ValueError("choose sidmap or uid/gid")
    if not isinstance(sidmap, str) or "\0" in sidmap:
        raise ValueError("invalid sidmap")
    return _desktop_call("ntfs_utils_mount_with_visibility",
        [_admin_path(device), _admin_path(target), sidmap.encode(), mode, int(readonly), flags],
        [ctypes.c_char_p] * 3 + [ctypes.c_uint32] * 3)


def unmount_fs(target):
    """Normal unmount; busy volumes remain mounted. Uses caller privileges."""
    return _desktop_call("ntfs_utils_unmount", [_admin_path(target)], [ctypes.c_char_p])
