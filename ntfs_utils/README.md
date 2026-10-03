<!--
Module: documentation.readme
Purpose: Document ntfs_utils.
Created: 2026-10-02
Architecture: Documents the userspace utility APIs and bindings; the core and recovery tools own
NTFS validation and mutation.
-->

# ntfs_utils

NTFS volume information and explicit Linux administration for Rust, C, and Python. Build from the
project root with `./build.sh`; no kernel module or `CONFIG_RUST` is needed
for this userspace library.

## Formatting and permissions

```python
import ntfs_utils as ntfs

# Destructive: use an offline disposable image for testing.
device = ntfs.get_device("/path/to/disposable.img", probe=False)
result = device.format_fs(label="Test", quick=True, cluster_size=4096)
if result.status != ntfs.Status.SUCCESS:
    print(result.status.name, result.message)
```

The backend constructs NTFS metadata in Rust; it does not invoke mkntfs.
`ntfs-format --dry-run IMAGE` validates a plan without changing bytes;
`ntfs-format --yes --quick IMAGE` applies it. `--help` lists geometry, label,
compression/indexing defaults, timestamps and UUID options. Quick format does
not erase old contents. Failure after writes begin may leave partial metadata.
Legacy 256-byte sectors, bad-sector quarantine and Windows bootloader code
are not supported.

Results use SUCCESS=0, FAILURE=1, PERMISSION_DENIED=2, BUSY=3,
INVALID_ARGUMENT=4, UNSUPPORTED=5, DEPENDENCY_MISSING=6 (reserved), and
VERIFICATION_FAILED=7 across C, Rust, Python and CLI. Python results expose
`.success` and boolean conversion; use `.status` for the specific outcome.
The process retains its actual credentials. It never escalates privileges;
mounted block devices and active loop backing files are refused.
On WSL, a host-managed loop may name a backing path that the distribution
cannot resolve. Run the formatter as WSL root in that case: it compares the
loop driver's backing device and inode, without requiring the path. An
ordinary user without access to the loop status receives a permission error.

`set_device_permissions(mode)` / `set_device_owner(uid, gid)` change Linux
device-node permissions. `set_permissions(mounted_path, mode)`,
`set_owner(mounted_path, uid, gid)` and `set_security_descriptor(mounted_path,
descriptor)` use the mounted NTFS driver's permission interfaces. Native ACL
updates are supported through slate's live `system.ntfs_security` writer on
supported layouts, with native access checks. `ntfs-permissions` exposes the same operations. UID/SID mapping
must be configured in the mounted driver.

## Python

The Python **distribution** is named `ntfs-utils`; the **import** is
`ntfs_utils` (Python module names cannot contain a hyphen). After building,
run directly from the checkout:

```sh
PYTHONPATH="$PWD/ntfs_utils/python" python3 -c \
  'import ntfs_utils; print(ntfs_utils.get_device("/dev/sda1"))'
```

Or install the package containing the built native library:

```sh
python3 -m pip install ./ntfs_utils/python
```

Usage:

```python
import ntfs_utils

device = ntfs_utils.get_device("/dev/sda1")
print(device.is_dirty)
print(device.size_bytes, device.allocatable_bytes)
print(device.used_bytes, device.free_bytes)
print(device.manufacturer, device.model)
print(device.physical_size_bytes)  # whole parent hardware disk, or None
device = device.refresh()  # explicit new snapshot

all_devices = ntfs_utils.list_ntfs_devices()
hdds = ntfs_utils.list_ntfs_hdds()
ssds = ntfs_utils.list_ntfs_ssds()
usb_sticks = ntfs_utils.list_ntfs_usb_sticks()
report = ntfs_utils.scan_ntfs_devices()
print(len(report.devices), report.skipped_count)
```

`used_bytes` and `free_bytes` are `None` when the allocation bitmap uses an
unsupported layout. `manufacturer` and `model` are `None` when Linux
udev/sysfs does not provide reliable hardware identity, including for plain
image files. A malformed NTFS structure or I/O failure raises `NtfsError`
with a C API status code; a missing native library raises `OSError`.
Each discovered `Device` has `path` and `kind` (`"hdd"`, `"ssd"`,
`"usb_stick"`, or `"other"`). Discovery needs permission to read block
devices, usually root. Check `skipped_count` before treating an inventory as
complete; the convenience lists contain only successfully probed volumes.

## Security descriptor snapshots

On an offline image or quiesced device, read exact native permission bytes:

```python
# Example only: obtain the actual sequence/record reference from the file.
reference = (sequence_number << 48) | mft_record_number
descriptor = ntfs_utils.get_security_descriptor("test.img", reference)
# Or: device.security_descriptor(reference)
```

Rust provides `get_file_security(path, reference)`, returning `FileSecurity`
with `raw()` and `check_access(token, mask)`. C provides
`ntfs_utils_security_descriptor`, with a caller-owned buffer and size query.
No UID-to-SID mapping is inferred. The snapshot cannot authorize a live
filesystem operation. Corrupt, stale, missing, or unsupported data is an
error; raw ACE order and unknown ACE bytes are preserved.

Run `python3 ntfs_utils/tests/test_security_store.py` from the project root after building.
Set `SLATE_TEST_WINDOWS_NTFS_IMAGE` to an offline partition image containing
Windows-populated external security indices for the additional copy-only cases.

## Rust

Add `ntfs-utils` as a path dependency on `ntfs_utils/`:

```rust
let device = ntfs_utils::get_device("/dev/sda1")?;
println!("dirty: {}", device.is_dirty);
println!("NTFS size: {} bytes", device.volume_size_bytes);
println!("allocated: {:?} bytes", device.used_bytes);

let report = ntfs_utils::scan_ntfs_devices()?;
for device in &report.devices {
    println!("{}: {:?}", device.path.display(), device.kind);
}
eprintln!("{} block paths skipped", report.skipped.len());
let usb_sticks = ntfs_utils::list_ntfs_usb_sticks()?;
```

## C

Link `libntfs_utils.so` and include `include/ntfs_utils.h`:

```c
#include <stdio.h>
#include "ntfs_utils.h"

int main(void) {
    ntfs_device_info info;
    char error[256];
    int code = ntfs_utils_probe("/dev/sda1", &info, sizeof(info),
                                error, sizeof(error));
    if (code) {
        fprintf(stderr, "NTFS probe failed: %s\n", error);
        return code;
    }
    printf("dirty=%u size=%llu\n", info.is_dirty,
           (unsigned long long)info.volume_size_bytes);
    if (info.usage_available)
        printf("allocated=%llu\n", (unsigned long long)info.used_bytes);
    return 0;
}
```

`ntfs_utils_list(NTFS_UTILS_KIND_ALL, ...)` returns sorted snapshots in a
caller-owned array. Pass a zero capacity and `NULL` output to obtain the
required count, allocate that many entries, then call again. Use
`NTFS_UTILS_KIND_HDD`, `NTFS_UTILS_KIND_SSD`, or
`NTFS_UTILS_KIND_USB_STICK` to filter. The `skipped_count` output reports
unreadable or invalid candidates.

Linux classifies HDD/SSD by `/sys` rotational metadata. A USB stick must
have USB transport and removable media metadata; this takes precedence over
rotational type. External USB HDDs and SSDs appear in their corresponding
disk lists. Unknown type remains in the general list. These are heuristics;
some USB flash devices advertise fixed media and may appear as SSDs.

All values are snapshots from read-only opens. Allocated space counts set
clusters in NTFS `$Bitmap`, including filesystem metadata. It can differ
from file sizes or physical space consumed by a sparse image or storage
device. `size_bytes` is the boot sector's total sector size;
`allocatable_bytes` counts whole clusters and can be slightly smaller.
`used_bytes + free_bytes == allocatable_bytes` when usage is available.
Concurrent writes by another filesystem driver can make a snapshot
inconsistent; query an unmounted or stable volume when accuracy matters.

`bash ./ntfs_utils/tests/test_bindings.sh` from the project root exercises the Rust library
through C and Python against disposable clean and dirty NTFS images.
On WSL, run `./ntfs_utils/tests/test_bindings_wsl.ps1` in PowerShell from the project root.
It builds as the normal WSL user, then runs the image test as WSL root so it
can attach a read-only loop device and exercise `/sys/class/block` discovery.
The test detaches the loop device afterward. No permanent sudo change is
needed. If your WSL setup blocks root or loop-device creation, the test still
runs image probes and reports that the discovery attachment was skipped.

## Per-application compatibility

Defaults are **NTFS** in Rust `Compatibility::default()`, Python `mount_fs` and
`run_application`, the mount/launcher CLIs, and C's default options macro or NULL
launcher options. Existing numeric ABI values remain Linux=0, NTFS=1; use
`NTFS_APPLICATION_OPTIONS_INIT`, not zero-initialization, for the default.

```python
import ntfs_utils
status = ntfs_utils.run_application("steam", ["-applaunch", "12345"],
                                   compatibility="ntfs", mounts=["/games"])
```

Rust exposes `spawn_application(program, arguments, &ApplicationOptions)` and
returns a `Child`. C exposes `ntfs_utils_run_application`; a successful API call
returns SUCCESS and reports the application's exit status separately. Python
returns that status and raises `NtfsError` if setup/launch fails. The CLI returns
the application status (128+signal when signaled), or 125 on launch failure.

The launcher selects existing slate mountpoints, not raw devices. Omit mounts
to select all visible slate mounts. Arguments are passed directly, without a
shell. Unprivileged use requires permitted user namespaces and existing volume
permissions; read-only callers get read-only views. No sudo or setuid helper is
installed. Inherited descriptors keep their original view. Both policies use the
same live volume writer and Linux VFS. See ARCHITECTURE.md for current bounds.

## Checking, repair jobs and sector rescue

Rust `check_device(path)`, C `ntfs_utils_check` (JSON callback), and Python
`check_device(path)` perform the implemented structural audit. Inspect the
report's `passed`, `complete` and findings fields: API success alone does not
mean the volume is clean. Block-device checking claims the offline device;
regular image files must be quiescent. This is not full Windows CHKDSK coverage.

Rust `check_device_with_log(path, Some(log_path))` and
`DeviceInfo::check_with_log` save the complete finding report to a new file.
C provides `ntfs_utils_check_with_log` and chunked
`ntfs_utils_check_stream`; Python provides `check_device(path, log=...)` and
`write_check_report(path, binary_output, log=None)`. The Rust
`CheckReport::write_json` method streams the complete JSON report to a writer.

`start_repair(source, target, mode)` starts an asynchronous job. Rust exposes
`progress()` and `wait()`, C exposes `ntfs_utils_repair_progress` / `_wait`, and
Python exposes `get_progress()` / `wait()`. Freeing/closing a job waits for it;
it does not interrupt durable publication. Numeric C/Rust modes are:

| Mode | Python name | Target |
| --- | --- | --- |
| 0 | `copy` | New repaired image |
| 1 | `in_place` | External journal; source must be an unmounted block device |
| 2 | `resume` | Existing external repair journal |
| 3 | `rescue` | New external sector rescue archive |
| 4 | `resume_rescue` | Existing sector rescue archive |

Progress reports phase, completed/total 512-byte sectors and a phase-relative
percentage. An unknown phase total has C/Rust percentage -1 / Python `None`.
Revalidation may restart scan counters. There is no estimated overall percentage.
Rescue counts only durably archived sectors; unresolved ranges yield
`VerificationFailed`. A rescue archive contains offset/checksum/data records and
explicit EIO ranges, not a mountable image or zero-filled substitute. Phase 13
for rescue means all sectors were preserved, not that NTFS metadata is valid.

`extract_rescue(archive, new_image)` requires a complete archive, validates
all checksums and duplicate sector copies, and publishes a new image without
filling missing sectors. `reintegrate_rescue(source, archive, new_image)` first
retries unresolved sectors against the original source identity. The CLI has
`--extract-rescue` and `--reintegrate-rescue`; C and Python expose matching
functions. These operations restore captured physical sectors. They do not
relocate clusters or update `$BadClus`.

`repair_rescue(source, archive, new_image)` is the separate NTFS mapping
repair. It retries unresolved sectors, extracts a private image, reserves
previously unreadable clusters in the standard `$BadClus:$Bad` runlist,
relocates readable owners and publishes only after the structural audit.
The CLI uses `--repair-rescue-to`; C uses `ntfs_utils_rescue_repair` and Python
uses `repair_rescue`. It refuses missing bytes, critical system owners and
`$BadClus` layouts requiring an extension record. The archive and private
image remain available if repair cannot finish. This path is build-checked
only; the crash and Windows/ntfs-3g matrix has not run.
The `$Secure` repair also rebuilds a present but independently invalid `$SII`
or `$SDH` index from validated `$SDS` descriptors; intact indexes retain their
existing bytes and attribute IDs.

Audits and structural plans spill to private scratch files; set `TMPDIR` to
external disk-backed storage with sufficient space. Online auditing rejects
scratch on the filesystem being frozen. Scratch exhaustion stops publication.
See `RECOVERY_TRANSACTIONS.md` for remaining per-object limits and the deferred matrix.
These additions have compile/link validation only; runtime tests are deferred.

## Linux desktop integration and live visibility

All package profiles install the same udev/UDisks mount helper and hotplug
adapter. NTFS signatures and labels remain visible to standard Linux clients.
File managers must support UDisks to show a volume in their devices sidebar;
a manager that only browses paths can open the resulting mount directory.
GNOME is not required. Systemd starts the packaged hotplug adapter on these
distributions; the kernel and libraries do not depend on systemd. Other init
systems can launch `ntfs-automount --watch --user=UID` in an authorized session.
Explicit fstab entries take precedence, including `noauto` entries.

NTFS HIDDEN/SYSTEM files and internal metadata are excluded from directory
listings by default. Arbitrary user files starting with `$` stay visible unless
their NTFS attributes mark them hidden. Exact-path access still uses native
ACL checks. Linux dot-file display remains a file-manager preference.

```sh
sudo ntfs-run --live --mount '/run/media/user/Volume' --show-hidden
sudo ntfs-run --live --mount '/run/media/user/Volume' --hide-hidden
sudo ntfs-run --automount=off
sudo ntfs-run --desktop-policy --automount=on --hide-hidden
ntfs-run --show-hidden --mount '/run/media/user/Volume' --application PROGRAM
```

Live controls require no unmount. Applications can update their own private
views without affecting the host view or other applications. Updating the
host view requires administration rights and access under the SID map.
Refresh existing file-manager listings after a live change. Ctrl+H alone does
not change the kernel's NTFS visibility policy. Desktop policy changes apply
to future mounts; use the live API for existing mounts.

```python
import ntfs_utils

device = ntfs_utils.get_device('/dev/sdb2')
print(device.manufacturer or 'Unknown', device.model or 'Unknown')
print('NTFS volume:', device.size_bytes)
print('Whole hardware disk:', device.physical_size_bytes)
ntfs_utils.set_visibility('/run/media/user/Volume',
    show_hidden=True, show_system=True, show_metadata=True)
ntfs_utils.set_automount(False)
```

The package installs `libntfs_utils.so.0`, its development symlink,
`/usr/include/ntfs_utils.h`, pkg-config metadata and the system Python module.
The Python import requires no environment-variable setup. Native libraries are
rebuilt against the installing distribution's libc. C `probe_v3/list_v3`
return full physical capacity with an availability flag; the original v2
functions keep their layout and behavior. Rust `DeviceInfo` exposes
`physical_size_bytes: Option<u64>`. Python exposes `physical_size_bytes` as an
integer or None. This is the full parent hardware disk, not partition size.
Images and virtual devices without one identifiable hardware disk report
unknown; no physical capacity is inferred from NTFS geometry.

The default desktop SID map projects the UDisks-authorized user to the Windows
Administrators identity and root to SYSTEM, and explicitly maps the user's
primary and supplementary groups. This policy applies only to that mounted
volume. Supply `/etc/slate-ntfs/sidmap.conf` to use a custom complete map.
Neither the APIs nor the mount helper rewrite NTFS security descriptors.

Ubuntu and Linux Mint automatic mounts use `/media/<user>/<volume-label>`.
A duplicate label gets the UUID appended. The root is configured in
`/etc/slate-ntfs/mount-root`. The adapter creates marked `noauto` fstab
entries for discovered NTFS volumes; UDisks then mounts at the same location.
Existing administrator-defined entries take precedence. Disabling automatic
mounting keeps these entries available for manual mounting and does not unmount
volumes. Other profiles keep the standard UDisks mountpoint policy.

The administrator-installed adapter prepares custom-root fstab entries, then
submits the UDisks mount request with the selected local user's credentials.
UDisks records that user as the mounting user, so the same user can unmount in
the file manager or with `udisksctl unmount` without providing a password.
The entry's UID/GID controls filesystem access separately; changing a saved
permission owner does not transfer UDisks unmount ownership. Other users remain
subject to the distribution's normal authorization, and busy volumes can still
refuse unmounting. Existing volumes mounted by an older root request need one
ordinary authorized unmount and a fresh mount to acquire the correct ownership.

## Manual mounting and unmounting

Device paths are accepted directly. The target directory must exist. For example:

```sh
sudo mkdir -p /media/$USER/Novo_volume
sudo ntfs-run --mount-volume /dev/sda2 /media/$USER/Novo_volume
sudo ntfs-run --unmount-volume /media/$USER/Novo_volume
```

Use `--read-only` for a read-only mount; `--uid UID --gid GID` selects the
Linux account for desktop identity mapping. `--sidmap MAP` supplies a custom
map instead. Under sudo, the CLI defaults to SUDO_UID/SUDO_GID. The API defaults
are explicit or the process effective IDs. No API elevates privileges.
`--mount PATH --application ...` still selects an existing application view.

Rust: `mount_fs`, `mount_fs_with_visibility`, `mount_fs_for_user`, `unmount_fs`.
C: `ntfs_utils_mount`, `ntfs_utils_mount_with_visibility`,
`ntfs_utils_mount_for_user`, `ntfs_utils_unmount` (see installed header).
Python exposes top-level functions and Device/DeviceHandle methods:

```python
import ntfs_utils
result = ntfs_utils.mount_fs("/dev/sda2", "/media/x/Novo_volume",
                            uid=1000, gid=1000, readonly=True)
if not result.success:
    raise RuntimeError(result.message)
result = ntfs_utils.unmount_fs("/media/x/Novo_volume")
```

Unmounting is normal and synchronous. Busy volumes remain mounted. Images must
be attached to a loop device first. Manual operations run in the caller's mount
namespace and need the corresponding kernel privileges.
