<!--
Module: slate_ntfs::readme
Purpose: Introduce slate-ntfs, then explain installation, command usage and supported behavior.
Created: 2026-09-30
Architecture: Documents the public interface; ARCHITECTURE.md describes implementation
    boundaries.
-->

# slate-ntfs

**NTFS on Linux, done properly: journaled, permission-aware, and repairable.**

> **Warning: limited testing.** slate-ntfs has been tested, but only in a limited
> setting (Ubuntu). Other distributions, hardware and real-world workloads have
> not been covered, and using it on a production machine can be risky: a driver
> bug can corrupt data on the volume.
> 
> Writable mounts, recovery and repair are experimental.

## What is slate-ntfs?

slate-ntfs is a Linux NTFS driver with a Rust core. If you dual-boot Windows, share
external drives with Windows machines, or keep a games library on an NTFS disk,
slate-ntfs aims to let Linux treat that disk the way Windows does: writing through
NTFS's own journal, honouring Windows permissions, and repairing damage instead of
just refusing to mount.

It comes as a set of pieces that share one engine:

- **The `ntfsrs` kernel module**, a thin C VFS bridge over the Rust engine. Your
  kernel does not need `CONFIG_RUST`.
- **A `no_std` Rust core** (`ntfs_rs`) for on-disk parsing, the journal engine and
  metadata operations.
- **Offline tools**: `ntfs-chkdsk` (a CHKDSK-style checker and repairer),
  `fsck.ntfsrs`, `ntfs-inspect`, `ntfs-checkfs` and `ntfs-bitlocker`.
- **`ntfs_utils`**, a userspace library with Rust, C and Python bindings.
- **A GTK permissions manager** for Windows ACLs.

## Why slate-ntfs?

Linux already has two good NTFS options: **NTFS-3G**, the long-standing FUSE driver,
and the **in-kernel NTFS driver** (as of Linux 7.1). Both are mature and widely used,
and for many people they are the right choice. slate-ntfs exists for the cases where
you want more of Windows' own behaviour on Linux:

| | slate-ntfs | NTFS-3G | In-kernel driver (Linux 7.1) |
| --- | --- | --- | --- |
| Runs in | Kernel (module) | Userspace (FUSE) | Kernel (built in) |
| Writes through NTFS's `$LogFile` journal | Yes; Windows can recover them | No; it resets the log | Replays it on mount |
| Windows permissions (DACLs) | Enforced natively, root included | Optional user mapping | POSIX ACLs only |
| CHKDSK-style check and repair | `ntfs-chkdsk`, `fsck.ntfsrs` | `ntfsfix` (basic fixes) | No dedicated tool |
| Replays a dirty Windows journal | Yes, offline | No | On mount |
| BitLocker volumes | Unlock with password, recovery key or BEK | No | No |
| NTFS as the root filesystem | Yes, with initramfs hooks | Not practical | Possible |
| Hibernated (Fast Startup) volumes | Kept read-only, never cleared | Refused or cleared on request | Refused |
| Maturity | Experimental | Very mature | Mature |

The comparison reflects our reading of each project at the time of writing. Check
their own documentation for the latest details.

In short, pick slate-ntfs if you want:

- **Crash safety Windows understands.** Metadata changes are written as native
  NTFS log transactions, so after a power cut either Linux or Windows can finish or
  roll back the work.
- **Windows permissions that mean something.** Access is decided by the file's own
  NTFS security descriptor. Mode bits are only a ceiling, and root does not bypass
  native permissions.
- **Real repair tooling.** `ntfs-chkdsk` checks MFT records, allocation, indexes,
  security descriptors, link counts and more, and can repair into a copy or in place
  through a resumable external journal.
- **Both worlds on one disk.** The default view behaves like NTFS. `compatibility=linux`
  adds POSIX names and Unix modes, and `ntfs-run` gives each application the view
  it expects.

Pick NTFS-3G or the in-kernel driver instead if you need a long track record,
volume layouts slate-ntfs does not write yet (see [Mounting](#mounting)), or
untested architectures.

## Benchmarks

**Real-world test: copying a 2 GB file from a USB SSD to an NVMe drive.**
Higher is better.

| Driver | Median | Range (3 runs) | Compared with NTFS-3G |
| --- | --- | --- | --- |
| slate-ntfs (build .20) | **253 MB/s** | 238 – 276 MB/s | 19% slower |
| NTFS-3G 2022.10.3 | **313 MB/s** | 241 – 372 MB/s | baseline |
| In-kernel driver (Linux 7.1) | *coming soon* | | |

NTFS-3G's median was 23.8% higher (slate-ntfs reached 81% of its speed), and slate-ntfs
won one of the three runs. The ranges overlap a lot, though, so three
runs per driver are not enough to call a consistent winner. Read-ahead
improvements made after build .20 are not included here.

| Run | slate-ntfs | NTFS-3G | slate-ntfs compared with NTFS-3G |
| --- | --- | --- | --- |
| 1 | 276 MB/s (7.24 s) | 313 MB/s (6.39 s) | 12% slower |
| 2 | 253 MB/s (7.91 s) | 241 MB/s (8.28 s) | **5% faster** |
| 3 | 238 MB/s (8.41 s) | 372 MB/s (5.37 s) | 36% slower |

<details>
<summary>How it was measured</summary>

- **Setup:** a SATA SSD in a USB 3 enclosure (UAS, 5 Gbps) as the source, an NVMe
  drive with ext4 as the destination, on Ubuntu with kernel 7.0.
- **Same disk, same conditions:** both drivers mounted the same NTFS partition
  read-only, each through its own read-only loop device, with `noatime`, `nosuid`,
  `nodev` and `noexec`.
- **Cold reads only:** before each run, the file was evicted from the page cache.
  Disk counters confirmed that every run read the full 2 GB from the SSD, not
  from memory.
- **Fair ordering:** runs alternated between drivers, and the second round
  reversed the order.
- **Timed:** a GIO copy (the same mechanism file managers use) plus an `fsync` of
  the destination.
- **Verified:** every copy matched the source's SHA-256 hash, checked outside the
  timed section. No data was written to the source SSD.
- **Not covered:** writes and small-file workloads. One earlier run was
  discarded because an unrelated directory scan overlapped it.

</details>

To run the synthetic read and write benchmarks yourself:

```sh
sudo bash kernel/tests/benchmark_reads.sh NEW_DIR
python3 kernel/tests/benchmark_writes.py /mnt/slate /mnt/ntfs3g --rounds 3
```

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): implementation boundaries.
- [WRITE_SUPPORT.md](WRITE_SUPPORT.md): VFS feature status and the hibernation policy.
- [NTFS_PERMISSIONS.md](NTFS_PERMISSIONS.md): SID mapping and ACLs.
- [RECOVERY_TRANSACTIONS.md](RECOVERY_TRANSACTIONS.md): repair coordination and coverage.
- [WSL_TESTING.md](WSL_TESTING.md): WSL test setup.
- [STYLE_GUIDE.md](STYLE_GUIDE.md): coding conventions.

The Rust library is imported as `ntfs_rs`, and the mount type is `ntfsrs`.

## Building

```sh
./build.sh                                        # core, tools, ntfs_utils
KDIR=/lib/modules/$(uname -r)/build ./build.sh    # plus kernel/ntfs_rs.ko
./clean_build.sh
```

The build never runs tests.

The kernel does not need `CONFIG_RUST`. The module build needs:

- A Rust toolchain with `rust-src`, including its lockfile. Ubuntu's packaged Rust source lacks this, so use rustup.
- Matching kernel headers and module symbols.

Supported architectures are x86_64 and little-endian ARM64. The kernel side uses `aarch64-unknown-none-softfloat`.

To cross-build for ARM64:

```sh
CARGO_BUILD_TARGET=aarch64-unknown-linux-gnu \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
KDIR=/path/to/prepared/arm64/kernel ./build.sh
```

Header feature probes select the right 5.15-era or newer page, folio, tmpfile and lock APIs. The module builds against:

- Ubuntu 22.04 and 24.04
- Mint 21.3, 22.1 and 22.3
- Debian 11, 12 and 13

Runtime mount tests use the custom WSL 6.18 kernel. ARM64 has not been runtime-tested.

`bash generate_packages/generate_package.sh` builds amd64 `.deb` packages. Use `--list` to see targets and `--build TARGET` to build one. For details, see [generate_packages/deb/README.md](generate_packages/deb/README.md).


### NTFS as the root filesystem

```sh
sudo bash boot/install-initramfs.sh "$(uname -r)"
# kernel command line:
root=UUID=<uuid> rootfstype=ntfsrs rootflags=compatibility=linux,sidmap=u:0:S-1-5-32-544;g:0:S-1-5-18 ro
```

The initramfs hook loads `ntfs_rs`. The system-shutdown hook remounts `/` read-only after services stop.

Use `kernel/tests/test_root_boot.sh` and `test_ubuntu_root_boot.sh` for consecutive QEMU boots. Use `test_power_boot.py` for S3 and hibernation tests. Linux hibernation needs a swap device that is not on NTFS.

### BitLocker

`ntfs-mount --bitlocker=password|recovery|bek=FILE|clear` derives the FVEK and creates the dm-crypt and dm-linear mappings. It then mounts the NTFS view and removes the mappings after unmount. This requires `dmsetup`.

```sh
./target/release/ntfs-bitlocker info /dev/DEVICE
./target/release/ntfs-bitlocker verify /dev/DEVICE --bitlocker=recovery
./ntfs_utils/target/release/ntfs-mount /dev/DEVICE /mnt/ntfs --bitlocker=recovery --sidmap=MAP
```

Secrets come from the terminal or from `--secret-fd=N`. The following are not supported:

- TPM-only protectors.
- Creating or removing encryption.
- EFS-encrypted files.

Volumes that are still converting are read-only.

### Linux flags across Windows visits

Windows can drop EAs when it overwrites a file. Snapshot the immutable, append-only, nodump and noatime flags before you boot Windows, then restore them afterward:

```sh
python3 src/tools/slate-flags.py snapshot /mnt/slate
python3 src/tools/slate-flags.py restore /mnt/slate
python3 src/tools/slate-flags.py prune /mnt/slate
```

The backup is `.slate-metadata/linux-flags`, a checksummed JSON file.

- Entries are matched by volume serial, MFT reference and birth time.
- Only a missing `$SLATE_FLAGS` EA is restored.
- The checksum detects damage, not tampering.

#

## License

slate-ntfs is released under the [MIT License](LICENSE), with these exceptions:

- The `ntfsrs` kernel module (`kernel/`) is dual-licensed MIT or GPL-2.0
  (`MODULE_LICENSE("Dual MIT/GPL")`), because Linux only lets GPL-compatible
  modules use the kernel interfaces it needs.
- `ntfs_utils/src/format_tables.rs` holds the NTFS upcase table ported from
  NTFS-3G and stays under GPL-2.0-or-later (see [COPYING](COPYING)). The
  `ntfs_utils` library includes it, so `libntfs_utils`, its Python bindings and
  the programs linked with it (`ntfs-format`, `ntfs-mount`, `ntfs-run`,
  `ntfs-automount` and `ntfs-permissions`) are distributed under the GPL as a
  whole.
- `kernel/patches/` contains patches to the Linux kernel, which are GPL-2.0.
- Bundled icons keep their own licenses: Yaru icons are CC-BY-SA-4.0
  (`permissions/icons/COPYING.Yaru`) and flag icons are MIT
  (`permissions/icons/flags/COPYING.flag-icons`).
