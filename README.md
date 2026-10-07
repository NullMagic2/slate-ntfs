<!--
Module: slate_ntfs::readme
Purpose: Introduce slate-ntfs, then explain installation, command usage and supported behavior.
Created: 2026-09-30
Architecture: Documents the public interface; ARCHITECTURE.md describes implementation
    boundaries.
-->

# slate-ntfs

**NTFS on Linux, done properly: journaled, permission-aware, and repairable.**

> **Warning: limited testing.** slate-ntfs has been tested, but only in a limited setting (Ubuntu).
> While tested performance has  shown to have been very stable, production machine can be risky: a driver bug can corrupt data on the volume. 
> Keep backups ready.

## What is slate-ntfs?

slate-ntfs is a Linux NTFS driver with a Rust core. If you dual-boot Windows, share
external drives with Windows machines, or keep a games library on an NTFS disk,
slate-ntfs aims to let Linux treat that disk the way Windows does: writing through
NTFS's own journal, honouring Windows permissions, and repairing damage instead of
just refusing to mount.

It comes as a set of pieces that share one engine:

- **The `slate-ntfs` kernel module**, a thin C VFS bridge over the Rust engine. Your
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
  it expects. Both views find a name only by its exact spelling, so the file
  manager can rename `Texto` to `TeXto`. The NTFS view still refuses a new name
  that differs from an existing one only in case, as Windows does.

Pick NTFS-3G or the in-kernel driver instead if you need a long track record,
volume layouts slate-ntfs does not write yet (see [Mounting](#mounting)), or
untested architectures.

## Benchmarks

**Real-world test: reading and copying a 2 GB file from a USB SSD.** Higher is
better. Measured on 2026-10-05 with slate-ntfs 0.7.1, five cold-cache runs per
driver and operation.

**All three drivers on Linux 7.1.** Linux 7.1 added a new read-write `ntfs`
driver. It is not packaged for Ubuntu 26.04, so this comparison ran in a virtual
machine with the 7.1.13 mainline kernel, where slate-ntfs, the in-kernel `ntfs`
driver and NTFS-3G read the same partition in turn.

| Driver | Cold read, median | Range (5 runs) | Copy, median | Range (5 runs) |
| --- | --- | --- | --- | --- |
| slate-ntfs 0.7.1 | **469 MB/s** | 469 – 471 MB/s | 290 MB/s | 235 – 367 MB/s |
| `ntfs` (Linux 7.1) | 463 MB/s | 463 – 464 MB/s | 278 MB/s | 265 – 322 MB/s |
| NTFS-3G 2022.10.3 | **469 MB/s** | 468 – 469 MB/s | 308 MB/s | 271 – 380 MB/s |

**Reads** measure the driver alone. slate-ntfs and NTFS-3G read at the same speed,
the limit of the SSD behind its USB link, in every run; the Linux 7.1 driver was
about 1% slower in every run (4.32 s against 4.26 s). slate-ntfs also read the
least from the disk: 0.06% more than the file, against 0.2–0.6% for NTFS-3G and 1.5%
for the Linux 7.1 driver.

**Copies** add the destination's writes and its final flush. Their times varied by
up to 56% between runs of the same driver, and each driver was fastest in at least
one round, so the copy medians differ by less than the run-to-run variation: no
driver copies measurably faster than the others.

**Without a virtual machine.** The in-kernel `ntfs` driver needs Linux 7.1, so
only slate-ntfs and NTFS-3G ran directly on this machine's Linux 7.0. The virtual
disk is slower than direct access, so compare these figures only with each other.

| Driver | Cold read, median | Range (5 runs) | Copy, median | Range (5 runs) |
| --- | --- | --- | --- | --- |
| slate-ntfs 0.7.1 | **456 MB/s** | 456 – 456 MB/s | 341 MB/s | 306 – 389 MB/s |
| NTFS-3G 2022.10.3 | **456 MB/s** | 456 – 456 MB/s | 388 MB/s | 279 – 389 MB/s |

Both read at the SSD's limit, within 10 ms of each other in every run. Both
reached about 389 MB/s copying, and each had slow copies (slate-ntfs's slowest
306 MB/s, NTFS-3G's 279 MB/s); as in the virtual machine, the destination's
writes, not the source driver, set the copy times.

<details>
<summary>How it was measured</summary>

- **Setup:** a Samsung 850 EVO SATA SSD in a USB 3 enclosure (UAS, 5 Gbps) as the
  source, an NVMe drive with ext4 as the destination, on Ubuntu 26.04 with
  kernel 7.0.0-34. The file was a 2,000,000,000-byte game installer.
- **Same disk, same conditions:** every driver mounted the same NTFS partition
  read-only, each through its own read-only loop device, with `noatime`,
  `nosuid`, `nodev` and `noexec`.
- **Cold runs only:** before each run, all caches were dropped. Disk counters
  confirmed that every run read the full 2 GB from the SSD, not from memory.
- **Fair ordering:** runs alternated between drivers, and every second round
  reversed the order.
- **Timed:** a read is `dd` to `/dev/null` in 1 MiB blocks. A copy is a GIO copy
  (the same mechanism file managers use) plus an `fsync` of the destination.
- **Verified:** every copy matched the source's SHA-256 hash, checked outside the
  timed section. No data was written to the source SSD.
- **Virtual machine:** QEMU with KVM, 8 CPUs and 8 GiB of memory; the partition
  was attached read-only as a virtio disk with host caching off, so every read
  reached the SSD. Copies went to an ext4 virtio disk on the NVMe drive with
  `dd conv=fsync`, timed to 10 ms. slate-ntfs 0.7.1 was built for the 7.1.13
  kernel from the same sources as the 7.0 module.
- **Not covered:** writes and small-file workloads.

</details>

To reproduce the copy benchmark (root; the partition must not be mounted):

```sh
sudo bash kernel/tests/benchmark_copy.sh /dev/sdX2 PATH/IN/VOLUME DESTINATION_DIR NEW_RESULTS_DIR
```

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
KDIR=/lib/modules/$(uname -r)/build ./build.sh    # plus kernel/slate-ntfs.ko
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

The initramfs hook loads `slate_ntfs`. The system-shutdown hook remounts `/` read-only after services stop.

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

## License

slate-ntfs is released under the [MIT License](LICENSE), with these exceptions:

- The `slate-ntfs` kernel module (`kernel/`) is dual-licensed MIT or GPL-2.0
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
