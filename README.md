<!--
Module: slate_ntfs::readme
Purpose: Explain installation, command usage and supported behavior.
Created: 2026-09-30
Architecture: Documents the public interface; ARCHITECTURE.md describes implementation
    boundaries.
-->

# slate-ntfs

slate-ntfs is a Rust-first Linux NTFS driver. It has five parts:

- A `no_std` core (`ntfs_rs`) covering on-disk parsing, the journal engine and metadata operations.
- Offline tools: `ntfs-inspect`, `ntfs-checkfs`, `ntfs-chkdsk`, `fsck.ntfsrs`, `ntfs-bitlocker` and the write labs.
- The `ntfsrs` kernel module. It is a C VFS bridge over the shared Rust engine.
- The `ntfs_utils` userspace library, with Rust, C and Python bindings.
- A GTK permissions manager.

Writable mounts, recovery and repair are experimental. Use disposable images or keep backups.

Related documents:

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

## Tests

```sh
bash test.sh --list                  # lists suites; never runs everything
bash test.sh unit:logfile
bash test.sh recovery:unit --list
bash test.sh recovery:unit metadata filename --offline
bash test.sh checker:broader
bash test.sh style
```

Test sources live under `src/tests`, `kernel/tests` and `ntfs_utils/tests`.

Writer crash matrices are ignored by default. They need these disposable fixtures:

- `SLATE_CRASH_SOURCE`
- `SLATE_WINDOWS_SOURCE`
- `SLATE_NAMESPACE_SOURCE`

Run them with `bash test.sh recovery:unit recovery_io::writer_crash:: --offline -- --ignored`.

## Mounting

```sh
mount -t ntfsrs -o 'ro,sidmap=u:0:S-1-5-32-544;g:0:S-1-5-18' /dev/sdX1 /mnt/ntfs
mount -t ntfsrs -o 'rw,sidmap=...' /dev/loopN /mnt/slate
```

The `sidmap` option is required. Native DACL evaluation is authoritative. Root does not bypass native permissions. Mode bits are only a ceiling.

Writable mounts require all of the following:

- A clean, unhibernated NTFS 3.1 volume.
- A validated restart pair, or a fresh log.
- 512-byte sectors, 4 KiB clusters and index blocks, and 1 KiB MFT records.

Clean Windows journals are admitted. Slate publishes a new checkpoint before it changes metadata. Dirty or hibernated volumes stay read-only until they are recovered offline.

Writes go through the shared journal engine and are limited to 1 MiB per syscall. Metadata can stay queued until one of these points:

- `fsync`, `sync_fs` or unmount.
- The batch fills up.
- A transaction barrier.
- The five-second drain worker runs.

A rw→ro remount publishes a clean volume flag. An ro→rw remount starts a freshly validated writer.

**NTFS is the default view.** Use `compatibility=linux` to get POSIX names and persisted Unix modes. `ntfs-run` gives applications a Linux or native view of the same writable volume, and the views share one writer:

```sh
ntfs-run --compatibility=ntfs --application steam -- -applaunch 12345
ntfs-run --compatibility=linux --mount /games --application steam
```

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

## Inspection and checking

```sh
ntfs-inspect IMAGE [ROOT-FILE]
ntfs-checkfs [--status] DEVICE          # dirty=0|1; exit 4 when dirty, 8 when unknown
ntfs-chkdsk --check|--audit IMAGE       # full read-only consistency check
ntfs-chkdsk --recovery-status IMAGE     # log_state, hibernation, dirty
ntfs-chkdsk --log-inventory|--replay-plan IMAGE
ntfs-chkdsk --hibernation-page SAMPLE
ntfs-chkdsk --surface-check SOURCE
```

`--check` validates the following:

- Every MFT record.
- Allocation.
- Attribute-list ownership.
- Directory references, reachability and `$I30` collation.
- The `$SII`/`$SDH`/`$SDS` security inventory.
- Mirrors, filename caches and link counts.
- EA summaries.
- `$R`, `$O` and `$Q`.
- USN history and `$AttrDef`.

An unsupported layout, error finding or dirty flag means the check cannot pass.

These modifiers go before the command:

- `--json` for JSON output.
- `--log PATH` to write a complete report.
- `--progress`.
- `--skip-cycles`, which applies to read-only checks only.
- `--index-check=full|quick`.
- `--index-cache-passes=auto|0|N`.

Quick index checking keeps structural, collation, parent and reference-count checks. Depleted counts trigger full validation. Cache passes change only the working set.

In `--json --check`, `passed` and `write_ready` are separate fields. Neither one grants write authority.

| ntfs-chkdsk | CHKDSK | Behavior |
| --- | --- | --- |
| `--index-check=quick` | `/i` | Reduced entry cross-checking with suspect rechecks |
| `--index-cache-passes=N` | `/i:number` | Full-check cache partitions; `0` streams |
| `--skip-cycles` | `/c` | Skip folder-cycle detection (read-only commands only) |
| `--log-size IMAGE` | `/l` | Logical, allocated and initialized log bytes |
| `--resize-log SIZE SRC DST` | `/l:size` | Resize into a new image |
| `--resize-log-in-place SIZE DEV JOURNAL` | `/l:size` | Journaled in-place resize |
| `--scan-resources=high --online-scan …` | `/scan /perf` | Larger read-ahead and index caches |
| `--defer-repairs --online-scan …` | `/scan /forceofflinefix` | Queue all findings for offline repair |

## Recovery and repair

```sh
ntfs-chkdsk --replay-to DIRTY.img NEW.img            # native $LogFile replay into a copy
ntfs-chkdsk --validate-replay DIRTY.img
ntfs-chkdsk --repair-to SOURCE NEW.img               # copy repair
ntfs-chkdsk --repair-in-place DEVICE JOURNAL         # durable external journal
ntfs-chkdsk --resume-repair DEVICE JOURNAL
ntfs-chkdsk --security-cleanup|--rescan-bad --repair-to SOURCE NEW.img
ntfs-chkdsk --resize-log 4MiB SOURCE NEW.img
ntfs-chkdsk --resize-log-in-place 4MiB DEVICE JOURNAL
ntfs-chkdsk --resume-log-resize 4MiB DEVICE JOURNAL
```

### Replay

Replay handles bounded LFS 1.1 and 2.0 histories. It chooses redo or undo from checked transaction chains, then publishes an empty checkpoint.

Replay refuses:

- Unknown operations.
- Ambiguous histories.
- Torn records.
- Hibernated volumes.

### Repair

Copy repair never writes the source or overwrites the destination. Repair includes:

- Reconnecting orphans under `found.NNN`.
- Rebuilding derived indexes.
- Restoring object, reparse and quota system files.

In-place repair and in-place resize work like this:

- Each claims an unmounted block device exclusively.
- It journals preimages outside the device.
- It validates the complete result before publication.
- It refuses to resume under a changed policy or size.

Log sizes must be multiples of 1 KiB, at least 2 MiB, and below 4 GiB.

### Mounted scans

```sh
ntfs-chkdsk --online-scan MOUNTPOINT DEVICE QUEUE
ntfs-chkdsk --spotfix DEVICE QUEUE JOURNAL           # after unmount
```

The scan freezes the mount. Through the mounted writer, it repairs:

- Missing allocation bits.
- EA summaries.
- DATA cross-links.

Everything else it queues for `--spotfix`.

Resource controls require `--online-scan`:

- `--scan-resources=balanced|high`: high may use up to 80% of available memory.
- `--scan-memory-percent=N` (balanced only).
- `--scan-io-priority=low|normal|high`.
- `--scan-write-cache-size=1280KiB..128MiB`.

All memory budgets respect cgroup limits.

### fsck

`fsck.ntfsrs` takes these modes:

- `--check`, also `-n`.
- `--repair`, also `-y`, `-a` or `-p`.
- `--ask`, the default, which gives a 15-second console prompt.

The wrapper first resumes any pending journal. Journals go under `/var/lib/slate-ntfs/fsck` unless `--journal PATH` is given.

| Exit | Meaning |
| --- | --- |
| 1 | Repaired |
| 4 | Unresolved |
| 8 | Failure |
| 16 | Usage error |

To opt in, install `ntfs-chkdsk` and `fsck.ntfsrs` in `/usr/sbin` and set the fstab pass number to 2. Add `nofail` so a dirty volume cannot block boot.

### Write labs

`ntfs-write-lab SOURCE NEW ROOT-FILE OFFSET EXPECTED_HEX REPLACEMENT_HEX` overwrites bytes in a disposable copy. `--journaled` makes it use a native log transaction; Windows 11 recovers those transactions.

`--override-hibernation` refuses active images until transactional `hiberfil.sys` deletion exists.

## Benchmarks

`sudo bash kernel/tests/benchmark_reads.sh NEW_DIR` compares read, stat and listing performance with NTFS-3G on a disposable loop image. Options:

- `SLATE_BASELINE_MODULE=/path/to/previous.ko` adds an older module to the comparison.
- `SLATE_BENCH_ROUNDS` sets the number of rounds, from 3 to 99.

`kernel/tests/test_kernel_read_errors.sh` injects block I/O failures through device-mapper.
