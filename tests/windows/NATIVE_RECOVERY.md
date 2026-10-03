<!--
Module: documentation.native_recovery
Purpose: Document Native writer Windows recovery test.
Created: 2026-10-02
Architecture: Describes the host fixture preparation and disposable Windows guest validation
flow; the verifier assesses captured evidence.
-->

# Native writer Windows recovery test

This test mounts generated disposable data disks read/write in a Windows VM
so that **Windows itself** performs journal recovery. `chkdsk` then runs
without repair switches. Do not attach these disks to the host or combine
them with valuable data disks. Keep the VM offline and use a new OS overlay
for each batch. The scripts neither download Windows nor modify its login.

## Reproduce

1. Build the release tools with `bash build.sh` on Linux/WSL. Install
   `mkfs.ntfs` and `ntfscp` from NTFS-3G.
2. Run `python3 tests/windows/prepare_native_recovery.py /absolute/new-directory`.
   The directory must not exist. This creates a fresh 64 MiB source, one
   untouched control, all 11 interrupted writes, and a completed write. No
   generated log bytes are patched. Phase 12 denotes the completed write.
3. For each of the three printed batch directories, attach only its `.disk`
   files as raw SATA disks to a disposable Windows VM. Preserve `.img` files
   and `cases.json` as pre-recovery evidence. Boot with guest automatic
   `autochk` disabled; otherwise a boot-time repair could conceal a failure.
   Normal NTFS mount-time journal recovery must remain enabled.
4. Copy that batch's generated `guest.ps1` into the VM. Run it elevated:
   `powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\guest.ps1 -Shutdown`.
   It selects only the expected disk signatures and sizes, reads `write.bin`
   before checking it, records current-boot NTFS events, and shuts down.
5. From the stopped VM, extract `C:\<batch-directory-name>.txt` read-only as
   `windows.txt` in that batch directory. Run
   `python3 tests/windows/verify_native_recovery.py /absolute/batch-directory`.
   Keep the generated `verified.json`, manifest, and transcript together.

Acceptance requires exact run and completion IDs, all expected disk identities,
old data before commit, new data after commit, successful `chkdsk`, and no
corruption/repair event for a tested volume. An unrelated guest OS event does
not imply a test-volume failure; the verifier matches event volume identities.
A zero `chkdsk` result alone is insufficient. A missing, stale, or truncated
transcript fails validation.

## Scope

The tested operation changes three bytes in an existing ordinary resident
unnamed stream. The writer requires a clean, unhibernated input with an
uninitialized log and writes only a newly created copy. Tests stop after
durable flushes; they do not emulate torn sectors, storage devices that lie
about flush completion, arbitrary Windows logs, or a writable VFS.

LFS flag 1 means a spanning record; flags 2 and 4 indicate absent redo and
undo buffers. This writer emits flags 4 for OpenNonresidentAttribute, 0 for
UpdateResidentValue, and 6 for its empty-buffer CommitTransaction. Restart
records retain flags 0. Omitting the absent-buffer flags caused Windows to
report event 55 and retain old data in the committed case.

Format evidence: [DFIR NTFS log parser](https://github.com/msuhanov/dfir_ntfs/blob/master/dfir_ntfs/LogFile.py)
and [upstream NTFS3 log implementation](https://github.com/torvalds/linux/blob/v6.18/fs/ntfs3/fslog.c).
See `NATIVE_RECOVERY_RESULTS.md` for the executed Windows test and limits.
