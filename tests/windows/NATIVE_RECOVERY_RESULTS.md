<!--
Module: documentation.native_recovery_results
Purpose: Document Native writer recovery results — 2026-09-28.
Created: 2026-10-02
Architecture: Preserves implementation or validation evidence for maintainers; runtime behavior
remains owned by the documented core, tools and kernel modules.
-->

# Native writer recovery results — 2026-09-28

**Passed for the bounded same-size resident overwrite.** Windows 11 Pro build
22000, isolated QEMU/KVM guest under WSL, new OS child overlay for each of
three batches. The original VDI and original source images were not modified.
The data volumes were newly formatted 64 MiB NTFS images with 512-byte sectors,
4 KiB clusters and 4 KiB LFS 1.1 pages. The tested update replaces `AAA` at
offset 1 in `write.bin`, changing `AAAA` to `A111`.

## Results

| Phase | Last durable step | Windows content | chkdsk exit | Test-volume corruption/repair events |
| --- | --- | --- | --- | --- |
| 0 | Unmodified control | `AAAA` | 0 | None |
| 1 | Published initialized dirty copy | `AAAA` | 0 | None |
| 2 | Open/update intent, restart unchanged | `AAAA` | 0 | None |
| 3 | Intent secondary restart | `AAAA` | 0 | None |
| 4 | Intent primary restart | `AAAA` | 0 | None |
| 5 | Commit, restart still at intent | `A111` | 0 | None |
| 6 | Commit secondary restart | `A111` | 0 | None |
| 7 | Commit primary restart | `A111` | 0 | None |
| 8 | Replayed target MFT record | `A111` | 0 | None |
| 9 | Empty checkpoint record | `A111` | 0 | None |
| 10 | Checkpoint secondary restart | `A111` | 0 | None |
| 11 | Checkpoint primary restart | `A111` | 0 | None |
| 12 | Normal writer completion | `A111` | 0 | None |

After each guest stopped, NTFS-3G independently read all 13 data disks through
read-only NBD attachments: all matched the table. Source and pre-recovery
partition hashes remained unchanged. The data disk copies intentionally
changed during Windows recovery. Guest OS C: had pre-existing repair events;
those are captured and excluded by volume identity, not silently suppressed.

Fresh manifests, full guest transcripts, verification summaries and the
post-Windows readback summary are in `results/2026-09-28-native-recovery/`.
Each batch has a distinct run/completion ID and exact disk signatures. These
are fresh results; earlier diagnostic transcripts are not reused as evidence.

## Fix and regression coverage

The original OpenNonresidentAttribute and CommitTransaction records both had
LFS flags 0. Isolated variants showed that Open requires the no-undo flag 4,
and the empty-buffer Commit requires both no-redo/no-undo flags (6). With
those changes alone, Windows recovered committed data. The Rust writer now
derives these bits from the encoded operation's buffer lengths; restart
records retain flags 0. The parser and encoder accept defined bits 0..2 and
reject unknown bits. No new transaction opcode or C bridge change was needed.

- `bash build.sh`: format, Rust unit/integration tests and release tools passed.
- `python3 src/tests/writer/test_native_writer.py`: all 11 interruption/recovery cases,
  independent emitted-flag checks, refusal paths and source immutability passed.
- `python3 src/tests/recovery/test_native_replay.py`: 34 interruption/refusal cases passed.
- Matching WSL 6.18.33.2 kernel build: `.ko` linked without `CONFIG_RUST`.
  Kbuild emitted host/WSL timestamp-skew warnings; no runtime kernel behavior
  changed or writable mount was enabled in this milestone.

## Limits and next write milestones

This tests one operation on one Windows build and one volume geometry at
completed flush boundaries. It is not hardware power-cut or torn-write
validation, general Windows log replay, allocation, file growth, namespace
mutation, ACL mutation, hibernation discard, or clean unmount. The writer
requires a clean, unhibernated source with an uninitialized log and writes
only a new copy. Kernel mounts remain read-only.

Next: recover broader real Windows histories, support repeated transactions
and log reuse, then add allocation and directory operations with equivalent
interruption/Windows tests and NTFS write-permission enforcement.
