<!--
Module: documentation.write_support
Purpose: Track implemented writing operations, evidence and release limits.
Created: 2026-10-01
Architecture: This tracker connects core and VFS behavior to validation evidence.
-->

# Write support implementation tracker
## VFS feature status

Linux and native views share the writer, canonical page cache and native ACL
authorization. The shared engine passes the writer lifecycle and crash suites;
the mounted VFS paths below compile for Ubuntu 22.04/5.15 and WSL 6.18 but need
runtime, crash and Windows validation. In-place user-data overwrites and partial
punch-hole edge zeroing can tear.

| Feature | Implemented in source | Remaining |
| --- | --- | --- |
| Directories / attribute lists | mkdir/rmdir, checked resident and nonresident lists, external index attributes, family assembly and journaled publication. Parent lookup validates all filename parent references through the same resolver. | Bounded record/list/index capacity; runtime and crash validation of external layouts. |
| Timestamps / stat | Creation/birth time, mtime, ctime and atime at 100 ns precision; statx birth-time mask, allocated blocks and compression/encryption attributes. Explicit time changes and writeback persist through Rust. Alternate-view accesses update canonical atime; truncate, link removal and rename update times. | Runtime persistence/concurrency validation of this merge; complete Windows USN policy. |
| Locking / leases | POSIX, flock and OFD operations share canonical files. F_SETLEASE is wired; shared open/write accounting gates leases and opens/truncate/fallocate break conflicting leases across cached views. | Runtime race and lease-break validation; network NFS. |
| Notifications | Cached inode and directory projections receive namespace, data and attribute notifications. The companion WSL patch routes path/range events and permission denials across live mounted views, reconstructing uncached paths below each receiving root. Namespace events carry the actual child identity. Self events do not notify parents as child events. | Companion WSL patch required for cross-view mount/path events, including permissions; runtime concurrency and namespace teardown validation pending. |
| Symlinks | Resident/nonresident reparse storage, creation and target resolution, including targets up to 4096 bytes. | Windows interoperability and crash validation of nonresident storage. |
| Hard links | Filename extension records; complete family name-count checks; special-file links and transactional temporary-file publication with data sizes. | Transaction/list capacity bounds; symbolic-link hard links remain unsupported. |
| Special files | Linux-mode FIFOs, sockets and devices; WSL eight-byte LXDEV creation and recognized WSL special reparse tags. | Native-mode creation is refused; broader interoperability validation. |
| O_TMPFILE / orphans | Nameless marked records, publication, failed-creation cleanup, final eviction and mount-time orphan reclamation. | Expanded interruption and security validation. |
| Rename | Replacement, exchange and atomic WHITEOUT (Linux view, CAP_MKNOD, character device 0:0); replaced open files retain durable orphan state. | Complete crash matrix; whiteouts retain standard NTFS records/EAs. |
| mmap / writeback | Canonical page cache; header-selected page/folio callbacks and write_cache_pages or writeback_iter; bounded splice writes. | Memory-pressure and writeback race validation; large folios are not enabled. |
| Direct / nonblocking I/O | O_DIRECT uses owned bounce buffers and synchronous bios, ordered against file and block caches. NOWAIT supports an already-dirty, uptodate cached-page overwrite with trylocks and fault-disabled copying; other paths return EAGAIN. | Direct reads return up to 256 KiB per call; writes retain the 1 MiB transaction bound. Old kernels without kiocb_modified conservatively require cached NOSEC before NOWAIT. Mixed I/O and fault/race validation pending. |
| Allocation / truncate | Ordinary/KEEP_SIZE, punch, zero, aligned collapse/insert and unshare range operations; sparse FIEMAP, copy/splice; split DATA supported within bounds. | Reflink/dedupe is intentionally unsupported to preserve Windows/ntfs-3g ownership semantics; larger plans; sparse-range crash validation. |
| Permissions / ACLs | Explicit SID mapping, native rights, chown, Linux modes, POSIX access/default ACL get/set/list, atomic inheritance, chmod-mask adjustment, parent set-GID inheritance and VFS privilege removal before writes/mmap/range edits. | Runtime ACL/set-ID validation; broader Windows policy. |
| Linux security xattrs | `security.*` get/set/remove/list uses standard NTFS EAs, including `security.capability` and `security.selinux`. VFS/LSM authorization remains authoritative. LSM creation labels join inherited ACLs in the create transaction, including temporary files and whiteouts. Security labels remain active in both Slate views. Capability changes invalidate cached privilege checks across views; NOWAIT refuses cold checks. | Compiled for Ubuntu 22.04 / 5.15 and custom WSL 6.18; capability execution/stripping, enforcing SELinux transitions, cross-view relabel races, remount persistence and crash validation have not run for this revision. Windows does not enforce Linux labels/capabilities. |
| NFS export | Sequence-checked handles, d_splice_alias lookup, checked parent reconstruction and metadata commit. | Real nfsd/client testing. |
| Superblock lifecycle | write_inode, sync_fs, freeze/thaw, clean rw-to-ro writer finish, full-sync shutdown on file or directory descriptors. | Clean read-only-to-writable remount revalidates/reinitializes the writer; poisoned sessions remain refused. Power-loss validation pending. |
| Names / views | Native case folding, exact Linux names, shared identity/cache and per-view restrictions. | Full Steam/Proton workloads and Windows interoperability. |

## Hibernation override policy

`hibernation::write_gate` blocks writes for an active or ambiguous saved
Windows session. An override (`ntfs-write-lab --override-hibernation`) may only
apply to a recognized active image and yields `DiscardRequired`, not write
permission; short or unknown headers, interrupted resumes and inspection
failures still block. This is stricter than NTFS-3G's `remove_hiberfile`,
which only rejects `HIBR`/`hibr` signatures and still refuses a log with
Windows cached metadata.

A discard must re-read the file identity, links, attributes, index entries and
allocation after an exclusive offline open, then delete through the ordinary
journaled unlink path and verify absence before clearing the gate. Until that
exists the override refuses active images without creating a copy. The
copy-only `ntfs-hiber-discard-lab` prototype handles only a narrow
uninitialized-log layout and is not the production path. Windows 11 leaves a
`WAKE` header after resume; see tests/windows/VDI_CASE_2022.md.

## Implemented and selectively exercised

- Initial rw mounts on supported clean volumes, without CONFIG_RUST or a
  loop-device-only mount restriction. Fault injection remains loop-only.
- VFS resident/nonresident writes, growth, truncation, append and zero-filled
  holes; initialized nonresident overwrites write in place, and growth appends runs.
- Regular-file creation and closed-file unlink through the shared B-tree editor.
  File/namespace/allocation changes share one native transaction. MFT capacity
  growth is a preceding durable transaction, so failed creation can leave free capacity.
- Native hard links are no longer constrained to `$FILE_NAME` attributes that fit
  in the base FILE record. Long/many names spill into validated extension records,
  the resident or nonresident `$ATTRIBUTE_LIST` is rebuilt in the same transaction, and empty
  extension records are reclaimed as links are removed. Direct coverage forces
  multiple extensions and mounted coverage uses twelve long links. Unlink of a
  nonfinal name leaves data and handles intact; last-link VFS removal creates a
  durable marked orphan. Final canonical inode eviction queues it for a
  background worker that frees it in bounded transactions, settling the device
  cache and releasing io_lock between them; unmount, remount read-only and
  freeze wait for that queue. The next writable mount reclaims any orphan left
  by a crash or a non-I/O reclaim failure.
- MFT data growth, initialization of newly exposed records, slot reuse and
  mirror publication. Inode cache identity includes the MFT sequence number.
- Creation/deletion and rename support splitting multi-level directory indexes.
- File/directory rename across directories, case-only rename, index splits,
  root push-down/collapse, destination replacement and `RENAME_EXCHANGE`. A
  replaced last-link destination is orphaned atomically with the move.
- Journaled MFT bitmap/data growth and recovery through MFT extension mappings.
- Native descriptor xattr and chown, SDS dedupe/append, SII/SDH updates and
  immediate RCU descriptor-cache publication; explicit native security/restore/
  take-ownership grants. Default root/Administrators have no implicit grants.
- Linux/native mount policies in Rust, C, Python and ntfs-mount. Default Linux mode
  adds persistent ordinary chmod/execute bits through `$LXMOD`, preserving native ACLs.
- Exact-case POSIX names, shared writable/private mmap, page-cache dirty/writeback,
  native hard links, advisory locking, notifications, real free-space reporting and
  directory fsync. Allocation/KEEP_SIZE, punch, zero, collapse/insert and unshare
  fallocate modes, FIEMAP, copy-file-range and
  explicit splice read/write paths are wired through the mounted VFS. The bridge
  selects 5.15 page `writepage`/`writepages` and legacy lock APIs or newer folio/lease APIs from the
  target headers.
- Truncate through `setattr` is exercised with filename extension records actually
  present: the regression forces a resident `$ATTRIBUTE_LIST`, then shrinks, grows,
  writes and shrinks again through hard-linked names and verifies the result after
  remount in earlier tests. Current source also handles bounded split/external
  DATA layouts; this merged revision has not run that matrix.
- NFS export operations are wired through `s_export_op`: sequence-bearing 48-bit
  MFT references form stable file handles, connectable handles carry the parent,
  stale sequences return `ESTALE`, positive lookup uses `d_splice_alias`, and
  `get_parent` follows checked filename attribute-list extensions. Local exportfs
  handle round trips are covered; end-to-end nfsd/client testing remains open.
- Superblock lifecycle hooks are explicit: `write_inode` journals inode times,
  `sync_fs` checkpoints, freeze/thaw is wired, and rw->ro reconfiguration performs
  full VFS writeback followed by a clean `Writer::finish`. A full-sync shutdown
  ioctl on files or directories deliberately keeps the dirty marker and rejects
  subsequent writes with I/O error. A finished/poisoned writer is not revived by
  ro->rw remount.
- Linux-mode FIFO/device/socket `mknod` and `O_TMPFILE` creation/publication, plus
  POSIX access/default ACL get/set/list and chmod mask updates. Native mode keeps
  refusing Unix special nodes and chmod.
- Native write/create/delete authorization and basic ACE inheritance, with
  creator SID substitution and ordered allow/deny preservation.
- Verified empty-journal reopening and journaled mount/unmount flag transitions,
  including offline recovery when only the primary or mirror was written.
- Copy-only LFS 1.1/2.0 discovery, tail/group/spanning records and nonempty
  checkpoint tables; repeated updates, global undo ordering, transaction-ID
  reuse, compensation and completed top-level actions in supported histories.
- DeleteDirtyClusters invalidation and HotFix redirection during analysis.
- Metadata replay primitives and target resolution for MFT/attributes/runlists,
  bitmap/index changes, including MFT growth dependencies in tested histories.

Tests run only through selected test.sh targets, never during builds.

## File deletion and Trash

Deletion reclaims physical runs from supported compressed, sparse and encrypted
streams. Bounded compressed orphan cleanup retains whole compression units,
and mapping edits preserve the compression header and physical allocation size.
The native rename path shares unlink's read-only-file permission check.

Before allocating an entirely zero, bitmap-free initialized MFT slot, the
writer formats and flushes a valid unused record as the transaction's undo
image. Nonzero malformed records remain refused. New and rewritten standalone
names use POSIX namespace; native mode retains Windows naming restrictions and
case-insensitive lookup and collision checks. Existing paired DOS aliases are
removed with their long names.

Host core, kernel adapter, writer lifecycle and C permission callback checks
pass, including compression boundaries and zero-slot flush failure. The mounted
regression is available through `bash test.sh kernel:file-deletion`; its optional
`--windows-source` fixture supplies compressed files and paired DOS names.
The ignored writer case uses `SLATE_WINDOWS_DELETE_SOURCE`. These mounted and
Windows-specific cases require separate execution; the host checks do not
establish live GIO behavior or all compressed-reclamation crash boundaries.

## Still required for general production writes/recovery

- Larger namespace shapes beyond the bounded filename-extension/transaction
  capacity and unsupported rename modes such as `RENAME_WHITEOUT`.
- Larger allocation plans and attribute-list expansion beyond current bounded
  records/transactions. Creation is now connected to expanded MFT growth.
- Recovery across arbitrary Windows histories, unresolved prepared transactions,
  deleted or extensively remapped streams and all metadata dependencies.
- Windows interoperability validation for these new allocation/namespace
  operations; current interruption fixtures and NTFS-3G readback do not prove it.
- Richer inherited policy, audit/MIC enforcement and security
  policies beyond the supported attribute-family capacity. Unsupported policy
  is refused, not discarded.
- Complete USN policy, broader geometries, read-only -> writable remount and
  in-place repair. rw->ro clean shutdown is implemented. Writeback still needs a wider memory-pressure and
  crash-interruption matrix.
- Transactional hibernation discard and complete recovery integration before
  dirty Windows volumes may be mounted writable.

The earlier same-size resident overwrite subset passed Windows 11 replay and
read-only chkdsk comparison; see tests/windows/NATIVE_RECOVERY_RESULTS.md.
That evidence does not extend automatically to the new operations.

Per-application launch and shared-volume views are implemented through ntfs-run.
Full Steam/Proton testing has not been performed; do not infer compatibility
from component tests.
