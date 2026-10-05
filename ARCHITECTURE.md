<!--
Module: slate_ntfs::architecture
Purpose: Describe module boundaries, implementation status and style conventions.
Created: 2026-09-30
Architecture: Guides changes across the Rust core, offline tools and Linux VFS bridge.
-->

# slate-ntfs architecture

## Goal

Build a Rust-first NTFS filesystem for Linux with checked on-disk parsing, writable VFS operations, and Windows-compatible crash recovery. Linux is the sole product target, including userspace recovery tools. Windows fixtures check NTFS interoperability; they do not define another product target. Rust owns NTFS interpretation, transactions, ordering, and flush decisions; the C bridge supplies Linux VFS callbacks and block I/O.

Source formatting, module headers, comments and documentation creation follow
[STYLE_GUIDE.md](STYLE_GUIDE.md).

The allocation-free `bytes` module owns checked little-endian reads and writes.
Record editors keep their public writer names as reexports, and metadata replay
and BitLocker parsing use the same bounded accessors. `filename_metadata` owns
borrowed FILE_NAME views, layout constants and transactional cache refresh, shared
by index readers, namespace editors and offline repair. Exact attribute framing
and prefix index-key framing remain separate operations. Callers retain empty-name,
namespace and character policies; parsing preserves cached metadata without
deciding whether it needs a refresh. The facade exposes `filename` as an alias
of this single implementation, and `index::FileName` remains a reexport.
The permissions `i18n` module likewise owns its private catalogs and lookup
logic, keeping each translation key and its consumers in one implementation.

The checks belong to these boundaries:

| Check | Responsibility |
| --- | --- |
| `automount:unit` | User-manager execution, direct invocation and process credential dropping |
| `permissions:unit` | Policy conversion, write intent, remount outcomes, state verification and translations |
| `kernel:permission-callback` | Real C callbacks with kernel API test doubles: granted/denied read, execute and directory probes; internal-open credential scope and error unwind in all three open API variants; public mmap identity, noexec and shared-write gates |
| `kernel:desktop-permissions` | Disposable mounted image: GIO capabilities, create/write/rename/delete, group rights, read-only transitions and attribute notifications |
| `kernel:file-deletion` | Disposable mounted image: GIO Trash, permanent deletion, DOS aliases, compressed streams and subsequent writes |
| `writer:lifecycle` | Real NTFS image creation/deletion and writer durability behavior |

The ignored writer lifecycle case
`scattered_orphan_reclamation_exceeds_one_bitmap_transaction` takes a fresh
1 GiB image through `SLATE_LIFECYCLE_LARGE_SOURCE`. It checks cleanup across
20 bitmap sectors, preallocated attribute-list storage and an orphan marker
in an extension record. Reclamation retains the marker until final deletion
and limits each tail release to the transaction's remaining bitmap capacity.

The live desktop test requires a matching module, root and loop devices on a
test host with no Slate module already loaded. It refuses to replace an active
driver or touch existing mounts. Callback tests and build checks do not replace
this live validation. Builds do not run tests automatically.

## Human-readable files and module headers

[STYLE_GUIDE.md](STYLE_GUIDE.md) owns formatting, module headers, creation-date
provenance, reusable types, named constants and comment conventions. Module headers
explain local responsibilities and callers; this document records how modules work
together and their directory layout. Update both when merging or moving code.

## Current state

Current package and kernel-module version: **0.7.1**. The kernel module is `slate-ntfs.ko`, loaded as `slate_ntfs`; before 0.7.1 it was `ntfs_rs`. The filesystem type stays `ntfsrs`. Both names register that type, so the package and `mount.ntfs` unload a loaded `ntfs_rs` before loading `slate_ntfs`, and the package deletes leftover `ntfs_rs.ko` builds.

BitLocker metadata parsing and protector unlock run in userspace. `ntfs-mount` builds a dm-crypt mapping for XTS, CBC or CBC-plus-diffuser sectors and a dm-linear view for the relocated NTFS boot region and reserved FVE areas, then mounts that view with the ordinary NTFS kernel driver. Fully encrypted idle volumes may be written; volumes still converting mount read-only. Direct `bitlocker_key=` mounts and the kernel AES bridge are removed. TPM-only unlock and BitLocker creation/removal remain open. Retained synthetic-image mounts and the Ubuntu 22.04 module build pass; real Windows BitLocker image, crash and interoperability validation remain open.

The shared `no_std` Rust core serves the library and experimental Linux module on x86_64 and little-endian ARM64. Rust owns transactions, ordering and durability; the C bridge provides VFS callbacks and block I/O. Checking, offline repair and recovery live in a separate tools crate. Mounted writes require supported volume geometry, a clean volume and an explicit SID map. General dirty-history recovery remains an offline operation. ARM64 has compile coverage only; its mounted and boot behavior remains unvalidated.

The C bridge now reads and stages boot/metadata bytes through the block-device page cache using page or folio mapping helpers, without direct `buffer_head` calls. Rust still controls checkpoint and flush ordering; the bridge still runs `sync_blockdev` before the device cache flush. Direct data I/O continues through bios. This is a build-checked I/O change; mounted crash behavior and performance have not been measured yet. A regular file reads ahead at least 4 MiB (`NTFS_RS_MIN_READAHEAD_BYTES`), widened from Slate's `readahead` callback: a device that reports no optimal I/O size otherwise gets the kernel's 128 KiB, one batch in flight. File readahead and `read_folio` map each batch of up to 256 KiB through Rust (`ntfs_rs_map_file`) and submit asynchronous bios straight into page-cache pages that lie wholly inside an initialized extent below EOF. Holes, resident and partially initialized pages, EOF tails and, on writable mounts, extents with dirty block-cache pages or held metadata images still go through the synchronous Rust reader. Buffered `write_iter` calls start asynchronous block-cache writeback each time a writer crosses a 1 MiB file offset, so drains find little left to write. The custom buffered file path remains in place; iomap, large file folios and delayed allocation have not been adopted. `statfs` counts `$Bitmap` once per write session and then applies `Writer::allocated_delta`, the net clusters that committed and pending transactions have allocated, taken from the `$Bitmap` sectors each transaction patches; a changed volume is recounted after `NTFS_RS_SPACE_RECOUNT_MS` in case a change bypassed the writer. A count reads all of `$Bitmap` under `io_lock`, about 130 ms on a 1 TB volume, and Wine asks for free space hundreds of times while a game starts. Dentries carry their folder's namespace epoch; after a change in that folder, revalidation looks a positive name up again and keeps the dentry when it still names the same file. Declaring it stale would make the VFS run `d_invalidate`, which unmounts everything beneath it, such as the Steam runtime container's bind mount of a game folder.

Ubuntu 22.04's initramfs can load the `slate_ntfs` module for `rootfstype=ntfsrs`; the module exports a filesystem alias and the package provides an installer, module hook and early loader. Retained QEMU images boot both a static init and a complete Ubuntu systemd root from NTFS, remount `/` writable, write files and shut down cleanly on consecutive boots. A late systemd shutdown hook remounts the NTFS root read-only. The Ubuntu root also survived QEMU S3 suspend and full hibernation to a separate swap disk: the next boot resumed the saved session, wrote the root and shut down with a clean volume flag. A dirty root remains read-only until offline recovery. Physical power-state transitions and Linux resume from a swap file on NTFS remain unvalidated.

`Volume::read_mft_zero` reads `$MFTMirr` when an interrupted write tore record 0, and replay planning takes a torn mirrored record from the mirror and any other torn record from the undo image of the first transaction in the replayed history that rewrote it; fsck's pre-replay assessment reports hibernation as unknown for a torn root folder and checks again on the replayed view. Clean Windows journal handoff validates both restart pages, retains them while removing obsolete log pages, and publishes a new standard LFS checkpoint before metadata writes. Explicit Linux-flag snapshots live in the ordinary hidden/system `.slate-metadata/linux-flags` file. Restoration checks volume serial, full MFT reference and creation time, preserves existing EAs, and prunes deleted/replaced identities; it never restores by pathname or runs automatically at mount.

The writer batches bounded metadata edits, separates the live log head from the checkpoint, and packs small standard LFS transactions into a fixup-protected page. Committed metadata stays in memory until checkpoint or retention-capacity spill; spill writes already-committed targets without advancing the checkpoint or adding a flush. Larger transactions preserve the update-before-commit barrier. A transaction may take up a structure that a pending one changed, such as an index block a deletion freed; a fresh target read through its protected hold is compared with the protected form of the pending image. Idle fsync adds no flush; checkpoints retain metadata, checkpoint record, secondary restart, then primary restart ordering. A drain that only makes room for a crowded batch (`Writer::make_room`, called by the kernel before each operation) journals the batch without the post-commit flush and records `log_unflushed`; the next commit's barrier, a spill or checkpoint (`settle_log`), fsync, or the periodic drain makes it durable before any of its targets goes home, so committed transactions stay a durable prefix of the log. A batch that freed clusters still drains durably, as its quarantine ends with the drain. Retained targets spill after the next commit's own barrier rather than before it. Together these halve the device flushes of namespace-heavy work such as the Steam runtime's hard-link tree; `room_drains_keep_commit_order_durable` interrupts such a history at every write and flush. In-place initialized overwrites do not set exposure_dirty. fdatasync skips timestamp-only write_inode work while retaining data writeback and journal drain. Disposable-image interruption checks pass for extension names, fragmented append, checkpoint wrapping and truncation; Windows journal handoff and namespace-specific controls require their separate fixtures. Restart copies at the same checkpoint may differ only in the clean-shutdown flag after an interrupted publication; assessment retains the dirty classification and offline replay validates that checkpoint before publishing a converged pair. Conflicting client/checkpoint fields and torn copies remain refused by assessment.

The checker implements supported boot/MFT/family reconstruction, directory rebuilding and invalid-parent reconnection, physical DATA/metadata cross-link cloning, duplicate security-descriptor restoration, EA/reparse framing repairs, and allocation reconciliation. It can rebuild supported `$Secure` indexes from validated `$SDS` descriptors and repair supported reserved metadata families. The merged repair planner adds extension-family publication, reserved-file repair, fragmented relocation, semantic repair checks, and relative-index replay operations. `$BadClus` replacement runs use a disk-backed spool while retaining the merged extension-family repair. Audits and structural plans use disk-backed catalogs, ownership/family queues, patch images and indexes; directory rebuilds stream index pages. Exclusive offline repair streams a durable external preimage/redo journal, revalidates under the device claim and resumes interrupted writes in at most 64 KiB units; the operation remains guarded until final validation. Sector rescue scans the complete source, including allocated and free clusters, and records readable bytes and unresolved EIO ranges externally. A complete archive can be extracted or reintegrated into a new image after identity and sector checks. Native replay spools log pages, records, transaction history, schedules, target descriptors and patch images to private files. Supported histories use one disk-backed general replay planner. An online scan repairs supported allocation, EA and DATA findings, then queues the remaining worklist externally after a frozen preflight. Mounted checks, scan snapshots and preflight use the selected index policy. The external queue retains that policy; offline spot-fix repeats the same assessment before applying its durable repair journal, and interrupted repair resumes with the same policy. Legacy queues retain default full checking. General mounted repair and unreadable-byte reconstruction remain open. Mounted typed EA/DATA repair remains narrower than offline repair. The merged semantic and native-replay matrices pass on disposable WSL images; the combined Windows interoperability and crash matrix remains open. This is not a complete CHKDSK replacement.

The CHKDSK checkpoint adds complete-family EA summaries and hard-link counts; per-file and directory duplicate-information checks; nameless-file reconnection; missing derived `$ObjId`/`$Reparse` creation; and semantic object-ID, quota, USN and reparse audits. Quota topology repair retains controls from every intact allocated node, including disconnected pages, and refuses missing or conflicting policies. Standard `$AttrDef` entries can be rebuilt while retaining valid private definitions; `$UpCase` validation checks stable mapping invariants and repair corrects only ASCII. Fixed-size filename and standard-information edits preserve physical attribute IDs and family-list ownership. Derived system indexes and compacted SDS streams can allocate fragmented runs and split mapping descriptors across extension records. Optional copy-repair maintenance rescans old bad-cluster declarations only after every source byte is read, and compacts unused shared descriptors while retaining referenced IDs and ACL bytes. A read-only surface scan reports unreadable physical ranges. Selected assessment and repair outputs pass Windows checks; broader corruption, maintenance and replay comparisons remain unverified. Full CHKDSK parity remains open.

The VFS implements mkdir/rmdir, reparse symlinks, Linux special files, temporary files, replacement/exchange/whiteout rename, durable orphans, buffered writes and shared writable mmap. Timestamp persistence, FIEMAP, copy/splice, export handles, leases, cross-view notifications, freeze, bidirectional read-only/writable remount and full-sync shutdown are wired.

The current source adds split DATA and external directory-index assembly/publication, resident and nonresident attribute lists, and nonresident reparse storage for symlink targets up to 4096 bytes. Standard 1 KiB MFT records remain on disk; a bounded 16 KiB logical image is used only in scratch. Family publication shares the existing transaction engine. Fallocate supports ordinary/KEEP_SIZE allocation, PUNCH_HOLE with KEEP_SIZE, ZERO_RANGE with optional KEEP_SIZE, aligned COLLAPSE_RANGE and INSERT_RANGE, and UNSHARE_RANGE with optional KEEP_SIZE. Parent resolution for exported handles includes extension records; A Rust-backed index scan supplies exportfs name lookup without opening directories.

The writer reaches every journal page through a map of the journal's pieces on the device (`LogMap`), so a journal Windows left fragmented, as it does after growing one on a full volume, is written, wrapped and recovered like a contiguous one. The pieces live in storage the mount lends for the session, sized for as many mapping pairs as the journal's file record can hold, so the map has no limit of its own; only a journal with a hole is refused. A journal may be as large as its format allows, just under 4 GiB (`MAX_LOG_BYTES`), which is also the largest size Windows accepts; the one-time erase of a journal last used by Windows is written in spans of up to 1 MiB. Windows itself declines to grow a journal into free space fragmented below about a megabyte per run.

The writer takes its sizes from the boot sector (`BootSector::writable_geometry`): clusters of 512 bytes to 2 MiB, 4 KiB index blocks and 1 KiB or 4 KiB file records, on sectors of any size. Fixups always stride 512 bytes, so a 4 KiB sector may hold four records and the sector size itself changes nothing in the engine; the C bridge writes metadata through the block cache, which aligns device requests. Where a cluster is larger than an index block, index VCNs count 512-byte units (`index_vcn_bytes`), and a journal record names its target by cluster with the offset inside it in 512-byte units, as Windows writes them. `$MFTMirr` holds four records or one cluster if that is more; the writer keeps the records below the first user record current there (`mirrored_bytes`), as Windows does, and the checker compares the four that Windows verifies. Allocation budgets (resize steps, append windows, table compaction) are byte counts, so they do not scale with the cluster. On clusters smaller than an index block, a block (or a file record on 512-byte clusters) spans several clusters. The writer allocates them together, journals the structure with one LCN for each cluster as Windows does, and stages data in units of one cluster so that padding never passes the allocation. A structure Windows left in clusters that are not adjacent is read, but an operation that would change it is refused, as is a journal with a page split between two runs.

Kernel stacks are 16 KiB, and a metadata operation ends in the block layer and the device's driver, which need several of them. The writer is therefore built in the mount's own storage (`Writer::prepare_in` fills a copy of `Writer::BLANK`) and never passes through a stack frame; a transaction carries a few-word copy of the journal map, which views every piece in the lent storage; a drain reads the batch's entries in place; and the kernel adapter drains a crowded batch at the top of each operation (`ntfs_rs_make_room`), before that operation's frames are on the stack. Measured with the kernel's stack tracer on a USB-attached copy of a real volume: 7 KiB at mount and 11 KiB under parallel load.

A directory listing states each entry's file type from the index entry alone: directory or file from the duplicated attributes, link or special file from the duplicated reparse tag; a system-flagged file, which may be an older-style link, is left unknown for the caller to stat. Programs rely on this: GLib's trash code crashes on a listing that leaves types unknown.

Both views accept the characters Windows forbids in a name (`" * : < > ? \ |` and control characters) by escaping them: each is stored as the private-use character U+F000 plus its code, the convention WSL uses, so the on-disk name stays legal for Windows and its checker, and a mounted view shows the original character again. `linux_names` owns this encoding; a name stored unescaped before the convention is still found. The NTFS view keeps refusing what escaping cannot express: a trailing dot or space and the reserved device names.

The 2026-09-29 merge adds WSL special-file/device metadata, temporary-file publication fixes, ACL callback wiring, export alias splicing and clean rw-to-ro writer finish. Stat exposes all four timestamps and allocated blocks; alternate-view atime changes reach the canonical inode. Leases share open/write accounting and cross-view break checks. Cached peer notifications cover namespace, data, access and attribute changes.

The subsequent VFS update adds atomic default-ACL inheritance, parent set-GID inheritance, VFS set-ID removal before content changes, atomic RENAME_WHITEOUT using ordinary WSL device metadata, and fresh writer validation for read-only-to-writable remount. Direct I/O bypasses file and block data caches using synchronous bios; resident data continues through journaled MFT publication. NOWAIT overwrites can copy without faults into an already-dirty cached page, with EAGAIN for paths needing I/O, metadata work or waiting. Reflink/dedupe remains unsupported to preserve Windows/ntfs-3g writable compatibility.

Full path-based cross-view fanotify routing uses the companion patch for the 6.18.33.2 WSL kernel. It snapshots live mounts, reconstructs paths beneath each receiving view root, preserves permission-event denials and range payloads, and avoids recursive delivery and superblock-only duplicate events. Ordinary unmodified kernels retain inode-based peer notifications. No on-disk format or recovery rules were changed by these VFS additions.

The core, tools, utility library and module build against Mint 22.3/22.1/21.3 kernel headers (6.14/6.8/5.15) and Debian 13/12/11 headers (6.12/6.1/5.10). Header probes select supported writeback, time and freeze APIs. The matching 6.18.33.2 WSL module has mounted and passed retained Ubuntu root boot, suspend and hibernate checks; the distribution builds are compile checks only. ARM64 userspace, freestanding Rust and the complete module cross-build against Ubuntu 6.14 ARM64 4 KiB and 64 KiB page headers pass; ARM64 runtime mount and boot remain unvalidated. Earlier VFS crash results and performance measurements do not validate every subsequent update. Network NFS remains untested.

Bounds remain explicit: 16 records per mounted transaction, 16 KiB logical record/list buffers and bounded log/bitmap/index arenas. A hard link loads only the records it changes (`load_namespace_family`) and puts the new name in the base record, the newest extension record holding names, or a new one, so a file keeps thousands of names; readers that do not need every name use the name-free projections (`resolve_record_attributes`, `resolve_record_streams`), and record validation checks attribute IDs past its 128-entry stack table by rescanning. Offline `$BadClus` runs spool to disk, but replacement descriptors and rebuilt family lists still grow in RAM; each encoded mapping segment must fit an MFT record, and extension publication needs free MFT slots. The mounted driver reads and writes a split `$MFT` whose extension records lie in the range record 0 maps by itself; it still refuses compression and per-file EFS encryption; full-volume BitLocker is handled below the NTFS parser. Offline mapping and physical relocation cover the validated cases described above. Capacity exhaustion fails the operation. In-place data writes and punch-hole edge zeroing can tear or survive an interrupted metadata operation; user data is not journaled. New layout publication, sparse-range transitions, native Windows replay and physical power loss require validation before use on valuable volumes.

Offline DATA recovery shares one authenticated archive classifier for copy and
in-place publication. In-place recovery claims an unmounted device exclusively,
binds the external archive and loss map to its durable journal, and preserves
readable bytes before retiring failed physical clusters. Resume uses the retained
plan and journal. Sparse and encrypted streams retain their encoding metadata;
encrypted losses are reported as missing encoded storage. Missing compressed
payload invalidates its whole initialized compression unit, which is replaced
with a valid sparse zero unit. The loss map records these affected logical ranges
separately from unreadable physical bytes. Critical unreadable metadata and
insufficient replacement space remain refusal cases. The new in-place and
encoded-stream paths still require runtime validation.

Filename assessment separates recoverable alias normalization from invalid
content, framing, missing indexed claims and duplicate link identity. Complete
families project normalized alias names into the private audit catalog before
index matching; source values and raw namespace bits are preserved. Duplicate
publication compares the full parent reference and exact UTF-16 spelling,
independently of cached metadata and namespace, while distinguishing base from
continuation placement. Derived I30 list rows must match an allocated physical
record, its complete generation and base ownership, and the exact attribute
identity before they can authorize extension membership. Stale or foreign rows
are filtered through the existing repair spool. Recoverable malformed derived
rows use independently validated physical attributes; index-only extensions
with stale backreferences can transfer to one qualified directory authority.
An extension-held root requires an original framed list row and a genuine full
backreference before it can establish that authority. Mixed-member payloads and
attribute IDs survive derived cleanup, and the shared publisher retires empty
extensions. Namespace-only key differences retain proven path edges while
reporting the key correction. Unreadable critical DATA and equally valid
competing ownership retain their existing refusal gates. These
new classification, duplicate and derived-family paths are compiled but still
require runtime validation.

### Fragmented stream reads and writes

`record_edit::pack_mapping_segment` fills each physical mapping segment by its
encoded byte size. `Tx::pack_runs` uses it to publish ordinary 1 KiB extension
records through the existing journal. A fixed sixteen-run split wastes most of
each record and can exhaust the sixteen-record transaction bound during an
otherwise ordinary file copy. The replacement streams mapping pairs into a
bounded buffer; it retains stream flags, sparse mappings, sizes and absolute
VCNs, and resets signed LCN deltas at each physical segment boundary. Memory
and transaction bounds remain explicit.

`record_edit::append_mapping_segment` assembles continuation mappings for both
the writer and read-only `Volume::resolve_record`. It preflights arithmetic and
capacity, then encodes rebased deltas in one pass. Repeated single-run appends
rescan the existing mapping and make fragmented streams progressively slow.
The shared streaming implementation removes that repeated work while keeping
on-disk fixup, sequence, ownership and attribute-list validation.

`Volume::visit_record_family` validates physical family members one record at a
time. `namespace_family.rs` uses that visitor to load the filename and EA
records a namespace operation changes, while retaining untouched DATA
continuations outside the transaction cache. `Tx::finish_namespace_families`
merges changed descriptors into the checked original list and publishes them
through the existing journal. Namespace changes preserve stream metadata;
content edits retain the ordinary assembly and filename-cache refresh path.

Orphan cleanup retires DATA continuations in bounded transactions, including
list allocation and retirement in the remaining bitmap-sector budget. A
descriptor is located again by its attribute ID after an earlier descriptor
changes length. Compressed tails must leave a complete compression unit;
layouts needing a partial-unit boundary or exceeding metadata/list scratch
capacity are refused. The writer lifecycle regression covers twenty DATA
extension records, dense and whole-unit compressed mappings, a tail preceding
its first descriptor in the same record, and mount-time orphan cleanup.
Unlink orphans any file whose runs exceed one transaction's bitmap budget, and
an empty index keeps its allocation when releasing it would exceed that budget.
Eviction hands an orphan to a background reclaim worker, so unlink and close
return at once; the worker frees it one transaction at a time, flushing the
device before taking io_lock so lookups keep running. The periodic drain and
sync_fs settle the device the same way. Only EIO poisons the writer.

`Volume::load_mft` is the one way to read `$MFT`'s record. When the table's
attributes are spread over several records it assembles them into one logical
record whose unnamed DATA maps every extent, so every lookup that follows works
for a split table and an unsplit one alike. It first chains the map: each
later DATA segment is read through the segments before it and appended, so an
extension record may lie anywhere those segments reach, not only among the
records 16 to 23 that NTFS reserves for them. The family is then checked
through the chained map. The attribute list may be resident or not and up to
8 KiB long; the assembled map holds 16 KiB.

The writer keeps the table in record 0 while its map fits there. When it no
longer fits, `pack_family` keeps the first map segment in record 0, sized to
the room left after the other attributes and a resident attribute list, and
puts later segments into the reserved records, which it formats first where the
formatter left them blank. Once those are taken, a segment goes to the first
free record that the segments before it map, and the list moves from record 0
to clusters of its own when it outgrows the room kept there. The mount's kept
copy of the map is voided explicitly after such a change (`drop_table`), since
those records lie outside the range whose writes void it. The writer reads the table through the same kept map, so an operation on a table in hundreds of segments does not chain them again. A map that fills
its 16 records or 16 KiB ends growth with a lack of space. Automatic growth adds an
eighth of the table (at most 16 MiB) beyond the request, first directly behind
the final extent, then anywhere, then in smaller steps, and leaves the data
allocation cursor where it was, so file data does not settle behind the new
extent. Each growth writes the table's records home with a checkpoint, and the
kernel adapter starts a growth from a shallow frame before create, link and
rename. Should no record have room for another extent, the writer gathers the
table's final extents into one extent.

The write path avoids device work that buys nothing. Preallocated clusters and
append windows lie past a stream's initialized size, where every reader returns
zero, so they are not zeroed on disk; bytes a write publishes are durable
before the commit that publishes them. Appends to a file of at least 64 KiB
allocate a window that grows with the file up to 2 MiB; a smaller file gets
exactly its clusters. A plain preallocation runs in 64 MiB steps and releases
the volume lock between them. Timestamps written back for an inode join the
pending journal batch; the caller that needs them durable (sync, fsync,
commit_metadata) supplies the barrier, so sync(2) costs one flush sequence and
not one per dirty inode. A write to a file with an empty page cache skips the
write-back, unmap and invalidation walks. Writable admission and the orphan
scan read the journal, the file table and its bitmap in 64 KiB spans through
`Volume::scan_mft_records`, and blank file-record slots are formatted 256 at a
time under one flush. The allocation cursor makes the next search start where
the previous allocation ended, which serves as the free-space cache.

An idle writable session parks. When a drain tick sees no journaled change
since the previous tick, nothing pending, no file open for writing and no queued
reclaim, the writer runs its unmount sequence: checkpoint, clean volume flag,
clean restart pages. An unplugged idle volume therefore needs no recovery. The
kernel adapter resumes the session, with the mount sequence that marks the
volume dirty again, before any operation that may change it. Background
writeback of an access time alone does not wake a parked session. Volume flags:
a completed full check clears the check requests 0x0020, 0x0100, 0x0200 and
0x4000 with the dirty bit; 0x0080 and the informational 0x8000 are preserved
and allow writes; 0x0004, 0x0008 and unknown bits are refused. The work
requests 0x0002 and 0x0010 block writes until `ntfs-chkdsk --repair` answers
them. For 0x0010 the structural repair retires the change journal's records
and zeroes every file's journal sequence number; the directory and allocation
phases then drop its `$Extend` entry and free its clusters. For 0x0002 the
journal keeps its size when that lies between 2 MiB and 4 GiB and the stream is
contiguous, as Windows' checker leaves it; otherwise it is rebuilt at the
default size.

One structural repair plan replays pending journal transactions first, so every
later phase sees the volume as a Windows mount would leave it. `offline_check`
sequences the steps for both `ntfs-chkdsk --repair` and `fsck.ntfsrs`; it
holds `/run/slate-ntfs/offline-MAJOR:MINOR.lock` for its whole run and the mount
helper takes the same lock, so an automounter cannot claim the device between
two repair steps.

`filename_metadata::duplicated_information` encodes the cached metadata shared
by each file's filename attributes and its parents' directory entries.
`Tx::refresh_file_names` updates both copies inside the content transaction,
before family packing and journal publication. The index editor checks the
file reference and changes the payload without changing collation or child
pointers. It synchronizes resident roots as well as external index blocks.
The offline checker uses this same encoding for ordinary files; reserved
metafiles can retain stale filename summaries when their internal streams grow.

`MetadataTx::commit_now` reserves space for loser-transaction compensation
records and a recovery checkpoint before admitting a journal transaction.
Recovery treats raw bitmap sectors separately from pages with an LSN. A later
durable sector is accepted only when all its bytes, stream identity, offset
and checked physical mapping match a later validated journal image. Replay
reconstructs it in a private plan and retains the original disk preimage for
publication; unrelated or unlogged changes still fail preimage validation.

A record that runs past the end of the journal file ends in the first record
pages, in the next sequence generation; the position after it belongs to that
generation too. One journal write can log a base record before the new
extension record its attribute list names, with an update located through that
extension in between: replay therefore notes every extension record the redo
schedule initializes and may locate an update through such a later image. A
location found this way is still checked against the clusters the update
logged.

`writer:lifecycle` checks fragmented copying, complete reads after checkpoint
and restart, sparse-hole reads and subsequent writes. The tools' writer crash
suite interrupts a split-stream append at every I/O boundary and checks real
recovery with omitted, reordered and torn writes. These checks exercise the
shared engine; a matching installed module and mounted file-manager test are
also required before claiming the complete desktop path is validated.

`kernel/core_fingerprint.sh` generates a header containing a stable digest of
the Rust core and kernel adapter. The C bridge includes this tracked Kbuild
dependency, so `srcversion` changes for Rust-only fixes as well as C edits.
Without it, package and mount helpers can mistake an old loaded Rust writer
for the installed replacement. The digest is also exposed through the module's
`slate_core_hash` metadata. Active mounts still prevent automatic replacement;
a clean unmount or reboot activates the new driver.
The loaded module exposes that compiled digest through the read-only
`/sys/module/slate_ntfs/parameters/core_hash` attribute, which has no setter.
Mounted validation checks it before creating temporary files.

Offline recovery now resolves split MFT mappings, combines complementary mirror sectors with matching generation evidence, reconciles missing/omitted family members and allocates external attribute lists. Directory rebuilding can allocate index storage and MFT extension slots, including external I30 families. Physical extent relocation preserves sparse holes and compressed/encrypted bytes. Native replay handles fragmented log-page publication, partial index values and longer histories; unknown operations, unresolved damage and incompatible geometry remain refused. These additions have Ubuntu 22.04 compile/link checks only; the combined crash and Windows matrix is pending.

## Directory structure

Recovery has two production files. `recovery.rs` groups related planners in
private namespaces and owns reusable types: `RecordStore` and
`RecordDescriptor` for scratch payloads, `ReplayPlan` and `RepairPlan` for
proposed edits, `RepairStorage` for named backing files, `PlannedImage` for
source-first overlays, and `ReplayState` for page LSNs or raw-sector evidence.
Family publication shares `RepairFamily`, `RepairSpace` and `StreamChange`.
`recovery_io.rs` coordinates these planners with admission, external journals
and durable writes. The public `recovery_io` and `recovery_journal` paths stay
compatible; journal selection is reexported from the shared owner. Planner
regression fixtures and test-only helpers live in `src/tests/recovery/`.
`bash test.sh recovery:unit --list` lists selective unit suites; a named domain
and optional test-name filter select only that scope. Modules reference external
test files and contain no embedded test implementations.

The log-size commands share the `log_resize` planner in `recovery.rs` for geometry, retained
extent planning, byte initialization and ownership audits. Copy resizing
publishes a validated new image without replacing a destination. In-place
resizing uses `recovery_io.rs` to claim an offline Linux device and persist an
external preimage/redo journal before writes. It clears the mirror dirty flag
before the primary flag, after validating the proposed clean result. Resize
journals record the requested size and use a distinct format identifier, so a
generic repair resume cannot consume a resize journal.

`test_log_resize.py` independently checks complete disposable layouts.
`log_resize_journal.rs` exercises the journal engine on disposable file
descriptors; the public command still requires an exclusive block-device
claim. Descriptor tests do not establish block-device claim behavior or
physical power-loss behavior. Focused Windows checks of grown and shrunk
images pass; broader Windows-created metadata compatibility remains open.

`checker.rs` resolves balanced or high resource budgets per frozen online
snapshot from available memory and ancestor cgroup limits. Unreadable cgroup
pressure data disables optional caches; missing host memory information uses
conservative fallback limits. Read-ahead grows only for consecutive reads and
is subtracted from the working budget; zero cache budgets use streaming.
Read-ahead belongs to a single frozen snapshot and is discarded before any
mounted repair or thaw. The selected budget reaches full-index cache partitioning
separately from AuditOptions; it changes execution resources, not checking
coverage or the policy stored in a repair queue. Text and JSON report the budgets.
Balanced scans may override the working percentage with 1–100 or select a
calling-thread best-effort I/O priority. The high profile bypasses those
balanced overrides. The priority guard saves and restores the exact inherited
class and level; a real-time setting must be restorable before it is replaced.
Successful scans confirm restoration before queue publication. These resource
options stay separate from repair authorization and the stored index policy.

Frozen repair preflight receives the same component budget. Its primary
RepairPlan uses bounded 128KiB pending-payload views backed by the existing
scratch file; nested plans keep uncached payloads. Updates replace cached bytes
coherently, and eviction writes the complete valid view before removal. A failed
spill retains the pending view and aborts preflight. Read and write-view limits
are deducted before every full-index audit in that plan. The write-view override
accepts 1280KiB..128MiB in either resource profile and is bounded by headroom;
unknown host memory disables these optional views. Cache settings and counters
remain separate from durable queue policy and device publication. Completed
preflights report measured payload allocation, hits and spills; a blocked
preflight reports those measurements as unavailable.

`consistency.rs` checks structural indexes before passing validated entries to
`consistency_index.rs`. The latter spools entries by target reference, performs
full validation with bounded cache partitions, or reconciles reduced-mode counts
and fully rechecks depleted targets. It supplies validated graph edges and bounded
repair-directory marks; consistency owns cycle and reachability decisions.
Cached FILE_NAME and directory-key metadata can legitimately differ from live
file metadata. Freshness reporting does not set repair-directory marks, and
per-file repair preserves valid caches. Directory reconstruction compares
parent, full target generation, namespace and exact name while retaining the
ordinary index framing and ordering checks. The planner still runs its repair
phases and validates their projected result; it has no clean-audit shortcut.
Recovery retains unmarked reduced-mode directories without reconstructing their
entries. A selected-mode repair journal records the checking policy separately
from the existing default repair format; resume checks that policy before writes.

`index_check.rs` tests count reconciliation, fallback and cache equivalence;
`test_index_check.py` checks eight independently mutated disposable images and
sixteen repaired copies, plus a malformed file-parent diagnostic.
`index_repair_journal.rs` compares all nine synthetic-fixture and twenty-one
Windows-created-fixture interrupted resumes with the exact copy-repair result.
These descriptor tests do not establish
public block-device claim behavior or physical power-loss behavior.

`tools/semantic_duplication_tools/` contains development-only similarity search.
It uses the supplied CodeGraph library to extract functions, types and call
evidence, then ranks related symbols and proposes groups for manual refactoring.
The offline LSA backend and optional local embedding models are separate from
the filesystem runtime. Usage and selective tests are documented in its README.txt.

Each file in the main source tree is listed below. `src/format.rs` exposes only the on-disk, engine, and operation modules to the kernel. The tools crate depends on that core; the core does not depend on the tools.

~~~text
src/
├── format.rs                   Core module map and shared error/result types
├── lib.rs                      Public no_std library root
├── crypto/
│   ├── aes.rs                  Portable constant-time bitsliced AES and key schedule
│   ├── aesni.rs                Userspace AES-NI blocks for offline operations
│   ├── ccm.rs                  Authenticated VMK/FVEK unwrap
│   ├── sector.rs               XTS/CBC/Elephant sector transforms
│   └── sha256.rs               Password/recovery protector stretching
├── ondisk/
│   ├── attrlist.rs             Parse attribute lists and extension-record references
│   ├── bitlocker.rs            FVE headers, protectors, unlock and logical sector view
│   ├── boot.rs                 Parse boot sector and validate volume geometry
│   ├── bytes.rs                Checked endian readers/writers and byte-range helpers
│   ├── hibernation.rs          Classify hiberfil.sys header state
│   ├── index.rs                Parse NTFS index roots, blocks, and entries
│   ├── logfile.rs              Parse and encode $LogFile restart/record pages and fixups
│   ├── mft.rs                  Parse MFT records and attributes; apply fixups
│   ├── reparse.rs              Read/build resident or nonresident symlink and junction reparse data
│   ├── runlist.rs              Decode nonresident mapping pairs
│   ├── security.rs             Parse self-relative security descriptors, ACLs, and ACEs
│   ├── security_store.rs       Resolve descriptors in $Secure and its indexes
│   ├── std_info.rs             Handle $STANDARD_INFORMATION times and attributes
│   ├── upcase.rs               NTFS case folding and name comparison table
│   ├── volume.rs               Resolve attribute families and read MFT, streams and directory indexes
│   └── volume_info.rs          Parse $Volume version and dirty flags
├── engine/
│   ├── allocation.rs           Checked cluster and MFT bitmap reservations
│   ├── batch.rs                Bounded pending/committed image arenas and freed-range quarantine
│   ├── journal.rs              Circular log slot and LSN reservations
│   ├── metadata_tx.rs          Log commit, metadata publication, and checkpoint ordering
│   ├── namespace_family.rs     Preserve DATA continuations during namespace edits and bounded cleanup
│   ├── mft_growth.rs           Grow $MFT data and bitmap through transactions
│   ├── record_edit.rs          Edit/merge logical attributes and sparse mapping pairs
│   ├── replay.rs               Shared log-window and metadata replay primitives
│   ├── resident_writer.rs      Writer session, journal initialization, and clean finish
│   ├── stream_writer.rs        Writes, append windows, resizing and sparse fallocate ranges
│   ├── tx.rs                   Assemble/pack record families and stage multi-structure transactions
│   └── write_plan.rs           Validate physical spans for nonresident reads/writes
├── ops/
│   ├── ea.rs                   Native NTFS extended attributes and Linux xattrs
│   ├── file_lifecycle.rs       Create, link, unlink, and reclaim namespace objects
│   ├── filename_metadata.rs    FILE_NAME views, layout and transactional cache updates
│   ├── identity.rs             Explicit Linux UID/GID to Windows SID mapping
│   ├── index_tree.rs           Transactional $I30, $SII, and $SDH B-tree edits
│   ├── linux_names.rs          Reversible Linux byte names and NTFS UTF-16 names
│   ├── namespace_writer.rs     Journaled rename and move operations
│   ├── security_create.rs      Inherit native descriptors for new objects
│   ├── security_writer.rs      Journal descriptor changes and $Secure index updates
│   └── unix_metadata.rs        Linux mode and metadata in NTFS EAs
├── tools/                      Separate slate-ntfs-tools Cargo crate
│   ├── Cargo.toml              Package targets and dependency on the shared core
│   ├── Cargo.lock              Reproducible tools dependency resolution
│   ├── lib.rs                  Exports the offline tool modules to its binaries
│   ├── linux.rs                Linux ioctl numbers, device size and mount identity helpers
│   ├── bitlocker_cli.rs        Secret input, protector unlock and FVE geometry
│   ├── checker.rs              Device checks/JSON reports; freeze supervision; typed repair requests
│   ├── consistency.rs          Disk-backed MFT, ownership, directory and security audits
│   ├── consistency_index.rs    Full/reduced entry checks, bounded caches and suspect fallback
│   ├── delete_plan.rs          Read-only hiberfil.sys deletion preflight
│   ├── metadata_lab.rs         Run kernel metadata writer on disposable image copies
│   ├── metadata_replay.rs      Checked metadata redo/undo operations
│   ├── offline_check.rs        One-command check and repair sequence shared by ntfs-chkdsk and fsck
│   ├── progress_display.rs     Progress bar and plain progress lines for backend steps
│   ├── recovery.rs             Shared recovery models, replay and metadata planners
│   ├── recovery_io.rs          Recovery orchestration, durable resume, sector rescue and publication
│   ├── write_io.rs             Create journaled writes on disposable image copies
│   ├── slate-flags.py          Snapshot, restore and prune identity-bound Linux flags
│   └── bin/
│       ├── ntfs-bitlocker.rs   Inspect metadata and verify BitLocker protectors
│       ├── fsck_ntfsrs.rs      fsck options and repair prompt over offline_check
│       ├── ntfs-checkfs.rs     Lightweight check/status command
│       ├── ntfs-chkdsk.rs      Check, offline repair/replay, online audit and typed repair CLI
│       ├── ntfs-hiber-discard-lab.rs  Copy-only hiberfil deletion experiment
│       ├── ntfs-inspect.rs     Read-only volume and file inspection CLI
│       └── ntfs-write-lab.rs   Disposable-image data and metadata write CLI
└── tests/                      Core and tools integration-test sources
    ├── bitlocker/test_image.py Independent disposable clear-key unlock fixture
    ├── core/                   Core unit tests (replay, runlist, attrlist, allocation, ...)
    ├── checker/
    │   ├── consistency_tests.rs  Consistency audit and inventory unit tests
    │   ├── scan_resources.rs     Online scan budget selection
    │   ├── log_size_arguments.rs ntfs-chkdsk log-size argument parsing
    │   ├── in_place_recovery.rs    Exclusive claims and durable repair/recovery publication checks
    │   ├── index_check.rs         Reduced entry, fallback, cache and bounds checks
    │   ├── index_repair_journal.rs Checking policy binding and interrupted-resume checks
    │   ├── test_index_check.py    Independent damaged-index checking and copy repairs
    │   ├── test_filename_cache.py Cache preservation, empty plans and allocation repair
    │   ├── test_readonly_assessment.py Immutable whole-volume assessment comparisons
    │   ├── test_fsck.py         Read-only policy, dirty recovery and repair admission controls
    │   ├── log_resize_journal.rs    Durable resize and existing-journal resume checks
    │   ├── test_log_resize.py       Log layouts, ownership and interruption checks
    │   ├── test_repair_expansion.py  Rescue/$Secure publication and repair interruption matrix
    │   └── verify_repair_interop.sh  Read-only ntfs-3g staged-image checks
    └── writer/
        ├── lifecycle.rs        Real writer lifecycle and I/O-failure checks
        └── crash.rs            Loss, reordering, tearing, wrap, and protected-span checks

kernel/
├── freestanding.rs             no_std kernel static-library root
├── ntfs_parser.rs              Read-side Rust/C ABI and shared core inclusion
├── writer.rs                   Write-side Rust/C ABI and persistent Writer session
├── vfs_bridge.c                Linux VFS callbacks and block-layer I/O
├── Makefile                    Kbuild module assembly and kernel API probes
├── patches/
│   └── wsl-6.18-cross-view-fanotify.patch  Mount snapshots and projected fanotify paths
├── rust/                       Freestanding Rust crate manifest
└── tests/                      Kernel adapter, mount, and crash test sources
    ├── root_boot_init           Minimal Linux init stored on a reusable NTFS root image
    ├── test_root_boot.sh        Two QEMU boots through Ubuntu initramfs, with clean shutdown checks
    ├── test_ubuntu_root_boot.sh Two boots of a retained Ubuntu systemd root image
    ├── power_boot_guest         Root-write probe across suspend and hibernation
    ├── power_boot_guest.service Start the power probe after local filesystems mount
    ├── test_power_boot.py       Reuse Ubuntu root and swap images for S3 and hibernation checks
    ├── test_kernel_vfs.py      Disposable mounted VFS, extension, mmap and view checks
    ├── test_permission_callback.py  Real C access-probe regression without root
    ├── test_desktop_permissions.py  Live GIO capabilities and permission remounts
    ├── test_file_deletion.py      Live GIO Trash and permanent deletion on private images
    ├── test_kernel_shutdown.py Full-sync shutdown and post-shutdown error checks
    └── test_kernel_preallocation.py  Last-close append-window reclamation check

boot/
├── install-initramfs.sh         Install the matching module and rebuild Ubuntu initramfs
├── systemd/system-shutdown/ntfsrs  Remount NTFS root read-only late in shutdown
└── initramfs-tools/
    ├── hooks/ntfsrs             Copy slate_ntfs into the boot initramfs
    └── scripts/local-top/ntfsrs Load slate_ntfs before mounting an NTFS root

ntfs_utils/
├── src/
│   ├── admin.rs                Explicit privileged administration operations
│   ├── application.rs          Per-application namespace views
│   ├── ffi.rs                  C ABI for read-only device snapshots
│   ├── format_backend.rs       NTFS 3.1 image creation and validation
│   ├── format_tables.rs        NTFS case-mapping tables
│   ├── lib.rs                  Userspace library root and device information
│   ├── mount.rs                Explicit mount policy and invocation
│   └── bin/                    ntfs-format, ntfs-mount, ntfs-permissions, ntfs-run
└── python/                     Python bindings for the userspace library

permissions/rust/               GTK permissions manager and privileged policy backend
└── src/
    ├── lib.rs                  Shared policy/UI library module root
    ├── core.rs                 Policies, accounts, SID maps and save/apply workflow
    ├── mount.rs                Live mount inspection, safe remount and verification
    ├── label.rs                Journaled volume-label updates
    ├── i18n.rs                 Language selection, translation lookup and private catalogs
    └── bin/
        ├── slate-ntfs-policy.rs Administrator backend and mount-option CLI
        └── slate-ntfs-permissions/
            ├── main.rs         GTK application entry point
            ├── model.rs        Saved selections, pending edits and live mount state
            ├── window.rs       Permission controls, mount warnings and retry action
            ├── session.rs      Authenticated administrator-helper session
            └── icons.rs        Interface icon and avatar loading

tests/                         Integration support, Windows cases, and saved results
└── windows/verify_repair_interop.ps1  Read-only staged-VHD and native CHKDSK checks
examples/                      Benchmarks and example drivers
~~~

`build.sh` builds the core, tools, and userspace library, plus the kernel module when `KDIR` is set. Tool binaries remain under the repository's `target/release/` for existing scripts.
