<!--
Module: documentation.recovery_transactions
Purpose: Document Recovery and transaction work.
Created: 2026-10-02
Architecture: Describes recovery-tool transaction boundaries; the shared journal and writer own
publication ordering.
-->

# Recovery and transaction work

## Implemented diagnostic boundary

`ntfs-chkdsk --recovery-status IMAGE` opens the image read-only and reports
`log_state`, `hibernation_file_present`, `hibernation_state`, and `dirty`. `--status` retains its
single `dirty=0` or `dirty=1` output for callers that only need the flag.

The Rust core checks `$LogFile` restart-page geometry, update-sequence fixups,
restart-area bounds, client indexes, log size, and redundant copies. It selects
the copy with the newer current LSN to distinguish a restart area with active
clients from one with no active clients. An all-`0xFF` result requires reading
the entire stream. Invalid, mismatched, or unsupported pages report
`needs-review`. The checker reads the first 4096 bytes of `hiberfil.sys` when
present. `HIBR`/`hibr` reports `active-image`, `RSTR` reports
`interrupted-resume`, `WAKE`/`wake` reports `invalidated-image`, and an
entirely zero first page reports `zeroed-header`. Anything else or an unreadable
page reports `unknown`. The reported signature is diagnostic: a real write
gate still blocks every present file until Windows 10/11 shutdown and Fast
Startup round trips establish when an invalidated or zeroed page is safe.

None of these states authorize a write. In particular, `no-active-clients`
does not prove that every log record, checkpoint, MFT LSN, or volume bitmap is
consistent. A dirty volume still requires verified replay and a full checker.

The format core validates `RCRD` page fixups, the active NTFS client record,
LFS headers, NTFS redo/undo bounds, checkpoint headers, and restart-table
entries and free chains. The read-only checker can reconstruct one bounded
record across consecutive pages and follow checkpoint table LSNs. The
`--replay-plan` command reports the restart record and the referenced
open-attribute, attribute-name, dirty-page, and transaction table records.
It reports `replay_ready=0` because this general inventory does not authorize
replay. A separate bounded replay path is described below. `--log-inventory` still
counts only records wholly contained in single-page transfers; its count is
not a count of all valid records in the log.

On the disposable hibernated Windows 11 image, `--replay-plan` validated a
16-page transfer's restart record and all three referenced checkpoint table
records (one spanning three pages). The resumed and fully shut down image had
an empty checkpoint table set. Both images retained an active NTFS client;
that observation alone does not prove replay is required. Neither image was
modified by this diagnostic.
The in-memory checked-patch primitive accepts only an exact preimage or an
already-applied postimage; a torn target is rejected unchanged. Tests cover
those outcomes; the copy-only native replay path now uses this primitive.

## Executable native replay and checkpoint publication

`ntfs-chkdsk --replay-to SOURCE NEW_IMAGE` now writes NTFS metadata in a
new disposable image. It validates the complete supported active circular
window, exact LSN generations, client identity, record boundaries,
transaction chains, MFT target opens, live extent mappings, allocation bits,
attribute boundaries and exact data preimages before creating an output.
It repeats the plan on the copied image before the first metadata write.

The initial subset supports LFS 1.1 with 4 KiB log pages and 512-byte sectors,
unused tail slots, an empty NTFS v1 checkpoint, and non-spanning records.
Open-target, same-length resident-data update and commit are the supported
operations. Each target MFT record may appear once. Committed transactions
receive redo bytes; unfinished transactions receive undo bytes. Security
attributes, security IDs, timestamps, names and unrelated bytes remain
unchanged. This restricted independent-target model makes interrupted undo
repeatable without publishing compensation records; arbitrary histories
require CLRs and remain unsupported.

Publication order is executable:

1. Copy the already-dirty source and flush the copy.
2. Apply each validated MFT patch with renewed USA protection, flush, read back.
3. Append an empty NTFS checkpoint record in an unused active-window page;
   flush and read back. Advance the LSN generation on circular wrap.
4. Advance the secondary restart page to this checkpoint; flush and read back.
5. Advance the primary restart page; flush and read back.
6. Reopen the recovery plan and require no remaining updates or publication.

If interrupted before step 4, the old history remains authoritative and all
supported patches are repeatable. After step 4, the newer empty checkpoint
is authoritative and the older restart copy can be repaired. A single torn
restart page can be recovered using the other valid page. A torn metadata
record or invalid published checkpoint is refused. A completed repeat is
byte-identical. The active client remains registered; the diagnostic label
`replay-required` alone does not mean that the new empty checkpoint has
outstanding operations.

The volume dirty flag is preserved. A replay checkpoint does not establish
that allocation, directory, security or other metadata is globally sound.
No clean-unmount claim or writable kernel mount is enabled by this command.
The captured Windows 11 log's grouped transfers/nonempty checkpoint tables
are still outside this executable subset.

`src/tests/recovery/test_native_replay.py` independently encodes native LFS records into
fresh mkfs.ntfs images. It tests redo, undo, circular wrap, all six flush
boundaries, torn checkpoint/restart pages, idempotence, source immutability,
permission-metadata preservation, and refusal of bad target mappings,
chains, clients, generations and fixups. NTFS-3G independently reads the
resulting file contents. Windows recovery compatibility for transactions
created by the new writer failed validation; see the outcome below.

The restart area's current LSN is not assumed to be the discovered log end.
Complete single-page appends immediately beyond that LSN can be discovered
and validated, including a durable commit before restart publication. Unknown
or ambiguous pages still cause refusal. General tail/group discovery remains
necessary for Windows histories. Output creation also
flushes its parent directory before any metadata patches are applied.

## Required recovery sequence

1. Validate both restart areas and select the newest valid state under NTFS
   LSN rules. Support torn-copy recovery without treating an unknown state as
   clean.
2. Walk and validate all record pages in the current circular LSN window,
   including tail copies and wrapped or torn transfers. The implemented
   exact-LSN checkpoint checks are only part of this step.
3. Build a **read-only replay plan** containing redo and undo operations with
   target checks. Refuse unknown operations and unsupported layouts.
4. On a disposable image, apply the plan through a journal-aware writer,
   validate the result with `ntfs-chkdsk`, and compare with Windows `chkdsk`.
   Never clear the dirty flag merely because our implemented subset passes.
5. Validate the signature classification against disposable Windows 10/11
   full-shutdown, Fast Startup, hibernate, and resume images. Until then,
   presence blocks a future write mount.

## Metadata transaction contract

`src/metadata_tx.rs` implements the live writer's metadata persistence order:

1. Mark the volume dirty and flush it.
2. Append NTFS-compatible redo/undo intent and flush `$LogFile`.
3. Persist new-cluster data that metadata will expose.
4. Append and flush the commit record.
5. Apply and flush metadata pages.
6. Write and flush a checkpoint.

If a failure occurs before step 4 begins, the operation is not committed. A
failure while writing or flushing the commit record has an **uncertain**
outcome and requires log inspection. After step 4 succeeds, failures require
redo or completion during replay.
The volume stays dirty until clean unmount has drained all pending metadata.
`writer:lifecycle` injects failures into the real writer at write and flush
boundaries and checks that a failed drain poisons the session.

The generic transaction contract remains a **harness**: there is no on-disk
`TransactionIo` implementation, complete NTFS log writer or general replay engine, metadata
page pinning, durable block barrier integration, or `fsync` implementation.
The format core encodes an isolated operation payload, LFS header, and
single-record `RCRD` page with fixups. Round-trip and torn-page tests pass.
The separate copy-only recovery path now allocates a checkpoint LSN and
updates restart areas for its bounded subset. Windows 11 compatibility is
validated for the copy-only same-length resident overwrite described below;
general new-transaction compatibility remains unestablished.
The kernel now exposes experimental journaled resident overwrites through
VFS; see `ARCHITECTURE.md` and `WRITE_SUPPORT.md`. Nonresident
in-place user-data writes need their own
durability semantics; the metadata contract does not make them atomic.

`src/tests/writer/lifecycle.rs` now injects write and flush failures into the
real writer on disposable NTFS images. It checks that a failed drain leaves the
session poisoned. The abstract sidecar ordering model has been removed.

The first real NTFS write experiment uses `ntfs-write-lab` to copy a clean,
unhibernated disposable image and overwrite existing initialized file data
without changing allocation or metadata. The test confirms the original
hash is unchanged, only 16 bytes differ in the copy, NTFS-3G reads the new
content, `ntfs-chkdsk --check` passes its current subset, and wrong-preimage
and dirty-image attempts are refused. This does not complete recovery step 4:
metadata replay, native NTFS journaling, Windows `chkdsk` comparison, and
power-cut testing remain required.

For the Windows 11 comparison, `tests/windows/prepare_vhd_case.sh` builds a
candidate fixed VHD from a disposable copied NTFS image. The elevated
`run_readonly_chkdsk_vhd.ps1` script attaches it read-only, runs `chkdsk`
without repair switches, records the result, and detaches it. A non-elevated
mount attempt was rejected by Windows for missing privilege. There is no
Windows host-attached `chkdsk` outcome from that script. Subsequently, an
isolated QEMU Windows 11 guest provided hibernation/resume fixtures and
native-writer tests using disposable raw MBR data disks. The original writer
omitted LFS absent-buffer flags, causing Windows to retain `AAAA` instead of
replaying committed `A111` and report corruption events. Read-only chkdsk
alone did not detect that failed recovery. After emitting flags 4 for the open
record and 6 for the empty-buffer commit, fresh Windows 11 build 22000 tests
passed the control, all 11 interrupted durability boundaries and completion.
Contents, chkdsk results and current-boot NTFS events were checked against
unique run IDs and disk signatures. Read-only NTFS-3G readback after shutdown
also passed. Reproduction and captured results are in
`tests/windows/NATIVE_RECOVERY.md` and `NATIVE_RECOVERY_RESULTS.md`.
General log recovery and allocation-changing writes remain unfinished.
The kernel's bounded resident writer now uses native write authorization and
VFS write_iter/fsync, with explicit experimental loop-device opt-in.

Format references: upstream Linux
[ntfs3 log implementation](https://github.com/torvalds/linux/blob/master/fs/ntfs3/fslog.c),
[NTFS structures](https://github.com/torvalds/linux/blob/master/fs/ntfs3/ntfs.h),
and [NTFS-3G's hibernation guidance](https://github.com/tuxera/ntfs-3g/wiki/NTFS-3G-FAQ).
The header classifier is based on the upstream
[NTFS-3G check](https://github.com/tuxera/ntfs-3g/blob/edge/libntfs-3g/volume.c),
[libhibr's format research](https://github.com/libyal/libhibr/blob/main/documentation/Windows%20Hibernation%20File%20(hiberfil.sys)%20format.asciidoc),
and [Microsoft's Fast Startup description](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/distinguishing-fast-startup-from-wake-from-hibernation).

## Repair coordination, disk-backed audit and sector rescue update

Implementation only; Ubuntu 22.04 compilation is the validation gate for this
update. No new image, crash, Windows or mounted-filesystem tests were run.

- Exclusive in-place repair streams and authenticates its external journal
  before writing. It revalidates every recorded range while retaining the
  device claim, then revalidates each range immediately before publication.
  New journals split data payloads into at most 64 KiB redo units. Each changed
  unit is flushed before advancing; resume accepts only original/final bytes
  and skips units already at their final image. Dirty guards remain until the
  complete post-repair audit. Journal integrity, device/volume identity and
  guard validation precede all writes. The former 256 MiB journal and 131072
  entry replay limits are removed; journal replay memory does not grow with
  journal length. Structural planning also spills to disk as described below. This does not
  change the NTFS log format or make intermediate states mountable.
- The read-only audit externally sorts ownership extents and security-ID
  inventories. MFT record/name storage, directory links, reachability queue,
  visited bitmap and merged allocation ranges use private temporary files.
  MFT allocation bits are read in 8 KiB windows. The former 8M-slot, 1M-record,
  4M-extent and 4M-directory-entry audit ceilings are removed. The sorter uses
  65536-row runs and pairwise merge levels; storage exhaustion is an error,
  never a clean result. Cross-link planning also uses external ownership
  sorting and checks allocation candidates against that complete inventory.
  Duplicate directory keys are caught by the existing strict collation check
  rather than a second in-memory name set; their diagnostic is
  `directory-index-order`. An unavailable UpCase table still prevents a complete
  audit. Use an external disk-backed TMPDIR; online audit refuses TMPDIR on the
  frozen filesystem. A tmpfs TMPDIR still consumes RAM.
- `--rescue-to SOURCE EXTERNAL_ARCHIVE` and `--resume-rescue SOURCE ARCHIVE`
  preserve readable ranges from an offline image or exclusively claimed block
  device. Bulk read failures fall back to the device logical sector size.
  Successful records retain source offsets, bytes and CRC64; EIO records retain
  offsets and lengths without invented data. Every appended record is flushed.
  Resume verifies checksums and identity, compares still-readable saved sectors
  with the source under its claim, rebuilds a disk-backed coverage bitmap, and
  retries unresolved ranges. Only an incomplete trailing append may be removed;
  checksum conflicts are retained and refused. The source must remain quiescent
  between attempts. The archive is external evidence, not an NTFS extension or
  a mountable image. Source bytes and NTFS allocation metadata are unchanged.
- Rescue is available through the existing asynchronous Rust/C/Python repair
  jobs (modes 3 and 4). Progress counts durably preserved 512-byte sectors; the
  denominator is the source size. Unresolved sectors produce CLI status 4 /
  API VerificationFailed and phase 14. Phase 13 means every sector has a saved
  copy, not that its NTFS structures are valid.

### Disk-backed structural planning

Reconstruction descriptors, original/final bytes and their sparse sector lookup
index now live in scratch files (`RepairPlan`). Successive edits preserve the
first preimage and require matching intermediate bytes; other overlaps fail.
Copy repair compares and applies the two plans by streaming. In-place repair
serializes the plan directly into its durable journal, with original/dirty flag
normalization, without building a second in-memory journal. Each redo unit is
at most 64 KiB. The complete operation remains dirty/guarded until the final
audit; those units are not independently mountable checkpoints.

Family catalogs and competing-owner claims are externally sorted; only one
validated attribute-list family is reconstructed in memory. Audit relationship
maps use sparse disk slots. Directory names sort externally using the existing
NTFS UpCase/collation function; directory reconstruction streams each index page
and successive parent levels to disk. Allocation candidates, cross-link work
queues and prior relocation reservations also live on disk. Allocation retains
the existing immediate overlap guard and checks the complete ownership and
reservation histories before accepting a candidate.

The old volume-wide 8M-slot, 64 MiB reconstruction/clone, 65536-family/candidate
and 1M-directory-page planning limits are removed. Existing per-object parser,
attribute-list and supported-layout limits remain; a single unsupported or
ambiguous dependency still prevents publication. Planning interrupted before
journal durability restarts without source changes; application interrupted
afterward resumes from the authenticated journal and persisted postimages.
This is exclusive offline coordination, not new live kernel transaction or
cache-repair support. Native-log replay retains separate geometry/snapshot bounds; the latest extensions are described below.

Complete rescue archives now extract to new images after verifying every
sector, checksum and conflicting duplicate. Reintegration first retries the
original source under its recorded identity; incomplete coverage still refuses
image publication. This restores physical bytes only. Missing `$Secure`
index roots, and present indexes that fail independent `$SDS` validation, are
rebuilt from all hash-valid `$SDS` entries, using index
allocation pages when their attributes fit the base record. The proposed
index is checked before publication; unsupported extension families refuse.
Raw native-log operations now stage only changed clusters. Whole-log discovery
uses a private file-backed mapping; validated pages retain offsets into it and
record payloads plus their index live in separate private scratch files.
Historical and active transaction rows, the undo priority queue, replay
schedules, target descriptors and preimages/edited images now use private
scratch files. Attribute-list replay no longer has a
1 MiB list cap; its list and duplicate-entry inventory are file backed.
Checkpoint dirty-page entries use scratch records, and dirty-cluster mappings
use a private exact-key scratch table. Log-page descriptors and occupied-page
sets, open-attribute bindings, and repeated log-write ordering are file backed.
Replay patch payloads and their physical lookup index are disk backed.
Individual native records and per-target extent lists are decoded in bounded
working memory. Supported histories use the general planner. The native
redo/undo and circular-wrap matrix passes on disposable images.

Readable DATA relocation away from existing BadClus reservations remains
available through the structural planner. Newly detected EIO is recorded in
the rescue archive. The separate `--repair-rescue-to` path retries unresolved
sectors, reserves recovered EIO clusters in standard `$BadClus:$Bad`, relocates
readable owners, reconciles allocation and audits before publishing a new
image. Validated existing `$BadClus` extension families can be rebuilt, with
mapping runs spooled to disk; critical unrelocatable owners and unreadable
bytes still refuse. Reconstruction of unreadable bytes remains open. The
rescue repair matrix passes on a disposable retained source image. No
unreadable range is reported as fixed.

### Additional deferred matrix

- Journal replay with more than 131072 entries and over 256 MiB; interrupt every
  chunk write/flush, guard, final audit and publication; foreign byte in the last
  range must prevent all writes. Retry a completed chunk, partial chunk, damaged
  header/checksum, device mismatch and concurrent resume.
- Audit beyond the previous slot/record/extent/entry limits; external-sort merge
  boundaries at 65535/65536/65537 rows and multiple levels; nested overlaps,
  sparse slot tables, duplicate links/IDs and disconnected directory islands.
  Inject scratch ENOSPC/read/write failures and compare findings with the prior
  auditor on supported small volumes. Online TMPDIR-on-target must refuse before
  freezing; interrupted audit must release scratch files and thaw.
- Structural planning beyond 8M slots, 65536 families/candidates, 64 MiB of
  edits/clones and 1M index pages; equal-range composition versus partial
  overlap; patch boundaries at 64 KiB; bitmap window boundaries; competing
  families and stale references. Rebuild directories at every root/page/level
  boundary and compare bytes/findings with the earlier builder. Inject failure
  in every scratch comparison/read/write and exhaust scratch storage before
  journal publication. Prove reservation checks include all previous clones,
  including those outside the allocator's immediate in-memory guard.
- Rescue EIO at first/last and interior sectors, both 512-byte and 4 KiB logical
  sectors; bulk failures with readable neighbors; previously good sectors that
  later fail; successful retry of a gap; changed readable source bytes; truncated
  append, complete checksum corruption, source/geometry mismatch and concurrent
  resume. Include single-sector sources/tails so a failed bulk read cannot be
  mistaken for successful sector data. Verify all saved bytes against source
  evidence and prove there is no payload for failed ranges. Inject ENOSPC and
  each archive fsync failure; never mutate source data or publish a clean image.

## Validation boundary

The initial missing-cluster-allocation-bit implementation passed 58 disposable-image cases in an isolated Ubuntu 22.04 VM: two formatter baselines, persisted subsets, partial-bit/sector persistence, flush interruption/resume, refusal cases and source preservation. The persistent-subset fixtures model repair outcomes independently; they are not physical power-loss tests.

After that run, the user requested implementation only. Boot/MFT redundancy repair, MFT allocation-bit restoration, FILE_NAME marker repair, free-cluster reclamation and dry-run planning were added with compile checks only. Their combined matrix and Windows differential checks remain pending. The updated source is not covered by the earlier 58-case result.

### Deferred combined matrix

- Every supported repair: both mkntfs and Windows baselines, no-op repeat, NTFS-3g readback and native Windows CHKDSK; preserve source hash and every readable stream hash.
- MFT header damage versus sector tears; disagreeing mirrors; missing bodies; sequence mismatch; base/extension families. Missing evidence must refuse rather than fabricate a record.
- Resident, one-level and multi-level directories; Unicode collation; promoted keys; exact-full pages; bitmap mismatch; missing names; invalid parents; DOS aliases; name collisions; inaccessible root; hibernation-name damage; unresolved cycles and nameless records.
- DATA/DATA and DATA/metadata overlaps, self-overlapping runs, partial overlap and nested ranges; ENOSPC; runlist growth failure; allocation bits incorrectly clear; original source bytes must survive both interpretations.
- SDS first-copy/second-copy corruption, valid-but-different descriptors and indexes, EA length/count damage versus invalid values, supported and unknown reparse payloads. No widening of permissions or loss of Linux security EAs.
- Supported dirty histories, multi-transaction redo/undo, deferred checkpoints and log wrap; unrecognized operations remain refused. Dirty flags must not be silently cleared.
- BadClus overlap with fully readable data and injected unreadable sectors. Unreadable bytes must never become successful zero-filled data.
- In-place crash points: partial external journal/header/checksum; journal fsync before parent-directory fsync; each primary/mirror dirty guard; every patch before/during/after write and flush; post-audit before each final flag word; completion hard-link creation and directory fsync; unlink of the working journal and final directory fsync. Resume with dropped, reordered and first-sector-only persistence; reject changed identity, truncation, checksum damage and foreign preimages.
- Mounted-device and competing-claim refusal; already-completed-journal recovery; raw-device geometry; preserved journal permissions and exact preimages.
- In-place preflight must detect a foreign byte in the last planned range before any device write; repeat with clean/dirty guard words and every partial-resume state.
- Mounted EA repair: valid/no-op, damaged counters, missing summary with/without base-record room, malformed/duplicate EAs, ATTRIBUTE_LIST refusal, stale sequence, read-only mounts/views, user-namespace privilege refusal and wrong-filesystem refusal. Race with EA/security-label changes, rename/unlink, ordinary writes, freeze and remount. Fail each journal write/flush; verify EA bytes, stream hashes, permissions and cached peer state remain unchanged. Check durability after remount and with native Windows CHKDSK.
- Online audit: normal success, audit error, freeze failure, checker SIGINT/SIGKILL, startup pipe failure and helper thaw failure; confirm writers resume. The separate helper must remain alive when the checking process exits. No online repair claim.
- Bitmap boundary bytes, trailing padding, huge allocated/free ranges, fragmented ownership and inventory/edit-limit refusal. No silent truncation at a limit.


## Offline recovery expansion — implementation, validation pending

- Native replay now publishes log pages spanning multiple physical runs as a
  single flush group. Redo/undo and checkpoint ordering are retained. General
  replay accepts 4 KiB-sector volumes with 4 KiB log pages, and partial index
  value updates preserve their remaining value bytes and child pointers.
  Discovery replaces the 65536-record and 256-page-group cutoffs with checked
  physical-log bounds. Missing records, surviving commits beyond gaps, unknown
  operations and in-doubt prepared transactions still refuse recovery.
- Offline MFT access assembles DATA/bitmap mappings through sequence-checked
  extension records. An extension is read only through an already verified
  prefix; circular/unreachable bootstrap dependencies are refused. The assembled
  record is a read-only scratch image, never an enlarged on-disk FILE record.
  Primary/mirror copies may be reconstructed from complementary intact sectors
  only when their generation, header and USA agree. Conflicting valid sectors
  and sectors missing from both copies are retained/refused. Derived framing
  and record-slot-number repairs preserve sequence numbers and attribute data.
- Family reconciliation discovers omitted members through validated back-
  references, reconstructs missing lists, and can spill growing resident or
  nonresident lists into standard NTFS allocation. Competing claims and missing
  non-derived attribute contents remain errors.
- Directory rebuilding can recreate a missing root, replace damaged allocation
  with new index storage, and rebuild external/split I30 attributes across a
  family. It can allocate a validated free MFT extension slot when required.
  It updates family lists and releases emptied index-only extension records.
  Filename-parent repair includes extension records. Original bytes remain in
  the input image or authenticated external repair journal.
- Cross-link cloning includes movable metadata and physical compressed, sparse
  and encrypted extents. Holes, VCN order, sizes and flags remain unchanged;
  stored bytes are copied without decompression/decryption. MFT bootstrap,
  MFTMirr, LogFile, Bitmap, Boot and BadClus ownership is not relocated blindly.
  Every allocation checks bitmap state, complete physical ownership and every
  prior repair reservation. Changed mirrored FILE records update both copies.

### Remaining boundaries

This is an expanded implementation, not complete native CHKDSK parity. Supported
relative index operations use the shared native replay planner; unknown layouts,
in-doubt prepared transactions and unrecoverable log gaps still stop replay.
The former 64 MiB LogFile snapshot bound is removed. Log publication still uses
supported 4 KiB/64-byte geometry. Targets, transaction state, descriptors and
page inventories use scratch files; individual records and decoded runlists
still use working memory.

Structural repair handles supported naming conflicts, cycles, nameless intact
objects and exhausted MFT allocation. Lost MFT attribute bodies, unreachable
bootstrap prefixes and shared primary/mirror sector loss remain unresolved.
Reserved system-file cross-links need independent reconstruction evidence.

Complete-family metadata checks include EA summaries, link counts, filename
sizes/timestamps/flags, reparse indexes, object IDs, quota controls/lookups and
USN configuration/history. Quota topology can be rebuilt from every intact
allocated node without discarding limits; missing default/owner policies and
conflicting controls remain unresolved. Both lost security descriptor copies
and missing per-file permissions remain unresolved. `$AttrDef` standard rows
are reconstructible with intact private definitions. `$UpCase` retains the
volume's Unicode mapping; only ASCII corrections are generated independently.

Fixed-size resident repairs preserve existing IDs and physical family ownership.
EA and nameless-file passes retain their MFT catalog instead of restarting the
whole scan for every changed file. Derived indexes and compacted SDS streams
can allocate fragmented storage and publish split mapping descriptors. Other
per-family working-memory and format bounds, and ENOSPC, still apply.

`--surface-check` reads all physical sectors and reports EIO ranges. Optional
`--rescan-bad --repair-to` clears old BadClus declarations only after a complete
source copy is readable. Rescue repair relocates supported recoverable ranges;
missing bytes are not reconstructed. `--security-cleanup --repair-to` compacts
unused shared descriptors without renumbering referenced IDs or changing ACLs.

Mounted repair remains limited to its supported allocation, EA and DATA
operations. General live semantic repair remains open. In-place structural
repair now replays pending journal transactions first (see
[One-command offline check](#one-command-offline-check)). CLI reporting still
uses Unix fsck status conventions. Runtime and Windows comparison testing of
this checkpoint are deferred. This checkpoint landed in source version 0.6.6.

### Interfaces

Existing CLI and Rust/C/Python checking, copy-repair, offline repair/resume and
progress interfaces retain their signatures and ABI layouts. `--capabilities`
now describes the additional paths and continues to report
`runtime_validated=false` and `full_chkdsk_replacement=false`.
Two existing core helpers are now public: `Volume::read_physical` retains its
volume-boundary checks, and `record_edit::merge_attribute` retains its checked
merge semantics. Offline split-MFT assembly uses them instead of duplicating
mapping/merge logic. Neither grants write authority.

### Deferred checks — run together

`bash test.sh checker:repair-expansion EXISTING_CLEAN_IMAGE --stage EMPTY_DIR`
is a separate disposable-image matrix, compiled but not run in this revision.
It copies the input, checks source hashes, captures/resumes/extracts rescue
archives, and removes `$SII`/`$SDH` roots on copies. It interrupts extraction
after: (1) two validation passes, (2) private file creation, (3) private
file sync, (4) final hard-link publication, and (5) parent-directory sync.
It also tries a short appended header and payload, a wrong checksum, a
conflicting duplicate sector, an EIO entry followed by resume, and every
copy-repair flush boundary after the durable copy and after each patch.
`--stage` produces repaired raw images and VHD copies. Run
`src/tests/checker/verify_repair_interop.sh` against the staged directory for
read-only ntfs-3g mounts, then
`tests/windows/verify_repair_interop.ps1` inside Windows for read-only VHD
mounts and native CHKDSK without `/f`. Both scripts verify hashes or attach
read-only; they are not substitutes for the broader power-loss matrix below.
With `--in-place` and root privileges, the same matrix uses a fresh loop copy
at each interruption point: external journal sync, each dirty guard and redo
sync, both finalizer syncs, completion journal sync, completed-name directory
sync, and journal unlink directory sync. It resumes from the authenticated
external journal and audits the detached loop image after each interruption.

Build-only this revision: no runtime tests, image creation, device writes,
mounts, module loads, Windows checks or benchmarks. Six new regression cases
are compiled but unexecuted (complementary mirrors, conflicting/missing sectors,
split-MFT reachability/stale references, partial index values and child bounds).

Run the existing native-replay and repair crash matrices, plus:

1. Native replay: both LFS versions; 512/4096-byte volume sectors; a log page
   crossing physical runs; more than 65536 records; circular wrap; partial
   root/allocation value redo and undo; stale references, mixed winners/losers,
   unsupported relative operations and in-doubt prepared transactions.
2. Fail before/during/after every compensation page fragment write and its
   flush; every target and mirror write/flush; checkpoint record write/flush;
   secondary restart write/flush; primary restart write/flush. Drop all pending
   writes, retain arbitrary subsets in reverse order, and tear after each first
   sector. A surviving commit beyond missing prerequisites must refuse.
3. MFT: split DATA and bitmap, multiple chained extensions, unreachable/cyclic
   bootstrap, stale sequence, bad first-offset/length/slot fields; complementary
   primary/mirror tears; conflicting valid sectors and shared sector loss.
4. Families: missing list, omitted member, stale/competing ownership, resident
   to nonresident list transition, external list growth, crowded base, and
   insufficient MFT slots. Preserve non-derived attributes byte-for-byte.
5. Directories: missing roots, external/split I30, exact-full/multi-level trees,
   Unicode/DOS aliases, extension-owned filenames, new/released extension
   bitmap bits sharing a byte, allocation bitmap falsely free, and ENOSPC.
6. Cross-links: data/metadata, metadata/metadata, compressed/sparse/EFS physical
   extents, self/nested overlaps, BadClus collisions, reserved system owners,
   runlist expansion and fragmented free space. Verify both surviving streams
   against their pre-repair bytes and check all new allocation ownership.
7. For every changed structural plan: interrupt external-journal creation and
   fsync, each dirty guard, each <=64 KiB write/flush, final audit, flag restore,
   and journal completion rename/link/fsync. Resume repeatedly and inject a
   foreign preimage. Re-run no-op repair and compare with native Windows CHKDSK
   and ntfs-3g using existing disposable images; preserve source hashes.

## One-command offline check

Version 0.6.8 adds `offline_check`, one sequence shared by
`ntfs-chkdsk --repair DEVICE` and `fsck.ntfsrs`. Each step runs as a child
`ntfs-chkdsk` process with `--progress` and is followed by a full check:

1. Resolve the device, take `/run/slate-ntfs/offline-MAJOR:MINOR.lock` for the
   whole run and refuse a mounted device. The mount helper takes the same lock,
   so an automounter cannot claim the device between two steps.
2. Report a volume clean without a scan when nothing asks for work: no check or
   work-request flag, no unsupported flag, no unreplayed or unreviewed journal,
   no hibernation gate and no pending external journal. `--force` scans anyway.
3. Without a pending journal, check first; a clean result ends the run.
4. Ask for consent once (`ntfs-chkdsk --repair` always consents), then resume a
   pending repair or replay a dirty Windows journal with `--recover-for-mount`.
   A replay that leaves a clean check ends the run.
5. Otherwise run `--repair-in-place` (or `--resume-repair`). The structural plan
   replays pending journal transactions before any repair phase, so later
   phases see the volume as a Windows mount would leave it.
6. Answer volume flag 0x0002 with an in-place journal resize, or resume an
   interrupted one. A contiguous journal between 2 MiB and 4 GiB keeps its
   size; anything else is rebuilt at the default size.

Exit status: 0 clean, 1 repaired after a passing check, 4 unresolved or
declined, 8 failed. Flag 0x0010 is answered inside structural repair: the
change journal's records are retired and every file's journal sequence number
is zeroed; the directory and allocation phases then drop its `$Extend` entry
and free its clusters.

Native replay now treats a transaction that finished before the checkpoint, or
a slot reused by a fresh chain, as committed intent: it is redone where pages
are still dirty and never undone. Records Windows starts exactly at
`next_record_offset` and spills into the next page are read through that
page's last LSN. MFT and index bitmap bits that Windows set ahead of a logged
extension are bounded by the logged transfer. A cleanly shut down journal is
treated as having nothing to apply.

When journal recovery for a mount is refused and nothing was resumed, the boot
sector, the complete `$LogFile` and the refusal text are saved next to the
replay journal with a `.refused` suffix, so the refusal can be reproduced
offline. Refusal errors name the recovery stage that produced them.

No runtime results for this sequence are recorded in this document. Run the native
replay and in-place repair crash matrices through `ntfs-chkdsk --repair` and
`fsck.ntfsrs -y`, including interruption between steps while a desktop
automounter is active.

Partial index-update behavior was checked against the upstream implementation:
https://github.com/torvalds/linux/blob/master/fs/ntfs3/fslog.c
