<!--
Module: documentation.ntfs_permissions
Purpose: Document NTFS permission design.
Created: 2026-10-02
Architecture: Documents the frontend, shared policy core and privileged backend; the kernel
retains authorization and write-admission decisions.
-->

# NTFS permission design

## Access policy (permissions=desktop | permissions=windows)

Access policy is a mount setting of its own, separate from `compatibility=`
(which only chooses NTFS or Linux presentation). It follows NTFS-3G's model:
mount-wide ownership and permission masks by default, strict Windows ACL
enforcement explicitly.

| Option | Meaning | Desktop default |
| --- | --- | --- |
| `permissions=desktop` | Linux permissions for the whole mount | used by the desktop helper |
| `permissions=windows` | Enforce stored Windows ACLs for the SID map | kernel default when absent |
| `uid=`, `gid=` | Owner and group of every file and folder | the user the drive is mounted for |
| `fmask=` | Bits removed from files (`umask=` sets both) | `0177` → files `0600` |
| `dmask=` | Bits removed from folders | `0077` → folders `0700` |

Share with a group: `gid=<group>,fmask=0117,dmask=0007` (files `0660`, folders `0770`).

In desktop mode the kernel checks the caller against the owner, the group or
"others" bits, with ordinary root privileges, exactly like a Linux file
system. It does not evaluate or change the Windows descriptors: they are kept
byte-exact on disk, and chmod/chown by the owner succeed without effect (NTFS-3G's
default `silent` behaviour). New files record the mount owner and group as their
Windows owner, so the SID map must contain them (the desktop helper ensures it).
Deletion is decided by write access to the parent folder. Read-only mounts, the
Windows read-only attribute and view restrictions still refuse writes, and
security-descriptor edits stay limited to root. `uid`, `gid` and the masks can
change on a live remount; the SID map cannot. `mount` output shows the active
policy.

The same controls are available everywhere:

- `ntfs-run --mount-volume DEV DIR --permissions=desktop [--uid U --gid G] [--file-mode 0660 --dir-mode 0770]`
  or `--permissions=windows --sidmap MAP`
- Rust `mount_fs_with_access(.., AccessPolicy::Desktop { uid, gid, file_mode, dir_mode })`,
  `AccessPolicy::private(uid, gid)`, `AccessPolicy::shared_group(uid, gid)`
- C `ntfs_utils_mount_with_access(.., permissions, uid, gid, file_mode, dir_mode, ..)`
- Python `mount_fs(.., permissions="desktop", uid=.., gid=.., file_mode=0o660, dir_mode=0o770)`
- Desktop configuration `/etc/slate-ntfs/permissions/<UUID>.conf`, edited by the
  **NTFS Permissions Manager** app. Its *Simple* mode shows these as Read / Write / Execute for
  Owner, Group and Everyone else (Read gives folders r+x, Write needs Read, Execute runs
  programs); its *Strict* mode sets per-person Windows levels.

NTFS stores owner and group SIDs, an ordered DACL, and an optional SACL in a
self-relative security descriptor. An absent DACL, a null DACL, and an empty
DACL have different access semantics. Deny and allow ACE order matters;
inheritance flags affect child objects. Linux mode bits cannot represent all
of this information.

## Implemented foundation

### Live mutation (integrated 2026-09-28)

`ntfsrs` exposes `system.ntfs_security` as a raw self-relative descriptor xattr.
Reading requires READ_CONTROL. DACL changes require WRITE_DAC, owner/group
changes require WRITE_OWNER, and a new owner must equal the caller's mapped SID.
Descriptor removal is refused. Chown preserves ACL bytes. Neither Linux root
nor Administrators receives an implicit privilege bypass. An explicit user SID-map
suffix (`:security+restore+take-ownership`) grants the corresponding descriptor
administration privileges. Security is required for SACL changes; restore allows
foreign owner assignment and bypasses WRITE_DAC/WRITE_OWNER for descriptor changes.
Take-ownership supplies WRITE_OWNER but still cannot assign a foreign owner.
Nonempty SACL access/auditing evaluation remains unsupported and fails closed.

With explicit `compatibility=linux`, ordinary Unix permissions are persisted in
native `$LXMOD` extended attributes. chmod leaves the native descriptor byte-exact;
Linux mode checks and native DACL checks both constrain access. Mode changes require
Linux ownership authorization plus native WRITE_DAC. In `compatibility=ntfs`, mode
translation is disabled and chmod is refused. Metadata remains stored for the next
Linux-mode mount. Set-ID mode changes and nonresident EA editing remain unsupported.

Rust deduplicates or appends SDS descriptors, updates both SII/SDH indexes and
journals the target security-ID switch. The kernel publishes the new immutable
descriptor through RCU before success; its stable open-handle counter lives in
a separate inode object. The xattr getter authorizes the same snapshot it
returns.

### Parsing and resolution

- `src/security.rs` validates self-relative descriptor offsets, SIDs, ACLs,
  and ACE boundaries without reordering or discarding bytes. Unknown ACEs
  remain opaque. It distinguishes absent, null, and empty DACLs.
- `check_file_access` evaluates ordered basic allow/deny ACEs, file generic
  rights, deny-only groups, and owner READ_CONTROL/WRITE_DAC rights including
  OWNER RIGHTS ACE overrides. The caller supplies an unrestricted Windows
  token. Unknown effective ACEs, nonempty SACLs, and unsupported rights fail
  closed. Experimental resident kernel writes require its FILE_WRITE_DATA check.
- `MftRecord::security_id()` reads the NTFS 3.x security ID from resident
  `$STANDARD_INFORMATION`. `ntfs-chkdsk` counts security-ID references in
  its allocated-MFT audit.
- `SdsEntry::parse` checks a `$Secure:$SDS` entry's header size, absolute
  offset, descriptor hash, and descriptor structure. It retains the exact
  entry bytes and can compare the header copy from an index entry.
- `security_store::read_descriptor` resolves `$SII` and `$SDH` using their
  native key order, verifies allocated external INDX blocks and fixups,
  cross-checks the copied headers, and checks the SDS descriptor hash and
  byte-identical mirror. Traversal has depth/cycle bounds and validates every
  entry in a visited node. Resident and nonresident legacy descriptors also
  work. Attribute-list extensions in security storage remain unsupported.
- `ntfs_utils::get_file_security` checks allocation and MFT sequence before
  returning exact bytes. C/Python bindings expose the same read-only snapshot.
  Tests cover mkfs-created resident indices and Windows-created external
  indices, descriptor corruption, stale references, and buffer contracts.

## Kernel identity and authorization

The kernel adapter uses the same Rust resolver and evaluator for reads and
experimental resident writes.
An explicit, immutable mount option supplies numeric Linux identities:

```sh
mount -t ntfsrs -o 'ro,sidmap=u:1000:S-1-5-21-111-222-333-1001;g:1000:S-1-5-21-111-222-333-513' DEVICE DIRECTORY
```

Use the actual owner/group SIDs for the volume. This example does not discover
or create Windows accounts. `u:UID:SID` and `g:GID:SID` entries are separated by
semicolons. Up to 64 entries and 4096 text bytes are supported. Duplicate IDs
or SIDs within the same identity kind are rejected. The map must contain a
user entry. Mapping changes during remount or a second mount of the same
superblock are refused.

The bridge captures filesystem UID/GID and every supplementary group from
the current Linux credentials in the initial user namespace. Rust requires
all of them to map: silently dropping an unknown group could bypass a deny
ACE. The bounded token allows a primary group and up to 63 supplementary
groups. Everyone and Authenticated Users are added; administrator membership
and privilege overrides are never inferred. Linux root must also map and
pass the DACL. Idmapped mounts are not advertised.

VFS read/list, execute/traverse, and metadata queries require their native
NTFS rights. Unknown effective ACEs and nonempty SACLs remain fail-closed.
Owner/group IDs reported by stat come from reverse SID mapping; an unmapped
owner or group is displayed as 65534. Mode 0555 is a provisional display value,
not a projection of the native ACL. The permission callback is authoritative.
Explicit experimental writable mounts check FILE_WRITE_DATA at open and at
each write using current credentials. Ordinary read-only mounts return EROFS.
Validated descriptor bytes are cached on the inode and SID
maps are compiled once at mount. Permission tokens borrow the compiled map's
SID bytes without heap allocation. Checks support nonblocking VFS RCU path
walks; descriptor reclamation and map teardown wait for RCU readers.
Every access check uses current credentials;
no access decision is reused across credentials. External writes to a mounted
volume are unsupported. The current write path preserves descriptor bytes
exactly and cannot mutate ACLs; a future ACL writer must invalidate descriptor
caches when descriptors change. Page-cache invalidation and volume transaction
locking are implemented for resident data writes.

`kernel/tests/test_kernel_permissions.sh` creates a disposable image with independent
descriptor fixtures and checks 30 credential cases plus mount-option failures
and 8,000 concurrent allowed/denied path walks. Group-limit and unmapped-group
cases verify that the allocation-free path preserves complete token checks.
On 2026-09-28 all access cases and final cleanup passed on WSL 6.18.33.2,
including after descriptor/map caching. A missing locked-superblock release
in the conflicting-map error path was fixed and revalidated after a WSL restart.
The test prints overall success only after unmount and module unload complete.

## Required for broader kernel writes

1. Extend supported security layouts beyond the implemented write locks and
   RCU descriptor replacement; support security
   attribute-list extensions and preserve exact descriptor
   bytes when changing unrelated file data or metadata.
2. Extend the bounded mapped token where needed. Complete supported privilege
   overrides and conditional/object ACE handling; unsupported ACE semantics
   must deny writes. Read/traverse enforcement already uses the mapped token.
3. Extend the implemented basic-ACE inheritance rules on create, and update parent and child
   descriptors transactionally when required. `chmod`/`chown` must not
   silently erase native ACLs. The raw interface is implemented; richer ACE
   policy and automatic inheritance propagation remain limited.
4. Test allow/deny order, null versus empty DACL, inherited ACEs, owner and
   group changes, hard links, and Windows round trips. Linux disposable-image
   mutation tests now pass; Windows round-trip validation remains outstanding.

Microsoft references: [DACLs and ACEs](https://learn.microsoft.com/en-us/windows/win32/secauthz/dacls-and-aces),
[ACE inheritance](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-inheritance),
[self-relative security descriptors](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d),
and [NTFS standard information](https://learn.microsoft.com/en-us/windows/win32/devnotes/standard-information).
The `$SDS` header and descriptor hash follow the upstream Linux
[ntfs3 structures](https://github.com/torvalds/linux/blob/master/fs/ntfs3/ntfs.h)
and [security implementation](https://github.com/torvalds/linux/blob/master/fs/ntfs3/fsntfs.c).

## Application views

Native NTFS is the default. Switching presentation never grants rights denied
by native ACLs. `ntfs-run` derives a view from an existing mounted directory,
checking the caller's source-view rights. Without directory write rights the
derived view is read-only. Read-only/noexec source restrictions persist through
nested view derivation. Linux compatibility adds ordinary Unix mode checks;
native compatibility retains Linux VFS integration without interpreting `$LXMOD`.
Descriptor cache replacement is shared immediately by both views.
