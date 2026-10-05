// SPDX-License-Identifier: MIT OR GPL-2.0-only
/*
 * Module: kernel.vfs_bridge
 * Purpose: connect Linux VFS operations and block I/O to the Rust NTFS engine.
 * Created: 2026-10-01
 * Architecture: Linux invokes these callbacks; Rust owns on-disk parsing,
 * DACL evaluation and writer admission. This bridge also projects desktop
 * permission bits and publishes inode changes to file-manager observers.
 */

#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/vmalloc.h>
#include <linux/rcupdate.h>
#include <linux/bug.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/exportfs.h>
#include <linux/fiemap.h>
#ifdef NTFS_RS_FILEATTR_H
#include <linux/fileattr.h>
#endif
#include <linux/falloc.h>
#include <linux/splice.h>
#include "core_fingerprint.h"
#include <linux/version.h>
#include <linux/compat.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/major.h>
#include <linux/math64.h>
#include <linux/rwsem.h>
#include <linux/timekeeping.h>
#include <linux/xattr.h>
#include <linux/xarray.h>
#include <linux/refcount.h>
#include <linux/statfs.h>
#include <linux/kdev_t.h>
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/writeback.h>
#include <linux/workqueue.h>
#include <linux/fsnotify.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#ifdef NTFS_RS_FILELOCK_H
#include <linux/filelock.h>
#endif

#ifdef NTFS_RS_BDEV_MAPPING
#define NTFS_RS_BLOCK_CACHE(sb) ((sb)->s_bdev->bd_mapping)
#else
#define NTFS_RS_BLOCK_CACHE(sb) ((sb)->s_bdev->bd_inode->i_mapping)
#endif

#define NTFS_RS_BUFFER_BYTES 65536U
#define NTFS_RS_READAHEAD_BYTES (4U * NTFS_RS_BUFFER_BYTES)
/* Smallest read-ahead window a regular file keeps: sixteen batches in flight. */
#define NTFS_RS_MIN_READAHEAD_BYTES (16U * NTFS_RS_READAHEAD_BYTES)
#define NTFS_RS_METADATA_READAHEAD_PAGES 16UL
#define NTFS_RS_SCRATCH_POOL 8
#define NTFS_RS_UPCASE_BYTES (2U * 65536U)
/* The decoded map of a split file table; an unsplit one is a single record. */
#define NTFS_RS_TABLE_BYTES (16U * 1024U)
#define NTFS_RS_KEPT_DESCRIPTORS 4096
#define NTFS_RS_SCRATCH_BYTES (3U * NTFS_RS_BUFFER_BYTES)
#define NTFS_RS_LOOKUP_BYTES (6U * NTFS_RS_BUFFER_BYTES)
#define NTFS_RS_SECURITY_BYTES (8U * NTFS_RS_BUFFER_BYTES)
#define NTFS_RS_MAX_GROUPS 64U
#define NTFS_RS_RECORD_MASK 0x0000ffffffffffffULL
#define NTFS_RS_MAX_WRITE (1U << 20)
/* Buffered writers start block-cache writeback once per this many file bytes. */
#define NTFS_RS_WRITEBACK_KICK_BYTES NTFS_RS_MAX_WRITE
#define NTFS_RS_BATCH_BYTES (1U << 19)
/* One preallocation step under the volume lock: the engine's own piece. */
#define NTFS_RS_ALLOCATE_STEP_BYTES (64LL << 20)
#define NTFS_RS_SESSION_SCRATCH ((2U << 20) + 0x20000U + 2U * 4096U)
#define NTFS_RS_HELD_MAX 72U
/* B-tree/rename transactions; descriptor changes use a size reported by Rust. */
#define NTFS_RS_MAX_DESCRIPTOR 0x20000U
/* Largest EA value (NTFS entries have 16-bit value lengths). */
#define NTFS_RS_MAX_EA_VALUE 65535U
/* Aggregate bound for the C/Rust ACL and LSM attribute call buffer. */
#define NTFS_RS_MAX_PACKED_EA_BYTES 0x20000U
#define NTFS_RS_DEFERRED_DRAIN_MS 5000U
/* Pause between background reclaim steps; readers take io_lock per read. */
#define NTFS_RS_RECLAIM_PAUSE_MS 2U
/* Age after which a changed volume's free space is counted from $Bitmap again,
 * should any change have bypassed the writer's allocation count. */
#define NTFS_RS_SPACE_RECOUNT_MS 60000U
/* ntfs_rs_space reports total clusters, free clusters and cluster bytes. */
#define NTFS_RS_SPACE_VALUES 3U
#define NTFS_RS_EPOCH_DELTA 11644473600LL
#define NTFS_RS_IOC_GET_VISIBILITY _IOR('N', 0xe4, __u32)
#define NTFS_RS_IOC_SET_VISIBILITY _IOW('N', 0xe5, __u32)
#define NTFS_RS_IOC_SHUTDOWN _IOR('X', 125, __u32)
/* No userspace patch bytes: recompute this inode's EA summary in Rust. */
#define NTFS_RS_IOC_REPAIR_EA _IO('N', 0xe0)
#define NTFS_RS_IOC_REPAIR_DATA _IO('N', 0xe1)
#define NTFS_RS_IOC_REPAIR_EA_NUMBER _IOW('N', 0xe2, __u64)
#define NTFS_RS_IOC_REPAIR_ALLOCATION_SECTOR _IOW('N', 0xe3, __u64)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
static DECLARE_RWSEM(ntfs_rs_invalidate_rwsem);
#define filemap_invalidate_lock(mapping) down_write(&ntfs_rs_invalidate_rwsem)
#define filemap_invalidate_unlock(mapping) up_write(&ntfs_rs_invalidate_rwsem)
#define filemap_invalidate_lock_shared(mapping) down_read(&ntfs_rs_invalidate_rwsem)
#define filemap_invalidate_unlock_shared(mapping) up_read(&ntfs_rs_invalidate_rwsem)
#define filemap_invalidate_trylock_shared(mapping) down_read_trylock(&ntfs_rs_invalidate_rwsem)
#define kmap_local_page(page) kmap_atomic(page)
#define kunmap_local(address) kunmap_atomic(address)
#define copy_page_from_iter_atomic(page, offset, bytes, iter) copy_page_from_iter(page, offset, bytes, iter)
#define NTFS_RS_CALLBACK_IDMAP
#define NTFS_RS_CALLBACK_IDMAP_INIT struct user_namespace *idmap = &init_user_ns
#define NTFS_RS_XATTR_IDMAP
#define NTFS_RS_XATTR_IDMAP_UNUSED
#define ntfs_rs_setattr_prepare(idmap, dentry, attr) setattr_prepare(dentry, attr)
#define ntfs_rs_setattr_copy(idmap, inode, attr) setattr_copy(inode, attr)
#define ntfs_rs_acl_update_mode(idmap, inode, mode, acl) posix_acl_update_mode(inode, mode, acl)
#define ntfs_rs_generic_permission(idmap, inode, mask) generic_permission(inode, mask)
#define ntfs_rs_generic_fillattr(idmap, inode, stat) generic_fillattr(inode, stat)
#define ntfs_rs_issue_flush(bdev) blkdev_issue_flush(bdev, GFP_NOFS)
#define ntfs_rs_inode_init_owner(idmap, inode, dir, mode) inode_init_owner(inode, dir, mode)
static int ntfs_rs_old_freeze(struct block_device *bdev)
{
    struct super_block *sb = freeze_bdev(bdev);
    return IS_ERR(sb) ? PTR_ERR(sb) : 0;
}
#define bdev_freeze ntfs_rs_old_freeze
#define bdev_thaw(bdev) thaw_bdev((bdev), (bdev)->bd_super)
#else
#define NTFS_RS_CALLBACK_IDMAP NTFS_RS_IDMAP *idmap,
#define NTFS_RS_CALLBACK_IDMAP_INIT
#define NTFS_RS_XATTR_IDMAP NTFS_RS_IDMAP *idmap,
#define NTFS_RS_XATTR_IDMAP_UNUSED (void)idmap
#define ntfs_rs_setattr_prepare(idmap, dentry, attr) setattr_prepare(idmap, dentry, attr)
#define ntfs_rs_setattr_copy(idmap, inode, attr) setattr_copy(idmap, inode, attr)
#define ntfs_rs_acl_update_mode(idmap, inode, mode, acl) posix_acl_update_mode(idmap, inode, mode, acl)
#define ntfs_rs_generic_permission(idmap, inode, mask) generic_permission(idmap, inode, mask)
#define ntfs_rs_generic_fillattr(idmap, inode, stat) generic_fillattr(idmap, inode, stat)
#define ntfs_rs_issue_flush(bdev) blkdev_issue_flush(bdev)
#define ntfs_rs_inode_init_owner(idmap, inode, dir, mode) inode_init_owner(idmap, inode, dir, mode)
#ifndef NTFS_RS_BDEV_FREEZE
#define bdev_freeze freeze_bdev
#define bdev_thaw thaw_bdev
#endif
#endif

#ifdef NTFS_RS_FILE_KATTR
#define NTFS_RS_FILEATTR struct file_kattr
#elif defined(NTFS_RS_FILEATTR_H)
#define NTFS_RS_FILEATTR struct fileattr
#endif

/* Windows file attributes. */
#define NTFS_RS_ATTR_READONLY 0x0001U
#define NTFS_RS_ATTR_SETTABLE 0x3127U /* RO, hidden, system, archive, temporary, offline, not-indexed */

/* Native access rights used by the bridge. */
#define NTFS_RS_READ_DATA 0x0001U
#define NTFS_RS_WRITE_DATA 0x0002U
#define NTFS_RS_ADD_SUBDIRECTORY 0x0004U
#define NTFS_RS_READ_EA 0x0008U
#define NTFS_RS_WRITE_EA 0x0010U
#define NTFS_RS_EXECUTE 0x0020U
#define NTFS_RS_DELETE_CHILD 0x0040U
#define NTFS_RS_READ_ATTRIBUTES 0x0080U
#define NTFS_RS_WRITE_ATTRIBUTES 0x0100U
#define NTFS_RS_DELETE 0x10000U
#define NTFS_RS_READ_CONTROL 0x20000U
#define NTFS_RS_WRITE_DAC 0x40000U
#define NTFS_RS_WRITE_OWNER 0x80000U
#define NTFS_RS_SYNCHRONIZE 0x100000U

/* Outcomes reported by the Rust namespace engine. */
#define NTFS_RS_UNLINKED 1
#define NTFS_RS_FREED 2
#define NTFS_RS_ORPHANED 3

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#define NTFS_RS_IDMAP struct mnt_idmap
#else
#define NTFS_RS_IDMAP struct user_namespace
#endif

#define NTFS_RS_REF(inode) ((inode)->i_ino | ((u64)(inode)->i_generation << 48))
/* Arguments shared by every writer call: live superblock and I/O callbacks. */
#define NTFS_RS_IO(sb) (sb), ntfs_rs_read_unlocked, ntfs_rs_write_at, ntfs_rs_flush

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
#define ntfs_rs_get_atime(i) inode_get_atime(i)
#define ntfs_rs_get_mtime(i) inode_get_mtime(i)
#define ntfs_rs_set_atime(i, t) inode_set_atime_to_ts((i), (t))
#define ntfs_rs_set_mtime(i, t) inode_set_mtime_to_ts((i), (t))
#else
#define ntfs_rs_get_atime(i) ((i)->i_atime)
#define ntfs_rs_get_mtime(i) ((i)->i_mtime)
#define ntfs_rs_set_atime(i, t) ((i)->i_atime = (t))
#define ntfs_rs_set_mtime(i, t) ((i)->i_mtime = (t))
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
#define ntfs_rs_get_ctime(i) inode_get_ctime(i)
#define ntfs_rs_set_ctime(i, t) inode_set_ctime_to_ts((i), (t))
#else
#define ntfs_rs_get_ctime(i) ((i)->i_ctime)
#define ntfs_rs_set_ctime(i, t) ((i)->i_ctime = (t))
#endif

/* Test-only crash boundary, opt-in on an experimental loop-device mount. */
static unsigned int fail_after_flush;
module_param(fail_after_flush, uint, 0600);
MODULE_PARM_DESC(fail_after_flush, "Experimental writer: fail after N durable flushes (0 disables)");

/* Layout shared with ntfs_parser.rs NodeInfo (repr(C)). */
struct ntfs_rs_node {
	u64 file_reference;
	u64 data_size;
	u32 flags;
	u32 mode;
	u32 links;
	u32 attributes;
	u64 times[4]; /* creation, modification, MFT change, access */
	u64 allocated;
	u32 reparse_tag;
	u32 reserved;
    u32 linux_flags;
	u32 security_id; /* $Secure ID that alone determines the descriptor, or 0 */
};

typedef int (*ntfs_rs_read_t)(void *, u64, unsigned char *, size_t);
typedef int (*ntfs_rs_write_t)(void *, u64, const unsigned char *, size_t);
typedef int (*ntfs_rs_flush_t)(void *);

/* C callbacks linked from the Rust adapter. */
int ntfs_rs_hold_at(void *, u64, const unsigned char *, size_t, int);
size_t ntfs_rs_table_copy(void *, unsigned char *, size_t);
u64 ntfs_rs_table_epoch(void *);
void ntfs_rs_table_drop(void *);
void ntfs_rs_table_store(void *, const unsigned char *, size_t, u64, u64, u64);
void ntfs_rs_release_at(void *, u64, size_t);
int ntfs_rs_write_data_at(void *, u64, const unsigned char *, size_t);

/* NTFS interpretation belongs to ntfs_parser.rs and writer.rs. */
extern int ntfs_rs_probe(const unsigned char *data, size_t length, void *context,
			 ntfs_rs_read_t read_at, unsigned char *scratch, size_t scratch_length);
extern int ntfs_rs_stat(const unsigned char *data, size_t length, void *context,
			ntfs_rs_read_t read_at, unsigned char *scratch, size_t scratch_length,
			u64 number, u16 sequence, struct ntfs_rs_node *output);
extern int ntfs_rs_read_file(const unsigned char *data, size_t length, void *context,
			     ntfs_rs_read_t read_at, unsigned char *scratch, size_t scratch_length,
			     u64 reference, u64 offset, unsigned char *output, size_t output_length);
extern int ntfs_rs_read_scratch_size(const unsigned char *, size_t);
/* Same scratch as read_file; emit gets logical, physical, length and FIEMAP flags. */
extern int ntfs_rs_map_file(const unsigned char *boot, void *context, ntfs_rs_read_t read_at,
			    unsigned char *scratch, size_t scratch_length, u64 reference,
			    u64 start, u64 length, void *emit_context,
			    int (*emit)(void *, u64, u64, u64, u32));
extern int ntfs_rs_lookup_name(const unsigned char *data, size_t length, void *context,
			       ntfs_rs_read_t read_at, unsigned char *scratch, size_t scratch_length,
			       u64 parent_reference, const unsigned char *name, size_t name_length,
			       u64 *output_reference, int linux_compatibility,
			       const unsigned char *upcase);
extern int ntfs_rs_read_upcase(const unsigned char *data, size_t length, void *context,
			       ntfs_rs_read_t read_at, unsigned char *scratch, size_t scratch_length,
			       unsigned char *output);
extern int ntfs_rs_readdir(const unsigned char *data, size_t length, void *context,
			   ntfs_rs_read_t read_at, unsigned char *scratch, size_t scratch_length,
			   u64 parent_reference, u64 start, const unsigned char *resume,
			   size_t resume_length, u32 visibility, const unsigned char *upcase,
			   void *emit_context,
			   int (*emit)(void *, const unsigned char *, size_t, u64, u64, u32));
extern int ntfs_rs_space(const unsigned char *, void *, ntfs_rs_read_t, unsigned char *, u64 *);
extern size_t ntfs_rs_ea_scratch_size(void);
extern int ntfs_rs_read_link(const unsigned char *, void *, ntfs_rs_read_t, unsigned char *,
			     u64 reference, u64 parent, unsigned char *output, size_t output_length);
extern int ntfs_rs_get_ea(const unsigned char *, void *, ntfs_rs_read_t, unsigned char *,
			  u64 reference, const unsigned char *name, size_t name_length,
			  unsigned char *output, size_t output_length);
extern int ntfs_rs_list_ea(const unsigned char *, void *, ntfs_rs_read_t, unsigned char *,
			   u64 reference, unsigned char *output, size_t output_length);
void __noreturn ntfs_rs_panic(void);
extern int ntfs_rs_validate_sidmap(const unsigned char *, size_t);
extern size_t ntfs_rs_sidmap_size(void);
extern int ntfs_rs_compile_sidmap(const unsigned char *, size_t, void *, size_t);
extern int ntfs_rs_load_security(const unsigned char *, size_t, void *, ntfs_rs_read_t,
				 unsigned char *, size_t, u64);
extern int ntfs_rs_check_security(const unsigned char *, size_t, const void *, u32,
				  const u32 *, size_t, u32, u32 *);
extern size_t ntfs_rs_writer_size(void);
extern size_t ntfs_rs_journal_map_bytes(void);
extern int ntfs_rs_writer_init(void *, const unsigned char *, void *, ntfs_rs_read_t,
			       ntfs_rs_write_t, ntfs_rs_flush_t, unsigned char *, unsigned char *, u64 *, int);
extern size_t ntfs_rs_writer_pending(const void *);
extern int ntfs_rs_writer_drain(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t,
				ntfs_rs_flush_t, unsigned char *, int);
extern int ntfs_rs_writer_write(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t, ntfs_rs_flush_t,
				unsigned char *, u64, u64, const unsigned char *, size_t);
extern int ntfs_rs_writer_resize(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t, ntfs_rs_flush_t,
				 unsigned char *, u64, u64);
extern int ntfs_rs_writer_rename(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t, ntfs_rs_flush_t,
				 unsigned char *, u64 parent, u64 reference,
				 const unsigned char *old, size_t old_length, u64 new_parent,
				 const unsigned char *new, size_t new_length, int target, u64 other,
				 int *outcome, int linux_compatibility, const unsigned char *, size_t,
                 const void *, u32, u32, u64, const unsigned char *, size_t);
extern int ntfs_rs_writer_finish(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t, ntfs_rs_flush_t,
				 unsigned char *);
extern int ntfs_rs_writer_create(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t, ntfs_rs_flush_t,
				 unsigned char *, u64 parent, const unsigned char *name,
				 size_t name_length, const unsigned char *parent_sd, size_t sd_length,
				 const void *map, u32 uid, u32 gid, u16 mode, u64 timestamp, int kind,
				 const unsigned char *target, size_t target_length,
				 const unsigned char *eas, size_t eas_length, u64 *result,
				 int linux_compatibility);
extern int ntfs_rs_writer_unlink(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t, ntfs_rs_flush_t,
				 unsigned char *, u64 parent, u64 reference,
				 const unsigned char *name, size_t name_length, int orphan,
				 int *outcome, int linux_compatibility);
extern int ntfs_rs_writer_reclaim(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t, ntfs_rs_flush_t,
				  unsigned char *, u64 reference);
extern int ntfs_rs_writer_reclaim_step(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t, ntfs_rs_flush_t,
				       unsigned char *, u64 reference);
extern int ntfs_rs_writer_park(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t, ntfs_rs_flush_t,
			       unsigned char *);
extern u64 ntfs_rs_writer_activity(const void *, int *parked);
extern int ntfs_rs_writer_failed(const void *);
extern int ntfs_rs_writer_crowded(const void *);
extern s64 ntfs_rs_writer_allocated_delta(const void *);
extern int ntfs_rs_writer_make_room(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t,
                                    ntfs_rs_flush_t, unsigned char *);
extern const char *ntfs_rs_writer_last_refusal(void);
extern int ntfs_rs_writer_reserve(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t, ntfs_rs_flush_t, unsigned char *);
extern int ntfs_rs_writer_reclaim_orphans(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t,
					  ntfs_rs_flush_t, unsigned char *, u64 *count);
extern int ntfs_rs_writer_set_ea(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t, ntfs_rs_flush_t,
				 unsigned char *, u64 reference, const unsigned char *name,
				 size_t name_length, const unsigned char *value, size_t value_length,
				 int remove, u32 flags, u32 mode);
extern int ntfs_rs_writer_set_times(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t,
				    ntfs_rs_flush_t, unsigned char *, u64 reference,
				    const u64 *times, u32 valid, u32 attribute_mask, u32 attributes);
extern int ntfs_rs_writer_set_label(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t,
				    ntfs_rs_flush_t, unsigned char *, const unsigned char *label,
				    size_t label_length);
extern size_t ntfs_rs_writer_security_scratch_size(void);
extern int ntfs_rs_writer_set_security(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t,
				       ntfs_rs_flush_t, unsigned char *, u64, const unsigned char *,
				       size_t, const void *, u32, const u32 *, size_t);
extern int ntfs_rs_writer_chown(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t, ntfs_rs_flush_t,
				unsigned char *, u64, u32, u32, const void *, u32, const u32 *, size_t);
extern int ntfs_rs_writer_mode(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t, ntfs_rs_flush_t,
			       unsigned char *, u64, u32);
extern int ntfs_rs_writer_link(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t, ntfs_rs_flush_t,
			       unsigned char *, u64, u64, const unsigned char *, size_t, int);

/* Scratch for stat, EA and symlink reads; reported once by Rust. */


/* Exact validated bytes. A published copy is immutable; a descriptor change
 * publishes a new copy and frees the old one after an RCU grace period.
 * Never cache an authorization result: every check uses current credentials. */
struct ntfs_rs_security {
	struct rcu_head rcu;
	size_t length;
	unsigned char data[];
};

/* Stable per-inode lifetime; descriptor replacement must not reset handles. */
struct ntfs_rs_inode {
	bool native_mode;
	unsigned int limits; /* Inherited read-only/noexec ceilings on delegated views. */
	struct inode *canonical; /* Native projection pins the Linux/canonical inode. */
	atomic_long_t directory_epoch;
	bool unix_mode;
	/* Canonical only: the last name is gone but the record is a durable
	 * orphan; eviction reclaims it (or the next writable mount does). */
	bool orphaned;
	u32 linux_flags; /* Stored standard EA; enforced only by Linux projections. */
	u32 attributes; /* Windows attributes; the canonical copy is authoritative. */
	u64 persisted_times[3]; /* Last journaled mtime, ctime and atime. */
	u64 created;    /* NTFS creation time, reported as statx birth time. */
	struct rcu_head rcu;
	atomic_t open_files;
	/* Canonical only: a writable open or a resize may have left allocation
	 * past the end of the file for the last close to give back. */
	atomic_t trim_due;
	/* Canonical only: i_blocks reflects the record. Cleared by whatever may
	 * change the allocation, so stat reads the record again only then. */
	atomic_t blocks_known;
	/* Canonical only: files open for writing, in any view. */
	atomic_t writers;
	/* Canonical only: the target of a symbolic link, read once. */
	struct ntfs_rs_link *link;
	struct ntfs_rs_security __rcu *security;
};

/* A link target as resolved from one parent directory; it never changes
 * while the inode lives. */
struct ntfs_rs_link {
	struct rcu_head rcu;
	u64 parent;
	char target[];
};

struct ntfs_rs_options {
	char *view;
	bool native_mode;
	bool compatibility_set;
	char *sidmap;
	bool experimental_rw;
	u32 visibility;
	bool visibility_set;
	/* Access policy, independent of compatibility: -1 unset, 0 windows, 1 desktop. */
	int permissions;
	bool uid_set, gid_set, fmask_set, dmask_set;
	u32 uid, gid, fmask, dmask;
};

/* The identity map in one allocation: the compiled (opaque, immutable) Rust
 * value first, then the option text. Readers use it under RCU, writers under
 * io_lock; remount publishes a new one and frees the old with kvfree_rcu, so
 * no callback into module text remains after unload. */
struct ntfs_rs_identity {
	struct rcu_head rcu;
	void *map;
	char *sidmap;
};

/* permissions=desktop: NTFS-3G-style mount-wide Linux ownership and modes.
 * Windows ACLs stay on disk untouched and are not evaluated. Published by
 * RCU so remount can change it while RCU path walks read it. */
struct ntfs_rs_access {
	struct rcu_head rcu;
	bool desktop;
	kuid_t uid;
	kgid_t gid;
	umode_t file_mode, dir_mode;	/* 0777 & ~fmask, 0777 & ~dmask */
};

/* Queued metadata lives here until Rust has made its journal durable. */
struct ntfs_rs_held {
	u64 offset;
	size_t length;
	bool active;
	u8 data[4096];
};

struct ntfs_rs_visibility { u32 flags; kuid_t owner; refcount_t references; };

struct ntfs_rs_super {
    const struct cred *mount_cred;
	struct xarray visibility; /* IDs stay live while a view has cached inodes. */
	unsigned char boot[512]; /* Immutable mount geometry, validated by Rust. */
	size_t read_scratch_bytes;
	/* SID map text + its compiled Rust value; replaced live on remount. */
	struct ntfs_rs_identity __rcu *ident;
	struct ntfs_rs_access __rcu *access;
	void *writer; /* Serialized opaque Rust journal state. */
	unsigned char *op_scratch;
	unsigned char *batch_arena;
	u64 *journal_map; /* Lent to the writer for the session. */
	struct ntfs_rs_held *held;
	unsigned int held_count;
	struct super_block *sb;
	struct delayed_work drain_work;
	bool drain_scheduled;
	struct work_struct writeback_work;
	/* Evicted orphans whose clusters the reclaim worker still has to free. */
	struct work_struct reclaim_work;
	spinlock_t reclaim_lock;
	struct list_head reclaim_list;
	/* Idle detection for parking the session clean; see ntfs_rs_park_if_idle. */
	u64 idle_activity;
	atomic_t write_opens;
	struct rw_semaphore io_lock;
	bool write_failed;
	bool writer_ready;
	/* The first device mount's view (1 Linux, 2 NTFS), and whether the volume
	 * has since become reachable through another one. Until then no peer of
	 * an inode can be watched, and nothing needs telling about a change. */
	int first_view;
	bool several_views;
	/* Idle working buffers of NTFS_RS_SECURITY_BYTES, the largest a read path
	 * asks for: taking one costs a pointer swap where an allocation of that
	 * size maps pages. */
	/* The decoded map of the file table, kept between operations. A write or
	 * hold reaching [table_start, table_end) voids it; table_epoch counts
	 * every metadata change so a map decoded across one is not kept. */
	/* Descriptors by $Secure ID, kept until unmount. */
	struct xarray descriptors;
	atomic_t descriptor_count;
	spinlock_t table_lock;
	unsigned char *table;
	size_t table_bytes;
	u64 table_start, table_end;
	atomic64_t table_epoch;
	/* The last $Bitmap count for statfs: its values, table_epoch, time, and
	 * the writer and allocation delta it was taken with. space_lock
	 * serializes counting. See ntfs_rs_statfs. */
	struct mutex space_lock;
	u64 space[NTFS_RS_SPACE_VALUES];
	u64 space_epoch;
	unsigned long space_counted;
	const void *space_writer;
	s64 space_delta;
	bool space_valid;
	/* $UpCase, read once: every lookup and resumed listing collates with it.
	 * NULL if it could not be read; those then load it themselves. */
	unsigned char *upcase;
	spinlock_t scratch_lock;
	unsigned int scratch_idle;
	unsigned char *scratch_pool[NTFS_RS_SCRATCH_POOL];
    bool direct_io; /* only while io_lock is held exclusively */
	unsigned int flushes;
};

/* A failed write session accepts no further changes and leaves the volume
 * dirty for recovery. Say where it failed, once, so that state is explained. */
static void ntfs_rs_poison(struct ntfs_rs_super *state, const char *where)
{
    if (!state->write_failed) {
        pr_err("slate-ntfs: %s write session failed in %s (%s); the volume stays dirty for recovery\n",
            state->sb ? state->sb->s_id : "volume", where, ntfs_rs_writer_last_refusal());
    }
    state->write_failed = true;
}

static bool ntfs_rs_native(const struct inode *inode)
{
	const struct ntfs_rs_inode *p = inode->i_private;
	return p && p->native_mode;
}

#define NTFS_RS_VIEW_RO 1U
#define NTFS_RS_VIEW_NOEXEC 2U

static unsigned int ntfs_rs_limits(const struct inode *inode)
{
	const struct ntfs_rs_inode *p = inode->i_private;
	return p ? p->limits : 0;
}

static struct ntfs_rs_visibility *ntfs_rs_visibility_policy(const struct inode *inode)
{
    struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
    return xa_load(&state->visibility, ntfs_rs_limits(inode) >> 2);
}

static u32 ntfs_rs_visibility_flags(const struct inode *inode)
{
    struct ntfs_rs_visibility *policy = ntfs_rs_visibility_policy(inode);
    return policy ? READ_ONCE(policy->flags) : 0;
}

/* Each inode pins its policy; the initial host policy has a superblock pin. */
static void ntfs_rs_put_visibility(struct super_block *sb, u32 id)
{
    struct ntfs_rs_super *state = sb->s_fs_info;
    struct ntfs_rs_visibility *policy;
    xa_lock(&state->visibility);
    policy = xa_load(&state->visibility, id);
    if (policy && refcount_dec_and_test(&policy->references)) {
        __xa_erase(&state->visibility, id);
        xa_unlock(&state->visibility);
        kfree(policy);
        return;
    }
    xa_unlock(&state->visibility);
}

/* Walk allocated policies rather than just the eight host projections. */
static u32 ntfs_rs_next_policy(struct inode *inode, u32 minimum)
{
    struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
    unsigned long id = minimum >> 3;
    if (!xa_find(&state->visibility, &id, (U32_MAX >> 3) - 1, XA_PRESENT))
        return U32_MAX;
    return id == (minimum >> 3) ? minimum : (u32)(id << 3);
}

static bool ntfs_rs_readonly(const struct inode *inode)
{
	return sb_rdonly(inode->i_sb) || (ntfs_rs_limits(inode) & NTFS_RS_VIEW_RO);
}

static struct inode *ntfs_rs_canonical(struct inode *inode)
{
	struct ntfs_rs_inode *p = inode->i_private;
	return p && p->canonical ? p->canonical : inode;
}

static struct ntfs_rs_inode *ntfs_rs_shared(struct inode *inode)
{
	return ntfs_rs_canonical(inode)->i_private;
}

static struct timespec64 ntfs_rs_to_ts(u64 value)
{
	u32 remainder;
	u64 seconds = div_u64_rem(value, 10000000U, &remainder);
	struct timespec64 ts = {
		.tv_sec = (s64)seconds - NTFS_RS_EPOCH_DELTA,
		.tv_nsec = remainder * 100,
	};
	return ts;
}

static u64 ntfs_rs_from_ts(struct timespec64 ts)
{
	s64 seconds = ts.tv_sec + NTFS_RS_EPOCH_DELTA;
	if (seconds < 0)
		return 0;
	return (u64)seconds * 10000000ULL + (u64)ts.tv_nsec / 100;
}

#define NTFS_RS_LINUX_FLAGS (FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NODUMP_FL | FS_NOATIME_FL)
static void ntfs_rs_apply_linux_flags(struct inode *inode)
{
    u32 flags = ntfs_rs_native(inode) ? 0 : READ_ONCE(ntfs_rs_shared(inode)->linux_flags);
    unsigned int value = (flags & FS_IMMUTABLE_FL ? S_IMMUTABLE : 0) |
        (flags & FS_APPEND_FL ? S_APPEND : 0) | (flags & FS_NOATIME_FL ? S_NOATIME : 0);
    inode_set_flags(inode, value, S_IMMUTABLE | S_APPEND | S_NOATIME);
}
static bool ntfs_rs_content_forbidden(struct inode *inode, bool append)
{
    u32 flags = ntfs_rs_native(inode) ? 0 : READ_ONCE(ntfs_rs_shared(inode)->linux_flags);
    return (flags & FS_IMMUTABLE_FL) || ((flags & FS_APPEND_FL) && !append);
}

static void ntfs_rs_sync_projection(struct inode *inode);

/* Update in-memory times of the canonical inode. write_inode persists them
 * through a journaled $STANDARD_INFORMATION transaction. */
static void ntfs_rs_touch(struct inode *inode, bool modified)
{
	struct inode *canonical = ntfs_rs_canonical(inode);
	struct timespec64 now = current_time(canonical);
	if (ntfs_rs_readonly(canonical))
		return;
	ntfs_rs_set_ctime(canonical, now);
	if (modified)
		ntfs_rs_set_mtime(canonical, now);
	mark_inode_dirty_sync(canonical);
}

/* VFS calls this after applying mount atime policy. Persist the canonical
 * inode even when the access used an alternate namespace projection. */
#ifdef NTFS_RS_UPDATE_TIME_TYPE
static int ntfs_rs_update_time(struct inode *inode, enum fs_update_time type, unsigned int flags)
#elif defined(NTFS_RS_UPDATE_TIME_FLAGS)
static int ntfs_rs_update_time(struct inode *inode, int flags)
#else
static int ntfs_rs_update_time(struct inode *inode, struct timespec64 *now, int flags)
#endif
{
    struct inode *canonical = ntfs_rs_canonical(inode);
    if (ntfs_rs_readonly(inode))
        return 0;
#ifdef NTFS_RS_UPDATE_TIME_TYPE
    generic_update_time(canonical, type, flags);
#elif defined(NTFS_RS_UPDATE_TIME_FLAGS)
    generic_update_time(canonical, flags);
#else
    generic_update_time(canonical, now, flags);
#endif
    ntfs_rs_sync_projection(canonical);
    return 0;
}

/* Cross-view notifications. VFS notifies the view an operation used; every
 * other cached projection of the same NTFS object (and its parent
 * directory) receives the same event here. Callers never hold io_lock. */
static u32 ntfs_rs_cookie(void)
{
	static atomic_t cookie = ATOMIC_INIT(0);
	return (u32)atomic_inc_return(&cookie) | 0x80000000U;
}

struct ntfs_rs_key { u64 reference; bool native; unsigned int limits; };
static unsigned long ntfs_rs_hash(const struct ntfs_rs_key *key)
{
	return (unsigned long)key->reference ^ ((unsigned long)(key->native | (key->limits << 1)) << 44);
}

static int ntfs_rs_inode_matches(struct inode *inode, void *data)
{
	const struct ntfs_rs_key *key = data;
	return inode->i_ino == (key->reference & NTFS_RS_RECORD_MASK) &&
		inode->i_generation == key->reference >> 48 &&
		ntfs_rs_native(inode) == key->native && ntfs_rs_limits(inode) == key->limits;
}

/* Return a referenced cached projection (policy 0 is the canonical inode). */
static struct inode *ntfs_rs_peer(struct inode *canonical, unsigned int policy)
{
	struct ntfs_rs_key key = { NTFS_RS_REF(canonical), policy & 1, policy >> 1 };
	struct inode *peer;
	bool initializing;
	if (!policy)
		return igrab(canonical);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 0)
	peer = ilookup5_nowait(canonical->i_sb, ntfs_rs_hash(&key), ntfs_rs_inode_matches,
		&key, &initializing);
#else
	peer = ilookup5_nowait(canonical->i_sb, ntfs_rs_hash(&key), ntfs_rs_inode_matches, &key);
	initializing = peer && (peer->i_state & I_NEW);
#endif
	if (peer && initializing) {
		iput(peer);
		return NULL;
	}
	return peer;
}

static struct inode *ntfs_rs_project_inode(struct inode *, unsigned int);

#ifdef NTFS_RS_FSNOTIFY_PATH
#define NTFS_RS_NOTIFY_PEER fsnotify_peer
#else
#define NTFS_RS_NOTIFY_PEER fsnotify
#endif

static void ntfs_rs_notify_peers(struct inode *origin, u32 mask, const struct qstr *name,
		u32 cookie, struct inode *child)
{
#ifdef CONFIG_FSNOTIFY
	struct inode *canonical = ntfs_rs_canonical(origin);
	const struct ntfs_rs_super *state = origin->i_sb->s_fs_info;
	unsigned int own = (ntfs_rs_native(origin) ? 1U : 0U) | (ntfs_rs_limits(origin) << 1);
	unsigned int policy;
	if (!READ_ONCE(state->several_views))
		return;
	for (policy = ntfs_rs_next_policy(canonical, 0); policy != U32_MAX;
            policy = ntfs_rs_next_policy(canonical, policy + 1)) {
		struct inode *peer;
		if (policy == own)
			continue;
		peer = ntfs_rs_peer(canonical, policy);
		if (!peer)
			continue;
        if (!name && S_ISDIR(peer->i_mode)) mask |= FS_ISDIR;
        if (mask & (FS_MOVE_SELF | FS_DELETE_SELF)) {
            NTFS_RS_NOTIFY_PEER(mask, peer, FSNOTIFY_EVENT_INODE, NULL, NULL, peer, 0);
        } else if (name) {
            struct inode *object = child ? ntfs_rs_project_inode(child, policy) : NULL;
            if (!IS_ERR_OR_NULL(object)) {
                NTFS_RS_NOTIFY_PEER(mask, object, FSNOTIFY_EVENT_INODE, peer, name, NULL, cookie);
                iput(object);
            }
		} else {
			struct dentry *alias = d_find_alias(peer);
			if (alias) {
				{
                    struct dentry *parent = dget_parent(alias);
                    struct name_snapshot name;
                    take_dentry_name_snapshot(&name, alias);
                    NTFS_RS_NOTIFY_PEER(mask | FS_EVENT_ON_CHILD, peer,
                        FSNOTIFY_EVENT_INODE, d_inode(parent), &name.name, peer, 0);
                    release_dentry_name_snapshot(&name);
                    dput(parent);
                }
				dput(alias);
			} else {
				NTFS_RS_NOTIFY_PEER(mask, peer, FSNOTIFY_EVENT_INODE, NULL, NULL, peer, 0);
			}
		}
		iput(peer);
	}
#endif
}

static int ntfs_rs_resolve_name(struct inode *parent, const struct qstr *name, u64 *reference);
static int ntfs_rs_read_at(void *context, u64 offset, unsigned char *output, size_t length);

/* Whether a positive dentry from an older namespace epoch still names its
 * inode. Declaring it stale makes the VFS run d_invalidate, which unmounts
 * every mount beneath it, such as a container's bind mount of a game folder,
 * so only a name that has gone or now names another file may be dropped. */
static int ntfs_rs_still_named(struct inode *parent, const struct qstr *name,
		struct dentry *dentry, unsigned long epoch)
{
	u64 reference;
	int result = ntfs_rs_resolve_name(parent, name, &reference);

	if (result == -ENOENT)
		return 0;
	if (result)
		return result;
	if (reference != NTFS_RS_REF(d_inode(dentry)))
		return 0;
	WRITE_ONCE(dentry->d_fsdata, (void *)epoch);
	return 1;
}

/* Policy belongs to the directory tree, never to a task or PID. Both trees
 * observe the same namespace epoch. After a committed mutation through either
 * view, a negative dentry is looked up again and a positive one is re-checked
 * by name before it may be discarded. */
#ifdef NTFS_RS_REVALIDATE_PARENT
static int ntfs_rs_revalidate(struct inode *parent_arg, const struct qstr *name,
		struct dentry *dentry, unsigned int flags)
#else
static int ntfs_rs_revalidate(struct dentry *dentry, unsigned int flags)
#endif
{
	struct inode *parent;
	unsigned long epoch;
	if (IS_ROOT(dentry))
		return 1;
	/* A mounted dentry cannot be replaced while the mount is attached.
	 * Revalidating it as stale would hide the mounted filesystem. */
	if (d_mountpoint(dentry))
		return 1;
	parent = d_inode(dentry->d_parent);
	if (!parent)
		return 0;
	epoch = atomic_long_read(&ntfs_rs_shared(parent)->directory_epoch);
	if ((unsigned long)READ_ONCE(dentry->d_fsdata) == epoch)
		return 1;
	if (d_really_is_negative(dentry))
		return flags & LOOKUP_RCU ? -ECHILD : 0;
	/* Re-reading the index may sleep: leave RCU walk first. */
	if (flags & LOOKUP_RCU)
		return -ECHILD;
#ifdef NTFS_RS_REVALIDATE_PARENT
	return ntfs_rs_still_named(parent_arg, name, dentry, epoch);
#else
	{
		struct dentry *locked_parent = dget_parent(dentry);
		struct name_snapshot snapshot;
		int result;

		take_dentry_name_snapshot(&snapshot, dentry);
		result = ntfs_rs_still_named(d_inode(locked_parent), &snapshot.name, dentry, epoch);
		release_dentry_name_snapshot(&snapshot);
		dput(locked_parent);
		return result;
	}
#endif
}

static const struct dentry_operations ntfs_rs_dentry_ops = {
	.d_revalidate = ntfs_rs_revalidate,
};

static void ntfs_rs_namespace_changed(struct inode *parent)
{
	atomic_long_inc(&ntfs_rs_shared(parent)->directory_epoch);
	atomic_set(&ntfs_rs_shared(parent)->blocks_known, 0);
}

/* A working buffer of at least `bytes` for one read operation. Its contents
 * are unspecified, as they are for the session's write buffer. */
static unsigned char *ntfs_rs_scratch_get(const struct ntfs_rs_super *shared, size_t bytes)
{
	struct ntfs_rs_super *state = (struct ntfs_rs_super *)shared;
	unsigned char *scratch = NULL;

	if (bytes > NTFS_RS_SECURITY_BYTES)
		return kvmalloc(bytes, GFP_NOFS);
	spin_lock(&state->scratch_lock);
	if (state->scratch_idle)
		scratch = state->scratch_pool[--state->scratch_idle];
	spin_unlock(&state->scratch_lock);
	return scratch ?: kvmalloc(NTFS_RS_SECURITY_BYTES, GFP_NOFS);
}

static void ntfs_rs_scratch_put(const struct ntfs_rs_super *shared, unsigned char *scratch, size_t bytes)
{
	struct ntfs_rs_super *state = (struct ntfs_rs_super *)shared;

	if (scratch && bytes <= NTFS_RS_SECURITY_BYTES) {
		spin_lock(&state->scratch_lock);
		if (state->scratch_idle < NTFS_RS_SCRATCH_POOL) {
			state->scratch_pool[state->scratch_idle++] = scratch;
			scratch = NULL;
		}
		spin_unlock(&state->scratch_lock);
	}
	kvfree(scratch);
}

/* The file reference that name has in the parent folder, through the
 * parent's view; lookup and revalidation share it. Returns 0 or -errno,
 * -ENOENT when the folder holds no such name. */
static int ntfs_rs_resolve_name(struct inode *parent, const struct qstr *name, u64 *reference)
{
	struct super_block *sb = parent->i_sb;
	const struct ntfs_rs_super *state = sb->s_fs_info;
	unsigned char *scratch = ntfs_rs_scratch_get(state, NTFS_RS_LOOKUP_BYTES);
	int result;

	if (!scratch)
		return -ENOMEM;
	result = ntfs_rs_lookup_name(state->boot, 512, sb, ntfs_rs_read_at,
				     scratch, NTFS_RS_LOOKUP_BYTES, NTFS_RS_REF(parent),
				     name->name, name->len,
				     reference, !ntfs_rs_native(parent), state->upcase);
	ntfs_rs_scratch_put(state, scratch, NTFS_RS_LOOKUP_BYTES);
	return result;
}

void __noreturn ntfs_rs_panic(void)
{
	BUG();
}

/* A bio on the volume's device; op combines the operation and request flags. */
static struct bio *ntfs_rs_bio_alloc(struct super_block *sb, unsigned int vectors, unsigned int op)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
	return bio_alloc(sb->s_bdev, vectors, op, GFP_NOFS);
#else
	struct bio *bio = bio_alloc(GFP_NOFS, vectors);

	if (bio) {
		bio_set_dev(bio, sb->s_bdev);
		bio->bi_opf = op;
	}
	return bio;
#endif
}

/* Rust bounds the physical extent. The owned buffer remains live until
 * submit_bio_wait completes; no user pages or kernel-stack buffers reach DMA. */
static int ntfs_rs_rw_span(struct super_block *sb, u64 offset,
                     unsigned char *output, size_t length, bool write)
{
	struct bio *bio;
	void *start = output;
	size_t bytes = length;
	bool vmapped = is_vmalloc_addr(output);
	unsigned int vectors = DIV_ROUND_UP(offset_in_page(output) + length, PAGE_SIZE);
	int result;

	bio = ntfs_rs_bio_alloc(sb, vectors, write ? REQ_OP_WRITE : REQ_OP_READ);
	if (!bio)
		return -ENOMEM;
	if (vmapped)
		flush_kernel_vmap_range(start, bytes);
	bio->bi_iter.bi_sector = offset >> 9;
	while (length) {
		unsigned int within = offset_in_page(output);
		unsigned int amount = min_t(size_t, length, PAGE_SIZE - within);
		struct page *page = is_vmalloc_addr(output) ?
			vmalloc_to_page(output) : virt_to_page(output);
		if (!page || bio_add_page(bio, page, amount, within) != amount) {
			bio_put(bio);
			return -EIO;
		}
		output += amount;
		length -= amount;
	}
	result = submit_bio_wait(bio);
	if (vmapped && !write)
		invalidate_kernel_vmap_range(start, bytes);
	bio_put(bio);
	return result;
}

/* These callbacks run with io_lock held for writing. Mount-owned image copies
 * survive buffer-cache eviction and stay out of writeback until checkpoint.
 * Reads always overlay them, including newer uncommitted versions. */
/* Metadata at [offset, offset + length) is changing, as readers see it. */
static void ntfs_rs_table_changed(struct ntfs_rs_super *state, u64 offset, size_t length)
{
	atomic64_inc(&state->table_epoch);
	if (READ_ONCE(state->table_bytes)) {
		spin_lock(&state->table_lock);
		if (offset < state->table_end && offset + length > state->table_start)
			state->table_bytes = 0;
		spin_unlock(&state->table_lock);
	}
}

size_t ntfs_rs_table_copy(void *context, unsigned char *output, size_t capacity)
{
	struct ntfs_rs_super *state = ((struct super_block *)context)->s_fs_info;
	size_t length;

	if (!state || !state->table || !READ_ONCE(state->table_bytes))
		return 0;
	spin_lock(&state->table_lock);
	length = state->table_bytes <= capacity ? state->table_bytes : 0;
	memcpy(output, state->table, length);
	spin_unlock(&state->table_lock);
	return length;
}

/* The table's map changed in a record outside the guarded range. */
void ntfs_rs_table_drop(void *context)
{
	struct ntfs_rs_super *state = ((struct super_block *)context)->s_fs_info;

	if (state)
		ntfs_rs_table_changed(state, state->table_start, 1);
}

u64 ntfs_rs_table_epoch(void *context)
{
	struct ntfs_rs_super *state = ((struct super_block *)context)->s_fs_info;
	return state ? atomic64_read(&state->table_epoch) : 0;
}

void ntfs_rs_table_store(void *context, const unsigned char *table, size_t length,
			 u64 start, u64 end, u64 epoch)
{
	struct ntfs_rs_super *state = ((struct super_block *)context)->s_fs_info;

	if (!state || !state->table || !length || length > NTFS_RS_TABLE_BYTES)
		return;
	spin_lock(&state->table_lock);
	/* Decoded across a metadata change: possibly from both sides of it. */
	if (atomic64_read(&state->table_epoch) == epoch) {
		memcpy(state->table, table, length);
		state->table_start = start;
		state->table_end = end;
		state->table_bytes = length;
	}
	spin_unlock(&state->table_lock);
}

int ntfs_rs_hold_at(void *context, u64 offset, const unsigned char *data,
		    size_t length, int first)
{
	struct ntfs_rs_super *state = ((struct super_block *)context)->s_fs_info;
	struct ntfs_rs_held *slot = NULL;
	unsigned int i;
	(void)first;
	if (!state || !state->held || !data || !length || length > 4096 ||
	    offset > U64_MAX - length)
		return -EINVAL;
	ntfs_rs_table_changed(state, offset, length);
	for (i = 0; i < NTFS_RS_HELD_MAX; i++) {
		struct ntfs_rs_held *h = &state->held[i];
		if (h->active && h->offset == offset && h->length == length) {
			slot = h;
			break;
		}
		if (!h->active && !slot)
			slot = h;
	}
	if (!slot)
		return -ENOSPC;
	if (!slot->active) {
		slot->offset = offset;
		slot->length = length;
		slot->active = true;
		state->held_count++;
	}
	memcpy(slot->data, data, length);
	return 0;
}

void ntfs_rs_release_at(void *context, u64 offset, size_t length)
{
	struct ntfs_rs_super *state = ((struct super_block *)context)->s_fs_info;
	unsigned int i;
	if (!state || !state->held)
		return;
	/* The device copy shows again: the same bytes once written, but older
	 * ones if the hold is dropped unwritten. */
	ntfs_rs_table_changed(state, offset, length);
	for (i = 0; i < NTFS_RS_HELD_MAX; i++) {
		struct ntfs_rs_held *h = &state->held[i];
		if (h->active && h->offset == offset && h->length == length) {
			h->active = false;
			state->held_count--;
			return;
		}
	}
}

static void ntfs_rs_overlay_held(struct ntfs_rs_super *state, u64 offset,
				 unsigned char *output, size_t length)
{
	unsigned int i;
	if (!state || !state->held_count)
		return;
	for (i = 0; i < NTFS_RS_HELD_MAX; i++) {
		const struct ntfs_rs_held *h = &state->held[i];
		u64 from, to;
		if (!h->active || offset >= h->offset + h->length ||
		    h->offset >= offset + length)
			continue;
		from = max(offset, h->offset);
		to = min(offset + length, h->offset + h->length);
		memcpy(output + (from - offset), h->data + (from - h->offset), to - from);
	}
}

/* Device bytes through the block device's page cache. The filesystem does not
 * attach buffer heads to its own inodes; the block device manages writeback. */
/* Metadata clusters: file records and index blocks of one directory lie
 * together, so a miss fetches its neighbours in the same request: the aligned
 * chunk around it, as records are as often reached descending as ascending. */
static void ntfs_rs_metadata_readahead(struct address_space *mapping, u64 offset, size_t length)
{
	pgoff_t first = round_down(offset >> PAGE_SHIFT, NTFS_RS_METADATA_READAHEAD_PAGES);
	pgoff_t last = (offset + length - 1) >> PAGE_SHIFT;
	struct file_ra_state ra;

	file_ra_state_init(&ra, mapping);
	page_cache_sync_readahead(mapping, &ra, NULL, first,
		round_up(last - first + 1, NTFS_RS_METADATA_READAHEAD_PAGES));
}

static int ntfs_rs_plain_read(void *context, u64 offset,
			   unsigned char *output, size_t length)
{
	struct super_block *sb = context;
	struct ntfs_rs_super *state = sb ? sb->s_fs_info : NULL;
	struct address_space *mapping;

	if (!sb || (!output && length) || offset > U64_MAX - length)
		return -EINVAL;
	if (length >= 16384 && length <= NTFS_RS_READAHEAD_BYTES &&
	    !((offset | length | (unsigned long)output) &
	      (bdev_logical_block_size(sb->s_bdev) - 1)) &&
	    (!state || !state->writer))
		return ntfs_rs_rw_span(sb, offset, output, length, false);
	mapping = NTFS_RS_BLOCK_CACHE(sb);
	if (length > PAGE_SIZE)
		ntfs_rs_metadata_readahead(mapping, offset, length);
	while (length) {
#ifdef NTFS_RS_BDEV_FOLIO_IO
		/* A cached page is the common case and needs one lookup. */
		struct folio *folio = filemap_get_folio(mapping, offset >> PAGE_SHIFT);
		if (IS_ERR_OR_NULL(folio) || !folio_test_uptodate(folio)) {
			if (IS_ERR_OR_NULL(folio))
				ntfs_rs_metadata_readahead(mapping, offset, 1);
			else
				folio_put(folio);
			folio = read_mapping_folio(mapping, offset >> PAGE_SHIFT, NULL);
		}
#else
		struct page *page = read_mapping_page(mapping, offset >> PAGE_SHIFT, NULL);
#endif
		size_t within = offset_in_page(offset);
		size_t amount = min(length, (size_t)PAGE_SIZE - within);
		void *address;

#ifdef NTFS_RS_BDEV_FOLIO_IO
		if (IS_ERR(folio))
			return PTR_ERR(folio);
		address = kmap_local_folio(folio, offset - folio_pos(folio) - within);
#else
		if (IS_ERR(page))
			return PTR_ERR(page);
		address = kmap_local_page(page);
#endif
		memcpy(output, (unsigned char *)address + within, amount);
		kunmap_local(address);
#ifdef NTFS_RS_BDEV_FOLIO_IO
		folio_put(folio);
#else
		put_page(page);
#endif
		offset += amount;
		output += amount;
		length -= amount;
	}
	return 0;
}

static int ntfs_rs_read_unlocked(void *context, u64 offset,
			   unsigned char *output, size_t length)
{
	struct super_block *sb = context;
	struct ntfs_rs_super *state = sb ? sb->s_fs_info : NULL;
	int result;

	if (!sb || (!output && length) || offset > U64_MAX - length)
		return -EINVAL;
	result = ntfs_rs_plain_read(context, offset, output, length);
	if (!result)
		ntfs_rs_overlay_held(state, offset, output, length);
	return result;
}

/* Direct reads include metadata overlays but never read user data through
 * the buffer cache. Partial final sectors use an owned bounce buffer. The
 * caller has completed cached writeback and holds io_lock. */
static int ntfs_rs_plain_direct_read(void *context, u64 offset, unsigned char *output, size_t length)
{
    struct super_block *sb = context;
    unsigned int sector = bdev_logical_block_size(sb->s_bdev);
    unsigned char *bounce;
    int error = 0;
    if (offset > U64_MAX - length) return -EINVAL;
    bounce = kmalloc(NTFS_RS_BUFFER_BYTES, GFP_NOFS);
    if (!bounce) return -ENOMEM;
    while (length) {
        u64 base = round_down(offset, sector);
        size_t head = offset - base;
        size_t n = min_t(size_t, length, NTFS_RS_BUFFER_BYTES - head);
        size_t bytes = round_up(head + n, sector);
        error = ntfs_rs_rw_span(sb, base, bounce, bytes, false);
        if (error) break;
        memcpy(output, bounce + head, n);
        offset += n; output += n; length -= n;
    }
    kfree(bounce);
    return error;
}

static int ntfs_rs_direct_read_at(void *context, u64 offset, unsigned char *output, size_t length)
{
    struct super_block *sb = context;
    struct ntfs_rs_super *state = sb->s_fs_info;
    int error;
    if (offset > U64_MAX - length) return -EINVAL;
    error = ntfs_rs_plain_direct_read(context, offset, output, length);
    if (!error)
        ntfs_rs_overlay_held(state, offset, output, length);
    return error;
}

static int ntfs_rs_read_at(void *context, u64 offset, unsigned char *output, size_t length)
{
	struct super_block *sb = context;
	struct ntfs_rs_super *state = sb->s_fs_info;
	int result;
	/* Also exclude writer initialization during a read-only -> writable remount. */
	down_read(&state->io_lock);
	result = ntfs_rs_read_unlocked(context, offset, output, length);
	up_read(&state->io_lock);
	return result;
}

/* Stage device bytes in the block device's page cache. sync_blockdev in
 * ntfs_rs_flush persists these pages before the device cache flush. */
static int ntfs_rs_plain_write(void *context, u64 offset, const unsigned char *input, size_t length)
{
	struct super_block *sb = context;
	struct address_space *mapping = NTFS_RS_BLOCK_CACHE(sb);
	u64 bytes;

	if (sb->s_fs_info)
		ntfs_rs_table_changed(sb->s_fs_info, offset, length);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
	bytes = bdev_nr_bytes(sb->s_bdev);
#else
	bytes = i_size_read(sb->s_bdev->bd_inode);
#endif
	if (offset > bytes || length > bytes - offset)
		return -EIO;
	while (length) {
		size_t within = offset_in_page(offset);
		size_t amount = min(length, (size_t)PAGE_SIZE - within);
		bool full_page = !within && amount == PAGE_SIZE;
#ifdef NTFS_RS_BDEV_FOLIO_IO
		struct folio *folio;
		bool grabbed = false;
#else
		struct page *page;
#endif
		void *address;

#ifdef NTFS_RS_BDEV_FOLIO_IO
#ifdef NTFS_RS_BDEV_GRAB_FOLIO
		if (full_page) {
			folio = filemap_grab_folio(mapping, offset >> PAGE_SHIFT);
			grabbed = true;
		} else
#endif
			folio = read_mapping_folio(mapping, offset >> PAGE_SHIFT, NULL);
		if (IS_ERR(folio))
			return PTR_ERR(folio);
		if (!grabbed)
			folio_lock(folio);
		if (unlikely(folio->mapping != mapping ||
			     (!full_page && !folio_test_uptodate(folio)))) {
			folio_unlock(folio);
			folio_put(folio);
			return -EIO;
		}
		address = kmap_local_folio(folio, offset - folio_pos(folio) - within);
		memcpy((unsigned char *)address + within, input, amount);
		kunmap_local(address);
		flush_dcache_folio(folio);
		if (full_page)
			folio_mark_uptodate(folio);
		folio_mark_dirty(folio);
		folio_unlock(folio);
		folio_put(folio);
#else
		if (full_page)
			page = grab_cache_page(mapping, offset >> PAGE_SHIFT);
		else
			page = read_mapping_page(mapping, offset >> PAGE_SHIFT, NULL);
		if (IS_ERR(page))
			return PTR_ERR(page);
		if (!page)
			return -ENOMEM;
		if (!full_page)
			lock_page(page);
		if (unlikely(page->mapping != mapping ||
			     (!full_page && !PageUptodate(page)))) {
			unlock_page(page);
			put_page(page);
			return -EIO;
		}
		address = kmap_local_page(page);
		memcpy((unsigned char *)address + within, input, amount);
		kunmap_local(address);
		flush_dcache_page(page);
		if (full_page)
			SetPageUptodate(page);
		set_page_dirty(page);
		unlock_page(page);
		put_page(page);
#endif
		offset += amount;
		input += amount;
		length -= amount;
	}
	return 0;
}

static int ntfs_rs_write_at(void *context, u64 offset, const unsigned char *input, size_t length)
{
	return ntfs_rs_plain_write(context, offset, input, length);
}

static int ntfs_rs_plain_direct_write(void *context, u64 offset, const unsigned char *input, size_t length);

/* Only staged stream bytes use this entry point. The journal still uses
 * write_at. Flush and invalidate overlapping block-cache pages before DMA,
 * so a later metadata/data read cannot return an old cached sector. */
int ntfs_rs_write_data_at(void *context, u64 offset, const unsigned char *input, size_t length)
{
    struct super_block *sb = context;
    struct ntfs_rs_super *state = sb->s_fs_info;
    if (!state->direct_io) return ntfs_rs_write_at(context, offset, input, length);
    return ntfs_rs_plain_direct_write(context, offset, input, length);
}

/* Synchronous bios for whole logical-block ranges, after flushing and
 * invalidating overlapping block-cache pages. */
static int ntfs_rs_plain_direct_write(void *context, u64 offset, const unsigned char *input, size_t length)
{
    struct super_block *sb = context;
    struct address_space *mapping;
    unsigned char *bounce;
    u64 device_bytes;
    unsigned int sector = bdev_logical_block_size(sb->s_bdev);
    int error;
    if (!length) return 0;
    if ((offset | length) & (sector - 1)) return -EINVAL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
    device_bytes = bdev_nr_bytes(sb->s_bdev);
#else
    device_bytes = i_size_read(sb->s_bdev->bd_inode);
#endif
    if (offset > device_bytes || length > device_bytes - offset) return -EINVAL;
    mapping = NTFS_RS_BLOCK_CACHE(sb);
    error = filemap_write_and_wait_range(mapping, offset & PAGE_MASK, (offset + length - 1) | (PAGE_SIZE - 1));
    if (error) return error;
    error = invalidate_inode_pages2_range(mapping, offset >> PAGE_SHIFT, (offset + length - 1) >> PAGE_SHIFT);
    if (error == -EBUSY) {
        /* Drop idle block-device cache references before the retry. */
        invalidate_bdev(sb->s_bdev);
        error = invalidate_inode_pages2_range(mapping, offset >> PAGE_SHIFT,
                                              (offset + length - 1) >> PAGE_SHIFT);
    }
    if (error) return error;
    bounce = kmalloc(NTFS_RS_BUFFER_BYTES, GFP_NOFS);
    if (!bounce) return -ENOMEM;
    while (length) {
        size_t n = min_t(size_t, length, NTFS_RS_BUFFER_BYTES);
        memcpy(bounce, input, n);
        error = ntfs_rs_rw_span(sb, offset, bounce, n, true);
        if (error) break;
        offset += n; input += n; length -= n;
    }
    kfree(bounce);
    return error;
}

static int ntfs_rs_flush(void *context)
{
	struct super_block *sb = context;
	struct ntfs_rs_super *state = sb->s_fs_info;
	int result = sync_blockdev(sb->s_bdev);
	if (!result)
		result = ntfs_rs_issue_flush(sb->s_bdev);
	if (!result && ++state->flushes == READ_ONCE(fail_after_flush) &&
	    MAJOR(sb->s_bdev->bd_dev) == LOOP_MAJOR)
		return -EIO;
	return result;
}

/* Caller holds io_lock exclusively. Rust decides when the queued transaction
 * reaches its durable boundary; the adapter only implements its I/O calls. */
/* Grow the file table, when the coming create, link or rename needs it, from
 * this shallow frame: the growth's commit descends far into the block layer. */
static int ntfs_rs_reserve_records(struct ntfs_rs_super *state, unsigned char *scratch)
{
    return state->write_failed ? -EIO :
        ntfs_rs_writer_reserve(state->writer, NTFS_RS_IO(state->sb), scratch);
}

static int ntfs_rs_drain_locked(struct super_block *sb, bool checkpoint)
{
	struct ntfs_rs_super *state = sb->s_fs_info;
	int result;
	if (!state->writer_ready || state->write_failed)
		return -EIO;
	state->flushes = 0;
	result = ntfs_rs_writer_drain(state->writer, NTFS_RS_IO(sb),
                                    state->op_scratch, checkpoint);

	if (result)
		ntfs_rs_poison(state, __func__);
	return result;
}

/* Drain a crowded batch now, near the top of the stack. Left to the operation
 * that fills it, the drain and its device flush run beneath that operation's
 * own frames, and together they come close to the kernel stack's limit.
 * Caller holds io_lock exclusively. */
static void ntfs_rs_make_room(struct ntfs_rs_super *state)
{
	if (!state->writer_ready || state->write_failed || !ntfs_rs_writer_crowded(state->writer))
		return;
	/* Only room is wanted here, not durability: Rust journals the batch and
	 * leaves its device flush to the next barrier or the periodic drain. */
	state->flushes = 0;
	if (ntfs_rs_writer_make_room(state->writer, NTFS_RS_IO(state->sb), state->op_scratch))
		ntfs_rs_poison(state, __func__);
}

/* Write back staged device pages and flush the device cache without io_lock.
 * A commit flush after a large copy can otherwise hold io_lock for seconds
 * while the disk settles, stalling every lookup on the volume. */
static void ntfs_rs_settle_device(struct super_block *sb)
{
    if (!sync_blockdev(sb->s_bdev)) {
        ntfs_rs_issue_flush(sb->s_bdev);
    }
}

/* Caller holds io_lock exclusively. Once a healthy session has seen no change
 * for a full drain interval and no file is open for writing, publish the clean
 * volume state, so unplugging an idle volume needs no recovery. The writer
 * resumes, marking the volume dirty again, before its next change. */
static void ntfs_rs_park_if_idle(struct ntfs_rs_super *state)
{
    int parked = 0;
    u64 activity = ntfs_rs_writer_activity(state->writer, &parked);
    bool idle = !parked && activity == state->idle_activity &&
        !ntfs_rs_writer_pending(state->writer) &&
        !atomic_read(&state->write_opens) && list_empty_careful(&state->reclaim_list);

    state->idle_activity = activity;
    /* A frozen volume must not be written; try again on a later tick. */
    if (!idle || !sb_start_write_trylock(state->sb)) {
        return;
    }
    state->flushes = 0;
    if (ntfs_rs_writer_park(state->writer, NTFS_RS_IO(state->sb), state->op_scratch)) {
        ntfs_rs_poison(state, __func__);
    }
    sb_end_write(state->sb);
}

static void ntfs_rs_drain_work(struct work_struct *work)
{
	struct ntfs_rs_super *state = container_of(to_delayed_work(work),
					struct ntfs_rs_super, drain_work);
	bool pending;

	/* Settle the device only when a drain is due, so an idle disk stays idle. */
	down_read(&state->io_lock);
	pending = state->writer_ready && !state->write_failed && ntfs_rs_writer_pending(state->writer);
	up_read(&state->io_lock);
	if (pending) {
		ntfs_rs_settle_device(state->sb);
	}
	down_write(&state->io_lock);
	if (state->writer_ready && !state->write_failed) {
		if (ntfs_rs_writer_pending(state->writer))
			ntfs_rs_drain_locked(state->sb, false);
		if (!state->write_failed)
			ntfs_rs_park_if_idle(state);
	}
	up_write(&state->io_lock);
	if (READ_ONCE(state->drain_scheduled) && state->writer_ready && !state->write_failed)
		queue_delayed_work(system_unbound_wq, &state->drain_work,
                msecs_to_jiffies(NTFS_RS_DEFERRED_DRAIN_MS));
}

/* Start writeback of staged block-cache pages without waiting for it. The
 * cache never holds uncommitted metadata (pending images stay held), so its
 * pages may reach the disk at any time; drains still flush before commits. */
static void ntfs_rs_writeback_work(struct work_struct *work)
{
	struct ntfs_rs_super *state = container_of(work, struct ntfs_rs_super, writeback_work);

	filemap_flush(NTFS_RS_BLOCK_CACHE(state->sb));
}

static const struct inode_operations ntfs_rs_dir_inode_ops;
static const struct inode_operations ntfs_rs_file_inode_ops;
static const struct inode_operations ntfs_rs_symlink_inode_ops;
static int ntfs_rs_fsync(struct file *, loff_t, loff_t, int);
static int ntfs_rs_write_inode(struct inode *, struct writeback_control *);
static int ntfs_rs_break_leases(struct inode *, unsigned int);
static const struct file_operations ntfs_rs_dir_file_ops;
static const struct file_operations ntfs_rs_file_ops;
static const struct address_space_operations ntfs_rs_aops;

/* Every journaled operation: exclusive volume lock, fresh crash counter,
 * refusal once the session is poisoned. An I/O error poisons the session. */
static int ntfs_rs_begin(struct ntfs_rs_super *state)
{
	down_write(&state->io_lock);
	ntfs_rs_make_room(state);
	state->flushes = 0;
	return state->write_failed || !state->writer_ready ? -EIO : 0;
}

static int ntfs_rs_end(struct ntfs_rs_super *state, int result)
{
	if (result == -EIO)
		ntfs_rs_poison(state, __func__);
	up_write(&state->io_lock);
	return result;
}

static bool ntfs_rs_writable(struct inode *inode)
{
	const struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
	return !ntfs_rs_readonly(inode) && state->writer;
}

/* Resolve and copy the inode's descriptor without publishing it. */
static struct ntfs_rs_security *ntfs_rs_read_descriptor(struct inode *inode, int *error)
{
	struct super_block *sb = inode->i_sb;
	struct ntfs_rs_security *security = NULL;
	const struct ntfs_rs_super *state = sb->s_fs_info;
	unsigned char *scratch;
	int result;

	scratch = ntfs_rs_scratch_get(state, NTFS_RS_SECURITY_BYTES);
	if (!scratch) {
		*error = -ENOMEM;
		return NULL;
	}
	result = ntfs_rs_load_security(state->boot, 512, sb, ntfs_rs_read_unlocked,
			scratch, NTFS_RS_SECURITY_BYTES, NTFS_RS_REF(inode));
	if (result > 0 && result <= NTFS_RS_MAX_DESCRIPTOR) {
		security = kvmalloc(sizeof(*security) + result, GFP_NOFS);
		if (!security) {
			result = -ENOMEM;
		} else {
			security->length = result;
			memcpy(security->data, scratch, result);
			result = 0;
		}
	} else if (result >= 0) {
		result = -EIO;
	}
	ntfs_rs_scratch_put(state, scratch, NTFS_RS_SECURITY_BYTES);
	*error = result;
	return security;
}

/* A $Secure ID names one descriptor for good, and thousands of files share a
 * few: keep each loaded one for the mount and hand new inodes a copy. */
static struct ntfs_rs_security *ntfs_rs_shared_descriptor(struct ntfs_rs_super *state, u32 security_id)
{
	const struct ntfs_rs_security *kept;
	struct ntfs_rs_security *copy = NULL;

	if (!security_id)
		return NULL;
	kept = xa_load(&state->descriptors, security_id);
	if (kept) {
		copy = kvmalloc(sizeof(*copy) + kept->length, GFP_NOFS);
		if (copy)
			memcpy(copy, kept, sizeof(*copy) + kept->length);
	}
	return copy;
}

static void ntfs_rs_keep_descriptor(struct ntfs_rs_super *state, u32 security_id,
		const struct ntfs_rs_security *security)
{
	struct ntfs_rs_security *kept;

	if (!security_id || atomic_read(&state->descriptor_count) >= NTFS_RS_KEPT_DESCRIPTORS)
		return;
	kept = kvmalloc(sizeof(*kept) + security->length, GFP_NOFS);
	if (!kept)
		return;
	memcpy(kept, security, sizeof(*kept) + security->length);
	/* Entries live until unmount, so readers need no reference. */
	if (xa_insert(&state->descriptors, security_id, kept, GFP_NOFS))
		kvfree(kept);
	else
		atomic_inc(&state->descriptor_count);
}

static int ntfs_rs_cache_security(struct inode *inode, u32 security_id)
{
	struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
	struct ntfs_rs_inode *private = inode->i_private;
	struct ntfs_rs_security *security = ntfs_rs_shared_descriptor(state, security_id);
	int result = 0;

	if (security) {
		RCU_INIT_POINTER(private->security, security);
		return 0;
	}
	down_read(&state->io_lock);
	security = ntfs_rs_read_descriptor(inode, &result);
	if (security)
		RCU_INIT_POINTER(private->security, security);
	up_read(&state->io_lock);
	if (security)
		ntfs_rs_keep_descriptor(state, security_id, security);
	return result;
}

/* C captures Linux credentials and owns I/O buffers. All SID conversion,
 * descriptor lookup and policy decisions happen in Rust. No capability
 * bypass is used: Linux root must have an explicit mapping and pass the DACL.
 * A zero rights mask loads ownership only, without granting any access. */
/* Capture the complete filesystem identity: fsuid, fsgid and every
 * supplementary group. Rust requires all of them to be mapped. */
static int ntfs_rs_caller(u32 *uid, u32 *gids, unsigned int *count, bool groups)
{
	const struct cred *cred = current_cred();
	unsigned int i;

	if (groups && cred->group_info->ngroups >= NTFS_RS_MAX_GROUPS)
		return -E2BIG;
	*uid = from_kuid(&init_user_ns, cred->fsuid);
	gids[0] = from_kgid(&init_user_ns, cred->fsgid);
	*count = 1;
	if (groups) {
		for (i = 0; i < cred->group_info->ngroups; i++)
			gids[(*count)++] = from_kgid(&init_user_ns, cred->group_info->gid[i]);
	}
	return 0;
}

static const struct ntfs_rs_security *ntfs_rs_descriptor_rcu(struct inode *inode)
{
	const struct ntfs_rs_inode *private = ntfs_rs_shared(inode);
	return private ? rcu_dereference(private->security) : NULL;
}

static struct ntfs_rs_identity *ntfs_rs_identity_new(const char *sidmap)
{
	size_t head = ALIGN(sizeof(struct ntfs_rs_identity), 16);
	size_t map_size = ALIGN(ntfs_rs_sidmap_size(), 16);
	size_t text = strlen(sidmap) + 1;
	struct ntfs_rs_identity *ident = kvzalloc(head + map_size + text, GFP_KERNEL);
	int result;
	if (!ident)
		return ERR_PTR(-ENOMEM);
	ident->map = (char *)ident + head;
	ident->sidmap = (char *)ident->map + map_size;
	memcpy(ident->sidmap, sidmap, text);
	result = ntfs_rs_compile_sidmap((const unsigned char *)ident->sidmap, text - 1,
		ident->map, ntfs_rs_sidmap_size());
	if (result) {
		kvfree(ident);
		return ERR_PTR(result);
	}
	return ident;
}

/* For callers holding io_lock (the writer paths): stable until they drop it. */
static void *ntfs_rs_identity_locked(const struct ntfs_rs_super *state)
{
	return rcu_dereference_protected(state->ident, 1)->map;
}

/* ----- permissions=desktop ----------------------------------------------
 * Windows rights requested by the bridge are mapped onto Linux r/w/x of the
 * mount-wide owner, group or others, with ordinary root privileges. This is
 * a Linux-visible permission baseline only: nothing here reads or changes the
 * stored descriptors, and read-only mounts and the Windows read-only
 * attribute are enforced by the callers exactly as in windows mode. */
#define NTFS_RS_DESKTOP_R (NTFS_RS_READ_DATA | NTFS_RS_READ_EA)
#define NTFS_RS_DESKTOP_W (NTFS_RS_WRITE_DATA | NTFS_RS_ADD_SUBDIRECTORY | NTFS_RS_WRITE_EA | \
			   NTFS_RS_DELETE_CHILD | NTFS_RS_WRITE_ATTRIBUTES)
#define NTFS_RS_DESKTOP_X NTFS_RS_EXECUTE
#define NTFS_RS_DESKTOP_FREE (NTFS_RS_READ_ATTRIBUTES | NTFS_RS_READ_CONTROL | NTFS_RS_SYNCHRONIZE)
#define NTFS_RS_DESKTOP_ADMIN (NTFS_RS_WRITE_DAC | NTFS_RS_WRITE_OWNER)

static int ntfs_rs_desktop_check(struct inode *inode, const struct ntfs_rs_access *access, u32 rights)
{
	kuid_t fsuid = current_fsuid();
	bool owner = uid_eq(fsuid, access->uid);
	umode_t mode;
	unsigned int want = 0, bits;

	if (!rights) {
		/* Numeric ownership for stat and VFS owner checks. */
		inode->i_uid = access->uid;
		inode->i_gid = access->gid;
		return 0;
	}
	if (rights & ~(NTFS_RS_DESKTOP_R | NTFS_RS_DESKTOP_W | NTFS_RS_DESKTOP_X |
		       NTFS_RS_DESKTOP_FREE | NTFS_RS_DESKTOP_ADMIN | NTFS_RS_DELETE))
		return -EACCES; /* Unknown rights fail closed. */
	/* Unix deletion is decided by the parent directory: refusing DELETE on
	 * the object makes callers fall back to FILE_DELETE_CHILD there. */
	if (rights & NTFS_RS_DELETE)
		return -EACCES;
	/* Descriptor and owner edits stay administrator-only; chmod/chown are
	 * accepted without effect in setattr, as NTFS-3G's default "silent". */
	if (rights & NTFS_RS_DESKTOP_ADMIN)
		return capable(CAP_FOWNER) ? 0 : -EPERM;
	if (rights & NTFS_RS_DESKTOP_R)
		want |= 4;
	if (rights & (NTFS_RS_DESKTOP_W & ~NTFS_RS_WRITE_ATTRIBUTES))
		want |= 2;
	else if ((rights & NTFS_RS_WRITE_ATTRIBUTES) && !owner)
		want |= 2; /* Like utimes: the owner, or anyone who may write. */
	if (rights & NTFS_RS_DESKTOP_X)
		want |= 1;
	if (!want)
		return 0;
	mode = S_ISDIR(inode->i_mode) ? access->dir_mode :
	       S_ISLNK(inode->i_mode) ? 0777 : access->file_mode;
	if (owner)
		bits = (mode >> 6) & 7;
	else if (in_group_p(access->gid))
		bits = (mode >> 3) & 7;
	else
		bits = mode & 7;
	if ((bits & want) == want)
		return 0;
	/* The same privilege rules as generic_permission(). */
	if (S_ISDIR(inode->i_mode) || !(want & 1) || (mode & 0111)) {
		if (capable(CAP_DAC_OVERRIDE))
			return 0;
	}
	if (!(want & 2) && (S_ISDIR(inode->i_mode) || !(want & 1)) &&
	    capable(CAP_DAC_READ_SEARCH))
		return 0;
	return -EACCES;
}

/* Returns true and the mount-wide owner when permissions=desktop is active. */
static bool ntfs_rs_desktop_owner(struct super_block *sb, kuid_t *uid, kgid_t *gid)
{
	const struct ntfs_rs_super *state = sb->s_fs_info;
	const struct ntfs_rs_access *access;
	bool desktop = false;
	rcu_read_lock();
	access = state ? rcu_dereference(state->access) : NULL;
	if (access && access->desktop) {
		desktop = true;
		if (uid) *uid = access->uid;
		if (gid) *gid = access->gid;
	}
	rcu_read_unlock();
	return desktop;
}

/* Build the policy for a new mount (old == NULL) or a remount. */
static struct ntfs_rs_access *ntfs_rs_access_from(const struct ntfs_rs_options *options,
						   const struct ntfs_rs_access *old)
{
	struct ntfs_rs_access *access = kzalloc(sizeof(*access), GFP_KERNEL);
	if (!access)
		return ERR_PTR(-ENOMEM);
	if (old) {
		access->desktop = old->desktop;
		access->uid = old->uid;
		access->gid = old->gid;
		access->file_mode = old->file_mode;
		access->dir_mode = old->dir_mode;
	} else {
		/* NTFS-3G defaults: the mounting user; files 0600, directories 0700. */
		access->uid = current_fsuid();
		access->gid = current_fsgid();
		access->file_mode = 0600;
		access->dir_mode = 0700;
	}
	if (options->permissions >= 0)
		access->desktop = options->permissions;
	if (options->uid_set)
		access->uid = make_kuid(&init_user_ns, options->uid);
	if (options->gid_set)
		access->gid = make_kgid(&init_user_ns, options->gid);
	if (options->fmask_set)
		access->file_mode = 0777 & ~options->fmask;
	if (options->dmask_set)
		access->dir_mode = 0777 & ~options->dmask;
	if (!uid_valid(access->uid) || !gid_valid(access->gid)) {
		kfree(access);
		return ERR_PTR(-EINVAL);
	}
	return access;
}

static bool ntfs_rs_access_options_set(const struct ntfs_rs_options *options)
{
	return options->permissions >= 0 || options->uid_set || options->gid_set ||
	       options->fmask_set || options->dmask_set;
}

static int ntfs_rs_authorize(struct inode *inode, u32 rights, bool rcu_walk)
{
	struct super_block *sb = inode->i_sb;
	const struct ntfs_rs_super *state = sb->s_fs_info;
	const struct ntfs_rs_security *security;
	u32 gids[NTFS_RS_MAX_GROUPS], owners[2], uid;
	unsigned int count;
	int result;

	if (!state || !rcu_access_pointer(state->ident))
		return rcu_walk ? -ECHILD : -EACCES;
	rcu_read_lock();
	{
		const struct ntfs_rs_access *access = rcu_dereference(state->access);
		if (access && access->desktop) {
			result = ntfs_rs_desktop_check(inode, access, rights);
			rcu_read_unlock();
			return result;
		}
	}
	rcu_read_unlock();
	result = ntfs_rs_caller(&uid, gids, &count, rights != 0);
	if (result)
		return result;
	/* A concurrent descriptor change replaces the RCU pointer; the old copy
	 * stays valid until this RCU read-side section ends. */
	rcu_read_lock();
	security = ntfs_rs_descriptor_rcu(inode);
	if (!security) {
		rcu_read_unlock();
		return rcu_walk ? -ECHILD : -EACCES;
	}
	result = ntfs_rs_check_security(security->data, security->length,
			rcu_dereference(state->ident)->map, uid, gids, count, rights, owners);
	rcu_read_unlock();
	if (!result && !rights) {
		/* Numeric ownership is for stat; it never replaces the native ACL. */
		inode->i_uid = make_kuid(&init_user_ns, owners[0] == U32_MAX ? 65534 : owners[0]);
		inode->i_gid = make_kgid(&init_user_ns, owners[1] == U32_MAX ? 65534 : owners[1]);
	}
	return result;
}

/* DELETE on the object, or FILE_DELETE_CHILD on its directory. Native views
 * also honour the Windows read-only attribute, which forbids deletion. */
static int ntfs_rs_may_delete(struct inode *parent, struct inode *inode)
{
	int result;
	if (ntfs_rs_native(parent) && S_ISREG(inode->i_mode) &&
	    (READ_ONCE(ntfs_rs_shared(inode)->attributes) & NTFS_RS_ATTR_READONLY))
		return -EACCES;
	result = ntfs_rs_authorize(inode, NTFS_RS_DELETE, false);
	if (result == -EACCES)
		result = ntfs_rs_authorize(parent, NTFS_RS_DELETE_CHILD, false);
	return result;
}

/* Publish the on-disk descriptor after a committed change. Rust re-resolves
 * $SII/$SDH/$SDS exactly as for a fresh inode, so this also verifies the
 * committed metadata. Readers see either the complete old or the complete new
 * copy. If resolution fails, the inode is left without a descriptor, so every
 * later access check fails closed. The caller holds io_lock and refreshes
 * other projections after releasing it. */
static int ntfs_rs_reload_security(struct inode *inode)
{
	struct ntfs_rs_inode *private = ntfs_rs_shared(inode);
	struct ntfs_rs_security *old, *fresh;
	int result;
	inode = ntfs_rs_canonical(inode);
	old = rcu_dereference_protected(private->security, 1);
	fresh = ntfs_rs_read_descriptor(inode, &result);
	/* Contents are complete before the pointer becomes visible. */
	rcu_assign_pointer(private->security, fresh);
	if (old)
		kvfree_rcu(old, rcu);
	if (!result)
		ntfs_rs_authorize(inode, 0, false); /* refresh stat ownership */
	return result;
}

/* One journaled descriptor replacement. The caller holds the inode lock
 * (VFS setxattr/notify_change), serializing descriptor publication. */
static int ntfs_rs_apply_security(struct inode *inode, const void *value, size_t size,
				  bool owner_only, u32 new_uid, u32 new_gid)
{
	struct super_block *sb = inode->i_sb;
	struct ntfs_rs_super *state = sb->s_fs_info;
	u32 gids[NTFS_RS_MAX_GROUPS], uid;
	unsigned int count;
	unsigned char *scratch;
	int result;

	if (!ntfs_rs_writable(inode))
		return -EROFS;
	if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode) && !S_ISLNK(inode->i_mode))
		return -EOPNOTSUPP;
	result = ntfs_rs_caller(&uid, gids, &count, true);
	if (result)
		return result;
	scratch = state->op_scratch;
	if (!scratch)
		return -ENOMEM;
	result = ntfs_rs_begin(state);
	if (!result && owner_only) {
		result = ntfs_rs_writer_chown(state->writer, NTFS_RS_IO(sb), scratch,
			NTFS_RS_REF(inode), new_uid, new_gid, ntfs_rs_identity_locked(state), uid, gids, count);
	} else if (!result) {
		result = ntfs_rs_writer_set_security(state->writer, NTFS_RS_IO(sb), scratch,
			NTFS_RS_REF(inode), value, size, ntfs_rs_identity_locked(state), uid, gids, count);
	}
	if (result == -EIO)
		ntfs_rs_poison(state, __func__);
	/* Publish the shared descriptor before releasing the writer lock. */
	if (!result)
		result = ntfs_rs_reload_security(inode);
	if (result == -EIO)
		pr_err("slate-ntfs descriptor update I/O error, writer_ready=%d failed=%d\n",
			state->writer_ready, state->write_failed);
	ntfs_rs_end(state, result);
	if (scratch != state->op_scratch) kvfree(scratch);
	if (!result) {
		ntfs_rs_touch(inode, false);
		ntfs_rs_sync_projection(inode);
		ntfs_rs_notify_peers(inode, FS_ATTRIB, NULL, 0, NULL);
	}
	return result;
}

/* ----- Extended attributes ------------------------------------------------ */

/* Read one EA of the canonical record under a consistent volume snapshot. */
static int ntfs_rs_read_ea(struct inode *inode, const char *name, void *buffer, size_t size)
{
	struct super_block *sb = inode->i_sb;
	struct ntfs_rs_super *state = sb->s_fs_info;
	unsigned char *scratch = kvzalloc(ntfs_rs_ea_scratch_size(), GFP_NOFS);
	int result;
	if (!scratch)
		return -ENOMEM;
	down_read(&state->io_lock);
	result = ntfs_rs_get_ea(state->boot, sb, ntfs_rs_read_unlocked, scratch,
		NTFS_RS_REF(ntfs_rs_canonical(inode)), (const unsigned char *)name, strlen(name),
		buffer, size);
	up_read(&state->io_lock);
	if (scratch != state->op_scratch) kvfree(scratch);
	return result;
}

/* One journaled EA edit; mode (or U32_MAX) replaces $LXMOD atomically. */
static int ntfs_rs_write_ea(struct inode *inode, const char *name, const void *value,
			    size_t size, bool remove, u32 flags, u32 mode)
{
	struct super_block *sb = inode->i_sb;
	struct ntfs_rs_super *state = sb->s_fs_info;
	unsigned char *scratch;
	int result;
	if (!ntfs_rs_writable(inode))
		return -EROFS;
	scratch = state->op_scratch;
	if (!scratch)
		return -ENOMEM;
	result = ntfs_rs_begin(state);
	if (!result)
		result = ntfs_rs_writer_set_ea(state->writer, NTFS_RS_IO(sb), scratch,
			NTFS_RS_REF(ntfs_rs_canonical(inode)), (const unsigned char *)name,
			strlen(name), value, size, remove, flags, mode);
	ntfs_rs_end(state, result);
	if (scratch != state->op_scratch) kvfree(scratch);
	return result;
}

static int ntfs_rs_security_get(const struct xattr_handler *handler,
				struct dentry *dentry, struct inode *inode,
				const char *name, void *buffer, size_t size)
{
	const struct ntfs_rs_security *security;
	const struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
	u32 uid, gids[NTFS_RS_MAX_GROUPS], owners[2];
	unsigned int count;
	int result;

	(void)handler; (void)dentry; (void)name;
	result = ntfs_rs_caller(&uid, gids, &count, true);
	if (result)
		return result;
	rcu_read_lock();
	security = ntfs_rs_descriptor_rcu(inode);
	if (!security) {
		result = -EACCES;
		goto out;
	}
	/* Authorize the same immutable snapshot that is returned below. */
	result = ntfs_rs_check_security(security->data, security->length,
		rcu_dereference(state->ident)->map, uid, gids, count, NTFS_RS_READ_CONTROL, owners);
	if (result)
		goto out;
	if (!size)
		result = security->length;
	else if (size < security->length)
		result = -ERANGE;
	else {
		memcpy(buffer, security->data, security->length);
		result = security->length;
	}
out:
	rcu_read_unlock();
	return result;
}

static int ntfs_rs_security_set(const struct xattr_handler *handler,
				NTFS_RS_XATTR_IDMAP struct dentry *dentry,
				struct inode *inode, const char *name,
				const void *value, size_t size, int flags)
{
	(void)handler; NTFS_RS_XATTR_IDMAP_UNUSED; (void)dentry; (void)name;
	/* Every file keeps a descriptor: removal is not an NTFS operation. */
	if (!value)
		return -EOPNOTSUPP;
	if (flags & XATTR_CREATE)
		return -EEXIST;
	if (size < 20 || size > NTFS_RS_MAX_DESCRIPTOR)
		return -EINVAL;
	return ntfs_rs_apply_security(inode, value, size, false, 0, 0);
}

/* Same name and raw self-relative format as the upstream ntfs3 driver. */
static const struct xattr_handler ntfs_rs_security_xattr = {
	.name = "system.ntfs_security",
	.get = ntfs_rs_security_get,
	.set = ntfs_rs_security_set,
};

/* Windows file attributes as a little-endian u32 (ntfs3/NTFS-3G name). */
static int ntfs_rs_attrib_get(const struct xattr_handler *handler,
			      struct dentry *dentry, struct inode *inode,
			      const char *name, void *buffer, size_t size)
{
	__le32 value;
	int result;
	(void)handler; (void)dentry; (void)name;
	result = ntfs_rs_authorize(inode, NTFS_RS_READ_ATTRIBUTES, false);
	if (result)
		return result;
	if (!size)
		return sizeof(value);
	if (size < sizeof(value))
		return -ERANGE;
	value = cpu_to_le32(READ_ONCE(ntfs_rs_shared(inode)->attributes));
	memcpy(buffer, &value, sizeof(value));
	return sizeof(value);
}

static int ntfs_rs_attrib_set(const struct xattr_handler *handler,
			      NTFS_RS_XATTR_IDMAP struct dentry *dentry,
			      struct inode *inode, const char *name,
			      const void *value, size_t size, int flags)
{
	struct super_block *sb = inode->i_sb;
	struct ntfs_rs_super *state = sb->s_fs_info;
	struct ntfs_rs_inode *shared = ntfs_rs_shared(inode);
	u64 times[4] = { 0 };
	unsigned char *scratch;
	__le32 raw;
	u32 wanted, old;
	int result;
	(void)handler; NTFS_RS_XATTR_IDMAP_UNUSED; (void)dentry; (void)name;
	if (!value)
		return -EOPNOTSUPP;
	if (flags & XATTR_CREATE)
		return -EEXIST;
	if (size != sizeof(raw))
		return -EINVAL;
	if (!ntfs_rs_writable(inode))
		return -EROFS;
	memcpy(&raw, value, sizeof(raw));
	wanted = le32_to_cpu(raw) & ~0x80U; /* FILE_ATTRIBUTE_NORMAL is not stored */
	old = READ_ONCE(shared->attributes);
	/* Structural flags (directory, reparse, sparse, ...) follow the layout. */
	if ((wanted ^ old) & ~NTFS_RS_ATTR_SETTABLE)
		return -EINVAL;
	result = ntfs_rs_authorize(inode, NTFS_RS_WRITE_ATTRIBUTES, false);
	if (result)
		return result;
	scratch = state->op_scratch;
	if (!scratch)
		return -ENOMEM;
	result = ntfs_rs_begin(state);
	if (!result)
		result = ntfs_rs_writer_set_times(state->writer, NTFS_RS_IO(sb), scratch,
			NTFS_RS_REF(ntfs_rs_canonical(inode)), times, 0, NTFS_RS_ATTR_SETTABLE, wanted);
	if (!result)
		WRITE_ONCE(shared->attributes, (old & ~NTFS_RS_ATTR_SETTABLE) |
			(wanted & NTFS_RS_ATTR_SETTABLE));
	ntfs_rs_end(state, result);
	if (scratch != state->op_scratch) kvfree(scratch);
	if (!result) {
		ntfs_rs_touch(inode, false);
		ntfs_rs_notify_peers(inode, FS_ATTRIB, NULL, 0, NULL);
	}
	return result;
}

/* Generic flags expose only semantics already encoded by NTFS. Windows
 * readonly is not Linux immutable, and hidden/system have no chattr bits. */
static int ntfs_rs_flags_get(struct dentry *dentry, u32 *result)
{
    struct inode *inode = d_inode(dentry);
    u32 attrs = READ_ONCE(ntfs_rs_shared(inode)->attributes), flags = 0;
    int error = ntfs_rs_authorize(inode, NTFS_RS_READ_ATTRIBUTES, false);
    if (error) return error;
    if (attrs & 0x0800U) flags |= FS_COMPR_FL;
    if (attrs & 0x4000U) flags |= FS_ENCRYPT_FL;
    if (!ntfs_rs_native(inode)) flags |= READ_ONCE(ntfs_rs_shared(inode)->linux_flags);
    *result = flags;
    return 0;
}
static int ntfs_rs_flags_set(struct dentry *dentry, u32 flags)
{
    struct inode *view = d_inode(dentry), *inode = ntfs_rs_canonical(view);
    struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
    u32 existing;
    __le32 stored = cpu_to_le32(flags & NTFS_RS_LINUX_FLAGS);
    static const unsigned char name[] = "$SLATE_FLAGS";
    int error;
    if (ntfs_rs_readonly(view)) return -EROFS;
    error = ntfs_rs_flags_get(dentry, &existing);
    if (error) return error;
    if (ntfs_rs_native(view)) return flags == existing ? 0 : -EOPNOTSUPP;
    if ((flags ^ existing) & ~NTFS_RS_LINUX_FLAGS) return -EOPNOTSUPP;
    error = ntfs_rs_authorize(inode, NTFS_RS_WRITE_ATTRIBUTES | NTFS_RS_WRITE_EA, false);
    if (error) return error;
    if (inode != view) inode_lock(inode);
    filemap_invalidate_lock(inode->i_mapping);
    unmap_mapping_range(inode->i_mapping, 0, 0, 1);
    error = filemap_write_and_wait(inode->i_mapping);
    if (!error) {
        down_write(&state->io_lock);
        ntfs_rs_make_room(state);
        error = state->write_failed || !state->writer_ready ? -EIO :
            ntfs_rs_writer_set_ea(state->writer, NTFS_RS_IO(inode->i_sb), state->op_scratch,
                NTFS_RS_REF(inode), name, sizeof(name)-1, (unsigned char *)&stored, sizeof(stored), 0, 0, U32_MAX);
        if (!error) error = ntfs_rs_drain_locked(inode->i_sb, false);
        if (!error) {
            WRITE_ONCE(ntfs_rs_shared(inode)->linux_flags, flags & NTFS_RS_LINUX_FLAGS);
            ntfs_rs_apply_linux_flags(inode);
            ntfs_rs_sync_projection(inode);
        }
        if (error == -EIO) ntfs_rs_poison(state, __func__);
        up_write(&state->io_lock);
    }
    filemap_invalidate_unlock(inode->i_mapping);
    if (inode != view) inode_unlock(inode);
    if (!error) { ntfs_rs_touch(view, false); ntfs_rs_notify_peers(view, FS_ATTRIB, NULL, 0, NULL); }
    return error;
}

#ifdef NTFS_RS_FILEATTR_H
static int ntfs_rs_fileattr_get(struct dentry *dentry, NTFS_RS_FILEATTR *fa)
{
    u32 flags;
    int error = ntfs_rs_flags_get(dentry, &flags);
    if (!error) fileattr_fill_flags(fa, flags);
    return error;
}

static int ntfs_rs_fileattr_set(NTFS_RS_IDMAP *idmap, struct dentry *dentry,
                              NTFS_RS_FILEATTR *fa)
{
    (void)idmap;
    if (fileattr_has_fsx(fa)) return -EOPNOTSUPP;
    return ntfs_rs_flags_set(dentry, fa->flags);
}
#endif

static const struct xattr_handler ntfs_rs_attrib_xattr = {
	.name = "system.ntfs_attrib",
	.get = ntfs_rs_attrib_get,
	.set = ntfs_rs_attrib_set,
};

/* Read-only presence query for explicit flag-backup restoration. GETFLAGS
 * alone cannot distinguish a missing EA from an intentionally stored zero. */
static int ntfs_rs_linux_flags_get(const struct xattr_handler *handler,
        struct dentry *dentry, struct inode *inode, const char *name,
        void *buffer, size_t size)
{
    int error;
    (void)handler; (void)dentry; (void)name;
    error = ntfs_rs_authorize(inode, NTFS_RS_READ_EA, false);
    return error ?: ntfs_rs_read_ea(inode, "$SLATE_FLAGS", size ? buffer : NULL, size);
}
static const struct xattr_handler ntfs_rs_linux_flags_xattr = {
    .name = "system.ntfs_linux_flags",
    .get = ntfs_rs_linux_flags_get,
};

/* Linux xattrs are native EAs named with the full Linux name
 * (ntfs3 layout). Native FILE_READ_EA/FILE_WRITE_EA rights apply on top of
 * the VFS namespace checks (trusted.* needs CAP_SYS_ADMIN). */
static int ntfs_rs_ea_name(const struct xattr_handler *handler, const char *name,
			   char *full)
{
	size_t prefix = strlen(handler->prefix), length = strlen(name);
	if (!length || prefix + length > XATTR_NAME_MAX)
		return -ERANGE;
	memcpy(full, handler->prefix, prefix);
	memcpy(full + prefix, name, length + 1);
	return 0;
}

static int ntfs_rs_ea_get(const struct xattr_handler *handler,
			  struct dentry *dentry, struct inode *inode,
			  const char *name, void *buffer, size_t size)
{
	char full[XATTR_NAME_MAX + 1];
	int result;
	(void)dentry;
	result = ntfs_rs_ea_name(handler, name, full);
	/* LSM label loading and capability stripping are kernel operations, not
	 * discretionary EA reads by the process that triggered them. The VFS/LSM
	 * checks security.* access before calling the namespace handler. */
	if (!result && strcmp(handler->prefix, XATTR_SECURITY_PREFIX))
		result = ntfs_rs_authorize(inode, NTFS_RS_READ_EA, false);
	if (!result)
		result = ntfs_rs_read_ea(inode, full, size ? buffer : NULL, size);
	return result;
}

static int ntfs_rs_ea_set(const struct xattr_handler *handler,
			  NTFS_RS_XATTR_IDMAP struct dentry *dentry,
			  struct inode *inode, const char *name,
			  const void *value, size_t size, int flags)
{
	char full[XATTR_NAME_MAX + 1];
	struct inode *canonical = ntfs_rs_canonical(inode);
	bool security = !strcmp(handler->prefix, XATTR_SECURITY_PREFIX);
	int result;
	NTFS_RS_XATTR_IDMAP_UNUSED; (void)dentry;
	if (value && size > NTFS_RS_MAX_EA_VALUE)
		return -E2BIG;
	result = ntfs_rs_ea_name(handler, name, full);
	if (!result && strcmp(handler->prefix, XATTR_SECURITY_PREFIX))
		result = ntfs_rs_authorize(inode, NTFS_RS_WRITE_EA, false);
	/* Serialize a view's capability changes with writes through the shared
	 * backing inode, whose lock protects VFS privilege stripping. */
	if (security && inode != canonical) inode_lock(canonical);
	if (!result)
		result = ntfs_rs_write_ea(inode, full, value, value ? size : 0, !value,
			flags & (XATTR_CREATE | XATTR_REPLACE), U32_MAX);
	if (result == -ENOSPC)
		result = -E2BIG;
	if (!result) {
		if (!strcmp(handler->prefix, XATTR_SECURITY_PREFIX)) {
			unsigned int policy;
			/* Views share EAs, but each inode has its own LSM/NOSEC cache. */
			for (policy = ntfs_rs_next_policy(inode, 0); policy != U32_MAX;
                    policy = ntfs_rs_next_policy(inode, policy + 1)) {
				struct inode *peer = ntfs_rs_peer(ntfs_rs_canonical(inode), policy);
				if (!peer) continue;
				inode_set_flags(peer, 0, S_NOSEC);
				if (peer != inode) security_inode_invalidate_secctx(peer);
				iput(peer);
			}
		}
		ntfs_rs_touch(inode, false);
		ntfs_rs_notify_peers(inode, FS_ATTRIB, NULL, 0, NULL);
	}
	if (security && inode != canonical) inode_unlock(canonical);
	return result;
}

static const struct xattr_handler ntfs_rs_user_xattr = {
	.prefix = XATTR_USER_PREFIX,
	.get = ntfs_rs_ea_get,
	.set = ntfs_rs_ea_set,
};

static const struct xattr_handler ntfs_rs_trusted_xattr = {
	.prefix = XATTR_TRUSTED_PREFIX,
	.get = ntfs_rs_ea_get,
	.set = ntfs_rs_ea_set,
};

/* Linux security namespaces remain active in both views of this mount.
 * Windows and ntfs-3g see ordinary, interoperable NTFS EAs. */
static const struct xattr_handler ntfs_rs_lsm_xattr = {
	.prefix = XATTR_SECURITY_PREFIX,
	.get = ntfs_rs_ea_get,
	.set = ntfs_rs_ea_set,
};

static const struct xattr_handler *ntfs_rs_xattr_handlers[] = {
	&ntfs_rs_security_xattr,
	&ntfs_rs_attrib_xattr,
	&ntfs_rs_linux_flags_xattr,
	&ntfs_rs_user_xattr,
	&ntfs_rs_trusted_xattr,
	&ntfs_rs_lsm_xattr,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0) && IS_ENABLED(CONFIG_FS_POSIX_ACL)
	/* Before 6.2 the VFS reaches ->get_acl/->set_acl through these. */
	&posix_acl_access_xattr_handler,
	&posix_acl_default_xattr_handler,
#endif
	NULL,
};

/* List security.*, user.* (regular files and directories), trusted.* (CAP_SYS_ADMIN)
 * and, in Linux mode, stored POSIX ACL names. system.ntfs_* stays unlisted,
 * as with NTFS-3G, so copy tools do not replay raw NTFS metadata. */
static ssize_t ntfs_rs_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	struct inode *inode = d_inode(dentry);
	struct super_block *sb = inode->i_sb;
	struct ntfs_rs_super *state = sb->s_fs_info;
	unsigned char *scratch, *names;
	bool user = S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode);
	bool trusted = capable(CAP_SYS_ADMIN);
	bool acls = !ntfs_rs_native(inode) && IS_ENABLED(CONFIG_FS_POSIX_ACL);
	size_t used = 0;
	int total, at = 0;

	total = ntfs_rs_authorize(inode, NTFS_RS_READ_EA, false);
	if (total)
		return total;
	scratch = kvzalloc(ntfs_rs_ea_scratch_size(), GFP_NOFS);
	names = kvzalloc(NTFS_RS_BUFFER_BYTES * 2, GFP_NOFS);
	if (!scratch || !names) {
		total = -ENOMEM;
		goto out;
	}
	down_read(&state->io_lock);
	total = ntfs_rs_list_ea(state->boot, sb, ntfs_rs_read_unlocked, scratch,
		NTFS_RS_REF(ntfs_rs_canonical(inode)), names, NTFS_RS_BUFFER_BYTES * 2);
	up_read(&state->io_lock);
	if (total < 0)
		goto out;
	while (at < total) {
		const char *name = (const char *)names + at;
		size_t length = strnlen(name, total - at);
		bool listed = (user && !strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN)) ||
			(trusted && !strncmp(name, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN)) ||
			!strncmp(name, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN) ||
			(acls && (!strcmp(name, XATTR_NAME_POSIX_ACL_ACCESS) ||
				  !strcmp(name, XATTR_NAME_POSIX_ACL_DEFAULT)));
		at += length + 1;
		if (!listed || length > XATTR_NAME_MAX)
			continue;
		if (size) {
			if (used + length + 1 > size) {
				total = -ERANGE;
				goto out;
			}
			memcpy(buffer + used, name, length + 1);
		}
		used += length + 1;
	}
	total = used;
out:
	kvfree(names);
	if (scratch != state->op_scratch) kvfree(scratch);
	return total;
}

/* ----- POSIX ACLs (Linux mode) --------------------------------------------- */

#if IS_ENABLED(CONFIG_FS_POSIX_ACL)
static struct posix_acl *ntfs_rs_get_inode_acl(struct inode *inode, int type, bool rcu)
{
	struct posix_acl *acl;
	void *buffer;
	int size;
	if (rcu)
		return ERR_PTR(-ECHILD);
	if (ntfs_rs_native(inode))
		return NULL;
	if (type != ACL_TYPE_ACCESS && type != ACL_TYPE_DEFAULT)
		return ERR_PTR(-EINVAL);
	buffer = kvmalloc(NTFS_RS_MAX_EA_VALUE, GFP_NOFS);
	if (!buffer)
		return ERR_PTR(-ENOMEM);
	size = ntfs_rs_read_ea(inode, type == ACL_TYPE_ACCESS ? XATTR_NAME_POSIX_ACL_ACCESS :
		XATTR_NAME_POSIX_ACL_DEFAULT, buffer, NTFS_RS_MAX_EA_VALUE);
	if (size == -ENODATA)
		acl = NULL;
	else if (size < 0)
		acl = ERR_PTR(size);
	else
		acl = posix_acl_from_xattr(&init_user_ns, buffer, size);
	kvfree(buffer);
	return acl;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
static struct posix_acl *ntfs_rs_get_acl_old(struct inode *inode, int type)
{
    return ntfs_rs_get_inode_acl(inode, type, false);
}
#endif

/* Refresh every cached Linux projection; native projections never use ACLs. */
static void ntfs_rs_cache_acl(struct inode *canonical, int type, struct posix_acl *acl)
{
	unsigned int policy;
	for (policy = ntfs_rs_next_policy(canonical, 0); policy != U32_MAX;
            policy = ntfs_rs_next_policy(canonical, policy + 2)) {
		struct inode *peer = ntfs_rs_peer(canonical, policy);
		if (!peer)
			continue;
		set_cached_acl(peer, type, acl);
		iput(peer);
	}
}

/* Keep the packed-EA caller contract across allocating/nonallocating ACL APIs. */
static int ntfs_rs_acl_to_xattr(struct user_namespace *ns,
        const struct posix_acl *acl, void *value, size_t capacity)
{
#ifdef NTFS_RS_ACL_XATTR_ALLOC
    size_t size;
    void *encoded = posix_acl_to_xattr(ns, acl, &size, GFP_NOFS);
    if (IS_ERR(encoded))
        return PTR_ERR(encoded);
    if (size > capacity) {
        kfree(encoded);
        return -ERANGE;
    }
    memcpy(value, encoded, size);
    kfree(encoded);
    return size;
#else
    return posix_acl_to_xattr(ns, acl, value, capacity);
#endif
}

static int ntfs_rs_set_acl_inode(NTFS_RS_IDMAP *idmap, struct inode *inode,
				 struct posix_acl *acl, int type)
{
	struct inode *canonical = ntfs_rs_canonical(inode);
	umode_t mode = canonical->i_mode;
	u32 new_mode = U32_MAX;
	void *value = NULL;
	int size = 0, result;

	if (ntfs_rs_native(inode))
		return -EOPNOTSUPP;
	if (!ntfs_rs_writable(inode))
		return -EROFS;
	/* POSIX ACLs are Linux permission metadata, like chmod: native WRITE_DAC. */
	result = ntfs_rs_authorize(inode, NTFS_RS_WRITE_DAC, false);
	if (result)
		return result;
	if (type == ACL_TYPE_ACCESS) {
		if (acl) {
			result = ntfs_rs_acl_update_mode(idmap, canonical, &mode, &acl);
			if (result)
				return result;
		}
		if (mode != canonical->i_mode)
			new_mode = mode & 07777;
	} else if (type == ACL_TYPE_DEFAULT) {
		if (!S_ISDIR(canonical->i_mode))
			return acl ? -EACCES : 0;
	} else {
		return -EINVAL;
	}
	if (acl) {
		size = posix_acl_xattr_size(acl->a_count);
		value = kvmalloc(size, GFP_NOFS);
		if (!value)
			return -ENOMEM;
		size = ntfs_rs_acl_to_xattr(&init_user_ns, acl, value, size);
		if (size < 0) {
			kvfree(value);
			return size;
		}
		if (size > NTFS_RS_MAX_EA_VALUE) {
			kvfree(value);
			return -E2BIG;
		}
	}
	/* Flag 4: removing an absent ACL is a no-op, but a mode change still applies. */
	result = ntfs_rs_write_ea(canonical, type == ACL_TYPE_ACCESS ? XATTR_NAME_POSIX_ACL_ACCESS :
		XATTR_NAME_POSIX_ACL_DEFAULT, value, value ? size : 0, !acl, 4, new_mode);
	kvfree(value);
	if (result == -ENOSPC)
		result = -E2BIG;
	if (result)
		return result;
	if (new_mode != U32_MAX) {
		canonical->i_mode = (canonical->i_mode & S_IFMT) | new_mode;
		WRITE_ONCE(ntfs_rs_shared(inode)->unix_mode, true);
	}
	ntfs_rs_cache_acl(canonical, type, acl);
	ntfs_rs_touch(canonical, false);
	ntfs_rs_sync_projection(canonical);
	ntfs_rs_notify_peers(inode, FS_ATTRIB, NULL, 0, NULL);
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
static int ntfs_rs_set_acl(NTFS_RS_IDMAP *idmap, struct dentry *dentry,
			   struct posix_acl *acl, int type)
{
	return ntfs_rs_set_acl_inode(idmap, d_inode(dentry), acl, type);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
static int ntfs_rs_set_acl(struct user_namespace *idmap, struct inode *inode,
			   struct posix_acl *acl, int type)
{
	return ntfs_rs_set_acl_inode(idmap, inode, acl, type);
}
#else
static int ntfs_rs_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
    return ntfs_rs_set_acl_inode(&init_user_ns, inode, acl, type);
}
#endif

static int ntfs_rs_chmod_acl(NTFS_RS_IDMAP *idmap, struct dentry *dentry, umode_t mode)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
	return posix_acl_chmod(idmap, dentry, mode);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	return posix_acl_chmod(idmap, d_inode(dentry), mode);
#else
	return posix_acl_chmod(d_inode(dentry), mode);
#endif
}
#endif /* CONFIG_FS_POSIX_ACL */

/* ----- Permission and attributes ----------------------------------------- */

static int ntfs_rs_permission(NTFS_RS_CALLBACK_IDMAP struct inode *inode, int mask)
{
	NTFS_RS_CALLBACK_IDMAP_INIT;
	u32 rights = 0;
	struct ntfs_rs_inode *private = ntfs_rs_shared(inode);
	if ((mask & MAY_EXEC) && S_ISREG(inode->i_mode) && (ntfs_rs_limits(inode) & NTFS_RS_VIEW_NOEXEC))
		return -EACCES;
	if (!ntfs_rs_native(inode) && private && READ_ONCE(private->unix_mode) &&
	    !ntfs_rs_desktop_owner(inode->i_sb, NULL, NULL)) {
		/* Linux mode: mode bits and POSIX ACLs constrain; the DACL still decides. */
		int result = ntfs_rs_generic_permission(idmap, ntfs_rs_canonical(inode), mask);
		if (result)
			return result;
	}
	(void)idmap; /* FS_ALLOW_IDMAP is deliberately not advertised. */
	/* The evaluator borrows immutable metadata and uses only bounded stack
	 * space. RCU readers may run without allocations, I/O or sleeping locks. */
	if (mask & ~(MAY_READ | MAY_WRITE | MAY_EXEC | MAY_APPEND | MAY_ACCESS | MAY_OPEN | MAY_CHDIR | MAY_NOT_BLOCK))
		return -EACCES;
	if (mask & (MAY_WRITE | MAY_APPEND)) {
		struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
		if (ntfs_rs_readonly(inode) || !state->writer)
			return -EROFS;

		/* Desktop permissions must check a directory's write bit too. GIO
		 * probes W_OK with MAY_ACCESS to decide whether Files offers create,
		 * paste, rename and delete. In Windows mode use FILE_ADD_FILE for
		 * that probe; mutations still check their precise DACL rights below. */
		if (S_ISDIR(inode->i_mode) &&
		    ((mask & MAY_ACCESS) || ntfs_rs_desktop_owner(inode->i_sb, NULL, NULL)))
			rights |= NTFS_RS_WRITE_DATA; /* FILE_ADD_FILE for directories */
		if (S_ISREG(inode->i_mode)) {
			/* The Windows read-only attribute forbids data writes. */
			if (private && (READ_ONCE(private->attributes) & NTFS_RS_ATTR_READONLY))
				return -EACCES;
			rights |= NTFS_RS_WRITE_DATA;
		}
	}
	if (mask & MAY_READ)
		rights |= NTFS_RS_READ_DATA; /* FILE_READ_DATA / FILE_LIST_DIRECTORY */
	if (mask & (MAY_EXEC | MAY_CHDIR))
		rights |= NTFS_RS_EXECUTE; /* FILE_EXECUTE / FILE_TRAVERSE */
	return rights ? ntfs_rs_authorize(inode, rights, mask & MAY_NOT_BLOCK) : 0;
}

static int ntfs_rs_getattr(NTFS_RS_CALLBACK_IDMAP const struct path *path,
			   struct kstat *stat, u32 request_mask, unsigned int flags)
{
	NTFS_RS_CALLBACK_IDMAP_INIT;
	struct inode *view = d_inode(path->dentry);
	struct inode *inode = ntfs_rs_canonical(view);
	struct ntfs_rs_inode *shared = ntfs_rs_shared(view);
	int result = ntfs_rs_authorize(inode, NTFS_RS_READ_ATTRIBUTES, false);
    (void)idmap;
    (void)flags;
    if (result) return result;
    /* Owners shown by stat follow the current SID map, which remount may replace. */
    if (!ntfs_rs_desktop_owner(inode->i_sb, NULL, NULL))
        ntfs_rs_authorize(inode, 0, false);
    /* The allocation is read from the record once and again after anything
     * that may have changed it; a file open for writing is always read. */
    if (!atomic_read(&shared->blocks_known) || atomic_read(&shared->writers) > 0) {
        struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
        struct ntfs_rs_node info;
        unsigned char *scratch = ntfs_rs_scratch_get(state, ntfs_rs_ea_scratch_size());
        bool settled = atomic_read(&shared->writers) <= 0;
        if (!scratch) return -ENOMEM;
        if (settled) atomic_set(&shared->blocks_known, 1);
        result = ntfs_rs_stat(state->boot, 512, inode->i_sb, ntfs_rs_read_at,
            scratch, ntfs_rs_ea_scratch_size(), inode->i_ino, inode->i_generation, &info);
        ntfs_rs_scratch_put(state, scratch, ntfs_rs_ea_scratch_size());
        if (result) { atomic_set(&shared->blocks_known, 0); return result; }
        inode->i_blocks = DIV_ROUND_UP_ULL(info.allocated, 512);
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	generic_fillattr(idmap, request_mask, inode, stat);
#else
	ntfs_rs_generic_fillattr(idmap, inode, stat);
#endif
	{
		kuid_t owner_uid = GLOBAL_ROOT_UID;
		kgid_t owner_gid = GLOBAL_ROOT_GID;
		const struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
		const struct ntfs_rs_access *access;
		umode_t desktop_mode = 0;
		bool desktop = false;
		rcu_read_lock();
		access = rcu_dereference(state->access);
		if (access && access->desktop) {
			desktop = true;
			owner_uid = access->uid;
			owner_gid = access->gid;
			desktop_mode = S_ISDIR(inode->i_mode) ? access->dir_mode : access->file_mode;
		}
		rcu_read_unlock();
		if (desktop) {
			/* Keep VFS owner checks (utimes, sticky) in step with a remount. */
			inode->i_uid = owner_uid;
			inode->i_gid = owner_gid;
			stat->uid = owner_uid;
			stat->gid = owner_gid;
			if (!S_ISLNK(inode->i_mode)) {
				stat->mode = (stat->mode & S_IFMT) | desktop_mode;
				if (S_ISREG(inode->i_mode) &&
				    (READ_ONCE(shared->attributes) & NTFS_RS_ATTR_READONLY))
					stat->mode &= ~0222; /* Windows read-only attribute */
			}
			goto desktop_done;
		}
	}
	if (S_ISLNK(inode->i_mode))
		stat->mode = S_IFLNK | 0777;
	else if (ntfs_rs_native(view))
		stat->mode = (stat->mode & S_IFMT) | 0555;
	else if (S_ISREG(inode->i_mode) && (READ_ONCE(shared->attributes) & NTFS_RS_ATTR_READONLY))
		stat->mode &= ~0222; /* Windows read-only attribute */
desktop_done:
    if (ntfs_rs_native(view)) stat->attributes &= ~(STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND);
    stat->attributes_mask |= STATX_ATTR_COMPRESSED | STATX_ATTR_ENCRYPTED;
    if (READ_ONCE(shared->attributes) & 0x0800) stat->attributes |= STATX_ATTR_COMPRESSED;
    if (READ_ONCE(shared->attributes) & 0x4000) stat->attributes |= STATX_ATTR_ENCRYPTED;
	if (request_mask & STATX_BTIME) {
		stat->btime = ntfs_rs_to_ts(shared->created);
		stat->result_mask |= STATX_BTIME;
	}
	return 0;
}

static int ntfs_rs_inode_identity(struct inode *inode, void *data)
{
	const struct ntfs_rs_key *key = data;
    struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
    struct ntfs_rs_visibility *policy;
	/* iget5's set callback runs under the inode hash lock. */
	struct ntfs_rs_inode *p = kzalloc(sizeof(*p), GFP_ATOMIC);
	if (!p)
		return -ENOMEM;
    xa_lock(&state->visibility);
    policy = xa_load(&state->visibility, key->limits >> 2);
    if (!policy) {
        xa_unlock(&state->visibility);
        kfree(p);
        return -ESTALE;
    }
    refcount_inc(&policy->references);
    xa_unlock(&state->visibility);
	p->native_mode = key->native;
	p->limits = key->limits;
	atomic_set(&p->open_files, 0);
	atomic_long_set(&p->directory_epoch, 1);
	inode->i_private = p;
	inode->i_ino = key->reference & NTFS_RS_RECORD_MASK;
	inode->i_generation = key->reference >> 48;
	return 0;
}

static struct inode *ntfs_rs_get_inode(struct super_block *sb,
		const struct ntfs_rs_node *info, bool native, unsigned int limits,
		struct inode *created)
{
	struct ntfs_rs_key key = { info->file_reference, native, limits };
	struct inode *canonical = NULL, *inode;
	struct ntfs_rs_inode *p;
	int result;
	if ((info->file_reference & NTFS_RS_RECORD_MASK) > ULONG_MAX ||
	    info->data_size > MAX_LFS_FILESIZE) {
		iput(created);
		return ERR_PTR(-EOVERFLOW);
	}
	if (native || limits) {
		canonical = ntfs_rs_get_inode(sb, info, false, 0, created);
		created = NULL;
		if (IS_ERR(canonical))
			return canonical;
	}
	/* Keep the creation hook's LSM blob on the real, cached inode. */
	if (created) {
		inode = inode_insert5(created, ntfs_rs_hash(&key),
			ntfs_rs_inode_matches, ntfs_rs_inode_identity, &key);
		if (inode != created) iput(created);
	} else {
		inode = iget5_locked(sb, ntfs_rs_hash(&key),
			ntfs_rs_inode_matches, ntfs_rs_inode_identity, &key);
	}
	if (!inode) {
		iput(canonical);
		return ERR_PTR(-ENOMEM);
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 0)
	if (!(inode_state_read(inode) & I_NEW)) {
#else
	if (!(inode->i_state & I_NEW)) {
#endif
		iput(canonical);
		return inode;
	}
	p = inode->i_private;
	p->canonical = canonical;
    inode->i_mode = (info->reparse_tag ? S_IFLNK : (info->flags & 2 ? S_IFDIR : S_IFREG)) | 0555;
    p->attributes = info->attributes;
    p->linux_flags = info->linux_flags;
    p->created = info->times[0];
    memcpy(p->persisted_times, &info->times[1], sizeof(p->persisted_times));
    ntfs_rs_set_mtime(inode, ntfs_rs_to_ts(info->times[1]));
    ntfs_rs_set_ctime(inode, ntfs_rs_to_ts(info->times[2]));
    ntfs_rs_set_atime(inode, ntfs_rs_to_ts(info->times[3]));
    inode->i_blocks = DIV_ROUND_UP_ULL(info->allocated, 512);
    inode->i_op = info->reparse_tag ? &ntfs_rs_symlink_inode_ops :
        (info->flags & 2 ? &ntfs_rs_dir_inode_ops : &ntfs_rs_file_inode_ops);
    inode->i_fop = info->reparse_tag ? NULL :
        (info->flags & 2 ? &ntfs_rs_dir_file_ops : &ntfs_rs_file_ops);
	if (!info->reparse_tag && info->mode != U32_MAX &&
        !S_ISREG(info->mode) && !S_ISDIR(info->mode))
        init_special_inode(inode, info->mode, info->reserved);
    /* NTFS directory link counts do not count child directories. Keep a
     * stable value across eviction/remount, rather than decrementing an
     * incomplete child count to zero when removing existing children. */
    set_nlink(inode, info->flags & 2 ? 2 : info->links);
	i_size_write(inode, info->data_size);
	if (canonical) {
		/* There is only one data mapping, even with two inode projections. */
		inode->i_mapping = canonical->i_mapping;
		inode->i_uid = canonical->i_uid;
		inode->i_gid = canonical->i_gid;
		i_size_write(inode, i_size_read(canonical));
		set_nlink(inode, canonical->i_nlink);
        inode->i_blocks = canonical->i_blocks;
        ntfs_rs_set_atime(inode, ntfs_rs_get_atime(canonical));
        ntfs_rs_set_mtime(inode, ntfs_rs_get_mtime(canonical));
        ntfs_rs_set_ctime(inode, ntfs_rs_get_ctime(canonical));
		if (!native)
			inode->i_mode = canonical->i_mode;
		result = 0;
	} else {
		inode->i_mapping->a_ops = &ntfs_rs_aops;
		atomic_set(&p->blocks_known, 1);
		result = ntfs_rs_cache_security(inode, info->security_id);
		if (!result) {
			p->unix_mode = info->mode != U32_MAX;
			if (p->unix_mode)
				inode->i_mode = (inode->i_mode & S_IFMT) | (info->mode & 07777);
			result = ntfs_rs_authorize(inode, 0, false);
		}
	}
	if (result) {
		iget_failed(inode);
		return ERR_PTR(result);
	}
    ntfs_rs_apply_linux_flags(inode);
	unlock_new_inode(inode);
	return inode;
}

/* Build a missing projection from its pinned canonical object, including
 * an orphan whose on-disk name has already been removed. */
static struct inode *ntfs_rs_project_inode(struct inode *origin, unsigned int policy)
{
    struct inode *canonical = ntfs_rs_canonical(origin);
    struct ntfs_rs_node info = {
        .file_reference = NTFS_RS_REF(canonical), .data_size = i_size_read(canonical),
        .flags = S_ISDIR(canonical->i_mode) ? 3 : 1, .mode = canonical->i_mode,
        .links = canonical->i_nlink, .allocated = canonical->i_blocks << 9,
        .attributes = ntfs_rs_shared(origin)->attributes,
        .linux_flags = ntfs_rs_shared(origin)->linux_flags,
        .reparse_tag = S_ISLNK(canonical->i_mode) ? 1 : 0,
        .reserved = canonical->i_rdev,
        .times = { ntfs_rs_shared(origin)->created,
            ntfs_rs_from_ts(ntfs_rs_get_mtime(canonical)),
            ntfs_rs_from_ts(ntfs_rs_get_ctime(canonical)),
            ntfs_rs_from_ts(ntfs_rs_get_atime(canonical)) },
    };
    return ntfs_rs_get_inode(origin->i_sb, &info, policy & 1, policy >> 1, NULL);
}

/* Refresh the other projection without waiting for an I_NEW inode whose
 * initialization may itself be waiting for io_lock. Canonical data is primary. */
static void ntfs_rs_sync_projection(struct inode *inode)
{
	struct inode *canonical = ntfs_rs_canonical(inode), *peer;
	unsigned int policy;
	if (is_sxid(canonical->i_mode)) inode_set_flags(canonical, 0, S_NOSEC);
	/* Refresh all live visibility policies and inherited restrictions. */
	for (policy = ntfs_rs_next_policy(canonical, 1); policy != U32_MAX;
            policy = ntfs_rs_next_policy(canonical, policy + 1)) {
	bool initializing;
	struct ntfs_rs_key key = {
		canonical->i_ino | ((u64)canonical->i_generation << 48),
		policy & 1, policy >> 1,
	};
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 0)
	peer = ilookup5_nowait(inode->i_sb, ntfs_rs_hash(&key),
		ntfs_rs_inode_matches, &key, &initializing);
#else
	peer = ilookup5_nowait(inode->i_sb, ntfs_rs_hash(&key),
		ntfs_rs_inode_matches, &key);
	initializing = peer && (peer->i_state & I_NEW);
#endif
	if (!peer)
		continue;
	if (!initializing) {
        ntfs_rs_apply_linux_flags(peer);
		peer->i_uid = canonical->i_uid;
		peer->i_gid = canonical->i_gid;
		if (!key.native)
			peer->i_mode = canonical->i_mode;
		if (is_sxid(peer->i_mode)) inode_set_flags(peer, 0, S_NOSEC);
		i_size_write(peer, i_size_read(canonical));
		set_nlink(peer, canonical->i_nlink);
        peer->i_blocks = canonical->i_blocks;
        ntfs_rs_set_atime(peer, ntfs_rs_get_atime(canonical));
        ntfs_rs_set_mtime(peer, ntfs_rs_get_mtime(canonical));
        ntfs_rs_set_ctime(peer, ntfs_rs_get_ctime(canonical));
	}
	iput(peer);
	}
}

static struct dentry *ntfs_rs_lookup(struct inode *parent,
				     struct dentry *dentry, unsigned int flags)
{
	struct super_block *sb = parent->i_sb;
	struct ntfs_rs_node info;
	const struct ntfs_rs_super *state = sb->s_fs_info;
	struct inode *inode;
	struct dentry *alias = NULL;
	void *epoch;
	unsigned char *scratch;
	u64 reference;
	int result;

	(void)flags;
	epoch = (void *)atomic_long_read(&ntfs_rs_shared(parent)->directory_epoch);
	dentry->d_fsdata = epoch;
	result = ntfs_rs_resolve_name(parent, &dentry->d_name, &reference);
	if (result == -ENOENT) {
		d_add(dentry, NULL);
		return NULL;
	}
	if (result)
		return ERR_PTR(result);
	scratch = ntfs_rs_scratch_get(state, NTFS_RS_LOOKUP_BYTES);
	if (!scratch) {
		return ERR_PTR(-ENOMEM);
	}
	result = ntfs_rs_stat(state->boot, 512, sb, ntfs_rs_read_at,
			      scratch, ntfs_rs_ea_scratch_size(),
			      reference & NTFS_RS_RECORD_MASK, reference >> 48,
			      &info);
	if (result)
		goto out;

    inode = ntfs_rs_get_inode(sb, &info, ntfs_rs_native(parent), ntfs_rs_limits(parent), NULL);
	if (IS_ERR(inode)) {
		result = PTR_ERR(inode);
		goto out;
	}
	/* Exportfs reconnects file handles through anonymous aliases.  Positive
	 * lookup must splice those aliases into the namespace instead of blindly
	 * adding a second dentry for the same inode.  This is also the contract
	 * required by filesystems that set s_export_op. */
	alias = d_splice_alias(inode, dentry);
	if (IS_ERR(alias)) {
		result = PTR_ERR(alias);
		alias = NULL;
	} else if (alias) {
		/* d_splice_alias may return a previously disconnected dentry rather
		 * than the candidate passed above.  Give that alias the same namespace
		 * epoch so the cross-view revalidator does not immediately discard it. */
		alias->d_fsdata = epoch;
	}
out:
	ntfs_rs_scratch_put(state, scratch, NTFS_RS_LOOKUP_BYTES);
	return result ? ERR_PTR(result) : alias;
}

static int ntfs_rs_open(struct inode *, struct file *);
static int ntfs_rs_release(struct inode *, struct file *);

/* Per open directory: the view's backing file (or NULL) and the last name
 * returned with the position after it. A read continuing from that position
 * resumes after the name, so entries deleted meanwhile do not shift it. */
struct ntfs_rs_dir_file {
    struct file *backing;
    loff_t pos;
    size_t length;
    unsigned char name[NAME_MAX];
};

struct ntfs_rs_dir_walk {
    struct dir_context *position;
    struct ntfs_rs_dir_file *cursor;
    bool resuming;
};

static int ntfs_rs_emit(void *context, const unsigned char *name,
                        size_t length, u64 reference, u64 ordinal, u32 kind)
{
    struct ntfs_rs_dir_walk *walk = context;
    struct dir_context *position = walk->position;
    loff_t next;

    if (!length || length > NAME_MAX)
        return -ENAMETOOLONG;
    if (ordinal > LLONG_MAX - 3)
        return -EOVERFLOW;
    /* Hidden entries consume Rust ordinals. Counting only emitted names
     * resumes too early on the next getdents buffer. Keep the current entry
     * cookie when the buffer is full; dots retain positions zero and one.
     * A name-based resume numbers on from the cursor instead. */
    if (!walk->resuming)
        position->pos = ordinal + 2;
    next = walk->resuming ? position->pos + 1 : (loff_t)ordinal + 3;
    /* kind is the entry's file type as the index tells it, or 0. Programs
     * take a stated type as the answer and DT_UNKNOWN as a reason to stat. */
    if (!dir_emit(position, name, length, reference & NTFS_RS_RECORD_MASK,
                  kind ? S_DT(kind) : DT_UNKNOWN))
        return 1;
    position->pos = next;
    if (walk->cursor) {
        memcpy(walk->cursor->name, name, length);
        walk->cursor->length = length;
        walk->cursor->pos = next;
    }
    return 0;
}

static int ntfs_rs_iterate(struct file *file, struct dir_context *position)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	const struct ntfs_rs_super *state = sb->s_fs_info;
	struct ntfs_rs_dir_file *cursor = file->private_data;
	struct ntfs_rs_dir_walk walk = { position, cursor, false };
	unsigned char resume[NAME_MAX];
	size_t resume_length = 0;
	size_t scratch_bytes;
	unsigned char *scratch;
	u64 reference;
	int result;

	if (!dir_emit_dots(file, position))
		return 0;
	/* Continue after the last returned name only when this read starts where
	 * the previous one stopped; a seek or rewind uses the ordinal position. */
	if (cursor && cursor->length && cursor->pos == position->pos) {
		memcpy(resume, cursor->name, cursor->length);
		resume_length = cursor->length;
		walk.resuming = true;
	}
	/* Past the first call's needs, the space holds index blocks per level. */
	scratch_bytes = resume_length || state->upcase ? NTFS_RS_LOOKUP_BYTES : NTFS_RS_SCRATCH_BYTES;
	scratch = ntfs_rs_scratch_get(state, scratch_bytes);
	if (!scratch) {
		return -ENOMEM;
	}
	reference = inode->i_ino | ((u64)inode->i_generation << 48);
	result = ntfs_rs_readdir(state->boot, 512, sb, ntfs_rs_read_at,
				 scratch, scratch_bytes, reference,
				 position->pos - 2, resume_length ? resume : NULL, resume_length,
				 ntfs_rs_visibility_flags(inode), state->upcase, &walk, ntfs_rs_emit);
	ntfs_rs_scratch_put(state, scratch, scratch_bytes);
	return result;
}

static int ntfs_rs_dir_open(struct inode *inode, struct file *file)
{
    struct ntfs_rs_dir_file *cursor = kzalloc(sizeof(*cursor), GFP_KERNEL);
    int result;

    if (!cursor)
        return -ENOMEM;
    result = ntfs_rs_open(inode, file);
    if (result) {
        kfree(cursor);
        return result;
    }
    cursor->backing = file->private_data;
    file->private_data = cursor;
    return 0;
}

static int ntfs_rs_dir_release(struct inode *inode, struct file *file)
{
    struct ntfs_rs_dir_file *cursor = file->private_data;

    file->private_data = cursor ? cursor->backing : NULL;
    kfree(cursor);
    return ntfs_rs_release(inode, file);
}

/* Extents one read batch may load straight into page-cache pages. */
#define NTFS_RS_MAP_EXTENTS 8U
#define NTFS_RS_BATCH_PAGES (NTFS_RS_READAHEAD_BYTES / PAGE_SIZE)

struct ntfs_rs_extent_map {
	u64 logical[NTFS_RS_MAP_EXTENTS];
	u64 physical[NTFS_RS_MAP_EXTENTS];
	u64 length[NTFS_RS_MAP_EXTENTS];
	unsigned int count;
};

/* Keep initialized, allocated extents only. Holes, resident data and bytes
 * past initialized size stay with the Rust reader, which also rejects
 * runlists that do not cover the stream. A full table ends the walk. */
static int ntfs_rs_collect_extent(void *context, u64 logical, u64 physical, u64 length, u32 flags)
{
	struct ntfs_rs_extent_map *map = context;

	if (flags & (FIEMAP_EXTENT_UNWRITTEN | FIEMAP_EXTENT_DATA_INLINE | FIEMAP_EXTENT_NOT_ALIGNED))
		return 0;
	if (map->count == NTFS_RS_MAP_EXTENTS)
		return 1;
	map->logical[map->count] = logical;
	map->physical[map->count] = physical;
	map->length[map->count] = length;
	map->count++;
	return 0;
}

/* Caller holds io_lock. With a writer, staged data may still be dirty in the
 * block-device cache and pending metadata lives in held images; extents that
 * touch either keep using the cached reader, which sees both. */
static bool ntfs_rs_extent_direct(struct super_block *sb, u64 physical, u64 length)
{
	struct ntfs_rs_super *state = sb->s_fs_info;
	u64 device_bytes;
	unsigned int i;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
	device_bytes = bdev_nr_bytes(sb->s_bdev);
#else
	device_bytes = i_size_read(sb->s_bdev->bd_inode);
#endif
	if (!length || physical > device_bytes || length > device_bytes - physical)
		return false;
	if (!state->writer)
		return true;
	for (i = 0; state->held_count && i < NTFS_RS_HELD_MAX; i++) {
		const struct ntfs_rs_held *h = &state->held[i];
		if (h->active && physical < h->offset + h->length && h->offset < physical + length)
			return false;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
	return !filemap_range_needs_writeback(NTFS_RS_BLOCK_CACHE(sb), physical, physical + length - 1);
#else
	return false;
#endif
}

/* Completion owns the pages: success publishes them, and a failed page stays
 * non-uptodate so the next demand read reports the error. */
static void ntfs_rs_read_end_io(struct bio *bio)
{
	struct bio_vec *vec;
	struct bvec_iter_all iter;

	bio_for_each_segment_all(vec, bio, iter) {
		if (!bio->bi_status)
			SetPageUptodate(vec->bv_page);
		unlock_page(vec->bv_page);
	}
	bio_put(bio);
}

/* Map a batch of consecutive locked pages through Rust and read every page
 * that lies wholly inside one initialized extent below EOF with asynchronous
 * bios. Returns the mask of pages handed to bios; the caller must then only
 * drop its own references to them. Other pages remain locked for the caller. */
static u64 ntfs_rs_submit_pages(struct inode *inode, struct page **pages,
				unsigned int count, unsigned char *scratch, unsigned int flags)
{
	struct super_block *sb = inode->i_sb;
	struct ntfs_rs_super *state = sb->s_fs_info;
	struct ntfs_rs_extent_map map = { .count = 0 };
	unsigned int sector_mask = bdev_logical_block_size(sb->s_bdev) - 1;
	loff_t position = page_offset(pages[0]);
	loff_t size = i_size_read(inode);
	struct bio *bio = NULL;
	struct blk_plug plug;
	u64 submitted = 0, next = 0;
	unsigned int i, e = 0;

	BUILD_BUG_ON(NTFS_RS_BATCH_PAGES > BITS_PER_TYPE(u64));
	if (!count || count > NTFS_RS_BATCH_PAGES || position >= size)
		return 0;
	down_read(&state->io_lock);
	if (ntfs_rs_map_file(state->boot, sb, ntfs_rs_read_unlocked, scratch,
			     state->read_scratch_bytes, NTFS_RS_REF(inode), position,
			     (u64)count * PAGE_SIZE, &map, ntfs_rs_collect_extent) || !map.count) {
		up_read(&state->io_lock);
		return 0;
	}
	for (i = 0; i < map.count; i++)
		if (!ntfs_rs_extent_direct(sb, map.physical[i], map.length[i]))
			map.length[i] = 0;
	blk_start_plug(&plug);
	for (i = 0; i < count; i++) {
		loff_t at = position + (loff_t)i * PAGE_SIZE;
		u64 physical;

		if (page_offset(pages[i]) != at)
			break;
		while (e < map.count && map.logical[e] + map.length[e] <= at)
			e++;
		if (e == map.count || at < map.logical[e] || at + PAGE_SIZE > size ||
		    at + PAGE_SIZE > map.logical[e] + map.length[e])
			continue;
		physical = map.physical[e] + (at - map.logical[e]);
		if (physical & sector_mask)
			continue;
		if (bio && (physical != next || bio_add_page(bio, pages[i], PAGE_SIZE, 0) != PAGE_SIZE)) {
			submit_bio(bio);
			bio = NULL;
		}
		if (!bio) {
			bio = ntfs_rs_bio_alloc(sb, count - i, REQ_OP_READ | flags);
			if (!bio)
				break;
			bio->bi_iter.bi_sector = physical >> SECTOR_SHIFT;
			bio->bi_end_io = ntfs_rs_read_end_io;
			__bio_add_page(bio, pages[i], PAGE_SIZE, 0);
		}
		next = physical + PAGE_SIZE;
		submitted |= 1ULL << i;
	}
	if (bio)
		submit_bio(bio);
	blk_finish_plug(&plug);
	up_read(&state->io_lock);
	return submitted;
}

/* Fill consecutive locked pages through the Rust reader, which interprets
 * every byte of holes, resident and partially initialized data. Without a
 * buffer the pages are released non-uptodate for a later demand read. */
static void ntfs_rs_fill_pages(struct inode *inode, struct page **pages, unsigned int count,
			       unsigned char *scratch, unsigned char *buffer)
{
	struct super_block *sb = inode->i_sb;
	const struct ntfs_rs_super *state = sb->s_fs_info;
	loff_t position = page_offset(pages[0]);
	size_t amount = position >= i_size_read(inode) ? 0 :
		min_t(u64, count * PAGE_SIZE, i_size_read(inode) - position);
	int result = buffer ? 0 : -ENOMEM;
	unsigned int i;

	for (i = 1; i < count; i++)
		if (page_offset(pages[i]) != position + i * PAGE_SIZE)
			result = -EIO;
	if (!result && amount)
		result = ntfs_rs_read_file(state->boot, 512, sb, ntfs_rs_read_at, scratch,
					   state->read_scratch_bytes, NTFS_RS_REF(inode),
					   position, buffer, amount);
	/* Successful Rust reads initialize the complete requested range,
	 * including sparse/uninitialized data. Only the EOF tail needs clearing. */
	if (!result)
		memset(buffer + amount, 0, count * PAGE_SIZE - amount);
	for (i = 0; i < count; i++) {
		if (!result) {
			void *mapped = kmap_local_page(pages[i]);
			memcpy(mapped, buffer + i * PAGE_SIZE, PAGE_SIZE);
			kunmap_local(mapped);
			flush_dcache_page(pages[i]);
			SetPageUptodate(pages[i]);
		}
		/* Failed speculative reads stay non-uptodate. A demand read
		 * retries through read_folio/readpage and returns its errno. */
		unlock_page(pages[i]);
		put_page(pages[i]);
	}
}

/* Fill a single locked page. A wholly mapped page completes through its bio;
 * other pages go through the synchronous Rust reader. */
static int ntfs_rs_fill_page(struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct super_block *sb = inode->i_sb;
	const struct ntfs_rs_super *state = sb->s_fs_info;
	unsigned char *scratch;
	void *mapped;
	loff_t position = page_offset(page);
	size_t amount;
	int result = 0;

	scratch = kvzalloc(state->read_scratch_bytes, GFP_NOFS);
	if (!scratch) {
		result = -ENOMEM;
		goto out;
	}
	if (ntfs_rs_submit_pages(inode, &page, 1, scratch, 0)) {
		kvfree(scratch);
		return 0;
	}
	/* The synchronous reader fills this locked page directly. kmap_local
	 * permits scheduling; no mapping escapes this task or the read call. */
	mapped = kmap_local_page(page);
	amount = position >= i_size_read(inode) ? 0 :
		min_t(u64, PAGE_SIZE, i_size_read(inode) - position);
	if (amount)
		result = ntfs_rs_read_file(state->boot, 512, sb,
					   ntfs_rs_read_at, scratch,
					   state->read_scratch_bytes, NTFS_RS_REF(inode),
					   position, mapped, amount);
	if (!result) {
		memset((unsigned char *)mapped + amount, 0, PAGE_SIZE - amount);
	}
	kunmap_local(mapped);
	if (!result) {
		flush_dcache_page(page);
		SetPageUptodate(page);
	}
out:
	kvfree(scratch);
	unlock_page(page);
	return result;
}

#ifdef NTFS_RS_FOLIO_AOPS
static int ntfs_rs_read_folio(struct file *file, struct folio *folio)
{
	(void)file;
	/* Large folios are not enabled for this mapping. */
	if (folio_size(folio) != PAGE_SIZE) {
		folio_unlock(folio);
		return -EOPNOTSUPP;
	}
	return ntfs_rs_fill_page(&folio->page);
}
#else
static int ntfs_rs_read_page(struct file *file, struct page *page)
{
	(void)file;
	return ntfs_rs_fill_page(page);
}
#endif

/* Batches of up to 256 KiB: mapped pages go to asynchronous bios, so the
 * device works ahead of the reader; the rest fill through Rust in runs. */
static void ntfs_rs_readahead(struct readahead_control *rac)
{
	struct inode *inode = rac->mapping->host;
	struct super_block *sb = inode->i_sb;
	struct page *pages[NTFS_RS_BATCH_PAGES];
	const struct ntfs_rs_super *state = sb->s_fs_info;
	unsigned char *scratch, *buffer = NULL;
	unsigned int count, i, run;
	size_t buffer_bytes = min_t(size_t, readahead_count(rac), ARRAY_SIZE(pages)) * PAGE_SIZE;
	u64 direct;

	if (!buffer_bytes)
		return;
	/* A device that reports no optimal I/O size, as most USB enclosures and
	 * virtual disks do, gets 128 KiB of read-ahead: one batch in flight, then
	 * an idle device. Widen this file's window; later rounds grow into it. */
	if (rac->file && READ_ONCE(rac->file->f_ra.ra_pages) < NTFS_RS_MIN_READAHEAD_BYTES / PAGE_SIZE)
		WRITE_ONCE(rac->file->f_ra.ra_pages, NTFS_RS_MIN_READAHEAD_BYTES / PAGE_SIZE);
	scratch = ntfs_rs_scratch_get(state, state->read_scratch_bytes);
	if (!scratch)
		return; /* The VM unlocks requests we have not consumed. */
	for (;;) {
		count = 0;
		while (count < buffer_bytes / PAGE_SIZE) {
#ifdef NTFS_RS_FOLIO_AOPS
			struct folio *folio = __readahead_folio(rac);
			if (!folio)
				break;
			if (folio_size(folio) != PAGE_SIZE) {
				folio_unlock(folio);
				folio_put(folio);
				continue;
			}
			pages[count++] = &folio->page;
#else
			struct page *page = readahead_page(rac);
			if (!page)
				break;
			pages[count++] = page;
#endif
		}
		if (!count)
			break;
		direct = ntfs_rs_submit_pages(inode, pages, count, scratch, REQ_RAHEAD);
		for (i = 0; i < count; i += run) {
			if (direct & (1ULL << i)) {
				put_page(pages[i]);
				run = 1;
				continue;
			}
			for (run = 1; i + run < count && !(direct & (1ULL << (i + run))); run++)
				;
			if (!buffer)
				buffer = kvmalloc(buffer_bytes, GFP_NOFS);
			ntfs_rs_fill_pages(inode, pages + i, run, scratch, buffer);
		}
	}
	kvfree(buffer);
	ntfs_rs_scratch_put(state, scratch, state->read_scratch_bytes);
}

/* Dirty cache entries are persisted through the same transactional Rust writer
 * as write_iter. Kbuild selects the page/folio callback and available walker
 * from the target headers; newer kernels replace write_cache_pages with
 * writeback_iter. */
struct ntfs_rs_writeback_ctx {
	struct inode *inode;
	struct ntfs_rs_super *state;
	unsigned char *page;
};

#if defined(NTFS_RS_AOPS_WRITEPAGE) || (!defined(NTFS_RS_WRITEBACK_ITER) && !defined(NTFS_RS_WRITEPAGE_FOLIO))
static int ntfs_rs_writeback_page(struct page *page,
				  struct writeback_control *wbc,
				  struct ntfs_rs_writeback_ctx *ctx)
{
	struct inode *inode = ctx->inode;
	struct ntfs_rs_super *state = ctx->state;
	loff_t pos = page_offset(page);
	loff_t size = i_size_read(inode);
	size_t length = pos < size ? min_t(u64, PAGE_SIZE, size - pos) : 0;
	void *address;
	int error = 0;

	set_page_writeback(page);
	if (length) {
		address = kmap_local_page(page);
		memcpy(ctx->page, address, length);
		kunmap_local(address);

		down_write(&state->io_lock);
		ntfs_rs_make_room(state);
		error = state->write_failed ? -EIO :
			ntfs_rs_writer_write(state->writer, NTFS_RS_IO(inode->i_sb),
				state->op_scratch, NTFS_RS_REF(inode), pos,
				ctx->page, length);
		if (error == -EIO)
			ntfs_rs_poison(state, __func__);
		up_write(&state->io_lock);
	}

	if (error) {
		mapping_set_error(page->mapping, error);
		redirty_page_for_writepage(wbc, page);
	}
	unlock_page(page);
	end_page_writeback(page);
	return error;
}

#ifdef NTFS_RS_AOPS_WRITEPAGE
static int ntfs_rs_writepage(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	struct ntfs_rs_writeback_ctx ctx = {
		.inode = inode,
		.state = inode->i_sb->s_fs_info,
	};
	int error;

	ctx.page = kmalloc(PAGE_SIZE, GFP_NOFS);
	if (!ctx.page) {
		redirty_page_for_writepage(wbc, page);
		unlock_page(page);
		return -ENOMEM;
	}
	error = ntfs_rs_writeback_page(page, wbc, &ctx);
	kfree(ctx.page);
	return error;
}

#endif
#endif

#if defined(NTFS_RS_WRITEPAGE_FOLIO) || defined(NTFS_RS_WRITEBACK_ITER)
static int ntfs_rs_writeback_folio(struct folio *folio,
				   struct writeback_control *wbc, void *data)
{
	struct ntfs_rs_writeback_ctx *ctx = data;
	struct inode *inode = ctx->inode;
	struct ntfs_rs_super *state = ctx->state;
	loff_t pos = folio_pos(folio);
	loff_t size = i_size_read(inode);
	size_t length = pos < size ? min_t(u64, folio_size(folio), size - pos) : 0;
	size_t off;
	int error = 0;

	folio_start_writeback(folio);
	for (off = 0; off < length; off += PAGE_SIZE) {
		size_t n = min_t(size_t, PAGE_SIZE, length - off);
		void *address = kmap_local_folio(folio, off);

		memcpy(ctx->page, address, n);
		kunmap_local(address);

		down_write(&state->io_lock);
		ntfs_rs_make_room(state);
		error = state->write_failed ? -EIO :
			ntfs_rs_writer_write(state->writer, NTFS_RS_IO(inode->i_sb),
				state->op_scratch, NTFS_RS_REF(inode), pos + off,
				ctx->page, n);
		if (error == -EIO)
			ntfs_rs_poison(state, __func__);
		up_write(&state->io_lock);
		if (error)
			break;
	}

	if (error) {
		mapping_set_error(folio->mapping, error);
		folio_redirty_for_writepage(wbc, folio);
	}
	folio_unlock(folio);
	folio_end_writeback(folio);
	return error;
}
#else
static int ntfs_rs_writeback_page_cb(struct page *page,
				     struct writeback_control *wbc, void *data)
{
	return ntfs_rs_writeback_page(page, wbc, data);
}
#endif

static int ntfs_rs_writepages(struct address_space *mapping,
			      struct writeback_control *wbc)
{
	struct ntfs_rs_writeback_ctx ctx = {
		.inode = mapping->host,
		.state = mapping->host->i_sb->s_fs_info,
	};
	int error;

	ctx.page = kmalloc(PAGE_SIZE, GFP_NOFS);
	if (!ctx.page)
		return -ENOMEM;
#ifdef NTFS_RS_WRITEBACK_ITER
    {
        struct folio *folio = NULL;
        error = 0;
        while ((folio = writeback_iter(mapping, wbc, folio, &error)))
            error = ntfs_rs_writeback_folio(folio, wbc, &ctx);
    }
#elif defined(NTFS_RS_WRITEPAGE_FOLIO)
	error = write_cache_pages(mapping, wbc, ntfs_rs_writeback_folio, &ctx);
#else
	error = write_cache_pages(mapping, wbc, ntfs_rs_writeback_page_cb, &ctx);
#endif
	kfree(ctx.page);
	return error;
}

#ifndef FMODE_CAN_ODIRECT
/* Older VFS open code requires this marker even with custom iterators.
 * All requests are serviced by read_iter/write_iter, never this fallback. */
static ssize_t ntfs_rs_direct_io(struct kiocb *iocb, struct iov_iter *iter)
{
    return -EOPNOTSUPP;
}
#endif

static const struct address_space_operations ntfs_rs_aops = {
#ifndef FMODE_CAN_ODIRECT
    .direct_IO = ntfs_rs_direct_io,
#endif
#ifdef NTFS_RS_AOPS_WRITEPAGE
	.writepage = ntfs_rs_writepage,
#endif
	.writepages = ntfs_rs_writepages,
#ifdef NTFS_RS_DIRTY_FOLIO
	.dirty_folio = filemap_dirty_folio,
#else
	.set_page_dirty = __set_page_dirty_nobuffers,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	/* Pages carry no private state, so memory compaction may move them. */
	.migrate_folio = filemap_migrate_folio,
#endif
	.readahead = ntfs_rs_readahead,
#ifdef NTFS_RS_FOLIO_AOPS
	.read_folio = ntfs_rs_read_folio,
#else
	.readpage = ntfs_rs_read_page,
#endif
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
static int ntfs_rs_setattr(struct dentry *dentry, struct iattr *attr)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
static int ntfs_rs_setattr(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *attr)
#else
static int ntfs_rs_setattr(struct user_namespace *idmap, struct dentry *dentry, struct iattr *attr)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
	struct user_namespace *idmap = &init_user_ns;
#endif
	struct inode *inode = d_inode(dentry);
	struct super_block *sb = inode->i_sb;
	struct ntfs_rs_super *state = sb->s_fs_info;
	unsigned char *scratch;
	int result;
	if (ntfs_rs_readonly(inode) || !state->writer)
		return -EROFS;
    /* permissions=desktop: modes and owners are mount-wide. Like NTFS-3G's
     * default "silent" option, chmod/chown by the owner succeed without
     * changing anything, so cp -a and file managers keep working and the
     * stored Windows ownership and ACLs are preserved. */
    {
        kuid_t owner_uid;
        kgid_t owner_gid;
        bool desktop = ntfs_rs_desktop_owner(sb, &owner_uid, &owner_gid);
        if (desktop) {
            inode->i_uid = owner_uid; /* setattr_prepare's owner checks */
            inode->i_gid = owner_gid;
        }
        if (desktop && (attr->ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID))) {
            if (!uid_eq(current_fsuid(), owner_uid) && !capable(CAP_FOWNER))
                return -EPERM;
            attr->ia_valid &= ~(ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_KILL_SUID | ATTR_KILL_SGID);
            if (!(attr->ia_valid & ~(ATTR_FORCE | ATTR_CTIME | ATTR_FILE)))
                return 0;
        }
    }
    /* VFS privilege removal only clears the requested set-ID bits. It must
     * not require WRITE_DAC or rewrite the access ACL's unchanged rwx mask.
     * Do this before a size/owner change so an interruption cannot retain
     * privileges on modified contents. A failed later change may lose bits. */
    if ((attr->ia_valid & ATTR_MODE) &&
        (attr->ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))) {
        struct inode *canonical = ntfs_rs_canonical(inode);
        umode_t clear = ((attr->ia_valid & ATTR_KILL_SUID) ? S_ISUID : 0) |
                       ((attr->ia_valid & ATTR_KILL_SGID) ? S_ISGID : 0);
        result = ntfs_rs_setattr_prepare(idmap, dentry, attr);
        if (result) return result;
        if (attr->ia_mode != (inode->i_mode & ~clear)) return -EINVAL;
        down_write(&state->io_lock);
        ntfs_rs_make_room(state);
        result = state->write_failed ? -EIO : ntfs_rs_writer_mode(state->writer,
            NTFS_RS_IO(sb), state->op_scratch, NTFS_RS_REF(canonical),
            (canonical->i_mode & ~clear) & 07777);
        if (result == -EIO) ntfs_rs_poison(state, __func__);
        if (!result) {
            canonical->i_mode &= ~clear;
            WRITE_ONCE(ntfs_rs_shared(inode)->unix_mode, true);
            ntfs_rs_sync_projection(canonical);
        }
        up_write(&state->io_lock);
        if (result) return result;
        ntfs_rs_touch(inode, false);
        ntfs_rs_notify_peers(inode, FS_ATTRIB, NULL, 0, NULL);
        attr->ia_valid &= ~(ATTR_MODE | ATTR_KILL_SUID | ATTR_KILL_SGID);
        if (!(attr->ia_valid & ~(ATTR_FORCE | ATTR_CTIME | ATTR_MTIME | ATTR_FILE)))
            return 0;
    }
    if (attr->ia_valid & ATTR_MODE) {
        if (ntfs_rs_native(inode))
            return -EOPNOTSUPP;
        if (attr->ia_valid & (ATTR_UID | ATTR_GID | ATTR_SIZE))
            return -EOPNOTSUPP;
        result = ntfs_rs_setattr_prepare(idmap, dentry, attr);
        if (result)
            return result;
        result = ntfs_rs_authorize(inode, NTFS_RS_WRITE_DAC, false);
        if (result)
            return result;
#if IS_ENABLED(CONFIG_FS_POSIX_ACL)
        /* POSIX chmod must also rewrite an existing access ACL mask.  Probe the
         * filesystem ACL directly instead of relying on a cached projection: if
         * no access ACL exists the ordinary $LXMOD path below still has to run
         * (even when the visible mode already matches) so Linux-mode metadata is
         * made durable. */
        {
            struct posix_acl *acl = ntfs_rs_get_inode_acl(ntfs_rs_canonical(inode),
                ACL_TYPE_ACCESS, false);
            if (IS_ERR(acl))
                return PTR_ERR(acl);
            if (acl) {
                posix_acl_release(acl);
                result = ntfs_rs_chmod_acl(idmap, dentry, attr->ia_mode);
                if (result)
                    return result;
                ntfs_rs_touch(inode, false);
                ntfs_rs_sync_projection(inode);
                return 0;
            }
        }
#endif
        scratch = state->op_scratch;
        if (!scratch)
            return -ENOMEM;
        down_write(&state->io_lock);
        ntfs_rs_make_room(state);
        state->flushes = 0;
        result = state->write_failed ? -EIO : ntfs_rs_writer_mode(state->writer,
            sb, ntfs_rs_read_unlocked, ntfs_rs_write_at, ntfs_rs_flush, scratch,
            inode->i_ino | ((u64)inode->i_generation << 48), attr->ia_mode & 07777);
        if (result == -EIO)
            ntfs_rs_poison(state, __func__);
        if (!result) {
            struct inode *canonical = ntfs_rs_canonical(inode);
            canonical->i_mode = (canonical->i_mode & S_IFMT) | (attr->ia_mode & 07777);
            WRITE_ONCE(ntfs_rs_shared(inode)->unix_mode, true);
            inode->i_mode = canonical->i_mode;
            ntfs_rs_sync_projection(inode);
        }
        up_write(&state->io_lock);
        if (scratch != state->op_scratch) kvfree(scratch);
        if (!result) { ntfs_rs_touch(inode, false); ntfs_rs_sync_projection(inode);
            ntfs_rs_notify_peers(inode, FS_ATTRIB, NULL, 0, NULL); }
        return result;
    }
	if (attr->ia_valid & (ATTR_UID | ATTR_GID)) {
		u32 new_uid = U32_MAX, new_gid = U32_MAX;
		if (attr->ia_valid & ATTR_SIZE)
			return -EOPNOTSUPP;
		/* Native semantics decide: WRITE_OWNER on the current DACL, and a
		 * new owner must be the caller's own mapped SID. Linux CAP_CHOWN
		 * is never treated as a Windows privilege. */
		if (attr->ia_valid & ATTR_UID) {
			new_uid = from_kuid(&init_user_ns, attr->ia_uid);
			if (new_uid == U32_MAX)
				return -EINVAL;
		}
		if (attr->ia_valid & ATTR_GID) {
			new_gid = from_kgid(&init_user_ns, attr->ia_gid);
			if (new_gid == U32_MAX)
				return -EINVAL;
		}
		return ntfs_rs_apply_security(inode, NULL, 0, true, new_uid, new_gid);
	}
	if (attr->ia_valid & ATTR_SIZE) {
		atomic_set(&ntfs_rs_shared(inode)->trim_due, 1);
		atomic_set(&ntfs_rs_shared(inode)->blocks_known, 0);
	}
	if (!(attr->ia_valid & ATTR_SIZE)) {
        u64 times[4] = { 0 };
        u32 valid = 0;
        result = ntfs_rs_setattr_prepare(idmap, dentry, attr);
        if (result) return result;
        result = ntfs_rs_authorize(inode, NTFS_RS_WRITE_ATTRIBUTES, false);
        if (result) return result;
        if (attr->ia_valid & ATTR_MTIME) { valid |= 2; times[1] = ntfs_rs_from_ts(attr->ia_mtime); }
        if (attr->ia_valid & ATTR_CTIME) { valid |= 4; times[2] = ntfs_rs_from_ts(attr->ia_ctime); }
        if (attr->ia_valid & ATTR_ATIME) { valid |= 8; times[3] = ntfs_rs_from_ts(attr->ia_atime); }
        down_write(&state->io_lock);
        ntfs_rs_make_room(state);
        result = state->write_failed ? -EIO : ntfs_rs_writer_set_times(state->writer,
            NTFS_RS_IO(sb), state->op_scratch, NTFS_RS_REF(inode), times, valid, 0, 0);
        if (result == -EIO) ntfs_rs_poison(state, __func__);
        up_write(&state->io_lock);
        if (!result) {
            ntfs_rs_setattr_copy(idmap, ntfs_rs_canonical(inode), attr);
            ntfs_rs_sync_projection(inode);
            ntfs_rs_notify_peers(inode, FS_ATTRIB, NULL, 0, NULL);
        }
        return result;
    }
    if (!S_ISREG(inode->i_mode)) return -EINVAL;
	result = ntfs_rs_setattr_prepare(idmap, dentry, attr);
	if (result)
		return result;
	result = ntfs_rs_authorize(inode, 2, false);
	if (result)
		return result;
	result = ntfs_rs_break_leases(inode, O_WRONLY);
    if (result) return result;
    result = inode_newsize_ok(inode, attr->ia_size);
	if (result)
		return result;
	scratch = state->op_scratch;
	if (!scratch)
		return -ENOMEM;
	/* VFS holds i_rwsem; keep the same invalidation -> volume lock order. */
	filemap_invalidate_lock(inode->i_mapping);
	result = filemap_write_and_wait(inode->i_mapping);
    if (result) { filemap_invalidate_unlock(inode->i_mapping); return result; }
    truncate_inode_pages(inode->i_mapping, 0);
	down_write(&state->io_lock);
	ntfs_rs_make_room(state);
	state->flushes = 0;
	result = state->write_failed ? -EIO : ntfs_rs_writer_resize(state->writer,
		sb, ntfs_rs_read_unlocked, ntfs_rs_write_at, ntfs_rs_flush, scratch,
		inode->i_ino | ((u64)inode->i_generation << 48), attr->ia_size);
	if (result == -EIO) {
		ntfs_rs_poison(state, __func__);
		mapping_set_error(inode->i_mapping, result);
	}
	if (!result) {
        struct inode *canonical = ntfs_rs_canonical(inode);
        truncate_setsize(canonical, attr->ia_size);
        ntfs_rs_touch(inode, true);
        ntfs_rs_setattr_copy(idmap, canonical, attr);
        ntfs_rs_sync_projection(inode);
	}
	up_write(&state->io_lock);
	filemap_invalidate_unlock(inode->i_mapping);
	if (scratch != state->op_scratch) kvfree(scratch);
    if (!result) ntfs_rs_notify_peers(inode, FS_MODIFY | FS_ATTRIB, NULL, 0, NULL);
	return result;
}

static int ntfs_rs_initxattrs(struct inode *, const struct xattr *, void *);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
static int ntfs_rs_rename(struct inode *old_dir,
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
static int ntfs_rs_rename(struct mnt_idmap *idmap, struct inode *old_dir,
#else
static int ntfs_rs_rename(struct user_namespace *idmap, struct inode *old_dir,
#endif
        struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry,
        unsigned int flags)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
	struct user_namespace *idmap = &init_user_ns;
#endif
    struct inode *inode = d_inode(old_dentry);
    struct super_block *sb = old_dir->i_sb;
    struct ntfs_rs_super *state = sb->s_fs_info;
    unsigned char *scratch;
    const struct ntfs_rs_security *security;
    struct inode *victim = d_inode(new_dentry);
    bool exchange = flags & RENAME_EXCHANGE, whiteout = flags & RENAME_WHITEOUT;
    struct kvec initial_eas = { 0 };
    int outcome = 0;
    int result;
    kuid_t rename_uid = current_fsuid();
    kgid_t rename_gid = (old_dir->i_mode & S_ISGID) ? old_dir->i_gid : current_fsgid();
    (void)idmap;
    if (ntfs_rs_readonly(old_dir) || !state->writer)
        return -EROFS;
    /* Desktop mode records the mount owner, whose SIDs are always mapped. */
    ntfs_rs_desktop_owner(sb, &rename_uid, &rename_gid);
    if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT) ||
        (exchange && (flags & (RENAME_NOREPLACE | RENAME_WHITEOUT)))) return -EINVAL;
    if (whiteout) {
        if (ntfs_rs_native(old_dir) || ntfs_rs_native(new_dir)) return -EOPNOTSUPP;
        if (!capable(CAP_MKNOD)) return -EPERM;
        result = ntfs_rs_authorize(old_dir, NTFS_RS_WRITE_DATA, false);
        if (result) return result;
    }
    if ((flags & RENAME_NOREPLACE) && victim) return -EEXIST;
    if (victim && NTFS_RS_REF(victim) == NTFS_RS_REF(inode)) return 0;
    if (exchange && !victim) return -ENOENT;
    if (exchange) {
        result = ntfs_rs_authorize(old_dir, S_ISDIR(victim->i_mode) ? 4 : 2, false);
        if (result) return result;
    }
    if (victim) {
        if (!exchange && S_ISDIR(inode->i_mode) != S_ISDIR(victim->i_mode))
            return S_ISDIR(inode->i_mode) ? -ENOTDIR : -EISDIR;
        result = ntfs_rs_may_delete(new_dir, victim);
        if (result) return result;
    }
    /* FILE_ADD_SUBDIRECTORY for directories, FILE_ADD_FILE otherwise. */
    result = ntfs_rs_authorize(new_dir, S_ISDIR(inode->i_mode) ? 4 : 2, false);
    if (result)
        return result;
    result = ntfs_rs_may_delete(old_dir, inode);
    if (result)
        return result;
    scratch = state->op_scratch;
    if (!scratch)
        return -ENOMEM;
    if (whiteout) {
        struct inode *created = new_inode(sb);
        if (!created) return -ENOMEM;
        ntfs_rs_inode_init_owner(idmap, created, old_dir, S_IFCHR | WHITEOUT_MODE);
        result = security_inode_init_security(created, old_dir, &old_dentry->d_name,
            ntfs_rs_initxattrs, &initial_eas);
        iput(created);
        if (result) { kvfree(initial_eas.iov_base); return result; }
    }
    /* VFS holds lock_rename() on both directories plus the inode locks. */
    down_write(&state->io_lock);
    ntfs_rs_make_room(state);
    state->flushes = 0;
    security = rcu_dereference_protected(ntfs_rs_shared(old_dir)->security, 1);
    result = whiteout && !security ? -EACCES : ntfs_rs_reserve_records(state, scratch);
    if (!result) result = ntfs_rs_writer_rename(state->writer,
        sb, ntfs_rs_read_unlocked, ntfs_rs_write_at, ntfs_rs_flush, scratch,
        old_dir->i_ino | ((u64)old_dir->i_generation << 48),
        inode->i_ino | ((u64)inode->i_generation << 48),
        old_dentry->d_name.name, old_dentry->d_name.len,
        new_dir->i_ino | ((u64)new_dir->i_generation << 48),
        new_dentry->d_name.name, new_dentry->d_name.len,
        whiteout ? (victim ? 4 : 3) : victim ? (exchange ? 2 : 1) : 0,
        victim ? NTFS_RS_REF(victim) : 0, &outcome, !ntfs_rs_native(new_dir),
        security ? security->data : NULL, security ? security->length : 0,
        ntfs_rs_identity_locked(state), from_kuid(&init_user_ns, rename_uid),
        from_kgid(&init_user_ns, rename_gid),
        ntfs_rs_from_ts(current_time(old_dir)), initial_eas.iov_base, initial_eas.iov_len);
    if (result == -EIO) {
        ntfs_rs_poison(state, __func__);
        mapping_set_error(inode->i_mapping, result);
    }
    if (!result) {
        if (victim && !exchange) {
            if (outcome == NTFS_RS_ORPHANED) WRITE_ONCE(ntfs_rs_shared(victim)->orphaned, true);
            if (S_ISDIR(victim->i_mode)) {
                clear_nlink(ntfs_rs_canonical(victim));
            } else drop_nlink(ntfs_rs_canonical(victim));
            ntfs_rs_sync_projection(victim);
        }
        ntfs_rs_sync_projection(old_dir);
        ntfs_rs_sync_projection(new_dir);
        ntfs_rs_namespace_changed(old_dir);
        ntfs_rs_namespace_changed(new_dir);
    }
    up_write(&state->io_lock);
    kvfree(initial_eas.iov_base);
    if (scratch != state->op_scratch) kvfree(scratch);
    if (!result) {
        u32 cookie = ntfs_rs_cookie();
        u32 dirbit = S_ISDIR(inode->i_mode) ? FS_ISDIR : 0;
        ntfs_rs_touch(old_dir, true); ntfs_rs_touch(new_dir, true); ntfs_rs_touch(inode, false);
        if (victim) { ntfs_rs_touch(victim, false); ntfs_rs_sync_projection(victim); }
        ntfs_rs_notify_peers(old_dir, FS_MOVED_FROM | dirbit, &old_dentry->d_name, cookie, inode);
        ntfs_rs_notify_peers(new_dir, FS_MOVED_TO | dirbit, &new_dentry->d_name, cookie, inode);
        ntfs_rs_notify_peers(inode, FS_MOVE_SELF, NULL, 0, NULL);
        if (exchange) {
            cookie = ntfs_rs_cookie(); dirbit = S_ISDIR(victim->i_mode) ? FS_ISDIR : 0;
            ntfs_rs_notify_peers(new_dir, FS_MOVED_FROM | dirbit, &new_dentry->d_name, cookie, victim);
            ntfs_rs_notify_peers(old_dir, FS_MOVED_TO | dirbit, &old_dentry->d_name, cookie, victim);
            ntfs_rs_notify_peers(victim, FS_MOVE_SELF, NULL, 0, NULL);
        } else if (victim) ntfs_rs_notify_peers(victim, FS_ATTRIB, NULL, 0, NULL);
    }
    return result;
}
/* Node kinds shared with Rust ntfs_rs_writer_create. */
#define NTFS_RS_NODE_FILE 0
#define NTFS_RS_NODE_DIRECTORY 1
#define NTFS_RS_NODE_SYMLINK 2
#define NTFS_RS_NODE_SPECIAL 3   /* FIFO, socket, character or block device */
#define NTFS_RS_NODE_TEMPORARY 4 /* O_TMPFILE: nameless, created as an orphan */

/* The returned packed EAs are consumed by the same transaction as create. */
static int ntfs_rs_inherit_acl(struct inode *parent, umode_t *mode,
        unsigned char **packed, size_t *length)
{
    *packed = NULL;
    *length = 0;
#if IS_ENABLED(CONFIG_FS_POSIX_ACL)
    if (!ntfs_rs_native(parent) && !S_ISLNK(*mode)) {
        struct posix_acl *acl[2] = { NULL, NULL };
        const char *names[2] = { XATTR_NAME_POSIX_ACL_DEFAULT, XATTR_NAME_POSIX_ACL_ACCESS };
        size_t sizes[2] = { 0, 0 }, total = 0, at = 0;
        int i, error = posix_acl_create(parent, mode, &acl[0], &acl[1]);
        if (error) return error;
        for (i = 0; i < 2; i++) {
            if (!acl[i]) continue;
            sizes[i] = posix_acl_xattr_size(acl[i]->a_count);
            if (sizes[i] > NTFS_RS_MAX_EA_VALUE) { error = -E2BIG; goto out; }
            total += 4 + strlen(names[i]) + sizes[i];
        }
        if (!total) goto out;
        if (total > NTFS_RS_MAX_PACKED_EA_BYTES) { error = -E2BIG; goto out; }
        *packed = kvmalloc(total, GFP_NOFS);
        if (!*packed) { error = -ENOMEM; goto out; }
        for (i = 0; i < 2; i++) {
            size_t n = strlen(names[i]);
            unsigned char *entry;
            if (!acl[i]) continue;
            entry = *packed + at;
            entry[0] = n; entry[1] = n >> 8;
            entry[2] = sizes[i]; entry[3] = sizes[i] >> 8;
            memcpy(entry + 4, names[i], n);
            error = ntfs_rs_acl_to_xattr(&init_user_ns, acl[i], entry + 4 + n, sizes[i]);
            if (error < 0) goto out;
            at += 4 + n + sizes[i];
        }
        *length = total;
        error = 0;
out:
        posix_acl_release(acl[0]); posix_acl_release(acl[1]);
        if (error) { kvfree(*packed); *packed = NULL; }
        return error;
    }
#endif
    if (!S_ISLNK(*mode)) *mode &= ~current_umask();
    return 0;
}

/* Append the LSM's security.* entries to the inherited ACLs. The existing
 * packed-EA format is only a C/Rust call buffer, not an on-disk format. */
static int ntfs_rs_initxattrs(struct inode *inode, const struct xattr *attrs,
        void *context)
{
    struct kvec *eas = context;
    const struct xattr *attr;
    unsigned char *packed, *entry;
    size_t total = eas->iov_len, at = total;
    (void)inode;
    for (attr = attrs; attr->name; attr++) {
        size_t n = strlen(attr->name) + XATTR_SECURITY_PREFIX_LEN;
        if (n <= XATTR_SECURITY_PREFIX_LEN || n > XATTR_NAME_MAX ||
            attr->value_len > NTFS_RS_MAX_EA_VALUE) return -E2BIG;
        total += 4 + n + attr->value_len;
        if (total > NTFS_RS_MAX_PACKED_EA_BYTES) return -E2BIG;
    }
    if (total == at) return 0;
    packed = kvmalloc(total, GFP_NOFS);
    if (!packed) return -ENOMEM;
    if (at) memcpy(packed, eas->iov_base, at);
    for (attr = attrs; attr->name; attr++) {
        size_t n = strlen(attr->name) + XATTR_SECURITY_PREFIX_LEN;
        entry = packed + at;
        entry[0] = n; entry[1] = n >> 8;
        entry[2] = attr->value_len; entry[3] = attr->value_len >> 8;
        memcpy(entry + 4, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN);
        memcpy(entry + 4 + XATTR_SECURITY_PREFIX_LEN, attr->name,
            n - XATTR_SECURITY_PREFIX_LEN);
        if (attr->value_len) memcpy(entry + 4 + n, attr->value, attr->value_len);
        at += 4 + n + attr->value_len;
    }
    kvfree(eas->iov_base);
    eas->iov_base = packed;
    eas->iov_len = total;
    return 0;
}

/* file is the O_TMPFILE file on kernels whose ->tmpfile opens it (6.1+);
 * otherwise NULL, and a temporary node is attached to dentry. */
static int ntfs_rs_create_node(NTFS_RS_IDMAP *idmap, struct inode *parent,
        struct dentry *dentry, umode_t mode, int kind, const void *target, size_t target_length, struct file *file)
{
    bool temporary = kind == NTFS_RS_NODE_TEMPORARY;
    struct super_block *sb = parent->i_sb;
    struct ntfs_rs_super *state = sb->s_fs_info;
    struct ntfs_rs_inode *private = ntfs_rs_shared(parent);
    const struct ntfs_rs_security *security;
    struct ntfs_rs_node info = { .flags = 1, .links = 1, .mode = mode };
    struct inode *inode;
    struct inode *owner;
    unsigned char *scratch, *eas;
    size_t eas_length;
    struct kvec initial_eas;
    int result;
    if (ntfs_rs_readonly(parent) || !state->writer)
        return -EROFS;
    result = ntfs_rs_authorize(parent, kind == NTFS_RS_NODE_DIRECTORY ?
        NTFS_RS_ADD_SUBDIRECTORY : NTFS_RS_WRITE_DATA, false);
    if (result)
        return result;
    scratch = state->op_scratch;
    if (!scratch)
        return -ENOMEM;
    if (kind == NTFS_RS_NODE_DIRECTORY) mode |= S_IFDIR;
    else if (kind == NTFS_RS_NODE_SYMLINK) mode |= S_IFLNK;
    else if (kind != NTFS_RS_NODE_SPECIAL) mode |= S_IFREG;
    owner = new_inode(sb);
    if (!owner) return -ENOMEM;
    ntfs_rs_inode_init_owner(idmap, owner, parent, mode);
    {
        /* Desktop mode: whoever creates it, the stored owner is the mount
         * owner, whose SIDs the mount's identity map always contains. */
        kuid_t owner_uid;
        kgid_t owner_gid;
        if (ntfs_rs_desktop_owner(sb, &owner_uid, &owner_gid)) {
            owner->i_uid = owner_uid;
            owner->i_gid = owner_gid;
        }
    }
    mode = owner->i_mode;
    result = ntfs_rs_inherit_acl(parent, &mode, &eas, &eas_length);
    if (result) { iput(owner); return result; }
    owner->i_mode = mode;
    initial_eas.iov_base = eas;
    initial_eas.iov_len = eas_length;
    result = security_inode_init_security(owner, parent, &dentry->d_name,
        ntfs_rs_initxattrs, &initial_eas);
    eas = initial_eas.iov_base;
    eas_length = initial_eas.iov_len;
    if (result) { kvfree(eas); iput(owner); return result; }
    down_write(&state->io_lock);
    ntfs_rs_make_room(state);
    state->flushes = 0;
    security = rcu_dereference_protected(private->security, 1);
    result = !security ? -EACCES : ntfs_rs_reserve_records(state, scratch);
    if (!result) result = ntfs_rs_writer_create(state->writer,
        sb, ntfs_rs_read_unlocked, ntfs_rs_write_at, ntfs_rs_flush, scratch,
        parent->i_ino | ((u64)parent->i_generation << 48),
        dentry->d_name.name, temporary ? 0 : dentry->d_name.len, security->data, security->length,
        ntfs_rs_identity_locked(state), from_kuid(&init_user_ns, owner->i_uid),
        from_kgid(&init_user_ns, owner->i_gid), mode,
        ntfs_rs_from_ts(current_time(parent)),
        kind, target, target_length,
        eas, eas_length, &info.file_reference, !ntfs_rs_native(parent));
    if (!result) {
        result = ntfs_rs_stat(state->boot, 512, sb, ntfs_rs_read_unlocked,
            scratch, ntfs_rs_ea_scratch_size(), info.file_reference & NTFS_RS_RECORD_MASK,
            info.file_reference >> 48, &info);
        /* An unreadable new temporary node cannot be handed out: free it. */
        if (result && temporary && !state->write_failed &&
            ntfs_rs_writer_reclaim(state->writer, NTFS_RS_IO(sb), scratch, info.file_reference))
            ntfs_rs_poison(state, __func__);
    }
    /* An error other than EIO that ended the session explains every later
     * EIO: name it before it is forgotten. */
    if (result && result != -EIO && !state->write_failed && ntfs_rs_writer_failed(state->writer)) {
        pr_err("slate-ntfs: %s creating \"%pd\" failed with %d and ended the write session\n",
            sb->s_id, dentry, result);
        ntfs_rs_poison(state, __func__);
    }
    if (result == -EIO)
        ntfs_rs_poison(state, __func__);
    if (!result && !temporary)
        ntfs_rs_namespace_changed(parent);
    up_write(&state->io_lock);
    kvfree(eas);
    if (result) {
        iput(owner);
        return result;
    }
    if (ntfs_rs_native(parent))
        info.mode = U32_MAX;
    inode = ntfs_rs_get_inode(sb, &info, ntfs_rs_native(parent), ntfs_rs_limits(parent), owner);
    if (IS_ERR(inode)) {
        /* A nameless record nobody can reach: free it now rather than at the
         * next writable mount. A failure here still leaves a marked orphan. */
        if (temporary) {
            down_write(&state->io_lock);
            if (state->writer_ready && !state->write_failed &&
                ntfs_rs_writer_reclaim(state->writer, NTFS_RS_IO(sb),
                    state->op_scratch, info.file_reference))
                ntfs_rs_poison(state, __func__);
            up_write(&state->io_lock);
        }
        return PTR_ERR(inode);
    }
    if (temporary) {
        /* The on-disk record has zero links and the $SLATE_ORPHAN mark, so
         * final close (evict) or the next writable mount frees it, unless
         * linkat(AT_EMPTY_PATH) publishes it first (ntfs_rs_link). */
        WRITE_ONCE(ntfs_rs_shared(inode)->orphaned, true);
        set_nlink(inode, 1); /* d_tmpfile drops this initial in-memory link. */
#ifdef NTFS_RS_TMPFILE_FILE
        d_tmpfile(file, inode);
        return finish_open_simple(file, 0);
#else
        (void)file;
        d_tmpfile(dentry, inode);
        return 0;
#endif
    }
    d_instantiate(dentry, inode);
    ntfs_rs_touch(parent, true);
    ntfs_rs_notify_peers(parent, FS_CREATE | (kind == NTFS_RS_NODE_DIRECTORY ? FS_ISDIR : 0),
        &dentry->d_name, 0, inode);
    return 0;
}

static int ntfs_rs_create(NTFS_RS_CALLBACK_IDMAP struct inode *parent,
        struct dentry *dentry, umode_t mode, bool excl)
{
    NTFS_RS_CALLBACK_IDMAP_INIT;
    (void)excl;
    return ntfs_rs_create_node(idmap, parent, dentry, mode, NTFS_RS_NODE_FILE, NULL, 0, NULL);
}

#ifdef NTFS_RS_MKDIR_DENTRY
static struct dentry *ntfs_rs_mkdir(NTFS_RS_CALLBACK_IDMAP struct inode *parent,
        struct dentry *dentry, umode_t mode)
{
    NTFS_RS_CALLBACK_IDMAP_INIT;
    return ERR_PTR(ntfs_rs_create_node(idmap, parent, dentry, mode, NTFS_RS_NODE_DIRECTORY, NULL, 0, NULL));
}
#else
static int ntfs_rs_mkdir(NTFS_RS_CALLBACK_IDMAP struct inode *parent,
        struct dentry *dentry, umode_t mode)
{
    NTFS_RS_CALLBACK_IDMAP_INIT;
    return ntfs_rs_create_node(idmap, parent, dentry, mode, NTFS_RS_NODE_DIRECTORY, NULL, 0, NULL);
}
#endif

static int ntfs_rs_symlink(NTFS_RS_CALLBACK_IDMAP struct inode *parent,
        struct dentry *dentry, const char *target)
{
    NTFS_RS_CALLBACK_IDMAP_INIT;
    return ntfs_rs_create_node(idmap, parent, dentry, 0777, NTFS_RS_NODE_SYMLINK,
        target, strlen(target), NULL);
}

/* O_TMPFILE: an unnamed regular file. The VFS has already checked write and
 * search permission on parent and set S_IFREG; since 6.0 it also strips
 * the umask. Stripping it again on older kernels is idempotent, so this is
 * also correct where the 6.0 fix was backported. */
#ifdef NTFS_RS_TMPFILE_FILE
static int ntfs_rs_tmpfile(NTFS_RS_CALLBACK_IDMAP struct inode *parent,
        struct file *file, umode_t mode)
{
    NTFS_RS_CALLBACK_IDMAP_INIT;
    return ntfs_rs_create_node(idmap, parent, file->f_path.dentry,
        S_IFREG | (mode & 07777), NTFS_RS_NODE_TEMPORARY, NULL, 0, file);
}
#else
static int ntfs_rs_tmpfile(NTFS_RS_CALLBACK_IDMAP struct inode *parent,
        struct dentry *dentry, umode_t mode)
{
    NTFS_RS_CALLBACK_IDMAP_INIT;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
    if (!IS_POSIXACL(parent))
        mode &= ~current_umask();
#endif
    return ntfs_rs_create_node(idmap, parent, dentry,
        S_IFREG | (mode & 07777), NTFS_RS_NODE_TEMPORARY, NULL, 0, NULL);
}
#endif

/* mknod(2) and AF_UNIX bind(2). The VFS has validated the type, required
 * CAP_MKNOD for devices and consulted the device cgroup. Special files are
 * Linux-view objects stored as WSL metadata ($LXMOD, 8-byte $LXDEV); the
 * native NTFS view cannot represent them, so it refuses them with EPERM,
 * which mknod(2) documents for an unsupported node type. */
static int ntfs_rs_mknod(NTFS_RS_CALLBACK_IDMAP struct inode *parent,
        struct dentry *dentry, umode_t mode, dev_t device)
{
    NTFS_RS_CALLBACK_IDMAP_INIT;
    __le32 dev[2] = { 0, 0 };
    if (S_ISREG(mode) || !(mode & S_IFMT))
        return ntfs_rs_create_node(idmap, parent, dentry, S_IFREG | (mode & 07777),
            NTFS_RS_NODE_FILE, NULL, 0, NULL);
    if (!S_ISFIFO(mode) && !S_ISSOCK(mode) && !S_ISCHR(mode) && !S_ISBLK(mode))
        return -EINVAL;
    if (ntfs_rs_native(parent))
        return -EPERM;
    if (S_ISCHR(mode) || S_ISBLK(mode)) {
        dev[0] = cpu_to_le32(MAJOR(device));
        dev[1] = cpu_to_le32(MINOR(device));
    }
    return ntfs_rs_create_node(idmap, parent, dentry, mode, NTFS_RS_NODE_SPECIAL,
        dev, sizeof(dev), NULL);
}

static int ntfs_rs_unlink(struct inode *parent, struct dentry *dentry)
{
    struct inode *inode = d_inode(dentry);
    struct super_block *sb = parent->i_sb;
    struct ntfs_rs_super *state = sb->s_fs_info;
    struct ntfs_rs_inode *private = ntfs_rs_shared(inode);
    unsigned char *scratch;
    int outcome = 0;
    int result;
    if (ntfs_rs_readonly(parent) || !state->writer)
        return -EROFS;
    /* The caller and VFS enforce unlink/rmdir type rules. Rust checks
     * directory emptiness and journals the durable open-file orphan marker. */
    result = ntfs_rs_may_delete(parent, inode);
    if (result)
        return result;
    scratch = state->op_scratch;
    if (!scratch)
        return -ENOMEM;
    down_write(&state->io_lock);
    ntfs_rs_make_room(state);
    state->flushes = 0;
    result = state->write_failed ? -EIO : ntfs_rs_writer_unlink(state->writer,
        sb, ntfs_rs_read_unlocked, ntfs_rs_write_at, ntfs_rs_flush, scratch,
        parent->i_ino | ((u64)parent->i_generation << 48),
        inode->i_ino | ((u64)inode->i_generation << 48), dentry->d_name.name,
        dentry->d_name.len,
        1, /* Reclaim at eviction: O_PATH and cwd also pin the inode. */
        &outcome, !ntfs_rs_native(parent));
    if (result == -EIO)
        ntfs_rs_poison(state, __func__);
    if (!result) {
        if (outcome == NTFS_RS_ORPHANED)
            WRITE_ONCE(private->orphaned, true);
        if (S_ISDIR(inode->i_mode)) {
            clear_nlink(ntfs_rs_canonical(inode));
        } else {
            drop_nlink(ntfs_rs_canonical(inode));
        }
        ntfs_rs_sync_projection(inode);
        ntfs_rs_namespace_changed(parent);
    }
    up_write(&state->io_lock);
    if (scratch != state->op_scratch) kvfree(scratch);
    if (!result) {
        ntfs_rs_touch(parent, true);
        ntfs_rs_touch(inode, false);
        ntfs_rs_sync_projection(inode);
        ntfs_rs_notify_peers(parent, FS_DELETE | (S_ISDIR(inode->i_mode) ? FS_ISDIR : 0), &dentry->d_name, 0, inode);
        ntfs_rs_notify_peers(inode, FS_ATTRIB, NULL, 0, NULL);
    }
    return result;
}

static int ntfs_rs_link(struct dentry *old, struct inode *parent, struct dentry *new)
{
	struct inode *inode = d_inode(old);
	struct super_block *sb = parent->i_sb;
	struct ntfs_rs_super *state = sb->s_fs_info;
	unsigned char *scratch;
	int result;
	if (ntfs_rs_readonly(parent) || !state->writer)
		return -EROFS;
	/* Regular and special files (FIFO, socket, device) may gain names.
	 * Directories never reach here; symbolic links keep one name because
	 * their stored target is resolved relative to that name's directory. */
	if (S_ISLNK(inode->i_mode))
		return -EPERM;
	if (!S_ISREG(inode->i_mode) && !S_ISFIFO(inode->i_mode) && !S_ISSOCK(inode->i_mode) &&
	    !S_ISCHR(inode->i_mode) && !S_ISBLK(inode->i_mode))
		return -EOPNOTSUPP;
	result = ntfs_rs_authorize(parent, 2, false);
	if (!result)
		result = ntfs_rs_authorize(inode, 0x100, false);
	if (result)
		return result;
	scratch = state->op_scratch;
	if (!scratch)
		return -ENOMEM;
	down_write(&state->io_lock);
	ntfs_rs_make_room(state);
	state->flushes = 0;
	result = ntfs_rs_reserve_records(state, scratch);
	if (!result) result = ntfs_rs_writer_link(state->writer,
		sb, ntfs_rs_read_unlocked, ntfs_rs_write_at, ntfs_rs_flush, scratch,
		inode->i_ino | ((u64)inode->i_generation << 48),
		parent->i_ino | ((u64)parent->i_generation << 48), new->d_name.name, new->d_name.len, !ntfs_rs_native(parent));
	if (result == -EIO)
		ntfs_rs_poison(state, __func__);
	if (!result) {
		struct inode *canonical = ntfs_rs_canonical(inode);
		/* Publishing an O_TMPFILE inode: only the view that was opened has
		 * I_LINKABLE, so set the first link directly instead of inc_nlink(). */
		if (!canonical->i_nlink)
			set_nlink(canonical, 1);
		else
			inc_nlink(canonical);
        WRITE_ONCE(ntfs_rs_shared(inode)->orphaned, false);
		ntfs_rs_sync_projection(inode);
		ntfs_rs_namespace_changed(parent);
		ihold(inode);
		d_instantiate(new, inode);
	}
	up_write(&state->io_lock);
	if (scratch != state->op_scratch) kvfree(scratch);
	if (!result) {
        ntfs_rs_touch(parent, true); ntfs_rs_touch(inode, false);
        ntfs_rs_notify_peers(parent, FS_CREATE, &new->d_name, 0, inode);
        ntfs_rs_notify_peers(inode, FS_ATTRIB, NULL, 0, NULL);
    }
    return result;
}

/* Leases live on the view which owns their fd, preserving F_GETLEASE and
 * SIGIO ownership. Every open/truncate breaks conflicting leases in all views. */
static int ntfs_rs_break_leases(struct inode *inode, unsigned int flags)
{
    const struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
    unsigned int policy;
    /* With one view mounted the only peer is the canonical inode. */
    if (!READ_ONCE(state->several_views)) {
        struct inode *canonical = ntfs_rs_canonical(inode);
        int error = break_lease(inode, flags);
        return error || canonical == inode ? error : break_lease(canonical, flags);
    }
    for (policy = ntfs_rs_next_policy(inode, 0); policy != U32_MAX;
            policy = ntfs_rs_next_policy(inode, policy + 1)) {
        struct inode *peer = ntfs_rs_peer(ntfs_rs_canonical(inode), policy);
        int error;
        if (!peer) continue;
        error = break_lease(peer, flags);
        iput(peer);
        if (error) return error;
    }
    return 0;
}

static int ntfs_rs_open(struct inode *inode, struct file *file)
{
    struct inode *canonical = ntfs_rs_canonical(inode);
    struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
    int result = 0;

    if (S_ISREG(inode->i_mode)) {
        file->f_mode |= FMODE_NOWAIT;
#ifdef FMODE_CAN_ODIRECT
        file->f_mode |= FMODE_CAN_ODIRECT;
#endif
    }
    /* With one view mounted, a projection has no peer whose locks, leases or
     * writers its opens must meet on the canonical inode: account for the
     * open directly, as for a canonical inode, and open no second file. */
    if (canonical != inode && READ_ONCE(state->several_views)) {
        struct path path = { .mnt = file->f_path.mnt };
        struct file *backing;
        const struct cred *previous_cred;

        path.dentry = d_obtain_alias(igrab(canonical));
        if (IS_ERR(path.dentry))
            return PTR_ERR(path.dentry);

        /* VFS has checked the caller's visible path before this callback.
         * The canonical handle supplies shared lock and inode accounting;
         * userspace never receives it. Use the mounting credentials for this
         * internal open, as a stacked filesystem does. The public file keeps
         * the caller's credentials and its visible-path security checks.
         * Scope current credentials too: LSM file-security allocation can
         * cache the creating task's label independently of file->f_cred. */
        previous_cred = override_creds(state->mount_cred);
#ifdef NTFS_RS_OPEN_NONOTIFY
        backing = dentry_open_nonotify(&path, file->f_flags, state->mount_cred);
#elif defined(__FMODE_NONOTIFY)
        backing = dentry_open(&path, file->f_flags | __FMODE_NONOTIFY,
                             state->mount_cred);
#else
        /* Unpatched modern kernels do not export the no-notify helper. */
        backing = dentry_open(&path, file->f_flags, state->mount_cred);
#endif
        revert_creds(previous_cred);
        dput(path.dentry);
        if (IS_ERR(backing))
            return PTR_ERR(backing);
        if (file->f_mode & FMODE_EXEC) {
            result = deny_write_access(backing);
            if (result) {
                fput(backing);
                return result;
            }
        }
        file->private_data = backing;
        return 0;
    }
    down_read(&state->io_lock);
    if (!canonical->i_nlink && !(file->f_flags & __O_TMPFILE) &&
        !READ_ONCE(ntfs_rs_shared(inode)->orphaned))
        result = -ENOENT;
    else
        atomic_inc(&ntfs_rs_shared(inode)->open_files);
    up_read(&state->io_lock);
    if (!result) {
        result = ntfs_rs_break_leases(inode, file->f_flags);
        if (result)
            atomic_dec(&ntfs_rs_shared(inode)->open_files);
    }
    /* A file open for writing keeps the session from parking. */
    if (!result && (file->f_mode & FMODE_WRITE)) {
        atomic_set(&ntfs_rs_shared(inode)->trim_due, 1);
        atomic_set(&ntfs_rs_shared(inode)->blocks_known, 0);
        atomic_inc(&ntfs_rs_shared(inode)->writers);
        atomic_inc(&state->write_opens);
    }
    return result;
}

extern int ntfs_rs_writer_trim(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t,
                              ntfs_rs_flush_t, unsigned char *, u64);

static int ntfs_rs_release(struct inode *inode, struct file *file)
{
	struct file *backing = file->private_data;
	if (backing) {
		if (file->f_mode & FMODE_EXEC)
			allow_write_access(backing);
		fput(backing);
	} else {
        struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
        if (file->f_mode & FMODE_WRITE) {
            atomic_dec(&ntfs_rs_shared(inode)->writers);
            atomic_dec(&state->write_opens);
        }
        /* Most closes end a read: only a file that may hold allocation past
         * its end needs the volume lock, which every other operation on the
         * volume would otherwise wait behind. */
        if (!atomic_dec_and_test(&ntfs_rs_shared(inode)->open_files) ||
            !atomic_xchg(&ntfs_rs_shared(inode)->trim_due, 0))
            return 0;
        down_write(&state->io_lock);
        ntfs_rs_make_room(state);
        atomic_set(&ntfs_rs_shared(inode)->blocks_known, 0);
        if (inode->i_nlink && state->writer_ready && !state->write_failed) {
            int error = ntfs_rs_writer_trim(state->writer, NTFS_RS_IO(inode->i_sb),
                state->op_scratch, inode->i_ino | ((u64)inode->i_generation << 48));
            if (error) {
                ntfs_rs_poison(state, __func__);
                mapping_set_error(inode->i_mapping, error);
            }
        }
        up_write(&state->io_lock);
	}
	return 0;
}

static int ntfs_rs_file_flush(struct file *file, fl_owner_t owner)
{
	if (file->private_data)
		locks_remove_posix(file->private_data, owner);
	return 0;
}

static int ntfs_rs_file_lock(struct file *file, int cmd, struct file_lock *lock)
{
	struct file *backing = file->private_data ?: file;
	int result;

	if (cmd == F_CANCELLK)
		return 0;
	/* OFD locks use the backing file as both owner and lifetime token. */
#ifdef NTFS_RS_FILE_LOCK_CORE
	lock->c.flc_file = backing;
	if (lock->c.flc_flags & FL_OFDLCK)
		lock->c.flc_owner = backing;
#else
	lock->fl_file = backing;
	if (lock->fl_flags & FL_OFDLCK)
		lock->fl_owner = backing;
#endif
	if (IS_GETLK(cmd)) {
		posix_test_lock(backing, lock);
		return 0;
	}
	result = posix_lock_file(backing, lock, NULL);
	/* A blocked request is retried by its caller, which expects to find the
	 * file it passed; the granted lock is a copy and keeps the backing file. */
#ifdef NTFS_RS_FILE_LOCK_CORE
	lock->c.flc_file = file;
#else
	lock->fl_file = file;
#endif
	return result;
}

static int ntfs_rs_file_flock(struct file *file, int cmd, struct file_lock *lock)
{
	struct file *backing = file->private_data ?: file;
	(void)cmd;
#ifdef NTFS_RS_FILE_LOCK_CORE
	lock->c.flc_file = backing;
#else
	lock->fl_file = backing;
#endif
	return locks_lock_file_wait(backing, lock);
}

static const struct inode_operations ntfs_rs_dir_inode_ops = {
#ifdef NTFS_RS_FILEATTR_H
    .fileattr_get = ntfs_rs_fileattr_get,
    .fileattr_set = ntfs_rs_fileattr_set,
#endif
    .update_time = ntfs_rs_update_time,
    .mkdir = ntfs_rs_mkdir,
    .mknod = ntfs_rs_mknod,
    .tmpfile = ntfs_rs_tmpfile,
    .rmdir = ntfs_rs_unlink,
    .symlink = ntfs_rs_symlink,
	.link = ntfs_rs_link,
	.create = ntfs_rs_create,
	.unlink = ntfs_rs_unlink,
	.rename = ntfs_rs_rename,
	.setattr = ntfs_rs_setattr,
	.lookup = ntfs_rs_lookup,
	.permission = ntfs_rs_permission,
	.getattr = ntfs_rs_getattr,
	.listxattr = ntfs_rs_listxattr,
#if IS_ENABLED(CONFIG_FS_POSIX_ACL)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
	.get_inode_acl = ntfs_rs_get_inode_acl,
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
	.get_acl = ntfs_rs_get_acl_old,
#else
	.get_acl = ntfs_rs_get_inode_acl,
#endif
	.set_acl = ntfs_rs_set_acl,
#endif
};

static const char *ntfs_rs_get_link(struct dentry *dentry, struct inode *inode,
                                  struct delayed_call *done)
{
    struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
    unsigned char *scratch;
    char *target;
    int n;
    struct ntfs_rs_inode *shared = ntfs_rs_shared(inode);
    struct ntfs_rs_link *link;
    u64 parent;
    if (!dentry) return ERR_PTR(-ECHILD);
    parent = NTFS_RS_REF(d_inode(dentry->d_parent));
    link = READ_ONCE(shared->link);
    if (link && link->parent == parent) return link->target;
    scratch = kvzalloc(ntfs_rs_ea_scratch_size(), GFP_NOFS);
    target = kmalloc(PATH_MAX + 1, GFP_NOFS);
    if (!scratch || !target) { kvfree(scratch); kfree(target); return ERR_PTR(-ENOMEM); }
    down_read(&state->io_lock);
    n = ntfs_rs_read_link(state->boot, inode->i_sb, ntfs_rs_read_unlocked, scratch,
        NTFS_RS_REF(inode), parent, target, PATH_MAX);
    up_read(&state->io_lock);
    kvfree(scratch);
    if (n < 0) { kfree(target); return ERR_PTR(n); }
    target[n] = 0;
    /* Keep the first resolution for the life of the inode; a hard link in
     * another directory resolves on its own each time. */
    if (!link && (link = kmalloc(struct_size(link, target, n + 1), GFP_NOFS))) {
        link->parent = parent;
        memcpy(link->target, target, n + 1);
        if (!cmpxchg(&shared->link, NULL, link)) {
            kfree(target);
            return link->target;
        }
        kfree(link);
    }
    set_delayed_call(done, kfree_link, target);
    return target;
}

static const struct inode_operations ntfs_rs_symlink_inode_ops = {
    .update_time = ntfs_rs_update_time,
    .get_link = ntfs_rs_get_link,
    .getattr = ntfs_rs_getattr,
    .setattr = ntfs_rs_setattr,
    .permission = ntfs_rs_permission,
    .listxattr = ntfs_rs_listxattr,
};

static int ntfs_rs_emit_extent(void *context, u64 logical, u64 physical, u64 length, u32 flags)
{
    return fiemap_fill_next_extent(context, logical, physical, length, flags);
}
static int ntfs_rs_fiemap(struct inode *inode, struct fiemap_extent_info *info, u64 start, u64 length)
{
    struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
    unsigned char *scratch;
    int error = fiemap_prep(ntfs_rs_canonical(inode), info, start, &length, 0);
    if (error) return error;
    scratch = kvzalloc(state->read_scratch_bytes, GFP_NOFS);
    if (!scratch) return -ENOMEM;
    down_read(&state->io_lock);
    error = ntfs_rs_map_file(state->boot, inode->i_sb, ntfs_rs_read_unlocked,
        scratch, state->read_scratch_bytes, NTFS_RS_REF(inode), start, length,
        info, ntfs_rs_emit_extent);
    up_read(&state->io_lock);
    kvfree(scratch);
    return error;
}

static const struct inode_operations ntfs_rs_file_inode_ops = {
#ifdef NTFS_RS_FILEATTR_H
    .fileattr_get = ntfs_rs_fileattr_get,
    .fileattr_set = ntfs_rs_fileattr_set,
#endif
    .update_time = ntfs_rs_update_time,
    .fiemap = ntfs_rs_fiemap,
	.setattr = ntfs_rs_setattr,
	.permission = ntfs_rs_permission,
	.getattr = ntfs_rs_getattr,
	.listxattr = ntfs_rs_listxattr,
#if IS_ENABLED(CONFIG_FS_POSIX_ACL)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
	.get_inode_acl = ntfs_rs_get_inode_acl,
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
	.get_acl = ntfs_rs_get_acl_old,
#else
	.get_acl = ntfs_rs_get_inode_acl,
#endif
	.set_acl = ntfs_rs_set_acl,
#endif
};

static long ntfs_rs_ioctl(struct file *, unsigned int, unsigned long);

static const struct file_operations ntfs_rs_dir_file_ops = {
    .unlocked_ioctl = ntfs_rs_ioctl,
    .compat_ioctl = compat_ptr_ioctl,
    .open = ntfs_rs_dir_open,
    .release = ntfs_rs_dir_release,
	.fsync = ntfs_rs_fsync,
	.owner = THIS_MODULE,
	.iterate_shared = ntfs_rs_iterate,
	.llseek = generic_file_llseek,
};

/* A NOWAIT write may modify an already-dirty, uptodate cached page.
 * Everything requiring allocation, faults, timestamp/privilege work, data
 * writeback or an extending transaction returns EAGAIN before copying. */
/* Whether the file's page cache holds nothing at all. */
static bool ntfs_rs_mapping_empty(struct address_space *mapping)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	return mapping_empty(mapping);
#else
	return !mapping->nrpages && !mapping->nrexceptional;
#endif
}

static ssize_t ntfs_rs_write_nowait(struct kiocb *iocb, struct iov_iter *from)
{
    struct file *file = iocb->ki_filp;
    struct inode *inode = ntfs_rs_canonical(file_inode(file));
    struct address_space *mapping = inode->i_mapping;
    struct page *page;
#ifdef NTFS_RS_KIOCB_MODIFIED
    struct kiocb check = *iocb;
#endif
    ssize_t result = -EAGAIN;
    size_t n;
    if (!iov_iter_count(from)) return 0;
    if (iocb->ki_flags & (IOCB_DIRECT | IOCB_APPEND | IOCB_DSYNC | IOCB_SYNC)) return -EAGAIN;
    if (iocb->ki_pos < 0) return -EINVAL;
    if (!inode_trylock(inode)) return -EAGAIN;
    if (READ_ONCE(((struct ntfs_rs_super *)inode->i_sb->s_fs_info)->write_failed)) {
        result = -EIO; goto out;
    }
    if (iocb->ki_pos >= i_size_read(inode)) goto out;
    result = ntfs_rs_authorize(inode, NTFS_RS_WRITE_DATA, true);
    if (result) { if (result == -ECHILD) result = -EAGAIN; goto out; }
    result = -EAGAIN;
    /* A cold capability lookup allocates and may read the device. NOWAIT
     * can proceed only after a blocking writer established NOSEC. */
    if (!IS_NOSEC(inode)) goto out;
#ifdef NTFS_RS_KIOCB_MODIFIED
    check.ki_filp = file;
    result = kiocb_modified(&check);
    if (result) goto out;
#else
    {
        struct timespec64 now = current_time(inode);
        struct timespec64 mtime = ntfs_rs_get_mtime(inode), ctime = ntfs_rs_get_ctime(inode);
        /* Old kernels have no exported NOWAIT privilege helper. */
        if (!timespec64_equal(&now, &mtime) || !timespec64_equal(&now, &ctime)) goto out;
    }
#endif
    result = -EAGAIN;
    if (!filemap_invalidate_trylock_shared(mapping)) goto out;
    page = find_get_page(mapping, iocb->ki_pos >> PAGE_SHIFT);
    if (!page) goto invalidate_out;
    if (!trylock_page(page)) goto put;
    if (page->mapping != mapping || !PageUptodate(page) || !PageDirty(page) || PageWriteback(page)) goto unlock;
    n = min_t(size_t, iov_iter_count(from), PAGE_SIZE - offset_in_page(iocb->ki_pos));
    n = min_t(u64, n, i_size_read(inode) - iocb->ki_pos);
    pagefault_disable();
#ifdef NTFS_RS_COPY_FOLIO_ATOMIC
    n = copy_folio_from_iter_atomic(page_folio(page), offset_in_page(iocb->ki_pos), n, from);
#else
    n = copy_page_from_iter_atomic(page, offset_in_page(iocb->ki_pos), n, from);
#endif
    pagefault_enable();
    if (n) {
        flush_dcache_page(page);
        iocb->ki_pos += n;
        result = n;
    }
unlock:
    unlock_page(page);
put:
    put_page(page);
invalidate_out:
    filemap_invalidate_unlock_shared(mapping);
out:
    inode_unlock(inode);
#ifndef NTFS_RS_FSNOTIFY_PATH
    if (result > 0) ntfs_rs_notify_peers(file_inode(file), FS_MODIFY, NULL, 0, NULL);
#endif
    return result;
}

static ssize_t ntfs_rs_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *view = file_inode(iocb->ki_filp);
	struct inode *inode = ntfs_rs_canonical(view);
	struct super_block *sb = inode->i_sb;
	struct ntfs_rs_super *state = sb->s_fs_info;
	unsigned char *data;
	size_t count = iov_iter_count(from);
	ssize_t result;
	if (ntfs_rs_readonly(view) || !state->writer)
		return -EROFS;
    if (ntfs_rs_content_forbidden(view, iocb->ki_flags & IOCB_APPEND)) return -EPERM;
    if (iocb->ki_flags & IOCB_NOWAIT)
        return ntfs_rs_write_nowait(iocb, from);
    if ((iocb->ki_flags & IOCB_DIRECT) &&
        ((iocb->ki_pos | iov_iter_alignment(from)) & (bdev_logical_block_size(sb->s_bdev) - 1)))
        return -EINVAL;
    if (!count) { return 0; }
    /* Report a POSIX short write at the transaction bound. The caller can
     * retry the remainder without turning one syscall into multiple commits. */
    count = min_t(size_t, count, NTFS_RS_MAX_WRITE);
    /* Faulting user memory can enter this filesystem again (including a
     * shared writable mapping). Copy before taking filesystem locks. */
    data = kvmalloc(count, GFP_NOFS);
    if (!data) return -ENOMEM;
    if (!copy_from_iter_full(data, count, from)) { kvfree(data); return -EFAULT; }
	inode_lock(inode);
    if (iocb->ki_flags & IOCB_DIRECT) inode_dio_begin(inode);
	if (ntfs_rs_content_forbidden(view, iocb->ki_flags & IOCB_APPEND)) {
		result = -EPERM;
		goto out;
	}
	result = ntfs_rs_authorize(inode, 2, false);
	if (result)
		goto out;
	if (iocb->ki_pos < 0 || count > sb->s_maxbytes - iocb->ki_pos) {
		result = -EFBIG;
		goto out;
	}
    /* The backing file names the canonical inode whose i_rwsem we hold. */
    result = file_remove_privs(iocb->ki_filp);
    if (result) goto out;
	if (!state->op_scratch) {
		result = -ENOMEM;
		goto out;
	}
	/* Lock order: inode -> page-cache invalidation -> volume transaction. */
	filemap_invalidate_lock(inode->i_mapping);
	if (iocb->ki_flags & IOCB_APPEND)
		iocb->ki_pos = i_size_read(inode);
	if (count > sb->s_maxbytes - iocb->ki_pos) {
		result = -EFBIG;
		goto invalidate_out;
	}
    if ((iocb->ki_flags & IOCB_DIRECT) &&
        (iocb->ki_pos & (bdev_logical_block_size(sb->s_bdev) - 1))) {
        result = -EINVAL; goto invalidate_out;
    }
	/* A file nobody has read or mapped has no cached pages to write back,
	 * unmap or invalidate: the common case while a file is being copied in,
	 * and three walks saved on every write. */
	if (!ntfs_rs_mapping_empty(inode->i_mapping)) {
		result = filemap_write_and_wait_range(inode->i_mapping, iocb->ki_pos, iocb->ki_pos + count - 1);
		if (result) goto invalidate_out;
		unmap_mapping_range(inode->i_mapping, iocb->ki_pos & PAGE_MASK,
			PAGE_ALIGN((iocb->ki_pos & ~PAGE_MASK) + count), 0);
		result = invalidate_inode_pages2_range(inode->i_mapping,
			iocb->ki_pos >> PAGE_SHIFT,
			(iocb->ki_pos + count - 1) >> PAGE_SHIFT);
		if (result)
			goto invalidate_out;
	}
	down_write(&state->io_lock);
	ntfs_rs_make_room(state);
	state->flushes = 0;
	if (state->write_failed) {
		result = -EIO;
	} else {
        state->direct_io = !!(iocb->ki_flags & IOCB_DIRECT);
		result = ntfs_rs_writer_write(state->writer, sb, ntfs_rs_read_unlocked,
			ntfs_rs_write_at, ntfs_rs_flush, state->op_scratch,
			inode->i_ino | ((u64)inode->i_generation << 48),
			iocb->ki_pos, data, count);
        state->direct_io = false;
        /* Complete data and resident/size metadata before returning direct I/O. */
        if (!result && (iocb->ki_flags & IOCB_DIRECT)) result = ntfs_rs_drain_locked(sb, false);
		if (result == -EIO) {
			ntfs_rs_poison(state, __func__);
			mapping_set_error(inode->i_mapping, -EIO);
		}
	}
	if (!result) {
		iocb->ki_pos += count;
		if (iocb->ki_pos > i_size_read(inode))
			i_size_write(inode, iocb->ki_pos);
		ntfs_rs_sync_projection(inode);
		result = count;
	}
	up_write(&state->io_lock);
invalidate_out:
	filemap_invalidate_unlock(inode->i_mapping);
out:
	if (result < 0)
		iov_iter_revert(from, count);
	kvfree(data);
    if (iocb->ki_flags & IOCB_DIRECT) inode_dio_end(inode);
	inode_unlock(inode);
    if (result > 0) {
        ntfs_rs_touch(view, true);
#ifndef NTFS_RS_FSNOTIFY_PATH
        ntfs_rs_notify_peers(view, FS_MODIFY, NULL, 0, NULL);
#endif
        /* Each MiB a buffered writer crosses queues block-cache writeback, so
         * the device works while the caller produces more data instead of
         * idling until the next drain. A pending request absorbs later ones. */
        if (!(iocb->ki_flags & IOCB_DIRECT) &&
            (iocb->ki_pos - result) / NTFS_RS_WRITEBACK_KICK_BYTES !=
            iocb->ki_pos / NTFS_RS_WRITEBACK_KICK_BYTES)
            queue_work(system_unbound_wq, &state->writeback_work);
        result = generic_write_sync(iocb, result);
    }
    return result;
}

static int ntfs_rs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct super_block *sb = file_inode(file)->i_sb;
	struct ntfs_rs_super *state = sb->s_fs_info;
	int result;
    struct writeback_control wbc = { .sync_mode = WB_SYNC_NONE };
    inode_dio_wait(ntfs_rs_canonical(file_inode(file)));
    result = file_write_and_wait_range(file, start, end);
    if (result) return result;
    /* ->write_inode persists only mtime/ctime/atime. fdatasync need not
     * journal those timestamp-only changes; size/allocation and all metadata
     * required to retrieve file data are committed by their operation paths. */
    if (!datasync) {
        result = ntfs_rs_write_inode(ntfs_rs_canonical(file_inode(file)), &wbc);
        if (result) return result;
    }
    if (!state->writer_ready) {
        return state->write_failed ? -EIO : file_check_and_advance_wb_err(file);
    }
	down_write(&state->io_lock);
	result = ntfs_rs_drain_locked(sb, false);
	if (result) {
		ntfs_rs_poison(state, __func__);
		mapping_set_error(file->f_mapping, result);
	}
	up_write(&state->io_lock);
	return result ? result : file_check_and_advance_wb_err(file);
}

static vm_fault_t ntfs_rs_page_mkwrite(struct vm_fault *vmf)
{
    struct inode *inode = ntfs_rs_canonical(file_inode(vmf->vma->vm_file));
    struct address_space *mapping = inode->i_mapping;
    vm_fault_t result = VM_FAULT_LOCKED;
    if (ntfs_rs_readonly(file_inode(vmf->vma->vm_file)) ||
        ntfs_rs_content_forbidden(file_inode(vmf->vma->vm_file), false)) return VM_FAULT_SIGBUS;
    sb_start_pagefault(inode->i_sb);
    if (READ_ONCE(((struct ntfs_rs_super *)inode->i_sb->s_fs_info)->write_failed)) {
        sb_end_pagefault(inode->i_sb);
        return VM_FAULT_SIGBUS;
    }
    inode_lock(inode);
    if (file_remove_privs(vmf->vma->vm_file)) {
        inode_unlock(inode);
        sb_end_pagefault(inode->i_sb);
        return VM_FAULT_SIGBUS;
    }
    ntfs_rs_touch(inode, true);
    inode_unlock(inode);
    filemap_invalidate_lock_shared(mapping);
#ifdef NTFS_RS_FOLIO_AOPS
    {
    struct folio *folio = page_folio(vmf->page);
    folio_lock(folio);
    if (folio->mapping != mapping || folio_pos(folio) >= i_size_read(inode)) {
        folio_unlock(folio);
        result = VM_FAULT_NOPAGE;
    } else {
        folio_wait_writeback(folio);
        folio_mark_dirty(folio);
    }
    }
#else
    lock_page(vmf->page);
    if (vmf->page->mapping != mapping || page_offset(vmf->page) >= i_size_read(inode)) {
        unlock_page(vmf->page);
        result = VM_FAULT_NOPAGE;
    } else {
        wait_on_page_writeback(vmf->page);
        set_page_dirty(vmf->page);
    }
#endif
    filemap_invalidate_unlock_shared(mapping);
    sb_end_pagefault(inode->i_sb);
    if (result == VM_FAULT_LOCKED) {
        fsnotify_modify(vmf->vma->vm_file);
        ntfs_rs_notify_peers(file_inode(vmf->vma->vm_file), FS_MODIFY, NULL, 0, NULL);
    }
    return result;
}

static const struct vm_operations_struct ntfs_rs_vm_ops = {
    .fault = filemap_fault,
    .map_pages = filemap_map_pages,
    .page_mkwrite = ntfs_rs_page_mkwrite,
};

static int ntfs_rs_mmap(struct file *file, struct vm_area_struct *vma)
{
    int error;
    if ((vma->vm_flags & VM_EXEC) && (ntfs_rs_limits(file_inode(file)) & NTFS_RS_VIEW_NOEXEC))
        return -EACCES;
    if (ntfs_rs_limits(file_inode(file)) & NTFS_RS_VIEW_NOEXEC) {
#ifdef NTFS_RS_VM_FLAGS_HELPERS
        vm_flags_clear(vma, VM_MAYEXEC);
#else
        vma->vm_flags &= ~VM_MAYEXEC;
#endif
    }
    if ((vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_WRITE)) {
        if (ntfs_rs_readonly(file_inode(file))) return -EROFS;
        if (ntfs_rs_content_forbidden(file_inode(file), false)) return -EPERM;
        error = ntfs_rs_authorize(file_inode(file), NTFS_RS_WRITE_DATA, false);
        if (error) return error;
    }
    error = generic_file_mmap(file, vma);
    if (!error) vma->vm_ops = &ntfs_rs_vm_ops;
    return error;
}

static loff_t ntfs_rs_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = ntfs_rs_canonical(file_inode(file));
	return generic_file_llseek_size(file, offset, whence, inode->i_sb->s_maxbytes,
		i_size_read(inode));
}

#ifdef NTFS_RS_FILE_LEASE
static int ntfs_rs_setlease(struct file *file, int arg, struct file_lease **lease, void **private)
#elif defined(NTFS_RS_SETLEASE_INT)
static int ntfs_rs_setlease(struct file *file, int arg, struct file_lock **lease, void **private)
#else
static int ntfs_rs_setlease(struct file *file, long arg, struct file_lock **lease, void **private)
#endif
{
    struct inode *inode = ntfs_rs_canonical(file_inode(file));
    struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
    int error;
    down_write(&state->io_lock);
    if ((arg == F_WRLCK && atomic_read(&ntfs_rs_shared(inode)->open_files) != 1) ||
        (arg == F_RDLCK && atomic_read(&ntfs_rs_shared(inode)->writers) > 0)) error = -EAGAIN;
    else error = generic_setlease(file, arg, lease, private);
    up_write(&state->io_lock);
    return error;
}

extern int ntfs_rs_writer_allocate(void *, void *, ntfs_rs_read_t, ntfs_rs_write_t,
    ntfs_rs_flush_t, unsigned char *, u64, u64, u64, u32, u64 *);
static long ntfs_rs_fallocate(struct file *file, int mode, loff_t offset, loff_t length)
{
    struct inode *inode = ntfs_rs_canonical(file_inode(file));
    struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
    u64 size = i_size_read(inode);
    loff_t first, last;
    int error;
    switch (mode) {
    case 0: case FALLOC_FL_KEEP_SIZE:
    case FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE:
    case FALLOC_FL_ZERO_RANGE: case FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE:
    case FALLOC_FL_COLLAPSE_RANGE: case FALLOC_FL_INSERT_RANGE:
    case FALLOC_FL_UNSHARE_RANGE: case FALLOC_FL_UNSHARE_RANGE | FALLOC_FL_KEEP_SIZE: break;
    default: return -EOPNOTSUPP;
    }
    if (ntfs_rs_readonly(file_inode(file))) return -EROFS;
    if (offset < 0 || length <= 0 || offset > inode->i_sb->s_maxbytes - length) return -EFBIG;
    error = ntfs_rs_authorize(inode, NTFS_RS_WRITE_DATA, false);
    if (error) return error;
    error = ntfs_rs_break_leases(inode, O_WRONLY);
    if (error) return error;
    inode_lock(inode);
    if (mode == FALLOC_FL_INSERT_RANGE && length > inode->i_sb->s_maxbytes - i_size_read(inode)) {
        error = -EFBIG; goto unlock;
    }
    if (mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE |
                FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE)) {
        error = file_remove_privs(file);
        if (error) goto unlock;
    }
    first = offset & PAGE_MASK;
    last = (mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE)) ? LLONG_MAX :
        ((offset + length - 1) | (PAGE_SIZE - 1));
    filemap_invalidate_lock(inode->i_mapping);
    unmap_mapping_range(inode->i_mapping, first, last == LLONG_MAX ? 0 : last - first + 1, 1);
    error = filemap_write_and_wait(inode->i_mapping);
    if (!error) {
        truncate_inode_pages_range(inode->i_mapping, first, last);
        /* A plain preallocation runs in steps, releasing the volume lock
         * between them: other files stay responsive during a large request.
         * Only the last step publishes the new length. The inode lock keeps
         * this file unchanged meanwhile. */
        bool stepwise = !(mode & ~FALLOC_FL_KEEP_SIZE);
        loff_t at = offset, end = offset + length;
        do {
            loff_t step = stepwise ? min_t(loff_t, end - at, NTFS_RS_ALLOCATE_STEP_BYTES) : end - at;
            int step_mode = at + step < end ? mode | FALLOC_FL_KEEP_SIZE : mode;
            down_write(&state->io_lock);
            ntfs_rs_make_room(state);
            error = state->write_failed ? -EIO : ntfs_rs_writer_allocate(state->writer,
                NTFS_RS_IO(inode->i_sb), state->op_scratch, NTFS_RS_REF(inode), at, step, step_mode, &size);
            if (!error && at + step == end) i_size_write(inode, size);
            if (error == -EIO) { ntfs_rs_poison(state, __func__); mapping_set_error(inode->i_mapping, error); }
            up_write(&state->io_lock);
            at += step;
            if (!error && at < end) {
                if (fatal_signal_pending(current)) error = -EINTR;
                cond_resched();
            }
        } while (!error && at < end);
    }
    filemap_invalidate_unlock(inode->i_mapping);
    if (!error) { ntfs_rs_touch(inode, true); ntfs_rs_sync_projection(inode);
        ntfs_rs_notify_peers(file_inode(file), FS_MODIFY | FS_ATTRIB, NULL, 0, NULL); }
unlock:
    inode_unlock(inode);
    return error;
}
static ssize_t ntfs_rs_copy_file_range(struct file *in, loff_t from, struct file *out,
    loff_t to, size_t length, unsigned int flags)
{
    if (flags) return -EINVAL;
#ifdef NTFS_RS_SPLICE_COPY_RANGE
    return splice_copy_file_range(in, from, out, to, min_t(size_t, length, NTFS_RS_MAX_WRITE));
#else
    return generic_copy_file_range(in, from, out, to,
        min_t(size_t, length, NTFS_RS_MAX_WRITE), 0);
#endif
}
static ssize_t ntfs_rs_splice_write(struct pipe_inode_info *pipe, struct file *out,
    loff_t *ppos, size_t length, unsigned int flags)
{
    /* Keep one write_iter transaction within the writer's bounded request size. */
    return iter_file_splice_write(pipe, out, ppos,
        min_t(size_t, length, NTFS_RS_MAX_WRITE), flags);
}

extern int ntfs_rs_volume_identity(const unsigned char *, void *, ntfs_rs_read_t,
    unsigned char *, unsigned char *, unsigned char *);
extern int ntfs_rs_trim_free(const unsigned char *, void *, ntfs_rs_read_t,
    unsigned char *, u64, u64, u64, int (*)(void *, u64, u64), u64 *);

static int ntfs_rs_discard(void *context, u64 offset, u64 length)
{
    struct super_block *sb = context;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
    return blkdev_issue_discard(sb->s_bdev, offset >> 9, length >> 9, GFP_NOFS);
#else
    return blkdev_issue_discard(sb->s_bdev, offset >> 9, length >> 9, GFP_NOFS, 0);
#endif
}

static int ntfs_rs_fitrim(struct file *file, unsigned long arg)
{
    struct super_block *sb = file_inode(file)->i_sb;
    struct ntfs_rs_super *state = sb->s_fs_info;
    struct fstrim_range range;
    unsigned char *scratch;
    int error;
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;
    if (ntfs_rs_readonly(file_inode(file))) return -EROFS;
#ifdef NTFS_RS_BDEV_DISCARD
    if (!bdev_max_discard_sectors(sb->s_bdev)) return -EOPNOTSUPP;
#else
    if (!blk_queue_discard(bdev_get_queue(sb->s_bdev))) return -EOPNOTSUPP;
#endif
    if (copy_from_user(&range, (void __user *)arg, sizeof(range))) return -EFAULT;
    if (range.start > U64_MAX - range.len) return -EINVAL;
    scratch = kvzalloc(ntfs_rs_ea_scratch_size(), GFP_NOFS);
    if (!scratch) return -ENOMEM;
    error = mnt_want_write_file(file);
    if (error) goto free;
    down_write(&state->io_lock);
    /* Freed clusters are discardable only after their metadata checkpoint.
     * Exclude new allocations until every synchronous discard is complete. */
    error = !state->writer_ready || state->write_failed ? -EIO : ntfs_rs_drain_locked(sb, true);
    if (!error) error = ntfs_rs_trim_free(state->boot, sb, ntfs_rs_read_unlocked,
        scratch, range.start, range.len, max_t(u64, range.minlen, sb->s_blocksize),
        ntfs_rs_discard, &range.len);
    up_write(&state->io_lock);
    mnt_drop_write_file(file);
free:
    kvfree(scratch);
    if (!error && copy_to_user((void __user *)arg, &range, sizeof(range))) return -EFAULT;
    return error;
}

/* Same command number as the Linux ext4/exfat shutdown ABI. Only full-sync
 * shutdown is implemented; a failed session stays poisoned until unmount. */
extern int ntfs_rs_writer_repair_ea(void *, void *, ntfs_rs_read_t,
    ntfs_rs_write_t, ntfs_rs_flush_t, unsigned char *, u64);
extern int ntfs_rs_writer_repair_ea_number(void *, void *, ntfs_rs_read_t,
    ntfs_rs_write_t, ntfs_rs_flush_t, unsigned char *, u64);
extern int ntfs_rs_writer_repair_allocation_sector(void *, void *, ntfs_rs_read_t,
    ntfs_rs_write_t, ntfs_rs_flush_t, unsigned char *, u64);
extern int ntfs_rs_writer_repair_data(void *, void *, ntfs_rs_read_t,
    ntfs_rs_write_t, ntfs_rs_flush_t, unsigned char *, u64);

static long ntfs_rs_repair_data(struct file *file, unsigned long arg)
{
    struct inode *view = file_inode(file), *inode = ntfs_rs_canonical(view);
    struct super_block *sb = inode->i_sb;
    struct ntfs_rs_super *state = sb->s_fs_info;
    int error, thaw_error;
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;
    if (arg) return -EINVAL;
    if (ntfs_rs_readonly(view)) return -EROFS;
    if (view != inode || !S_ISREG(inode->i_mode)) return -EOPNOTSUPP;
    error = ntfs_rs_break_leases(inode, O_WRONLY);
    if (error) return error;
    /* Freeze before taking inode/io locks: freeze flushes through both.
     * It quiesces all possible owners, not merely the selected file. There
     * must be no mnt_want_write reference held across our own freeze. */
    error = bdev_freeze(sb->s_bdev);
    if (error) return error;
    inode_lock(inode);
    inode_dio_wait(inode);
    filemap_invalidate_lock(inode->i_mapping);
    unmap_mapping_range(inode->i_mapping, 0, 0, 1);
    /* Freeze has already flushed dirty pages. Refuse pinned/dirty pages
     * instead of discarding data or starting writeback while frozen. */
    error = invalidate_inode_pages2(inode->i_mapping);
    if (!error) {
        down_write(&state->io_lock);
        ntfs_rs_make_room(state);
        state->flushes = 0;
        error = !state->writer_ready || !state->writer || state->write_failed ? -EIO :
            sb_rdonly(sb) ? -EROFS : ntfs_rs_writer_repair_data(state->writer,
                NTFS_RS_IO(sb), state->op_scratch, NTFS_RS_REF(inode));
        if (error == -EIO) { ntfs_rs_poison(state, __func__); mapping_set_error(inode->i_mapping, error); }
        up_write(&state->io_lock);
    }
    filemap_invalidate_unlock(inode->i_mapping);
    inode_unlock(inode);
    thaw_error = bdev_thaw(sb->s_bdev);
    if (thaw_error) return thaw_error;
    return error;
}

static long ntfs_rs_repair_ea(struct file *file, unsigned long arg)
{
    struct inode *view = file_inode(file), *inode = ntfs_rs_canonical(view);
    struct super_block *sb = inode->i_sb;
    struct ntfs_rs_super *state = sb->s_fs_info;
    int error;
    /* Host administrator only; delegated view mounts cannot acquire this
     * power through a user-namespace CAP_SYS_ADMIN or a writable fd. */
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;
    if (arg) return -EINVAL;
    if (view != inode || (ntfs_rs_limits(view) & NTFS_RS_VIEW_RO)) return -EOPNOTSUPP;
    if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode)) return -EOPNOTSUPP;
    error = mnt_want_write_file(file);
    if (error) return error;
    inode_lock(inode);
    down_write(&state->io_lock);
    ntfs_rs_make_room(state);
    state->flushes = 0;
    error = !state->writer_ready || !state->writer || state->write_failed ? -EIO :
        ntfs_rs_writer_repair_ea(state->writer, NTFS_RS_IO(sb),
            state->op_scratch, NTFS_RS_REF(inode));
    if (error == -EIO) ntfs_rs_poison(state, __func__);
    /* EA values, inode fields, stream mappings and names are unchanged.
     * The ordinary writer updates the shared metadata buffer cache. */
    up_write(&state->io_lock);
    inode_unlock(inode);
    mnt_drop_write_file(file);
    return error;
}

static long ntfs_rs_repair_number(struct file *file, unsigned long arg, bool allocation)
{
    struct inode *view = file_inode(file), *inode = ntfs_rs_canonical(view);
    struct super_block *sb = inode->i_sb;
    struct ntfs_rs_super *state = sb->s_fs_info;
    __u64 number;
    int error, thaw_error;
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;
    if (copy_from_user(&number, (void __user *)arg, sizeof(number))) return -EFAULT;
    if (allocation ? number % 512 != 0 : number >= (1ULL << 48)) return -EINVAL;
    if (view != inode || !S_ISDIR(inode->i_mode) ||
        (ntfs_rs_limits(view) & NTFS_RS_VIEW_RO)) return -EOPNOTSUPP;
    if (ntfs_rs_readonly(view) || sb_rdonly(sb)) return -EROFS;
    error = bdev_freeze(sb->s_bdev);
    if (error) return error;
    down_write(&state->io_lock);
    ntfs_rs_make_room(state);
    state->flushes = 0;
    error = !state->writer_ready || !state->writer || state->write_failed ? -EIO :
        allocation ? ntfs_rs_writer_repair_allocation_sector(state->writer,
            NTFS_RS_IO(sb), state->op_scratch, number) :
        ntfs_rs_writer_repair_ea_number(state->writer, NTFS_RS_IO(sb), state->op_scratch, number);
    if (error == -EIO) ntfs_rs_poison(state, __func__);
    up_write(&state->io_lock);
    thaw_error = bdev_thaw(sb->s_bdev);
    if (thaw_error) return thaw_error;
    return error;
}

static long ntfs_rs_ioctl(struct file *file, unsigned int command, unsigned long arg)
{
    struct super_block *sb = file_inode(file)->i_sb;
    struct ntfs_rs_super *state = sb->s_fs_info;
    u32 flags;
    int error;
    if (command == NTFS_RS_IOC_GET_VISIBILITY || command == NTFS_RS_IOC_SET_VISIBILITY) {
        struct inode *inode = file_inode(file);
        struct ntfs_rs_visibility *policy = ntfs_rs_visibility_policy(inode);
        if (!policy) return -ESTALE;
        if (command == NTFS_RS_IOC_GET_VISIBILITY)
            return put_user(READ_ONCE(policy->flags), (__u32 __user *)arg);
        if (!capable(CAP_SYS_ADMIN) &&
            (!(ntfs_rs_limits(inode) >> 2) || !uid_eq(policy->owner, current_fsuid())))
            return -EPERM;
        if (get_user(flags, (__u32 __user *)arg)) return -EFAULT;
        if (flags & ~7U) return -EINVAL;
        WRITE_ONCE(policy->flags, flags);
        fsnotify_change(file->f_path.dentry, ATTR_MODE);
        return 0;
    }
#ifndef NTFS_RS_FILEATTR_H
    if (command == FS_IOC_GETFLAGS) {
        error = ntfs_rs_flags_get(file->f_path.dentry, &flags);
        if (error) return error;
        return put_user(flags, (__u32 __user *)arg);
    }
    if (command == FS_IOC_SETFLAGS) {
        if (get_user(flags, (__u32 __user *)arg)) return -EFAULT;
        return ntfs_rs_flags_set(file->f_path.dentry, flags);
    }
#endif
    if (command == NTFS_RS_IOC_REPAIR_EA) return ntfs_rs_repair_ea(file, arg);
    if (command == NTFS_RS_IOC_REPAIR_DATA) return ntfs_rs_repair_data(file, arg);
    if (command == NTFS_RS_IOC_REPAIR_EA_NUMBER) return ntfs_rs_repair_number(file, arg, false);
    if (command == NTFS_RS_IOC_REPAIR_ALLOCATION_SECTOR) return ntfs_rs_repair_number(file, arg, true);
    if (command == FITRIM) return ntfs_rs_fitrim(file, arg);
    if (command == FS_IOC_GETFSLABEL) {
        unsigned char label[FSLABEL_MAX], uuid[8];
        unsigned char *scratch = kvzalloc(ntfs_rs_ea_scratch_size(), GFP_NOFS);
        if (!scratch) return -ENOMEM;
        down_read(&state->io_lock);
        error = ntfs_rs_volume_identity(state->boot, sb, ntfs_rs_read_unlocked, scratch, label, uuid);
        up_read(&state->io_lock);
        kvfree(scratch);
        if (!error && copy_to_user((void __user *)arg, label, sizeof(label))) error = -EFAULT;
        return error;
    }
    if (command == FS_IOC_SETFSLABEL) {
        /* Renaming the volume is an administrator action (like ext4/btrfs). */
        unsigned char label[FSLABEL_MAX];
        size_t length;
        if (!capable(CAP_SYS_ADMIN)) return -EPERM;
        if (copy_from_user(label, (void __user *)arg, sizeof(label))) return -EFAULT;
        length = strnlen((const char *)label, sizeof(label));
        if (length == sizeof(label)) return -EINVAL;
        if (!state->writer || sb_rdonly(sb)) return -EROFS;
        if (!state->op_scratch) return -ENOMEM;
        error = mnt_want_write_file(file);
        if (error) return error;
        error = ntfs_rs_begin(state);
        if (!error)
            error = ntfs_rs_writer_set_label(state->writer, NTFS_RS_IO(sb), state->op_scratch,
                                             label, length);
        ntfs_rs_end(state, error);
        mnt_drop_write_file(file);
        return error;
    }
    if (command != NTFS_RS_IOC_SHUTDOWN) return -ENOTTY;
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;
    if (get_user(flags, (__u32 __user *)arg)) return -EFAULT;
    if (flags > 2) return -EINVAL;
    if (flags) return -EOPNOTSUPP;
    if (!state->writer || sb_rdonly(sb)) return -EROFS;
    error = bdev_freeze(sb->s_bdev);
    if (error) return error;
    down_write(&state->io_lock);
    error = state->write_failed ? -EIO : 0;
    if (!error) {
        /* Freeze has written page-cache data and checkpointed metadata.
         * Keep the dirty-volume marker for explicit offline recovery. */
        WRITE_ONCE(state->write_failed, true);
    }
    up_write(&state->io_lock);
    bdev_thaw(sb->s_bdev);
    return error;
}

static ssize_t ntfs_rs_direct_read(struct kiocb *iocb, struct iov_iter *to)
{
    struct inode *inode = ntfs_rs_canonical(file_inode(iocb->ki_filp));
    struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
    size_t count = min_t(size_t, iov_iter_count(to), NTFS_RS_READAHEAD_BYTES);
    unsigned char *data, *scratch;
    ssize_t result;
    if (!count) return 0;
    if (iocb->ki_flags & IOCB_NOWAIT) return -EAGAIN;
    if (iocb->ki_pos < 0 ||
        ((iocb->ki_pos | iov_iter_alignment(to)) & (bdev_logical_block_size(inode->i_sb->s_bdev) - 1))) return -EINVAL;
    data = kvmalloc(count, GFP_NOFS);
    scratch = kvmalloc(state->read_scratch_bytes, GFP_NOFS);
    if (!data || !scratch) { result = -ENOMEM; goto free; }
    inode_lock_shared(inode);
    inode_dio_begin(inode);
    if (iocb->ki_pos >= i_size_read(inode)) { result = 0; goto unlock; }
    count = min_t(u64, count, i_size_read(inode) - iocb->ki_pos);
    filemap_invalidate_lock(inode->i_mapping);
    result = filemap_write_and_wait_range(inode->i_mapping, iocb->ki_pos, iocb->ki_pos + count - 1);
    if (!result) {
        down_write(&state->io_lock);
        result = sync_blockdev(inode->i_sb->s_bdev);
        if (!result) result = ntfs_rs_read_file(state->boot, 512, inode->i_sb,
            ntfs_rs_direct_read_at, scratch, state->read_scratch_bytes, NTFS_RS_REF(inode),
            iocb->ki_pos, data, count);
        up_write(&state->io_lock);
    }
    filemap_invalidate_unlock(inode->i_mapping);
    if (!result) result = count;
unlock:
    inode_dio_end(inode);
    inode_unlock_shared(inode);
    /* Copy after releasing filesystem locks: a user fault can read this FS. */
    if (result > 0) {
        size_t copied = copy_to_iter(data, result, to);
        result = copied ? copied : -EFAULT;
        iocb->ki_pos += copied;
        file_accessed(iocb->ki_filp);
    }
free:
    kvfree(scratch); kvfree(data);
    return result;
}

static ssize_t ntfs_rs_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
    ssize_t result = (iocb->ki_flags & IOCB_DIRECT) ? ntfs_rs_direct_read(iocb, to) :
        generic_file_read_iter(iocb, to);
#ifndef NTFS_RS_FSNOTIFY_PATH
    if (result > 0)
        ntfs_rs_notify_peers(file_inode(iocb->ki_filp), FS_ACCESS, NULL, 0, NULL);
#endif
    return result;
}

static const struct file_operations ntfs_rs_file_ops = {
	.open = ntfs_rs_open,
	.release = ntfs_rs_release,
    .unlocked_ioctl = ntfs_rs_ioctl,
    .compat_ioctl = compat_ptr_ioctl,
	.flush = ntfs_rs_file_flush,
	.lock = ntfs_rs_file_lock,
	.flock = ntfs_rs_file_flock,
	.setlease = ntfs_rs_setlease,
	.owner = THIS_MODULE,
	.read_iter = ntfs_rs_read_iter,
	.mmap = ntfs_rs_mmap,
	.write_iter = ntfs_rs_write_iter,
    .fallocate = ntfs_rs_fallocate,
    .copy_file_range = ntfs_rs_copy_file_range,
#ifdef NTFS_RS_FILEMAP_SPLICE_READ
    .splice_read = filemap_splice_read,
#else
    .splice_read = generic_file_splice_read,
#endif
    .splice_write = ntfs_rs_splice_write,
	.fsync = ntfs_rs_fsync,
	.llseek = ntfs_rs_llseek,
};

static int ntfs_rs_show_options(struct seq_file *seq, struct dentry *root)
{
	const struct ntfs_rs_super *state = root->d_sb->s_fs_info;
	seq_printf(seq, ",visibility=%u", ntfs_rs_visibility_flags(d_inode(root)));
	rcu_read_lock();
	seq_printf(seq, ",compatibility=%s,sidmap=%s", ntfs_rs_native(d_inode(root)) ? "ntfs" : "linux",
		   rcu_dereference(state->ident)->sidmap);
	rcu_read_unlock();
	{
		const struct ntfs_rs_access *access;
		rcu_read_lock();
		access = rcu_dereference(state->access);
		if (access && access->desktop)
			seq_printf(seq, ",permissions=desktop,uid=%u,gid=%u,fmask=%04o,dmask=%04o",
				   from_kuid_munged(&init_user_ns, access->uid),
				   from_kgid_munged(&init_user_ns, access->gid),
				   0777 & ~access->file_mode, 0777 & ~access->dir_mode);
		else
			seq_puts(seq, ",permissions=windows");
		rcu_read_unlock();
	}
	if (ntfs_rs_limits(d_inode(root)) & NTFS_RS_VIEW_RO)
		seq_puts(seq, ",view_readonly");
	if (ntfs_rs_limits(d_inode(root)) & NTFS_RS_VIEW_NOEXEC)
		seq_puts(seq, ",view_noexec");
	return 0;
}

struct ntfs_rs_reclaim {
    struct list_head link;
    u64 reference;
};

/* Free a marked orphan one bounded transaction at a time, releasing io_lock
 * between steps. A step returns 0 while more remains, 1 once freed and
 * -errno on failure. Only I/O failure poisons the session; any other failure
 * leaves a valid marked orphan that the next writable mount reclaims. */
static void ntfs_rs_reclaim(struct super_block *sb, u64 reference, bool background)
{
    struct ntfs_rs_super *state = sb->s_fs_info;
    bool continued = false;
    int result = 0;

    while (!result) {
        /* Freeze waits for intwrite holders, so no step runs on a frozen volume. */
        if (background) {
            sb_start_intwrite(sb);
            /* Only a file large enough to need several steps stages enough
             * to be worth settling; a flush per small file would dominate
             * the deletion of a tree. */
            if (continued)
                ntfs_rs_settle_device(sb);
        }
        down_write(&state->io_lock);
        ntfs_rs_make_room(state);
        result = 1;
        if (state->writer_ready && !state->write_failed) {
            result = ntfs_rs_writer_reclaim_step(state->writer, NTFS_RS_IO(sb),
                state->op_scratch, reference);
        }
        if (result == -EIO) {
            ntfs_rs_poison(state, __func__);
        }
        up_write(&state->io_lock);
        if (background) {
            sb_end_intwrite(sb);
        }
        continued = true;
        if (!result && background) {
            msleep(NTFS_RS_RECLAIM_PAUSE_MS);
        } else if (!result) {
            cond_resched();
        }
    }
    if (result < 0) {
        pr_warn_ratelimited("slate-ntfs: %s orphan %llu left for next mount: %d\n",
            sb->s_id, (unsigned long long)(reference & NTFS_RS_RECORD_MASK), result);
    }
}

static void ntfs_rs_reclaim_work(struct work_struct *work)
{
    struct ntfs_rs_super *state = container_of(work, struct ntfs_rs_super, reclaim_work);

    for (;;) {
        struct ntfs_rs_reclaim *entry;

        spin_lock(&state->reclaim_lock);
        entry = list_first_entry_or_null(&state->reclaim_list, struct ntfs_rs_reclaim, link);
        if (entry) {
            list_del(&entry->link);
        }
        spin_unlock(&state->reclaim_lock);
        if (!entry) {
            return;
        }
        ntfs_rs_reclaim(state->sb, entry->reference, true);
        kfree(entry);
    }
}

static void ntfs_rs_evict_inode(struct inode *inode)
{
	struct ntfs_rs_inode *private = inode->i_private;
	/* Never leave a pointer into the canonical inode after dropping its pin. */
	inode->i_mapping = &inode->i_data;
	truncate_inode_pages_final(&inode->i_data);
    if (private && !private->canonical && private->orphaned) {
        struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
        struct ntfs_rs_reclaim *entry = kmalloc(sizeof(*entry), GFP_NOFS);
        /* Free the clusters in the background so unlink and close return at
         * once; without memory for the queue entry, reclaim here instead. */
        if (entry) {
            entry->reference = NTFS_RS_REF(inode);
            spin_lock(&state->reclaim_lock);
            list_add_tail(&entry->link, &state->reclaim_list);
            spin_unlock(&state->reclaim_lock);
            queue_work(system_unbound_wq, &state->reclaim_work);
        } else {
            ntfs_rs_reclaim(inode->i_sb, NTFS_RS_REF(inode), false);
        }
    }
	clear_inode(inode);
	WRITE_ONCE(inode->i_private, NULL);
	/* Permission checks may still be using the immutable bytes in RCU-walk. */
	if (private) {
		struct ntfs_rs_security *security = rcu_dereference_protected(private->security, 1);
		if (security)
			kvfree_rcu(security, rcu);
		if (private->link)
			kfree_rcu(private->link, rcu);
		iput(private->canonical);
        ntfs_rs_put_visibility(inode->i_sb, private->limits >> 2);
		kfree_rcu(private, rcu);
	}
}

static int ntfs_rs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
    struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
    u64 times[4];
    int error;
    if (ntfs_rs_canonical(inode) != inode || !state->writer_ready ||
        !inode->i_nlink || sb_rdonly(inode->i_sb)) return 0;
    times[0] = ntfs_rs_shared(inode)->created;
    times[1] = ntfs_rs_from_ts(ntfs_rs_get_mtime(inode));
    times[2] = ntfs_rs_from_ts(ntfs_rs_get_ctime(inode));
    times[3] = ntfs_rs_from_ts(ntfs_rs_get_atime(inode));
    down_write(&state->io_lock);
    ntfs_rs_make_room(state);
    if (!memcmp(ntfs_rs_shared(inode)->persisted_times, &times[1], 3 * sizeof(u64))) {
        up_write(&state->io_lock);
        return 0;
    }
    /* Reading a file must not wake a parked session: background writeback of
     * an access time alone waits for the next change, sync or unmount. */
    if (wbc->sync_mode != WB_SYNC_ALL &&
        !memcmp(ntfs_rs_shared(inode)->persisted_times, &times[1], 2 * sizeof(u64))) {
        int parked = 0;

        ntfs_rs_writer_activity(state->writer, &parked);
        if (parked) {
            up_write(&state->io_lock);
            return 0;
        }
    }
    error = state->write_failed ? -EIO : ntfs_rs_writer_set_times(state->writer,
        NTFS_RS_IO(inode->i_sb), state->op_scratch, NTFS_RS_REF(inode), times, 14, 0, 0);
    if (!error) memcpy(ntfs_rs_shared(inode)->persisted_times, &times[1], 3 * sizeof(u64));
    /* The timestamps join the pending journal batch. Whoever needs them
     * durable follows with its own barrier: sync(2) with sync_fs, fsync and
     * commit_metadata with theirs. A barrier here would cost sync(2) one
     * flush for every dirty inode. */
    if (error == -EIO) ntfs_rs_poison(state, __func__);
    up_write(&state->io_lock);
    return error;
}

static int ntfs_rs_sync_fs(struct super_block *sb, int wait)
{
    struct ntfs_rs_super *state = sb->s_fs_info;
    int result = 0;
    if (!state->writer_ready)
        return state->write_failed ? -EIO : 0;
    if (wait) {
        ntfs_rs_settle_device(sb);
        down_write(&state->io_lock);
        result = ntfs_rs_drain_locked(sb, true);
        if (result)
            ntfs_rs_poison(state, __func__);
        up_write(&state->io_lock);
    }
    return result;
}

static int ntfs_rs_freeze_fs(struct super_block *sb)
{
    /* VFS has already quiesced userspace writers and page faults before this
     * callback. Checkpoint the journal so the frozen image is self-consistent. */
    return ntfs_rs_sync_fs(sb, 1);
}

static int ntfs_rs_unfreeze_fs(struct super_block *sb)
{
    /* No extra transaction gate remains held by ->freeze_fs().  In
     * particular, administrative shutdown poisons later writes only after
     * bdev_freeze(), and thaw must still be allowed to complete. */
    (void)sb;
    return 0;
}

static void ntfs_rs_cancel_drain_work(struct ntfs_rs_super *state)
{
    if (state && READ_ONCE(state->drain_scheduled)) {
        WRITE_ONCE(state->drain_scheduled, false);
        cancel_delayed_work_sync(&state->drain_work);
    }
}

/* Finish the Rust writer after VFS has made ordinary writes quiescent.  This
 * publishes the clean NTFS volume flag only after the empty checkpoint is
 * durable. A later writable remount constructs a freshly validated session. */
static int ntfs_rs_finish_writer(struct super_block *sb)
{
    struct ntfs_rs_super *state = sb->s_fs_info;
    int result;
    if (!state || !state->writer_ready)
        return state && state->write_failed ? -EIO : 0;
    if (state->write_failed)
        return -EIO;
    if (!state->op_scratch)
        return -ENOMEM;
    /* Queued orphans are freed before the clean volume flag is published. */
    flush_work(&state->reclaim_work);
    ntfs_rs_cancel_drain_work(state);
    down_write(&state->io_lock);
    if (!state->writer_ready) {
        result = state->write_failed ? -EIO : 0;
        goto out;
    }
    ntfs_rs_make_room(state);
    state->flushes = 0;
    result = ntfs_rs_writer_finish(state->writer, sb, ntfs_rs_read_unlocked,
        ntfs_rs_write_at, ntfs_rs_flush, state->op_scratch);
    if (!result)
        state->writer_ready = false;
    else {
        ntfs_rs_poison(state, __func__);
        pr_err("slate-ntfs: clean writer shutdown failed: %d\n", result);
    }
out:
    up_write(&state->io_lock);
    return result;
}

static void ntfs_rs_put_super(struct super_block *sb)
{
    struct ntfs_rs_super *state = sb->s_fs_info;
    int result;
    if (!state)
        return;
    /* Every inode was evicted before put_super; finish their queued reclaim. */
    flush_work(&state->reclaim_work);
    ntfs_rs_cancel_drain_work(state);
    cancel_work_sync(&state->writeback_work);
    if (!state->writer_ready || state->write_failed)
        return;
    result = ntfs_rs_finish_writer(sb);
    if (result)
        pr_err("slate-ntfs: clean-unmount publication failed: %d\n", result);
}

/* The writer whose allocations are applied to the count: none on a
 * read-only mount or a failed session. Caller holds io_lock. */
static const void *ntfs_rs_space_writer(const struct ntfs_rs_super *state)
{
	return state->writer_ready && !state->write_failed ? state->writer : NULL;
}

/* Count free clusters into state->space with the writer's allocation delta at
 * that moment. Caller holds space_lock and io_lock for reading, under which no
 * device write or transaction runs, so count, epoch and delta agree. */
static int ntfs_rs_count_space(struct ntfs_rs_super *state)
{
	unsigned char *scratch = kvzalloc(4 * NTFS_RS_BUFFER_BYTES, GFP_NOFS);
	const void *writer = ntfs_rs_space_writer(state);
	int result;

	if (!scratch)
		return -ENOMEM;
	result = ntfs_rs_space(state->boot, state->sb, ntfs_rs_read_unlocked, scratch, state->space);
	kvfree(scratch);
	if (!result) {
		state->space_epoch = atomic64_read(&state->table_epoch);
		state->space_counted = jiffies;
		state->space_writer = writer;
		state->space_delta = writer ? ntfs_rs_writer_allocated_delta(writer) : 0;
		state->space_valid = true;
	}
	return result;
}

/* Counting reads all of $Bitmap, about 30 MB on a 1 TB volume, and Wine asks
 * for free space constantly. Count once per write session, then apply the
 * clusters the writer has allocated since; recount after a writer change, or
 * when a changed volume's count is NTFS_RS_SPACE_RECOUNT_MS old. */
static int ntfs_rs_statfs(struct dentry *dentry, struct kstatfs *out)
{
	struct super_block *sb = dentry->d_sb;
	struct ntfs_rs_super *state = sb->s_fs_info;
	const void *writer;
	unsigned long due;
	u64 values[NTFS_RS_SPACE_VALUES];
	s64 allocated = 0;
	int result = 0;

	mutex_lock(&state->space_lock);
	down_read(&state->io_lock);
	writer = ntfs_rs_space_writer(state);
	due = state->space_counted + msecs_to_jiffies(NTFS_RS_SPACE_RECOUNT_MS);
	if (!state->space_valid || state->space_writer != writer ||
	    (atomic64_read(&state->table_epoch) != state->space_epoch && time_after_eq(jiffies, due)))
		result = ntfs_rs_count_space(state);
	if (!result && writer)
		allocated = ntfs_rs_writer_allocated_delta(writer) - state->space_delta;
	up_read(&state->io_lock);
	memcpy(values, state->space, sizeof(values));
	mutex_unlock(&state->space_lock);
	if (result)
		return result;
	/* values: total clusters, free clusters at the count, cluster bytes. */
	if (allocated > 0)
		values[1] -= min_t(u64, values[1], allocated);
	else
		values[1] = min_t(u64, values[0], values[1] - allocated);
	out->f_type = sb->s_magic;
	out->f_bsize = values[2];
	out->f_frsize = values[2];
	out->f_blocks = values[0];
	out->f_bfree = out->f_bavail = values[1];
	out->f_namelen = 255;
	out->f_fsid = u64_to_fsid(huge_encode_dev(sb->s_bdev->bd_dev));
	return 0;
}

/* Export handles retain the 48-bit record, 16-bit sequence, and view policy.
 * A stale sequence never resolves to a reused record. */
static int ntfs_rs_encode_fh(struct inode *inode, u32 *fh, int *length, struct inode *parent)
{
    u64 reference = NTFS_RS_REF(inode);
    int needed = parent ? 6 : 3;
    if (*length < needed) { *length = needed; return FILEID_INVALID; }
    fh[0] = reference; fh[1] = reference >> 32;
    fh[2] = ntfs_rs_native(inode) | (ntfs_rs_limits(inode) << 1);
    if (parent) {
        reference = NTFS_RS_REF(parent);
        fh[3] = reference; fh[4] = reference >> 32;
        fh[5] = ntfs_rs_native(parent) | (ntfs_rs_limits(parent) << 1);
    }
    *length = needed;
    return parent ? 0x92 : 0x91;
}

static struct dentry *ntfs_rs_handle_inode(struct super_block *sb, u64 reference, unsigned int policy)
{
    struct ntfs_rs_super *state = sb->s_fs_info;
    struct ntfs_rs_node info;
    unsigned char *scratch;
    int error;
    if (!xa_load(&state->visibility, policy >> 3) || !(reference >> 48)) return ERR_PTR(-ESTALE);
    scratch = kvzalloc(ntfs_rs_ea_scratch_size(), GFP_NOFS);
    if (!scratch) return ERR_PTR(-ENOMEM);
    error = ntfs_rs_stat(state->boot, 512, sb, ntfs_rs_read_at, scratch,
        ntfs_rs_ea_scratch_size(), reference & NTFS_RS_RECORD_MASK, reference >> 48, &info);
    kvfree(scratch);
    if (error || !info.links) return ERR_PTR(error == -ENOMEM ? error : -ESTALE);
    return d_obtain_alias(ntfs_rs_get_inode(sb, &info, policy & 1, policy >> 1, NULL));
}

static struct dentry *ntfs_rs_fh_to_dentry(struct super_block *sb, struct fid *fid, int length, int type)
{
    if ((type != 0x91 && type != 0x92) || length < (type == 0x92 ? 6 : 3)) return ERR_PTR(-ESTALE);
    return ntfs_rs_handle_inode(sb, (u64)fid->raw[0] | ((u64)fid->raw[1] << 32), fid->raw[2]);
}

static struct dentry *ntfs_rs_fh_to_parent(struct super_block *sb, struct fid *fid, int length, int type)
{
    if (type != 0x92 || length < 6) return ERR_PTR(-ESTALE);
    return ntfs_rs_handle_inode(sb, (u64)fid->raw[3] | ((u64)fid->raw[4] << 32), fid->raw[5]);
}

extern int ntfs_rs_parent(const unsigned char *, void *, ntfs_rs_read_t, unsigned char *, u64, u64 *);
static struct dentry *ntfs_rs_get_parent(struct dentry *child)
{
    struct inode *inode = d_inode(child);
    struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
    unsigned char *scratch = kvzalloc(ntfs_rs_ea_scratch_size(), GFP_NOFS);
    u64 reference;
    int error;
    if (!scratch) return ERR_PTR(-ENOMEM);
    down_read(&state->io_lock);
    error = ntfs_rs_parent(state->boot, inode->i_sb, ntfs_rs_read_unlocked,
        scratch, NTFS_RS_REF(inode), &reference);
    up_read(&state->io_lock);
    kvfree(scratch);
    if (error) return ERR_PTR(error);
    return ntfs_rs_handle_inode(inode->i_sb, reference, ntfs_rs_native(inode) | (ntfs_rs_limits(inode) << 1));
}

static int ntfs_rs_commit_metadata(struct inode *inode)
{
    struct writeback_control wbc = { .sync_mode = WB_SYNC_ALL };
    int error = ntfs_rs_write_inode(ntfs_rs_canonical(inode), &wbc);
    return error ?: ntfs_rs_sync_fs(inode->i_sb, 1);
}

/* Exportfs reconstruction must not open a directory (which would recurse
 * into fanotify permissions). Find its child's exact record reference using
 * the existing Rust index walker instead. */
struct ntfs_rs_name_query { u64 reference; char *name; bool found; };
static int ntfs_rs_find_export_name(void *context, const unsigned char *name,
                                   size_t length, u64 reference, u64 ordinal, u32 kind)
{
    (void)kind;
    struct ntfs_rs_name_query *query = context;
    (void)ordinal;
    if (reference != query->reference) return 0;
    if (!length || length > NAME_MAX) return -ENAMETOOLONG;
    memcpy(query->name, name, length);
    query->name[length] = 0;
    query->found = true;
    return 1;
}

static int ntfs_rs_get_name(struct dentry *parent, char *name, struct dentry *child)
{
    struct inode *inode = d_inode(parent);
    struct ntfs_rs_super *state = inode->i_sb->s_fs_info;
    struct ntfs_rs_name_query query = { NTFS_RS_REF(d_inode(child)), name, false };
    unsigned char *scratch = kvmalloc(NTFS_RS_SCRATCH_BYTES, GFP_NOFS);
    int error;
    if (!scratch) return -ENOMEM;
    error = ntfs_rs_readdir(state->boot, 512, inode->i_sb, ntfs_rs_read_at,
        scratch, NTFS_RS_SCRATCH_BYTES, NTFS_RS_REF(inode), 0, NULL, 0,
        7, state->upcase, &query, ntfs_rs_find_export_name);
    kvfree(scratch);
    return error < 0 ? error : query.found ? 0 : -ENOENT;
}

#ifdef NTFS_RS_FSNOTIFY_PATH
static int ntfs_rs_notify_beneath(void *context, struct dentry *dentry)
{
    return is_subdir(dentry, context);
}

/* The companion kernel pins target mounts and does the fanotify delivery.
 * Reconstruct directories using exportfs, then the exact source name. No
 * pathname is exposed outside the receiving mount's root. */
static struct dentry *ntfs_rs_notify_path(const struct path *source, struct vfsmount *target)
{
    struct inode *origin = d_inode(source->dentry), *root = d_inode(target->mnt_root);
    struct inode *peer;
    struct dentry *parent, *mapped_parent, *mapped;
    struct name_snapshot name;
    u64 reference;
    u32 policy = ntfs_rs_native(root) | (ntfs_rs_limits(root) << 1);
    u32 fh[3];
    if (policy == (ntfs_rs_native(origin) | (ntfs_rs_limits(origin) << 1))) return NULL;
    if (NTFS_RS_REF(origin) == NTFS_RS_REF(root)) return dget(target->mnt_root);
    /* Private canonical backing-file aliases have no namespace path. */
    if (IS_ROOT(source->dentry) && !S_ISDIR(origin->i_mode)) return NULL;
    parent = dget_parent(source->dentry);
    reference = NTFS_RS_REF(d_inode(parent));
    fh[0] = reference; fh[1] = reference >> 32; fh[2] = policy;
    if (reference == NTFS_RS_REF(root)) mapped_parent = dget(target->mnt_root);
    else mapped_parent = exportfs_decode_fh_raw(target, (struct fid *)fh, 3, 0x91,
        EXPORT_FH_NOTIFY | EXPORT_FH_DIR_ONLY, ntfs_rs_notify_beneath, target->mnt_root);
    dput(parent);
    if (IS_ERR(mapped_parent)) {
        /* A subtree mount does not see ancestors or siblings. */
        if (PTR_ERR(mapped_parent) == -EACCES) return NULL;
        /* A stale/missing ancestor is not proof of invisibility. Propagate
         * it so permission delivery fails closed instead of skipping a mark. */
        return mapped_parent;
    }
    if (!mapped_parent) return NULL;
    take_dentry_name_snapshot(&name, source->dentry);
    name.name.hash = full_name_hash(mapped_parent, name.name.name, name.name.len);
    inode_lock(d_inode(mapped_parent));
    mapped = lookup_one_qstr_excl(&name.name, mapped_parent, LOOKUP_CREATE);
    inode_unlock(d_inode(mapped_parent));
    if (IS_ERR(mapped)) goto out;
    if (d_is_positive(mapped) && NTFS_RS_REF(d_inode(mapped)) == NTFS_RS_REF(origin)) goto out;
    dput(mapped);
    /* An open unlinked/replaced file still has a live canonical inode. An
     * unhashed alias preserves its old name for the event without publishing
     * a name in the namespace or accidentally reporting its replacement. */
    peer = ntfs_rs_project_inode(origin, policy);
    if (IS_ERR(peer)) { mapped = ERR_CAST(peer); goto out; }
    if (S_ISDIR(peer->i_mode)) {
        mapped = d_find_alias(peer);
        if (mapped) {
            struct dentry *alias_parent = dget_parent(mapped);
            struct name_snapshot alias_name;
            bool same;
            take_dentry_name_snapshot(&alias_name, mapped);
            same = alias_parent == mapped_parent && alias_name.name.len == name.name.len &&
                !memcmp(alias_name.name.name, name.name.name, name.name.len);
            release_dentry_name_snapshot(&alias_name);
            dput(alias_parent);
            if (!same) { dput(mapped); mapped = NULL; }
            iput(peer);
            goto out;
        }
    }
    mapped = d_alloc(mapped_parent, &name.name);
    if (!mapped) { iput(peer); mapped = ERR_PTR(-ENOMEM); goto out; }
    d_instantiate(mapped, peer);
out:
    release_dentry_name_snapshot(&name);
    dput(mapped_parent);
    return mapped;
}
#endif

static const struct export_operations ntfs_rs_export_ops = {
    .get_name = ntfs_rs_get_name,
    .encode_fh = ntfs_rs_encode_fh,
    .fh_to_dentry = ntfs_rs_fh_to_dentry,
    .fh_to_parent = ntfs_rs_fh_to_parent,
    .get_parent = ntfs_rs_get_parent,
    .commit_metadata = ntfs_rs_commit_metadata,
};

static const struct super_operations ntfs_rs_super_ops = {
#ifdef NTFS_RS_FSNOTIFY_PATH
    .fsnotify_path = ntfs_rs_notify_path,
#endif
	.put_super = ntfs_rs_put_super,
    .write_inode = ntfs_rs_write_inode,
	.sync_fs = ntfs_rs_sync_fs,
    .freeze_fs = ntfs_rs_freeze_fs,
    .unfreeze_fs = ntfs_rs_unfreeze_fs,
	.evict_inode = ntfs_rs_evict_inode,
	.statfs = ntfs_rs_statfs,
	.show_options = ntfs_rs_show_options,
};

/* Called under mount/reconfigure exclusion; publish readiness last. */
void ntfs_rs_mount_refusal(void *context, const char *reason, size_t length);
void ntfs_rs_mount_refusal(void *context, const char *reason, size_t length)
{
    struct super_block *sb = context;
    pr_err_ratelimited("slate-ntfs: %s writable mount refused: %.*s\n", sb->s_id, (int)length, reason);
}

static int ntfs_rs_start_writer(struct super_block *sb)
{
    struct ntfs_rs_super *state = sb->s_fs_info;
    u64 reclaimed;
    int result;
    if (state->write_failed) return -EIO;
    if (state->writer_ready) return 0;
    if (state->held_count) return -EIO;
    if (bdev_read_only(sb->s_bdev)) return -EROFS;
    if (READ_ONCE(fail_after_flush) && MAJOR(sb->s_bdev->bd_dev) != LOOP_MAJOR)
        return -EINVAL;
    down_write(&state->io_lock);
    if (!state->op_scratch) state->op_scratch = kvzalloc(NTFS_RS_SESSION_SCRATCH, GFP_KERNEL);
    if (!state->batch_arena) state->batch_arena = kvzalloc(NTFS_RS_BATCH_BYTES, GFP_KERNEL);
    if (!state->journal_map) state->journal_map = kvmalloc(ntfs_rs_journal_map_bytes(), GFP_KERNEL);
    if (!state->held) state->held = kvzalloc(sizeof(*state->held) * NTFS_RS_HELD_MAX, GFP_KERNEL);
    if (!state->writer) state->writer = kzalloc(ntfs_rs_writer_size(), GFP_KERNEL);
    if (!state->op_scratch || !state->batch_arena || !state->journal_map || !state->held || !state->writer ||
        ntfs_rs_writer_security_scratch_size() > NTFS_RS_SESSION_SCRATCH) {
        result = -ENOMEM;
        goto out;
    }
    ntfs_rs_make_room(state);
    state->flushes = 0;
    /* prepare() revalidates the volume, journal and allocation invariants;
     * initialize() durably marks it dirty before any writable session exists. */
    result = ntfs_rs_writer_init(state->writer, state->boot, sb,
        ntfs_rs_read_unlocked, ntfs_rs_write_at, ntfs_rs_flush,
        state->op_scratch, state->batch_arena, state->journal_map, 1);
    if (result) { if (result == -EIO) ntfs_rs_poison(state, __func__); goto out; }
    result = ntfs_rs_writer_reclaim_orphans(state->writer, NTFS_RS_IO(sb),
        state->op_scratch, &reclaimed);
    if (result) { ntfs_rs_poison(state, __func__); goto out; }
    state->writer_ready = true;
    state->sb = sb;
    INIT_DELAYED_WORK(&state->drain_work, ntfs_rs_drain_work);
    WRITE_ONCE(state->drain_scheduled, true);
    /* A drain journals and flushes for many milliseconds of CPU time; keep
     * it off per-CPU workers, where it would delay unrelated work items. */
    queue_delayed_work(system_unbound_wq, &state->drain_work,
        msecs_to_jiffies(NTFS_RS_DEFERRED_DRAIN_MS));
out:
    up_write(&state->io_lock);
    return result;
}

static int ntfs_rs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct ntfs_rs_super *state;
	u64 device_bytes;
	struct ntfs_rs_node root_info;
	struct inode *root_inode;
	unsigned char *scratch;
	int result;

	/* The destructive failure-injection knob is restricted to test loops.
	 * Ordinary writes use the same Rust safety gate on any block device. */
	if (!(fc->sb_flags & SB_RDONLY) && READ_ONCE(fail_after_flush) &&
	    MAJOR(sb->s_bdev->bd_dev) != LOOP_MAJOR)
		return -EINVAL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
	device_bytes = bdev_nr_bytes(sb->s_bdev);
#else
	device_bytes = i_size_read(sb->s_bdev->bd_inode);
#endif
	/* The writer's journal and metadata use 4 KiB cache units. */
	if (device_bytes < 4096 || !sb_set_blocksize(sb, 4096))
		return -EINVAL;
	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;
	sb->s_fs_info = state;
    state->mount_cred = get_cred(fc->cred);
	init_rwsem(&state->io_lock);
	state->sb = sb;
	INIT_WORK(&state->writeback_work, ntfs_rs_writeback_work);
	INIT_WORK(&state->reclaim_work, ntfs_rs_reclaim_work);
	spin_lock_init(&state->reclaim_lock);
	spin_lock_init(&state->scratch_lock);
	spin_lock_init(&state->table_lock);
	mutex_init(&state->space_lock);
	xa_init(&state->descriptors);
	state->table = kvmalloc(NTFS_RS_TABLE_BYTES, GFP_KERNEL);
	INIT_LIST_HEAD(&state->reclaim_list);
    xa_init_flags(&state->visibility, XA_FLAGS_ALLOC);
    {
        struct ntfs_rs_visibility *policy = kzalloc(sizeof(*policy), GFP_KERNEL);
        void *old;
        if (!policy) return -ENOMEM;
        policy->flags = ((struct ntfs_rs_options *)fc->fs_private)->visibility;
        policy->owner = GLOBAL_ROOT_UID;
        refcount_set(&policy->references, 1);
        old = xa_store(&state->visibility, 0, policy, GFP_KERNEL);
        if (xa_is_err(old)) { kfree(policy); return xa_err(old); }
    }
	result = ntfs_rs_plain_read(sb, 0, state->boot, sizeof(state->boot));
	if (result) {
		pr_err_ratelimited("slate-ntfs: %s boot-sector read failed: %d\n", sb->s_id, result);
		return result;
	}
	result = ntfs_rs_read_scratch_size(state->boot, sizeof(state->boot));
	if (result <= 0)
		return result ? result : -EINVAL;
	state->read_scratch_bytes = result;
	scratch = kvmalloc(NTFS_RS_LOOKUP_BYTES, GFP_KERNEL);
	state->upcase = kvmalloc(NTFS_RS_UPCASE_BYTES, GFP_KERNEL);
	if (!scratch || !state->upcase ||
	    ntfs_rs_read_upcase(state->boot, sizeof(state->boot), sb, ntfs_rs_read_at,
			scratch, NTFS_RS_LOOKUP_BYTES, state->upcase)) {
		kvfree(state->upcase);
		state->upcase = NULL;
	}
	kvfree(scratch);
#ifdef NTFS_RS_UUID_LEN
    /* FS_IOC_GETFSUUID is handled by the VFS from these superblock bytes. */
    {
        unsigned char label[FSLABEL_MAX], uuid[8];
        scratch = kvzalloc(ntfs_rs_ea_scratch_size(), GFP_KERNEL);
        if (!scratch) return -ENOMEM;
        result = ntfs_rs_volume_identity(state->boot, sb, ntfs_rs_read_at, scratch, label, uuid);
        kvfree(scratch);
        if (result) {
            pr_err_ratelimited("slate-ntfs: %s volume identity failed: %d\n", sb->s_id, result);
            return result;
        }
        super_set_uuid(sb, uuid, sizeof(uuid));
    }
#endif
	scratch = kvzalloc(ntfs_rs_ea_scratch_size(), GFP_KERNEL);
	if (!scratch) {
		return -ENOMEM;
	}
	result = ntfs_rs_probe(state->boot, 512, sb, ntfs_rs_read_at,
			       scratch, NTFS_RS_SCRATCH_BYTES);
	if (!result)
		result = ntfs_rs_stat(state->boot, 512, sb, ntfs_rs_read_at,
				      scratch, ntfs_rs_ea_scratch_size(),
				      5, 0, &root_info);
	if (scratch != state->op_scratch) kvfree(scratch);
	if (result) {
		pr_err_ratelimited("slate-ntfs: %s root probe failed: %d\n", sb->s_id, result);
		return result;
	}
	if (!(root_info.flags & 2)) {
		pr_err_ratelimited("slate-ntfs: %s root record is not a directory\n", sb->s_id);
		return -EINVAL;
	}
	{
		struct ntfs_rs_identity *ident =
			ntfs_rs_identity_new(((struct ntfs_rs_options *)fc->fs_private)->sidmap);
		if (IS_ERR(ident))
			return PTR_ERR(ident);
		RCU_INIT_POINTER(state->ident, ident);
	}
	{
		struct ntfs_rs_access *access = ntfs_rs_access_from(fc->fs_private, NULL);
		if (IS_ERR(access))
			return PTR_ERR(access);
		RCU_INIT_POINTER(state->access, access);
	}
	sb->s_magic = 0x5346544e;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_time_gran = 100;
	sb->s_op = &ntfs_rs_super_ops;
    sb->s_export_op = &ntfs_rs_export_ops;
#ifdef NTFS_RS_DEFAULT_D_OP
	set_default_d_op(sb, &ntfs_rs_dentry_ops);
#else
	sb->s_d_op = &ntfs_rs_dentry_ops;
#endif
	/* Must precede inode creation: inode_init_always() sets IOP_XATTR. */
	sb->s_xattr = ntfs_rs_xattr_handlers;
    /* VFS may cache absence of capabilities; security EA edits and set-ID
     * publication invalidate that cache on every inode projection. */
    sb->s_flags |= SB_NOSEC;
#if IS_ENABLED(CONFIG_FS_POSIX_ACL)
    sb->s_flags |= SB_POSIXACL;
#endif
	root_inode = ntfs_rs_get_inode(sb, &root_info, false, 0, NULL);
	if (IS_ERR(root_inode))
		return PTR_ERR(root_inode);
	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root)
		return -ENOMEM;
    if (!(fc->sb_flags & SB_RDONLY)) {
        result = ntfs_rs_start_writer(sb);
        if (result) pr_err_ratelimited("slate-ntfs: %s writable mount refused: %d; try an explicit read-only mount for diagnosis\n", sb->s_id, result);
        return result;
    }
    return 0;
}

static struct file_system_type ntfs_rs_type;

/* An unprivileged context can only derive an accessible directory from an
 * already mounted instance. No block device is opened and no SID map changes.
 * Restriction bits are inode-view properties, so a malicious fsmount/remount
 * caller cannot clear them by dropping mount flags. */
static int ntfs_rs_get_view(struct fs_context *fc)
{
	struct ntfs_rs_options *options = fc->fs_private;
	struct path path;
	struct inode *source, *canonical, *inode;
	struct super_block *sb;
	struct ntfs_rs_node info;
	unsigned int limits;
    u32 policy_id = 0;
	int result = kern_path(options->view, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &path);
	if (result)
		return result;
	sb = path.dentry->d_sb;
	source = d_inode(path.dentry);
	if (sb->s_type != &ntfs_rs_type || options->sidmap || fc->source) {
		result = -EINVAL;
		goto out;
	}
	WRITE_ONCE(((struct ntfs_rs_super *)sb->s_fs_info)->several_views, true);
	/* Do not reveal files hidden beneath child mounts to a user namespace. */
	if (!capable(CAP_SYS_ADMIN) && path_has_submounts(&path)) {
		result = -EBUSY;
		goto out;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	result = inode_permission(mnt_idmap(path.mnt), source, MAY_READ | MAY_EXEC);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
	result = inode_permission(source, MAY_READ | MAY_EXEC);
#else
	result = inode_permission(mnt_user_ns(path.mnt), source, MAY_READ | MAY_EXEC);
#endif
	if (result)
		goto out;
    limits = ntfs_rs_limits(source) & 3;
    {
        struct ntfs_rs_visibility *policy = kzalloc(sizeof(*policy), GFP_KERNEL);
        u32 id;
        if (!policy) { result = -ENOMEM; goto out; }
        policy->flags = options->visibility_set ? options->visibility : ntfs_rs_visibility_flags(source);
        policy->owner = current_fsuid();
        refcount_set(&policy->references, 1);
        result = xa_alloc(&((struct ntfs_rs_super *)sb->s_fs_info)->visibility,
            &id, policy, XA_LIMIT(1, (U32_MAX >> 3) - 1), GFP_KERNEL);
        if (result) { kfree(policy); goto out; }
        policy_id = id;
        limits |= id << 2;
    }
	if (sb_rdonly(sb) || (path.mnt->mnt_flags & MNT_READONLY))
		limits |= NTFS_RS_VIEW_RO;
	if (path.mnt->mnt_flags & MNT_NOEXEC)
		limits |= NTFS_RS_VIEW_NOEXEC;
	if (!capable(CAP_SYS_ADMIN)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		result = inode_permission(mnt_idmap(path.mnt), source, MAY_WRITE);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
		result = inode_permission(source, MAY_WRITE);
#else
		result = inode_permission(mnt_user_ns(path.mnt), source, MAY_WRITE);
#endif
		if (result || ntfs_rs_authorize(source, 2, false))
			limits |= NTFS_RS_VIEW_RO;
	}
	canonical = ntfs_rs_canonical(source);
	info = (struct ntfs_rs_node) {
		.file_reference = canonical->i_ino | ((u64)canonical->i_generation << 48),
		.data_size = i_size_read(canonical), .flags = 2, .links = 2,
		.mode = ntfs_rs_shared(source)->unix_mode ? canonical->i_mode : U32_MAX,
	};
	/* The path pins a live mount while its superblock reference is acquired. */
	atomic_inc(&sb->s_active);
	down_write(&sb->s_umount);
	inode = ntfs_rs_get_inode(sb, &info, options->native_mode, limits, NULL);
	if (IS_ERR(inode)) {
		result = PTR_ERR(inode);
		deactivate_locked_super(sb);
		goto out;
	}
	fc->root = d_obtain_root(inode);
	if (IS_ERR(fc->root)) {
		result = PTR_ERR(fc->root);
		fc->root = NULL;
		deactivate_locked_super(sb);
		goto out;
	}
	result = 0; /* VFS consumes the locked active reference. */
out:
    if (policy_id) ntfs_rs_put_visibility(sb, policy_id);
	path_put(&path);
	return result;
}

static int ntfs_rs_get_tree(struct fs_context *fc)
{
	struct ntfs_rs_options *options = fc->fs_private;
	struct super_block *sb;
	int result;
	if (options->view)
		return ntfs_rs_get_view(fc);
	/* FS_USERNS_MOUNT enables only get_view, never raw device mounting. */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!options->sidmap) {
		pr_err_ratelimited("slate-ntfs: mount requires sidmap; use mount.ntfsrs or ntfs-mount\n");
		return -EINVAL;
	}
	result = get_tree_bdev(fc, ntfs_rs_fill_super);
	if (result) {
		pr_err_ratelimited("slate-ntfs: mounting %s failed with errno %d; see preceding diagnostics\n",
			fc->source ? fc->source : "device", result);
		return result;
	}
	sb = fc->root->d_sb;
	rcu_read_lock();
	result = strcmp(options->sidmap,
		rcu_dereference(((struct ntfs_rs_super *)sb->s_fs_info)->ident)->sidmap) ? -EBUSY : 0;
	rcu_read_unlock();
	if (result)
		goto fail;
	if (options->native_mode) {
		struct inode *root = d_inode(sb->s_root), *inode;
		struct dentry *view;
		struct ntfs_rs_node info = {
			.file_reference = root->i_ino | ((u64)root->i_generation << 48),
			.data_size = i_size_read(root), .flags = 2, .links = 2, .mode = U32_MAX,
		};
		inode = ntfs_rs_get_inode(sb, &info, true, 0, NULL);
		if (IS_ERR(inode)) { result = PTR_ERR(inode); goto fail; }
		/* Register this tree in s_roots so final shutdown prunes it too. */
		view = d_obtain_root(inode);
		if (IS_ERR(view)) { result = PTR_ERR(view); goto fail; }
		dput(fc->root);
		fc->root = view;
	}
	{
		struct ntfs_rs_super *state = sb->s_fs_info;
		int view = options->native_mode ? 2 : 1;
		int first = cmpxchg(&state->first_view, 0, view);
		if (first && first != view)
			WRITE_ONCE(state->several_views, true);
	}
	return 0;
fail:
	dput(fc->root);
	fc->root = NULL;
	deactivate_locked_super(sb);
	return result;
}

/* After a live permission change, tell file managers and other watchers:
 * an "attributes changed" event (inotify IN_ATTRIB) for every cached file and
 * folder, also delivered to watchers of their parent folders. An open folder
 * view then re-checks what the user may do (paste, new folder, rename, ...)
 * instead of keeping the old answer. Same inode walk as drop_pagecache_sb(). */
static void ntfs_rs_announce_permissions(struct super_block *sb)
{
	struct inode *inode, *previous = NULL;
	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		unsigned long state;
		struct dentry *dentry;
		spin_lock(&inode->i_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 0)
		state = inode_state_read(inode);
#else
		state = inode->i_state;
#endif
		spin_unlock(&inode->i_lock);
		/* igrab() (exported, unlike __iget) refuses inodes being freed. */
		if ((state & I_NEW) || !igrab(inode))
			continue;
		spin_unlock(&sb->s_inode_list_lock);
		dentry = d_find_alias(inode);
		if (dentry) {
			fsnotify_change(dentry, ATTR_MODE | ATTR_UID | ATTR_GID);
			dput(dentry);
		}
		iput(previous);	/* never under s_inode_list_lock */
		previous = inode;
		cond_resched();
		spin_lock(&sb->s_inode_list_lock);
	}
	spin_unlock(&sb->s_inode_list_lock);
	iput(previous);
}

static int ntfs_rs_reconfigure(struct fs_context *fc)
{
    struct ntfs_rs_options *options = fc->fs_private;
    struct super_block *sb = fc->root->d_sb;
    struct ntfs_rs_super *state = sb->s_fs_info;
    struct ntfs_rs_visibility *policy = ntfs_rs_visibility_policy(d_inode(fc->root));
    bool want_ro = fc->sb_flags & SB_RDONLY;
    bool was_ro = sb_rdonly(sb);
    struct ntfs_rs_identity *new_ident = NULL;
    struct ntfs_rs_access *new_access = NULL;
    bool announce = false;
    int result = 0;
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;
    if (!policy) return -ESTALE;
    if (options->compatibility_set && options->native_mode !=
        ntfs_rs_native(d_inode(fc->root))) return -EBUSY;
    /* A new SID map (people added, removed or given another level) applies
     * live; build it first so an invalid map changes nothing. */
    {
        const struct ntfs_rs_identity *current_ident = rcu_dereference_protected(state->ident, 1);
        if (options->sidmap && strcmp(options->sidmap, current_ident->sidmap)) {
            new_ident = ntfs_rs_identity_new(options->sidmap);
            if (IS_ERR(new_ident)) return PTR_ERR(new_ident);
        }
    }
    /* Mount-wide permissions can change while mounted; stored ACLs never do. */
    if (ntfs_rs_access_options_set(options)) {
        new_access = ntfs_rs_access_from(options, rcu_dereference_protected(state->access, 1));
        if (IS_ERR(new_access)) {
            if (new_ident) kvfree(new_ident);
            return PTR_ERR(new_access);
        }
    }
    /* Publish visibility only after a successful writer transition. */
    if (was_ro && !want_ro) result = ntfs_rs_start_writer(sb);
    else if (!was_ro && !want_ro)
        result = state->writer_ready && !state->write_failed ? 0 : -EROFS;
    else if (!was_ro) {
        if (state->write_failed) ntfs_rs_cancel_drain_work(state);
        else {
            result = sync_filesystem(sb);
            if (!result) result = ntfs_rs_finish_writer(sb);
        }
    }
    if (!result && new_ident) {
        /* Writers use the map under io_lock; permission checks under RCU. */
        struct ntfs_rs_identity *old;
        down_write(&state->io_lock);
        old = rcu_dereference_protected(state->ident, 1);
        rcu_assign_pointer(state->ident, new_ident);
        up_write(&state->io_lock);
        kvfree_rcu(old, rcu);
        new_ident = NULL;
        announce = true;
    }
    if (new_ident) kvfree(new_ident);
    if (!result && new_access) {
        struct ntfs_rs_access *old = rcu_dereference_protected(state->access, 1);
        rcu_assign_pointer(state->access, new_access);
        if (old) kfree_rcu(old, rcu);
        new_access = NULL;
        announce = true;
    }
    kfree(new_access);
    if (!result && options->visibility_set) WRITE_ONCE(policy->flags, options->visibility);
    if (!result && (announce || was_ro != want_ro))
        ntfs_rs_announce_permissions(sb);
    return result;
}

static int ntfs_rs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct ntfs_rs_options *options = fc->fs_private;
    if (!strcmp(param->key, "visibility")) {
        unsigned int value;
        if (param->type != fs_value_is_string || kstrtouint(param->string, 10, &value) || value & ~7U)
            return -EINVAL;
        options->visibility = value;
        options->visibility_set = true;
        return 0;
    }
    if (!strcmp(param->key, "show_hidden") || !strcmp(param->key, "showmeta")) {
        if (param->type != fs_value_is_flag) return -EINVAL;
        options->visibility |= !strcmp(param->key, "showmeta") ? 4 : 7;
        options->visibility_set = true;
        return 0;
    }
	if (!strcmp(param->key, "view")) {
		if (param->type != fs_value_is_string || options->view)
			return -EINVAL;
		options->view = kmemdup_nul(param->string, param->size, GFP_KERNEL);
		return options->view ? 0 : -ENOMEM;
	}
    if (!strcmp(param->key, "compatibility")) {
        if (param->type != fs_value_is_string || options->compatibility_set)
            return -EINVAL;
        if (!strcmp(param->string, "linux"))
            options->native_mode = false;
        else if (!strcmp(param->string, "ntfs"))
            options->native_mode = true;
        else
            return -EINVAL;
        options->compatibility_set = true;
        return 0;
    }
	if (!strcmp(param->key, "permissions")) {
		if (param->type != fs_value_is_string || options->permissions >= 0)
			return -EINVAL;
		if (!strcmp(param->string, "desktop"))
			options->permissions = 1;
		else if (!strcmp(param->string, "windows"))
			options->permissions = 0;
		else
			return -EINVAL;
		return 0;
	}
	if (!strcmp(param->key, "uid") || !strcmp(param->key, "gid")) {
		bool is_uid = param->key[0] == 'u';
		unsigned int value;
		if (param->type != fs_value_is_string || (is_uid ? options->uid_set : options->gid_set) ||
		    kstrtouint(param->string, 10, &value) || value == U32_MAX)
			return -EINVAL;
		if (is_uid) { options->uid = value; options->uid_set = true; }
		else { options->gid = value; options->gid_set = true; }
		return 0;
	}
	if (!strcmp(param->key, "fmask") || !strcmp(param->key, "dmask") ||
	    !strcmp(param->key, "umask")) {
		unsigned int value;
		if (param->type != fs_value_is_string || kstrtouint(param->string, 8, &value) ||
		    value & ~0777U)
			return -EINVAL;
		if (param->key[0] != 'd') { options->fmask = value; options->fmask_set = true; }
		if (param->key[0] != 'f') { options->dmask = value; options->dmask_set = true; }
		return 0;
	}
	if (!strcmp(param->key, "experimental_rw")) {
		if (param->type != fs_value_is_flag || options->experimental_rw)
			return -EINVAL;
		options->experimental_rw = true;
		return 0;
	}
	if (strcmp(param->key, "sidmap"))
		return -ENOPARAM;
	if (param->type != fs_value_is_string || options->sidmap ||
	    ntfs_rs_validate_sidmap((const unsigned char *)param->string, param->size))
		return -EINVAL;
	options->sidmap = kmemdup_nul(param->string, param->size, GFP_KERNEL);
	return options->sidmap ? 0 : -ENOMEM;
}

static void ntfs_rs_free_context(struct fs_context *fc)
{
	struct ntfs_rs_options *options = fc->fs_private;
	if (options) {
		kfree(options->view);
		kfree(options->sidmap);
		kfree(options);
	}
}

static const struct fs_context_operations ntfs_rs_context_ops = {
	.free = ntfs_rs_free_context,
	.parse_param = ntfs_rs_parse_param,
	.get_tree = ntfs_rs_get_tree,
	.reconfigure = ntfs_rs_reconfigure,
};

static int ntfs_rs_init_fs_context(struct fs_context *fc)
{
	fc->fs_private = kzalloc(sizeof(struct ntfs_rs_options), GFP_KERNEL);
	if (!fc->fs_private)
		return -ENOMEM;
	((struct ntfs_rs_options *)fc->fs_private)->native_mode = true;
	((struct ntfs_rs_options *)fc->fs_private)->permissions = -1;
	fc->ops = &ntfs_rs_context_ops;
	return 0;
}

static void ntfs_rs_kill_super(struct super_block *sb)
{
	struct ntfs_rs_super *state = sb->s_fs_info;
	kill_block_super(sb);
	/* Wait for speculative path walks before freeing the shared SID map.
	 * Descriptor reclamation uses the kernel's generic kvfree_rcu callback,
	 * so no callback into module text can remain after unload. */
	synchronize_rcu();
	if (state) {
        unsigned long index;
        struct ntfs_rs_visibility *policy;
        xa_for_each(&state->visibility, index, policy) kfree(policy);
        xa_destroy(&state->visibility);
		kfree(state->writer);
        put_cred(state->mount_cred);
		kvfree(state->held);
		kvfree(state->batch_arena);
		kvfree(state->journal_map);
		kvfree(state->op_scratch);
		kvfree(state->upcase);
		kvfree(state->table);
		{
			struct ntfs_rs_security *kept;
			unsigned long id;
			xa_for_each(&state->descriptors, id, kept)
				kvfree(kept);
			xa_destroy(&state->descriptors);
		}
		while (state->scratch_idle)
			kvfree(state->scratch_pool[--state->scratch_idle]);
		kvfree(rcu_dereference_protected(state->ident, 1));
		kfree(rcu_dereference_protected(state->access, 1));
		kfree(state);
	}
}

static struct file_system_type ntfs_rs_type = {
	.owner = THIS_MODULE,
	.name = "ntfsrs",
	.init_fs_context = ntfs_rs_init_fs_context,
	.kill_sb = ntfs_rs_kill_super,
	.fs_flags = FS_REQUIRES_DEV | FS_USERNS_MOUNT,
};

static int __init ntfs_rs_init(void)
{
	return register_filesystem(&ntfs_rs_type);
}

static void __exit ntfs_rs_exit(void)
{
	unregister_filesystem(&ntfs_rs_type);
}

module_init(ntfs_rs_init);
module_exit(ntfs_rs_exit);
/* The generated header is a modpost dependency, including Rust-only changes
 * in srcversion. Expose its digest for diagnostics without loading a module. */
MODULE_INFO(slate_core_hash, NTFS_RS_CORE_HASH);
/* Expose the compiled digest of the loaded module too. There is no setter:
 * neither module arguments nor runtime writes can replace the identity. */
static char *ntfs_rs_core_hash = NTFS_RS_CORE_HASH;
static const struct kernel_param_ops ntfs_rs_core_hash_ops = {
    .get = param_get_charp,
};
module_param_cb(core_hash, &ntfs_rs_core_hash_ops, &ntfs_rs_core_hash, 0444);
MODULE_PARM_DESC(core_hash, "Read-only fingerprint of the compiled Rust NTFS core");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_VERSION("0.7.1");
MODULE_ALIAS_FS("ntfsrs");
MODULE_DESCRIPTION("slate-ntfs Rust filesystem with experimental journaled writes, B-tree renames and native ACL updates");
