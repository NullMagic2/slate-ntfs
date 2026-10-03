# Module: kernel.kbuild
# Purpose: Build the C bridge and link the freestanding Rust NTFS engine.
# Created: 2026-10-01
# Architecture: Kbuild probes kernel interfaces, tracks the Rust fingerprint
# and combines both language adapters into the installable ntfs_rs module.

obj-m := ntfs_rs.o
ntfs_rs-y := vfs_bridge.o rust_core.o

# modpost normally sees only C dependencies. A generated, tracked header also
# makes Rust-only fixes change srcversion, allowing safe stale-driver reloads.
ccflags-y += -I$(obj)
targets += core_fingerprint.h
quiet_cmd_ntfs_rs_fingerprint = COREHASH $@
      cmd_ntfs_rs_fingerprint = sh "$(src)/core_fingerprint.sh" > "$@.tmp" && \
        { cmp -s "$@.tmp" "$@" && rm -f "$@.tmp" || mv -f "$@.tmp" "$@"; }

$(obj)/core_fingerprint.h: $(src)/core_fingerprint.sh FORCE
	$(call cmd,ntfs_rs_fingerprint)

$(obj)/vfs_bridge.o: $(obj)/core_fingerprint.h
# The d_revalidate callback changed independently of distribution versions.
ccflags-y += $(shell grep -q 'd_revalidate.*struct inode' $(srctree)/include/linux/dcache.h && echo -DNTFS_RS_REVALIDATE_PARENT)
ccflags-y += $(shell grep -q 'set_default_d_op' $(srctree)/include/linux/dcache.h && echo -DNTFS_RS_DEFAULT_D_OP)
# Probe API shape instead of assuming distro kernel version numbers.
ccflags-y += $(shell grep -qw bdev_freeze $(srctree)/include/linux/blkdev.h && echo -DNTFS_RS_BDEV_FREEZE)
ccflags-y += $(shell grep -qw writeback_iter $(srctree)/include/linux/writeback.h && echo -DNTFS_RS_WRITEBACK_ITER)
ccflags-y += $(shell grep -q '\*writepage[^s]' $(srctree)/include/linux/fs.h && echo -DNTFS_RS_AOPS_WRITEPAGE)
ccflags-y += $(shell grep 'update_time.*struct inode.*int' $(srctree)/include/linux/fs.h | grep -qv timespec && echo -DNTFS_RS_UPDATE_TIME_FLAGS)
ccflags-y += $(shell grep -q 'read_folio' $(srctree)/include/linux/fs.h && echo -DNTFS_RS_FOLIO_AOPS)
ccflags-y += $(shell grep -q 'dirty_folio' $(srctree)/include/linux/fs.h && echo -DNTFS_RS_DIRTY_FOLIO)
ccflags-y += $(shell grep -qw read_mapping_folio $(srctree)/include/linux/pagemap.h && echo -DNTFS_RS_BDEV_FOLIO_IO)
ccflags-y += $(shell grep -qw filemap_grab_folio $(srctree)/include/linux/pagemap.h && echo -DNTFS_RS_BDEV_GRAB_FOLIO)
ccflags-y += $(shell grep -A1 'writepage_t' $(srctree)/include/linux/writeback.h | grep -q 'struct folio' && echo -DNTFS_RS_WRITEPAGE_FOLIO)
ccflags-y += $(shell grep -Fq 'struct dentry *(*mkdir)' $(srctree)/include/linux/fs.h && echo -DNTFS_RS_MKDIR_DENTRY)
ccflags-y += $(shell grep -q 'd_tmpfile.*struct file' $(srctree)/include/linux/dcache.h && echo -DNTFS_RS_TMPFILE_FILE)
ccflags-y += $(shell grep -q 'vm_flags_clear' $(srctree)/include/linux/mm.h && echo -DNTFS_RS_VM_FLAGS_HELPERS)
ccflags-y += $(shell grep -q 'filemap_splice_read' $(srctree)/include/linux/fs.h && echo -DNTFS_RS_FILEMAP_SPLICE_READ)
ccflags-y += $(shell grep -q 'splice_copy_file_range' $(srctree)/include/linux/splice.h && echo -DNTFS_RS_SPLICE_COPY_RANGE)
ccflags-y += $(shell test -f $(srctree)/include/linux/filelock.h && echo -DNTFS_RS_FILELOCK_H)
ccflags-y += $(shell test -f $(srctree)/include/linux/filelock.h && grep -q 'struct file_lock_core {' $(srctree)/include/linux/filelock.h && echo -DNTFS_RS_FILE_LOCK_CORE)
ccflags-y += $(shell test -f $(srctree)/include/linux/filelock.h && grep -q 'struct file_lease \*\*' $(srctree)/include/linux/filelock.h && echo -DNTFS_RS_FILE_LEASE)
ccflags-y += $(shell grep -q 'setlease.*struct file \*, int,' $(srctree)/include/linux/fs.h && echo -DNTFS_RS_SETLEASE_INT)

ifeq ($(ARCH),arm64)
NTFS_RS_RUST_TARGET ?= aarch64-unknown-none-softfloat
else ifeq ($(ARCH),x86)
NTFS_RS_RUST_TARGET ?= x86_64-unknown-none
else
$(error unsupported ARCH=$(ARCH); use x86 or arm64)
endif

targets += rust_core.o
NTFS_RS_RUST_TARGET_DIR ?= $(src)/rust/target
quiet_cmd_ntfs_rs_rust = RUSTLINK $@
      cmd_ntfs_rs_rust = $(LD) -r --gc-sections \
	-u ntfs_rs_volume_identity -u ntfs_rs_trim_free -u ntfs_rs_map_file -u ntfs_rs_writer_allocate -u ntfs_rs_parent -u ntfs_rs_probe -u ntfs_rs_stat -u ntfs_rs_space -u ntfs_rs_read_file -u ntfs_rs_read_scratch_size \
	-u ntfs_rs_lookup_name -u ntfs_rs_readdir -u ntfs_rs_read_link \
	-u ntfs_rs_get_ea -u ntfs_rs_list_ea -u ntfs_rs_ea_scratch_size \
	-u ntfs_rs_load_security -u ntfs_rs_check_security \
	-u ntfs_rs_validate_sidmap -u ntfs_rs_sidmap_size \
	-u ntfs_rs_compile_sidmap -u ntfs_rs_writer_size -u ntfs_rs_writer_init \
	-u ntfs_rs_writer_write -u ntfs_rs_writer_resize -u ntfs_rs_writer_rename \
	-u ntfs_rs_writer_pending -u ntfs_rs_writer_drain -u ntfs_rs_writer_trim \
	-u ntfs_rs_writer_finish -u ntfs_rs_writer_create -u ntfs_rs_writer_unlink \
	-u ntfs_rs_writer_reclaim -u ntfs_rs_writer_reclaim_orphans \
	-u ntfs_rs_writer_set_ea -u ntfs_rs_writer_repair_ea -u ntfs_rs_writer_repair_ea_number \
	-u ntfs_rs_writer_repair_allocation_sector -u ntfs_rs_writer_repair_data -u ntfs_rs_writer_set_times \
	-u ntfs_rs_writer_security_scratch_size -u ntfs_rs_writer_set_security \
	-u ntfs_rs_writer_chown -u ntfs_rs_writer_mode -u ntfs_rs_writer_link -u ntfs_rs_writer_set_label $< -o $@ && \
	$(OBJCOPY) --remove-section=.llvmbc --remove-section=.llvmcmd $@

$(obj)/rust_core.o: $(NTFS_RS_RUST_TARGET_DIR)/$(NTFS_RS_RUST_TARGET)/release/libslate_ntfs_kernel.a FORCE
	$(call if_changed,ntfs_rs_rust)

ccflags-y += $(shell grep -qw bd_mapping $(srctree)/include/linux/blk_types.h && echo -DNTFS_RS_BDEV_MAPPING)
ccflags-y += $(shell grep -qw copy_folio_from_iter_atomic $(srctree)/include/linux/uio.h && echo -DNTFS_RS_COPY_FOLIO_ATOMIC)
ccflags-y += $(shell grep -qw kiocb_modified $(srctree)/include/linux/fs.h && echo -DNTFS_RS_KIOCB_MODIFIED)

ccflags-y += $(shell grep -q '(\*fsnotify_path)' $(srctree)/include/linux/fs.h && echo -DNTFS_RS_FSNOTIFY_PATH)

ccflags-y += $(shell grep -qw dentry_open_nonotify $(objtree)/Module.symvers && echo -DNTFS_RS_OPEN_NONOTIFY)

ccflags-y += $(shell test -f $(srctree)/include/linux/fileattr.h && grep -qw file_kattr $(srctree)/include/linux/fileattr.h && echo -DNTFS_RS_FILE_KATTR)
ccflags-y += $(shell test -f $(srctree)/include/linux/fileattr.h && echo -DNTFS_RS_FILEATTR_H)
ccflags-y += $(shell grep -qw super_set_uuid $(srctree)/include/linux/fs.h && echo -DNTFS_RS_UUID_LEN)
ccflags-y += $(shell grep -qw bdev_max_discard_sectors $(srctree)/include/linux/blkdev.h && echo -DNTFS_RS_BDEV_DISCARD)

ccflags-y += $(shell grep -q "update_time.*enum fs_update_time" $(srctree)/include/linux/fs.h && echo -DNTFS_RS_UPDATE_TIME_TYPE)
ccflags-y += $(shell grep -q "extern void \*posix_acl_to_xattr" $(srctree)/include/linux/posix_acl_xattr.h && echo -DNTFS_RS_ACL_XATTR_ALLOC)
