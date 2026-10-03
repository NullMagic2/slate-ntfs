/*
 * Module: ntfs_utils::c_api
 * Purpose: Declare the public NTFS utility C ABI.
 * Created: 2026-10-01
 * Architecture: C callers use this header with libntfs_utils; Rust ffi owns implementation and validation.
 */

#ifndef NTFS_UTILS_H
#define NTFS_UTILS_H

#include <stddef.h>
#include <stdint.h>

#define NTFS_UTILS_ABI_VERSION 2u
#define NTFS_UTILS_KIND_ALL 0u
#define NTFS_UTILS_KIND_HDD 1u
#define NTFS_UTILS_KIND_SSD 2u
#define NTFS_UTILS_KIND_USB_STICK 3u
#define NTFS_UTILS_OK 0
#define NTFS_UTILS_BAD_ARGUMENT 1
#define NTFS_UTILS_IO_ERROR 2
#define NTFS_UTILS_INVALID_NTFS 3
#define NTFS_UTILS_UNSUPPORTED 4
#define NTFS_UTILS_INTERNAL_ERROR 5

typedef struct ntfs_device_info {
    uint32_t abi_version;
    uint8_t is_dirty;
    uint8_t usage_available;
    uint16_t volume_flags;
    uint64_t volume_size_bytes;
    uint64_t allocatable_bytes;
    uint64_t used_bytes;
    uint64_t free_bytes;
    uint64_t volume_serial;
    uint32_t cluster_size_bytes;
    uint32_t device_kind;
    char path[512];
    char manufacturer[128];
    char model[128];
} ntfs_device_info;

/* v3 adds full hardware disk capacity. available=0 means unknown, not zero.
 * Use ntfs_utils_probe_v3/list_v3; legacy v2 functions stay compatible. */
#define NTFS_UTILS_ABI_VERSION_V3 3u
typedef struct ntfs_device_info_v3 {
    ntfs_device_info base;
    uint64_t physical_size_bytes;
    uint32_t physical_size_available;
    uint32_t reserved;
} ntfs_device_info_v3;

#ifdef __cplusplus
extern "C" {
#endif

int ntfs_utils_probe_v3(const char *path, ntfs_device_info_v3 *out,
    size_t out_size, char *error_buffer, size_t error_length);
int ntfs_utils_list_v3(uint32_t kind_filter, ntfs_device_info_v3 *out,
    size_t capacity, size_t *total_count, size_t *skipped_count,
    char *error_buffer, size_t error_length);

/* Administration statuses (separate namespace from read-only probe statuses).
 * Linux credentials/capabilities always apply. No automatic elevation. */
typedef enum ntfs_admin_status {
    NTFS_ADMIN_SUCCESS = 0, NTFS_ADMIN_FAILURE = 1,
    NTFS_ADMIN_PERMISSION_DENIED = 2, NTFS_ADMIN_BUSY = 3,
    NTFS_ADMIN_INVALID_ARGUMENT = 4, NTFS_ADMIN_UNSUPPORTED = 5,
    NTFS_ADMIN_DEPENDENCY_MISSING = 6, /* reserved; native format needs no helper */
    NTFS_ADMIN_VERIFICATION_FAILED = 7
} ntfs_admin_status;

/* DESTRUCTIVE native Rust format. quick is 0 or 1; NULL label means empty.
 * Existing partition/device or regular image; no partition-table creation.
 * SUCCESS requires flush and readback. Failure may leave a partial format.
 * Caller must own exclusive use of regular images (flock is cooperative).
 * Message buffers may be NULL only with zero capacity. */
int ntfs_utils_format(const char *path, const char *label, uint32_t quick,
                     char *message, size_t message_length);

#define NTFS_FORMAT_QUICK 1u
#define NTFS_FORMAT_DRY_RUN 2u
#define NTFS_FORMAT_COMPRESSION 4u
#define NTFS_FORMAT_NO_INDEXING 8u
#define NTFS_FORMAT_EPOCH_TIME 16u
#define NTFS_FORMAT_UUID 32u
typedef struct ntfs_format_options {
    uint32_t size, version, flags; /* sizeof(struct), 1, NTFS_FORMAT_* */
    uint32_t sector_size, cluster_size; /* 0: automatic */
    uint32_t mft_zone_multiplier; /* 1..4; allocation-layout hint */
    uint32_t heads, sectors_per_track, partition_start;
    uint32_t reserved; /* zero */
    uint64_t sectors; /* 0: complete target; otherwise logical sector count */
} ntfs_format_options;
int ntfs_utils_format_ex(const char *path, const char *label,
                     const ntfs_format_options *options,
                     char *message, size_t message_length);

#define NTFS_ADMIN_DEVICE_MODE 1u
#define NTFS_ADMIN_DEVICE_OWNER 2u
#define NTFS_ADMIN_FILE_MODE 3u
#define NTFS_ADMIN_FILE_OWNER 4u
#define NTFS_ADMIN_FILE_SECURITY 5u
/* mode in value1; owner in value1=UID, value2=GID. File actions require an
 * absolute mounted path on the selected NTFS device. Security takes a complete
 * self-relative descriptor, preserving ACE order; requires backend support.
 * Unused path/descriptor may be NULL. No recursive operation or offline patch.
 * All inputs and message storage must be valid and nonoverlapping. */
int ntfs_utils_change_permissions(const char *device, const char *path,
                     uint32_t action, uint32_t value1, uint32_t value2,
                     const uint8_t *descriptor, size_t descriptor_length,
                     char *message, size_t message_length);

/* Read-only snapshot. used/free are meaningful only when usage_available=1.
 * Empty manufacturer/model means unknown. The caller owns
 * every buffer. error_buffer may be NULL only with error_length == 0. */
int ntfs_utils_probe(const char *path, ntfs_device_info *out, size_t out_size,
                     char *error_buffer, size_t error_length);

/* Read-only offline device/image check. Mounted Linux block devices are BUSY
 * (reported as IO_ERROR); regular images must be quiesced by their owner.
 * report is called once on success with borrowed UTF-8 JSON (schema_version=1).
 * Copy it before returning. A zero API return does not mean a clean volume:
 * inspect JSON passed, complete, errors, log_state and findings. Callback must
 * not throw/unwind. No Rust buffers are transferred to the caller. */
typedef void (*ntfs_check_report_fn)(void *context, const uint8_t *json, size_t length);
int ntfs_utils_check(const char *path, ntfs_check_report_fn report, void *context,
                     char *error_buffer, size_t error_length);
/* Same one-callback contract. log_path is NULL or a new full findings report
 * file. Every finding is included; no fixed preview or report limit applies. */
int ntfs_utils_check_with_log(const char *path, const char *log_path,
                     ntfs_check_report_fn report, void *context,
                     char *error_buffer, size_t error_length);
/* Streaming alternative: concatenate chunks (at most 65536 bytes each) to
 * obtain the JSON document. Chunks need not end on a UTF-8 character or JSON
 * boundary. Return zero to accept, nonzero to abort. A nonzero API result
 * means any partial output must be discarded. log_path may be NULL. */
typedef int (*ntfs_check_write_fn)(void *context, const uint8_t *json, size_t length);
int ntfs_utils_check_stream(const char *path, const char *log_path,
                     ntfs_check_write_fn report, void *context,
                     char *error_buffer, size_t error_length);

typedef struct ntfs_repair_job ntfs_repair_job;
typedef struct ntfs_repair_progress {
    uint32_t phase;
    uint32_t sector_bytes; /* always 512 for reported work coverage */
    uint64_t completed_sectors;
    uint64_t total_sectors;
    double percentage; /* current phase, -1 if its total is not yet measurable */
} ntfs_repair_progress;
#define NTFS_REPAIR_COPY 0u
#define NTFS_REPAIR_IN_PLACE 1u
#define NTFS_REPAIR_RESUME 2u
#define NTFS_REPAIR_RESCUE 3u
#define NTFS_REPAIR_RESUME_RESCUE 4u
/* Rescue target is an external archive, never a mountable image. Good sectors
 * carry original offsets and checksums; unresolved sectors have no payload.
 * Resume retries missing sectors, keeping durable good copies. */
/* Phases: 0 plan, 1 MFT scan, 2 families, 3 directories, 4 allocation,
 * 5 security, 6 audit, 7 copy, 8 replay, 9 external journal, 10 repair writes,
 * 11 verification, 12 publication, 13 complete, 14 failed.
 * Counts are phase-relative work coverage, not device I/O traffic or an
 * estimated overall percentage. Revalidation can repeat a scan phase.
 * Copy counts advance on transfer; repair counts advance after flush. Only
 * phase 13 means the requested operation finished. For rescue it means all
 * sectors were preserved, not that NTFS structures are valid. Rescue counts
 * advance after archive fsync; phase 14 can mean unresolved sectors remain. */
int ntfs_utils_repair_start(const char *source, const char *target, uint32_t mode,
                    ntfs_repair_job **out, char *error_buffer, size_t error_length);
int ntfs_utils_repair_progress(const ntfs_repair_job *job,
                    ntfs_repair_progress *out, size_t out_size, uint32_t *finished);
/* wait returns NTFS_ADMIN_*, is repeatable and may run alongside progress.
 * free waits; do not free concurrently with another call on the handle. */
int ntfs_utils_repair_wait(const ntfs_repair_job *job, char *message, size_t length);
void ntfs_utils_repair_free(ntfs_repair_job *job);

/* Extract a complete external rescue archive to a new image. Incomplete or
 * conflicting archives are refused; no missing sector is zero-filled.
 * Reintegration first retries missing sectors from the original quiescent
 * source, verifies source identity, then extracts a complete new image.
 * Destination must not exist and is never an in-place repair target. */
int ntfs_utils_rescue_extract(const char *archive, const char *destination,
                    char *message, size_t message_length);
int ntfs_utils_rescue_reintegrate(const char *source, const char *archive,
                    const char *destination, char *message, size_t message_length);
/* Retire recorded EIO clusters in standard $BadClus metadata on a private
 * copy and relocate readable owners. Unsupported/unreadable owners refuse
 * publication; the external archive and private image remain for review. */
int ntfs_utils_rescue_repair(const char *source, const char *archive,
                    const char *destination, char *message, size_t message_length);

/* Exact self-relative descriptor snapshot from an offline/quiesced volume.
 * file_reference includes the high 16-bit MFT sequence number. Both security
 * indices, the SDS hash and its mirror are checked. Unsupported layouts fail.
 * capacity=0/output=NULL obtains required bytes. A short nonzero buffer is
 * not written and returns BAD_ARGUMENT. Buffers must not overlap.
 * This function grants no access rights and performs no UID/SID mapping. */
int ntfs_utils_security_descriptor(const char *path, uint64_t file_reference,
                    uint8_t *output, size_t capacity, size_t *required,
                    char *error_buffer, size_t error_length);

/* Lists NTFS partitions and whole-disk volumes. Entries are sorted by path.
 * A zero-capacity call (out=NULL) obtains total_count. If total_count exceeds
 * capacity, retry with a larger array. skipped_count reports paths that could
 * not be read or parsed; check it when a complete inventory is required.
 * kind_filter is one of NTFS_UTILS_KIND_*. Empty path is never returned. */
int ntfs_utils_list(uint32_t kind_filter, ntfs_device_info *out, size_t capacity,
                    size_t *total_count, size_t *skipped_count,
                    char *error_buffer, size_t error_length);

#define NTFS_COMPATIBILITY_LINUX 0U
#define NTFS_COMPATIBILITY_NTFS 1U
#define NTFS_COMPATIBILITY_DEFAULT NTFS_COMPATIBILITY_NTFS

/* Per-view compatibility: Linux=0, native NTFS=1 (default).
 * Uses current credentials/namespace. readonly is 0 or 1; no elevation.
 * Both modes can mount the same volume concurrently with the same SID map.
 * A conflicting SID map is BUSY; the mode cannot be changed by remounting. */
int ntfs_utils_mount(const char *device, const char *target, const char *sidmap,
                    uint32_t compatibility, uint32_t readonly,
                    char *message, size_t message_length);

typedef struct ntfs_application_options {
    uint32_t size; /* sizeof(ntfs_application_options) */
    uint32_t compatibility; /* NTFS_COMPATIBILITY_DEFAULT, or explicit mode */
    const char *const *mounts; /* NULL / zero count = all visible slate mounts */
    size_t mount_count;
    uint32_t visibility; /* NTFS_VISIBILITY_* bits */
    uint32_t flags; /* bit 0: override source visibility; otherwise inherit */
} ntfs_application_options;
#define NTFS_APPLICATION_OPTIONS_INIT {sizeof(ntfs_application_options), NTFS_COMPATIBILITY_DEFAULT, NULL, 0, 0, 0}

/* Unprivileged namespace setup requires enabled user namespaces. Preserves caller credentials and
 * mount restrictions; no shell, sudo or implicit privilege elevation.
 * options=NULL defaults to NTFS mode on all existing slate-ntfs mounts.
 * arguments does NOT include argv[0]. Returns administration status; on success
 * exit_code contains the application's exit status, or 128+termination signal.
 * A successful launch with an unsuccessful application exit still returns
 * NTFS_ADMIN_SUCCESS. On launch failure exit_code is -1. */
int ntfs_utils_run_application(const char *program, const char *const *arguments,
    size_t argument_count, const ntfs_application_options *options,
    int32_t *exit_code, char *message, size_t message_length);

/* Live view policy; no unmount and no on-disk metadata changes.
 * A host view requires root/CAP_SYS_ADMIN; delegated views may be changed
 * by their creator. Existing GUI listings may require Refresh. */
#define NTFS_VISIBILITY_HIDDEN 1u
#define NTFS_VISIBILITY_SYSTEM 2u
#define NTFS_VISIBILITY_METADATA 4u
#define NTFS_VISIBILITY_ALL 7u
#define NTFS_APPLICATION_VISIBILITY 1u
int ntfs_utils_get_visibility(const char *mounted_path, uint32_t *flags,
    char *message, size_t length);
int ntfs_utils_set_visibility(const char *mounted_path, uint32_t flags,
    char *message, size_t length);
int ntfs_utils_get_desktop_policy(uint32_t *automount, uint32_t *visibility,
    char *message, size_t length);
/* Persistent administrator settings; disabling automount leaves current mounts intact. */
int ntfs_utils_set_desktop_policy(uint32_t automount, uint32_t visibility,
    char *message, size_t length);
int ntfs_utils_set_automount(uint32_t enabled, char *message, size_t length);
int ntfs_utils_mount_with_visibility(const char *device, const char *target,
    const char *sidmap, uint32_t compatibility, uint32_t readonly,
    uint32_t visibility, char *message, size_t length);

/* Mount with configured/generated SID mapping. Same credentials and namespace
 * as the caller; target must exist. No implicit privilege elevation. */
int ntfs_utils_mount_for_user(const char *device, const char *target,
    uint32_t uid, uint32_t gid, uint32_t compatibility, uint32_t readonly,
    uint32_t visibility, char *message, size_t length);
/* Access policy is separate from compatibility.
 * permissions=0 (windows): strict Windows ACLs through sidmap (required).
 * permissions=1 (desktop): NTFS-3G-style mount-wide owner uid, group gid
 *   and permission bits (file_mode/dir_mode, e.g. 0600/0700, or 0660/0770 to
 *   share with a group). Stored Windows ownership and ACLs are preserved but
 *   not evaluated. sidmap may be NULL to use the owner's desktop map. */
int ntfs_utils_mount_with_access(const char *device, const char *target,
    const char *sidmap, uint32_t compatibility, uint32_t readonly,
    uint32_t visibility, uint32_t permissions, uint32_t uid, uint32_t gid,
    uint32_t file_mode, uint32_t dir_mode, char *message, size_t length);

/* Normal unmount. BUSY leaves the filesystem mounted; never forces/detaches. */
int ntfs_utils_unmount(const char *target, char *message, size_t length);

#ifdef __cplusplus
}
#endif

#endif
