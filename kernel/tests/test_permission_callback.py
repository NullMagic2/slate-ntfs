#!/usr/bin/env python3
"""Module: kernel.tests.test_permission_callback
Purpose: execute real C permission and internal-open callbacks with kernel
API test doubles.
Created: 2026-10-01
Architecture: this host test extracts callbacks from vfs_bridge.c, exercises
Linux access probes, desktop mode bits, canonical-handle credentials and public
mmap policy. It complements mounted GIO checks; it does not replace the Rust
DACL evaluator, live AppArmor enforcement or mounted kernel validation.

This needs a C compiler, not root or a mounted filesystem. Mounted/GIO checks
live in test_desktop_permissions.py. --source can test an older bridge too.
"""
import argparse
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def function(source, name):
    # Compile the production callback body so this test cannot drift into a copy.

    start = source.index("static int " + name + "(")
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source", type=Path, default=ROOT / "kernel/vfs_bridge.c")
args = parser.parse_args()
source = args.source.read_text()
defines = "\n".join(re.findall(
    r"^#define NTFS_RS_(?:ATTR_READONLY|VIEW_RO|VIEW_NOEXEC|READ_DATA|WRITE_DATA|"
    r"ADD_SUBDIRECTORY|READ_EA|WRITE_EA|EXECUTE|DELETE_CHILD|READ_ATTRIBUTES|"
    r"WRITE_ATTRIBUTES|DELETE|READ_CONTROL|WRITE_DAC|WRITE_OWNER|SYNCHRONIZE) .*",
    source,
    re.M,
))
desktop_defines = source[
    source.index("#define NTFS_RS_DESKTOP_R"):
    source.index("static int ntfs_rs_desktop_check(")
]
header = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <errno.h>
#include <sys/stat.h>
typedef uint32_t u32;
typedef unsigned int kuid_t;
typedef unsigned int kgid_t;
typedef unsigned int umode_t;
#define MAY_EXEC 1
#define MAY_WRITE 2
#define MAY_READ 4
#define MAY_APPEND 8
#define MAY_ACCESS 16
#define MAY_OPEN 32
#define MAY_CHDIR 64
#define MAY_NOT_BLOCK 128
#define CAP_FOWNER 1
#define CAP_DAC_OVERRIDE 2
#define CAP_DAC_READ_SEARCH 3
#define READ_ONCE(value) (value)
#define NTFS_RS_CALLBACK_IDMAP void *idmap,
#define NTFS_RS_CALLBACK_IDMAP_INIT
struct ntfs_rs_access {
    bool desktop;
    kuid_t uid;
    kgid_t gid;
    umode_t file_mode, dir_mode;
};
struct ntfs_rs_super {
    void *writer;
};
struct super_block {
    struct ntfs_rs_super *s_fs_info;
    bool ro;
};
struct inode {
    umode_t i_mode;
    kuid_t i_uid;
    kgid_t i_gid;
    struct super_block *i_sb;
};
struct ntfs_rs_inode {
    bool unix_mode;
    u32 attributes;
};
static struct ntfs_rs_access access_policy;
static struct ntfs_rs_inode private;
static kuid_t uid;
static kgid_t gid, supplementary;
static u32 limits, last_rights, windows_rights;
static bool native;
static kuid_t current_fsuid(void) {
    return uid;
}

static bool uid_eq(kuid_t a, kuid_t b) {
    return a == b;
}

static bool in_group_p(kgid_t g) {
    return gid == g || supplementary == g;
}

static bool capable(int cap) {
    (void)cap;
    return false;
}

static struct ntfs_rs_inode *ntfs_rs_shared(struct inode *i) {
    (void)i;
    return &private;
}

static u32 ntfs_rs_limits(struct inode *i) {
    (void)i;
    return limits;
}

static bool ntfs_rs_native(struct inode *i) {
    (void)i;
    return native;
}

static bool ntfs_rs_desktop_owner(struct super_block *sb, kuid_t *u, kgid_t *g) {
    (void)sb;
    (void)u;
    (void)g;
    return access_policy.desktop;
}

static struct inode *ntfs_rs_canonical(struct inode *i) {
    return i;
}

static int ntfs_rs_generic_permission(void *idmap, struct inode *i, int mask) {
    (void)idmap;
    (void)i;
    (void)mask;
    return -EACCES;
}

static bool ntfs_rs_readonly(struct inode *i) {
    return i->i_sb->ro || (limits & 1);
}
"""
authorize = r"""
static int ntfs_rs_authorize(struct inode *i, u32 rights, bool rcu) {
    (void)rcu;
    last_rights = rights;
    return access_policy.desktop ? ntfs_rs_desktop_check(i, &access_policy, rights) :
        (rights & ~windows_rights ? -EACCES : 0);
}
"""
cases = r"""
int main(void) {
    struct ntfs_rs_super state = { .writer = &state };
    struct super_block sb = { .s_fs_info = &state };
    struct inode directory = { .i_mode = S_IFDIR | 0555, .i_sb = &sb };
    struct inode file = { .i_mode = S_IFREG | 0555, .i_sb = &sb };
    access_policy = (struct ntfs_rs_access){ .desktop = true, .uid = 1000, .gid = 2000,
        .file_mode = 0600, .dir_mode = 0700 };
    uid = 1000;
    gid = 1000;
    assert(ntfs_rs_permission(NULL, &directory, MAY_WRITE | MAY_ACCESS) == 0);
    assert(ntfs_rs_permission(NULL, &file, MAY_WRITE | MAY_ACCESS) == 0);
    assert(ntfs_rs_permission(NULL, &file, MAY_READ | MAY_OPEN) == 0);
    assert(ntfs_rs_permission(NULL, &file, MAY_EXEC | MAY_OPEN) == -EACCES);
    access_policy.file_mode = 0700;
    assert(ntfs_rs_permission(NULL, &file, MAY_EXEC | MAY_OPEN) == 0);
    access_policy.file_mode = 0600;
    access_policy.dir_mode = 0500;
    assert(ntfs_rs_permission(NULL, &directory, MAY_WRITE | MAY_ACCESS) == -EACCES);
    assert(ntfs_rs_permission(NULL, &directory, MAY_WRITE) == -EACCES);
    assert(ntfs_rs_permission(NULL, &directory, MAY_READ | MAY_EXEC) == 0);
    access_policy.dir_mode = 0770;
    access_policy.file_mode = 0660;
    uid = 1001;
    gid = 2000;
    assert(ntfs_rs_permission(NULL, &directory, MAY_WRITE | MAY_ACCESS) == 0);
    assert(ntfs_rs_permission(NULL, &file, MAY_WRITE | MAY_ACCESS) == 0);
    gid = 1001;
    supplementary = 2000;
    assert(ntfs_rs_permission(NULL, &directory, MAY_WRITE | MAY_ACCESS) == 0);
    supplementary = 0;
    assert(ntfs_rs_permission(NULL, &directory, MAY_WRITE | MAY_ACCESS) == -EACCES);
    assert(ntfs_rs_permission(NULL, &file, MAY_WRITE | MAY_ACCESS) == -EACCES);
    assert(ntfs_rs_permission(NULL, &file, MAY_READ | MAY_OPEN) == -EACCES);
    access_policy.dir_mode = 0777;
    assert(ntfs_rs_permission(NULL, &directory, MAY_WRITE | MAY_ACCESS) == 0);
    sb.ro = true;
    assert(ntfs_rs_permission(NULL, &directory, MAY_WRITE | MAY_ACCESS) == -EROFS);
    uid = 1000;
    assert(ntfs_rs_permission(NULL, &file, MAY_READ | MAY_OPEN) == 0);
    access_policy.file_mode = 0770;
    assert(ntfs_rs_permission(NULL, &file, MAY_EXEC | MAY_OPEN) == 0);
    sb.ro = false;
    limits = NTFS_RS_VIEW_RO;
    assert(ntfs_rs_permission(NULL, &directory, MAY_WRITE | MAY_ACCESS) == -EROFS);
    limits = 0;
    state.writer = NULL;
    assert(ntfs_rs_permission(NULL, &directory, MAY_WRITE | MAY_ACCESS) == -EROFS);
    state.writer = &state;
    uid = 1000;
    private.attributes = NTFS_RS_ATTR_READONLY;
    assert(ntfs_rs_permission(NULL, &file, MAY_WRITE | MAY_ACCESS) == -EACCES);
    private.attributes = 0;
    limits = NTFS_RS_VIEW_NOEXEC;
    assert(ntfs_rs_permission(NULL, &file, MAY_EXEC | MAY_ACCESS) == -EACCES);
    limits = 0;
    access_policy.desktop = false;
    windows_rights = NTFS_RS_READ_DATA | NTFS_RS_EXECUTE;
    assert(ntfs_rs_permission(NULL, &directory, MAY_WRITE | MAY_ACCESS) == -EACCES);
    assert(last_rights == NTFS_RS_WRITE_DATA);
    windows_rights |= NTFS_RS_WRITE_DATA;
    assert(ntfs_rs_permission(NULL, &directory, MAY_WRITE | MAY_ACCESS) == 0);
    // Operation callbacks retain precise Windows checks;
    // This generic check is deferred.
    assert(ntfs_rs_permission(NULL, &directory, MAY_WRITE) == 0);
    assert(ntfs_rs_permission(NULL, &file, MAY_READ | MAY_OPEN) == 0);
    assert(ntfs_rs_permission(NULL, &file, MAY_EXEC | MAY_OPEN) == 0);
    windows_rights &= ~NTFS_RS_EXECUTE;
    assert(ntfs_rs_permission(NULL, &file, MAY_EXEC | MAY_OPEN) == -EACCES);
    private.unix_mode = true;
    assert(ntfs_rs_permission(NULL, &directory, MAY_WRITE | MAY_ACCESS) == -EACCES);
    // The same deletion gate serves unlink and rename in native views.
    private.unix_mode = false;
    access_policy.desktop = true;
    access_policy.dir_mode = 0700;
    native = true;
    private.attributes = NTFS_RS_ATTR_READONLY;
    assert(ntfs_rs_may_delete(&directory, &file) == -EACCES);
    // A read-only directory attribute does not forbid deleting its name.
    assert(ntfs_rs_may_delete(&directory, &directory) == 0);
    native = false;
    assert(ntfs_rs_may_delete(&directory, &file) == 0);
    access_policy.dir_mode = 0500;
    assert(ntfs_rs_may_delete(&directory, &file) == -EACCES);
    access_policy.desktop = false;
    private.attributes = 0;
    native = true;
    windows_rights = NTFS_RS_DELETE;
    assert(ntfs_rs_may_delete(&directory, &file) == 0);
    windows_rights = NTFS_RS_DELETE_CHILD;
    assert(ntfs_rs_may_delete(&directory, &file) == 0);
    windows_rights = 0;
    assert(ntfs_rs_may_delete(&directory, &file) == -EACCES);
    puts("PASS: real C delete and permission callback cases for owner/group/others, mount/view read-only, Windows probes and file attributes");
}
"""
with tempfile.TemporaryDirectory(prefix="slate-permission-callback-") as temporary:
    path = Path(temporary)
    test = path / "callback.c"
    test.write_text(
        header + defines + "\n" + desktop_defines
        + function(source, "ntfs_rs_desktop_check") + authorize
        + function(source, "ntfs_rs_permission")
        + function(source, "ntfs_rs_may_delete") + cases
    )
    subprocess.run(
        ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", str(test),
         "-o", str(path / "callback")],
        check=True,
    )
    subprocess.run([str(path / "callback")], check=True)


# Model a confined application whose visible file is allowed but whose hidden
# canonical alias has no pathname. The public VFS checks still decide access;
# only the internal handle must use retained mounting credentials.

open_header = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#define FMODE_NOWAIT 1
#define FMODE_EXEC 2
#define FMODE_CAN_ODIRECT 4
#define VM_EXEC 1
#define VM_MAYEXEC 2
#define VM_SHARED 4
#define VM_WRITE 8
#define __O_TMPFILE 020000000
#define READ_ONCE(value) (value)
#define IS_ERR(pointer) ((intptr_t)(pointer) < 0)
#define PTR_ERR(pointer) ((int)(intptr_t)(pointer))
#define ERR_PTR(error) ((void *)(intptr_t)(error))
#define current_cred() active_cred
struct cred {
    bool confined;
};
struct ntfs_rs_super {
    const struct cred *mount_cred;
    int io_lock;
};
struct super_block {
    struct ntfs_rs_super *s_fs_info;
    bool ro;
};
struct inode {
    unsigned int i_mode, i_nlink;
    struct super_block *i_sb;
    struct inode *canonical;
};
struct dentry {
    struct inode *inode;
};
struct path {
    void *mnt;
    struct dentry *dentry;
};
struct file {
    unsigned int f_mode, f_flags;
    struct path f_path;
    void *private_data;
    const struct cred *f_cred;
};
struct vm_area_struct {
    unsigned int vm_flags;
    struct file *vm_file;
    const void *vm_ops;
};
struct ntfs_rs_inode {
    bool orphaned;
    int open_files;
};
static struct ntfs_rs_inode shared;
static const struct cred mount_cred = { .confined = false };
static const struct cred caller_cred = { .confined = true };
static const struct cred *active_cred = &caller_cred;
static struct file backing;
static struct dentry alias;
static int alias_error, open_error, execute_error, lease_error;
static unsigned int alias_calls, open_calls, overrides, reversions;
static unsigned int dputs, fput_calls, execute_calls, internal_flags;
static unsigned int view_limits;
static int write_error;
static bool content_forbidden;
static const int ntfs_rs_vm_ops;

static struct inode *file_inode(struct file *file) {
    return file->f_path.dentry->inode;
}

static unsigned int ntfs_rs_limits(struct inode *inode) {
    (void)inode;
    return view_limits;
}

static bool ntfs_rs_readonly(struct inode *inode) {
    return inode->i_sb->ro;
}

static bool ntfs_rs_content_forbidden(struct inode *inode, bool nowait) {
    (void)inode;
    (void)nowait;
    return content_forbidden;
}

static int ntfs_rs_authorize(struct inode *inode, unsigned int rights, bool rcu) {
    (void)inode;
    (void)rights;
    (void)rcu;
    assert(active_cred == &caller_cred);
    return write_error;
}

static int generic_file_mmap(struct file *file, struct vm_area_struct *vma) {
    assert(file == vma->vm_file);
    assert(file->f_cred == &caller_cred && active_cred == &caller_cred);
    return 0;
}

static struct inode *ntfs_rs_canonical(struct inode *inode) {
    return inode->canonical ? inode->canonical : inode;
}

static struct ntfs_rs_inode *ntfs_rs_shared(struct inode *inode) {
    (void)inode;
    return &shared;
}

static struct inode *igrab(struct inode *inode) {
    return inode;
}

static struct dentry *d_obtain_alias(struct inode *inode) {
    alias_calls++;
    alias.inode = inode;
    return alias_error ? ERR_PTR(alias_error) : &alias;
}

static inline const struct cred *override_creds(const struct cred *cred) {
    const struct cred *previous = active_cred;
    assert(cred == &mount_cred);
    overrides++;
    active_cred = cred;
    return previous;
}

static inline void revert_creds(const struct cred *cred) {
    assert(cred == &caller_cred);
    reversions++;
    active_cred = cred;
}

static struct file *test_dentry_open(const struct path *path, unsigned int flags,
                                    const struct cred *cred) {
    assert(path->dentry == &alias);
    open_calls++;
    internal_flags = flags;
    /* File-security allocation and file-open hooks both see the mount label. */
    if (active_cred->confined || cred->confined)
        return ERR_PTR(-EACCES);
    backing.f_cred = cred;
    return open_error ? ERR_PTR(open_error) : &backing;
}

#define dentry_open test_dentry_open
#define dentry_open_nonotify test_dentry_open

static void dput(struct dentry *dentry) {
    assert(dentry == &alias);
    assert(active_cred == &caller_cred);
    dputs++;
}

static void fput(struct file *file) {
    assert(file == &backing);
    assert(active_cred == &caller_cred);
    fput_calls++;
}

static int deny_write_access(struct file *file) {
    assert(file == &backing);
    assert(active_cred == &caller_cred);
    execute_calls++;
    return execute_error;
}

static void down_read(int *lock) {
    (void)lock;
}

static void up_read(int *lock) {
    (void)lock;
}

static void atomic_inc(int *value) {
    ++*value;
}

static void atomic_dec(int *value) {
    --*value;
}

static int ntfs_rs_break_leases(struct inode *inode, unsigned int flags) {
    (void)inode;
    (void)flags;
    return lease_error;
}
"""
open_cases = r"""
static int public_open(struct inode *inode, struct file *file,
                       bool permitted_path) {
    /* An application denial never reaches the internal handle callback. */
    if (!permitted_path)
        return -EACCES;
    return ntfs_rs_open(inode, file);
}

static void reset(void) {
    active_cred = &caller_cred;
    alias_error = open_error = execute_error = lease_error = 0;
    alias_calls = open_calls = overrides = reversions = 0;
    dputs = fput_calls = execute_calls = internal_flags = 0;
    shared = (struct ntfs_rs_inode){0};
    backing = (struct file){0};
}

int main(void) {
    struct ntfs_rs_super state = { .mount_cred = &mount_cred };
    struct super_block sb = { .s_fs_info = &state };
    struct inode canonical = { .i_mode = S_IFREG | 0700,
        .i_nlink = 1, .i_sb = &sb };
    struct inode native = { .i_mode = S_IFREG | 0700,
        .i_nlink = 1, .i_sb = &sb, .canonical = &canonical };
    struct file file = { .f_cred = &caller_cred, .f_flags = 0100000 };
    reset();
    assert(public_open(&native, &file, false) == -EACCES);
    assert(alias_calls == 0 && overrides == 0);
    assert(file.f_cred == &caller_cred && file.private_data == NULL);
    assert(public_open(&native, &file, true) == 0);
    assert(file.private_data == &backing && backing.f_cred == &mount_cred);
    assert(file.f_cred == &caller_cred && active_cred == &caller_cred);
    assert(overrides == 1 && reversions == 1 && dputs == 1);
    assert(file.f_mode & FMODE_NOWAIT);
    assert(file.f_mode & FMODE_CAN_ODIRECT);
#if defined(__FMODE_NONOTIFY) && !defined(NTFS_RS_OPEN_NONOTIFY)
    assert(internal_flags == (file.f_flags | __FMODE_NONOTIFY));
#else
    assert(internal_flags == file.f_flags);
#endif
    reset();
    file.private_data = NULL;
    alias_error = -ENOMEM;
    assert(public_open(&native, &file, true) == -ENOMEM);
    assert(overrides == 0 && reversions == 0 && dputs == 0);
    reset();
    open_error = -EACCES;
    assert(public_open(&native, &file, true) == -EACCES);
    assert(overrides == 1 && reversions == 1 && dputs == 1);
    assert(active_cred == &caller_cred && file.private_data == NULL);
    reset();
    file.f_mode |= FMODE_EXEC;
    execute_error = -ETXTBSY;
    assert(public_open(&native, &file, true) == -ETXTBSY);
    assert(execute_calls == 1 && fput_calls == 1 && file.private_data == NULL);
    assert(active_cred == &caller_cred && reversions == 1);
    reset();
    assert(public_open(&native, &file, true) == 0);
    assert(execute_calls == 1 && fput_calls == 0 && file.private_data == &backing);
    assert(file.f_cred == &caller_cred && active_cred == &caller_cred);
    reset();
    file.private_data = NULL;
    assert(ntfs_rs_open(&canonical, &file) == 0);
    assert(shared.open_files == 1 && overrides == 0);
    shared.open_files = 0;
    lease_error = -EAGAIN;
    assert(ntfs_rs_open(&canonical, &file) == -EAGAIN);
    assert(shared.open_files == 0);
    lease_error = 0;
    canonical.i_nlink = 0;
    assert(ntfs_rs_open(&canonical, &file) == -ENOENT);
    shared.orphaned = true;
    assert(ntfs_rs_open(&canonical, &file) == 0);
    assert(shared.open_files == 1);
    struct dentry visible = { .inode = &native };
    file.f_path.dentry = &visible;
    struct vm_area_struct vma = { .vm_file = &file, .vm_flags = VM_MAYEXEC };
    assert(ntfs_rs_mmap(&file, &vma) == 0);
    assert(vma.vm_file == &file && vma.vm_ops == &ntfs_rs_vm_ops);
    view_limits = NTFS_RS_VIEW_NOEXEC;
    vma.vm_flags = VM_EXEC | VM_MAYEXEC;
    assert(ntfs_rs_mmap(&file, &vma) == -EACCES);
    vma.vm_flags = VM_MAYEXEC;
    assert(ntfs_rs_mmap(&file, &vma) == 0);
    assert(!(vma.vm_flags & VM_MAYEXEC));
    view_limits = 0;
    sb.ro = true;
    vma.vm_flags = VM_WRITE;
    assert(ntfs_rs_mmap(&file, &vma) == 0);
    vma.vm_flags = VM_WRITE | VM_SHARED;
    assert(ntfs_rs_mmap(&file, &vma) == -EROFS);
    sb.ro = false;
    content_forbidden = true;
    assert(ntfs_rs_mmap(&file, &vma) == -EPERM);
    content_forbidden = false;
    write_error = -EACCES;
    assert(ntfs_rs_mmap(&file, &vma) == -EACCES);
    write_error = 0;
    assert(ntfs_rs_mmap(&file, &vma) == 0);
    assert(vma.vm_file == &file && active_cred == &caller_cred);
    puts("PASS: canonical open credentials, caller denials, error unwind and execution accounting");
    puts("PASS: public mmap file identity, noexec and shared-write policy");
}
"""
with tempfile.TemporaryDirectory(prefix="slate-open-callback-") as temporary:
    path = Path(temporary)
    test = path / "open.c"
    test.write_text(
        open_header + defines + "\n"
        + function(source, "ntfs_rs_open")
        + function(source, "ntfs_rs_mmap") + open_cases
    )
    for name, variant in (
        ("ordinary", []),
        ("nonotify-flags", ["-D__FMODE_NONOTIFY=0x1000000"]),
        ("nonotify-helper", ["-DNTFS_RS_OPEN_NONOTIFY"]),
    ):
        binary = path / name
        subprocess.run(
            [
                "cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", *variant,
                str(test), "-o", str(binary),
            ],
            check=True,
        )
        subprocess.run([str(binary)], check=True)
