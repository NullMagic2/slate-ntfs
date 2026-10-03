#!/usr/bin/env python3
"""Module: kernel.tests.test_desktop_permissions
Purpose: verify Files/GIO access on one new disposable NTFS image.
Created: 2026-10-01
Architecture: this integration test joins the Linux VFS bridge, Rust writer
and GIO access probes. It checks permission application through real remounts,
file operations and notifications, complementing the backend and callback tests.

Run as root on a test host with no loaded Slate driver. Existing mounts and
disks are never touched. Requires ntfs-format, gio, losetup and matching .ko.
"""
import argparse
import ctypes
import errno
import os
import select
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UID, GID = 12345, 23456
MAPPING = f"u:0:S-1-5-18;g:0:S-1-5-32-544;u:{UID}:S-1-5-32-544;g:{GID}:S-1-22-2-{GID}"


def run(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def credentials(uid=UID, gid=GID, groups=()):
    # Drop child credentials so root capabilities cannot mask an access denial.

    def drop():
        os.setgroups(groups)
        os.setgid(gid)
        os.setuid(uid)
    return drop


def as_user(operation, allowed=True, uid=UID, gid=GID, groups=()):
    # Check real mutations in an isolated child, accepting only access errors.

    pid = os.fork()
    if pid == 0:
        try:
            credentials(uid, gid, groups)()
            try:
                operation()
                success = True
            except OSError as error:
                assert error.errno in (errno.EACCES, errno.EPERM, errno.EROFS), error
                success = False
            os._exit(0 if success == allowed else 1)
        except BaseException:
            os._exit(2)
    assert os.waitpid(pid, 0)[1] == 0, "operation disagrees with selected permissions"


def gio_access(path, writable, deletable=None, uid=UID, gid=GID, groups=()):
    # Check the same GIO capabilities that determine Files menu actions.

    text = run("gio", "info", "-a", "access::can-write,access::can-delete,access::can-rename", path,
               capture_output=True, text=True, preexec_fn=credentials(uid, gid, groups)).stdout
    assert f"access::can-write: {'TRUE' if writable else 'FALSE'}" in text, text
    if deletable is not None:
        for action in ("delete", "rename"):
            assert f"access::can-{action}: {'TRUE' if deletable else 'FALSE'}" in text, text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", type=Path, default=ROOT / "kernel/ntfs_rs.ko")
    parser.add_argument("--formatter", default=shutil.which("ntfs-format"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root on a disposable test host")
    if Path("/sys/module/ntfs_rs").exists():
        parser.error("a Slate module is already loaded; this test will not replace it or disturb its mounts")
    if not args.formatter:
        parser.error("build ntfs-format or install it first")
    for tool in ("gio", "losetup", "mount", "umount", "insmod", "rmmod", "modinfo"):
        if not shutil.which(tool):
            parser.error(f"missing {tool}")
    version = run("modinfo", "-F", "vermagic", args.module, capture_output=True, text=True).stdout.split()[0]
    if version != os.uname().release:
        parser.error("module does not match the running kernel")
    loaded = mounted = False
    loop = None
    watch = -1
    with tempfile.TemporaryDirectory(prefix="slate-desktop-permissions-") as temporary:
        base = Path(temporary)
        base.chmod(0o755)
        image = base / "test.img"
        with image.open("xb") as stream:
            stream.truncate(128 * 1024 * 1024)
        run(args.formatter, image, "--yes", "-c", "4096")
        target = base / "mount"
        target.mkdir()
        try:
            run("insmod", args.module)
            loaded = True
            # Attach only the image created above; never discover or reuse a
            # user device. -i below also excludes userspace helper fallback.
            loop = run("losetup", "--find", "--show", image, capture_output=True, text=True).stdout.strip()
            access = f"permissions=desktop,uid={UID},gid={GID},fmask=0177,dmask=0077"
            run("mount", "-i", "-t", "ntfsrs", "-o", f"ro,sidmap={MAPPING},{access}", loop, target)
            mounted = True
            assert target.stat().st_mode & 0o777 == 0o700
            gio_access(target, False)
            as_user(lambda: (target / "blocked").mkdir(), False)
            readonly = run("gio", "info", "-f", "-a", "filesystem::readonly", target,
                           capture_output=True, text=True, preexec_fn=credentials()).stdout
            assert "filesystem::readonly: TRUE" in readonly, readonly

            libc = ctypes.CDLL(None, use_errno=True)
            libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            watch = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
            assert watch >= 0
            assert libc.inotify_add_watch(watch, os.fsencode(target), 4) >= 0 # IN_ATTRIB

            def remount(state, fmask="0177", dmask="0077"):
                # Verify both the remount and its file-manager refresh notification.

                run("mount", "-i", "-t", "ntfsrs", "-o",
                    f"remount,{state},permissions=desktop,uid={UID},gid={GID},fmask={fmask},dmask={dmask}", target)
                assert select.select([watch], [], [], 5)[0], "no permission-refresh event"
                events = os.read(watch, 65536)
                offset = 0
                changed = False
                while offset < len(events):
                    _, mask, _, length = struct.unpack_from("iIII", events, offset)
                    changed |= bool(mask & 4)
                    offset += 16 + length
                assert changed, "missing IN_ATTRIB"

            remount("rw")
            gio_access(target, True)
            def lifecycle():
                directory = target / "New Folder"
                directory.mkdir()
                path = directory / "pasted.txt"
                path.write_text("first")
                path.write_text("changed")
                renamed = directory / "renamed.txt"
                path.rename(renamed)
                assert renamed.read_text() == "changed"
                renamed.unlink()
                directory.rmdir()
                (target / "existing.txt").write_text("retained")
            as_user(lifecycle)
            gio_access(target / "existing.txt", True, True)

            remount("rw", "0377", "0277") # files 0400, directories 0500
            gio_access(target, False)
            gio_access(target / "existing.txt", False, False)
            as_user(lambda: (target / "denied").mkdir(), False)
            as_user(lambda: (target / "existing.txt").unlink(), False)

            remount("rw", "0117", "0007") # files 0660, directories 0770
            gio_access(target, True, uid=UID + 1)
            gio_access(target, True, uid=UID + 1, gid=GID + 1, groups=[GID])
            gio_access(target, False, uid=UID + 1, gid=GID + 1)
            as_user(lambda: (target / "group.txt").write_text("group"), uid=UID + 1)
            as_user(lambda: (target / "stranger.txt").write_text("denied"), False, uid=UID + 1, gid=GID + 1)

            remount("ro", "0117", "0007")
            gio_access(target, False)
            gio_access(target / "existing.txt", False, False)
            print("PASS: live ro/rw transitions, GIO create/delete/rename capabilities, file lifecycle, group permissions and IN_ATTRIB refresh")
        finally:
            if watch >= 0:
                os.close(watch)
            if mounted:
                run("umount", target)
            if loop:
                run("losetup", "-d", loop)
            if loaded:
                run("rmmod", "ntfs_rs")


if __name__ == "__main__":
    main()
