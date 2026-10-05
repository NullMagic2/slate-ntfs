#!/usr/bin/env python3
"""
Module: kernel.tests.test_kernel_acl
Purpose: Live native ACL changes, chown and B-tree renames on disposable loop mounts.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Live native ACL changes, chown and B-tree renames on disposable loop mounts.

Checks the system.ntfs_security xattr (raw self-relative descriptors, the
ntfs3 name), immediate descriptor-cache replacement for later access checks,
native WRITE_DAC/WRITE_OWNER enforcement, chown through explicit SID maps,
cross-directory and directory renames that split and collapse indexes, NTFS-3G
readback after unmount, and recovery after an injected failure at every
durable flush of a descriptor change and of a rename.

Requires root, a module built for the running kernel, and a NEW output
directory: sudo python3 kernel/tests/test_kernel_acl.py /abs/new-directory
"""
import errno
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests/support"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src/tests/writer"))
from ntfs_image import run  # noqa: E402
import test_metadata_writer as meta  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
MAPPING = meta.MAP
PARAMETER = Path("/sys/module/slate_ntfs/parameters/fail_after_flush")


def as_user(uid, gid, action):
    child = os.fork()
    if child == 0:
        try:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            action()
            os._exit(0)
        except BaseException as error:  # noqa: BLE001 - report through status
            print("child failure:", repr(error), flush=True)
            os._exit(1)
    assert os.waitpid(child, 0)[1] == 0


def denied(call, codes):
    try:
        call()
    except OSError as error:
        assert error.errno in codes, error
    else:
        raise AssertionError("operation unexpectedly succeeded")


class Loop:
    def __init__(self, image, mountpoint):
        self.image, self.mountpoint, self.loop = image, mountpoint, None

    def __enter__(self):
        self.loop = run("losetup", "--find", "--show", self.image).stdout.decode().strip()
        run("mount", "-t", "ntfsrs", "-o", f"rw,experimental_rw,compatibility=ntfs,sidmap={MAPPING}", self.loop, self.mountpoint)
        return self.mountpoint

    def __exit__(self, *exc):
        subprocess.run(["umount", str(self.mountpoint)])
        subprocess.run(["losetup", "-d", self.loop])


def main():
    assert os.geteuid() == 0
    out = Path(sys.argv[1]).resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = out / "source.img"
    meta.mkimage(source, 64)
    with meta.Mounted(source, out / "populate") as m:
        (m / "a").mkdir()
        (m / "b").mkdir()
        (m / "a" / "dir").mkdir()
        for i in range(300):
            (m / "a" / f"entry-{i:03d}").write_bytes(f"{i}".encode())
        (m / "file.txt").write_bytes(b"secret")
    # Grant everyone full control so the unprivileged checks below start open.
    probe = subprocess.run([str(meta.CHKDSK), '--audit', str(source)], capture_output=True)
    meta.BASELINE.update(l for l in probe.stdout.decode().splitlines() if l.startswith('finding='))
    assert all('finding=unsupported record=0 ' in l or 'finding=unsupported record=1 ' in l for l in meta.BASELINE), meta.BASELINE
    meta.audit(source)
    open_sd = meta.descriptor(meta.OWNER, meta.GROUP, [meta.ace(0, meta.EVERYONE_SID, 0x1F01FF)])
    prepared = out / "prepared.img"
    meta.lab(source, prepared,
             ("set-security", "/file.txt", open_sd.hex(), "1000", "1000", MAPPING),
             ("set-security", "/a", open_sd.hex(), "1000", "1000", MAPPING),
             ("set-security", "/b", open_sd.hex(), "1000", "1000", MAPPING))
    mount = out / "mount"
    mount.mkdir()
    run("insmod", ROOT / "kernel/slate-ntfs.ko")
    try:
        image = out / "live.img"
        shutil.copyfile(prepared, image)
        with Loop(image, mount) as m:
            path = m / "file.txt"
            got = os.getxattr(path, "system.ntfs_security")
            assert got == open_sd, got
            as_user(1002, 1002, lambda: path.read_bytes())
            # Deny reading to uid 1002; the change must apply immediately.
            deny = meta.descriptor(meta.OWNER, meta.GROUP, [
                meta.ace(1, meta.OTHER, 0x1), meta.ace(0, meta.EVERYONE_SID, 0x1F01FF)])
            os.setxattr(path, "system.ntfs_security", deny)
            assert os.getxattr(path, "system.ntfs_security") == deny
            as_user(1002, 1002, lambda: denied(lambda: path.read_bytes(), (errno.EACCES,)))
            # Swapping a descriptor must preserve a separately held file handle.
            fd = os.open(path, os.O_RDONLY)
            try:
                os.setxattr(path, 'system.ntfs_security', open_sd)
                assert os.read(fd, 6) == b'secret'
            finally:
                os.close(fd)
            # 1002 lacks WRITE_DAC once Everyone is read-only; the owner keeps it.
            readonly = meta.descriptor(meta.OWNER, meta.GROUP, [meta.ace(0, meta.EVERYONE_SID, 0x120089)])
            os.setxattr(path, "system.ntfs_security", readonly)
            as_user(1002, 1002, lambda: denied(
                lambda: os.setxattr(path, "system.ntfs_security", open_sd), (errno.EACCES,)))
            as_user(1000, 1000, lambda: os.setxattr(path, "system.ntfs_security", open_sd))
            # SACL changes need a privilege no mapped token holds.
            sacl = meta.descriptor(meta.OWNER, meta.GROUP, [meta.ace(0, meta.EVERYONE_SID, 0x1F01FF)],
                                   sacl_aces=[meta.ace(2, meta.EVERYONE_SID, 0x10000, 0xC0)])
            denied(lambda: os.setxattr(path, "system.ntfs_security", sacl), (errno.EPERM,))
            denied(lambda: os.removexattr(path, "system.ntfs_security"), (errno.EOPNOTSUPP,))
            # chown: group change through the explicit map; stat follows.
            os.chown(path, -1, 1002)
            assert os.stat(path).st_gid == 1002
            as_user(1000, 1000, lambda: denied(lambda: os.chown(path, 1002, -1), (errno.EPERM,)))
            denied(lambda: os.chmod(path, 0o777), (errno.EOPNOTSUPP,))
            # Renames: cross-directory, splitting names, directory move, drain.
            for i in range(0, 300, 3):
                os.rename(m / "a" / f"entry-{i:03d}", m / "b" / (f"moved-{i:03d}-" + "q" * 150))
            os.rename(m / "a" / "dir", m / "b" / "dir-moved")
            for name in os.listdir(m / "a"):
                os.rename(m / "a" / name, m / "b" / name)
            assert os.listdir(m / "a") == []
            assert len(os.listdir(m / "b")) == 301
            denied(lambda: os.rename(m / "b" / "entry-001", m / "b" / "ENTRY-002"), (errno.EEXIST,))
            os.sync()
        assert meta.names(image, "/a") == []
        assert len(meta.names(image, "/b")) == 301
        recovered = out / "live-recovered.img"
        meta.replay(image, recovered)
        meta.audit(recovered, allow_dirty=True)
        print("PASS live ACL, chown and B-tree rename", flush=True)

        # Interruption at every durable flush of one descriptor change and
        # one rename; recovery yields exactly the old or the new state.
        fresh = meta.descriptor(meta.OWNER, meta.GROUP, [
            meta.ace(0, meta.EVERYONE_SID, 0x1F01FF), meta.ace(0, meta.sid(5, 21, 4, 4, 4), 0x120089)])
        for kind in ("xattr", "rename"):
            seen_new = False
            for phase in range(1, 40):
                image = out / f"{kind}-{phase:02}.img"
                shutil.copyfile(prepared, image)
                with Loop(image, mount) as m:
                    PARAMETER.write_text(str(phase))
                    try:
                        if kind == "xattr":
                            os.setxattr(m / "file.txt", "system.ntfs_security", fresh)
                        else:
                            os.rename(m / "a" / "entry-150", m / "b" / ("r" * 200))
                        completed = True
                    except OSError as error:
                        assert error.errno == errno.EIO, error
                        completed = False
                    finally:
                        PARAMETER.write_text("0")
                recovered = out / f"{kind}-{phase:02}-recovered.img"
                meta.replay(image, recovered)
                meta.audit(recovered, allow_dirty=True)
                if kind == "xattr":
                    new = meta.raw_descriptor(recovered, "/file.txt", out) == fresh
                else:
                    new = "r" * 200 in meta.names(recovered, "/b")
                    assert new != ("entry-150" in meta.names(recovered, "/a"))
                assert not (seen_new and not new), (kind, phase)
                seen_new |= new
                image.unlink()
                recovered.unlink()
                if completed:
                    print(f"PASS {kind} interruption matrix: {phase - 1} boundaries", flush=True)
                    break
    finally:
        PARAMETER.write_text("0")
        if os.path.ismount(mount):
            subprocess.run(["umount", str(mount)])
        run("rmmod", "slate_ntfs")
    print("Live native ACL, chown, rename and interruption cases passed.")


if __name__ == "__main__":
    main()
