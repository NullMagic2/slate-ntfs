#!/usr/bin/env python3
"""
Module: kernel.tests.test_linux_compatibility
Purpose: Linux/native policies on throwaway loops; no tests are run by a build.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Linux/native policies on throwaway loops; no tests are run by a build.
"""
import ctypes
import errno
import fcntl
import mmap
import os
from pathlib import Path
import stat
import sys
from test_kernel_writes import ROOT, MAPPING, run, denied
sys.path.insert(0, str(ROOT / 'ntfs_utils/python'))
import ntfs_utils

def main():
    out = Path(sys.argv[1]).resolve(); out.mkdir(parents=True, exist_ok=False)
    mount = out / 'mount'; mount.mkdir()
    other = out / 'other'; other.mkdir()
    image = out / 'source.img'
    with image.open('xb') as f: f.truncate(96 * 1024 * 1024)
    run('mkntfs', '-F', '-Q', '-q', image)
    loop = None; mounted = False; other_mounted = False
    run('insmod', ROOT / 'kernel/slate-ntfs.ko')
    try:
        loop = run('losetup', '--find', '--show', image).stdout.decode().strip()
        def attach(mode):
            run(ROOT / 'ntfs_utils/target/release/ntfs-mount', loop, mount,
                '--sidmap=' + MAPPING, '--compatibility=' + mode)
        attach('linux'); mounted = True
        space = os.statvfs(mount)
        assert space.f_blocks > 0 and 0 < space.f_bavail < space.f_blocks
        odd = ['Case', 'case', 'c:', 'ends.', 'space ', 'back\\slash', 'wild*card?']
        for name in odd: (mount / name).write_bytes(name.encode())
        assert not (mount / 'CASE').exists()
        for name in odd: assert (mount / name).read_bytes() == name.encode()
        p = mount / 'mode'; p.write_bytes(b'hello mapping')
        executable = mount / 'executable'; executable.write_bytes(Path('/bin/true').read_bytes())
        os.chmod(executable, 0o755); run(executable)
        executable.unlink()
        before = os.getxattr(p, 'system.ntfs_security')
        os.chmod(p, 0o751)
        assert stat.S_IMODE(p.stat().st_mode) == 0o751
        assert os.getxattr(p, 'system.ntfs_security') == before
        alias = mount / 'hard-link'
        os.link(p, alias)
        assert p.stat().st_ino == alias.stat().st_ino and p.stat().st_nlink == 2
        with p.open('rb') as held:
            alias.unlink()
            assert p.stat().st_nlink == 1 and held.read() == b'hello mapping'
        with p.open('r+b') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m: assert m[:] == b'hello mapping'
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_COPY) as m:
                m[0:1] = b'H'; assert m[:] == b'Hello mapping'
            assert p.read_bytes() == b'hello mapping'
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with p.open('rb') as second:
                denied(lambda: fcntl.flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB), (errno.EAGAIN, errno.EACCES))
        print('PASS Linux filenames, exact case, mode preservation, private mmap and flock', flush=True)
        libc = ctypes.CDLL(None, use_errno=True)
        notify = libc.inotify_init1(os.O_NONBLOCK); assert notify >= 0
        try:
            assert libc.inotify_add_watch(notify, os.fsencode(mount), 0x100 | 0x200 | 0x40 | 0x80) >= 0
            n = mount / 'notify'; n.touch(); n.rename(mount / 'notified'); (mount / 'notified').unlink()
            events = os.read(notify, 8192)
            assert b'notify\x00' in events and b'notified\x00' in events
        finally: os.close(notify)
        names = [f'entry-{i:04d}-' + 'q' * 90 for i in range(220)]
        for name in names: (mount / name).touch()
        assert set(names) <= set(os.listdir(mount))
        for name in names[::2] + names[1::2]: (mount / name).unlink()
        assert not (set(names) & set(os.listdir(mount)))
        print('PASS 220 creates/deletes through splitting trees and expanded MFT growth', flush=True)
        run('mount', '-t', 'ntfsrs', '-o', 'compatibility=ntfs,sidmap=' + MAPPING, loop, other)
        other_mounted = True
        assert (other / 'mode').read_bytes() == p.read_bytes()
        assert stat.S_IMODE((other / 'mode').stat().st_mode) == 0o555
        assert (other / 'mode').stat().st_ino == p.stat().st_ino
        run('umount', other); other_mounted = False
        for name in odd: (mount / name).unlink()
        directory_fd = os.open(mount, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
        run('umount', mount); mounted = False
        result = ntfs_utils.get_device(loop).mount_fs(mount, MAPPING, compatibility='linux')
        assert int(result.status) == 0, result
        mounted = True
        assert stat.S_IMODE(p.stat().st_mode) == 0o751
        assert os.getxattr(p, 'system.ntfs_security') == before
        run('umount', mount); mounted = False
        attach('ntfs'); mounted = True
        # A stored POSIX name stays exact-case even in native mode.
        assert p.read_bytes() == b'hello mapping'
        native = mount / 'Native'; native.write_bytes(b'native')
        assert (mount / 'NATIVE').read_bytes() == b'native'
        denied(lambda: os.chmod(p, 0o700), (errno.EOPNOTSUPP,))
        denied(lambda: (mount / 'c:').touch(), (errno.EOPNOTSUPP,))
        run('umount', mount); mounted = False
        assert run(ROOT / 'target/release/ntfs-chkdsk', '--status', image).stdout.strip() == b'dirty=0'
        assert run('ntfscat', '-f', image, '/mode').stdout == b'hello mapping'
        print('PASS persisted mode, native policy, simultaneous views and NTFS-3G readback', flush=True)
    finally:
        if other_mounted: run('umount', other)
        if mounted: run('umount', mount)
        if loop: run('losetup', '-d', loop)
        run('rmmod', 'slate_ntfs')

if __name__ == '__main__': main()
