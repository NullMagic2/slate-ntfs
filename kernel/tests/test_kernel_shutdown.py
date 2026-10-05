#!/usr/bin/env python3
"""
Module: kernel.tests.test_kernel_shutdown
Purpose: Superblock lifecycle: clean ro-remount plus full-sync shutdown ioctl.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Superblock lifecycle: clean ro-remount plus full-sync shutdown ioctl.
"""
import errno
import fcntl
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from run_wsl_fresh_benchmark import mounted, run

ROOT = Path(__file__).resolve().parents[2]
SHUTDOWN_IOCTL = 0x8004587D  # _IOR('X', 125, __u32)
assert os.geteuid() == 0


def fresh_image(path: Path) -> None:
    with path.open('xb') as stream:
        stream.truncate(32 << 20)
    run('mkntfs', '-F', '-Q', '-c', '4096', str(path), capture_output=True)


def audit(path: Path) -> str:
    result = subprocess.run(
        [str(ROOT / 'target/release/ntfs-chkdsk'), '--audit', str(path)],
        capture_output=True, text=True,
    )
    assert result.returncode in (0, 4), result.stdout + result.stderr
    assert 'errors=0' in result.stdout, result.stdout
    return result.stdout


run('insmod', str(ROOT / 'kernel/slate-ntfs.ko'))
try:
    with tempfile.TemporaryDirectory(prefix='slate-shutdown-', dir='/var/tmp') as raw:
        base = Path(raw)

        # rw -> ro reconfigure is a clean writer shutdown, not merely a sync.
        clean_image, clean_mount = base / 'remount.img', base / 'remount'
        clean_mount.mkdir()
        fresh_image(clean_image)
        loop = mounted(clean_mount, clean_image, 'slate')
        try:
            path = clean_mount / 'saved'
            path.write_bytes(b'durable before read-only remount')
            os.utime(path, ns=(1_700_000_000_123_456_700, 1_700_000_001_987_654_300))
            fd = os.open(path, os.O_RDONLY)
            try:
                os.fsync(fd)  # exercises inode timestamp writeback before remount
            finally:
                os.close(fd)
            run('mount', '-o', 'remount,ro', str(clean_mount))
            try:
                os.open(clean_mount / 'denied', os.O_CREAT | os.O_WRONLY, 0o600)
            except OSError as error:
                assert error.errno == errno.EROFS, error
            else:
                raise AssertionError('read-only remount still allowed writes')
            # A clean read-only remount can initialize a fresh writer session.
            run('mount', '-o', 'remount,rw', str(clean_mount))
            (clean_mount / 'after-remount').write_bytes(b'new writer session')
            run('mount', '-o', 'remount,ro', str(clean_mount))
            assert (clean_mount / 'after-remount').read_bytes() == b'new writer session'
        finally:
            run('umount', str(clean_mount))
            run('losetup', '-d', loop)
        clean = audit(clean_image)
        assert 'dirty=0' in clean, clean
        assert run('ntfscat', '-f', str(clean_image), '/saved', capture_output=True).stdout == \
            b'durable before read-only remount'
        print('PASS rw->ro remount: write_inode/sync/finish persisted metadata and clean state')

        # The filesystem-level shutdown ioctl works from a directory fd too;
        # unlike a clean ro-remount it intentionally leaves the NTFS dirty flag.
        image, mount = base / 'shutdown.img', base / 'shutdown'
        mount.mkdir()
        fresh_image(image)
        loop = mounted(mount, image, 'slate')
        try:
            path = mount / 'saved'
            path.write_bytes(b'durable before shutdown')
            fd = os.open(mount, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for flags, expected in ((1, errno.EOPNOTSUPP), (3, errno.EINVAL)):
                    try:
                        fcntl.ioctl(fd, SHUTDOWN_IOCTL, struct.pack('I', flags))
                    except OSError as error:
                        assert error.errno == expected, error
                    else:
                        raise AssertionError('unsupported shutdown flag accepted')
                fcntl.ioctl(fd, SHUTDOWN_IOCTL, struct.pack('I', 0))
            finally:
                os.close(fd)
            target = os.open(path, os.O_RDWR)
            try:
                for action in (
                    lambda: os.pwrite(target, b'bad', 0),
                    lambda: os.fsync(target),
                ):
                    try:
                        action()
                    except OSError as error:
                        assert error.errno == errno.EIO, error
                    else:
                        raise AssertionError('shutdown allowed a write or successful fsync')
            finally:
                os.close(target)
            # Even a poisoned session can be made VFS-read-only; it must not be
            # advertised as a clean NTFS shutdown, however.
            run('mount', '-o', 'remount,ro', str(mount))
        finally:
            run('umount', str(mount))
            run('losetup', '-d', loop)
        content = run('ntfscat', '-f', str(image), '/saved', capture_output=True).stdout
        assert content == b'durable before shutdown', content
        dirty = audit(image)
        assert 'dirty=1' in dirty, dirty
        print('PASS full-sync shutdown: data retained; later writes fail; dirty marker retained')
        print(dirty)
finally:
    run('rmmod', 'slate_ntfs')
