#!/usr/bin/env python3
"""
Module: kernel.tests.test_kernel_preallocation
Purpose: Verify append-window reclamation on a new disposable WSL loop mount.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Verify append-window reclamation on a new disposable WSL loop mount.
"""
import ctypes
import os
from pathlib import Path
import sys
import tempfile

from run_wsl_fresh_benchmark import mounted
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tests/support'))
from ntfs_image import attr, decode, run, u

ROOT = Path(__file__).resolve().parents[2]


def sizes(image, number):
    with image.open('rb') as stream:
        boot = stream.read(512)
        cluster = u(boot, 11, 2) * boot[13]
        stream.seek(u(boot, 48, 8) * cluster)
        zero = decode(stream.read(1024))
        at = attr(zero, 0x80)
        cursor = at + u(zero, at + 32, 2)
        lcn = vcn = 0
        logical = number * 1024
        while zero[cursor]:
            tag = zero[cursor]
            n, m = tag & 15, tag >> 4
            count = u(zero, cursor + 1, n)
            lcn += int.from_bytes(zero[cursor + 1 + n:cursor + 1 + n + m], 'little', signed=True)
            if vcn <= logical // cluster < vcn + count:
                stream.seek((lcn + logical // cluster - vcn) * cluster + logical % cluster)
                record = decode(stream.read(1024))
                at = attr(record, 0x80)
                assert record[at + 8] == 1
                return u(record, at + 40, 8), u(record, at + 48, 8)
            vcn += count
            cursor += 1 + n + m
    raise AssertionError('file record outside MFT runs')


def main():
    assert os.geteuid() == 0
    assert b'ntfs_rs ' not in run('lsmod').stdout
    libc = ctypes.CDLL(None, use_errno=True)
    def checkpoint(fd):
        if libc.syncfs(fd):
            raise OSError(ctypes.get_errno(), 'syncfs')
    run('insmod', ROOT / 'kernel/ntfs_rs.ko')
    try:
        with tempfile.TemporaryDirectory(prefix='slate-window-trim-', dir='/var/tmp') as raw:
            base = Path(raw)
            image, mount = base / 'source.img', base / 'mount'
            mount.mkdir()
            with image.open('xb') as stream:
                stream.truncate(32 << 20)
            run('mkntfs', '-F', '-Q', '-c', '4096', image)
            loop = mounted(mount, image, 'slate')
            fds = []
            try:
                fd = os.open(mount / 'window.bin', os.O_CREAT | os.O_RDWR, 0o600)
                fds.append(fd)
                os.write(fd, b'W' * 4096)
                os.fsync(fd)
                checkpoint(fd)
                number = os.fstat(fd).st_ino
                assert sizes(image, number) == (65536, 4096), sizes(image, number)
                reader = os.open(mount / 'window.bin', os.O_RDONLY)
                fds.append(reader)
                os.close(fd)
                fds.remove(fd)
                checkpoint(reader)
                assert sizes(image, number) == (65536, 4096)
                assert os.read(reader, 4096) == b'W' * 4096
                os.close(reader)
                fds.remove(reader)
                directory = os.open(mount, os.O_RDONLY | os.O_DIRECTORY)
                fds.append(directory)
                checkpoint(directory)
                assert sizes(image, number) == (4096, 4096), sizes(image, number)
                os.close(directory)
                fds.remove(directory)
                print('PASS last-file close returned 15 unused clusters; data preserved')
            finally:
                for fd in fds:
                    os.close(fd)
                run('umount', mount)
                run('losetup', '-d', loop)
            audit = run(ROOT / 'target/release/ntfs-chkdsk', '--audit', image)
            print(audit.stdout.decode())
            assert b'errors=0' in audit.stdout
    finally:
        run('rmmod', 'ntfs_rs')


if __name__ == '__main__':
    main()
