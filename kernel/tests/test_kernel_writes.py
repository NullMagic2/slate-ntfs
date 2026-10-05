#!/usr/bin/env python3
"""
Module: kernel.tests.test_kernel_writes
Purpose: Actual VFS writes on disposable loops, DACL checks and durable failure cases.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Actual VFS writes on disposable loops, DACL checks and durable failure cases.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil

import permission_fixture as fixture
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests/support"))
from ntfs_image import run

ROOT = Path(__file__).resolve().parents[2]
MAPPING = 'u:0:S-1-5-32-544;g:0:S-1-5-18;u:1002:S-1-5-1002;g:65534:S-1-5-65534'

def denied(call, codes):
    try: call()
    except OSError as error:
        assert error.errno in codes, error
    else: raise AssertionError('unsupported/denied operation succeeded')

def main():
    assert os.geteuid() == 0
    out = Path(sys.argv[1]).resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = out/'source.img'
    with source.open('xb') as stream: stream.truncate(64*1024*1024)
    run('mkfs.ntfs', '-F', '-Q', source)
    (out/'payload').write_bytes(b'AAAA')
    run('ntfscp', '-f', source, out/'payload', '/write.bin')
    fixture.CASES = {'write.bin': fixture.descriptor([
        fixture.ace(1, fixture.sid(5,1002), 2), fixture.ace(0,fixture.EVERYONE,0x1f01ff)])}
    old_args = sys.argv
    sys.argv = ['permission_fixture', str(source)]
    fixture.main()
    sys.argv = old_args
    original = hashlib.sha256(source.read_bytes()).hexdigest()
    mount = out/'mount'; mount.mkdir()
    run('insmod', ROOT/'kernel/slate-ntfs.ko')
    results = []
    loop = None; mounted = False
    parameter = Path('/sys/module/slate_ntfs/parameters/fail_after_flush')
    try:
        # Refusals must happen before any disk mutation or writable mount.
        for gate in ('hibernated', 'dirty'):
            image = out/f'gate-{gate}.img'
            shutil.copyfile(source, image)
            if gate == 'hibernated':
                run('ntfscp', '-f', image, out/'payload', '/HiBeRfIl.SyS')
            if gate == 'dirty':
                data = bytearray(image.read_bytes())
                cluster = fixture.u(data,11,2)*data[13]
                mft = fixture.u(data,48,8)*cluster
                mirror = fixture.u(data,56,8)*cluster
                raw = fixture.decode(data[mft+3072:mft+4096])
                attr = fixture.attr(raw,0x70)
                flags = attr+fixture.u(raw,attr+20,2)+10
                fixture.put(raw,flags,1,2)
                raw = fixture.protect(raw)
                data[mft+3072:mft+4096] = raw
                data[mirror+3072:mirror+4096] = raw
                image.write_bytes(data)
            before = hashlib.sha256(image.read_bytes()).hexdigest()
            loop = run('losetup', '--find', '--show', image).stdout.decode().strip()
            options = f'rw,sidmap={MAPPING}'
            # -w disables mount(8)'s automatic read-only retry on EROFS.
            run('mount','-w','-t','ntfsrs','-o',options,loop,mount,ok=False)
            run('losetup','-d',loop); loop = None
            assert hashlib.sha256(image.read_bytes()).hexdigest() == before, gate
        # 0: 130 successive syscalls, including circular reuse. 1..10:
        # crash after every write-session flush in the first transaction.
        for phase in range(11):
            image = out/f'phase{phase:02}.img'
            shutil.copyfile(source, image)
            loop = run('losetup', '--find', '--show', image).stdout.decode().strip()
            run('mount', '-t', 'ntfsrs', '-o', f'rw,experimental_rw,sidmap={MAPPING}', loop, mount)
            mounted = True
            path = mount/'write.bin'
            assert path.read_bytes() == b'AAAA'
            if phase == 0:
                # Reading is allowed, but FILE_WRITE_DATA deny must win even
                # with a later Everyone allow ACE.
                child = os.fork()
                if child == 0:
                    try:
                        os.setgroups([]); os.setgid(65534); os.setuid(1002)
                        assert path.read_bytes() == b'AAAA'
                        denied(lambda: os.open(path, os.O_WRONLY), (errno.EACCES,))
                        os._exit(0)
                    except BaseException: os._exit(1)
                assert os.waitpid(child, 0)[1] == 0
            fd = os.open(path, os.O_RDWR)
            try:
                if phase:
                    parameter.write_text(str(phase))
                    denied(lambda: os.pwrite(fd, b'111', 1), (errno.EIO,))
                    parameter.write_text('0')
                    denied(lambda: os.fsync(fd), (errno.EIO,))
                    denied(lambda: os.pwrite(fd, b'222', 1), (errno.EIO,))
                else:
                    for number in range(130):
                        data = b'111' if number % 2 == 0 else b'222'
                        assert os.pwrite(fd, data, 1) == 3
                        assert os.pread(fd, 4, 0) == b'A'+data
                        assert path.read_bytes() == b'A'+data
                    os.fsync(fd)
                    assert os.pwrite(fd,b'X',4) == 1
                    assert path.read_bytes() == b'A222X'
                    os.ftruncate(fd,4)
                    denied(lambda: os.chmod(path,0o777), (errno.EOPNOTSUPP,))
                    assert path.read_bytes() == b'A222'
            finally: os.close(fd)
            run('umount', mount); mounted = False
            run('losetup', '-d', loop); loop = None
            recovered = image
            if phase:
                recovered = out/f'recovered{phase:02}.img'
                run(ROOT/'target/release/ntfs-chkdsk', '--replay-to', image, recovered)
            else:
                assert run(ROOT/'target/release/ntfs-chkdsk','--status',image).stdout.strip()==b'dirty=0'
            expected = b'A222' if phase == 0 else (b'AAAA' if phase < 4 else b'A111')
            assert run('ntfscat','-f',recovered,'/write.bin').stdout == expected
            results.append(dict(phase=phase, expected=expected.decode(), passed=True))
            print(results[-1], flush=True)
        assert hashlib.sha256(source.read_bytes()).hexdigest() == original
        (out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    finally:
        parameter.write_text('0')
        if mounted or os.path.ismount(mount): run('umount', mount)
        if loop: run('losetup', '-d', loop)
        run('rmmod', 'slate_ntfs')
    print('Live kernel writes, log wrap, page-cache coherence, native DACL and 10 durable interruption cases passed.')

if __name__ == '__main__': main()
