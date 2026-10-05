#!/usr/bin/env python3
"""
Module: kernel.tests.test_kernel_lifecycle_crashes
Purpose: Creation/MFT growth and deletion recovery at every durable boundary.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Creation/MFT growth and deletion recovery at every durable boundary.
"""
import errno
import hashlib
import os
from pathlib import Path
import shutil
import sys
from test_kernel_writes import ROOT,MAPPING,run,denied

def main():
    assert os.geteuid()==0
    out=Path(sys.argv[1]).resolve();out.mkdir(parents=True,exist_ok=False)
    mount=out/'mount';mount.mkdir();loop=None;mounted=False
    parameter=Path('/sys/module/slate_ntfs/parameters/fail_after_flush')
    run('insmod',ROOT/'kernel/slate-ntfs.ko')
    try:
        for operation in ['create', 'delete']:
            stops = 64
            states = set()
            source=out/f'{operation}-source.img'
            with source.open('xb') as f:f.truncate(64*1024*1024)
            run('mkfs.ntfs','-F','-Q',source)
            if operation=='delete':
                # Prepare through VFS so this also exercises the descriptor and
                # clean-journal layout produced by our creation path.
                loop=run('losetup','--find','--show',source).stdout.decode().strip()
                run('mount','-w','-t','ntfsrs','-o',f'rw,sidmap={MAPPING}',loop,mount);mounted=True
                (mount/'file.bin').write_bytes(b'D'*9000)
                run('umount',mount);mounted=False;run('losetup','-d',loop);loop=None
            original=hashlib.sha256(source.read_bytes()).digest()
            for phase in range(stops+1):
                image=out/f'{operation}-{phase}.img';shutil.copyfile(source,image)
                loop=run('losetup','--find','--show',image).stdout.decode().strip()
                run('mount','-w','-t','ntfsrs','-o',f'rw,sidmap={MAPPING}',loop,mount);mounted=True
                def act():
                    if operation=='create':
                        fd=os.open(mount/'file.bin',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o640);os.close(fd)
                    else:(mount/'file.bin').unlink()
                    # Namespace mutations are queued; fsync is the durable boundary.
                    fd=os.open(mount,os.O_RDONLY|os.O_DIRECTORY)
                    try:os.fsync(fd)
                    finally:os.close(fd)
                parameter.write_text(str(phase))
                failed = False
                try: act()
                except OSError as error:
                    assert phase and error.errno == errno.EIO, (operation, phase, error)
                    failed = True
                parameter.write_text('0')
                run('umount',mount);mounted=False;run('losetup','-d',loop);loop=None
                if failed:
                    recovered=out/f'{operation}-{phase}-recovered.img'
                    run(ROOT/'target/release/ntfs-chkdsk','--replay-to',image,recovered)
                    again=out/f'{operation}-{phase}-again.img'
                    run(ROOT/'target/release/ntfs-chkdsk','--replay-to',recovered,again)
                    assert hashlib.sha256(recovered.read_bytes()).digest()==hashlib.sha256(again.read_bytes()).digest()
                else:recovered=image
                names=run('ntfsls','-f',recovered).stdout.decode().splitlines()
                assert set(names) <= {'file.bin'}, (operation, phase, names)
                present = 'file.bin' in names
                committed = present if operation == 'create' else not present
                if not failed: assert committed, (operation, phase, names)
                if failed: states.add(committed)
                if present:assert run('ntfscat','-f',recovered,'/file.bin').stdout==(b'' if operation=='create' else b'D'*9000)
                # Replay deliberately retains the dirty flag; exit 4 is expected
                # for that flag, but structural findings are never accepted.
                audit=run(ROOT/'target/release/ntfs-chkdsk','--audit',recovered,ok=not failed)
                assert audit.returncode==(4 if failed else 0),(operation,phase,audit)
                assert b'audit_complete=1' in audit.stdout and b'omitted_findings=0' in audit.stdout and b'finding=' not in audit.stdout,(operation,phase,audit.stdout)
                print('PASS lifecycle recovery',operation,phase,'committed' if committed else 'aborted',flush=True)
                if phase and not failed:
                    # A packed one-page commit has no earlier flush. Loss and
                    # torn-write outcomes are covered by the real Writer matrix.
                    assert True in states, (operation, states)
                    print('PASS all', phase - 1, operation, 'durability boundaries', flush=True)
                    break
            else: raise AssertionError(('increase boundary bound', operation))
            assert hashlib.sha256(source.read_bytes()).digest()==original
    finally:
        parameter.write_text('0')
        if mounted:run('umount',mount)
        if loop:run('losetup','-d',loop)
        run('rmmod','slate_ntfs')

if __name__=='__main__':main()
