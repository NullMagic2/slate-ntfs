#!/usr/bin/env python3
"""
Module: kernel.tests.test_kernel_namespace
Purpose: Journaled VFS rename and interrupted multi-page index transactions.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Journaled VFS rename and interrupted multi-page index transactions.
"""
import hashlib
import os
from pathlib import Path
import shutil
import sys
from test_kernel_writes import ROOT, MAPPING, run, fixture, denied
import errno

def main():
    assert os.geteuid()==0
    out=Path(sys.argv[1]).resolve();out.mkdir(parents=True,exist_ok=False)
    source=out/'source.img'
    with source.open('xb') as f:f.truncate(64*1024*1024)
    run('mkfs.ntfs','-F','-Q',source)
    payload=out/'payload';payload.write_bytes(b'namespace content')
    run('ntfscp','-f',source,payload,'/original.bin')
    fixture.CASES={'original.bin':fixture.descriptor([fixture.ace(0,fixture.EVERYONE,0x1f01ff)])}
    args=sys.argv;sys.argv=['fixture',str(source)];fixture.main();sys.argv=args
    original=hashlib.sha256(source.read_bytes()).hexdigest()
    mount=out/'mount';mount.mkdir();loop=None;mounted=False
    parameter=Path('/sys/module/ntfs_rs/parameters/fail_after_flush')
    run('insmod',ROOT/'kernel/ntfs_rs.ko')
    try:
        for phase in range(12):
            image=out/f'phase-{phase}.img';shutil.copyfile(source,image)
            loop=run('losetup','--find','--show',image).stdout.decode().strip()
            run('mount','-w','-t','ntfsrs','-o',f'rw,compatibility=ntfs,sidmap={MAPPING}',loop,mount);mounted=True
            old=mount/'original.bin';new=mount/'renamed-long.bin'
            if phase:
                parameter.write_text(str(phase))
                denied(lambda:os.rename(old,new),(errno.EIO,))
                parameter.write_text('0')
            else:
                os.rename(old,new);assert new.read_bytes()==b'namespace content' and not old.exists()
                assert 'renamed-long.bin' in os.listdir(mount)
            run('umount',mount);mounted=False;run('losetup','-d',loop);loop=None
            if phase:
                recovered=out/f'recovered-{phase}.img'
                run(ROOT/'target/release/ntfs-chkdsk','--replay-to',image,recovered)
                again=out/f'again-{phase}.img';run(ROOT/'target/release/ntfs-chkdsk','--replay-to',recovered,again)
                assert hashlib.sha256(recovered.read_bytes()).digest()==hashlib.sha256(again.read_bytes()).digest()
            else:recovered=image
            expected='original.bin' if 0<phase<4 else 'renamed-long.bin'
            assert run('ntfscat','-f',recovered,'/'+expected).stdout==b'namespace content',phase
            names=run('ntfsls','-f',recovered).stdout.decode().splitlines()
            assert expected in names and ('renamed-long.bin' if expected=='original.bin' else 'original.bin') not in names,(phase,names)
            print('PASS namespace transaction',phase,expected,flush=True)
        assert hashlib.sha256(source.read_bytes()).hexdigest()==original
    finally:
        parameter.write_text('0')
        if mounted:run('umount',mount)
        if loop:run('losetup','-d',loop)
        run('rmmod','ntfs_rs')

if __name__=='__main__':main()
