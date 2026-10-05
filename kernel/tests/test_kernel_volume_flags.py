#!/usr/bin/env python3
"""
Module: kernel.tests.test_kernel_volume_flags
Purpose: Journaled mount/unmount flags and interrupted MFT mirror publication.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Journaled mount/unmount flags and interrupted MFT mirror publication.
"""
import hashlib
import os
from pathlib import Path
import shutil
import sys
from test_kernel_writes import ROOT, MAPPING, run
from ntfs_image import u, decode

def copies(path):
    with path.open('rb') as f:
        boot=f.read(512); cluster=u(boot,11,2)*boot[13]
        offsets=[u(boot,n,8)*cluster+3072 for n in (48,56)]
        records=[]
        for at in offsets:
            f.seek(at);records.append(f.read(1024))
    return offsets,records

def main():
    assert os.geteuid()==0
    out=Path(sys.argv[1]).resolve();out.mkdir(parents=True,exist_ok=False)
    source=out/'source.img'
    with source.open('xb') as f:f.truncate(64*1024*1024)
    run('mkntfs','-F','-Q',source)
    original=hashlib.sha256(source.read_bytes()).digest()
    mount=out/'mount';mount.mkdir();loop=None;mounted=False
    knob=Path('/sys/module/slate_ntfs/parameters/fail_after_flush')
    run('insmod',ROOT/'kernel/slate-ntfs.ko')
    try:
        for action,total in [('initialize',13),('finish',11)]:
            for phase in range(1,total+1):
                image=out/f'{action}-{phase}.img';shutil.copyfile(source,image)
                loop=run('losetup','--find','--show',image).stdout.decode().strip()
                knob.write_text(str(phase if action=='initialize' else 0))
                run('mount','-w','-t','ntfsrs','-o',f'rw,sidmap={MAPPING}',loop,mount,ok=action!='initialize')
                if action=='finish':
                    mounted=True;knob.write_text(str(phase))
                    run('umount',mount);mounted=False
                knob.write_text('0')
                run('losetup','-d',loop);loop=None
                raw=copies(image)[1]
                assert raw[0]==raw[1],(action,phase,'mirror mismatch at flush')
                if action=='initialize' and phase==1:
                    assert raw==copies(source)[1] # no restart yet, no filesystem mutation
                else:
                    recovered=out/f'{action}-{phase}-recovered.img'
                    run(ROOT/'target/release/ntfs-chkdsk','--replay-to',image,recovered)
                    assert copies(recovered)[1][0]==copies(recovered)[1][1]
                    expected = int(phase >= 7) if action=='initialize' else int(phase < 5)
                    assert run(ROOT/'target/release/ntfs-chkdsk','--status',recovered).stdout.strip()==f'dirty={expected}'.encode(),(action,phase)
                    again=out/'again.img';run(ROOT/'target/release/ntfs-chkdsk','--replay-to',recovered,again)
                    assert hashlib.sha256(again.read_bytes()).digest()==hashlib.sha256(recovered.read_bytes()).digest()
                    again.unlink();recovered.unlink()
                if not (action=='initialize' and phase in (9,10)):image.unlink()
                print('PASS journaled volume flag',action,phase,flush=True)
        # Simulate power loss between the primary and mirror writes themselves,
        # with a durable commit but no published completion checkpoint.
        before=out/'initialize-9.img';after=out/'initialize-10.img'
        offsets,new=copies(after)
        for which in (0,1):
            image=out/f'one-copy-{which}.img';shutil.copyfile(before,image)
            with image.open('r+b') as f:f.seek(offsets[which]);f.write(new[which])
            recovered=out/f'one-copy-{which}-recovered.img'
            run(ROOT/'target/release/ntfs-chkdsk','--replay-to',image,recovered)
            assert copies(recovered)[1][0]==copies(recovered)[1][1]
            assert run(ROOT/'target/release/ntfs-chkdsk','--status',recovered).stdout.strip()==b'dirty=1'
            ro=out/'ntfs3g';ro.mkdir(exist_ok=True)
            run('ntfs-3g','-o','ro',recovered,ro)
            run('umount',ro)
            print('PASS recovery of primary-only/mirror-only flag publication',which,flush=True)
        assert hashlib.sha256(source.read_bytes()).digest()==original
    finally:
        knob.write_text('0')
        if mounted:run('umount',mount)
        if loop:run('losetup','-d',loop)
        run('rmmod','slate_ntfs')

if __name__=='__main__':main()
