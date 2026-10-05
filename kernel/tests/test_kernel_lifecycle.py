#!/usr/bin/env python3
"""
Module: kernel.tests.test_kernel_lifecycle
Purpose: Create/write/rename/unlink through VFS on private disposable NTFS images.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Create/write/rename/unlink through VFS on private disposable NTFS images.
"""
import errno
import os
from pathlib import Path
import sys
from test_kernel_writes import ROOT,MAPPING,run,denied

def main():
    assert os.geteuid()==0
    out=Path(sys.argv[1]).resolve();out.mkdir(parents=True,exist_ok=False)
    image=out/'lifecycle.img'
    with image.open('xb') as f:f.truncate(64*1024*1024)
    run('mkfs.ntfs','-F','-Q',image)
    payload=out/'payload';payload.write_bytes(b'keep')
    fresh='--fresh' in sys.argv
    if not fresh:run('ntfscp','-f',image,payload,'/keep.bin')
    mount=out/'mount';mount.mkdir();loop=None;mounted=False
    resident='--resident' in sys.argv
    if resident:
        run('ntfs-3g',image,mount)
        try:(mount/'small').mkdir()
        finally:run('umount',mount)
    run('insmod',ROOT/'kernel/slate-ntfs.ko')
    try:
        loop=run('losetup','--find','--show',image).stdout.decode().strip()
        run('mount','-w','-t','ntfsrs','-o',f'rw,sidmap={MAPPING}',loop,mount);mounted=True
        directory=mount/'small' if resident else mount
        if fresh:
            (directory/'keep.bin').write_bytes(b'keep')
            print('PASS first file creation grows a freshly formatted MFT',flush=True)
        for i in range(4):
            path=directory/f'new-{i}.bin'
            fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o640)
            try:
                content=bytes([65+i])*9000
                assert os.write(fd,content)==len(content);os.fsync(fd)
                assert os.pread(fd,len(content),0)==content
            finally:os.close(fd)
            renamed=directory/f'new-{i}.dat';os.rename(path,renamed)
            assert renamed.read_bytes()==content
            renamed.unlink();assert not renamed.exists()
            print('PASS create, allocate, rename, delete and MFT-slot reuse',i,flush=True)
        old=directory/'identity.bin';old.write_bytes(b'old identity')
        handle=os.open(old,os.O_PATH)
        try:
            slot=os.fstat(handle).st_ino
            old.unlink()
            old.write_bytes(b'new identity')
            assert old.stat().st_ino!=slot
            assert os.fstat(handle).st_nlink==0
            assert old.read_bytes()==b'new identity'
            old.unlink()
        finally:os.close(handle)
        print('PASS orphan retains its MFT slot while an O_PATH inode is held',flush=True)
        assert (directory/'keep.bin').read_bytes()==b'keep'
        (directory/'retained.bin').write_bytes(b'created through VFS')
        run('umount',mount);mounted=False;run('losetup','-d',loop);loop=None
        assert run(ROOT/'target/release/ntfs-chkdsk','--status',image).stdout.strip()==b'dirty=0'
        prefix='/small' if resident else ''
        assert run('ntfscat','-f',image,prefix+'/retained.bin').stdout==b'created through VFS'
        names=run('ntfsls','-f','-p',prefix or '/',image).stdout.decode().splitlines()
        assert set(names)-{'.','..'}=={'keep.bin','retained.bin'},names
        print('PASS independent namespace/data readback and clean unmount',flush=True)
    finally:
        if mounted:run('umount',mount)
        if loop:run('losetup','-d',loop)
        run('rmmod','slate_ntfs')

if __name__=='__main__':main()
