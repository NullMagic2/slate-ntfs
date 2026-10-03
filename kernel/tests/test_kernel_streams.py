#!/usr/bin/env python3
"""
Module: kernel.tests.test_kernel_streams
Purpose: Selective live allocation/growth/truncation tests; disposable images only.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Selective live allocation/growth/truncation tests; disposable images only.
"""
import hashlib
import os
from pathlib import Path
import shutil
import sys
from test_kernel_writes import ROOT, MAPPING, run, fixture

def main():
    assert os.geteuid() == 0
    out = Path(sys.argv[1]).resolve(); out.mkdir(parents=True, exist_ok=False)
    source = out / 'source.img'
    with source.open('xb') as f: f.truncate(64*1024*1024)
    run('mkfs.ntfs', '-F', '-Q', source)
    payload = out / 'payload'; payload.write_bytes(b'initial')
    run('ntfscp', '-f', source, payload, '/write.bin')
    fixture.CASES = {'write.bin': fixture.descriptor([fixture.ace(0, fixture.EVERYONE, 0x1f01ff)])}
    args = sys.argv; sys.argv = ['fixture', str(source)]; fixture.main(); sys.argv = args
    original = hashlib.sha256(source.read_bytes()).hexdigest()
    mount = out/'mount'; mount.mkdir()
    image = out/'live.img'; shutil.copyfile(source, image)
    loop = None; mounted = False; mapper = None
    run('insmod', ROOT/'kernel/ntfs_rs.ko')
    try:
        loop = run('losetup', '--find', '--show', image).stdout.decode().strip()
        mapper=f'slate-streams-{os.getpid()}'
        run('dmsetup','create',mapper,'--table',f'0 {image.stat().st_size//512} linear {loop} 0')
        run('mount','-w','-t','ntfsrs','-o',f'rw,sidmap={MAPPING}',f'/dev/mapper/{mapper}',mount)
        mounted = True; path = mount/'write.bin'
        fd = os.open(path, os.O_RDWR)
        expected = b'initial'
        try:
            def check(label):
                os.fsync(fd)
                assert os.fstat(fd).st_size == len(expected), label
                assert path.read_bytes() == expected, label
                print('PASS', label, len(expected), flush=True)
            # Resident growth, conversion, zero-filled hole, nonresident rewrite.
            assert os.pwrite(fd,b'-grown',7) == 6; expected += b'-grown'; check('resident growth')
            content = bytes(range(256))*32
            assert os.pwrite(fd,content,8192) == len(content)
            expected += bytes(8192-len(expected))+content; check('nonresident conversion and hole')
            assert os.pwrite(fd,b'cross-sector',4090) == 12
            expected = expected[:4090]+b'cross-sector'+expected[4102:]; check('nonresident overwrite')
            os.ftruncate(fd,10000); expected=expected[:10000]; check('nonresident shrink')
            os.ftruncate(fd,24000); expected+=bytes(24000-len(expected)); check('zero extension')
            os.ftruncate(fd,5); expected=expected[:5]; check('return to resident')
            os.ftruncate(fd,0); expected=b''; check('truncate zero')
            assert os.pwrite(fd,b'reused',0)==6; expected=b'reused'; check('reuse after truncate')
            append = os.open(path,os.O_WRONLY|os.O_APPEND)
            try: assert os.write(append,b'-append')==7
            finally: os.close(append)
            expected+=b'-append';check('append')
        finally: os.close(fd)
        renamed=mount/'renamed-long.bin';os.rename(path,renamed)
        assert renamed.read_bytes()==expected and not path.exists()
        os.rename(renamed,path)
        assert path.read_bytes()==expected
        print('PASS journaled VFS rename and directory lookup',flush=True)
        run('umount',mount);mounted=False
        run('dmsetup','remove',mapper);mapper=None
        run('losetup','-d',loop);loop=None
        assert run('ntfscat','-f',image,'/write.bin').stdout==expected
        assert run(ROOT/'target/release/ntfs-chkdsk','--status',image).stdout.strip()==b'dirty=0'
        loop=run('losetup','--find','--show',image).stdout.decode().strip()
        run('mount','-w','-t','ntfsrs','-o',f'rw,sidmap={MAPPING}',loop,mount);mounted=True
        fd=os.open(mount/'write.bin',os.O_RDWR)
        try: assert os.pwrite(fd,b'R',0)==1;os.fsync(fd)
        finally:os.close(fd)
        expected=b'R'+expected[1:]
        run('umount',mount);mounted=False;run('losetup','-d',loop);loop=None
        assert run(ROOT/'target/release/ntfs-chkdsk','--status',image).stdout.strip()==b'dirty=0'
        assert run('ntfscat','-f',image,'/write.bin').stdout==expected
        assert hashlib.sha256(source.read_bytes()).hexdigest()==original
        print('PASS ordinary rw mount, clean unmount, initialized-journal reopen and NTFS-3G readback',flush=True)
        parameter=Path('/sys/module/ntfs_rs/parameters/fail_after_flush')
        # Conversion changes the file's MFT record and one bitmap sector.
        # Include data staging and each intent/commit/metadata/checkpoint flush.
        for phase in range(1,13):
            image=out/f'crash-{phase}.img';shutil.copyfile(source,image)
            loop=run('losetup','--find','--show',image).stdout.decode().strip()
            run('mount','-w','-t','ntfsrs','-o',f'rw,experimental_rw,sidmap={MAPPING}',loop,mount);mounted=True
            fd=os.open(mount/'write.bin',os.O_RDWR)
            try:
                parameter.write_text(str(phase))
                try: os.pwrite(fd,b'new-data',8192)
                except OSError as error: assert error.errno==5,error
                else: raise AssertionError(('missing interruption',phase))
                parameter.write_text('0')
                try:os.fsync(fd)
                except OSError as error:assert error.errno==5,error
                else:raise AssertionError(('missing latched I/O error',phase))
            finally:os.close(fd);parameter.write_text('0')
            run('umount',mount);mounted=False;run('losetup','-d',loop);loop=None
            recovered=out/f'crash-{phase}-recovered.img'
            run(ROOT/'target/release/ntfs-chkdsk','--replay-to',image,recovered)
            expected=b'initial' if phase<5 else b'initial'+bytes(8192-7)+b'new-data'
            assert run('ntfscat','-f',recovered,'/write.bin').stdout==expected,phase
            again=out/f'crash-{phase}-again.img'
            run(ROOT/'target/release/ntfs-chkdsk','--replay-to',recovered,again)
            assert hashlib.sha256(recovered.read_bytes()).digest()==hashlib.sha256(again.read_bytes()).digest()
            print('PASS allocation transaction interruption',phase,flush=True)
    finally:
        Path('/sys/module/ntfs_rs/parameters/fail_after_flush').write_text('0')
        if mounted: run('umount',mount)
        if mapper: run('dmsetup','remove',mapper)
        if loop: run('losetup','-d',loop)
        run('rmmod','ntfs_rs')

if __name__=='__main__': main()
