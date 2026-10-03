#!/usr/bin/env python3
"""
Module: ntfs_utils.tests.test_security_store
Purpose: Actual NTFS descriptor resolution and corruption refusal through C/Python.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Actual NTFS descriptor resolution and corruption refusal through C/Python.

Optional SLATE_TEST_WINDOWS_NTFS_IMAGE is an offline partition image copied
read-only into temporary storage, for Windows-created external index cases.
"""
import ctypes
import os
import pathlib
import shutil
import sys
import tempfile
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests/support"))
from ntfs_image import ROOT, attrs, attr, decode, digest, first_extent, protect, run, u, put

sys.path.insert(0, str(ROOT/'ntfs_utils/python'))
import ntfs_utils


def named(record, kind, name):
    for off, candidate in attrs(record):
        start = off + u(record, off+10, 2)
        if candidate == kind and record[start:start+2*record[off+9]].decode('utf-16le') == name:
            return off
    raise AssertionError((kind, name))


def exercise(source, directory, external=False):
    before = digest(source)
    data = bytearray(source.read_bytes())
    cluster = u(data,11,2)*data[13]
    mft = u(data,48,8)*cluster
    record_size = (1 << -int.from_bytes(data[64:65], 'little', signed=True))
    secure_at = mft+9*record_size
    secure = decode(data[secure_at:secure_at+record_size])
    a = named(secure,0x80,'$SDS')
    lcn, _ = first_extent(secure,a)
    sds = lcn*cluster
    # mkfs and the Windows fixture both keep descriptor ID 0x101 at 0x80.
    assert u(data,sds+0x80+4,4) == 0x101
    size = u(data,sds+0x80+16,4)
    expected = bytes(data[sds+0x80+20:sds+0x80+size])
    reference = (u(secure,16,2)<<48)|9
    assert ntfs_utils.get_security_descriptor(source,reference) == expected
    assert ntfs_utils.get_device(source).security_descriptor(reference) == expected
    try: ntfs_utils.get_security_descriptor(source,reference^(1<<48))
    except ntfs_utils.NtfsError: pass
    else: raise AssertionError('stale sequence accepted')

    # Verify the actual C buffer-size contract and no partial output on error.
    library = ntfs_utils._library()
    required = ctypes.c_size_t()
    error = ctypes.create_string_buffer(256)
    function = library.ntfs_utils_security_descriptor
    assert function(os.fsencode(source),reference,None,0,ctypes.byref(required),error,256) == 0
    assert required.value == len(expected)
    small = (ctypes.c_uint8*8)(*([0xa5]*8))
    assert function(os.fsencode(source),reference,small,8,ctypes.byref(required),error,256) == 1
    assert bytes(small) == b'\xa5'*8 and required.value == len(expected)

    def reject(label, changed):
        target = directory/(label+'.img')
        target.write_bytes(changed)
        try: ntfs_utils.get_security_descriptor(target,reference)
        except ntfs_utils.NtfsError: pass
        else: raise AssertionError(label+' accepted')

    for label, offset in [('bad-primary-hash',sds+0x80+40),
                          ('bad-mirror',sds+0x40000+0x80+40)]:
        changed=data.copy(); changed[offset]^=1; reject(label,changed)
    if external:
        a=named(secure,0xa0,'$SII'); lcn,_=first_extent(secure,a)
        changed=data.copy(); changed[lcn*cluster+510]^=1; reject('torn-index',changed)
        rec=secure.copy(); a=named(rec,0xb0,'$SII')
        assert not rec[a+8]
        rec[a+u(rec,a+20,2)]=0
        changed=data.copy(); changed[secure_at:secure_at+record_size]=protect(rec)
        reject('unallocated-index',changed)
    else:
        # In resident SII, corrupt an entry after the requested match. The
        # complete node must be checked even when lookup finds an early key.
        rec=secure.copy(); a=named(rec,0x90,'$SII'); root=a+u(rec,a+20,2)
        first=root+16+u(rec,root+16,4); second=first+u(rec,first+8,2)
        put(rec,second+16,u(rec,first+16,4),4)
        put(rec,second+u(rec,second,2)+4,u(rec,first+16,4),4)
        changed=data.copy(); changed[secure_at:secure_at+record_size]=protect(rec)
        reject('duplicate-security-id',changed)
        rec=secure.copy(); a=named(rec,0x90,'$SDH'); root=a+u(rec,a+20,2)
        entry=root+16+u(rec,root+16,4)
        # First SDH key is 0x101; alter its copied SDS offset only.
        header=entry+u(rec,entry,2); put(rec,header+8,0x90,8)
        changed=data.copy(); changed[secure_at:secure_at+record_size]=protect(rec)
        reject('disagreeing-indices',changed)
    assert digest(source)==before


def main():
    with tempfile.TemporaryDirectory(prefix='slate-security-') as tmp:
        directory=pathlib.Path(tmp)
        source=directory/'source.img'
        with source.open('wb') as f: f.truncate(64*1024*1024)
        run('mkfs.ntfs','-F','-Q',source)
        exercise(source,directory)
        # Root has a legacy nonresident descriptor; ntfscp produces a resident one.
        root=ntfs_utils.get_security_descriptor(source,(5<<48)|5)
        assert len(root)==4140 and root[0]==1
        payload=directory/'payload'; payload.write_bytes(b'AAAA')
        run('ntfscp','-f',source,payload,'/inline.bin')
        inline=ntfs_utils.get_security_descriptor(source,(1<<48)|64)
        assert inline[0]==1 and len(inline)==80
        windows=os.environ.get('SLATE_TEST_WINDOWS_NTFS_IMAGE')
        if windows:
            copied=directory/'windows.img'; shutil.copyfile(windows,copied)
            exercise(copied,directory,external=True)
    print('Security store: shared and legacy descriptors, SII/SDH agreement, SDS hash/mirror, stale references, corruption refusal, C buffer contract and Python API passed.'
          + (' Windows external-index cases passed.' if windows else ' Windows external-index cases not requested.'))


if __name__=='__main__': main()
