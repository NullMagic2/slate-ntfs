#!/usr/bin/env python3
"""
Module: kernel.tests.test_security_privileges
Purpose: Explicit privilege grants; default root still has no native bypass.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Explicit privilege grants; default root still has no native bypass.
"""
import errno
import os
from pathlib import Path
import sys
from test_kernel_acl import ROOT, denied, meta

def main():
    out = Path(sys.argv[1]).resolve(); out.mkdir(parents=True, exist_ok=False)
    image = out / 'source.img'; meta.mkimage(image, 64)
    mount = out / 'mount'; mount.mkdir()
    with meta.Mounted(image, mount) as m: (m / 'file').write_bytes(b'unchanged')
    base = meta.descriptor(meta.OWNER, meta.GROUP, [meta.ace(0, meta.EVERYONE_SID, 0x1f01ff)])
    prepared = out / 'prepared.img'
    meta.lab(image, prepared, ('set-security', '/file', base.hex(), '1000', '1000', meta.MAP))
    sacl = meta.descriptor(meta.OWNER, meta.GROUP, [meta.ace(0, meta.EVERYONE_SID, 0x1f01ff)],
                           [meta.ace(2, meta.EVERYONE_SID, 0x10000, 0xc0)])
    loop = None; mounted = False
    meta.run('insmod', ROOT / 'kernel/slate-ntfs.ko')
    try:
        loop = meta.run('losetup', '--find', '--show', prepared).stdout.decode().strip()
        for privileged in [False, True]:
            mapping = meta.MAP.replace('u:0:' + meta.ADMIN, 'u:0:' + meta.ADMIN + ':security+restore+take-ownership') if privileged else meta.MAP
            meta.run('mount', '-t', 'ntfsrs', '-o', 'rw,sidmap=' + mapping, loop, mount); mounted = True
            p = mount / 'file'
            if not privileged:
                denied(lambda: os.setxattr(p, 'system.ntfs_security', sacl), (errno.EPERM,))
                denied(lambda: os.chown(p, 1002, -1), (errno.EPERM,))
            else:
                os.setxattr(p, 'system.ntfs_security', sacl)
                # Auditing/MIC evaluation remains refused; privilege permits
                # removing the SACL without pretending its policy was enforced.
                denied(lambda: p.read_bytes(), (errno.EOPNOTSUPP,))
                os.setxattr(p, 'system.ntfs_security', base)
                assert os.getxattr(p, 'system.ntfs_security') == base
                os.chown(p, 1002, -1)
                assert p.stat().st_uid == 1002
                assert p.read_bytes() == b'unchanged'
            meta.run('umount', mount); mounted = False
        assert meta.content(prepared, '/file') == b'unchanged'
        print('PASS default root refusal, explicit SACL grant, removal and restore ownership', flush=True)
    finally:
        if mounted: meta.run('umount', mount)
        if loop: meta.run('losetup', '-d', loop)
        meta.run('rmmod', 'slate_ntfs')

if __name__ == '__main__': main()
