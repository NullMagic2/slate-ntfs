#!/usr/bin/env python3
"""
Module: src.tests.checker.test_broader_consistency
Purpose: Focused read-only audit fixtures; no mounts and no tests in build paths.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Focused read-only audit fixtures; no mounts and no tests in build paths.
"""
from pathlib import Path
import shutil
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'tests/support'))
from ntfs_image import ROOT, CHECKER, run, u, put, attrs, attr, decode, protect, first_extent, digest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'writer'))
import test_metadata_writer as meta


class Image:
    def __init__(self, path):
        self.f = path.open('r+b')
        self.boot = self.f.read(512)
        self.cluster = u(self.boot, 11, 2) * self.boot[13]
        self.size = 1 << -int.from_bytes(self.boot[64:65], 'little', signed=True)
        self.mft = u(self.boot, 48, 8) * self.cluster
    def get(self, n):
        self.f.seek(self.mft + n*self.size)
        return decode(self.f.read(self.size))
    def save(self, n, b):
        self.f.seek(self.mft + n*self.size); self.f.write(protect(b))
        if n < 4:
            self.f.seek(u(self.boot, 56, 8)*self.cluster + n*self.size)
            self.f.write(protect(b))
    def bitmap(self, n):
        b = self.get(0); lcn, _ = first_extent(b, attr(b, 0xb0))
        at = lcn*self.cluster+n//8
        self.f.seek(at); value = self.f.read(1)[0]
        self.f.seek(at); self.f.write(bytes([value | (1 << (n%8))]))
    def close(self):
        self.f.close()


def resident(kind, value, ident):
    b = bytearray((24+len(value)+7)&~7)
    put(b, 0, kind, 4); put(b, 4, len(b), 4); put(b, 14, ident, 2)
    put(b, 16, len(value), 4); put(b, 20, 24, 2); b[24:24+len(value)] = value
    return b


def rewrite(b, attributes):
    at = u(b, 20, 2); b[at:] = bytes(len(b)-at)
    for a in sorted(attributes, key=lambda a: u(a, 0, 4)):
        assert at+len(a)+8 <= len(b)
        b[at:at+len(a)] = a; at += len(a)
    put(b, at, 0xffffffff, 4); put(b, 24, at+8, 4)
    return b


def listed(a, reference):
    name = a[u(a, 10, 2):u(a, 10, 2)+a[9]*2] if a[9] else b''
    b = bytearray((26+len(name)+7)&~7)
    put(b, 0, u(a, 0, 4), 4); put(b, 4, len(b), 2)
    b[6] = len(name)//2; b[7] = 26
    put(b, 8, u(a, 16, 8) if a[8] else 0, 8)
    put(b, 16, reference, 8); put(b, 24, u(a, 14, 2), 2)
    b[26:26+len(name)] = name
    return b


def add_list(image, case):
    b = image.get(24); base_ref = 24 | (u(b, 16, 2)<<48)
    values = [bytearray(b[a:a+u(b, a+4, 4)]) for a, _ in attrs(b)]
    moved = next(a for a in values if u(a, 0, 4) == 0x30)
    values.remove(moved)
    extension = image.get(27); put(extension, 16, 1, 2); put(extension, 22, 1, 2)
    put(extension, 32, base_ref, 8); put(extension, 18, 0, 2)
    put(extension, 40, u(moved, 14, 2)+1, 2)
    image.save(27, rewrite(extension, [moved])); image.bitmap(27)
    entries = [listed(a, base_ref) for a in values] + [listed(moved, 27 | (1<<48))]
    entries.sort(key=lambda e: u(e, 0, 4))
    moved_entry = next(e for e in entries if u(e, 0, 4) == 0x30)
    if case == 'stale': put(moved_entry, 16, 27 | (2<<48), 8)
    if case == 'mismatch': put(moved_entry, 24, 999, 2)
    if case == 'missing': entries.remove(moved_entry)
    if case == 'duplicate': entries.append(bytearray(entries[0]))
    if case == 'owner':
        e = image.get(27); put(e, 32, 25 | (1<<48), 8); image.save(27, e)
    list_id = u(b, 40, 2); put(b, 40, list_id+1, 2)
    if case != 'unlisted': values.append(resident(0x20, b''.join(entries), list_id))
    image.save(24, rewrite(b, values))


def swap_entries(b, at):
    first = u(b, at+8, 2); second = u(b, at+first+8, 2)
    assert not u(b, at+first+12, 2)&2
    a = bytes(b[at:at+first]); c = bytes(b[at+first:at+first+second])
    b[at:at+first+second] = c+a


def damage(image, case):
    if case.startswith('list-'):
        add_list(image, case[5:]); return
    if case in ('directory-order', 'directory-bitmap'):
        b = image.get(5)
        if case == 'directory-bitmap':
            a = next(a for a, k in attrs(b) if k == 0xb0)
            b[a+u(b, a+20, 2)] |= 2; image.save(5, b); return
        a = next(a for a, k in attrs(b) if k == 0xa0)
        lcn, _ = first_extent(b, a); image.f.seek(lcn*image.cluster)
        block = decode(image.f.read(4096)); swap_entries(block, 24+u(block,24,4))
        image.f.seek(lcn*image.cluster); image.f.write(protect(block)); return
    if case == 'unused-descriptor':
        for n in list(range(16))+[24,25,26]:
            b = image.get(n); a = attr(b, 0x10)
            put(b, a+u(b,a+20,2)+52, 257, 4); image.save(n,b)
        return
    b = image.get(9)
    if case == 'inline-conflict':
        a = next(a for a,k in attrs(b) if k==0x80)
        lcn,_ = first_extent(b,a); image.f.seek(lcn*image.cluster); sds=image.f.read(512)
        value=sds[20:u(sds,16,4)]
        b=image.get(24); values=[bytearray(b[a:a+u(b,a+4,4)]) for a,_ in attrs(b)]
        values.append(resident(0x50,value,u(b,40,2))); put(b,40,u(b,40,2)+1,2)
        image.save(24,rewrite(b,values)); return
    wanted = '$SII' if case=='security-order' else '$SDH'
    a=next(a for a,k in attrs(b) if k==0x90 and b[a+u(b,a+10,2):a+u(b,a+10,2)+b[a+9]*2]==wanted.encode('utf-16le'))
    root=a+u(b,a+20,2); at=root+16+u(b,root+16,4)
    if case=='security-order': swap_entries(b,at)
    elif case=='security-header': b[at+u(b,at,2)+8] ^= 16
    else: raise AssertionError(case)
    image.save(9,b)


def main():
    cases = {
        'list-valid': None,
        'list-stale': 'attribute-list-reference',
        'list-mismatch': 'attribute-list-entry-mismatch',
        'list-missing': 'unlisted-extension-record',
        'list-duplicate': 'attribute-list-duplicate',
        'list-owner': 'attribute-list-owner',
        'list-unlisted': 'unlisted-extension-record',
        'directory-order': 'directory-index-order',
        'directory-bitmap': 'directory-invalid',
        'security-order': 'security-invalid',
        'security-header': 'security-invalid',
        'inline-conflict': 'security-invalid',
        'unused-descriptor': None,
    }
    with tempfile.TemporaryDirectory(prefix='slate-broader-') as tmp:
        d=Path(tmp); base=d/'base.img'
        with base.open('xb') as f: f.truncate(64*1024*1024)
        run(ROOT/'ntfs_utils/target/release/ntfs-format','--yes','--quick',base)
        run(CHECKER,'--audit',base)
        for case, expected in cases.items():
            target=d/(case+'.img'); shutil.copyfile(base,target)
            image=Image(target)
            try: damage(image,case)
            finally: image.close()
            before=digest(target)
            result=run(CHECKER,'--audit',target,ok=expected is None)
            assert digest(target)==before, case
            if expected:
                assert result.returncode==4 and ('finding='+expected+' ').encode() in result.stdout, (case,result.stdout,result.stderr)
            else:
                assert b'audit_complete=1' in result.stdout, (case,result.stdout)
                if case=='unused-descriptor':
                    assert b'finding=unreferenced-security-descriptor record=9 severity=info' in result.stdout
                    run(CHECKER,'--check',target)
            print('PASS',case,flush=True)
        # Exercise both full security-tree walks after forced index splitting.
        tree=d/'security-tree.img'
        operations=[]
        for i in range(96):
            sd=meta.descriptor(meta.ADMIN_SID,meta.sid(5,18),[
                meta.ace(0,meta.ADMIN_SID,0x1f01ff),
                meta.ace(0,meta.sid(5,21,42,i),0x120089)])
            operations.append(('set-security','/$Extend/$Quota',sd.hex(),'0','0',meta.MAP))
        meta.lab(base,tree,*operations)
        before=digest(tree); result=run(CHECKER,'--audit',tree)
        assert b'audit_complete=1' in result.stdout and b'descriptors=98' in result.stdout, result.stdout
        assert digest(tree)==before
        image=Image(tree)
        try:
            b=image.get(9)
            allocations=[a for a,k in attrs(b) if k==0xa0]
            assert len(allocations)==2, 'both security indexes must have external nodes'
        finally: image.close()
        print('PASS split security trees, 98 descriptors and retained unused entries',flush=True)
        for name in ('$SII','$SDH'):
            target=d/(name[1:]+'-bad-leaf.img'); shutil.copyfile(tree,target)
            image=Image(target)
            try:
                b=image.get(9)
                a=next(a for a,k in attrs(b) if k==0xa0 and b[a+u(b,a+10,2):a+u(b,a+10,2)+b[a+9]*2]==name.encode('utf-16le'))
                # Only the first block is mutated; later runs may be fragmented.
                at=a+u(b,a+32,2); tag=b[at]; n,m=tag&15,tag>>4
                assert n and m and u(b,at+1,n)*image.cluster>=4096
                lcn=int.from_bytes(b[at+1+n:at+1+n+m],'little',signed=True)
                image.f.seek(lcn*image.cluster)
                block=decode(image.f.read(4096)); swap_entries(block,24+u(block,24,4))
                image.f.seek(lcn*image.cluster); image.f.write(protect(block))
            finally: image.close()
            before=digest(target); result=run(CHECKER,'--audit',target,ok=False)
            assert result.returncode==4 and b'finding=security-invalid ' in result.stdout
            assert digest(target)==before
            print('PASS external',name,'ordering corruption',flush=True)
    print('Broader consistency: 16 fixtures; all audit inputs byte-preserved.',flush=True)


if __name__=='__main__': main()
