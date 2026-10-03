#!/usr/bin/env python3
"""
Module: src.tests.checker.test_consistency
Purpose: Corrupt disposable native-format images; assert diagnostic and no writes.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Corrupt disposable native-format images; assert diagnostic and no writes.
"""
import pathlib
import shutil
import tempfile
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tests/support"))
from ntfs_image import ROOT, CHECKER, run, u, put, attr, attrs, decode, protect, first_extent, digest


def damage(path, kind):
    with path.open('r+b') as f:
        boot=f.read(512); cluster=u(boot,11,2)*boot[13]
        size=1 << -int.from_bytes(boot[64:65],'little',signed=True)
        mft=u(boot,48,8)*cluster
        def get(n):
            f.seek(mft+n*size); return decode(f.read(size))
        def save(n,b):
            f.seek(mft+n*size); f.write(protect(b))
        def bit(at, number, set_bit):
            f.seek(at+number//8); b=f.read(1)[0]
            b=(b | (1 << (number%8))) if set_bit else (b & ~(1 << (number%8)))
            f.seek(at+number//8); f.write(bytes([b]))
        if kind in ('cluster-marked-free','unreferenced-clusters'):
            b=get(6); lcn,_=first_extent(b,attr(b,0x80))
            bit(lcn*cluster, u(boot,48,8) if kind=='cluster-marked-free' else 8000,
                kind=='unreferenced-clusters')
        elif kind=='mft-bitmap-free':
            b=get(0); lcn,_=first_extent(b,attr(b,0xb0)); bit(lcn*cluster,24,False)
        elif kind=='cross-linked-clusters':
            source=get(0); source_lcn,length=first_extent(source,attr(source,0x80))
            b=get(4); a=attr(b,0x80); at=a+u(b,a+32,2); tag=b[at]
            n,m=tag&15,tag>>4
            b[at+1+n:at+1+n+m]=source_lcn.to_bytes(m,'little',signed=True)
            save(4,b)
        elif kind in ('invalid-parent-reference','missing-directory-link','unreachable-record'):
            n=24 if kind=='unreachable-record' else 4
            b=get(n); a=attr(b,0x30); at=a+u(b,a+20,2)
            if kind=='invalid-parent-reference': b[at+6] ^= 1
            else: b[at+66] ^= 1
            save(n,b)
        elif kind=='stale-index-reference':
            root=get(5)
            a=next(a for a,k in attrs(root) if k==0xa0)
            lcn,_=first_extent(root,a); f.seek(lcn*cluster)
            b=decode(f.read(4096)); at=24+u(b,24,4); b[at+6]^=1
            f.seek(lcn*cluster); f.write(protect(b))
        elif kind=='security-invalid':
            b=get(9); a=next(a for a,k in attrs(b) if k==0x80)
            lcn,_=first_extent(b,a)
            # Descriptor primary intact, mirror hash/data disagree.
            f.seek(lcn*cluster+0x40000+24); f.write(b'\xff')
        elif kind=='mft-invalid':
            f.seek(mft+24*size+510); f.write(bytes(2))
        elif kind=='mft-mirror-mismatch':
            f.seek(u(boot,56,8)*cluster+510); f.write(bytes(2))
        elif kind=='boot-mirror-mismatch':
            f.seek(u(boot,40,8)*u(boot,11,2)+72); f.write(bytes(8))
        elif kind=='runlist-invalid':
            b=get(4); a=attr(b,0x80); b[a+u(b,a+32,2)]=0x99; save(4,b)
        else: raise AssertionError(kind)


def main():
    cases=['cluster-marked-free','unreferenced-clusters','mft-bitmap-free',
           'cross-linked-clusters','invalid-parent-reference','missing-directory-link',
           'stale-index-reference','security-invalid','mft-invalid',
           'mft-mirror-mismatch','boot-mirror-mismatch','runlist-invalid','unreachable-record']
    with tempfile.TemporaryDirectory(prefix='slate-consistency-') as tmp:
        d=pathlib.Path(tmp); base=d/'base.img'
        with base.open('wb') as f: f.truncate(64*1024*1024)
        run(ROOT/'ntfs_utils/target/release/ntfs-format','--yes','--quick',base)
        original=digest(base)
        for mode in ('--audit','--check'):
            p=run(CHECKER,mode,base)
            assert b'audit_complete=1' in p.stdout and digest(base)==original
        for case in cases:
            image=d/(case+'.img'); shutil.copyfile(base,image); damage(image,case)
            original=digest(image)
            p=run(CHECKER,'--audit',image,ok=False)
            assert p.returncode==4 and ('finding='+case).encode() in p.stdout, (case,p.stdout,p.stderr)
            assert digest(image)==original
        # Another formatter is a separate baseline, with inline metadata ACLs.
        other=d/'mkntfs.img'
        with other.open('wb') as f: f.truncate(64*1024*1024)
        run('mkfs.ntfs','-F','-Q',other)
        p=run(CHECKER,'--audit',other)
        assert b'audit_complete=1' in p.stdout
        legacy=d/'legacy.img'; shutil.copyfile(base,legacy)
        with legacy.open('r+b') as f:
            boot=f.read(512); cluster=u(boot,11,2)*boot[13]; mft=u(boot,48,8)*cluster
            f.seek(mft+9*1024); secure=decode(f.read(1024))
            a=next(a for a,k in attrs(secure) if k==0x80); lcn,_=first_extent(secure,a)
            f.seek(lcn*cluster); entry=f.read(512); sd=entry[20:u(entry,16,4)]
            for n in (24,25):
                f.seek(mft+n*1024); b=decode(f.read(1024))
                a=attr(b,0x10); put(b,a+u(b,a+20,2)+52,0,4)
                insert=next(a for a,k in attrs(b) if k>0x50)
                value=bytearray(sd)
                if n==25: put(value,2,0,2)  # invalid second descriptor
                extra=bytearray((24+len(value)+7)&~7)
                put(extra,0,0x50,4); put(extra,4,len(extra),4)
                put(extra,14,u(b,40,2),2); put(b,40,u(b,40,2)+1,2)
                put(extra,16,len(value),4); put(extra,20,24,2); extra[24:24+len(value)]=value
                used=u(b,24,4); assert used+len(extra)<len(b)
                b[insert+len(extra):used+len(extra)]=b[insert:used]
                b[insert:insert+len(extra)]=extra; put(b,24,used+len(extra),4)
                f.seek(mft+n*1024); f.write(protect(b))
        original=digest(legacy); p=run(CHECKER,'--audit',legacy,ok=False)
        assert b'finding=security-invalid record=25 ' in p.stdout and digest(legacy)==original
        assert b'finding=security-invalid record=24 ' not in p.stdout
        unresolved=d/'unresolved-system-security.img'; shutil.copyfile(base,unresolved)
        with unresolved.open('r+b') as f:
            f.seek(mft); b=decode(f.read(1024)); a=attr(b,0x10)
            put(b,a+u(b,a+20,2)+52,0,4)
            for at in (mft,u(boot,56,8)*cluster):
                f.seek(at); f.write(protect(b))
        original=digest(unresolved); p=run(CHECKER,'--audit',unresolved,ok=False)
        assert b'audit_complete=0' in p.stdout and b'finding=unsupported record=0 ' in p.stdout
        assert b'finding=security-invalid record=0 ' not in p.stdout and digest(unresolved)==original
    print(f'Consistency audit: 2 formatter baselines, default check, {len(cases)} corruption classes, legacy ACL cache and unsupported-security regressions, source preservation passed.')

if __name__=='__main__': main()
