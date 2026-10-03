#!/usr/bin/env python3
"""
Module: src.tests.recovery.test_advanced_replay
Purpose: Independent LFS 1.1/2.0 histories on disposable NTFS images.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Independent LFS 1.1/2.0 histories on disposable NTFS images.
"""
import os
import pathlib
import shutil
import struct
import tempfile
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tests/support"))
from ntfs_image import ROOT,CHECKER,run,u,put,attr,attrs,decode,protect,first_extent,operation,record,page,restart,digest

def geometry(path):
    with path.open('rb') as f:
        boot=f.read(512); cluster=u(boot,11,2)*boot[13]; size=1<<-int.from_bytes(boot[64:65],'little',signed=True)
        mft=u(boot,48,8)*cluster
        def get(n):
            f.seek(mft + n * size)
            return decode(f.read(size))
        zero=get(0); log=get(2); a=attr(log,0x80); log_lcn,_=first_extent(log,a)
        files={}
        for n in range(16,u(zero,attr(zero,0x80)+56,8)//size):
            b=get(n)
            if not u(b,22,2)&1: continue
            for a,k in attrs(b):
                if k==0x30:
                    at=a+u(b,a+20,2); name=bytes(b[at+66:at+66+b[at+64]*2]).decode('utf-16le'); files[name]=(n,b)
        return dict(boot=boot,cluster=cluster,size=size,mft=mft,zero=zero,log=log_lcn*cluster,log_size=u(log,attr(log,0x80)+48,8),files=files)

def op(code, **kw):
    undo_code=kw.pop('undo_code',code)
    b=operation(code,**kw);put(b,2,undo_code,2);return b

def opened(g, reference=None, kind=0x80, index_size=0):
    b=bytearray(40);put(b,0,0xffffffff,4);put(b,4,index_size,4);put(b,8,kind,4)
    put(b,16,reference if reference is not None else u(g['zero'],16,2)<<48,8);return b

def location(g,number):
    logical=number*g['size']
    return dict(target=24,vcn=logical//g['cluster'],cluster_off=(logical%g['cluster'])//512,lcn=(g['mft']+logical)//g['cluster'])

def resident(g,old,new):
    number,b=g['files']['winner.bin'];a=attr(b,0x80)
    return op(7,redo=new,undo=old,record_off=a,attr_off=u(b,a+20,2),**location(g,number))

def write_log(path,g,specs,version=1,tail=False,group=False,checkpoint=None,tables=False):
    """spec=(payload,tid,previous-index,undo-index,record-type); -1 means zero."""
    size=g['log_size']; bits=size.bit_length()-3; start=(4 if version==1 else 34)*4096
    positions=[]; at=start
    for payload,*_ in specs:
        positions.append(at); total=48+len(payload)
        at+=4096*max(1,(total+4031)//4032)
    lsns=[(1<<bits)|((at+64)//8) for at in positions]
    data=bytearray(b'\xff'*size)
    for i,(payload,tid,prev,undo,kind) in enumerate(specs):
        payload=bytearray(payload)
        if kind==2: put(payload,8,lsns[0],8)
        if tables and kind==2:
            for field,index in ((16,0),(24,1),(32,3),(40,4)):
                put(payload,field,lsns[index],8)
                table_payload=specs[index][0]
                put(payload,48+(field-16)//2,u(table_payload,6,2),4)
        if tables and i in (3,4):
            start=u(payload,4,2)+24
            if i==3: put(payload,start+24,lsns[2],8)
            else:
                for off in (8,16,24):put(payload,start+off,lsns[2],8)
        if kind==1 and u(payload,0,2)==28: put(payload,u(payload,4,2)+24,lsns[i],8)
        raw=record(lsns[i],payload,tid,0 if prev<0 else lsns[prev],kind)
        put(raw,16,0 if undo<0 else lsns[undo],8)
        chunks=(len(raw)+4031)//4032
        if chunks>1: put(raw,40,1,2)
        for j in range(chunks):
            pos=positions[i]+j*4096; part=raw[j*4032:(j+1)*4032]
            b=bytearray(4096);b[:4]=b'RCRD';struct.pack_into('<HHQ',b,4,40,9,lsns[i])
            last=j==chunks-1
            struct.pack_into('<IHHH',b,16,(1 if last else 0)|(2 if chunks>1 else 0),chunks,j+1,(64+len(part)+7)&~7 if last else 64)
            put(b,32,lsns[i] if last else 0,8);put(b,60,pos,4);b[64:64+len(part)]=part
            data[pos:pos+4096]=protect(b)
    if group:
        assert all(48+len(s[0])<=4032 for s in specs)
        for j,pos in enumerate(positions):
            b=decode(data[pos:pos+4096]);put(b,20,len(specs),2);put(b,22,j+1,2);put(b,16,3,4);data[pos:pos+4096]=protect(b)
    cp=0 if checkpoint is None else checkpoint
    rp=decode(restart(size,lsns[0],lsns[-1],len(specs[-1][0])))
    put(rp,26,1 if version==1 else 0,2);put(rp,28,version,2);put(rp,48+64+8,lsns[cp],8)
    data[:4096]=protect(rp);data[4096:8192]=protect(rp)
    if tail:
        pos=positions[-1];b=decode(data[pos:pos+4096])
        if version==1: put(b,8,pos,8)
        data[2*4096:3*4096]=protect(b);data[pos:pos+4096]=b'\xff'*4096
    with path.open('r+b') as f:
        f.seek(g['log']);f.write(data)
        f.seek(g['mft']+3*g['size']);b=decode(f.read(g['size']));a=attr(b,0x70);put(b,a+u(b,a+20,2)+10,1,2)
        for at in (g['mft']+3*g['size'],u(g['boot'],56,8)*g['cluster']+3*g['size']):f.seek(at);f.write(protect(b))
    return lsns,positions

def checkpoint():
    b=bytearray(64);put(b,0,1,4);return b

def run_case(d,base,name,specs,expected,**kwargs):
    source=d/(name+'.img');shutil.copyfile(base,source);g=geometry(source)
    write_log(source,g,specs(g),**kwargs);original=digest(source)
    out=d/(name+'-out.img');r=run(CHECKER,'--replay-to',source,out)
    assert run('ntfscat','-f',out,'/winner.bin').stdout==expected,(name,r.stdout)
    assert digest(source)==original
    count=int(next(line.split(b'=')[1] for line in r.stdout.splitlines() if line.startswith(b'durable_boundaries=')))
    for stop in range(1,count+1):
        crash=d/(name+f'-crash{stop}.img');resumed=d/(name+f'-resumed{stop}.img')
        run(CHECKER,'--replay-to',source,crash,ok=False,env=dict(os.environ,SLATE_NTFS_TEST_STOP_AFTER_FLUSH=str(stop)))
        run(CHECKER,'--replay-to',crash,resumed)
        assert run('ntfscat','-f',resumed,'/winner.bin').stdout==expected,(name,stop)
        crash.unlink();resumed.unlink()
    again=d/(name+'-again.img');run(CHECKER,'--replay-to',out,again);assert digest(out)==digest(again)
    print('PASS',name,count,'durable boundaries',flush=True)

def main():
    with tempfile.TemporaryDirectory(prefix='slate-advanced-replay-') as tmp:
        d=pathlib.Path(tmp);base=d/'base.img'
        with base.open('wb') as f:f.truncate(64*1024*1024)
        run('mkfs.ntfs','-F','-Q',base);p=d/'winner';p.write_bytes(b'AAAA');run('ntfscp','-f',base,p,'/winner.bin')
        def specs(g,commit=True,reuse=False):
            seq=[(checkpoint(),0,-1,-1,2),(op(28,target=24,redo=opened(g),undo_code=0),24,-1,-1,1),(resident(g,b'AAAA',b'BBBB'),24,1,1,1)]
            if reuse:
                seq += [(op(26,undo_code=0),24,2,2,1),(op(27,undo_code=0),24,3,0,1),(resident(g,b'BBBB',b'CCCC'),24,-1,-1,1)]
            else:seq += [(resident(g,b'BBBB',b'CCCC'),24,2,2,1)]
            if commit:seq.append((op(26,undo_code=0),24,len(seq)-1,len(seq)-1,1))
            return seq
        for version in (1,2):
            for commit in (True,False):
                run_case(d,base,f'repeated-v{version}-{commit}',lambda g:specs(g,commit),b'CCCC' if commit else b'AAAA',version=version)
            run_case(d,base,f'tail-v{version}',specs,b'CCCC',version=version,tail=True)
            run_case(d,base,f'group-v{version}',specs,b'CCCC',version=version,group=True)
        # Forget ends an epoch; the same numeric transaction ID starts anew.
        # Its undo-next must be zero, not a checkpoint record.
        def reused(g):
            seq=specs(g,False,True);payload,tid,prev,_,kind=seq[4];seq[4]=(payload,tid,prev,-1,kind);return seq
        run_case(d,base,'transaction-reuse',reused,b'BBBB')
        def interleaved(g,commit):
            number,b=g['files']['winner.bin'];a=attr(b,0x80)
            def change(offset,new):
                return op(7,redo=new,undo=b'A',record_off=a,attr_off=u(b,a+20,2)+offset,**location(g,number))
            seq=[(checkpoint(),0,-1,-1,2),(op(28,target=24,redo=opened(g),undo_code=0),24,-1,-1,1),
                 (change(0,b'B'),24,1,1,1),(change(3,b'C'),64,-1,-1,1),
                 (change(1,b'D'),24,2,2,1),(change(2,b'E'),64,3,3,1)]
            if commit:seq.append((op(26,undo_code=0),24,4,4,1))
            return seq
        for commit in (False,True):
            run_case(d,base,f'interleaved-{commit}',lambda g:interleaved(g,commit),b'BDAA' if commit else b'AAAA',version=2)
        def invalidated(g, reused=False):
            loc=location(g,g['files']['winner.bin'][0])
            seq=[(checkpoint(),0,-1,-1,2),(op(28,target=24,redo=opened(g),undo_code=0),24,-1,-1,1),
                 (resident(g,b'AAAA',b'BBBB'),24,1,1,1),
                 (op(10,redo=struct.pack('<QQ',loc['lcn'],1),undo_code=0),24,2,2,1)]
            if reused:seq.append((resident(g,b'AAAA',b'CCCC'),24,3,3,1))
            seq.append((op(26,undo_code=0),24,len(seq)-1,len(seq)-1,1))
            return seq
        run_case(d,base,'delete-dirty-cluster',invalidated,b'AAAA')
        run_case(d,base,'delete-and-reuse-cluster',lambda g:invalidated(g,True),b'CCCC')
        def hotfix(g):
            loc=location(g,g['files']['winner.bin'][0])
            change=resident(g,b'AAAA',b'BBBB');put(change,32,loc['lcn']+1,8)
            return [(checkpoint(),0,-1,-1,2),(op(28,target=24,redo=opened(g),undo_code=0),24,-1,-1,1),
                    (change,24,1,1,1),(op(23,undo_code=0,**loc),24,2,2,1),(op(26,undo_code=0),24,3,3,1)]
        run_case(d,base,'hotfix-redirects-old-lcn',hotfix,b'BBBB')
        def top_level(g):
            # Completed nested action survives rollback of its outer transaction.
            return [(checkpoint(),0,-1,-1,2),(op(28,target=24,redo=opened(g),undo_code=0),24,-1,-1,1),
                    (resident(g,b'AAAA',b'BBBB'),24,1,1,1),
                    (op(24,undo_code=1),24,2,1,1),
                    (resident(g,b'BBBB',b'CCCC'),24,3,1,1)]
        run_case(d,base,'completed-top-level-action',top_level,b'BBBB')
        def nonempty(g):
            def table(size,entries,slots=None):
                b=bytearray(24+size*(slots or len(entries)));put(b,0,size,2);put(b,2,slots or len(entries),2);put(b,4,len(entries),2)
                for i,e in enumerate(entries):b[24+i*size:24+i*size+len(e)]=e
                if slots and slots > len(entries):
                    put(b,16,24+len(entries)*size,4);put(b,20,24+(slots-1)*size,4)
                    for i in range(len(entries),slots):put(b,24+i*size,24+(i+1)*size if i+1<slots else 0,4)
                return b
            o=opened(g);root=opened(g,(5<<48)|5,0xa0,4096)
            names=struct.pack('<HH',64,8)+'$I30'.encode('utf-16le')+b'\0\0'+bytes(4)
            dp=bytearray(40);put(dp,0,0xffffffff,4);put(dp,4,24,4);put(dp,8,1024,4);put(dp,12,1,4)
            loc=location(g,g['files']['winner.bin'][0]);put(dp,16,loc['vcn'],8);put(dp,32,loc['lcn'],8)
            tx=bytearray(40);put(tx,0,0xffffffff,4);tx[4]=1
            return [(op(29,redo=table(40,[o,root],128),undo_code=0),0,-1,-1,1),
                    (op(30,redo=names,undo_code=0),0,-1,-1,1),
                    (resident(g,b'AAAA',b'CCCC'),24,-1,-1,1),
                    (op(31,redo=table(40,[dp]),undo_code=0),0,-1,-1,1),
                    (op(32,redo=table(40,[tx]),undo_code=0),0,-1,-1,1),
                    (checkpoint(),0,-1,-1,2),(op(26,undo_code=0),24,2,2,1)]
        for version in (1,2):
            run_case(d,base,f'checkpoint-spanning-v{version}',nonempty,b'CCCC',version=version,checkpoint=5,tables=True)
    print('Advanced replay fixture suite passed.',flush=True)

if __name__=='__main__':main()
