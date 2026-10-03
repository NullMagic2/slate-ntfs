#!/usr/bin/env python3
"""
Module: kernel.tests.permission_fixture
Purpose: Encode independent DACL fixtures into a newly created disposable image.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Encode independent DACL fixtures into a newly created disposable image.
"""
import pathlib,struct,sys
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests/support"))
from ntfs_image import attrs,attr,decode,protect,u,put

def sid(authority,*subs):
    return bytes([1,len(subs)])+authority.to_bytes(6,'big')+b''.join(struct.pack('<I',s) for s in subs)
USER=sid(5,1001); GROUP=sid(5,2001); SECOND=sid(5,2002); EVERYONE=sid(1,0)
def ace(kind,principal,mask=0x81,flags=0):
    return struct.pack('<BBHI',kind,flags,8+len(principal),mask)+principal
def descriptor(entries):
    if entries is None:
        return struct.pack('<BBHIIII',1,0,0x8004,0,0,0,0)
    acl=struct.pack('<BBHHH',2,0,8+sum(map(len,entries)),len(entries),0)+b''.join(entries)
    return struct.pack('<BBHIIII',1,0,0x8004,20,20+len(USER),0,20+len(USER)+len(GROUP))+USER+GROUP+acl

CASES={
    'allow_user':descriptor([ace(0,USER,0xa1)]),
    'deny_user':descriptor([ace(1,USER,1),ace(0,EVERYONE)]),
    'primary_group':descriptor([ace(0,GROUP)]),
    'supp_group':descriptor([ace(0,SECOND)]),
    'deny_group':descriptor([ace(1,SECOND,1),ace(0,USER)]),
    'everyone':descriptor([ace(0,EVERYONE)]),
    'empty':descriptor([]),
    'null':descriptor(None),
    'inherit_only':descriptor([ace(0,USER,0x81,8)]),
    'unknown':descriptor([ace(0,EVERYONE),ace(9,USER)]),
    'no_attributes':descriptor([ace(0,USER,1)]),
    'blocked':descriptor([ace(0,EVERYONE)]), # list allowed; traverse denied
}

def main():
    path=pathlib.Path(sys.argv[1]); data=bytearray(path.read_bytes())
    cluster=u(data,11,2)*data[13]; start=u(data,48,8)*cluster
    record_size=1 << -int.from_bytes(data[64:65],'little',signed=True)
    zero=decode(data[start:start+record_size]); mftattr=attr(zero,0x80)
    size=u(zero,mftattr+48,8)
    # Resolve MFT runs independently; never assume newly allocated records are contiguous.
    cursor=mftattr+u(zero,mftattr+32,2); runs=[]; lcn=0; vcn=0
    while zero[cursor]:
        tag=zero[cursor]; n,m=tag&15,tag>>4
        count=u(zero,cursor+1,n); assert m
        lcn+=int.from_bytes(zero[cursor+1+n:cursor+1+n+m],'little',signed=True)
        runs.append((vcn,vcn+count,lcn)); vcn+=count;cursor+=1+n+m
    changed=set()
    for number in range(size//record_size):
        logical=number*record_size; vcn=logical//cluster
        begin,end,lcn=next(r for r in runs if r[0]<=vcn<r[1])
        physical=(lcn+vcn-begin)*cluster+logical%cluster
        raw=data[physical:physical+record_size]
        if raw[:4]!=b'FILE': continue
        record=decode(raw)
        if not u(record,22,2)&1:continue
        name=None
        for off,kind in attrs(record):
            if kind==0x30:
                value=off+u(record,off+20,2)
                candidate=record[value+66:value+66+record[value+64]*2].decode('utf-16le')
                if candidate in CASES:name=candidate
        if name is None:continue
        off=attr(record,0x50); oldlen=u(record,off+4,4); sd=CASES[name]
        newlen=(24+len(sd)+7)&~7; new=bytearray(newlen)
        new[:24]=record[off:off+24];put(new,4,newlen,4);put(new,16,len(sd),4);put(new,20,24,2)
        new[24:24+len(sd)]=sd
        used=u(record,24,4)
        replacement=record[:off]+new+record[off+oldlen:used]
        assert len(replacement)<=record_size
        put(replacement,24,len(replacement),4)
        replacement.extend(bytes(record_size-len(replacement)))
        data[physical:physical+record_size]=protect(replacement)
        changed.add(name)
    assert changed==set(CASES),changed
    path.write_bytes(data)

if __name__=='__main__':main()
