#!/usr/bin/env python3
"""Module: tests.windows.prepare_format_validation
Purpose: Wrap geometry fixtures as disposable disks for Windows validation.
Created: 2026-10-02
Architecture: Consumes formatter test images and prepares guest manifests;
format_validation_guest.ps1 runs native checks.

Wrap five geometry-test images as disposable MBR disks for Windows.

QEMU must expose sector-4096-* with logical_block_size=4096 and
physical_block_size=4096. All other disks use 512-byte logical sectors.
Never attach these disks read/write to the host OS.
"""
from pathlib import Path
import hashlib, json, struct, sys

source,out=map(Path,sys.argv[1:])
out.mkdir(exist_ok=False)
names=['cluster-512','cluster-65536','cluster-2097152','sector-4096-cluster-4096','defaults']
cases=[]
for i,name in enumerate(names):
    data=(source/(name+'.img')).read_bytes()
    assert len(data)==64*1024*1024
    sector=4096 if name.startswith('sector-4096') else 512
    signature=0x5fa10000+i
    mbr=bytearray(1048576);struct.pack_into('<I',mbr,440,signature)
    mbr[446:462]=struct.pack('<B3sB3sII',0,b'\xfe\xff\xff',7,b'\xfe\xff\xff',1048576//sector,len(data)//sector)
    mbr[510:512]=b'\x55\xaa';(out/(name+'.disk')).write_bytes(mbr+data)
    cases.append(dict(name=name,signature=signature,sector=sector,sha256=hashlib.sha256(data).hexdigest()))
(out/'cases.json').write_text(json.dumps(cases,indent=2))
template=Path(__file__).with_name('format_validation_guest.ps1').read_text()
(out/'guest.ps1').write_text(template.replace('@RUN_ID@',out.name).replace('@CASES_JSON@',json.dumps(cases)))
print(out)
