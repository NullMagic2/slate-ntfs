#!/usr/bin/env python3
"""
Module: kernel.tests.test_v040_interop
Purpose: Create a fresh image, check Linux flags across drivers, export for Windows.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Create a fresh image, check Linux flags across drivers, export for Windows.
"""
import array,errno,fcntl,hashlib,json,os,shutil,subprocess,tempfile
from pathlib import Path
from run_wsl_fresh_benchmark import run
ROOT=Path(__file__).resolve().parents[2]
GET=0x80086601;SET=0x40086602
def flags(path,value=None):
 fd=os.open(path,os.O_RDONLY)
 try:
  bits=array.array('L',[0 if value is None else value]);fcntl.ioctl(fd,GET if value is None else SET,bits,True)
  return bits[0]
 finally:os.close(fd)
def denied(action):
 try:action()
 except OSError as e:assert e.errno in (errno.EPERM,errno.EACCES),e
 else:raise AssertionError('protected mutation succeeded')
run('insmod',str(ROOT/'kernel/ntfs_rs.ko'))
try:
 with tempfile.TemporaryDirectory(prefix='slate-interop-',dir='/var/tmp') as d:
  base=Path(d);image=base/'test.img';m=base/'linux';native=base/'native';m.mkdir();native.mkdir()
  with image.open('xb') as f:f.truncate(128<<20)
  run('mkntfs','-F','-Q','-c','4096','-L','SLATE040',str(image),capture_output=True)
  loop=run('losetup','--find','--show',str(image),capture_output=True,text=True).stdout.strip()
  try:
   run('mount','-t','ntfsrs','-o','rw,compatibility=linux,sidmap=u:0:S-1-5-32-544;g:0:S-1-5-18',loop,str(m))
   try:
    run('mount','-t','ntfsrs','-o','rw,sidmap=u:0:S-1-5-32-544;g:0:S-1-5-18',loop,str(native))
    try:
     p=m/'linux-flags.txt';p.write_bytes(b'Linux original\r\n');flags(p,0x10|0x40|0x80)
     assert flags(p)&0xf0==0xd0
     denied(lambda:p.write_bytes(b'forbidden'));denied(lambda:p.unlink())
     assert flags(native/p.name)&0xf0==0
     (native/p.name).write_bytes(b'Native mode wrote immutable file\r\n')
     assert p.read_bytes()==b'Native mode wrote immutable file\r\n'
     flags(p,0x20)
     denied(lambda:p.write_bytes(b'forbidden'))
     with p.open('ab',buffering=0) as f:f.write(b'Linux append\r\n');os.fsync(f.fileno())
     flags(p,0x10|0x40|0x80)
     (m/'resident.txt').write_bytes(b'Slate resident data\r\n')
     (m/'large.bin').write_bytes(bytes(range(256))*32768)
     (m/'directory').mkdir();(m/'directory'/'child.txt').write_bytes(b'Slate nested data\r\n')
     os.link(m/'resident.txt',m/'hardlink.txt')
     for i in range(12):os.link(m/'resident.txt',m/('long-link-'+str(i)+'-'+'x'*180))
     os.setxattr(m/'resident.txt','user.interop',b'EA round trip')
     os.sync()
     expected={str(p.relative_to(m)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [*m.glob('*.txt'), m/'large.bin', *m.glob('long-link-*'), *(m/'directory').glob('*')]}
    finally:run('umount',str(native))
   finally:run('umount',str(m))
  finally:run('losetup','-d',loop)
  print('PASS Linux flags enforced; native view ignores flags; standard EA and extension hard links',flush=True)
  run('ntfs-3g',str(image),str(m))
  try:
   for name,digest in expected.items():assert hashlib.sha256((m/name).read_bytes()).hexdigest()==digest,name
   (m/'linux-flags.txt').write_bytes(b'ntfs-3g wrote immutable file\r\n')
   (m/'ntfs3g-created.txt').write_bytes(b'Created by ntfs-3g\r\n');os.sync()
  finally:run('umount',str(m))
  loop=run('losetup','--find','--show',str(image),capture_output=True,text=True).stdout.strip()
  try:
   run('mount','-t','ntfsrs','-o','rw,compatibility=linux,sidmap=u:0:S-1-5-32-544;g:0:S-1-5-18',loop,str(m))
   try:
    assert flags(m/'linux-flags.txt')&0xf0==0xd0
    assert (m/'linux-flags.txt').read_bytes()==b'ntfs-3g wrote immutable file\r\n'
    denied(lambda:(m/'linux-flags.txt').unlink())
    assert os.getxattr(m/'resident.txt','user.interop')==b'EA round trip'
    expected={str(p.relative_to(m)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [*m.glob('*.txt'), m/'large.bin', *m.glob('long-link-*'), *(m/'directory').glob('*')]}
    for name in ['flag-renamed.txt','flag-deleted.txt','flag-replaced.txt','flag-cleared.txt']:
     (m/name).write_bytes(b'flag identity fixture\r\n');flags(m/name,0x40)
    run('python3',str(ROOT/'src/tools/slate-flags.py'),'snapshot',str(m))
    flags(m/'flag-cleared.txt',0)
   finally:run('umount',str(m))
  finally:run('losetup','-d',loop)
  print('PASS ntfs-3g read/write round trip; flags and user EA preserved',flush=True)
  shutil.copyfile(image,'/results/windows-interop.img')
  Path('/results/windows-expected.json').write_text(json.dumps(expected,indent=2))
finally:run('rmmod','ntfs_rs')
