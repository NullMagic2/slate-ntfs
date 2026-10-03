#!/usr/bin/env python3
"""
Module: kernel.tests.test_windows_return
Purpose: Validate a copy of the disposable image returned by native Windows.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Validate a copy of the disposable image returned by native Windows.
"""
import array,fcntl,hashlib,json,os,shutil,tempfile,subprocess
from pathlib import Path
from run_wsl_fresh_benchmark import run
ROOT=Path(__file__).resolve().parents[2]
run('insmod',str(ROOT/'kernel/ntfs_rs.ko'))
try:
 with tempfile.TemporaryDirectory(prefix='slate-windows-return-',dir='/var/tmp') as d:
  base=Path(d);image=base/'returned.img';m=base/'mount';m.mkdir();shutil.copyfile('/results/windows-returned.img',image)
  loop=run('losetup','--find','--show',str(image),capture_output=True,text=True).stdout.strip()
  try:
   run('mount','-t','ntfsrs','-o','rw,compatibility=linux,sidmap=u:0:S-1-5-32-544;g:0:S-1-5-18',loop,str(m))
   try:
    expected=json.loads(Path('/results/windows-expected.json').read_text())
    expected['linux-flags.txt']=hashlib.sha256(b'Windows wrote immutable file\r\n').hexdigest()
    expected['directory/child.txt']=hashlib.sha256(b'Slate nested data\r\nWindows append\r\n').hexdigest()
    expected['windows-created.txt']=hashlib.sha256(b'Created by Windows 11\r\n').hexdigest()
    expected['windows-link.txt']=expected['resident.txt']
    for name,digest in expected.items():assert hashlib.sha256((m/name).read_bytes()).hexdigest()==digest,name
    backup=m/'.slate-metadata'/'linux-flags'
    if backup.exists():
     before=backup.read_bytes()
     attempt=subprocess.run(['python3',str(ROOT/'src/tools/slate-flags.py'),'snapshot',str(m)],capture_output=True,text=True)
     assert attempt.returncode!=0 and 'missing live EAs' in attempt.stderr,attempt.stderr
     assert backup.read_bytes()==before
     run('python3',str(ROOT/'src/tools/slate-flags.py'),'restore',str(m))
     saved=json.loads(backup.read_text())['payload']['files']
     assert {e['path'] for e in saved}=={'linux-flags.txt','flag-renamed-after.txt'},saved
     assert not (m/'flag-deleted.txt').exists()
     assert not (m/'flag-renamed.txt').exists()
     assert (m/'flag-replaced.txt').read_bytes()==b'new file at old path\r\n'
     assert (m/'flag-renamed-after.txt').read_bytes()==b'renamed Windows overwrite\r\n'
     assert int.from_bytes(os.getxattr(m/'flag-renamed-after.txt','system.ntfs_linux_flags'),'little')==0x40
     assert int.from_bytes(os.getxattr(m/'flag-cleared.txt','system.ntfs_linux_flags'),'little')==0
     try:os.getxattr(m/'flag-replaced.txt','system.ntfs_linux_flags')
     except OSError as e:assert e.errno==61,e
     else:raise AssertionError('replacement inherited stale flags')
     assert int.from_bytes(os.getxattr(m/'.slate-metadata','system.ntfs_attrib'),'little')&6==6
     run('python3',str(ROOT/'src/tools/slate-flags.py'),'restore',str(m))
     assert json.loads(backup.read_text())['payload']['files']==saved
     print('PASS identity restore follows rename; deleted/replaced/cleared entries pruned; restore idempotent',flush=True)
     os.link(m/'flag-renamed-after.txt',m/'flag-alias.txt')
     (m/'flag-renamed-after.txt').unlink()
     run('python3',str(ROOT/'src/tools/slate-flags.py'),'prune',str(m))
     assert {e['path'] for e in json.loads(backup.read_text())['payload']['files']}=={'linux-flags.txt','flag-alias.txt'}
     (m/'flag-alias.txt').unlink()
     run('python3',str(ROOT/'src/tools/slate-flags.py'),'prune',str(m))
     assert {e['path'] for e in json.loads(backup.read_text())['payload']['files']}=={'linux-flags.txt'}
     print('PASS hard-link identity retained until last deletion; no ghost entries after prune',flush=True)
    fd=os.open(m/'linux-flags.txt',os.O_RDONLY)
    try:
     flags=array.array('L',[0]);fcntl.ioctl(fd,0x80086601,flags,True)
     assert flags[0]&0xf0==(0xd0 if backup.exists() else 0),flags[0]
    finally:os.close(fd)
    assert os.getxattr(m/'resident.txt','user.interop')==b'EA round trip'
    assert (m/'windows-pass.txt').read_text()=='PASS'
    (m/'after-windows.txt').write_bytes(b'Slate writes after native Windows\r\n');os.sync()
    print('PASS Windows -> Slate writable mount; all hashes and retained EAs verified; flag backup restored' if backup.exists() else
          'PASS Windows -> Slate writable mount; all hashes and retained EAs verified; old fixture has no flag backup',flush=True)
   finally:run('umount',str(m))
  finally:run('losetup','-d',loop)
  shutil.copyfile(image,'/results/windows-roundtrip-final.img')
finally:run('rmmod','ntfs_rs')
