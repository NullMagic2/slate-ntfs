#!/usr/bin/env python3
"""
Module: kernel.tests.test_kernel_vfs
Purpose: Mounted VFS regressions using a new disposable NTFS image only.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Mounted VFS regressions using a new disposable NTFS image only.
"""
import ctypes, errno, os, sys, tempfile, mmap, stat, socket, fcntl, struct, signal
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
from run_wsl_fresh_benchmark import run
sys.path.insert(0,str(ROOT/'tests/support'))
from ntfs_image import attr, attrs, decode, protect, put, u

def local_directory_list(image, number):
 # Add a standard resident list to a newly created, unmounted test directory.
 with image.open('r+b') as stream:
  boot=stream.read(512); cluster=u(boot,11,2)*boot[13]
  stream.seek(u(boot,48,8)*cluster); zero=decode(stream.read(1024))
  at=attr(zero,0x80); cursor=at+u(zero,at+32,2); lcn=vcn=0
  logical=number*1024; physical=None
  while zero[cursor]:
   tag=zero[cursor]; n,m=tag&15,tag>>4; count=u(zero,cursor+1,n)
   lcn+=int.from_bytes(zero[cursor+1+n:cursor+1+n+m],'little',signed=True)
   if vcn<=logical//cluster<vcn+count:
    physical=(lcn+logical//cluster-vcn)*cluster+logical%cluster; break
   vcn+=count; cursor+=1+n+m
  assert physical is not None
  stream.seek(physical); record=decode(stream.read(1024)); payload=bytearray()
  reference=number|(u(record,16,2)<<48)
  for off,kind in attrs(record):
   name_length=record[off+9]; name_at=off+u(record,off+10,2)
   name=record[name_at:name_at+name_length*2]
   entry=bytearray((26+len(name)+7)&~7)
   put(entry,0,kind,4); put(entry,4,len(entry),2)
   entry[6]=name_length; entry[7]=26 if name else 0
   put(entry,8,u(record,off+16,8) if record[off+8] else 0,8)
   put(entry,16,reference,8); put(entry,24,u(record,off+14,2),2)
   entry[26:26+len(name)]=name; payload+=entry
  value=bytearray((24+len(payload)+7)&~7)
  put(value,0,0x20,4); put(value,4,len(value),4)
  identifier=u(record,40,2); put(value,14,identifier,2)
  put(value,16,len(payload),4); put(value,20,24,2); value[24:24+len(payload)]=payload
  insertion=next(off for off,kind in attrs(record) if kind>0x20)
  used=u(record,24,4); assert used+len(value)<=len(record)
  record[insertion+len(value):used+len(value)]=record[insertion:used]
  record[insertion:insertion+len(value)]=value
  put(record,24,used+len(value),4); put(record,40,identifier+1,2)
  stream.seek(physical); stream.write(protect(record)); stream.flush(); os.fsync(stream.fileno())

def mounted(path,image,kind):
 loop=run('losetup','--find','--show',str(image),capture_output=True,text=True).stdout.strip()
 try: run('mount','-t','ntfsrs','-o','rw,compatibility=linux,sidmap=u:0:S-1-5-32-544;g:0:S-1-5-18',loop,str(path))
 except BaseException:
  run('losetup','-d',loop); raise
 return loop
libc=ctypes.CDLL(None,use_errno=True)
run('insmod',str(ROOT/'kernel/ntfs_rs.ko'))
try:
 with tempfile.TemporaryDirectory(prefix='slate-vfs-',dir='/var/tmp') as d:
  b=Path(d); image=b/'new.img'; m=b/'mount'; m.mkdir()
  with image.open('xb') as f: f.truncate(64<<20)
  run('mkntfs','-F','-Q','-c','4096',str(image),capture_output=True)
  loop=mounted(m,image,'slate')
  try:
   (m/'a').mkdir(); (m/'a'/'b').mkdir(); (m/'a'/'b').rmdir()
   (m/'a'/'f').write_bytes(b'content')
   os.symlink('a/f',m/'link'); assert os.readlink(m/'link')=='a/f'; assert (m/'link').read_bytes()==b'content'
   print('PASS mkdir/rmdir/symlink',flush=True)
   (m/'listed').mkdir(); number=(m/'listed').stat().st_ino
   run('umount',str(m)); run('losetup','-d',loop)
   local_directory_list(image,number)
   loop=mounted(m,image,'slate')
   (m/'listed'/'child').mkdir(); (m/'listed'/'file').write_bytes(b'listed')
   assert sorted(p.name for p in (m/'listed').iterdir())==['child','file']
   (m/'listed'/'file').unlink(); (m/'listed'/'child').rmdir(); (m/'listed').rmdir()
   print('PASS directory with a resident local ATTRIBUTE_LIST',flush=True)
   with (m/'a'/'f').open('r+b',buffering=0) as f:
    held=os.fstat(f.fileno()); (m/'a'/'f').unlink()
    assert os.fstat(f.fileno()).st_nlink==0
    assert f.read()==b'content'; f.write(b'!'); os.fsync(f.fileno())
    (m/'a'/'f').write_bytes(b'reborn')
    assert (m/'a'/'f').stat().st_ino!=held.st_ino
    assert f.seek(0)==0 and f.read()==b'content!'
    (m/'a'/'f').unlink()
   pinned=m/'opath'; pinned.write_bytes(b'pinned')
   fd=os.open(pinned,os.O_PATH)
   try:
    identity=os.fstat(fd); pinned.unlink()
    for i in range(8): (m/('reuse-'+str(i))).write_bytes(b'new')
    after=os.fstat(fd)
    assert after.st_ino==identity.st_ino and after.st_size==6 and after.st_nlink==0
   finally: os.close(fd)
   for i in range(8): (m/('reuse-'+str(i))).unlink()
   print('PASS open unlink, continued I/O and O_PATH lifetime',flush=True)
   (m/'one').write_bytes(b'1'); (m/'two').write_bytes(b'2')
   ctypes.set_errno(0)
   assert libc.renameat2(-100,os.fsencode(m/'one'),-100,os.fsencode(m/'two'),1)==-1
   assert ctypes.get_errno()==errno.EEXIST
   assert (m/'one').read_bytes()==b'1' and (m/'two').read_bytes()==b'2'
   with (m/'two').open('r+b',buffering=0) as old:
    victim=os.fstat(old.fileno()); os.rename(m/'one',m/'two')
    assert os.fstat(old.fileno()).st_nlink==0 and (m/'two').read_bytes()==b'1'
    assert old.read()==b'2'; old.write(b'!'); os.fsync(old.fileno())
    (m/'one').write_bytes(b'3'); assert (m/'one').stat().st_ino!=victim.st_ino
    assert old.seek(0)==0 and old.read()==b'2!'
   assert libc.renameat2(-100,os.fsencode(m/'one'),-100,os.fsencode(m/'two'),2)==0,ctypes.get_errno()
   assert (m/'one').read_bytes()==b'1' and (m/'two').read_bytes()==b'3'
   (m/'a').rmdir()
   print('PASS rename replacement/exchange',flush=True)
   os.mkfifo(m/'fifo',0o600)
   fd=os.open(m/'fifo',os.O_RDWR|os.O_NONBLOCK)
   try: os.write(fd,b'pipe'); assert os.read(fd,4)==b'pipe'
   finally: os.close(fd)
   os.mknod(m/'device',stat.S_IFCHR|0o600,os.makedev(1,3))
   assert (m/'device').stat().st_rdev==os.makedev(1,3)
   with (m/'device').open('wb') as f: f.write(b'null')
   sock=socket.socket(socket.AF_UNIX); sock.bind(str(m/'sock')); sock.close()
   fd=os.open(m,os.O_TMPFILE|os.O_RDWR,0o600)
   try:
    os.write(fd,b'temporary'); os.fsync(fd)
    assert os.fstat(fd).st_nlink==0
    assert libc.linkat(fd,b'',-100,os.fsencode(m/'published'),0x1000)==0,ctypes.get_errno()
    assert os.fstat(fd).st_nlink==1
   finally: os.close(fd)
   assert (m/'published').read_bytes()==b'temporary'
   fd=os.open(m,os.O_TMPFILE|os.O_RDWR,0o600); os.write(fd,b'orphan'); os.close(fd)
   # chmod keeps the special type; special files take hard links.
   os.chmod(m/'fifo',0o640); st=os.stat(m/'fifo')
   assert stat.S_ISFIFO(st.st_mode) and stat.S_IMODE(st.st_mode)==0o640,oct(st.st_mode)
   os.link(m/'fifo',m/'fifo-link'); assert os.stat(m/'fifo').st_nlink==2
   assert stat.S_ISFIFO(os.stat(m/'fifo-link').st_mode); os.unlink(m/'fifo-link')
   assert os.stat(m/'fifo').st_nlink==1
   # Large device numbers (WSL 8-byte $LXDEV) and a block device.
   os.mknod(m/'block',stat.S_IFBLK|0o600,os.makedev(259,0x12345))
   assert stat.S_ISBLK(os.stat(m/'block').st_mode)
   assert os.stat(m/'block').st_rdev==os.makedev(259,0x12345)
   # O_TMPFILE honours the umask; O_EXCL makes the file unlinkable.
   old=os.umask(0o077)
   try: fd=os.open(m,os.O_TMPFILE|os.O_RDWR,0o666)
   finally: os.umask(old)
   try: assert stat.S_IMODE(os.fstat(fd).st_mode)==0o600,oct(os.fstat(fd).st_mode)
   finally: os.close(fd)
   fd=os.open(m,os.O_TMPFILE|os.O_RDWR|os.O_EXCL,0o600)
   try:
    assert libc.linkat(fd,b'',-100,os.fsencode(m/'excluded'),0x1000)!=0
    assert ctypes.get_errno()==errno.ENOENT,ctypes.get_errno()
   finally: os.close(fd)
   assert not (m/'excluded').exists()
   # A published temporary file keeps working through its handle.
   fd=os.open(m,os.O_TMPFILE|os.O_RDWR,0o640)
   try:
    os.write(fd,b'first')
    assert libc.linkat(fd,b'',-100,os.fsencode(m/'published-2'),0x1000)==0,ctypes.get_errno()
    os.write(fd,b'-second'); os.fsync(fd)
   finally: os.close(fd)
   assert (m/'published-2').read_bytes()==b'first-second'
   assert stat.S_IMODE((m/'published-2').stat().st_mode)==0o640
   print('PASS FIFO/device/socket/tmpfile and publication',flush=True)
   # Exercise the inode ACL callbacks directly through the VFS xattr ABI.
   # A named-user entry keeps the ACL non-equivalent to plain mode bits so
   # chmod must rewrite the ACL mask rather than simply deleting the ACL.
   def acl_blob(user_perm=4,mask_perm=4):
    entries=[(0x01,7,0xffffffff),(0x02,user_perm,12345),(0x04,4,0xffffffff),
             (0x10,mask_perm,0xffffffff),(0x20,0,0xffffffff)]
    return struct.pack('<I',2)+b''.join(struct.pack('<HHI',*entry) for entry in entries)
   def acl_entries(blob):
    assert struct.unpack_from('<I',blob,0)[0]==2 and (len(blob)-4)%8==0
    return [struct.unpack_from('<HHI',blob,at) for at in range(4,len(blob),8)]
   acl_file=m/'acl-file'; acl_file.write_bytes(b'acl')
   os.setxattr(acl_file,'system.posix_acl_access',acl_blob())
   assert 'system.posix_acl_access' in os.listxattr(acl_file)
   assert any(tag==0x02 and ident==12345 for tag,perm,ident in acl_entries(
       os.getxattr(acl_file,'system.posix_acl_access')))
   os.chmod(acl_file,0o660)
   changed=acl_entries(os.getxattr(acl_file,'system.posix_acl_access'))
   assert stat.S_IMODE(acl_file.stat().st_mode)==0o660
   assert next(perm for tag,perm,ident in changed if tag==0x10)==6
   acl_dir=m/'acl-dir'; acl_dir.mkdir()
   os.setxattr(acl_dir,'system.posix_acl_default',acl_blob())
   assert 'system.posix_acl_default' in os.listxattr(acl_dir)
   print('PASS POSIX ACL get/set/list/chmod callbacks',flush=True)
   path=m/'mapped'; path.write_bytes(b'A'*8192)
   with path.open('r+b',buffering=0) as f:
    with mmap.mmap(f.fileno(),8192) as mem:
     mem[0:4]=b'MMAP'; mem.flush(); os.fsync(f.fileno())
     assert os.pread(f.fileno(),4,0)==b'MMAP'
     os.pwrite(f.fileno(),b'CALL',4096); assert mem[4096:4100]==b'CALL'
     mem[4097:4101]=b'RACE'
     os.ftruncate(f.fileno(),5000); os.fsync(f.fileno())
     assert os.pread(f.fileno(),5,4096)==b'CRACE'
   os.utime(path,ns=(1600000000123456700,1600000000987654300))
   before=path.stat()
   assert before.st_mtime_ns==1600000000987654300
   run('umount',str(m)); run('losetup','-d',loop)
   loop=mounted(m,image,'slate')
   assert path.stat().st_mtime_ns==before.st_mtime_ns
   assert stat.S_ISFIFO((m/'fifo').stat().st_mode)
   assert stat.S_ISSOCK((m/'sock').stat().st_mode)
   assert (m/'device').stat().st_rdev==os.makedev(1,3)
   assert (m/'block').stat().st_rdev==os.makedev(259,0x12345)
   assert stat.S_IMODE((m/'fifo').stat().st_mode)==0o640
   assert (m/'published').read_bytes()==b'temporary'
   assert (m/'published-2').read_bytes()==b'first-second'
   assert path.read_bytes()[4096:4101]==b'CRACE'
   assert stat.S_IMODE((m/'acl-file').stat().st_mode)==0o660
   assert next(perm for tag,perm,ident in acl_entries(os.getxattr(m/'acl-file','system.posix_acl_access')) if tag==0x10)==6
   assert 'system.posix_acl_default' in os.listxattr(m/'acl-dir')
   print('PASS mmap/pwrite/truncate, ACL and timestamp persistence',flush=True)
   fd=os.open(m/'allocated',os.O_CREAT|os.O_RDWR,0o600)
   try:
    assert libc.fallocate(fd,1,ctypes.c_longlong(0),ctypes.c_longlong(131072))==0,ctypes.get_errno()
    assert os.fstat(fd).st_size==0
    buf=bytearray(struct.pack('QQIIII',0,1<<30,0,0,16,0)+bytes(16*56))
    fcntl.ioctl(fd,0xC020660B,buf,True)
    assert struct.unpack_from('I',buf,20)[0]>0
    assert sum(struct.unpack_from('Q',buf,32+i*56+16)[0] for i in range(struct.unpack_from('I',buf,20)[0]))>=131072
    os.posix_fallocate(fd,0,65536); assert os.fstat(fd).st_size==65536
    assert os.pread(fd,65536,0)==bytes(65536)
    os.pwrite(fd,b'extent',100); os.fsync(fd)
   finally: os.close(fd)
   with (m/'allocated').open('rb') as source, (m/'copied').open('wb') as destination:
    assert os.copy_file_range(source.fileno(),destination.fileno(),65536)==65536
   assert (m/'copied').read_bytes()==(m/'allocated').read_bytes()
   splice_payload=b'splice-write-through-aops'
   read_end,write_end=os.pipe()
   try:
    os.write(write_end,splice_payload); os.close(write_end); write_end=-1
    splice_fd=os.open(m/'spliced',os.O_CREAT|os.O_TRUNC|os.O_WRONLY,0o600)
    try:
     assert os.splice(read_end,splice_fd,len(splice_payload))==len(splice_payload)
     os.fsync(splice_fd)
    finally: os.close(splice_fd)
   finally:
    os.close(read_end)
    if write_end>=0: os.close(write_end)
   assert (m/'spliced').read_bytes()==splice_payload
   class Handle(ctypes.Structure):
    _fields_=[('size',ctypes.c_uint),('kind',ctypes.c_int),('bytes',ctypes.c_ubyte*128)]
   handle=Handle(); handle.size=128; mount_id=ctypes.c_int()
   assert libc.name_to_handle_at(-100,os.fsencode(m/'allocated'),ctypes.byref(handle),ctypes.byref(mount_id),0)==0,ctypes.get_errno()
   # Modern kernels request an object-only handle by default; explicitly
   # request a connectable handle to exercise the parent encoding as well.
   assert (handle.kind,handle.size) in ((0x91,12),(0x92,24)),(handle.kind,handle.size)
   handle.size=128
   assert libc.name_to_handle_at(-100,os.fsencode(m/'allocated'),ctypes.byref(handle),ctypes.byref(mount_id),0x002)==0,ctypes.get_errno()
   assert handle.kind==(0x10000|0x92) and handle.size==24,(handle.kind,handle.size)
   mountfd=os.open(m,os.O_RDONLY|os.O_DIRECTORY)
   try:
    fd=libc.open_by_handle_at(mountfd,ctypes.byref(handle),os.O_RDONLY)
    assert fd>=0,ctypes.get_errno()
    try: assert os.pread(fd,6,100)==b'extent'
    finally: os.close(fd)
   finally: os.close(mountfd)
   stale=m/'stale-handle'; stale.write_bytes(b'old')
   stale_handle=Handle(); stale_handle.size=128
   assert libc.name_to_handle_at(-100,os.fsencode(stale),ctypes.byref(stale_handle),ctypes.byref(mount_id),0)==0,ctypes.get_errno()
   stale.unlink()
   for i in range(12): (m/('handle-reuse-'+str(i))).write_bytes(b'new')
   mountfd=os.open(m,os.O_RDONLY|os.O_DIRECTORY)
   try:
    ctypes.set_errno(0)
    assert libc.open_by_handle_at(mountfd,ctypes.byref(stale_handle),os.O_RDONLY)==-1
    assert ctypes.get_errno()==errno.ESTALE,ctypes.get_errno()
   finally: os.close(mountfd)
   for i in range(12): (m/('handle-reuse-'+str(i))).unlink()
   run('umount',str(m)); run('losetup','-d',loop); loop=mounted(m,image,'slate')
   assert (m/'allocated').read_bytes()[100:106]==b'extent'
   fd=os.open(m/'allocated',os.O_RDONLY)
   try:
    fcntl.ioctl(fd,0xC020660B,buf,True)
    assert sum(struct.unpack_from('Q',buf,32+i*56+16)[0] for i in range(struct.unpack_from('I',buf,20)[0]))>=131072
   finally: os.close(fd)
   print('PASS fallocate/KEEP_SIZE/FIEMAP/copy_file_range/splice_write/export handles and stale-generation rejection',flush=True)
   # Twelve ~200-byte hard-link names require several FILE extension records;
   # this directly exercises link creation beyond base-record capacity before
   # the existing setattr truncate/rename/remount checks.
   base=m/'links'; base.write_bytes(b'L'*128)
   names=[m/('long-'+str(i)+'-'+('x'*180)) for i in range(12)]
   for name in names: os.link(base,name)
   assert base.stat().st_nlink==13
   with base.open('r+b',buffering=0) as f:
    f.write(b'E'*8192); os.fsync(f.fileno())
    os.ftruncate(f.fileno(),1500); os.fsync(f.fileno())
    os.ftruncate(f.fileno(),7000); os.fsync(f.fileno())
   fd=os.open(names[-1],os.O_RDWR)
   try:
    assert os.pwrite(fd,b'extension-tail',6000)==14
    os.ftruncate(fd,6200); os.fsync(fd)
   finally: os.close(fd)
   expected=b'E'*1500+bytes(4500)+b'extension-tail'+bytes(186)
   assert len(expected)==6200
   for name in [base,*names]:
    assert name.read_bytes()==expected
   renamed=m/('renamed-'+('y'*150)); os.rename(names[-1],renamed); names[-1]=renamed
   run('umount',str(m)); run('losetup','-d',loop); loop=mounted(m,image,'slate')
   for name in names:
    assert name.read_bytes()==expected
    name.unlink()
   assert base.read_bytes()==expected
   assert base.stat().st_nlink==1
   base.unlink()
   print('PASS extension-record hard links, setattr truncate/grow, rename, remount and unlink',flush=True)
   native=b/'native'; native.mkdir()
   run('mount','-t','ntfsrs','-o','rw,sidmap=u:0:S-1-5-32-544;g:0:S-1-5-18',loop,str(native))
   try:
    # The native NTFS view cannot create special files (mknod EPERM) but
    # presents the ones the Linux view made.
    try: os.mkfifo(native/'native-fifo'); raise AssertionError('native mkfifo')
    except PermissionError: pass
    assert stat.S_ISFIFO((native/'fifo').stat().st_mode)
    fd=os.open(native,os.O_TMPFILE|os.O_RDWR,0o600)
    try: os.write(fd,b'native temporary')
    finally: os.close(fd)
    notify=libc.inotify_init1(os.O_NONBLOCK); assert notify>=0
    try:
     assert libc.inotify_add_watch(notify,os.fsencode(native),0x100|0x200|0x40|0x80)>=0
     (m/'notify').write_bytes(b'event'); os.rename(m/'notify',m/'notified'); (m/'notified').unlink()
     events=os.read(notify,65536); masks=[]; at=0
     while at<len(events):
      _,mask,_,n=struct.unpack_from('iIII',events,at); masks.append(mask); at+=16+n
     assert all(any(mask & bit for mask in masks) for bit in [0x100,0x200,0x40,0x80]),masks
    finally: os.close(notify)
    # Reading a projected inode must update and persist canonical atime.
    stamp=m/'view-times'; stamp.write_bytes(b'times')
    old=946684800000000000
    os.utime(stamp,ns=(old,old))
    assert (native/'view-times').read_bytes()==b'times'
    assert stamp.stat().st_atime_ns>old
    assert stamp.stat().st_atime_ns==(native/'view-times').stat().st_atime_ns
    fd=os.open(stamp,os.O_RDWR)
    try:
     before=os.fstat(fd).st_mtime_ns
     os.ftruncate(fd,2); os.fsync(fd)
     assert os.fstat(fd).st_mtime_ns>before
    finally: os.close(fd)
    notify=libc.inotify_init1(os.O_NONBLOCK); assert notify>=0
    try:
     assert libc.inotify_add_watch(notify,os.fsencode(native/'view-times'),0x1|0x2|0x4)>=0
     stamp.read_bytes(); os.chmod(stamp,0o600)
     with stamp.open('r+b') as f: f.truncate(1)
     events=os.read(notify,65536); masks=[]; at=0
     while at<len(events):
      _,mask,_,n=struct.unpack_from('iIII',events,at); masks.append(mask); at+=16+n
     assert all(any(mask & bit for mask in masks) for bit in [0x1,0x2,0x4]),masks
    finally: os.close(notify)
    (m/'leased').write_bytes(b'lease')
    signals=[]; old=signal.signal(signal.SIGIO,lambda *_:signals.append(True))
    try:
     for origin,other in [(m,native),(native,m)]:
      fd=os.open(origin/'leased',os.O_RDONLY)
      try:
       fcntl.fcntl(fd,fcntl.F_SETLEASE,fcntl.F_RDLCK)
       assert fcntl.fcntl(fd,fcntl.F_GETLEASE)==fcntl.F_RDLCK
       try: conflicting=os.open(other/'leased',os.O_WRONLY|os.O_NONBLOCK)
       except OSError as error: assert error.errno==errno.EAGAIN,error
       else: os.close(conflicting); raise AssertionError('lease conflict was missed')
       fcntl.fcntl(fd,fcntl.F_SETLEASE,fcntl.F_UNLCK)
      finally: os.close(fd)
     assert signals
    finally: signal.signal(signal.SIGIO,old)
   finally: run('umount',str(native))
   fd=os.open(m,os.O_RDONLY|os.O_DIRECTORY)
   try:
    fcntl.ioctl(fd,0xC0045877,0)
    fcntl.ioctl(fd,0xC0045878,0)
   finally: os.close(fd)
   print('PASS cross-view notifications, leases and freeze/thaw',flush=True)
  finally:
   run('umount',str(m)); run('losetup','-d',loop)
  result=run(str(ROOT/'target/release/ntfs-chkdsk'),'--audit',str(image),capture_output=True,text=True)
  print(result.stdout); assert 'errors=0' in result.stdout
finally: run('rmmod','ntfs_rs')
