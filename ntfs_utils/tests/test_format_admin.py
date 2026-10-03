#!/usr/bin/env python3
"""
Module: ntfs_utils.tests.test_format_admin
Purpose: Destructive tests confined to new throwaway images and their loop devices.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Destructive tests confined to new throwaway images and their loop devices.
Run as root in the test WSL distribution. Retains results/images for Windows.
"""
from pathlib import Path
import ctypes, fcntl, hashlib, json, os, shutil, subprocess, sys, tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'ntfs_utils/python'))
os.environ['NTFS_UTILS_LIB'] = str(ROOT/'ntfs_utils/target/release/libntfs_utils.so')
import ntfs_utils as ntfs
from ntfs_utils import Status

def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, capture_output=True, text=True, **kwargs)

def native_acl(path):
    # NTFS-3G returns the required size even for a short nonzero buffer. Use a
    # full buffer; Python's small first getxattr buffer can trigger FUSE EIO.
    libc=ctypes.CDLL(None,use_errno=True)
    libc.getxattr.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_size_t]
    libc.getxattr.restype=ctypes.c_ssize_t
    buf=ctypes.create_string_buffer(65536)
    size=libc.getxattr(os.fsencode(path),b'system.ntfs_acl',buf,len(buf))
    assert size>=0,os.strerror(ctypes.get_errno())
    return buf.raw[:size]

def main():
    assert os.geteuid() == 0, 'run as root; non-root cases explicitly drop credentials'
    out = Path(tempfile.mkdtemp(prefix='slate-format-', dir='/var/tmp'))
    out.chmod(0o755)
    (out/'mount').mkdir()
    (out/'UserMapping').write_text('65534::S-1-5-21-100-200-300-1000\n:65534:S-1-5-21-100-200-300-513\n')
    results = []
    def check(name, condition):
        assert condition, name
        results.append(name); print('PASS', name, flush=True)
    def new(name, size=64*1024*1024):
        p = out/name
        with p.open('xb') as f: f.truncate(size)
        return p
    def digest(p):
        return hashlib.sha256(p.read_bytes()).hexdigest()
    def child(code, user=True):
        env = dict(os.environ, PYTHONPATH=str(ROOT/'ntfs_utils/python'))
        command = [sys.executable, '-c', code]
        return subprocess.run(command, env=env, capture_output=True, text=True,
                              user=65534 if user else None, group=65534 if user else None,
                              extra_groups=[] if user else None)
    formatter = ROOT/'ntfs_utils/target/release/ntfs-format'
    cli = ROOT/'ntfs_utils/target/release/ntfs-permissions'
    for name, size, quick in [('quick.img',64*1024*1024,True), ('full.img',64*1024*1024,False),
                             ('small.img',16*1024*1024,True), ('odd.img',257*1024*1024,True)]:
        path = new(name,size)
        marker=size*3//4
        with path.open('r+b') as f: f.seek(marker); f.write(b'old bytes')
        result = ntfs.get_device(path,probe=False).format_fs(label='Slate '+name,quick=quick)
        check(name+' native SUCCESS', result.status == Status.SUCCESS)
        info = ntfs.get_device(path)
        check(name+' clean/usage', not info.is_dirty and 0 < info.used_bytes < size)
        run('ntfsfix','-n',path)
        check(name+' ntfs-3g inspection', '$Secure' in run('ntfsls','-s',path).stdout)
        with path.open('rb') as f:
            boot=f.read(512); f.seek(size-512); backup=f.read(512)
            f.seek(marker); previous=f.read(9)
        check(name+' boot mirror',boot==backup)
        check(name+' quick/full semantics', previous == (b'old bytes' if quick else bytes(9)))
        check(name+' native root descriptor', len(info.security_descriptor((5<<48)|5))>20)
    path = out/'quick.img'
    before = digest(path)
    check('invalid label refusal',ntfs.format_device(path,label='bad/name').status==Status.INVALID_ARGUMENT)
    check('invalid mode refusal',ntfs.get_device(path).set_device_permissions(0o10000).status==Status.INVALID_ARGUMENT)
    check('refused requests preserve bytes',digest(path)==before)
    with path.open('r+b') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        check('cooperative image lock refusal',ntfs.format_device(path).status==Status.BUSY)
    denied = new('root-only.img'); denied.chmod(0o600); before = digest(denied)
    r=child(f'import ntfs_utils as n; r=n.format_device({str(denied)!r}); print(r); assert r.status==n.Status.PERMISSION_DENIED')
    check('non-root raw format denied',r.returncode==0)
    check('denied format unchanged',digest(denied)==before)
    denied.chmod(0)
    check('root format respects DAC capability',ntfs.format_device(denied).success)
    owner = new('user-owned.img'); os.chown(owner,65534,65534); owner.chmod(0o600)
    r=child(f'import ntfs_utils as n; a=n.get_device({str(owner)!r},probe=False); assert a.format_fs().success; assert a.set_device_permissions(0o640).success; assert a.set_device_owner(0,0).status==n.Status.PERMISSION_DENIED')
    check('unprivileged owner formats/chmods own image; cannot chown root',r.returncode==0)
    run(cli,'device-mode',owner,'600')
    check('CLI permission status',owner.stat().st_mode & 0o777 == 0o600)
    missing_confirmation=subprocess.run([formatter,str(owner)],capture_output=True)
    check('CLI requires explicit destructive intent',missing_confirmation.returncode==int(Status.INVALID_ARGUMENT))
    tiny=new('tiny.img',1024)
    check('small target refusal',not ntfs.format_device(tiny).success)
    fault=new('fault.img')
    r=child(f'import resource,signal,ntfs_utils as n; signal.signal(signal.SIGXFSZ,signal.SIG_IGN); resource.setrlimit(resource.RLIMIT_FSIZE,(1048576,1048576)); r=n.format_device({str(fault)!r}); print(r); assert r.status==n.Status.FAILURE',user=False)
    check('I/O failure never SUCCESS',r.returncode==0)

    mounted=False; loop=None
    try:
        loop=run('losetup','--find','--show',out/'root-only.img').stdout.strip()
        run('udevadm','settle')
        check('active loop backing image refused',ntfs.format_device(out/'root-only.img').status==Status.BUSY)
        result=ntfs.format_device(loop,label='LOOPTEST'); print(result,flush=True)
        check('unmounted throwaway loop formats',result.success)
        run('mount','-t','ntfs-3g','-o','permissions,usermapping='+str(out/'UserMapping'),loop,out/'mount'); mounted=True
        check('mounted block device refused',ntfs.format_device(loop).status==Status.BUSY)
        file=out/'mount/file.txt'; file.write_text('native formatter read/write test\n')
        dev=ntfs.get_device(loop)
        result=dev.set_permissions(file,0o640)
        check('mounted NTFS chmod',result.success)
        check('mounted NTFS ownership',dev.set_owner(file,65534,65534).success)
        check('wrong filesystem rejected',not dev.set_permissions(owner,0o777).success)
        actual=native_acl(file)
        result=dev.set_security_descriptor(file,actual)
        check('native ACL exact roundtrip',result.success and native_acl(file)==actual)
        check('malformed ACL rejected',dev.set_security_descriptor(file,b'bad').status==Status.INVALID_ARGUMENT)
        data = bytes(range(256))*400
        (out/'mount/large.bin').write_bytes(data)
        (out/'mount/nested').mkdir(); (out/'mount/nested/caf\u00e9.txt').write_text('unicode')
        run('sync'); run('umount',out/'mount'); mounted=False
        run('mount','-t','ntfs-3g','-o','permissions,usermapping='+str(out/'UserMapping'),loop,out/'mount'); mounted=True
        check('remount large-file content', (out/'mount/large.bin').read_bytes()==data)
        check('permissions persist',file.stat().st_uid==65534 and file.stat().st_mode & 0o777 == 0o640)
        check('native ACL persists',native_acl(file)==actual)
        run('umount',out/'mount'); mounted=False
        run('losetup','-d',loop); loop=None
        shutil.copyfile(out/'root-only.img',out/'populated.img')
    finally:
        if mounted: run('umount',out/'mount')
        if loop: run('losetup','-d',loop)
    (out/'results.json').write_text(json.dumps(dict(passed=results),indent=2))
    print('RESULT_DIRECTORY='+str(out),flush=True)

if __name__=='__main__': main()
