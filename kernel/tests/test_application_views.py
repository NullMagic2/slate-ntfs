#!/usr/bin/env python3
"""
Module: kernel.tests.test_application_views
Purpose: Shared live Linux/native views and launcher; disposable loop only.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Shared live Linux/native views and launcher; disposable loop only.
"""
import errno
import fcntl
import json
import mmap
import os
from pathlib import Path
import stat
import subprocess
import sys
import struct
import ctypes
from test_kernel_writes import ROOT, MAPPING, run, denied
from test_kernel_acl import meta
sys.path.insert(0, str(ROOT/'ntfs_utils/python'))
import ntfs_utils


def main():
    out = Path(sys.argv[1]).resolve(); out.mkdir(parents=True, exist_ok=False)
    linux = out/'linux'; native = out/'native'
    linux.mkdir(); native.mkdir()
    image = out/'source.img'
    with image.open('xb') as f: f.truncate(96 * 1024 * 1024)
    run('mkntfs', '-F', '-Q', '-q', image)
    loop = None; mounts = []
    run('insmod', ROOT/'kernel/slate-ntfs.ko')
    try:
        loop = run('losetup', '--find', '--show', image).stdout.decode().strip()
        for target, mode in [(linux, 'linux'), (native, None)]:
            options = f'sidmap={MAPPING}' + (f',compatibility={mode}' if mode else '')
            run('mount', '-t', 'ntfsrs', '-o', options, loop, target)
            mounts.append(target)
        print('PASS simultaneous writable mounts', flush=True)
        # Prime negative dentries in both views before mutations.
        assert not (native/'shared').exists() and not (linux/'Native').exists()
        (linux/'shared').write_bytes(b'original content')
        assert (native/'shared').read_bytes() == b'original content'
        (native/'Native').write_bytes(b'native name')
        assert (native/'NATIVE').read_bytes() == b'native name'
        assert (linux/'Native').read_bytes() == b'native name'
        assert not (linux/'NATIVE').exists()
        (linux/'odd:name').touch()
        denied(lambda: (native/'new:bad').touch(), (errno.EOPNOTSUPP,))
        os.chmod(linux/'shared', 0o640)
        assert stat.S_IMODE((linux/'shared').stat().st_mode) == 0o640
        assert stat.S_IMODE((native/'shared').stat().st_mode) == 0o555
        denied(lambda: os.chmod(native/'shared', 0o700), (errno.EOPNOTSUPP,))
        assert (native/'shared').stat().st_ino == (linux/'shared').stat().st_ino
        assert (native/'shared').stat().st_dev == (linux/'shared').stat().st_dev
        with (linux/'shared').open('r+b', buffering=0) as a, (native/'shared').open('r+b', buffering=0) as b:
            with mmap.mmap(a.fileno(), 0, access=mmap.ACCESS_READ) as mapping:
                b.write(b'updated!'); os.fsync(b.fileno())
                assert mapping[:8] == b'updated!'
            fcntl.flock(a, fcntl.LOCK_EX | fcntl.LOCK_NB)
            denied(lambda: fcntl.flock(b, fcntl.LOCK_EX | fcntl.LOCK_NB), (errno.EAGAIN, errno.EACCES))
            fcntl.flock(a, fcntl.LOCK_UN)
            fcntl.flock(b, fcntl.LOCK_EX | fcntl.LOCK_NB)
            denied(lambda: fcntl.flock(a, fcntl.LOCK_EX | fcntl.LOCK_NB), (errno.EAGAIN, errno.EACCES))
            fcntl.flock(b, fcntl.LOCK_UN)
            b.truncate(6)
            assert (linux/'shared').stat().st_size == 6
            assert (native/'shared').stat().st_size == 6
        print('PASS naming, modes, shared page cache, truncate, locks and open-handle protection', flush=True)
        (native/'Native').rename(native/'Renamed')
        assert not (linux/'Native').exists()
        assert (linux/'Renamed').read_bytes() == b'native name'
        os.link(native/'shared', native/'linked')
        assert (linux/'shared').stat().st_nlink == 2
        assert (linux/'linked').stat().st_ino == (linux/'shared').stat().st_ino
        (linux/'linked').unlink()
        assert (native/'shared').stat().st_nlink == 1
        # Test lock conflict in a different process (POSIX locks are per-process).
        with (native/'shared').open('r+b') as f:
            fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            code = "import fcntl,sys; f=open(sys.argv[1],'r+b'); fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB)"
            assert subprocess.run([sys.executable, '-c', code, str(linux/'shared')], capture_output=True).returncode != 0
        with (linux/'shared').open('r+b') as f: fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print('PASS cross-view rename/link/unlink and POSIX lock cleanup', flush=True)
        launcher = ROOT/'ntfs_utils/target/release/ntfs-run'
        # Namespace-local remount at exactly the same path; NTFS is the default.
        child = "import os,sys; from pathlib import Path; p=Path(sys.argv[1]); assert (p/'RENAMED').read_bytes()==b'native name'; (p/'AppFile').write_bytes(b'app'); assert (p/'APPFILE').read_bytes()==b'app'"
        run(launcher, '--application', sys.executable, '--', '-c', child, linux)
        assert (linux/'AppFile').read_bytes() == b'app' and not (linux/'APPFILE').exists()
        child = "from pathlib import Path; import sys; p=Path(sys.argv[1]); assert not (p/'APPFILE').exists(); (p/'default:linux').touch()"
        run(launcher, '--compatibility=linux', '--application', sys.executable, '--', '-c', child, native)
        assert (native/'default:linux').exists()
        assert ntfs_utils.run_application(sys.executable, ['-c', "from pathlib import Path; import sys; assert (Path(sys.argv[1])/'APPFILE').read_bytes()==b'app'; sys.exit(7)", str(linux)]) == 7
        # Exercise the actual C ABI with NULL options, independently of Python's defaults.
        function = ntfs_utils._library().ntfs_utils_run_application
        args = (ctypes.c_char_p * 3)(b'-c', b'from pathlib import Path; import sys; assert (Path(sys.argv[1])/"APPFILE").exists(); sys.exit(23)', os.fsencode(linux))
        code = ctypes.c_int32(-1); message = ctypes.create_string_buffer(512)
        assert function(os.fsencode(sys.executable), args, len(args), None, ctypes.byref(code), message, len(message)) == 0
        assert code.value == 23
        print('PASS Rust launcher, C/Python APIs, unchanged host mounts and NTFS defaults', flush=True)
        # Two applications use different policies at the same pathname while
        # appending to one canonical stream. Each append must occur exactly once.
        (linux/'append').touch()
        concurrent = "import os,sys,time; from pathlib import Path; p=Path(sys.argv[1]); mode=sys.argv[2]; assert (p/'APPFILE').exists()==(mode=='ntfs'); f=os.open(p/'append',os.O_WRONLY|os.O_APPEND); [(os.write(f,mode[0].encode()*16),time.sleep(.001)) for _ in range(30)]; os.close(f)"
        children = [subprocess.Popen([str(launcher), '--mount', str(linux), '--compatibility='+mode, '--application', sys.executable, '--', '-c', concurrent, str(linux), mode]) for mode in ('ntfs','linux')]
        assert all(child.wait(timeout=30) == 0 for child in children)
        data = (linux/'append').read_bytes()
        assert len(data) == 960 and data.count(b'n') == data.count(b'l') == 480
        print('PASS simultaneous application views and atomic append positioning', flush=True)
        # Change only the root DACL; owner/group bytes remain unchanged.
        original = os.getxattr(linux, 'system.ntfs_security')
        def root_acl(user_rights):
            owner_at, group_at = struct.unpack_from('<II', original, 4)
            owner = original[owner_at:owner_at+8+4*original[owner_at+1]]
            group = original[group_at:group_at+8+4*original[group_at+1]]
            entries = [meta.ace(0, meta.ADMIN_SID, 0x1f01ff, 3)]
            if user_rights: entries.append(meta.ace(0, meta.sid(5,1002), user_rights, 3))
            return meta.descriptor(owner, group, entries)
        os.setxattr(linux, 'system.ntfs_security', root_acl(0x1f01ff))
        def as_user(script, mode='ntfs', okay=True):
            return run('setpriv', '--reuid=1002', '--regid=65534', '--clear-groups', launcher,
                       '--mount', linux, '--compatibility='+mode, '--application', sys.executable,
                       '--', '-c', script, linux, ok=okay)
        as_user("import os,sys; from pathlib import Path; assert os.geteuid()==1002; p=Path(sys.argv[1]); (p/'UserFile').write_bytes(b'user'); assert (p/'USERFILE').read_bytes()==b'user'")
        assert (linux/'UserFile').read_bytes() == b'user'
        os.setxattr(native, 'system.ntfs_security', root_acl(0x1200a9))
        read_only = "import os,sys,errno; from pathlib import Path; p=Path(sys.argv[1]); assert os.geteuid()==1002; assert (p/'UserFile').read_bytes()==b'user';\ntry: (p/'UserFile').write_bytes(b'bad')\nexcept OSError as e: assert e.errno==errno.EROFS\nelse: raise AssertionError('readonly view allowed writing')"
        as_user(read_only)
        as_user(read_only, mode='linux')
        os.setxattr(linux, 'system.ntfs_security', root_acl(0))
        assert as_user("raise AssertionError('application must not start')", okay=False).returncode == 125
        os.setxattr(linux, 'system.ntfs_security', original)
        print('PASS unprivileged native/Linux selection, writable/read-only access and denied access', flush=True)
        # Unmount the original Linux view while a native handle remains usable.
        run('umount', linux); mounts.remove(linux)
        print('PASS original Linux view unmounted', flush=True)
        (native/'after-unmount').write_bytes(b'last view owns writer')
        print('PASS native view still writes', flush=True)
        run('umount', native); mounts.remove(native)
        print('PASS final native view unmounted', flush=True)
        assert run(ROOT/'target/release/ntfs-chkdsk', '--status', image).stdout.strip() == b'dirty=0'
        assert run('ntfscat', '-f', image, '/after-unmount').stdout == b'last view owns writer'
        print('PASS shared writer lifetime, final clean unmount and NTFS-3G readback', flush=True)
    finally:
        for target in reversed(mounts): run('umount', target)
        if loop: run('losetup', '-d', loop)
        run('rmmod', 'slate_ntfs')


if __name__ == '__main__': main()
