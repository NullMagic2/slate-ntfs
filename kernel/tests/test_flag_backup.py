#!/usr/bin/env python3
"""
Module: kernel.tests.test_flag_backup
Purpose: Fresh mounted backup validation; never touches an existing volume.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Fresh mounted backup validation; never touches an existing volume.
"""
import array, errno, fcntl, hashlib, json, os, subprocess, tempfile
from pathlib import Path
from run_wsl_fresh_benchmark import run

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / 'src/tools/slate-flags.py'

def flags(path, value):
    fd = os.open(path, os.O_RDONLY)
    try: fcntl.ioctl(fd, 0x40086602, array.array('L', [value]), True)
    finally: os.close(fd)

def invoke(action, mount, success=True):
    result = subprocess.run(['python3', str(TOOL), action, str(mount)], capture_output=True, text=True)
    assert (result.returncode == 0) == success, result.stdout + result.stderr
    print(result.stdout or result.stderr, end='', flush=True)

run('insmod', str(ROOT/'kernel/slate-ntfs.ko'))
try:
    with tempfile.TemporaryDirectory(prefix='slate-flag-backup-', dir='/var/tmp') as temporary:
        base = Path(temporary); image = base/'fresh.img'; mount = base/'mount'; mount.mkdir()
        with image.open('xb') as stream: stream.truncate(64 << 20)
        run('mkntfs', '-F', '-Q', '-c', '4096', str(image), capture_output=True)
        loop = run('losetup', '--find', '--show', str(image), capture_output=True, text=True).stdout.strip()
        try:
            run('mount', '-t', 'ntfsrs', '-o', 'rw,compatibility=linux,sidmap=u:0:S-1-5-32-544;g:0:S-1-5-18', loop, str(mount))
            try:
                target = mount/'target'; target.write_bytes(b'unchanged')
                flags(target, 0x40); invoke('snapshot', mount)
                backup = mount/'.slate-metadata'/'linux-flags'; original = backup.read_bytes()
                backup.write_bytes(original.replace(b'"version":1', b'"version":2'))
                invoke('restore', mount, False)
                assert int.from_bytes(os.getxattr(target, 'system.ntfs_linux_flags'), 'little') == 0x40
                envelope = json.loads(original)
                envelope['payload']['volume_serial'] = '0000000000000000'
                envelope['sha256'] = hashlib.sha256(json.dumps(envelope['payload'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
                backup.write_text(json.dumps(envelope)); invoke('restore', mount, False)
                backup.write_bytes(original)
                flags(target, 0); invoke('restore', mount)
                assert json.loads(backup.read_text())['payload']['files'] == []
                flags(target, 0x40); invoke('snapshot', mount)
                target.unlink(); target.write_bytes(b'replacement')
                invoke('restore', mount)
                assert json.loads(backup.read_text())['payload']['files'] == []
                assert target.read_bytes() == b'replacement'
                try: os.getxattr(target, 'system.ntfs_linux_flags')
                except OSError as error: assert error.errno == errno.ENODATA
                else: raise AssertionError('replacement inherited stale flags')
                # Backup symlinks cannot redirect reads or writes outside the
                # reserved directory, even if their target is valid JSON.
                backup.unlink(); os.symlink('../target', backup)
                invoke('snapshot', mount, False)
                assert target.read_bytes() == b'replacement'
                backup.unlink(); invoke('snapshot', mount)
                flags(target, 0x40); invoke('snapshot', mount)
                target.unlink(); invoke('snapshot', mount)
                assert json.loads(backup.read_text())['payload']['files'] == []
                print('PASS damaged/wrong-volume backups refused; zero preserved; deletion/reuse pruned; symlink refused', flush=True)
            finally: run('umount', str(mount))
        finally: run('losetup', '-d', loop)
finally: run('rmmod', 'slate_ntfs')
