#!/usr/bin/env python3
"""Module: kernel.tests.deletion_matrix_guest
Purpose: Exercise deletion permissions, open handles and native fixtures.
Created: 2026-10-21
Architecture: Runs inside the isolated guest; existing GIO and descriptor
helpers drive production VFS operations with explicit user identities.
"""
import errno
import hashlib
import json
import os
import shutil
from pathlib import Path
import socket
import subprocess
import sys
import traceback

sys.path.insert(0, '/test-source/src/tests/writer')
sys.path.insert(0, '/test-source/kernel/tests')
import test_metadata_writer as metadata
import test_file_deletion as trash

OWNER = 1000
OTHER = 1001
OWNER_SID = 'S-1-5-32-544'
GROUP_SID = 'S-1-22-2-1000'
SYSTEM_SID = 'S-1-5-18'
EVERYONE_SID = 'S-1-1-0'
FULL_CONTROL = 0x1f01ff
DELETE = 0x10000
DELETE_CHILD = 0x40
ALLOW = 0
DENY = 1
PRIVATE_MODE = 0o700
STICKY_MODE = 0o1777
OPEN_MODE = 0o777
READ_ONLY = 0o444
SECURITY_XATTR = 'system.ntfs_security'
DOS_ATTRIBUTES_XATTR = 'system.ntfs_attrib'
DOS_READ_ONLY = 0x1
DOS_HIDDEN = 0x2
DOS_SYSTEM = 0x4
EXPECTED_DENIAL = (errno.EACCES, errno.EPERM)


def denied(operation, errors=EXPECTED_DENIAL):
    try:
        operation()
    except OSError as error:
        assert error.errno in errors, error
    else:
        raise AssertionError('Forbidden operation succeeded')


def as_user(uid, gid, operation, groups=()):
    pid = os.fork()
    if pid == 0:
        try:
            os.setgroups(groups)
            os.setgid(gid)
            os.setuid(uid)
            operation()
        except BaseException:
            traceback.print_exc()
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0, (uid, gid, status)


def basic(root, view):
    base = root / 'deletion-basics'
    base.mkdir()
    child = base / 'directory'
    child.mkdir()
    payload = child / 'payload'
    payload.write_bytes(b'open-file witness')
    denied(child.rmdir, (errno.ENOTEMPTY,))
    with payload.open('r+b') as stream:
        os.fsync(stream.fileno())
        payload.unlink()
        assert stream.read() == b'open-file witness'
        stream.seek(0)
        stream.write(b'held')
        stream.flush()
        os.fsync(stream.fileno())
        assert os.fstat(stream.fileno()).st_nlink == 0
    old = Path.cwd()
    os.chdir(child)
    try:
        child.rmdir()
        denied(Path.cwd, (errno.ENOENT,))
    finally:
        os.chdir(old)
    target = base / 'target'
    target.write_bytes(b'symlink witness')
    link = base / 'link'
    link.symlink_to('target')
    assert link.read_bytes() == target.read_bytes()
    link.unlink()
    assert target.read_bytes() == b'symlink witness'
    fifo = base / 'fifo'
    if view == 'linux':
        os.mkfifo(fifo)
        fifo.unlink()
    else:
        denied(lambda: os.mkfifo(fifo), (errno.EPERM, errno.EOPNOTSUPP))
    unix = base / 'socket'
    with socket.socket(socket.AF_UNIX) as endpoint:
        if view == 'linux':
            endpoint.bind(str(unix))
            unix.unlink()
        else:
            denied(lambda: endpoint.bind(str(unix)), (errno.EPERM, errno.EOPNOTSUPP))
    target.unlink()
    base.rmdir()
    print('D02_D16_D22_PASS', flush=True)


def desktop(root, view, native):
    as_user(OWNER, OWNER, lambda: basic(root, view))
    path = root / 'group-writable'
    as_user(OTHER, OWNER, lambda: path.write_bytes(b'primary group'))
    as_user(OTHER, OWNER, path.unlink)
    as_user(OTHER, OTHER, lambda: path.write_bytes(b'supplementary group'), groups=(OWNER,))
    as_user(OTHER, OTHER, path.unlink, groups=(OWNER,))
    as_user(OTHER, OTHER, lambda: denied(lambda: path.write_bytes(b'forbidden')))
    hint = root / '.hidden'
    assert hint.is_file()
    as_user(OWNER, OWNER, lambda: denied(hint.unlink, (errno.EACCES, errno.EPERM, errno.EROFS)))
    for name in ['$MFT', '$Bitmap', '$LogFile']:
        as_user(OWNER, OWNER, lambda name=name: denied(lambda: (root / name).unlink(),
                (errno.EACCES, errno.EPERM, errno.EOPNOTSUPP, errno.ENOENT)))
    trash.UID = OWNER
    trash.GID = OWNER
    try:
        trash.check_trash(root, view, native)
    except subprocess.CalledProcessError as error:
        print('GIO_CHECK_STDERR:', error.stderr, flush=True)
        raise
    if native:
        def retire_native():
            witness = root / 'native-witness.bin'
            before = hashlib.sha256(witness.read_bytes()).hexdigest()
            for name in ['encrypted.bin', 'streams.bin', 'sparse.bin', 'native-link']:
                (root / name).unlink()
            family = root / 'sparse-family.bin'
            if family.exists():
                family.unlink()
                print('D18_SPARSE_FAMILY_PASS', flush=True)
            assert hashlib.sha256(witness.read_bytes()).hexdigest() == before
        as_user(OWNER, OWNER, retire_native)
        print('D19_D21_D22_NATIVE_PASS', flush=True)
    print('D10_D14_D15_PASS', flush=True)



def repository(root, view):
    source_root = Path('/repository-fixture')
    expected = json.loads((source_root / 'repository-manifest.json').read_text())
    seed = source_root / 'tree'
    ram = Path('/home/x/repository-moves')
    ram.mkdir()
    os.chown(ram, OWNER, OWNER)

    def contents(tree):
        return {str(path.relative_to(tree)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in tree.rglob('*') if path.is_file()}

    def git_check(tree):
        subprocess.run(['git', '-C', str(tree), 'fsck', '--strict'], check=True)
        head = subprocess.check_output(['git', '-C', str(tree), 'rev-parse', 'HEAD'], text=True).strip()
        assert head == expected['head']
        assert contents(tree) == expected['files']

    def protect(tree):
        for relative in ['.git', 'system.dat']:
            path = tree / relative
            raw = os.getxattr(path, DOS_ATTRIBUTES_XATTR)
            flags = int.from_bytes(raw, 'little') | DOS_HIDDEN | DOS_SYSTEM
            os.setxattr(path, DOS_ATTRIBUTES_XATTR, flags.to_bytes(len(raw), 'little'))
        # Desktop mount masks do not import a RAM file's chmod as a DOS flag.
        # Set the native read-only bit explicitly to reproduce Git object denial.
        for path in (tree / '.git/objects').glob('*/*'):
            if path.is_file():
                raw = os.getxattr(path, DOS_ATTRIBUTES_XATTR)
                flags = int.from_bytes(raw, 'little') | DOS_READ_ONLY
                os.setxattr(path, DOS_ATTRIBUTES_XATTR, flags.to_bytes(len(raw), 'little'))

    def exercise():
        source = root / 'Work/Programming/Rust/Open Volar S/Github files/Open Volar S'
        source.parent.mkdir(parents=True)
        shutil.copytree(seed, source)
        git_check(source)
        protect(source)
        readonly = source / expected['readonly_object']
        denied(lambda: readonly.open('ab'), (errno.EACCES, errno.EPERM))
        info = subprocess.check_output(['gio', 'info', '-a', 'access::can-write,access::can-delete', str(readonly)],
                                       text=True, env={**os.environ, 'LC_ALL': 'C', 'GIO_USE_VFS': 'local'})
        assert 'access::can-delete: TRUE' in info and 'access::can-write: FALSE' in info, info
        destination = ram / 'Open Volar S'
        assert source.stat().st_dev != ram.stat().st_dev
        environment = {**os.environ, 'GIO_USE_VFS': 'local'}
        subprocess.run(['gio-repository', 'move-tree', str(source), str(destination)], check=True, env=environment)
        assert not source.exists()
        git_check(destination)
        retained = root / 'repository-move-witness'
        subprocess.run(['gio-repository', 'move-tree', str(destination), str(retained)], check=True, env=environment)
        assert not destination.exists()
        git_check(retained)
        victim = source.parent / 'remove-repository'
        shutil.copytree(seed, victim)
        protect(victim)
        subprocess.run(['gio-repository', 'remove-tree', str(victim)], check=True, env=environment)
        assert not victim.exists()
        after = root / 'after-repository-delete'
        after.write_bytes(b'writer remains usable')
        after.unlink()
        (root / 'repository-manifest.json').write_text(json.dumps(expected, sort_keys=True) + '\n')
        print(f'D09_D12_D29_REPOSITORY_PASS view={view} files={len(expected["files"])} head={expected["head"]}', flush=True)

    as_user(OWNER, OWNER, exercise)
    ram.rmdir()
    print('D09_D12_D29_REPOSITORY_PASS', flush=True)


def security(path, *, deny=0, allow=FULL_CONTROL):
    entries = [metadata.ace(ALLOW, metadata.sid_text(SYSTEM_SID), FULL_CONTROL)]
    if deny:
        entries.append(metadata.ace(DENY, metadata.sid_text(OWNER_SID), deny))
    entries.append(metadata.ace(ALLOW, metadata.sid_text(OWNER_SID), allow))
    descriptor = metadata.descriptor(metadata.sid_text(SYSTEM_SID), metadata.sid_text(OWNER_SID), entries)
    os.sync()
    os.setxattr(path, SECURITY_XATTR, descriptor)
    os.sync()


def strict(root):
    parent = root / 'strict-delete'
    parent.mkdir()
    for parent_right, child_right in [(False, False), (True, False), (False, True), (True, True)]:
        path = parent / 'victim'
        path.write_bytes(b'ACL witness')
        security(parent, deny=0 if parent_right else DELETE_CHILD)
        security(path, deny=0 if child_right else DELETE)
        operation = path.unlink if parent_right or child_right else lambda: denied(path.unlink)
        as_user(OWNER, OWNER, operation)
        if path.exists():
            path.unlink()
    security(parent)
    parent.rmdir()
    print('D13_DELETE_OR_DELETE_CHILD_PASS', flush=True)


def linux_flags(root):
    parent = root / 'linux-flags'
    parent.mkdir()
    os.chmod(parent, STICKY_MODE)
    os.chown(parent, OWNER, OWNER)
    descriptor = metadata.descriptor(metadata.sid_text(OWNER_SID), metadata.sid_text(GROUP_SID),
                                     [metadata.ace(ALLOW, metadata.sid_text(EVERYONE_SID), FULL_CONTROL)])
    os.setxattr(parent, SECURITY_XATTR, descriptor)
    protected = parent / 'owner-file'
    as_user(OWNER, OWNER, lambda: protected.write_bytes(b'sticky witness'))
    as_user(OTHER, OTHER, lambda: denied(protected.unlink))
    as_user(OWNER, OWNER, protected.unlink)
    for flag in ['i', 'a']:
        path = parent / ('flag-' + flag)
        path.write_bytes(b'flag witness')
        subprocess.run(['chattr', '+' + flag, str(path)], check=True)
        try:
            denied(path.unlink, (errno.EPERM,))
        finally:
            subprocess.run(['chattr', '-' + flag, str(path)], check=True)
        path.unlink()
    parent.rmdir()
    print('D14_STICKY_IMMUTABLE_APPEND_PASS', flush=True)


def read_only(root):
    path = root / 'ro-witness'
    directory = root / 'ro-directory'
    for operation in [path.unlink, directory.rmdir, lambda: path.rename(root / 'forbidden-rename'),
                      lambda: (root / 'forbidden-create').write_bytes(b'denied')]:
        as_user(OWNER, OWNER, lambda operation=operation: denied(operation, (errno.EROFS,)))
    assert path.read_bytes() == b'read-only witness'
    print('D15_READ_ONLY_NAMESPACE_PASS', flush=True)


if __name__ == '__main__':
    phase, location, view, native = sys.argv[1:]
    root = Path(location)
    if phase == 'desktop':
        desktop(root, view, native == 'native')
        as_user(OWNER, OWNER, lambda: (root / 'ro-witness').write_bytes(b'read-only witness'))
        as_user(OWNER, OWNER, lambda: (root / 'ro-directory').mkdir())
    elif phase == 'repository':
        repository(root, view)
    elif phase == 'strict':
        strict(root)
    elif phase == 'linux-flags':
        linux_flags(root)
    elif phase == 'read-only':
        read_only(root)
    else:
        raise ValueError(phase)
