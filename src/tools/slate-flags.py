#!/usr/bin/env python3
"""
Module: slate_flags
Purpose: Save and restore explicit Linux flag snapshots for NTFS files.
Created: 2026-10-01
Architecture: The command verifies filesystem identity before applying stored flag policy.

Explicit Linux-flag snapshot/restore on a quiescent Slate Linux mount.

The ordinary hidden/system file .slate-metadata/linux-flags is not a security
boundary. Windows administrators can change it. No path-based restoration,
background daemon, mount hook, private NTFS attributes, or recovery-log changes.
"""
import argparse
import array
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import subprocess

DIRECTORY = '.slate-metadata'
BACKUP = 'linux-flags'
EA = 'system.ntfs_linux_flags'
SUPPORTED = 0xf0
LIBC = ctypes.CDLL(None, use_errno=True)


def identity(fd):
    # name_to_handle_at(AT_EMPTY_PATH), using the driver's existing export ABI.
    handle = ctypes.create_string_buffer(struct.pack('Ii', 128, 0) + bytes(128))
    mount = ctypes.c_int()
    if LIBC.name_to_handle_at(fd, b'', handle, ctypes.byref(mount), 0x1000):
        raise OSError(ctypes.get_errno(), 'name_to_handle_at')
    size, kind, reference, policy = struct.unpack_from('IiQI', handle.raw)
    if kind != 0x91 or size != 12 or policy & 1:
        raise ValueError('requires a Slate compatibility=linux mount')
    data = ctypes.create_string_buffer(256)
    if LIBC.statx(fd, b'', 0x1000, 0x800, data):
        raise OSError(ctypes.get_errno(), 'statx')
    if not struct.unpack_from('I', data.raw)[0] & 0x800:
        raise ValueError('birth time unavailable; refusing weaker identity')
    birth = list(struct.unpack_from('qI', data.raw, 80))
    return mount.value, {'reference': str(reference), 'birth': birth}


def key(item):
    return item['reference'], tuple(item['birth'])


def raw_flags(fd):
    try:
        value = os.getxattr(fd, EA)
    except OSError as error:
        if error.errno == errno.ENODATA:
            return None
        raise
    if len(value) != 4:
        raise ValueError('invalid Linux flag EA')
    flags, = struct.unpack('<I', value)
    if flags & ~SUPPORTED:
        raise ValueError('unsupported Linux flags')
    return flags


def volume_serial(mount_id):
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left, right = line.split(' - ', 1)
        if int(left.split()[0]) != mount_id:
            continue
        filesystem, source, _ = right.split(' ', 2)
        if filesystem != 'ntfsrs':
            raise ValueError('not a Slate mount')
        source = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), source)
        serial = subprocess.check_output(
            ['blkid', '-p', '-s', 'UUID', '-o', 'value', source], text=True).strip()
        if not re.fullmatch('[0-9A-Fa-f]{16}', serial):
            raise ValueError('cannot identify NTFS volume serial')
        return serial.upper()
    raise ValueError('mount disappeared')


def scan(root, mount_id):
    found = {}
    def walk(directory, prefix):
        names = ['.'] if not prefix else []
        names += sorted(os.listdir(directory))
        for name in names:
            if not prefix and name == DIRECTORY:
                continue
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            # Reserved NTFS records (including the $Extend subtree) cannot
            # carry user Linux flag policy. Do not open their protected data.
            if info.st_ino < 24 and info.st_ino != 5:
                continue
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                continue
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                current_mount, item = identity(fd)
                if current_mount != mount_id:
                    raise ValueError('nested mounts must be unmounted before scanning')
                item['path'] = prefix + name
                item['flags'] = raw_flags(fd)
                found.setdefault(key(item), item)
                if stat.S_ISDIR(os.fstat(fd).st_mode) and name != '.':
                    walk(fd, prefix + name + '/')
            finally:
                os.close(fd)
    walk(root, '')
    return found


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def read_backup(directory, serial):
    fd = os.open(BACKUP, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_size > 16 << 20
                or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1):
            raise ValueError('invalid backup file')
        envelope = json.loads(stream.read())
    payload = envelope['payload']
    if hashlib.sha256(canonical(payload)).hexdigest() != envelope['sha256']:
        raise ValueError('backup checksum mismatch')
    if payload['version'] != 1 or payload['volume_serial'] != serial:
        raise ValueError('backup version or volume mismatch')
    seen = set()
    for item in payload['files']:
        reference = int(item['reference'])
        birth = item['birth']
        if not (0 < reference < 1 << 64 and reference >> 48
                and isinstance(birth, list) and len(birth) == 2
                and all(type(n) is int for n in birth) and 0 <= birth[1] < 1000000000
                and type(item['flags']) is int and 0 < item['flags'] <= SUPPORTED
                and item['flags'] & ~SUPPORTED == 0 and isinstance(item['path'], str)):
            raise ValueError('invalid backup entry')
        if key(item) in seen:
            raise ValueError('duplicate backup identity')
        seen.add(key(item))
    return payload['files']


def hidden(fd):
    flags, = struct.unpack('<I', os.getxattr(fd, 'system.ntfs_attrib'))
    os.setxattr(fd, 'system.ntfs_attrib', struct.pack('<I', flags | 6))


def save(directory, serial, files):
    payload = {'version': 1, 'volume_serial': serial, 'files': files}
    data = canonical({'payload': payload, 'sha256': hashlib.sha256(canonical(payload)).hexdigest()}) + b'\n'
    if len(data) > 16 << 20:
        raise ValueError('backup exceeds 16 MiB limit')
    temporary = '.flags-' + secrets.token_hex(12)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            hidden(stream.fileno())
            os.fsync(stream.fileno())
        os.replace(temporary, BACKUP, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def open_file(root, path):
    # Paths come only from this scan, never from the backup. Pin every directory
    # with O_NOFOLLOW so rename/symlink races cannot escape the mount.
    fd = os.dup(root)
    try:
        for component in path.split('/'):
            next_fd = os.open(component, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def run(action, path):
    if os.geteuid() != 0:
        raise ValueError('run as root; restoration uses normal SETFLAGS permission checks')
    root = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        mount_id, root_identity = identity(root)
        if int(root_identity['reference']) & 0xffffffffffff != 5:
            raise ValueError('supply the volume root, not a subdirectory')
        serial = volume_serial(mount_id)
        if action == 'snapshot':
            try:
                os.mkdir(DIRECTORY, 0o700, dir_fd=root)
            except FileExistsError:
                pass
        directory = os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        try:
            fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
            info = os.fstat(directory)
            if info.st_uid != 0 or info.st_mode & 0o077:
                raise ValueError('backup directory must be root-owned and mode 0700')
            if identity(directory)[0] != mount_id:
                raise ValueError('backup directory is on another mount')
            hidden(directory)
            old = []
            try:
                old = read_backup(directory, serial)
            except FileNotFoundError:
                if action != 'snapshot':
                    raise
            live = scan(root, mount_id)
            pruned = sum(key(item) not in live for item in old)
            conflicts = restored = 0
            if action == 'snapshot':
                # Do not silently destroy the last backup after Windows removed
                # an EA. The caller must explicitly restore it first.
                if any(key(item) in live and live[key(item)]['flags'] is None for item in old):
                    raise ValueError('missing live EAs: run restore before a new snapshot')
                files = [item for item in live.values() if item['flags']]
            else:
                files = []
                for item in old:
                    current = live.get(key(item))
                    if current is None:
                        print('pruned deleted/replaced:', item['path'])
                        continue
                    fd = open_file(root, current['path'])
                    try:
                        now_mount, now = identity(fd)
                        if now_mount != mount_id or key(now) != key(item) or not os.fstat(fd).st_nlink:
                            raise ValueError('file changed during scan; stop writers and retry')
                        flags = raw_flags(fd)
                        if action == 'restore':
                            if flags is None:
                                bits = array.array('L', [0])
                                fcntl.ioctl(fd, 0x80086601, bits, True)
                                bits[0] = (bits[0] & ~SUPPORTED) | item['flags']
                                fcntl.ioctl(fd, 0x40086602, bits, True)
                                os.fsync(fd)
                                restored += 1
                                print('restored:', current['path'])
                            elif flags != item['flags']:
                                conflicts += 1
                                print('preserved existing flags:', current['path'])
                        # Refresh from the same pinned file. Explicit zero
                        # clears its backup too; prune retains missing EAs.
                        flags = raw_flags(fd)
                    finally:
                        os.close(fd)
                    if flags is None or flags:
                        files.append(dict(current, flags=item['flags'] if flags is None else flags))
                    else:
                        pruned += 1
            save(directory, serial, files)
            os.fsync(root)
            print(f'{action}: {len(files)} entries, {restored} restored, {pruned} pruned, {conflicts} conflicts')
        finally:
            os.close(directory)
    finally:
        os.close(root)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('snapshot', 'restore', 'prune'))
    parser.add_argument('mount', help='quiescent Slate Linux-view volume root')
    args = parser.parse_args()
    try:
        run(args.action, args.mount)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'slate-flags: {error}\n')
