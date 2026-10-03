#!/usr/bin/env python3
"""Module: kernel.tests.test_file_deletion
Purpose: Verify permanent deletion and real GIO Trash on disposable NTFS copies.
Created: 2026-10-01
Architecture: Exercises the C/Rust adapter as an ordinary user and unmounts
cleanly. An optional Windows fixture covers compressed streams and DOS aliases.
Only a module not already loaded and private images are used.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
UID, GID = 12345, 23456


def run(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def credentials():
    def drop():
        os.setgroups([])
        os.setgid(GID)
        os.setuid(UID)

    return drop


def user_command(*args):
    return run(
        *args,
        preexec_fn=credentials(),
        capture_output=True,
        text=True,
        env={**os.environ, 'GIO_USE_VFS': 'local'},
    )


def write_file(path, contents):
    user_command(
        'python3', '-c',
        'import pathlib,sys; pathlib.Path(sys.argv[1]).write_text(sys.argv[2])',
        path, contents,
    )


def check_trash(mount, compatibility, windows_source):
    # Real GIO creates the directories, publishes .trashinfo and renames,
    # just as Ubuntu Files does for local Trash.

    path = mount / 'trash-me.txt'
    write_file(path, 'trash content')
    if compatibility == 'ntfs':
        assert user_command('cat', mount / 'TRASH-ME.TXT').stdout == 'trash content'
    user_command('gio', 'trash', path)
    assert not path.exists()
    trash = mount / f'.Trash-{UID}'
    assert (trash / 'files/trash-me.txt').read_text() == 'trash content'
    assert 'Path=trash-me.txt' in (trash / 'info/trash-me.txt.trashinfo').read_text()
    user_command('gio', 'remove', trash / 'files/trash-me.txt')
    user_command('gio', 'remove', trash / 'info/trash-me.txt.trashinfo')
    if windows_source:
        ordinary = mount / 'ordinary long filename.txt'
        user_command('gio', 'trash', ordinary)
        assert not ordinary.exists() and not (mount / 'ORDINA~1.TXT').exists()
        assert (trash / 'files/ordinary long filename.txt').stat().st_nlink == 1
        user_command('gio', 'remove', trash / 'files/ordinary long filename.txt')
        compressed = mount / 'compressed long filename.txt'
        user_command('gio', 'trash', compressed)
        assert not compressed.exists()
        user_command('gio', 'remove', trash / 'files/compressed long filename.txt')
        readonly = mount / 'read only filename.txt'
        if compatibility == 'ntfs':
            # Windows read-only blocks rename as well as unlink.

            for command in [
                ('gio', 'remove', readonly),
                ('mv', readonly, mount / 'renamed.txt'),
            ]:
                result = subprocess.run(
                    [str(arg) for arg in command],
                    preexec_fn=credentials(),
                    capture_output=True,
                )
                assert result.returncode != 0, result
            assert readonly.exists()
    # A cleanup failure poisons the writer. A subsequent create/delete must
    # remain usable after compressed deletion.

    write_file(mount / 'still-writable.txt', 'after deletion')
    user_command('gio', 'remove', mount / 'still-writable.txt')
    # Exercise directory rename and empty-directory GIO Trash.

    user_command('mkdir', mount / 'folder')
    user_command('mv', mount / 'folder', mount / 'moved-folder')
    user_command('gio', 'trash', mount / 'moved-folder')
    user_command('gio', 'remove', trash / 'files/moved-folder')
    write_file(mount / 'keep-source.txt', 'hard-link data')
    user_command('ln', mount / 'keep-source.txt', mount / 'keep-link.txt')
    user_command('mv', mount / 'keep-link.txt', mount / 'keep-renamed.txt')
    assert (mount / 'keep-source.txt').stat().st_nlink == 2
    assert (mount / 'keep-renamed.txt').read_text() == 'hard-link data'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--module', type=Path, default=ROOT / 'kernel/ntfs_rs.ko')
    parser.add_argument('--filesystem', default='ntfsrs')
    parser.add_argument('--windows-source', type=Path)
    parser.add_argument('--workdir', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root on a test host')
    module = run(
        'modinfo', '-F', 'name', args.module, capture_output=True, text=True,
    ).stdout.strip()
    if Path('/sys/module', module).exists():
        parser.error('module is already loaded; existing mounts will not be disturbed')
    mapping = (
        f'u:0:S-1-5-18;g:0:S-1-5-32-544;'
        f'u:{UID}:S-1-5-32-544;g:{GID}:S-1-22-2-{GID}'
    )
    run('insmod', args.module)
    try:
        for compatibility in ('ntfs', 'linux'):
            with tempfile.TemporaryDirectory(
                prefix='slate-delete-', dir=args.workdir,
            ) as temporary:
                base = Path(temporary)
                base.chmod(0o755)
                image = base / 'test.img'
                if args.windows_source:
                    shutil.copyfile(args.windows_source, image)
                else:
                    with image.open('xb') as stream:
                        stream.truncate(128 << 20)
                    run('ntfs-format', image, '--yes', '-c', '4096')
                mount = base / 'mount'
                mount.mkdir()
                loop = run(
                    'losetup', '--find', '--show', image,
                    capture_output=True, text=True,
                ).stdout.strip()
                mounted = False
                try:
                    options = (
                        f'rw,compatibility={compatibility},permissions=desktop,'
                        f'uid={UID},gid={GID},fmask=0017,dmask=0007,sidmap={mapping}'
                    )
                    run('mount', '-i', '-t', args.filesystem, '-o', options, loop, mount)
                    mounted = True
                    check_trash(mount, compatibility, args.windows_source)
                    run('sync', '-f', mount)
                    run('umount', mount)
                    mounted = False
                    status = run(
                        ROOT / 'src/tools/target/release/ntfs-chkdsk',
                        '--status', image, capture_output=True, text=True,
                    ).stdout
                    assert status.strip() == 'dirty=0', status
                    print(
                        f'PASS {compatibility}: GIO Trash, permanent delete, '
                        'subsequent writes and clean shutdown', flush=True,
                    )
                finally:
                    if mounted:
                        run('umount', mount)
                    run('losetup', '-d', loop)
    finally:
        run('rmmod', module)


if __name__ == '__main__':
    main()
