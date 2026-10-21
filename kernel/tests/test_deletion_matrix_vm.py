#!/usr/bin/env python3
"""Module: kernel.tests.deletion_matrix_vm
Purpose: Run missing deletion checks on private mounted image copies.
Created: 2026-10-21
Architecture: Reuses the shutdown guest and existing GIO/ACL helpers;
the host verifies image identity, clean shutdown and complete consistency.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

import test_shutdown_vm as guest

REPO = Path(__file__).resolve().parents[2]
PYTHON = Path('/usr/bin/python3.14')
STDLIB = Path('/usr/lib/python3.14')
OTHER_USER_MAP = ';u:1001:S-1-22-1-1001;g:1001:S-1-22-2-1001'

CONTROLLER = r'''#!/bin/sh
# Module: kernel.tests.deletion_matrix_controller
# Purpose: Exercise namespace changes under explicit mount policies.
# Created: 2026-10-21
# Architecture: Runs only against the private guest's copied data disk.
set -eu
export PATH=/bin:/usr/bin:/usr/sbin
root='/media/x/Novo volume'
view=$(cat /etc/d26-view)
native=$(cat /etc/deletion-native)
fail()
{
    echo D26_FAILED
    dmesg
    trap - EXIT
    systemctl poweroff
    exit 1
}
trap fail EXIT
mkdir -p "$root"
desktop="compatibility=$view,permissions=desktop,uid=1000,gid=1000,fmask=0017,dmask=0007,sidmap=@SID_MAP@"
mount -t ntfsrs -o "rw,$desktop" /dev/vda "$root"
if [ -d /repository-fixture ]; then
    python3 /bin/test-deletion-matrix-guest.py repository "$root" "$view" "$native"
fi
python3 /bin/test-deletion-matrix-guest.py desktop "$root" "$view" "$native"
sync
umount "$root"
mount -t ntfsrs -o 'rw,compatibility=ntfs,permissions=windows,sidmap=@SID_MAP@' /dev/vda "$root"
python3 /bin/test-deletion-matrix-guest.py strict "$root" "$view" "$native"
sync
umount "$root"
mount -t ntfsrs -o 'rw,compatibility=linux,permissions=windows,sidmap=@SID_MAP@' /dev/vda "$root"
python3 /bin/test-deletion-matrix-guest.py linux-flags "$root" "$view" "$native"
sync
umount "$root"
mount -t ntfsrs -o "ro,$desktop" /dev/vda "$root"
python3 /bin/test-deletion-matrix-guest.py read-only "$root" "$view" "$native"
umount "$root"
ntfs-chkdsk --recovery-status /dev/vda
echo DELETION_MATRIX_PASS
trap - EXIT
systemctl poweroff
'''


def stage_extra(root, native, repository_fixture=None):
    guest.copy_program(root, PYTHON)
    (root / 'usr/bin/python3').symlink_to(PYTHON.name)
    shutil.copytree(STDLIB, root / str(STDLIB).lstrip('/'),
                    ignore=shutil.ignore_patterns('__pycache__', 'test', 'site-packages'))
    for program in ['/usr/bin/gio', '/usr/bin/chattr', '/usr/bin/mv', '/usr/bin/ln']:
        guest.copy_program(root, program)
    files = {
        'kernel/tests/test_deletion_matrix_guest.py': 'bin/test-deletion-matrix-guest.py',
        'kernel/tests/test_file_deletion.py': 'test-source/kernel/tests/test_file_deletion.py',
        'src/tests/writer/test_metadata_writer.py': 'test-source/src/tests/writer/test_metadata_writer.py',
        'tests/support/ntfs_image.py': 'test-source/tests/support/ntfs_image.py',
    }
    for source, destination in files.items():
        path = root / destination
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / source, path)
    (root / 'etc/deletion-native').write_text('native\n' if native else 'ordinary\n')
    if repository_fixture is not None:
        shutil.copytree(repository_fixture, root / 'repository-fixture')
        guest.copy_program(root, '/usr/bin/git')
        flags = subprocess.check_output(['pkg-config', '--cflags', '--libs', 'gio-2.0'], text=True).split()
        helper = root / 'gio-repository'
        subprocess.run(['gcc', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(REPO / 'kernel/tests/test_hidden_moves.c'), '-o', str(helper), *flags], check=True)
        guest.copy_program(root, helper, '/bin/gio-repository')
        helper.unlink()


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['module', 'kernel', 'checker', 'fixture', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--view', choices=['ntfs', 'linux'], required=True)
    parser.add_argument('--native-fixture', action='store_true')
    parser.add_argument('--repository-fixture', type=Path, help='Private Git repository tree for GIO move/delete checks')
    args = parser.parse_args()
    for name in ['module', 'kernel', 'checker', 'fixture', 'output']:
        setattr(args, name, getattr(args, name).resolve())
    if not args.fixture.is_file():
        parser.error('Expected a disposable regular image')
    if args.repository_fixture is not None:
        args.repository_fixture = args.repository_fixture.resolve()
        if not (args.repository_fixture / 'tree/.git/HEAD').is_file():
            parser.error('Repository fixture must contain a private Git worktree under tree')
    args.case = 'matrix'
    args.kernel_version = subprocess.check_output(['modinfo', '-F', 'vermagic', str(args.module)], text=True).split()[0]
    args.output.mkdir(parents=True, exist_ok=False)
    before = digest(args.fixture)
    image = args.output / 'volume.img'
    shutil.copyfile(args.fixture, image)
    original_map = guest.SID_MAP
    guest.SID_MAP = guest.SID_MAP.replace('u:0:S-1-5-18', 'u:0:S-1-5-18:security+restore+take-ownership') + OTHER_USER_MAP
    try:
        initrd = guest.stage(args, controller=CONTROLLER, extra_setup=lambda root: stage_extra(root, args.native_fixture, args.repository_fixture))
    finally:
        guest.SID_MAP = original_map
    text = guest.boot(args, initrd, image, 1)
    assert 'DELETION_MATRIX_PASS' in text
    assert not re.search(r'\b(BUG:|Oops:|Kernel panic|WARNING:)', text)
    status = guest.check_image(args, image, 0)
    check = subprocess.run([str(args.checker), '--check', str(image)], capture_output=True, text=True)
    (args.output / 'check.log').write_text(check.stdout + check.stderr)
    assert check.returncode == 0, check.stdout + check.stderr
    assert digest(args.fixture) == before
    result = dict(view=args.view, native=args.native_fixture, source=str(args.fixture),
                  source_sha256=before, module_sha256=digest(args.module), status=status,
                  checks=re.findall(r'^D\d[^\n]*PASS$', text, re.MULTILINE), result=str(image))
    (args.output / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
