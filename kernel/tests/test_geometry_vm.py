#!/usr/bin/env python3
"""Module: kernel.tests.geometry_vm
Purpose: Test mounted deletion on a copied geometry or extent-layout fixture.
Created: 2026-10-21
Architecture: Reuses the isolated RAM-root guest staging and boot framework;
checks clean unmount, allocation audit and source-image preservation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

import test_shutdown_vm as guest

BOOT_SECTOR_BYTES = 512
BYTES_PER_SECTOR_OFFSET = 11
FIELD_BYTES = 2

CONTROLLER = r'''#!/bin/sh
# Module: kernel.tests.geometry_controller
# Purpose: Run mounted deletion against one private image.
# Created: 2026-10-21
# Architecture: Only the disposable systemd guest executes these operations.
set -eu
export PATH=/bin:/usr/bin:/usr/sbin
root='/media/x/Novo volume'
fail()
{
    echo D26_FAILED
    echo D28_FAILED
    dmesg
    trap - EXIT
    systemctl poweroff
    exit 1
}
trap fail EXIT
mkdir -p "$root"
view=$(cat /etc/d26-view)
mount -t ntfsrs -o "rw,compatibility=$view,permissions=desktop,uid=1000,gid=1000,sidmap=@SID_MAP@" /dev/vda "$root"
test-geometry-guest "$root"
sync
umount "$root"
ntfs-chkdsk --recovery-status /dev/vda
echo D28_PASS
trap - EXIT
systemctl poweroff
'''


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['module', 'kernel', 'checker', 'fixture', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--view', choices=['ntfs', 'linux'], required=True)
    args = parser.parse_args()
    for name in ['module', 'kernel', 'checker', 'fixture', 'output']:
        setattr(args, name, getattr(args, name).resolve())
    if not args.fixture.is_file():
        parser.error('--fixture must be a disposable regular file')
    args.case = 'geometry'
    with args.fixture.open('rb') as source:
        boot = source.read(BOOT_SECTOR_BYTES)
    args.device_sector_bytes = int.from_bytes(boot[BYTES_PER_SECTOR_OFFSET:BYTES_PER_SECTOR_OFFSET + FIELD_BYTES], 'little')
    args.kernel_version = subprocess.check_output(['modinfo', '-F', 'vermagic', str(args.module)], text=True).split()[0]
    args.output.mkdir(parents=True, exist_ok=False)
    source_hash = digest(args.fixture)
    image = args.output / 'volume.img'
    shutil.copyfile(args.fixture, image)
    initrd = guest.stage(args, helper_source=Path(__file__).with_name('test_geometry_guest.c'),
                         helper_name='test-geometry-guest', controller=CONTROLLER)
    text = guest.boot(args, initrd, image, 1)
    assert 'D28_PASS' in text and 'D28_GUEST_PASS' in text
    assert not re.search(r'\b(BUG:|Oops:|Kernel panic|WARNING:)', text), 'kernel diagnostics require investigation'
    status = guest.check_image(args, image, 0)
    checked = subprocess.run([str(args.checker), '--check', str(image)], capture_output=True, text=True)
    (args.output / 'check.log').write_text(checked.stdout + checked.stderr)
    assert checked.returncode == 0, checked.stdout + checked.stderr
    assert digest(args.fixture) == source_hash, 'source fixture changed'
    result = dict(view=args.view, source=str(args.fixture), source_sha256=source_hash,
                  module_sha256=digest(args.module), final_status=status,
                  kernel=args.kernel_version, device_sector_bytes=args.device_sector_bytes, result=str(image))
    (args.output / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
