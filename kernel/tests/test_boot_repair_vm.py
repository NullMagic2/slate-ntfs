#!/usr/bin/env python3
"""Module: kernel.tests.boot_repair_vm
Purpose: Exercise durable repair scheduling and mount ordering on private disks.
Created: 2026-11-24
Architecture: Reuses the RAM-root systemd guest; disposable NTFS and ext4 images
retain the request, external journal and evidence across separate guest boots.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace

import test_shutdown_vm as guest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'src/tests/checker'))
from test_readonly_assessment import Image, integer, put
MIB = 1024 * 1024
DATA_BYTES = 64 * MIB
STORE_BYTES = 512 * MIB
DUMMY_BYTES = 8 * MIB
BOOT_TIMEOUT_SECONDS = 120
POLL_SECONDS = 0.1
STOP_AFTER_SYNC = 5
DIRECTORY_MODE = 0o755
VOLUME_RECORD = 3
VOLUME_INFORMATION_ATTRIBUTE = 0x70
VOLUME_FLAGS_OFFSET = 10
FLAGS_BYTES = 2
DIRTY_FLAG = 1
SID_MAP = guest.SID_MAP

CONTROLLER = r'''#!/bin/sh
# Module: kernel.tests.boot_repair_controller
# Purpose: Check the scheduling contract within one isolated guest boot.
# Created: 2026-11-24
# Architecture: The real checker, generator and mount helper operate only on
# disposable virtio devices; the host retains every image and serial log.
set -eu
export PATH=/bin:/usr/bin:/usr/sbin:/sbin
mode=$(cat /etc/b24-mode)
uuid=$(cat /etc/b24-uuid)
device=/dev/disk/by-uuid/$uuid
root=/mnt/data
checker=/usr/sbin/ntfs-chkdsk
storage=/mnt/state/repair
fail()
{
    echo B24_FAILED
    systemctl --no-pager --full status "slate-ntfs-repair-$uuid.service" mnt-data.mount || true
    journalctl --no-pager -b -n 60 || true
    dmesg
    trap - EXIT
    systemctl poweroff
    exit 1
}
trap fail EXIT
udevadm settle --timeout=20
mkdir -p "$root" /mnt/guard
case "$mode" in
    prepare)
        mount -i -t ntfsrs -o "rw,compatibility=linux,sidmap=@SID_MAP@" "$device" "$root"
        printf 'retained B24 file contents\n' > "$root/witness.txt"
        mkdir -p "$root/bin" "$root/sbin" "$root/dev" "$root/proc" "$root/sys" "$root/run"
        cp /bin/busybox "$root/bin/busybox"
        cp /etc/b24-root-init "$root/sbin/init"
        chmod 0755 "$root/bin/busybox" "$root/sbin/init"
        sync
        umount "$root"
        ;;
    schedule)
        mount -i -t ntfsrs -o "ro,sidmap=@SID_MAP@" "$device" "$root"
        "$checker" --repair-storage "$storage" --schedule-repair "$device"
        "$checker" --schedule-status "$uuid" | grep 'state=pending'
        if "$checker" --boot-repair-pending "$device"; then exit 1; else test "$?" -eq 4; fi
        if /sbin/mount.ntfsrs "$device" /mnt/guard -o "ro,sidmap=@SID_MAP@"; then exit 1; fi
        umount "$root"
        if /usr/sbin/fsck.ntfsrs --check "$device"; then :; else test "$?" -eq 4; fi
        "$checker" --schedule-status "$uuid" | grep 'state=pending'
        ;;
    interrupt)
        if systemctl start mnt-data.mount; then exit 1; fi
        if grep -q " $root " /proc/mounts; then exit 1; fi
        "$checker" --schedule-status "$uuid" | grep 'state=failed'
        test -n "$(find "$storage" -name '*.journal' -print)"
        if "$checker" --cancel-scheduled-repair "$uuid"; then exit 1; fi
        ;;
    resume)
        systemctl start mnt-data.mount
        test "$(cat "$root/witness.txt")" = 'retained B24 file contents'
        "$checker" --schedule-status "$uuid" | grep 'state=not-scheduled'
        test -n "$(find "$storage" -name '*.journal.completed' -print)"
        test -z "$(find "$storage" -name '*.journal' -print)"
        systemctl stop mnt-data.mount
        "$checker" --recovery-status "$device" | grep 'dirty=0'
        "$checker" --check "$device"
        ;;
    cancel)
        "$checker" --repair-storage "$storage" --schedule-repair "$device"
        "$checker" --cancel-scheduled-repair "$device"
        "$checker" --schedule-status "$device" | grep 'state=not-scheduled'
        "$checker" --boot-repair-pending "$device"
        ;;
    busy-policy)
        mount -i -t ntfsrs -o "rw,compatibility=linux,sidmap=@SID_MAP@" "$device" "$root"
        if "$checker" --repair "$device"; then exit 1; else test "$?" -eq 8; fi
        if "$checker" --repair-storage "$storage" --schedule-if-busy --repair "$device"; then
            exit 1
        else
            test "$?" -eq 2
        fi
        "$checker" --schedule-status "$uuid" | grep 'state=pending'
        "$checker" --cancel-scheduled-repair "$uuid"
        if "$checker" --force --unmount --repair "$device"; then :; else test "$?" -eq 1; fi
        if grep -q " $root " /proc/mounts; then exit 1; fi
        ;;
    fsck-entry)
        "$checker" --repair-storage "$storage" --schedule-repair "$device"
        if /usr/sbin/fsck.ntfsrs --repair --force "$device"; then exit 1; else test "$?" -eq 1; fi
        "$checker" --schedule-status "$uuid" | grep 'state=not-scheduled'
        "$checker" --recovery-status "$device" | grep 'dirty=0'
        ;;
    direct-special)
        if "$checker" --repair-log-size=8M --repair-storage "$storage" --repair "$device"; then exit 1; else test "$?" -eq 1; fi
        "$checker" --schedule-status "$uuid" | grep 'state=not-scheduled'
        "$checker" --log-size "$device" | grep 'log_size_bytes=8388608'
        ;;
    special-busy)
        mount -i -t ntfsrs -o "rw,compatibility=linux,sidmap=@SID_MAP@" "$device" "$root"
        if "$checker" --recover-data --repair "$device"; then exit 1; else test "$?" -eq 8; fi
        if "$checker" --rescan-bad --repair-storage "$storage" --schedule-if-busy --repair "$device"; then
            exit 1
        else
            test "$?" -eq 2
        fi
        grep '^reassess$' /etc/slate-ntfs/boot-repair/$uuid.job
        "$checker" --cancel-scheduled-repair "$uuid"
        umount "$root"
        ;;
    index-schedule)
        "$checker" --index-check=quick --index-cache-passes=0 --repair-log-size=8M --repair-storage "$storage" --schedule-repair "$device"
        "$checker" --schedule-status "$uuid" | grep 'state=pending'
        ;;
    intent-tamper)
        config=/etc/slate-ntfs/boot-repair/$uuid.job
        cp "$config" /tmp/original-job
        sed -i 's/^8388608$/12582912/' "$config"
        if "$checker" --run-scheduled-repair "$uuid"; then exit 1; else test "$?" -eq 8; fi
        cp /tmp/original-job "$config"
        if "$checker" --index-check=full --repair "$device"; then exit 1; else test "$?" -eq 8; fi
        "$checker" --schedule-status "$uuid" | grep 'state=pending'
        ;;
    index-interrupt|resize-interrupt|surface-interrupt|reassess-interrupt|surface-completed-interrupt|resize-completed-interrupt)
        "$checker" --schedule-status "$uuid" | grep 'state=failed'
        case "$mode" in
            *-completed-interrupt) test -n "$(find "$storage" -name '*.journal.completed' -print)" ;;
            *)
                test -n "$(find "$storage" -name '*.journal' -print)"
                if "$checker" --cancel-scheduled-repair "$uuid"; then exit 1; fi
                ;;
        esac
        ;;
    completed-tamper)
        step=$(find "$storage" -name step -exec grep -l '^surface$' '{}' ';' | tail -n 1)
        job=${step%/step}
        cp "$job/surface.journal.completed" /tmp/original-completed
        printf X | dd of="$job/surface.journal.completed" bs=1 count=1 conv=notrunc
        if "$checker" --run-scheduled-repair "$uuid"; then exit 1; else test "$?" -eq 8; fi
        cp /tmp/original-completed "$job/surface.journal.completed"
        ;;
    stage-tamper)
        step=$(find "$storage" -name step -exec grep -l '^repair$' '{}' ';' | tail -n 1)
        test -n "$step"
        printf resize > "$step"
        if "$checker" --run-scheduled-repair "$uuid"; then exit 1; else test "$?" -eq 8; fi
        printf repair > "$step"
        ;;
    index-resume|resize-resume|surface-resume|reassess-resume)
        systemctl start mnt-data.mount
        test "$(cat "$root/witness.txt")" = 'retained B24 file contents'
        "$checker" --schedule-status "$uuid" | grep 'state=not-scheduled'
        systemctl stop mnt-data.mount
        "$checker" --recovery-status "$device" | grep 'dirty=0'
        "$checker" --check "$device"
        case "$mode" in
            index-resume|surface-resume) "$checker" --log-size "$device" | grep 'log_size_bytes=8388608' ;;
            resize-resume) "$checker" --log-size "$device" | grep 'log_size_bytes=12582912' ;;
            reassess-resume) grep -r 'complete_surface_classification=1' "$storage" ;;
        esac
        test -z "$(find "$storage" -name '*.journal' -print)"
        ;;
    resize-schedule)
        "$checker" --repair-log-size=12M --repair-storage "$storage" --schedule-repair "$device"
        ;;
    surface-schedule)
        "$checker" --recover-data --repair-log-size=8M --repair-storage "$storage" --schedule-repair "$device"
        ;;
    reassess-schedule)
        "$checker" --rescan-bad --repair-storage "$storage" --schedule-repair "$device"
        ;;
    unsupported)
        if "$checker" --skip-cycles --repair-storage "$storage" --schedule-repair "$device"; then exit 1; else test "$?" -eq 16; fi
        if "$checker" --recover-data --index-check=quick --repair-storage "$storage" --schedule-repair "$device"; then exit 1; fi
        if "$checker" --repair-log-size=1 --schedule-repair "$device"; then exit 1; else test "$?" -eq 16; fi
        if "$checker" --log /tmp/report --schedule-repair "$device"; then exit 1; else test "$?" -eq 16; fi
        test -z "$(find /etc/slate-ntfs/boot-repair -name '*.job' -print)"
        ;;
    root-schedule)
        "$checker" --rescan-bad --repair-log-size=8M --repair-storage "$storage" --schedule-repair "$device"
        "$checker" --schedule-status "$uuid" | grep 'state=pending'
        ;;
    root-cleanup)
        "$checker" --schedule-status "$uuid" | grep 'state=not-scheduled'
        "$checker" --log-size "$device" | grep 'log_size_bytes=8388608'
        "$checker" --recovery-status "$device" | grep 'dirty=0'
        "$checker" --check "$device"
        ;;
    duplicate|duplicate-storage)
        if "$checker" --repair-storage "$storage" --schedule-repair /dev/vda; then exit 1; fi
        test -z "$(find /etc/slate-ntfs/boot-repair -name '*.job' -print)"
        ;;
esac
echo "B24_${mode}_PASS"
trap - EXIT
systemctl poweroff
'''


def run(command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def uuid(path):
    return subprocess.check_output(['/sbin/blkid', '-p', '-s', 'UUID', '-o', 'value', str(path)], text=True).strip()


def file_digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def mark_dirty(image):
    # Reuse checked fixture record editing, including mirror publication.

    volume = Image(image)
    try:
        record = volume.get(VOLUME_RECORD)
        value = volume.value(record, volume.attribute(record, VOLUME_INFORMATION_ATTRIBUTE))
        offset = value + VOLUME_FLAGS_OFFSET
        put(record, offset, integer(record, offset, FLAGS_BYTES) | DIRTY_FLAG, FLAGS_BYTES)
        volume.save(VOLUME_RECORD, record)
        volume.file.flush()
        os.fsync(volume.file.fileno())
    finally:
        volume.file.close()


def stage(args, mode, volume_uuid, store_uuid):
    def setup(root):
        for source, destination in [
            (args.checker, '/usr/sbin/ntfs-chkdsk'),
            (args.fsck, '/usr/sbin/fsck.ntfsrs'),
            ('/sbin/blkid', '/sbin/blkid'),
            ('/usr/bin/ntfs-run', '/usr/bin/ntfs-run'),
            ('/usr/bin/udevadm', '/usr/bin/udevadm'),
            ('/usr/bin/mount', '/usr/bin/mount'),
            ('/usr/bin/umount', '/usr/bin/umount'),
            ('/usr/bin/systemd-escape', '/usr/bin/systemd-escape'),
            ('/usr/sbin/fsck', '/usr/sbin/fsck'),
            (args.fsck, '/sbin/fsck.ntfsrs'),
            ('/usr/lib/systemd/systemd-fsck', '/usr/lib/systemd/systemd-fsck'),
            ('/usr/lib/systemd/systemd-udevd', '/usr/lib/systemd/systemd-udevd'),
        ]:
            guest.copy_program(root, source, destination)
        for name in ['cp', 'find', 'stat', 'tail', 'sed', 'awk', 'tr', 'reboot', 'halt']:
            (root / 'bin' / name).symlink_to('busybox')
        shutil.copy2(REPO / 'generate_packages/deb/mount-ntfs', root / 'sbin/mount.ntfsrs')
        (root / 'sbin/mount.ntfsrs').chmod(guest.EXECUTABLE_MODE)
        generator = root / 'usr/lib/systemd/system-generators/slate-ntfs-repair-generator'
        generator.parent.mkdir(parents=True)
        shutil.copy2(REPO / 'boot/systemd/system-generators/slate-ntfs-repair-generator', generator)
        for name in ['systemd-fstab-generator']:
            guest.copy_program(root, '/usr/lib/systemd/system-generators/' + name)
        for name in ['systemd-udevd.service', 'systemd-udevd-control.socket', 'systemd-udevd-kernel.socket',
                     'systemd-udevd-varlink.socket', 'systemd-udev-trigger.service', 'systemd-udev-settle.service',
                     'systemd-fsck@.service']:
            source = Path('/usr/lib/systemd/system') / name
            guest.write(root, '/usr/lib/systemd/system/' + name, source.read_text())
        wants = root / 'etc/systemd/system/sysinit.target.wants'
        wants.mkdir(parents=True, exist_ok=True)
        for name in ['systemd-udevd.service', 'systemd-udev-trigger.service']:
            (wants / name).symlink_to('/usr/lib/systemd/system/' + name)
        for name in ['60-persistent-storage.rules', '99-systemd.rules']:
            source = Path('/usr/lib/udev/rules.d') / name
            guest.write(root, '/usr/lib/udev/rules.d/' + name, source.read_text())
        options = 'noauto,rw,compatibility=ntfs,sidmap=' + SID_MAP
        guest.write(root, '/etc/fstab', f'UUID={volume_uuid} /mnt/data ntfsrs {options} 0 2\n')
        guest.write(root, '/etc/slate-ntfs/sidmap.conf', SID_MAP + '\n')
        guest.write(root, '/etc/b24-root-init', (REPO / 'kernel/tests/root_boot_init').read_text())
        guest.write(root, '/etc/b24-mode', mode + '\n')
        guest.write(root, '/etc/b24-uuid', volume_uuid + '\n')
        guest.write(root, '/etc/systemd/system/d26-controller.service.d/udev.conf',
                    '[Unit]\nAfter=systemd-udev-settle.service\nWants=systemd-udev-settle.service\n')
        if mode in ['interrupt', 'index-interrupt', 'resize-interrupt', 'surface-interrupt', 'reassess-interrupt']:
            guest.write(root, f'/etc/systemd/system/slate-ntfs-repair-{volume_uuid}.service.d/interrupt.conf',
                        f'[Service]\nEnvironment=SLATE_NTFS_TEST_REPAIR_STOP_AFTER_SYNC={STOP_AFTER_SYNC}\n')
        if mode in ['intent-tamper', 'stage-tamper', 'completed-tamper']:
            guest.write(root, f'/etc/systemd/system/slate-ntfs-repair-{volume_uuid}.service.d/hold.conf',
                        '[Unit]\nConditionPathExists=/deliberately-unavailable-scheduled-fixture\n')
        if mode in ['surface-completed-interrupt', 'resize-completed-interrupt']:
            stop_stage = mode.split('-')[0]
            guest.write(root, f'/etc/systemd/system/slate-ntfs-repair-{volume_uuid}.service.d/completed.conf',
                        f'[Service]\nEnvironment=SLATE_NTFS_TEST_SCHEDULE_STOP_AFTER_STAGE={stop_stage}\n')
        init = (root / 'init').read_text()
        setup = f'''
export PATH=/bin:/usr/bin:/sbin:/usr/sbin
mkdir -p /mnt/state /mnt/data /etc/slate-ntfs/boot-repair
chmod 0755 / /mnt /etc /etc/slate-ntfs
state_device=$(/sbin/blkid -U {store_uuid})
mount -t ext4 "$state_device" /mnt/state || poweroff -f
mkdir -p /mnt/state/config
chmod 0700 /mnt/state/config
mount --bind /mnt/state/config /etc/slate-ntfs/boot-repair || poweroff -f
'''
        if mode in ['root-interrupt', 'root-resume']:
            guest.write(root, '/scripts/functions', Path('/usr/share/initramfs-tools/scripts/functions').read_text())
            guest.write(root, '/scripts/local-premount/ntfsrs-repair',
                        (REPO / 'boot/initramfs-tools/scripts/local-premount/ntfsrs-repair').read_text(), True)
            interruption = ''
            if mode == 'root-interrupt':
                interruption = f'export SLATE_NTFS_TEST_REPAIR_STOP_AFTER_SYNC={STOP_AFTER_SYNC}'
            setup += f"""
/usr/lib/systemd/systemd-udevd --daemon
udevadm trigger --action=add --subsystem-match=block
udevadm settle --timeout=20
export ROOT=UUID={volume_uuid} ROOTFSTYPE=ntfsrs panic=-1
{interruption}
echo B24_ROOT_PREMOUNT_STARTED
/bin/sh /scripts/local-premount/ntfsrs-repair || poweroff -f
/usr/sbin/ntfs-chkdsk --recovery-status /dev/disk/by-uuid/{volume_uuid} | grep dirty=0 || poweroff -f
echo B24_ROOT_PREMOUNT_COMPLETED
umount /etc/slate-ntfs/boot-repair
umount /mnt/state
mkdir -p /newroot
mount -i -t ntfsrs -o 'ro,compatibility=linux,sidmap={SID_MAP}' /dev/disk/by-uuid/{volume_uuid} /newroot || poweroff -f
mount --move /dev /newroot/dev
mount --move /proc /newroot/proc
mount --move /sys /newroot/sys
exec /bin/busybox switch_root /newroot /sbin/init
"""
        init = init.replace('exec /usr/lib/systemd/systemd', setup + '\nexec /usr/lib/systemd/systemd')
        guest.write(root, '/init', init, True)
        for directory in root.rglob('*'):
            if directory.is_dir():
                directory.chmod(DIRECTORY_MODE)
        root.chmod(DIRECTORY_MODE)
    return guest.stage(args, controller=CONTROLLER.replace('@SID_MAP@', SID_MAP), extra_setup=setup)


def boot(args, initrd, data, storage, dummy=None, duplicate=None):
    command = ['qemu-system-x86_64', '-machine', 'q35,accel=kvm', '-cpu', 'host', '-m', str(guest.MEMORY_MIB),
               '-smp', str(guest.CPUS), '-display', 'none', '-nic', 'none', '-serial', 'stdio', '-monitor', 'none',
               '-no-reboot', '-kernel', str(args.kernel), '-initrd', str(initrd),
               '-append', 'console=ttyS0 loglevel=5 panic=-1 noresume systemd.unit=d26.target systemd.log_target=console']
    disks = [data, storage]
    if dummy is not None:
        disks = [dummy, storage, data]
    if duplicate is not None:
        disks.append(duplicate)
    for disk in disks:
        command.extend(['-drive', f'file={disk},if=virtio,format=raw,cache=none'])
    log = args.output / 'boot.log'
    with log.open('w') as stream:
        process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT)
        try:
            process.wait(timeout=BOOT_TIMEOUT_SECONDS)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    text = log.read_text(errors='replace')
    expected = f'B24_{args.case}_PASS' in text
    if args.case == 'root-interrupt':
        expected = ('root remains unmounted' in text and 'B24_ROOT_PREMOUNT_COMPLETED' not in text
                    and 'SLATE_NTFS_ROOT_INIT_REACHED' not in text)
    elif args.case == 'root-resume':
        expected = ('B24_ROOT_PREMOUNT_COMPLETED' in text and 'SLATE_NTFS_ROOT_CLEAN_REMOUNT_OK' in text
                    and text.index('B24_ROOT_PREMOUNT_COMPLETED') < text.index('SLATE_NTFS_ROOT_INIT_REACHED'))
    assert process.returncode == 0 and expected, f'Inspect {log}'
    assert 'B24_FAILED' not in text and not re.search(r'\b(BUG:|Oops:|Kernel panic)', text), f'Inspect {log}'
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['kernel', 'module', 'checker', 'fsck', 'formatter', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    cases = ['prepare', 'schedule', 'interrupt', 'resume', 'cancel', 'duplicate', 'busy-policy', 'fsck-entry',
             'duplicate-storage', 'root-schedule', 'root-interrupt', 'root-resume', 'root-cleanup',
             'direct-special', 'special-busy', 'index-schedule', 'intent-tamper', 'index-interrupt', 'stage-tamper', 'index-resume',
             'resize-schedule', 'resize-interrupt', 'resize-resume', 'surface-schedule', 'surface-interrupt',
             'surface-resume', 'reassess-schedule', 'reassess-interrupt', 'reassess-resume', 'unsupported',
             'surface-completed-interrupt', 'resize-completed-interrupt', 'completed-tamper']
    parser.add_argument('--cases', nargs='+', choices=cases,
                        help='Ordered fixture phases; defaults to ordinary data/root scheduling controls')
    options = parser.parse_args()
    for name in ['kernel', 'module', 'checker', 'fsck', 'formatter', 'output']:
        setattr(options, name, getattr(options, name).resolve())
    options.output.mkdir(exist_ok=False)
    data = options.output / 'volume.img'
    storage = options.output / 'storage.img'
    dummy = options.output / 'dummy.img'
    for path, size in [(data, DATA_BYTES), (storage, STORE_BYTES), (dummy, DUMMY_BYTES)]:
        with path.open('xb') as stream:
            stream.truncate(size)
    run([str(options.formatter), str(data), '--yes', '--label', 'B24-DATA'], capture_output=True, text=True)
    run(['/usr/sbin/mkfs.ext4', '-q', '-F', str(storage)], capture_output=True, text=True)
    volume_uuid, store_uuid = uuid(data), uuid(storage)
    results = []
    default_cases = ['prepare', 'schedule', 'interrupt', 'resume', 'cancel', 'duplicate',
                 'busy-policy', 'fsck-entry', 'duplicate-storage',
                 'root-schedule', 'root-interrupt', 'root-resume', 'root-cleanup']
    for mode in options.cases or default_cases:
        if mode in ['schedule', 'fsck-entry', 'root-schedule', 'index-schedule']:
            mark_dirty(data)
        output = options.output / mode
        output.mkdir()
        args = SimpleNamespace(**vars(options))
        args.output, args.case, args.view = output, mode, 'ntfs'
        args.kernel_version = subprocess.check_output(
            ['modinfo', '-F', 'vermagic', str(args.module)], text=True
        ).split()[0]
        initrd = stage(args, mode, volume_uuid, store_uuid)
        duplicate = None
        if mode == 'duplicate':
            duplicate = options.output / 'duplicate.img'
            shutil.copyfile(data, duplicate)
        if mode == 'duplicate-storage':
            duplicate = options.output / 'duplicate-storage.img'
            shutil.copyfile(storage, duplicate)
        unchanged = mode in ['intent-tamper', 'stage-tamper', 'completed-tamper', 'unsupported']
        before = file_digest(data) if unchanged else None
        boot(args, initrd, data, storage, dummy=dummy if mode in ['resume', 'index-resume', 'surface-resume', 'reassess-resume', 'root-resume'] else None, duplicate=duplicate)
        if unchanged:
            assert file_digest(data) == before, f'{mode} changed the NTFS source'
        results.append(dict(case=mode, passed=True, log=str(output / 'boot.log')))
        print(json.dumps(results[-1]), flush=True)
        shutil.rmtree(output / 'root')
        initrd.unlink()
    result = dict(volume_uuid=volume_uuid, storage_uuid=store_uuid, data=str(data), storage=str(storage),
                  module_sha256=file_digest(options.module), results=results)
    (options.output / 'results.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
