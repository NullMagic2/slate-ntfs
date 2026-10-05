#!/usr/bin/env bash
# Module: kernel.tests.test_kernel_permissions
# Purpose: Verify kernel permissions behavior on disposable fixtures.
# Created: 2026-10-01
# Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
test "$(id -u)" -eq 0
test "$(modinfo -F vermagic kernel/slate-ntfs.ko | cut -d ' ' -f 1)" = "$(uname -r)"
temporary=$(mktemp -d)
loop_device=
loaded=0
mounted=0
preparing=0
cleanup() {
    if [[ $mounted == 1 ]]; then umount "$temporary/mount"; fi
    if [[ $loaded == 1 ]]; then rmmod slate_ntfs; fi
    if [[ $preparing == 1 ]]; then umount "$temporary/prep"; fi
    if [[ -n $loop_device ]]; then losetup -d "$loop_device"; fi
    rm -rf -- "$temporary"
}
trap cleanup EXIT
chmod 755 "$temporary"
truncate -s 64M "$temporary/image"
mkfs.ntfs -F -Q "$temporary/image" >/dev/null 2>&1
mkdir "$temporary/prep" "$temporary/mount" "$temporary/second"
ntfs-3g -o loop "$temporary/image" "$temporary/prep"
preparing=1
mkdir "$temporary/prep/blocked"
printf secret > "$temporary/prep/blocked/child"
for name in allow_user deny_user primary_group supp_group deny_group everyone empty null inherit_only unknown no_attributes; do
    printf payload > "$temporary/prep/$name"
done
umount "$temporary/prep"
preparing=0
python3 kernel/tests/permission_fixture.py "$temporary/image"
loop_device=$(losetup --find --show "$temporary/image")
insmod kernel/slate-ntfs.ko
loaded=1
mapping='u:0:S-1-5-32-544;g:0:S-1-5-18;u:1001:S-1-5-1001;u:1002:S-1-5-1002;g:2001:S-1-5-2001;g:2002:S-1-5-2002'
if mount -t ntfsrs -o ro "$loop_device" "$temporary/mount" 2>/dev/null; then
    mounted=1; echo 'missing mapping accepted' >&2;exit 1
fi
mount -t ntfsrs -o "ro,sidmap=$mapping" "$loop_device" "$temporary/mount"
mounted=1
if mount -t ntfsrs -o 'ro,sidmap=u:0:S-1-5-18;g:0:S-1-5-18' "$loop_device" "$temporary/second" 2>/dev/null; then
    umount "$temporary/second";echo 'conflicting shared-superblock mapping accepted' >&2;exit 1
fi
python3 kernel/tests/kernel_permission_checks.py "$temporary/mount"
if mount -o "remount,ro,sidmap=u:0:S-1-5-18;g:0:S-1-5-18" "$temporary/mount" 2>/dev/null; then
    echo 'mapping changed during remount' >&2;exit 1
fi
cleanup
trap - EXIT
echo 'Live kernel SID mapping, DACL enforcement and mount cleanup tests passed.'
