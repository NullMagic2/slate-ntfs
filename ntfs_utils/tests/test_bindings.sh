#!/usr/bin/env bash
# Module: ntfs_utils.tests.test_bindings
# Purpose: Verify bindings behavior on disposable fixtures.
# Created: 2026-10-01
# Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
for tool in cc mkfs.ntfs ntfscp python3 truncate; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: $tool is required" >&2
        exit 1
    }
done
if [[ ${SKIP_CARGO_BUILD:-0} != 1 ]]; then
    command -v cargo >/dev/null 2>&1 || { echo 'error: cargo is required' >&2; exit 1; }
    cargo build --manifest-path ntfs_utils/Cargo.toml --release --locked
fi
image=$(mktemp --suffix=.img)
content=$(mktemp)
temporary=$(mktemp -d)
loop_device=''
trap 'if [[ -n "$loop_device" ]]; then sudo -n losetup --detach "$loop_device" || true; fi; rm -f -- "$image" "$content" "$temporary/before" "$temporary/test.c" "$temporary/test" "$temporary/loop_error"; rmdir -- "$temporary"' EXIT
truncate -s 64M "$image"
mkfs.ntfs -F -Q "$image" >/dev/null 2>&1

PYTHONPATH="$PWD/ntfs_utils/python" python3 - "$image" "$temporary/before" <<'PY'
import ntfs_utils
import pathlib
import sys

device = ntfs_utils.get_device(sys.argv[1])
assert device.is_dirty is False
assert 0 < device.used_bytes < device.size_bytes
assert device.free_bytes == device.allocatable_bytes - device.used_bytes
assert device.allocatable_bytes <= device.size_bytes
assert device.manufacturer is None and device.model is None
assert device.refresh().volume_serial == device.volume_serial
pathlib.Path(sys.argv[2]).write_text(str(device.used_bytes))
print(f"Python: size={device.size_bytes}, used={device.used_bytes}")
PY

python3 - "$content" <<'PY'
import pathlib
import sys
pathlib.Path(sys.argv[1]).write_bytes(b'x' * (2 * 1024 * 1024))
PY
ntfscp -f "$image" "$content" /payload.bin

PYTHONPATH="$PWD/ntfs_utils/python" python3 - "$image" "$temporary/before" <<'PY'
import ntfs_utils
import pathlib
import sys

before = int(pathlib.Path(sys.argv[2]).read_text())
device = ntfs_utils.get_device(sys.argv[1])
assert device.used_bytes > before + 1024 * 1024
assert device.free_bytes == device.allocatable_bytes - device.used_bytes
print(f"Python: allocated bytes grew to {device.used_bytes}")
PY

cat > "$temporary/test.c" <<'C'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntfs_utils.h"

int main(int argc, char **argv) {
    ntfs_device_info info;
    ntfs_device_info listed[64];
    char error[256];
    int result;
    size_t count = 0, skipped = 0;
    if (argc < 2 || argc > 3) return 99;
    result = ntfs_utils_probe(argv[1], &info, sizeof(info), error, sizeof(error));
    if (result) {
        fprintf(stderr, "C probe: %s (%d)\n", error, result);
        return result;
    }
    if (info.abi_version != NTFS_UTILS_ABI_VERSION || !info.usage_available ||
        info.is_dirty != (argc == 3) ||
        !info.used_bytes || info.used_bytes >= info.volume_size_bytes ||
        info.free_bytes != info.allocatable_bytes - info.used_bytes ||
        info.manufacturer[0]) return 98;
    if (ntfs_utils_list(NTFS_UTILS_KIND_ALL, listed, 64, &count, &skipped,
                        error, sizeof(error))) return 97;
    int found = 0;
    if (count <= 64) {
        for (size_t i = 0; i < count; i++) {
            if (listed[i].abi_version != NTFS_UTILS_ABI_VERSION ||
                listed[i].path[0] != '/') return 96;
            if (strcmp(listed[i].path, argv[1]) == 0) found = 1;
        }
    }
    if (getenv("NTFS_UTILS_EXPECT_LISTED") && !found) return 94;
    if (ntfs_utils_list(99, NULL, 0, &count, &skipped,
                        error, sizeof(error)) != NTFS_UTILS_BAD_ARGUMENT) return 95;
    printf("C: size=%llu, used=%llu\n",
           (unsigned long long)info.volume_size_bytes,
           (unsigned long long)info.used_bytes);
    return 0;
}
C
cc -Wall -Wextra -Werror -I ntfs_utils/include "$temporary/test.c" \
    -L ntfs_utils/target/release -lntfs_utils -o "$temporary/test"
LD_LIBRARY_PATH="$PWD/ntfs_utils/target/release${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    "$temporary/test" "$image"

if command -v losetup >/dev/null && sudo -n true >/dev/null 2>&1; then
    if ! loop_device=$(sudo -n losetup --find --show --read-only "$image" 2>"$temporary/loop_error"); then
        loop_device=''
        echo "Loop setup unavailable: $(cat "$temporary/loop_error")"
    fi
fi
if [[ -n "$loop_device" ]]; then
    NTFS_UTILS_EXPECT_LISTED=1 \
        LD_LIBRARY_PATH="$PWD/ntfs_utils/target/release${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
        "$temporary/test" "$loop_device"
    sudo -n env PYTHONPATH="$PWD/ntfs_utils/python" \
        NTFS_UTILS_LIB="$PWD/ntfs_utils/target/release/libntfs_utils.so" \
        python3 - "$loop_device" <<'PY'
import ntfs_utils
import sys

path = sys.argv[1]
report = ntfs_utils.scan_ntfs_devices()
found = [device for device in report.devices if device.path == path]
assert len(found) == 1, (path, report)
assert found[0].kind == "other", found[0]
assert any(device.path == path for device in ntfs_utils.list_ntfs_devices())
assert all(device.path != path for device in ntfs_utils.list_ntfs_hdds())
assert all(device.path != path for device in ntfs_utils.list_ntfs_ssds())
assert all(device.path != path for device in ntfs_utils.list_ntfs_usb_sticks())
print(f"Python: discovered {path} as {found[0].kind}; skipped={report.skipped_count}")
PY
    sudo -n losetup --detach "$loop_device"
    loop_device=''
else
    echo 'Loop-device discovery test skipped (no permission or loop support).'
fi

PYTHONPATH="$PWD/ntfs_utils/python" python3 - <<'PY'
import ntfs_utils

report = ntfs_utils.scan_ntfs_devices()
assert report.skipped_count >= 0
assert report.devices == ntfs_utils.list_ntfs_devices()
for name, kind in (("list_ntfs_hdds", "hdd"),
                   ("list_ntfs_ssds", "ssd"),
                   ("list_ntfs_usb_sticks", "usb_stick")):
    assert all(device.kind == kind for device in getattr(ntfs_utils, name)())
print(f"Python: discovery API found {len(report.devices)} devices; skipped={report.skipped_count}")
PY

python3 - "$image" <<'PY'
import pathlib
import sys

with pathlib.Path(sys.argv[1]).open('r+b') as image:
    boot = image.read(512)
    cluster = int.from_bytes(boot[0x0b:0x0d], 'little') * boot[0x0d]
    encoded = int.from_bytes(boot[0x40:0x41], 'little', signed=True)
    record_size = cluster * encoded if encoded > 0 else 1 << -encoded
    mft_lcn = int.from_bytes(boot[0x30:0x38], 'little')
    base = mft_lcn * cluster + 3 * record_size
    image.seek(base)
    record = image.read(record_size)
    assert record[:4] == b'FILE'
    offset = int.from_bytes(record[0x14:0x16], 'little')
    while offset + 8 <= len(record):
        kind = int.from_bytes(record[offset:offset + 4], 'little')
        if kind == 0xffffffff:
            raise AssertionError('$VOLUME_INFORMATION not found')
        length = int.from_bytes(record[offset + 4:offset + 8], 'little')
        assert length >= 0x18 and offset + length <= len(record)
        if kind == 0x70:
            value = offset + int.from_bytes(record[offset + 0x14:offset + 0x16], 'little')
            flags = int.from_bytes(record[value + 10:value + 12], 'little')
            image.seek(base + value + 10)
            image.write((flags | 1).to_bytes(2, 'little'))
            break
        offset += length
PY
PYTHONPATH="$PWD/ntfs_utils/python" python3 - "$image" <<'PY'
import ntfs_utils
import sys
assert ntfs_utils.get_device(sys.argv[1]).is_dirty is True
PY
LD_LIBRARY_PATH="$PWD/ntfs_utils/target/release${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    "$temporary/test" "$image" dirty
echo 'ntfs_utils Rust/C/Python image test passed.'
