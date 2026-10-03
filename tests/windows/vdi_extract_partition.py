#!/usr/bin/env python3
"""Module: tests.windows.vdi_extract_partition
Purpose: Extract a GPT partition from a read-only dynamic VDI.
Created: 2026-10-02
Architecture: Uses vdi_probe.py for container access; emits raw partition images for host-side
NTFS fixture checks.

Copy one GPT partition out of a dynamic VDI; source is opened read-only."""

import os
import struct
import sys

from vdi_probe import DynamicVdi, u32, u64


def main(vdi_path, partition_number, output_path):
    vdi = DynamicVdi(vdi_path)
    gpt = vdi.read(512, 512)
    if gpt[:8] != b"EFI PART":
        raise ValueError("GPT header not found")
    entry_size = u32(gpt, 84)
    entry_count = u32(gpt, 80)
    if partition_number < 1 or partition_number > entry_count or entry_size < 128:
        raise ValueError("invalid partition number or GPT geometry")
    entry_offset = u64(gpt, 72) * 512 + (partition_number - 1) * entry_size
    entry = vdi.read(entry_offset, entry_size)
    start = u64(entry, 32) * 512
    size = (u64(entry, 40) - u64(entry, 32) + 1) * 512
    if start + size > vdi.disk_size or vdi.read(start + 3, 8) != b"NTFS    ":
        raise ValueError("selected partition is outside disk or not NTFS")
    print(f"Extracting GPT partition {partition_number}: {size} bytes", flush=True)
    with open(output_path, "xb") as output:
        output.truncate(size)
        copied = 0
        while copied < size:
            amount = min(vdi.block_size, size - copied)
            chunk = vdi.read(start + copied, amount)
            if any(chunk):
                output.seek(copied)
                output.write(chunk)
            copied += amount
            if copied % (1024 * 1024 * 1024) < vdi.block_size:
                print(f"  {copied // (1024 * 1024)} MiB", flush=True)
        output.flush()
        os.fsync(output.fileno())
    print("Done; source VDI was not opened for writing.", flush=True)


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]), sys.argv[3])
