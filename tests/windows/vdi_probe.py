#!/usr/bin/env python3
"""Module: tests.windows.vdi_probe
Purpose: Read geometry and partitions from dynamic VDI images.
Created: 2026-10-02
Architecture: Provides reusable read-only DynamicVdi access; vdi_extract_partition.py uses it to
extract fixtures.

Read-only geometry and partition probe for a normal dynamic VDI."""

import os
import struct
import sys


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


class DynamicVdi:
    def __init__(self, path):
        self.file = open(path, "rb")
        header = self.file.read(512)
        if u32(header, 64) != 0xBEDA107F:
            raise ValueError("not a VDI image")
        self.image_type = u32(header, 76)
        self.blocks_offset = u32(header, 340)
        self.data_offset = u32(header, 344)
        self.sector_size = u32(header, 360)
        self.disk_size = u64(header, 368)
        self.block_size = u32(header, 376)
        self.block_extra = u32(header, 380)
        self.block_count = u32(header, 384)
        self.allocated_count = u32(header, 388)
        if self.image_type != 1 or self.block_size == 0 or self.block_extra:
            raise ValueError("unsupported VDI layout")
        self.file.seek(self.blocks_offset)
        self.map = self.file.read(self.block_count * 4)
        if len(self.map) != self.block_count * 4:
            raise ValueError("truncated VDI block map")
        self.file_size = os.fstat(self.file.fileno()).st_size

    def read(self, offset, size):
        if offset < 0 or size < 0 or offset + size > self.disk_size:
            raise ValueError("logical read outside virtual disk")
        chunks = []
        while size:
            block, inner = divmod(offset, self.block_size)
            count = min(size, self.block_size - inner)
            physical = u32(self.map, block * 4)
            if physical >= 0xFFFFFFFE:
                chunks.append(bytes(count))
            else:
                pos = self.data_offset + physical * self.block_size + inner
                if pos + count > self.file_size:
                    raise ValueError("VDI block points outside the file")
                self.file.seek(pos)
                chunk = self.file.read(count)
                if len(chunk) != count:
                    raise ValueError("truncated VDI data block")
                chunks.append(chunk)
            offset += count
            size -= count
        return b"".join(chunks)


def probe(path):
    vdi = DynamicVdi(path)
    print(f"VDI type={vdi.image_type} logical={vdi.disk_size} bytes "
          f"block={vdi.block_size} allocated={vdi.allocated_count}/{vdi.block_count}")
    mbr = vdi.read(0, 512)
    print(f"MBR signature={mbr[510:512].hex()} entries:")
    for index in range(4):
        entry = mbr[446 + 16 * index:462 + 16 * index]
        kind = entry[4]
        start, count = struct.unpack_from("<II", entry, 8)
        if kind or count:
            print(f"  {index + 1}: type=0x{kind:02x} start={start} count={count}")
            if kind == 7:
                boot = vdi.read(start * 512, 512)
                print(f"    OEM={boot[3:11]!r} NTFS signature={boot[510:512].hex()}")
    if vdi.read(512, 8) == b"EFI PART":
        gpt = vdi.read(512, 512)
        entry_lba = u64(gpt, 72)
        count = u32(gpt, 80)
        entry_size = u32(gpt, 84)
        print(f"GPT entries={count} size={entry_size} at LBA={entry_lba}")
        if entry_size < 128 or count > 1024:
            raise ValueError("implausible GPT partition array")
        entries = vdi.read(entry_lba * 512, count * entry_size)
        for index in range(count):
            entry = entries[index * entry_size:(index + 1) * entry_size]
            if entry[:16] == bytes(16):
                continue
            start = u64(entry, 32)
            end = u64(entry, 40)
            name = entry[56:128].decode("utf-16le", errors="replace").rstrip("\0")
            boot = vdi.read(start * 512, 512)
            print(f"  {index + 1}: {name!r} LBA={start}-{end} "
                  f"OEM={boot[3:11]!r} signature={boot[510:512].hex()}")


if __name__ == "__main__":
    probe(sys.argv[1])
