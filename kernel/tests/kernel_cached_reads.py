#!/usr/bin/env python3
"""
Module: kernel.tests.kernel_cached_reads
Purpose: Read-iterator regression: resident data, EOF tails, vectors and concurrency.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Read-iterator regression: resident data, EOF tails, vectors and concurrency.
"""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import sys

root = Path(sys.argv[1])
expected = bytes(range(256)) * 32 + b'partial page tail'
fd = os.open(root / 'tail.bin', os.O_RDONLY)
try:
    offsets = [0, 1, 4095, 4096, 8191, 8192, len(expected) - 1,
               len(expected), len(expected) + 500]
    sizes = [0, 1, 17, 4096, 8192, 65536]

    def check(pair):
        offset, size = pair
        assert os.pread(fd, size, offset) == expected[offset:offset + size]

    for _ in range(2):
        # Evict only this file's clean data, then concurrently refill it.
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(check, [(o, n) for o in offsets for n in sizes] * 3))
        buffers = [bytearray(7), bytearray(4096), bytearray(5000)]
        amount = os.preadv(fd, buffers, 4093)
        assert amount == len(expected) - 4093
        assert b''.join(buffers)[:amount] == expected[4093:]
    assert os.lseek(fd, 0, os.SEEK_CUR) == 0
    assert os.read(fd, 65536) == expected
    assert os.read(fd, 1) == b''
finally:
    os.close(fd)
assert (root / 'hello.txt').read_bytes() == b'hello from ntfs-rs\n'
print('Cached reads: concurrent refill, unaligned/EOF ranges, preadv and resident data passed.')
